//! Comprehensive integration, determinism, negative-policy, RFC 8032 KAT, and live MCP drift tests.
#![forbid(unsafe_code)]

use chinwag_plugin_pack::{
    PLUGIN_RELEASE_DOMAIN_TAG, PackError,
    compiler::{ReleaseSigningSeed, build_deterministic_release, compile_release_to_map},
    manifest::LoadedCanonicalBundle,
    targets::StoreTarget,
    verification::{
        NativeValidatorMode, verify_domain_separated_ed25519, verify_release_dir,
        verify_runtime_mcp_catalog_zero_drift,
    },
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use std::{
    fs,
    path::{Path, PathBuf},
};
use tempfile::TempDir;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn canonical_manifest_path() -> PathBuf {
    workspace_root().join("plugins/canonical/chinwag-plugin.toml")
}

fn copy_canonical_fixture(dest: &Path) {
    let src = workspace_root().join("plugins/canonical");
    copy_dir_recursive(&src, dest);
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let ty = entry.file_type().unwrap();
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &to);
        } else {
            fs::copy(entry.path(), to).unwrap();
        }
    }
}

/// Published RFC 8032 §7.1 Test Vector 1 & Test Vector 2 known-answer tests + negative vectors (`cryptography/SKILL.md`).
#[test]
fn rfc8032_section_7_1_ed25519_known_answer_and_domain_separation_vectors() {
    // RFC 8032 §7.1 TEST 1 (empty message)
    let sk1_bytes: [u8; 32] =
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
            .try_into()
            .unwrap();
    let expected_pk1: [u8; 32] =
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .unwrap()
            .try_into()
            .unwrap();
    let expected_sig1: [u8; 64] = hex::decode(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
         5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    )
    .unwrap()
    .try_into()
    .unwrap();

    let sk1 = SigningKey::from_bytes(&sk1_bytes);
    assert_eq!(sk1.verifying_key().to_bytes(), expected_pk1);
    assert_eq!(sk1.sign(b"").to_bytes(), expected_sig1);
    VerifyingKey::from_bytes(&expected_pk1)
        .unwrap()
        .verify_strict(b"", &ed25519_dalek::Signature::from_bytes(&expected_sig1))
        .unwrap();

    // RFC 8032 §7.1 TEST 2 (1-byte message 0x72)
    let sk2_bytes: [u8; 32] =
        hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
            .unwrap()
            .try_into()
            .unwrap();
    let expected_pk2: [u8; 32] =
        hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
            .unwrap()
            .try_into()
            .unwrap();
    let expected_sig2: [u8; 64] = hex::decode(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
         085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    )
    .unwrap()
    .try_into()
    .unwrap();

    let sk2 = SigningKey::from_bytes(&sk2_bytes);
    assert_eq!(sk2.verifying_key().to_bytes(), expected_pk2);
    assert_eq!(sk2.sign(&[0x72]).to_bytes(), expected_sig2);

    // Domain separation & negative checks on ReleaseSigningSeed (using ephemeral CSPRNG key)
    let eph = ReleaseSigningSeed::generate_ephemeral().unwrap();
    assert_eq!(format!("{eph:?}"), "ReleaseSigningSeed([REDACTED])");
    let pk = eph.verifying_key().to_bytes();
    let payload = b"sample-manifest-payload";
    let sig = eph.sign_domain_separated(payload);
    verify_domain_separated_ed25519(&pk, payload, &sig).unwrap();

    // Negative 1: raw unprefixed signature over `payload` MUST be rejected by domain-separated verifier
    let mut wrong_raw = [0u8; 32];
    getrandom::fill(&mut wrong_raw).unwrap();
    let raw_sk = SigningKey::from_bytes(&wrong_raw);
    let raw_sig = raw_sk.sign(payload).to_bytes();
    assert!(
        verify_domain_separated_ed25519(&raw_sk.verifying_key().to_bytes(), payload, &raw_sig)
            .is_err()
    );
    assert_eq!(PLUGIN_RELEASE_DOMAIN_TAG, b"CHINWAG_PLUGIN_RELEASE_V1\0");

    // Negative 2: 1-bit flip in payload or signature MUST fail closed
    let mut bad_sig = sig;
    bad_sig[63] ^= 0x01;
    assert!(verify_domain_separated_ed25519(&pk, payload, &bad_sig).is_err());
    assert!(verify_domain_separated_ed25519(&pk, b"sample-manifest-payloae", &sig).is_err());
}

#[test]
fn deterministic_double_build_across_all_seven_stores_and_tamper_detection() {
    let manifest_path = canonical_manifest_path();
    let bundle = LoadedCanonicalBundle::load(&manifest_path).unwrap();

    // Ephemeral CSPRNG key shared across two independent in-memory builds -> 100% byte-identical
    let seed = ReleaseSigningSeed::generate_ephemeral().unwrap();
    let map_one = compile_release_to_map(&bundle, &seed).unwrap();
    let map_two = compile_release_to_map(&bundle, &seed).unwrap();
    assert_eq!(map_one, map_two);

    // Full on-disk double-build + verification (including native host validators if present)
    let tmp = TempDir::new().unwrap();
    let out_dir = tmp.path().join("dist");
    let summary = build_deterministic_release(
        &manifest_path,
        &out_dir,
        None,
        true,
        NativeValidatorMode::Auto,
    )
    .unwrap();
    assert!(summary.double_build_verified);
    assert_eq!(summary.archives.len(), 7);
    let report = summary.verification.as_ref().unwrap();
    assert!(report.cryptographic_provenance_verified);
    assert!(report.slsa_v1_verified);
    assert!(report.sigstore_bundle_verified);
    assert!(report.runtime_mcp_zero_drift_verified);
    assert_eq!(report.structural_targets_verified, StoreTarget::ALL);

    // Tampering with 1 byte of an archive MUST fail verify_release_dir
    let claude_archive = out_dir.join("archives/chinwag-claude-0.1.0.tar.gz");
    let mut bytes = fs::read(&claude_archive).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x55;
    fs::write(&claude_archive, bytes).unwrap();
    assert!(matches!(
        verify_release_dir(&out_dir, &bundle, None, NativeValidatorMode::Skip),
        Err(PackError::ProvenanceVerification { .. })
    ));
}

#[cfg(unix)]
#[test]
fn seed_file_0600_mode_symlink_pinned_pubkey_and_targets_integrity_guards() {
    use chinwag_plugin_pack::compiler::release_manifest_signing_payload;
    use std::os::unix::fs::{PermissionsExt, symlink};

    let manifest_path = canonical_manifest_path();
    let bundle = LoadedCanonicalBundle::load(&manifest_path).unwrap();
    let tmp = TempDir::new().unwrap();

    // 1. 0644 seed file MUST be refused (`INV-SOLE-KEYPAIR-PER-SEAT-01`)
    let seed_path = tmp.path().join("release_ed25519.seed");
    let seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60\n";
    fs::write(&seed_path, seed_hex).unwrap();
    fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        ReleaseSigningSeed::from_seed_file(&seed_path),
        Err(PackError::ProvenanceVerification { .. })
    ));

    // 2. Exact 0600 seed file succeeds & produces deterministic pinned public key
    fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600)).unwrap();
    let loaded_seed = ReleaseSigningSeed::from_seed_file(&seed_path).unwrap();
    let expected_pk = loaded_seed.verifying_key().to_bytes();

    // 3. Symlink pointing to the 0600 seed file MUST be refused via O_NOFOLLOW + symlink_metadata
    let link_path = tmp.path().join("seed_link.seed");
    symlink(&seed_path, &link_path).unwrap();
    assert!(matches!(
        ReleaseSigningSeed::from_seed_file(&link_path),
        Err(PackError::SymlinkOrUnsafeFile { .. })
    ));

    // 4. Build with 0600 seed file + verify pinned pubkey acceptance and wrong-pubkey rejection
    let out_dir = tmp.path().join("dist");
    build_deterministic_release(
        &manifest_path,
        &out_dir,
        Some(&seed_path),
        true,
        NativeValidatorMode::Skip,
    )
    .unwrap();
    verify_release_dir(
        &out_dir,
        &bundle,
        Some(&expected_pk),
        NativeValidatorMode::Skip,
    )
    .unwrap();

    let mut wrong_pk = expected_pk;
    wrong_pk[0] ^= 0x01;
    assert!(matches!(
        verify_release_dir(
            &out_dir,
            &bundle,
            Some(&wrong_pk),
            NativeValidatorMode::Skip,
        ),
        Err(PackError::ProvenanceVerification { .. })
    ));

    // 5. Injecting an extra unarchived file into `targets/<slug>/` MUST fail verify_release_dir
    let rogue = out_dir.join("targets/claude/plugins/chinwag/rogue.json");
    fs::write(&rogue, b"{}\n").unwrap();
    assert!(matches!(
        verify_release_dir(
            &out_dir,
            &bundle,
            Some(&expected_pk),
            NativeValidatorMode::Skip,
        ),
        Err(PackError::StoreValidation { .. })
    ));
    fs::remove_file(&rogue).unwrap();

    // 6. Path traversal `../escape` in SHA256SUMS (even when validly re-signed!) MUST fail closed
    let mut bad_sha = fs::read_to_string(out_dir.join("SHA256SUMS")).unwrap();
    bad_sha
        .push_str("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ../escape\n");
    let mut bad_b3 = fs::read_to_string(out_dir.join("BLAKE3SUMS")).unwrap();
    bad_b3
        .push_str("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262  ../escape\n");
    let new_payload = release_manifest_signing_payload(bad_sha.as_bytes(), bad_b3.as_bytes());
    let new_sig = loaded_seed.sign_domain_separated(&new_payload);
    fs::write(out_dir.join("SHA256SUMS"), bad_sha).unwrap();
    fs::write(out_dir.join("BLAKE3SUMS"), bad_b3).unwrap();
    fs::write(out_dir.join("SHA256SUMS.sig"), new_sig).unwrap();
    assert!(matches!(
        verify_release_dir(
            &out_dir,
            &bundle,
            Some(&expected_pk),
            NativeValidatorMode::Skip,
        ),
        Err(PackError::ProvenanceVerification { .. })
    ));
}

#[test]
fn compile_time_rejects_hooks_env_interpolation_mcp_token_and_soc2_misclaims() {
    // 1. PreToolUse / hooks in manifest -> ForbiddenHook
    let tmp_hook = TempDir::new().unwrap();
    copy_canonical_fixture(tmp_hook.path());
    let manifest_file = tmp_hook.path().join("chinwag-plugin.toml");
    let orig = fs::read_to_string(&manifest_file).unwrap();
    fs::write(
        &manifest_file,
        format!("{orig}\n[hooks]\nPreToolUse = \"/bin/echo\"\n"),
    )
    .unwrap();
    assert!(matches!(
        LoadedCanonicalBundle::load(&manifest_file),
        Err(PackError::ForbiddenHook { .. })
    ));

    // 2. `${ENV_VAR}` or `$SECRET` interpolation in manifest or skill -> ForbiddenEnvInterpolation
    let tmp_env = TempDir::new().unwrap();
    copy_canonical_fixture(tmp_env.path());
    let skill_file = tmp_env.path().join("skills/coordinate-work/SKILL.md");
    let orig_skill = fs::read_to_string(&skill_file).unwrap();
    fs::write(&skill_file, format!("{orig_skill}\nToken: ${{API_KEY}}\n")).unwrap();
    assert!(matches!(
        LoadedCanonicalBundle::load(&tmp_env.path().join("chinwag-plugin.toml")),
        Err(PackError::ForbiddenEnvInterpolation { .. })
    ));

    // 3. OpenAI user copy containing `"MCP"` token -> OpenAiPolicyViolation
    let tmp_oa = TempDir::new().unwrap();
    copy_canonical_fixture(tmp_oa.path());
    let oa_manifest = tmp_oa.path().join("chinwag-plugin.toml");
    let bad_oa = orig.replace(
        "subtitle = \"Blind engineering coordination and delivery status\"",
        "subtitle = \"Blind MCP server for engineering\"",
    );
    fs::write(&oa_manifest, bad_oa).unwrap();
    assert!(matches!(
        LoadedCanonicalBundle::load(&oa_manifest),
        Err(PackError::OpenAiPolicyViolation { .. })
    ));

    // 4. False `"SOC 2 certified"` claim -> ComplianceViolation
    let tmp_soc = TempDir::new().unwrap();
    copy_canonical_fixture(tmp_soc.path());
    let soc_manifest = tmp_soc.path().join("chinwag-plugin.toml");
    let bad_soc = orig.replace(
        "compliance_statement = \"Emun Labs is pursuing SOC 2.\"",
        "compliance_statement = \"Emun Labs is SOC 2 certified.\"",
    );
    fs::write(&soc_manifest, bad_soc).unwrap();
    assert!(matches!(
        LoadedCanonicalBundle::load(&soc_manifest),
        Err(PackError::ComplianceViolation { .. })
    ));
}

#[test]
fn cross_crate_live_chinwag_mcp_tools_list_has_zero_drift() {
    let mut bundle = LoadedCanonicalBundle::load(&canonical_manifest_path()).unwrap();
    verify_runtime_mcp_catalog_zero_drift(&bundle).unwrap();

    // Flipping one hint in the manifest MUST trigger CatalogDrift
    bundle.manifest.tools[0].destructive_hint = true;
    assert!(matches!(
        verify_runtime_mcp_catalog_zero_drift(&bundle),
        Err(PackError::CatalogDrift { .. })
    ));
}
