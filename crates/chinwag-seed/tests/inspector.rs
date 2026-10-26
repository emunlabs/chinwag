use chinwag_seed::vault::{Binding, Recipient, seal};
use std::{fs, process::Command};

const OID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn inspector_prints_only_authenticated_plaintext_and_refuses_a_wrong_target() {
    let directory = tempfile::tempdir().unwrap();
    let demo = Recipient::generate().unwrap();
    let org = Recipient::generate().unwrap();
    let plaintext = br#"{"fixture":"synthetic; not a live flight"}"#;
    let capsule = seal(
        &Binding::public_chinwag(OID).unwrap(),
        plaintext,
        &demo.public,
        &org.public,
    )
    .unwrap();
    let key_file = directory.path().join("demo.raw");
    let capsule_file = directory.path().join("capsule.bin");
    fs::write(&key_file, demo.secret_bytes()).unwrap();
    fs::write(&capsule_file, capsule).unwrap();
    for (slot, key) in [("demo", &demo), ("org", &org)] {
        fs::write(&key_file, key.secret_bytes()).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_chinwag-seed"))
            .args(["inspect-file", OID, slot])
            .arg(&key_file)
            .arg(&capsule_file)
            .output()
            .unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout, plaintext);
        assert!(result.stderr.is_empty());
    }
    let result = Command::new(env!("CARGO_BIN_EXE_chinwag-seed"))
        .args([
            "inspect-file",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "org",
        ])
        .arg(&key_file)
        .arg(&capsule_file)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert_eq!(
        result.stderr,
        b"chinwag-seed: capsule authentication failed\n"
    );
}

#[test]
fn inspector_rejects_a_non_key_file_without_echoing_it() {
    let directory = tempfile::tempdir().unwrap();
    let key_file = directory.path().join("not-a-key");
    let capsule_file = directory.path().join("empty");
    fs::write(&key_file, b"synthetic value that must not be echoed").unwrap();
    fs::write(&capsule_file, []).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_chinwag-seed"))
        .args(["inspect-file", OID, "demo"])
        .arg(&key_file)
        .arg(&capsule_file)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert_eq!(
        result.stderr,
        b"chinwag-seed: input exceeds its size limit\n"
    );
}
