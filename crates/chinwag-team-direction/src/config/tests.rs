use super::*;
use serde_json::{Value, json};
use std::{
    fs,
    io::Write as _,
    os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
};

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = temp.path().canonicalize().unwrap();
    (temp, root)
}

fn codex(id: &str) -> Value {
    json!({"id":id,"label":"Same visible label","provider":{
        "kind":"codex","owner_socket":"/owner/dedicated.sock","workdir":"/owner/work",
        "runtime_policy":"dedicated_runtime_with_explicit_login"
    }})
}

fn claude(id: &str) -> Value {
    json!({"id":id,"label":"Claude work","provider":{
        "kind":"claude","binary":"/owner/claude","sha256":"a".repeat(64),"workdir":"/owner/work",
        "startup_policy":"managed_policy_prose_only"
    }})
}

fn gemini(id: &str) -> Value {
    json!({"id":id,"label":"Gemini work","provider":{
        "kind":"gemini","binary":"/owner/gemini","sha256":"b".repeat(64),"workdir":"/owner/work",
        "startup_policy":"configured_runtime_effects_manual_mode_extensions_disabled"
    }})
}

fn launch(members: Vec<Value>) -> Value {
    json!({"schema":"chinwag-team-launch/v1","members":members})
}

fn checked(value: &Value) -> Result<Launch> {
    let parsed = json::decode(&serde_json::to_vec(value).unwrap(), 16384)?;
    validate(&parsed)?;
    Ok(parsed)
}

fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn duplicate_unknown_and_caller_control_fields_fail_before_creating_state() {
    let valid = launch(vec![codex("codex-a")]);
    let mut variants = Vec::new();
    for target in ["top", "member", "provider"] {
        let mut value = valid.clone();
        let object = match target {
            "top" => value.as_object_mut().unwrap(),
            "member" => value["members"][0].as_object_mut().unwrap(),
            _ => value["members"][0]["provider"].as_object_mut().unwrap(),
        };
        object.insert("unexpected".into(), json!(true));
        variants.push(serde_json::to_vec(&value).unwrap());
    }
    for field in ["journal", "args", "env", "session_id", "model"] {
        let mut value = valid.clone();
        value["members"][0]["provider"][field] = json!("not owner-declared here");
        variants.push(serde_json::to_vec(&value).unwrap());
    }
    variants.push(
        br#"{"schema":"chinwag-team-launch/v1","schema":"chinwag-team-launch/v1","members":[]}"#
            .to_vec(),
    );
    variants.push(br#"{"schema":"chinwag-team-launch/v1","members":[{"id":"a","id":"b","label":"x","provider":{"kind":"codex","owner_socket":"/owner/server.sock","workdir":"/owner/work","runtime_policy":"dedicated_runtime_with_explicit_login"}}]}"#.to_vec());
    for bytes in variants {
        let (_temp, root) = fixture();
        let config = root.join("team.json");
        let state = root.join("state");
        private_file(&config, &bytes);
        assert!(load(&config, &state).is_err());
        assert!(
            !state.exists(),
            "invalid input must not construct member owners or journals"
        );
        assert_eq!(fs::read(config).unwrap(), bytes);
    }
}

#[test]
fn exact_provider_policy_path_digest_and_member_bounds_are_required() {
    assert!(
        checked(&launch(vec![
            codex("codex-a"),
            claude("claude-a"),
            gemini("gemini-a")
        ]))
        .is_ok()
    );
    let mut invalid = vec![
        launch(vec![]),
        launch((0..5).map(|n| codex(&format!("member-{n}"))).collect()),
    ];
    let mut duplicate = launch(vec![codex("same"), claude("same")]);
    invalid.push(duplicate.clone());
    duplicate["schema"] = json!("another-domain/v1");
    invalid.push(duplicate);
    for id in ["../member", "Member", "", "member/child"] {
        let mut value = launch(vec![codex("valid")]);
        value["members"][0]["id"] = json!(id);
        invalid.push(value);
    }
    for label in [" ".into(), "bad\nlabel".into(), "x".repeat(65)] {
        let mut value = launch(vec![codex("valid")]);
        value["members"][0]["label"] = json!(label);
        invalid.push(value);
    }
    for (member, key, value) in [
        (codex("codex"), "runtime_policy", "default"),
        (claude("claude"), "startup_policy", "permission_bypass"),
        (gemini("gemini"), "startup_policy", "restricted"),
        (codex("codex"), "owner_socket", "relative.sock"),
        (claude("claude"), "binary", "/owner/../claude"),
        (gemini("gemini"), "workdir", "/owner/work/"),
        (claude("claude"), "sha256", "not-a-digest"),
    ] {
        let mut member = member;
        member["provider"][key] = json!(value);
        invalid.push(launch(vec![member]));
    }
    for value in invalid {
        assert!(checked(&value).is_err(), "reject {value}");
    }
}

#[test]
fn distinct_ids_allow_duplicate_labels_and_the_same_declared_codex_listener() {
    let parsed = checked(&launch(vec![codex("codex-a"), codex("codex-b")])).unwrap();
    assert_ne!(parsed.members[0].id, parsed.members[1].id);
    assert_eq!(parsed.members[0].label, parsed.members[1].label);
    let (
        Provider::Codex {
            owner_socket: first,
            ..
        },
        Provider::Codex {
            owner_socket: second,
            ..
        },
    ) = (&parsed.members[0].provider, &parsed.members[1].provider)
    else {
        panic!("expected Codex declarations")
    };
    assert_eq!(
        first, second,
        "a listener can own separate fresh work threads; it is not a duplicate port Arc"
    );
}

#[test]
fn foreign_state_manifest_or_unmarked_existing_bytes_are_preserved() {
    for marked in [false, true] {
        let (_temp, root) = fixture();
        let config = root.join("team.json");
        private_file(
            &config,
            &serde_json::to_vec(&launch(vec![codex("codex-a")])).unwrap(),
        );
        let state = root.join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let foreign = state.join(if marked { "launch.json" } else { "unknown" });
        let bytes = b"existing owner bytes must remain unchanged\n";
        private_file(&foreign, bytes);
        assert!(load(&config, &state).is_err());
        assert_eq!(fs::read(foreign).unwrap(), bytes);
        assert!(!state.join("members").exists());
    }
}

#[test]
fn derived_member_journal_cannot_alias_the_parent_actions_domain() {
    let (_temp, root) = fixture();
    let value = launch(vec![codex("codex-a")]);
    let parsed = checked(&value).unwrap();
    let config = root.join("team.json");
    private_file(&config, &serde_json::to_vec(&value).unwrap());
    let state = root.join("state");
    let (directory, _, _) = private::open_root(&state, true).unwrap();
    private::write_new(
        &directory,
        "launch.json",
        &serde_json::to_vec(&parsed).unwrap(),
    )
    .unwrap();
    let actions = state.join("actions");
    private::open_root(&actions, true).unwrap();
    let members = state.join("members");
    private::open_root(&members, true).unwrap();
    let member = members.join("codex-a");
    private::open_root(&member, true).unwrap();
    symlink(&actions, member.join("native")).unwrap();
    assert!(load(&config, &state).is_err());
    assert!(
        fs::symlink_metadata(member.join("native"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        fs::read_dir(actions).unwrap().count(),
        0,
        "no native journal may adopt the parent domain"
    );
}

#[test]
fn private_config_mode_size_and_final_symlink_are_checked_without_adoption() {
    for kind in ["public-mode", "oversized", "symlink"] {
        let (_temp, root) = fixture();
        let bytes = serde_json::to_vec(&launch(vec![codex("codex-a")])).unwrap();
        let original = root.join("original.json");
        private_file(&original, &bytes);
        let config = root.join("team.json");
        match kind {
            "public-mode" => {
                fs::rename(&original, &config).unwrap();
                fs::set_permissions(&config, fs::Permissions::from_mode(0o644)).unwrap();
            }
            "oversized" => private_file(&config, &vec![b' '; 16385]),
            _ => symlink(&original, &config).unwrap(),
        }
        let before = fs::read(&config).unwrap();
        let state = root.join("state");
        assert!(load(&config, &state).is_err());
        assert!(!state.exists());
        assert_eq!(fs::read(config).unwrap(), before);
    }
}

#[test]
fn held_state_lease_rejects_same_bytes_at_a_replaced_manifest_or_parent() {
    for replace_parent in [false, true] {
        let (_temp, root) = fixture();
        let state = root.join("state");
        let (directory, _, _) = private::open_root(&state, true).unwrap();
        let lock = private::lock(&directory, "team.lock").unwrap();
        let bytes = serde_json::to_vec(&checked(&launch(vec![codex("codex-a")])).unwrap()).unwrap();
        let manifest = private::write_new(&directory, "launch.json", &bytes).unwrap();
        let lease = StateLease {
            path: state.clone(),
            directory,
            lock,
            manifest,
            bytes: bytes.clone(),
        };
        lease.verify().unwrap();
        let retained = root.join("retained");
        if replace_parent {
            fs::rename(&state, &retained).unwrap();
            fs::create_dir(&state).unwrap();
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
            private_file(&state.join("launch.json"), &bytes);
        } else {
            fs::rename(state.join("launch.json"), &retained).unwrap();
            private_file(&state.join("launch.json"), &bytes);
        }
        assert!(lease.verify().is_err());
        let retained_file = if replace_parent {
            retained.join("launch.json")
        } else {
            retained
        };
        assert_eq!(fs::read(retained_file).unwrap(), bytes);
    }
}

#[test]
fn declared_multi_provider_construction_is_inert_and_uses_disjoint_native_domains() {
    let (_temp, root) = fixture();
    let workdir = root.join("work");
    fs::create_dir(&workdir).unwrap();
    fs::set_permissions(&workdir, fs::Permissions::from_mode(0o700)).unwrap();
    let mut value = launch(vec![
        codex("codex-a"),
        codex("codex-b"),
        claude("claude-a"),
        gemini("gemini-a"),
    ]);
    for member in value["members"].as_array_mut().unwrap() {
        member["provider"]["workdir"] = json!(workdir);
        if member["provider"]["kind"] == "codex" {
            member["provider"]["owner_socket"] = json!(root.join("not-started.sock"));
        } else {
            member["provider"]["binary"] = json!(root.join("not-executed-cli"));
        }
    }
    let config = root.join("team.json");
    private_file(&config, &serde_json::to_vec(&value).unwrap());
    let state = root.join("state");
    let loaded = load(&config, &state).unwrap();
    assert_eq!(loaded.members.len(), MAX_MEMBERS);
    loaded.lease.verify().unwrap();
    assert!(
        matches!(load(&config, &state), Err(TeamError::Unavailable)),
        "a second owner cannot adopt the same state lease"
    );
    let actions = fs::metadata(&loaded.actions).unwrap();
    let mut native_inodes = BTreeSet::new();
    for member in &loaded.members {
        let native = fs::metadata(state.join("members").join(&member.id).join("native")).unwrap();
        assert_ne!((native.dev(), native.ino()), (actions.dev(), actions.ino()));
        assert!(native_inodes.insert((native.dev(), native.ino())));
        match &member.port {
            HeldWorkPort::Codex(port) => {
                assert!(port.subscribe().borrow().start.is_none());
                port.close().unwrap();
            }
            HeldWorkPort::Claude(port) => {
                assert!(port.subscribe().borrow().start.is_none());
                port.end_input().unwrap();
            }
            HeldWorkPort::Gemini(port) => {
                assert!(port.subscribe().borrow().start.is_none());
                port.end_input().unwrap();
            }
        }
    }
    assert!(
        !root.join("not-executed-cli").exists(),
        "fixture provides no executable and issues no Start"
    );
    assert!(!root.join("not-started.sock").exists());
}
