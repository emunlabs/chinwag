//! Real local files/timers only. These do not construct a fake room, endpoint,
//! identity permit, or claim service, and are not whole-driver network proof.
use super::*;
use std::{
    cell::Cell,
    os::unix::fs::{PermissionsExt, symlink},
};

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    path: PathBuf,
    config: Value,
}
fn private_write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for name in [
            "guard",
            "received",
            "trace",
            "quarantine",
            "templates",
            "worktree",
            "cache",
        ] {
            DirBuilder::new()
                .mode(0o700)
                .create(root.join(name))
                .unwrap();
        }
        private_write(&root.join("key"), b"not a real key");
        private_write(&root.join("signers"), b"not a real signers file");
        let rustc = chinwag_test_fixtures::rustc();
        let config = json!({
            "schema":"chinwag-architect-receive/v3", "relay":{"mode":"disabled"}, "own_key":root.join("key"),
            "lan_ipv4":"192.0.2.10", "run":"11".repeat(32),
            "oid":"22".repeat(20), "tree":"33".repeat(20),
            "guard_directory":root.join("guard"), "received_directory":root.join("received"),
            "trace_directory":root.join("trace"),
            "quarantine":root.join("quarantine"), "empty_templates":root.join("templates"),
            "builder_signers":root.join("signers"), "worktree":root.join("worktree"),
            "toolchain":rustc.parent().unwrap().canonicalize().unwrap(), "cache":root.join("cache"),
        });
        let path = root.join("receive.json");
        private_write(&path, &serde_json::to_vec(&config).unwrap());
        Self {
            _temp: temp,
            root,
            path,
            config,
        }
    }
    fn selected(&self) -> Selected {
        select(&self.path).unwrap()
    }
    fn guard(&self) -> Guard {
        Guard::arm(&self.selected()).unwrap()
    }
    fn untouched(&self) {
        for name in [
            "guard",
            "received",
            "trace",
            "quarantine",
            "templates",
            "worktree",
            "cache",
        ] {
            assert!(fs::read_dir(self.root.join(name)).unwrap().next().is_none());
        }
        assert_eq!(fs::read(self.root.join("key")).unwrap(), b"not a real key");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn config_pins_one_role_and_real_receive_refuses_test_key_before_guard() {
    let f = Fixture::new();
    let selected = f.selected();
    assert_eq!(selected.peer, BUILDER.parse::<EndpointId>().unwrap());
    assert_eq!(selected.candidate.builder(), *selected.peer.as_bytes());
    f.untouched();
    assert!(matches!(receive(&f.path).await, Err(Error::Identity)));
    f.untouched();
    println!(
        "driver_startup real_receive_called=true malformed_TEST_key_refused=true guard_and_all_scopes_untouched=true no_room_or_owned_identity=true"
    );
}

#[test]
fn config_cap_is_valid_json_and_strict_or_unsafe_scopes_refuse() {
    let f = Fixture::new();
    let mut bytes = fs::read(&f.path).unwrap();
    bytes.resize(CONFIG_LIMIT, b' ');
    private_write(&f.path, &bytes);
    assert!(select(&f.path).is_ok());
    bytes.push(b' ');
    assert!(serde_json::from_slice::<Config>(&bytes).is_ok());
    private_write(&f.path, &bytes);
    assert!(select(&f.path).is_err());
    for (key, value) in [
        ("schema", json!("chinwag-architect-receive/v1")),
        ("run", json!("AA".repeat(32))),
        ("peer", json!(ARCHITECT)),
        ("oid", json!("bad")),
        ("lan_ipv4", json!("127.0.0.1")),
        ("quarantine", json!(f.root.join("received"))),
        ("trace_directory", json!(f.root.join("guard"))),
        ("trace_directory", json!(f.root.join("cache"))),
        ("guard_directory", json!("relative")),
    ] {
        let mut changed = f.config.clone();
        changed[key] = value;
        private_write(&f.path, &serde_json::to_vec(&changed).unwrap());
        assert!(select(&f.path).is_err(), "{key}");
    }
    private_write(&f.path, &serde_json::to_vec(&f.config).unwrap());
    let alias = f.root.join("alias");
    symlink(&f.path, &alias).unwrap();
    assert!(select(&alias).is_err());
    fs::remove_file(&alias).unwrap();
    fs::hard_link(&f.path, &alias).unwrap();
    assert!(select(&f.path).is_err());
    fs::remove_file(&alias).unwrap();
    fs::set_permissions(&f.path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(select(&f.path).is_err());
    f.untouched();
    println!(
        "driver_config valid_json16384_accepted_16385_refused=true strict_fields_and_disjoint_private_scopes=true no_key_bytes_loaded=true no_network=true"
    );
}

#[test]
fn guard_is_synced_private_and_original_or_note_cannot_be_overwritten() {
    let f = Fixture::new();
    let selected = f.selected();
    let guard = Guard::arm(&selected).unwrap();
    let path = guard.path.join(MARKER);
    let before = fs::read(&path).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    let marker: Marker = serde_json::from_slice(&before).unwrap();
    marker.validate().unwrap();
    assert!(Guard::arm(&selected).is_err());
    assert!(guard.write_new(MARKER, b"replacement").is_err());
    guard
        .write_new("receiver-finish.json", b"local test note")
        .unwrap();
    assert!(
        guard
            .write_new("receiver-finish.json", b"replacement")
            .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(
        fs::read(guard.path.join("receiver-finish.json")).unwrap(),
        b"local test note"
    );
    println!(
        "driver_guard create_new_file_and_parent_fsync_readback=true mode600=true original_and_note_preserved=true occupied_rearm_refused=true no_network=true"
    );
}

#[test]
fn complete_control_publishes_atomically_without_replacing_any_existing_file() {
    let f = Fixture::new();
    let guard = f.guard();
    let prepared = f.root.join("prepared");
    private_write(&prepared, FINISH);
    publish_finish(&guard.path, &prepared).unwrap();
    assert!(!prepared.exists() && guard.control_present().unwrap());
    let first = fs::metadata(guard.path.join(CONTROL)).unwrap();
    let replacement = f.root.join("replacement");
    private_write(&replacement, FINISH);
    assert!(publish_finish(&guard.path, &replacement).is_err());
    assert_eq!(fs::read(&replacement).unwrap(), FINISH);
    let actual = fs::metadata(guard.path.join(CONTROL)).unwrap();
    assert_eq!((first.dev(), first.ino()), (actual.dev(), actual.ino()));
    assert_eq!(fs::read(guard.path.join(CONTROL)).unwrap(), FINISH);
    println!(
        "driver_control actual_NOREPLACE_rename=true complete15bytes=true existing_inode_and_source_preserved=true file_and_both_parents_synced=true cleanup_only_not_sender_acceptance=true"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn first_control_file_is_final_and_must_be_exact_private_single_link() {
    for case in [
        "malformed",
        "oversize",
        "symlink",
        "hardlink",
        "public",
        "exact",
    ] {
        let f = Fixture::new();
        let guard = f.guard();
        let control = guard.path.join(CONTROL);
        let outside = f.root.join("outside");
        private_write(&outside, FINISH);
        match case {
            "malformed" => private_write(&control, b"finish-network\nextra"),
            "oversize" => private_write(&control, &[b'x'; 33]),
            "symlink" => symlink(&outside, &control).unwrap(),
            "hardlink" => fs::hard_link(&outside, &control).unwrap(),
            "public" => {
                private_write(&control, FINISH);
                fs::set_permissions(&control, fs::Permissions::from_mode(0o644)).unwrap();
            }
            "exact" => private_write(&control, FINISH),
            _ => unreachable!(),
        }
        let calls = Cell::new(0);
        let result = wait_control(&guard, Instant::now() + Duration::from_secs(1), || {
            calls.set(calls.get() + 1);
            Ok(()) // File-boundary fixture, not a RoomSession.
        })
        .await;
        assert_eq!(result.is_ok(), case == "exact", "{case}");
        assert_eq!(calls.get(), if case == "exact" { 2 } else { 1 });
        assert!(fs::symlink_metadata(&control).is_ok());
        assert_eq!(fs::read(&outside).unwrap(), FINISH);
    }
    println!(
        "driver_control first_present_file_final=true exact_private_single_link_required=true bad_file_preserved=true synthetic_freshness_callback_only=true no_room=true"
    );
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn absent_control_wait_ends_at_original_cutoff_or_failed_freshness() {
    let f = Fixture::new();
    let guard = f.guard();
    let start = Instant::now();
    assert!(
        wait_control(&guard, start + Duration::from_millis(250), || Ok(()))
            .await
            .is_err()
    );
    assert_eq!(Instant::now() - start, Duration::from_millis(250));
    assert!(!guard.path.join(CONTROL).exists());
    let now = Instant::now();
    assert!(
        wait_control(&guard, now + Duration::from_secs(1), || Err(Error::Control))
            .await
            .is_err()
    );
    assert_eq!(Instant::now(), now);
    println!(
        "driver_control absent_hits_fixed250ms_cutoff=true freshness_refusal_immediate=true no_file_created=true virtual_timer_file_boundary_only=true"
    );
}

#[test]
fn changed_guard_directory_refuses_before_creating_any_replacement_file() {
    let f = Fixture::new();
    let guard = f.guard();
    let old_marker = fs::read(guard.path.join(MARKER)).unwrap();
    let moved = f.root.join("moved");
    fs::rename(&guard.path, &moved).unwrap();
    DirBuilder::new().mode(0o700).create(&guard.path).unwrap();
    assert!(guard.write_new("note", b"forbidden").is_err());
    assert!(guard.control_present().is_err());
    assert!(fs::read_dir(&guard.path).unwrap().next().is_none());
    assert!(!moved.join("note").exists());
    assert_eq!(fs::read(moved.join(MARKER)).unwrap(), old_marker);
}

#[test]
fn trace_scope_rejects_old_missing_occupied_public_and_overlapping_without_opening_guard() {
    let f = Fixture::new();
    let mut old = f.config.clone();
    old["schema"] = json!("chinwag-architect-receive/v1");
    old.as_object_mut().unwrap().remove("trace_directory");
    private_write(&f.path, &serde_json::to_vec(&old).unwrap());
    assert!(select(&f.path).is_err());
    for path in [
        f.root.join("guard"),
        f.root.join("received"),
        f.root.join("cache"),
    ] {
        let mut changed = f.config.clone();
        changed["trace_directory"] = json!(path);
        private_write(&f.path, &serde_json::to_vec(&changed).unwrap());
        assert!(select(&f.path).is_err());
    }
    private_write(&f.path, &serde_json::to_vec(&f.config).unwrap());
    let trace = f.root.join("trace");
    private_write(&trace.join("keep"), b"original");
    assert!(select(&f.path).is_err());
    assert_eq!(fs::read(trace.join("keep")).unwrap(), b"original");
    assert!(!trace.join("events.jsonl").exists());
    fs::remove_file(trace.join("keep")).unwrap();
    fs::set_permissions(&trace, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(select(&f.path).is_err());
    fs::set_permissions(&trace, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(select(&f.path).is_ok());
    f.untouched();
}
