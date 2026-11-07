use super::*;
use crate::agent_instance::{ActorAddress, DispatchIdentity};
use crate::execution_binding::test_support::BindingFixture;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use tempfile::TempDir;

fn identity(agent: &str) -> DispatchIdentity {
    DispatchIdentity::new(
        ActorAddress::parse(&format!("{agent}#p009-child")).unwrap(),
        ActorAddress::parse("WORKHORSE#p009-parent").unwrap(),
    )
    .unwrap()
}

struct Effects<'a> {
    events: Vec<&'static str>,
    child: Option<&'a Path>,
    drift_after_persona: Option<&'a BindingFixture>,
    fail_persist: bool,
}
impl Effects<'_> {
    fn new() -> Self {
        Self {
            events: Vec::new(),
            child: None,
            drift_after_persona: None,
            fail_persist: false,
        }
    }
}
impl AgentRouteEffects for Effects<'_> {
    fn persona(&mut self, _: &str, _: Option<&CustomAgentMeta>) -> Result<String, String> {
        self.events.push("persona");
        if let Some(fixture) = self.drift_after_persona {
            fixture.bump_generation();
        }
        Ok("Controlled fixture persona".into())
    }
    fn memory(&mut self, _: &WorkspaceExecutionBinding) -> Result<String, String> {
        self.events.push("memory");
        Ok(String::new())
    }
    fn signing(&mut self, _: &str, _: &WorkspaceExecutionBinding) -> seat_signing::SeatSigning {
        self.events.push("signing");
        seat_signing::SeatSigning::default()
    }
    fn engine(
        &mut self,
        binding: &WorkspaceExecutionBinding,
        authority: &ExecutionAuthority,
        _: &EngineRequest<'_>,
    ) -> Result<(String, &'static str), String> {
        self.events.push("engine");
        let reply = match self.child {
            Some(child) => run_bound_local_command(
                binding,
                authority,
                Command::new(child)
                    .arg("--cwd")
                    .arg(binding.execution_root()),
            )?,
            None => "controlled fixture reply".into(),
        };
        Ok((reply, "controlled-fake-worker"))
    }
    fn persist(
        &mut self,
        binding: &WorkspaceExecutionBinding,
        authority: &ExecutionAuthority,
        exchange: &DispatchExchange<'_>,
    ) -> Result<(), String> {
        self.events.push("persist");
        if self.fail_persist {
            return Err("controlled uncertain persistence".into());
        }
        persist_to_crdb(binding, authority, exchange)
    }
}

fn input(identity: &DispatchIdentity) -> BoundDispatchInput<'_> {
    BoundDispatchInput {
        identity,
        item: "qualified-fixture",
        body: "controlled route test",
        history: &[],
        custom: None,
    }
}

fn fake_child() -> (TempDir, PathBuf) {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("worker.rs");
    let binary = temp.path().join("worker");
    fs::write(&source, r#"fn main() {
        let args: Vec<String> = std::env::args().collect();
        let cwd_arg = args.windows(2).find(|pair| pair[0] == "--cwd").map(|pair| pair[1].as_str()).unwrap_or("");
        println!("pwd={}\ncwd={}\nstore={}\nbinding={}",
            std::env::current_dir().unwrap().display(), cwd_arg,
            std::env::var("CHINWAG_STORE_PATH").unwrap(),
            std::env::var("CHINWAG_EXECUTION_BINDING").unwrap());
    }"#).unwrap();
    let output = Command::new(chinwag_test_fixtures::rustc())
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    (temp, binary)
}

#[test]
fn p009_agent_refuses_unsupported_before_persona_memory_signing_engine_or_store() {
    let fixture = BindingFixture::new();
    let request = AgentDispatchRequest {
        agent: Some("RUST#p009-child".into()),
        item: None,
        sender: Some("WORKHORSE#p009-parent".into()),
        instance: None,
        body: Some("fixture".into()),
        repo: Some(fixture.root().to_owned()),
        crdb: Some(fixture.store_path().to_owned()),
        stdin_json: false,
    };
    let mut effects = Effects::new();
    let mut out = Vec::new();
    let mut err = Vec::new();
    assert_eq!(
        run_agent_dispatch_with_effects(
            request,
            &mut &b""[..],
            &mut out,
            &mut err,
            &ExecutionAuthority::unsupported(),
            &mut effects
        ),
        2
    );
    assert!(effects.events.is_empty());
    assert!(out.is_empty());
    assert!(
        String::from_utf8(err)
            .unwrap()
            .contains("execution_binding_held")
    );
}

#[test]
fn p009_agent_revalidates_between_persona_and_memory_before_later_effects() {
    let fixture = BindingFixture::new();
    let binding = fixture.bind();
    let authority = fixture.authority();
    let mut effects = Effects::new();
    effects.drift_after_persona = Some(&fixture);
    assert!(
        run_bound_exchange(
            &binding,
            &authority,
            &input(&identity("RUST")),
            &mut effects,
            &mut Vec::new()
        )
        .is_err()
    );
    assert_eq!(effects.events, ["persona"]);
}

#[test]
fn p009_agent_fake_process_and_native_exchange_share_bound_root_and_store() {
    let (_child_dir, child) = fake_child();
    let fixture = BindingFixture::new();
    let binding = fixture.bind();
    let authority = fixture.authority();
    let mut effects = Effects::new();
    effects.child = Some(&child);
    let result = run_bound_exchange(
        &binding,
        &authority,
        &input(&identity("RUST")),
        &mut effects,
        &mut Vec::new(),
    )
    .unwrap();
    let reply = result["reply"].as_str().unwrap();
    assert!(reply.contains(&format!("pwd={}", fixture.root().display())));
    assert!(reply.contains(&format!("cwd={}", fixture.root().display())));
    assert!(reply.contains(&format!("store={}", fixture.store_path().display())));
    assert!(reply.contains(&format!("binding={}", binding.commitment_id())));
    assert_eq!(
        effects.events,
        ["persona", "memory", "signing", "engine", "persist"]
    );
    assert_eq!(result["crdb_persisted"], true);
    // Persistence replaces the exact enrolled inode; there was no implicit
    // refresh, second retention write, relay, or post-write engine effect.
    assert!(binding.revalidate(&authority).is_err());
    let owner = ReadOwner::acquire_existing_private_fixture(fixture.root()).unwrap();
    let session = SnapshotSession::from_owner(owner).unwrap();
    let context = session.context("RUST#p009-child").unwrap();
    assert_eq!(context.messages.len(), 2);
    assert_eq!(
        context.thread[0][1],
        Value::Text(binding.repo_id().to_owned())
    );
    assert_eq!(context.thread[0][2], Value::Text(binding.branch_metadata()));
    session.finish().unwrap();
}

#[test]
fn p009_agent_uncertain_persistence_has_one_attempt_and_no_later_effect() {
    let fixture = BindingFixture::new();
    let binding = fixture.bind();
    let authority = fixture.authority();
    let before = fs::read(fixture.store_path()).unwrap();
    let mut effects = Effects::new();
    effects.fail_persist = true;
    let error = run_bound_exchange(
        &binding,
        &authority,
        &input(&identity("RUST")),
        &mut effects,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(error.contains("unknown_no_retry"));
    assert_eq!(
        effects.events,
        ["persona", "memory", "signing", "engine", "persist"]
    );
    assert_eq!(fs::read(fixture.store_path()).unwrap(), before);
}

#[test]
fn p009_agent_foreign_native_marker_is_preserved_without_cleanup_or_retry() {
    let fixture = BindingFixture::new();
    let binding = fixture.bind();
    let authority = fixture.authority();
    let marker = fixture
        .store_path()
        .parent()
        .unwrap()
        .join("state.crdb.lock");
    fs::write(&marker, b"uncertain original must remain").unwrap();
    let before = fs::read(fixture.store_path()).unwrap();
    let who = identity("RUST");
    assert!(
        persist_to_crdb(
            &binding,
            &authority,
            &DispatchExchange {
                identity: &who,
                item_key: "fixture",
                inbound_id: "in",
                inbound_body: "before",
                outbound_id: "out",
                outbound_body: "after",
                now_ms: 1,
            }
        )
        .is_err()
    );
    assert_eq!(fs::read(marker).unwrap(), b"uncertain original must remain");
    assert_eq!(fs::read(fixture.store_path()).unwrap(), before);
}

#[test]
fn p009_agent_unmapped_remote_refuses_before_every_route_effect() {
    let fixture = BindingFixture::new();
    let binding = fixture.bind();
    let authority = fixture.authority();
    let mut effects = Effects::new();
    let error = run_bound_exchange(
        &binding,
        &authority,
        &input(&identity("WORKHORSE")),
        &mut effects,
        &mut Vec::new(),
    )
    .unwrap_err();
    assert_eq!(error, "remote_execution_binding_unsupported");
    assert!(effects.events.is_empty());
}

#[test]
fn p009_original_owner_rejects_store_changed_between_binding_and_acquisition() {
    for changed in ["image", "inode"] {
        let fixture = BindingFixture::new();
        let other = BindingFixture::new();
        let binding = fixture.bind();
        let authority = fixture.authority();
        let before_identity = fs::metadata(fixture.store_path()).unwrap().ino();
        let expected = fs::read(fixture.store_path()).unwrap();
        if changed == "image" {
            // A different valid store image on the SAME inode must not be
            // imported as the originally bound preimage.
            fs::write(fixture.store_path(), fs::read(other.store_path()).unwrap()).unwrap();
            assert_eq!(
                fs::metadata(fixture.store_path()).unwrap().ino(),
                before_identity
            );
        } else {
            // Even byte-identical replacement does not preserve file identity.
            let staged = fixture.store_path().parent().unwrap().join("substitute");
            fs::write(&staged, &expected).unwrap();
            fs::set_permissions(&staged, fs::Permissions::from_mode(0o600)).unwrap();
            fs::rename(&staged, fixture.store_path()).unwrap();
            assert_ne!(
                fs::metadata(fixture.store_path()).unwrap().ino(),
                before_identity
            );
        }
        let current = fs::read(fixture.store_path()).unwrap();
        let mut owner = WriteOwner::acquire_existing_private_fixture(fixture.root()).unwrap();
        assert!(
            binding
                .revalidate_for_store_owner(&authority, &mut owner)
                .is_err(),
            "{changed}"
        );
        assert_eq!(fs::read(fixture.store_path()).unwrap(), current);
        // Refusal retains the new owner's original marker; it never cleans up
        // artifacts or imports/replaces a different preimage under this binding.
        assert!(
            fixture
                .store_path()
                .parent()
                .unwrap()
                .join("state.crdb.lock")
                .exists()
        );
    }
}

#[test]
fn p009_another_sealed_native_owner_cannot_waive_this_bindings_marker_gate() {
    let fixture = BindingFixture::new();
    let other = BindingFixture::new();
    let binding = fixture.bind();
    let authority = fixture.authority();
    let before = fs::read(fixture.store_path()).unwrap();
    let mut foreign = WriteOwner::acquire_existing_private_fixture(other.root()).unwrap();
    assert!(
        binding
            .revalidate_for_store_owner(&authority, &mut foreign)
            .is_err()
    );
    assert_eq!(fs::read(fixture.store_path()).unwrap(), before);
    assert!(
        !fixture
            .store_path()
            .parent()
            .unwrap()
            .join("state.crdb.lock")
            .exists()
    );
    assert!(
        other
            .store_path()
            .parent()
            .unwrap()
            .join("state.crdb.lock")
            .exists()
    );
}
