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
        if let Some(path) = args.windows(2).find(|pair| pair[0] == "--mark").map(|pair| &pair[1]) {
            std::fs::write(path, b"actual controlled worker ran").unwrap();
        }
        let cwd_arg = args.windows(2).find(|pair| pair[0] == "--cwd").map(|pair| pair[1].as_str()).unwrap_or("");
        println!("pwd={}\ncwd={}\nstore={}\nbinding={}",
            std::env::current_dir().unwrap().display(), cwd_arg,
            std::env::var("CHINWAG_STORE_PATH").unwrap(),
            std::env::var("CHINWAG_EXECUTION_BINDING").unwrap());
        let mut names: Vec<_> = std::env::vars_os().filter_map(|(name, _)|
            name.as_encoded_bytes().starts_with(b"GIT_").then(|| name.to_string_lossy().into_owned())).collect();
        names.sort();
        println!("git_names={}", names.join(","));
        let git = std::process::Command::new("/usr/bin/git").args(["rev-parse", "--show-toplevel"]).output().unwrap();
        println!("git_ok={}\ngit_root={}", git.status.success(), String::from_utf8_lossy(&git.stdout).trim());
        let name = std::process::Command::new("/usr/bin/git").args(["config", "--get", "user.name"]).output().unwrap();
        println!("git_user_name={}\ngit_count={}", String::from_utf8_lossy(&name.stdout).trim(), std::env::var("GIT_CONFIG_COUNT").unwrap_or_default());
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

const BOUND_ENV_CHILD: &str = "CHINWAG_P009_BOUND_ENV_CHILD";
const BOUND_ENV_CHILD_TEST: &str = "agent_dispatch_run::execution_binding_route_tests::p009_agent_bound_environment_subprocess_child";

fn hostile_git_environment(root: &Path) -> Vec<(String, String)> {
    let global = root.join("hostile-global.cfg");
    fs::write(&global, format!("[core]\nworktree = {}\n", root.display())).unwrap();
    vec![
        ("GIT_DIR".into(), root.join(".git").display().to_string()),
        ("GIT_WORK_TREE".into(), root.display().to_string()),
        (
            "GIT_COMMON_DIR".into(),
            root.join(".git").display().to_string(),
        ),
        (
            "GIT_INDEX_FILE".into(),
            root.join(".git/index").display().to_string(),
        ),
        ("GIT_CONFIG_COUNT".into(), "1".into()),
        ("GIT_CONFIG_KEY_0".into(), "core.worktree".into()),
        ("GIT_CONFIG_VALUE_0".into(), root.display().to_string()),
        ("GIT_CONFIG_KEY_57".into(), "alias.bad".into()),
        (
            "GIT_CONFIG_VALUE_57".into(),
            "hostile explicit control".into(),
        ),
        (
            "GIT_CONFIG_PARAMETERS".into(),
            format!("'core.worktree={}'", root.display()),
        ),
        (
            "GIT_OBJECT_DIRECTORY".into(),
            root.join(".git/objects").display().to_string(),
        ),
        (
            "GIT_ALTERNATE_OBJECT_DIRECTORIES".into(),
            root.join(".git/objects").display().to_string(),
        ),
        ("GIT_CONFIG_GLOBAL".into(), global.display().to_string()),
        ("GIT_CONFIG_SYSTEM".into(), global.display().to_string()),
        ("GIT_CONFIG_NOSYSTEM".into(), "0".into()),
        ("GIT_NAMESPACE".into(), "hostile-namespace".into()),
        (
            "GIT_FUTURE_CONTROL".into(),
            "must not inherit unknown Git controls".into(),
        ),
    ]
}

#[test]
fn p009_agent_launch_removes_inherited_and_explicit_git_controls() {
    let foreign = BindingFixture::new();
    let hostile = hostile_git_environment(foreign.root());
    let mut failures = Vec::new();
    for mode in ["inherited", "explicit"] {
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", BOUND_ENV_CHILD_TEST, "--nocapture"])
            .env(BOUND_ENV_CHILD, mode);
        if mode == "inherited" {
            child.envs(hostile.iter().cloned());
        }
        let output = child.output().unwrap();
        if !output.status.success() {
            failures.push(format!(
                "{mode}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn p009_agent_pool_dispatch_branch_is_held_before_state_or_provider_effects() {
    let temporary = TempDir::new().unwrap();
    let state = temporary.path().join("pool");
    fs::create_dir(&state).unwrap();
    // The old implementation returns a paused-pool note. This guard ensures
    // the red regression cannot reach any credential/API/usage-ledger effect.
    fs::write(state.join("PAUSE"), b"controlled provider safety guard").unwrap();
    let token = temporary.path().join("fixture-token");
    fs::write(&token, b"fixture-only-not-a-credential").unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", BOUND_ENV_CHILD_TEST, "--nocapture"])
        .env(BOUND_ENV_CHILD, "pool")
        .env("HOME", temporary.path())
        .env("EPHEMERAL_DEEPSEEK_TOKEN_FILE", &token)
        .env("EPHEMERAL_POOLS_DIR", &state)
        .env("EPHEMERAL_DEEPSEEK_DISABLE", "0")
        .env_remove("CHINWAG_AGENT_MOCK_REPLY")
        .env_remove("EPHEMERAL_POOLS_PAUSED")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_dir(state).unwrap().count(), 1);
}

#[test]
fn p009_agent_reintroduces_only_generated_bound_signing_configuration() {
    let home = TempDir::new().unwrap();
    let keys = home.path().join(".chinwag/signing");
    fs::create_dir_all(&keys).unwrap();
    // Synthetic placeholders: no actual key material is read or used to sign.
    fs::write(keys.join("rust_ed25519.pub"), b"fixture public placeholder").unwrap();
    fs::write(keys.join("rust_ed25519"), b"fixture private placeholder").unwrap();
    let foreign = BindingFixture::new();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", BOUND_ENV_CHILD_TEST, "--nocapture"])
        .env(BOUND_ENV_CHILD, "trusted")
        .env("HOME", home.path())
        .envs(hostile_git_environment(foreign.root()))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn p009_hosted_command_without_bound_adapter_is_held_before_worker_or_transport() {
    struct NoTransport;
    impl crate::hosted_agent::HostedTransport for NoTransport {
        fn send(
            &mut self,
            _: &crate::hosted_agent::HttpRequest,
        ) -> Result<crate::hosted_agent::HttpResponse, crate::hosted_agent::HostedAgentError>
        {
            panic!("held hosted command must not reach a transport")
        }
    }
    let (temporary, worker) = fake_child();
    let fixture = BindingFixture::new();
    let binding = fixture.bind();
    let authority = fixture.authority();
    let marker = temporary.path().join("worker-effect");
    let mut executor = BoundHostedExecutor {
        binding: &binding,
        authority: &authority,
        inner: crate::hosted_agent::StandardToolExecutor::new(
            binding.execution_root().into(),
            Vec::new(),
        ),
    };
    let result = crate::hosted_agent::ToolExecutor::execute(
        &mut executor,
        &crate::hosted_agent::ToolCall {
            id: None,
            name: "run_command".into(),
            args: json!({"program": worker, "args": ["--mark", marker]}),
        },
        &crate::hosted_agent::ToolPolicy {
            enabled: true,
            ..Default::default()
        },
        &mut NoTransport,
    );
    assert_eq!(result["authority"], "HELD");
    assert_eq!(result["error"], "bound_hosted_command_adapter_unsupported");
    assert!(!marker.exists());
}

#[test]
fn p009_agent_bound_environment_subprocess_child() {
    let Ok(mode) = std::env::var(BOUND_ENV_CHILD) else {
        return;
    };
    if mode == "pool" {
        let fixture = BindingFixture::new();
        let binding = fixture.bind();
        let authority = fixture.authority();
        assert!(
            crate::deepseek_pool::enabled(),
            "controlled token enables the old branch"
        );
        let who = identity("DEV-1");
        let error = dispatch_to_engine(
            &binding,
            &authority,
            &EngineRequest {
                agent: "DEV-1",
                prompt: "controlled pool-route check",
                custom: None,
                environment: &[],
                git_signing: &BoundGitSigning::default(),
                identity: &who,
            },
        )
        .unwrap_err();
        assert_eq!(error, "pool_execution_binding_unsupported");
        return;
    }
    let (_temporary, worker) = fake_child();
    let fixture = BindingFixture::new();
    let binding = fixture.bind();
    let authority = fixture.authority();
    let foreign = BindingFixture::new();
    let mut command = Command::new(worker);
    command.arg("--cwd").arg(binding.execution_root());
    if mode == "explicit" || mode == "trusted" {
        command.envs(hostile_git_environment(foreign.root()));
    }
    let reply = if mode == "trusted" {
        let signing = seat_signing::build(
            "RUST",
            &PathBuf::from(user_home()),
            binding.execution_root(),
            None,
        );
        assert!(signing.is_active());
        let trusted = BoundGitSigning::from_generated("RUST", &binding, &signing).unwrap();
        let mut changed = seat_signing::SeatSigning {
            env: signing.env.clone(),
            warning: None,
        };
        changed.env.push((
            "GIT_CONFIG_PARAMETERS".into(),
            "'core.worktree=untrusted'".into(),
        ));
        assert!(BoundGitSigning::from_generated("RUST", &binding, &changed).is_err());
        run_bound_local_command_with_signing(&binding, &authority, &mut command, &trusted).unwrap()
    } else {
        run_bound_local_command(&binding, &authority, &mut command).unwrap()
    };
    assert!(reply.contains("git_ok=true"), "{reply}");
    assert!(
        reply.contains(&format!("git_root={}", binding.execution_root().display())),
        "{reply}"
    );
    let names = reply
        .lines()
        .find_map(|line| line.strip_prefix("git_names="))
        .unwrap();
    let unexpected: Vec<_> = names
        .split(',')
        .filter(|name| {
            !name.is_empty()
                && !(mode == "trusted"
                    && (*name == "GIT_CONFIG_COUNT"
                        || name
                            .strip_prefix("GIT_CONFIG_KEY_")
                            .or_else(|| name.strip_prefix("GIT_CONFIG_VALUE_"))
                            .and_then(|index| index.parse::<usize>().ok())
                            .is_some_and(|index| index < 6)))
                && !matches!(
                    *name,
                    "GIT_CONFIG_GLOBAL"
                        | "GIT_CONFIG_SYSTEM"
                        | "GIT_CONFIG_NOSYSTEM"
                        | "GIT_ATTR_NOSYSTEM"
                        | "GIT_NO_REPLACE_OBJECTS"
                        | "GIT_OPTIONAL_LOCKS"
                        | "GIT_TERMINAL_PROMPT"
                )
        })
        .collect();
    assert!(
        unexpected.is_empty(),
        "untrusted Git controls reached actual worker: {unexpected:?}"
    );
    if mode == "trusted" {
        assert!(reply.contains("git_count=6"), "{reply}");
        assert!(reply.contains("git_user_name=RUST (agent)"), "{reply}");
    }
}
