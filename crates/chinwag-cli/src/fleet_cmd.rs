// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

//! Manifest driven fleet inspection and execution. No organization policy lives here.

use chinwag_fleet::{
    DispatchRequest, ExecutionContext, ExecutionDriver, ExecutionOutcome, FleetManifest,
    KeyBijectionValidator, ProcessExecutionDriver, ResolvedDispatchPlan, prepare_execution_sandbox,
    release_execution_sandbox, resolve_dispatch_plan,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const HELP: &str = "Usage: chinwag fleet init --profile <solo|mesh|airgapped|cloud-pool>\n       chinwag fleet validate [--manifest <PATH>] [--strict-keys] [--json]\n       chinwag fleet status [--manifest <PATH>] [--json]\n       chinwag fleet explain --seat <SEAT> [--room <ROOM>] [--task-profile <NAME>] [--manifest <PATH>] [--json]\n       chinwag fleet launch --seat <SEAT> [--cwd <PATH>] [--skill <NAME>...] [--mode <interactive|headless>] [--manifest <PATH>]\n";

/// Explicit path, then process configuration, then the current workspace.
pub fn manifest_path(explicit: Option<&Path>, cwd: &Path) -> PathBuf {
    let path = explicit
        .map(Path::to_path_buf)
        .or_else(|| {
            std::env::var_os("CHINWAG_FLEET_MANIFEST")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from(".chinwag/fleet.toml"));
    if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    }
}

pub fn load_manifest(
    explicit: Option<&Path>,
    cwd: &Path,
) -> Result<(PathBuf, FleetManifest), String> {
    let path = manifest_path(explicit, cwd);
    let manifest = FleetManifest::load(&path).map_err(|error| error.to_string())?;
    Ok((path, manifest))
}

#[derive(Default)]
struct Options {
    values: BTreeMap<String, String>,
    skills: Vec<String>,
    json: bool,
    strict_keys: bool,
}

impl Options {
    fn parse(command: &str, args: &[String]) -> Result<Self, String> {
        let mut options = Self::default();
        let mut index = 0;
        while index < args.len() {
            let flag = args[index].as_str();
            match flag {
                "--json"
                    if matches!(command, "validate" | "status" | "explain") && !options.json =>
                {
                    options.json = true
                }
                "--strict-keys" if command == "validate" && !options.strict_keys => {
                    options.strict_keys = true
                }
                "--manifest" | "--fleet-manifest" | "--profile" | "--seat" | "--room"
                | "--task-profile" | "--cwd" | "--mode" | "--skill" => {
                    let permitted = match flag {
                        "--manifest" | "--fleet-manifest" => true,
                        "--profile" => command == "init",
                        "--seat" | "--room" | "--task-profile" => {
                            matches!(command, "explain" | "launch")
                        }
                        "--cwd" | "--mode" | "--skill" => command == "launch",
                        _ => false,
                    };
                    if !permitted {
                        return Err(format!("invalid_arguments: {flag}"));
                    }
                    index += 1;
                    let value = args
                        .get(index)
                        .filter(|value| !value.is_empty() && !value.starts_with("--"))
                        .ok_or_else(|| format!("missing_argument: {flag}"))?;
                    if flag == "--skill" {
                        options.skills.push(value.clone());
                    } else if options
                        .values
                        .insert(flag.to_owned(), value.clone())
                        .is_some()
                    {
                        return Err(format!("duplicate_argument: {flag}"));
                    }
                }
                _ => return Err(format!("invalid_arguments: {flag}")),
            }
            index += 1;
        }
        if options.values.contains_key("--manifest")
            && options.values.contains_key("--fleet-manifest")
        {
            return Err("duplicate_argument: --manifest".into());
        }
        Ok(options)
    }
    fn value(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }
    fn manifest(&self) -> Option<&Path> {
        self.value("--manifest")
            .or(self.value("--fleet-manifest"))
            .map(Path::new)
    }
}

pub fn run_fleet_cli(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(error) => {
            let _ = writeln!(err, "chinwag: {error}");
            return 2;
        }
    };
    run_fleet_cli_at(args, &cwd, out, err)
}

/// Explicit workspace entry point also keeps tests independent of process cwd and HOME.
pub fn run_fleet_cli_at(
    args: &[String],
    cwd: &Path,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    if args.is_empty()
        || args
            .iter()
            .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        return if out.write_all(HELP.as_bytes()).is_ok() {
            0
        } else {
            1
        };
    }
    let result = run_command(args, cwd);
    match result {
        Ok((response, json_mode, code)) => {
            let rendered = if json_mode {
                serde_json::to_string(&response)
            } else {
                serde_json::to_string_pretty(&response)
            };
            match rendered {
                Ok(rendered) if writeln!(out, "{rendered}").is_ok() => code,
                _ => 1,
            }
        }
        Err(error) => {
            let response = json!({"ok": false, "error": error});
            if args.iter().any(|arg| arg == "--json") {
                let _ = writeln!(out, "{response}");
            }
            let _ = writeln!(err, "chinwag: fleet: {error}");
            2
        }
    }
}

fn run_command(args: &[String], cwd: &Path) -> Result<(Value, bool, u8), String> {
    let command = args[0].as_str();
    if !matches!(
        command,
        "init" | "validate" | "status" | "explain" | "launch"
    ) {
        return Err("unknown_fleet_command".into());
    }
    let options = Options::parse(command, &args[1..])?;
    if command == "init" {
        let profile = options
            .value("--profile")
            .ok_or("missing_argument: --profile")?;
        let manifest =
            FleetManifest::starter_profile(profile).map_err(|error| error.to_string())?;
        let path = manifest_path(options.manifest(), cwd);
        let parent = path.parent().ok_or("invalid_manifest_path")?;
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        let content = manifest.to_toml().map_err(|error| error.to_string())?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|error| format!("manifest_not_created: {error}"))?;
        file.write_all(content.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| error.to_string())?;
        return Ok((
            json!({"ok": true, "manifest": path, "profile": profile}),
            false,
            0,
        ));
    }
    let path = manifest_path(options.manifest(), cwd);
    if command == "status" && !path.exists() {
        return Ok((
            json!({"ok": true, "status": "unconfigured (no fleet manifest)", "manifest": path, "seats": []}),
            options.json,
            0,
        ));
    }
    let (_, manifest) = load_manifest(Some(&path), cwd)?;
    if command == "validate" {
        manifest.validate().map_err(|error| error.to_string())?;
        KeyBijectionValidator::validate(&manifest, options.strict_keys)
            .map_err(|error| error.to_string())?;
        return Ok((
            json!({"ok": true, "manifest": path, "schema_version": manifest.schema_version, "seats": manifest.seats.len(), "nodes": manifest.nodes.len(), "strict_keys": options.strict_keys}),
            options.json,
            0,
        ));
    }
    if command == "status" {
        return Ok((
            json!({"ok": true, "status": "configured", "manifest": path, "schema_version": manifest.schema_version, "seats": manifest.seats, "nodes": manifest.nodes, "policy": manifest.policy}),
            options.json,
            0,
        ));
    }
    let seat = options.value("--seat").ok_or("missing_argument: --seat")?;
    let execution_cwd = match options.value("--cwd").map(PathBuf::from) {
        Some(path) if path.is_absolute() => path,
        Some(path) => cwd.join(path),
        None => cwd.to_path_buf(),
    };
    let request = DispatchRequest {
        seat: seat.to_owned(),
        room: options.value("--room").map(str::to_owned),
        task_profile: options.value("--task-profile").map(str::to_owned),
        cwd: execution_cwd,
        requested_skills: options.skills.clone(),
        requested_write_globs: manifest
            .seat(seat)
            .map(|definition| definition.allowed_write_roots.clone())
            .unwrap_or_default(),
        ..Default::default()
    };
    let plan = resolve_dispatch_plan(&manifest, &request).map_err(|error| error.to_string())?;
    if command == "explain" {
        return Ok((
            json!({"ok": true, "manifest": path, "plan": plan}),
            options.json,
            0,
        ));
    }
    let interactive = match options.value("--mode").unwrap_or("headless") {
        "interactive" => true,
        "headless" => false,
        _ => return Err("invalid_mode".into()),
    };
    let instance = crate::agent_instance::new_instance_id().map_err(|error| error.to_string())?;
    let actor = format!("{}#{instance}", plan.seat.as_str());
    let mut context = ExecutionContext {
        interactive,
        ..Default::default()
    };
    context.env.insert("CHINWAG_ACTOR".into(), actor.clone());
    context.env.insert("CHINWAG_INSTANCE_ID".into(), instance);
    if let Ok(caller) = std::env::var("CHINWAG_ACTOR") {
        let (seat, _) = caller.split_once('#').ok_or("BareSeatAddressRejected")?;
        let seat = chinwag_fleet::SeatId::new(seat).map_err(|error| error.to_string())?;
        chinwag_fleet::validate_actor(&seat, &caller).map_err(|error| error.to_string())?;
        context
            .env
            .insert("CHINWAG_CALLER".into(), caller.to_string());
        context
            .env
            .insert("CHINWAG_PARENT_INSTANCE".into(), caller.to_string());
    }
    let outcome = execute_plan(&manifest, &plan, &context, &actor)?;
    let code = if outcome.success { 0 } else { 1 };
    Ok((
        json!({"ok": outcome.success, "seat": plan.seat, "exit_code": outcome.exit_code, "stdout": outcome.stdout, "stderr": outcome.stderr}),
        false,
        code,
    ))
}

/// Every mutating launch passes the same path lease and isolation gate as wakes.
pub fn execute_plan(
    manifest: &FleetManifest,
    plan: &ResolvedDispatchPlan,
    context: &ExecutionContext,
    actor: &str,
) -> Result<ExecutionOutcome, String> {
    let claim_root = plan.cwd.join(".chinwag/fleet-claims");
    execute_plan_with_claim_root(manifest, plan, context, actor, &claim_root, || Ok(()))
}

/// A native workspace binding supplies a pinned bookkeeping root and revalidation guard.
pub fn execute_plan_with_claim_root(
    manifest: &FleetManifest,
    plan: &ResolvedDispatchPlan,
    context: &ExecutionContext,
    actor: &str,
    claim_root: &Path,
    validate_binding: impl Fn() -> Result<(), String>,
) -> Result<ExecutionOutcome, String> {
    validate_binding()?;
    let allowed_write_roots =
        serde_json::to_string(&plan.allowed_write_roots).map_err(|error| error.to_string())?;
    let receipt = prepare_execution_sandbox(manifest, plan, claim_root, actor)
        .map_err(|error| error.to_string())?;
    let mut context = context.clone();
    context
        .env
        .insert("CHINWAG_AGENT".into(), plan.seat.to_string());
    context
        .env
        .insert("CHINWAG_REPO_ROOT".into(), plan.cwd.display().to_string());
    context.env.insert(
        "CHINWAG_EXECUTION_CWD".into(),
        receipt.isolated_cwd.display().to_string(),
    );
    context.env.insert(
        "CHINWAG_WORKSPACE_CLAIM_ID".into(),
        receipt.claim_id.clone(),
    );
    context
        .env
        .insert("CHINWAG_ALLOWED_WRITE_ROOTS".into(), allowed_write_roots);
    let result = (|| {
        validate_binding()?;
        let isolated = plan
            .clone()
            .with_sandbox(claim_root, &receipt)
            .map_err(|error| error.to_string())?;
        validate_binding()?;
        let outcome = ProcessExecutionDriver
            .execute(&isolated, &context)
            .map_err(|error| error.to_string())?;
        validate_binding()?;
        Ok(outcome)
    })();
    let release = release_execution_sandbox(claim_root, &receipt, result.is_err())
        .map_err(|error| error.to_string());
    match (result, release) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(error), _) => Err(error),
        (_, Err(error)) => Err(format!("execution_completed_lease_release_failed: {error}")),
    }
}
