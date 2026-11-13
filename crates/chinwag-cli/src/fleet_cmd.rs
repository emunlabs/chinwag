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
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

const HELP: &str = "Usage: chinwag fleet init --profile <solo|mesh|airgapped|cloud-pool>\n       chinwag fleet validate [--manifest <PATH>] [--strict-keys] [--json]\n       chinwag fleet status [--manifest <PATH>] [--json]\n       chinwag fleet explain --seat <SEAT> [--room <ROOM>] [--task-profile <NAME>] [--cwd <PATH>] [--skill <NAME>...] [--manifest <PATH>] [--json]\n       chinwag fleet launch --seat <SEAT> [--room <ROOM>] [--task-profile <NAME>] [--cwd <PATH>] [--skill <NAME>...] [--prompt <TEXT>] [--timeout <SECS>] [--mode <interactive|headless>] [--manifest <PATH>] [--json]\n";

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
            let raw_flag = args[index].as_str();
            let flag = if raw_flag == "-p" {
                "--prompt"
            } else {
                raw_flag
            };
            match flag {
                "--json"
                    if matches!(command, "validate" | "status" | "explain" | "launch")
                        && !options.json =>
                {
                    options.json = true
                }
                "--strict-keys" if command == "validate" && !options.strict_keys => {
                    options.strict_keys = true
                }
                "--manifest" | "--fleet-manifest" | "--profile" | "--seat" | "--room"
                | "--task-profile" | "--cwd" | "--mode" | "--skill" | "--prompt" | "--timeout" => {
                    let permitted = match flag {
                        "--manifest" | "--fleet-manifest" => true,
                        "--profile" => command == "init",
                        "--seat" | "--room" | "--task-profile" | "--cwd" | "--skill" => {
                            matches!(command, "explain" | "launch")
                        }
                        "--mode" | "--prompt" | "--timeout" => command == "launch",
                        _ => false,
                    };
                    if !permitted {
                        return Err(format!("invalid_arguments: {raw_flag}"));
                    }
                    index += 1;
                    let value = args
                        .get(index)
                        .filter(|value| {
                            !value.is_empty() && (flag == "--prompt" || !value.starts_with("--"))
                        })
                        .ok_or_else(|| format!("missing_argument: {raw_flag}"))?;
                    if flag == "--skill" {
                        options.skills.push(value.clone());
                    } else if options
                        .values
                        .insert(flag.to_owned(), value.clone())
                        .is_some()
                    {
                        return Err(format!("duplicate_argument: {raw_flag}"));
                    }
                }
                _ => return Err(format!("invalid_arguments: {raw_flag}")),
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
    let timeout_override_secs = options
        .value("--timeout")
        .map(|raw| {
            raw.parse::<u64>()
                .ok()
                .filter(|secs| *secs > 0)
                .ok_or_else(|| "invalid_timeout".to_owned())
        })
        .transpose()?;
    let (actor, instance) = allocate_child_actor(plan.seat.as_str())?;
    let mut context = ExecutionContext {
        interactive,
        prompt: options.value("--prompt").map(str::to_owned),
        timeout_override_secs,
        ..Default::default()
    };
    install_actor_lineage(&mut context, &actor, &instance)?;
    let outcome = execute_plan(&manifest, &plan, &context, &actor)?;
    let code = if outcome.success { 0 } else { 1 };
    Ok((
        json!({
            "ok": outcome.success,
            "seat": plan.seat,
            "actor": actor,
            "model": plan.model,
            "exit_code": outcome.exit_code,
            "timed_out": outcome.timed_out,
            "stdout": outcome.stdout,
            "stderr": outcome.stderr
        }),
        options.json,
        code,
    ))
}

fn allocate_child_actor(seat: &str) -> Result<(String, String), String> {
    let instance = crate::agent_instance::new_instance_id().map_err(|error| error.to_string())?;
    Ok((format!("{seat}#{instance}"), instance))
}

fn install_actor_lineage(
    context: &mut ExecutionContext,
    actor: &str,
    instance: &str,
) -> Result<(), String> {
    context.env.insert("CHINWAG_ACTOR".into(), actor.to_owned());
    context
        .env
        .insert("CHINWAG_INSTANCE_ID".into(), instance.to_owned());
    if let Ok(caller) = std::env::var("CHINWAG_ACTOR") {
        let (seat, _) = caller.split_once('#').ok_or("BareSeatAddressRejected")?;
        let seat = chinwag_fleet::SeatId::new(seat).map_err(|error| error.to_string())?;
        chinwag_fleet::validate_actor(&seat, &caller).map_err(|error| error.to_string())?;
        context.env.insert("CHINWAG_CALLER".into(), caller.clone());
        context.env.insert("CHINWAG_PARENT_INSTANCE".into(), caller);
    }
    Ok(())
}

fn discover_multicall_manifest(explicit: Option<&Path>, cwd: &Path) -> PathBuf {
    if let Some(path) = explicit {
        return if path.is_absolute() {
            path.to_path_buf()
        } else {
            cwd.join(path)
        };
    }
    if let Some(env_path) = std::env::var_os("CHINWAG_FLEET_MANIFEST").filter(|v| !v.is_empty()) {
        let path = PathBuf::from(env_path);
        return if path.is_absolute() {
            path
        } else {
            cwd.join(path)
        };
    }
    let workspace_manifest = cwd.join(".chinwag/fleet.toml");
    if workspace_manifest.is_file() {
        return workspace_manifest;
    }
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        let home_manifest = PathBuf::from(home).join(".chinwag/fleet.toml");
        if home_manifest.is_file() {
            return home_manifest;
        }
    }
    workspace_manifest
}

/// Dispatch symlinked `<seat>-agent` binaries through the declarative fleet manifest.
pub fn run_multicall_agent_cli(
    seat_slug: &str,
    args: &[String],
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(error) => {
            let _ = writeln!(err, "{seat_slug}-agent: {error}");
            return 2;
        }
    };
    let mut stdin = std::io::stdin();
    let is_tty = stdin.is_terminal();
    run_multicall_agent_cli_at(seat_slug, args, &cwd, &mut stdin, is_tty, out, err)
}

#[allow(clippy::too_many_arguments)]
pub fn run_multicall_agent_cli_at(
    seat_slug: &str,
    args: &[String],
    cwd: &Path,
    stdin: &mut dyn Read,
    stdin_is_terminal: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        let usage = format!(
            "Usage: {seat_slug}-agent [run] [--cwd <PATH>] [--skill <NAME>...] [--room <ROOM>] [--task-profile <NAME>] [--timeout <SECS>] [--mode <interactive|headless>] [--manifest <PATH>] [--json] [-p|--prompt <TEXT> | <PROMPT...>]\n       {seat_slug}-agent status [--manifest <PATH>] [--json]\n       {seat_slug}-agent explain [--cwd <PATH>] [--skill <NAME>...] [--room <ROOM>] [--task-profile <NAME>] [--manifest <PATH>] [--json]\n"
        );
        return if out.write_all(usage.as_bytes()).is_ok() {
            0
        } else {
            1
        };
    }

    let (subcommand, rest) = match args.first().map(String::as_str) {
        Some("status") => ("status", &args[1..]),
        Some("explain") => ("explain", &args[1..]),
        Some("run") => ("run", &args[1..]),
        _ => ("run", args),
    };

    let mut values: BTreeMap<String, String> = BTreeMap::new();
    let mut skills = Vec::new();
    let mut positional = Vec::new();
    let mut json_mode = false;
    let mut idx = 0;
    let mut after_double_dash = false;
    while idx < rest.len() {
        let raw = rest[idx].as_str();
        if after_double_dash {
            positional.push(raw.to_owned());
            idx += 1;
            continue;
        }
        if raw == "--" {
            after_double_dash = true;
            idx += 1;
            continue;
        }
        let flag = if raw == "-p" { "--prompt" } else { raw };
        match flag {
            "--json" if !json_mode => json_mode = true,
            "--manifest" | "--fleet-manifest" | "--cwd" | "--skill" | "--room"
            | "--task-profile" | "--timeout" | "--mode" | "--prompt" => {
                idx += 1;
                let Some(val) = rest
                    .get(idx)
                    .filter(|v| !v.is_empty() && (flag == "--prompt" || !v.starts_with("--")))
                else {
                    let _ = writeln!(err, "{seat_slug}-agent: missing_argument: {raw}");
                    return 2;
                };
                if flag == "--skill" {
                    skills.push(val.clone());
                } else if values.insert(flag.to_owned(), val.clone()).is_some() {
                    let _ = writeln!(err, "{seat_slug}-agent: duplicate_argument: {raw}");
                    return 2;
                }
            }
            _ if raw.starts_with('-') => {
                let _ = writeln!(err, "{seat_slug}-agent: invalid_arguments: {raw}");
                return 2;
            }
            _ => positional.push(raw.to_owned()),
        }
        idx += 1;
    }

    let explicit_manifest = values
        .get("--manifest")
        .or_else(|| values.get("--fleet-manifest"))
        .map(PathBuf::from);
    let manifest_file = discover_multicall_manifest(explicit_manifest.as_deref(), cwd);
    let manifest = match FleetManifest::load(&manifest_file) {
        Ok(m) => m,
        Err(error) => {
            if json_mode {
                let _ = writeln!(out, "{}", json!({"ok": false, "error": error.to_string()}));
            }
            let _ = writeln!(err, "{seat_slug}-agent: {error}");
            return 2;
        }
    };
    let Some(seat_def) = manifest
        .seats
        .iter()
        .find(|seat| seat.id.as_str().eq_ignore_ascii_case(seat_slug))
    else {
        let msg = format!("UnknownSeat: {seat_slug}");
        if json_mode {
            let _ = writeln!(out, "{}", json!({"ok": false, "error": msg}));
        }
        let _ = writeln!(err, "{seat_slug}-agent: {msg}");
        return 2;
    };

    if subcommand == "status" {
        let payload = json!({
            "ok": true,
            "manifest": manifest_file,
            "seat": seat_def.id,
            "display_name": seat_def.display_name,
            "lifecycle": seat_def.lifecycle,
            "model": seat_def.model,
            "target": seat_def.target_selector,
            "profile_dir": seat_def.profile_dir,
            "allowed_skills": seat_def.skills.allowed_skills,
        });
        let rendered = if json_mode {
            serde_json::to_string(&payload)
        } else {
            serde_json::to_string_pretty(&payload)
        };
        return match rendered {
            Ok(text) if writeln!(out, "{text}").is_ok() => 0,
            _ => 1,
        };
    }

    let execution_cwd = match values.get("--cwd").map(PathBuf::from) {
        Some(path) if path.is_absolute() => path,
        Some(path) => cwd.join(path),
        None => cwd.to_path_buf(),
    };
    let request = DispatchRequest {
        seat: seat_def.id.as_str().to_owned(),
        room: values.get("--room").cloned(),
        task_profile: values.get("--task-profile").cloned(),
        cwd: execution_cwd,
        requested_skills: skills,
        requested_write_globs: seat_def.allowed_write_roots.clone(),
        ..Default::default()
    };
    let plan = match resolve_dispatch_plan(&manifest, &request) {
        Ok(plan) => plan,
        Err(error) => {
            if json_mode {
                let _ = writeln!(out, "{}", json!({"ok": false, "error": error.to_string()}));
            }
            let _ = writeln!(err, "{seat_slug}-agent: {error}");
            return 2;
        }
    };
    if subcommand == "explain" {
        let payload = json!({"ok": true, "manifest": manifest_file, "plan": plan});
        let rendered = if json_mode {
            serde_json::to_string(&payload)
        } else {
            serde_json::to_string_pretty(&payload)
        };
        return match rendered {
            Ok(text) if writeln!(out, "{text}").is_ok() => 0,
            _ => 1,
        };
    }

    let interactive = match values
        .get("--mode")
        .map(String::as_str)
        .unwrap_or("headless")
    {
        "interactive" => true,
        "headless" => false,
        _ => {
            let _ = writeln!(err, "{seat_slug}-agent: invalid_mode");
            return 2;
        }
    };
    let timeout_override_secs = match values
        .get("--timeout")
        .map(|raw| {
            raw.parse::<u64>()
                .ok()
                .filter(|secs| *secs > 0)
                .ok_or_else(|| "invalid_timeout".to_owned())
        })
        .transpose()
    {
        Ok(val) => val,
        Err(msg) => {
            let _ = writeln!(err, "{seat_slug}-agent: {msg}");
            return 2;
        }
    };

    let mut prompt = values.get("--prompt").cloned();
    if prompt.is_none() && !positional.is_empty() {
        prompt = Some(positional.join(" "));
    }
    if prompt.is_none() && !stdin_is_terminal {
        let mut buf = String::new();
        if stdin.read_to_string(&mut buf).is_ok() && !buf.trim().is_empty() {
            prompt = Some(buf);
        }
    }

    let (actor, instance) = match allocate_child_actor(plan.seat.as_str()) {
        Ok(ids) => ids,
        Err(msg) => {
            let _ = writeln!(err, "{seat_slug}-agent: {msg}");
            return 2;
        }
    };
    let mut context = ExecutionContext {
        interactive,
        prompt,
        timeout_override_secs,
        ..Default::default()
    };
    if let Err(msg) = install_actor_lineage(&mut context, &actor, &instance) {
        let _ = writeln!(err, "{seat_slug}-agent: {msg}");
        return 2;
    }
    let outcome = match execute_plan(&manifest, &plan, &context, &actor) {
        Ok(outcome) => outcome,
        Err(error) => {
            if json_mode {
                let _ = writeln!(out, "{}", json!({"ok": false, "error": error}));
            }
            let _ = writeln!(err, "{seat_slug}-agent: {error}");
            return 2;
        }
    };
    let code = if outcome.success { 0 } else { 1 };
    if json_mode {
        let payload = json!({
            "ok": outcome.success,
            "seat": plan.seat,
            "actor": actor,
            "model": plan.model,
            "exit_code": outcome.exit_code,
            "timed_out": outcome.timed_out,
            "stdout": outcome.stdout,
            "stderr": outcome.stderr,
        });
        if writeln!(out, "{payload}").is_err() {
            return 1;
        }
        return code;
    }
    if !outcome.stdout.is_empty() && out.write_all(outcome.stdout.as_bytes()).is_err() {
        return 1;
    }
    if !outcome.stdout.is_empty() && !outcome.stdout.ends_with('\n') {
        let _ = out.write_all(b"\n");
    }
    if !outcome.stderr.is_empty() {
        let _ = err.write_all(outcome.stderr.as_bytes());
    }
    code
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
