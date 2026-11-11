//! Daemon-independent read-only adapter. No key loader or create-on-open bus path.
#![forbid(unsafe_code)]
use crate::bus_recovery::{self as model, Check, Conclusion, DeploymentRecord, Diagnosis};
use rustix::fs::{Mode, OFlags, fcntl_getfl, fcntl_setfl, openat};
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type FileSnapshot = (u64, u64, u32, u32, u64, u64, i64, i64, i64, i64);
fn snapshot(m: &Metadata) -> FileSnapshot {
    (
        m.dev(),
        m.ino(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn open_read_only(path: &str, owner_record: bool) -> Result<File, &'static str> {
    if !model::absolute_path(path) {
        return Err("invalid_absolute_path");
    }
    let parts: Vec<_> = Path::new(path)
        .components()
        .filter_map(|c| {
            if let Component::Normal(n) = c {
                Some(n)
            } else {
                None
            }
        })
        .collect();
    let mut parent = File::open("/").map_err(|_| "root_unavailable")?;
    for part in &parts[..parts.len() - 1] {
        parent = File::from(
            openat(
                &parent,
                *part,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| "path_component_unavailable_or_symlink")?,
        );
    }
    let uid = rustix::process::geteuid().as_raw();
    let pm = parent
        .metadata()
        .map_err(|_| "parent_metadata_unavailable")?;
    if owner_record && (pm.uid() != uid || pm.mode() & 0o022 != 0) {
        return Err("record_parent_not_owner_controlled");
    }
    let file = File::from(
        openat(
            &parent,
            *parts.last().ok_or("invalid_leaf")?,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "file_missing_inaccessible_or_symlink")?,
    );
    let m = file.metadata().map_err(|_| "metadata_unavailable")?;
    if !m.is_file()
        || m.nlink() != 1
        || m.mode() & 0o022 != 0
        || (m.uid() != uid && (owner_record || m.uid() != 0))
    {
        return Err("unsafe_file_type_owner_links_or_mode");
    }
    Ok(file)
}
/// Hash a selected regular file with pinned descriptors and a strict byte cap.
/// This detects observed changes, not a hostile same-UID writer after return.
pub(crate) fn read_selected(
    path: &str,
    cap: u64,
    owner_record: bool,
    retain: bool,
) -> Result<(Vec<u8>, String), &'static str> {
    let mut file = open_read_only(path, owner_record)?;
    let before = file.metadata().map_err(|_| "metadata_unavailable")?;
    if before.len() > cap {
        return Err("file_size_limit");
    }
    let mut bytes = Vec::new();
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 16384];
    loop {
        let n = file.read(&mut buffer).map_err(|_| "read_unavailable")?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > cap {
            return Err("file_size_limit");
        }
        hash.update(&buffer[..n]);
        if retain {
            bytes.extend_from_slice(&buffer[..n]);
        }
    }
    let after = file.metadata().map_err(|_| "metadata_unavailable")?;
    let rebound = open_read_only(path, owner_record)?
        .metadata()
        .map_err(|_| "metadata_unavailable")?;
    if total != before.len()
        || snapshot(&before) != snapshot(&after)
        || snapshot(&before) != snapshot(&rebound)
    {
        return Err("file_changed_during_observation");
    }
    Ok((bytes, format!("{:x}", hash.finalize())))
}
struct Probe {
    success: bool,
    stdout: Vec<u8>,
    hash: String,
}
fn drain(pipe: &mut impl Read, bytes: &mut Vec<u8>, total: &mut usize) -> Result<(), &'static str> {
    let mut chunk = [0u8; 4096];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                *total += n;
                if *total > 32_768 {
                    return Err("probe_output_limit");
                }
                bytes.extend_from_slice(&chunk[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err("probe_read_unavailable"),
        }
    }
}
/// Only fixed OS executables are passed by production callers. Each child is
/// directly owned, read nonblocking, and killed and reaped on timeout/cap/error.
fn probe(executable: &str, args: &[&str], deadline: Duration) -> Result<Probe, &'static str> {
    let mut child = Command::new(executable)
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "probe_executable_missing_or_inaccessible")?;
    let result = (|| {
        let mut stdout = child.stdout.take().ok_or("probe_pipe_missing")?;
        let mut stderr = child.stderr.take().ok_or("probe_pipe_missing")?;
        for flags in [fcntl_getfl(&stdout), fcntl_getfl(&stderr)] {
            flags.map_err(|_| "probe_pipe_flags")?;
        }
        fcntl_setfl(
            &stdout,
            fcntl_getfl(&stdout).map_err(|_| "probe_pipe_flags")? | OFlags::NONBLOCK,
        )
        .map_err(|_| "probe_pipe_flags")?;
        fcntl_setfl(
            &stderr,
            fcntl_getfl(&stderr).map_err(|_| "probe_pipe_flags")? | OFlags::NONBLOCK,
        )
        .map_err(|_| "probe_pipe_flags")?;
        let start = Instant::now();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut total = 0;
        loop {
            drain(&mut stdout, &mut out, &mut total)?;
            drain(&mut stderr, &mut err, &mut total)?;
            if let Some(status) = child.try_wait().map_err(|_| "probe_wait_unavailable")? {
                drain(&mut stdout, &mut out, &mut total)?;
                drain(&mut stderr, &mut err, &mut total)?;
                let mut hash = Sha256::new();
                hash.update(&out);
                hash.update([0]);
                hash.update(&err);
                return Ok(Probe {
                    success: status.success(),
                    stdout: out,
                    hash: format!("{:x}", hash.finalize()),
                });
            }
            if start.elapsed() >= deadline {
                return Err("probe_deadline");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
fn unknown(name: &'static str, reason: &'static str, t: u64, next: &'static str) -> Check {
    Check::new(name, Conclusion::Unknown, reason, t, None, next)
}
fn live_checks(record: &DeploymentRecord, t: u64, checks: &mut Vec<Check>) {
    let deadline = Duration::from_secs(2);
    match probe("/usr/sbin/scutil", &["--get", "LocalHostName"], deadline) {
        Ok(p) if p.success => {
            let host = std::str::from_utf8(&p.stdout).unwrap_or("").trim();
            checks.push(Check::new(
                "host_role_binding",
                if host == record.host_binding {
                    Conclusion::Observed
                } else {
                    Conclusion::Refused
                },
                if host == record.host_binding {
                    "local_host_name_matches_selected_role_claim"
                } else {
                    "host_name_does_not_match_deployment"
                },
                t,
                Some(p.hash),
                "Qualify the actual node role against the named operator's inventory",
            ));
        }
        Ok(p) => checks.push(Check::new(
            "host_role_binding",
            Conclusion::Unknown,
            "host_name_query_failed",
            t,
            Some(p.hash),
            "Read the exact host LocalHostName",
        )),
        Err(e) => checks.push(unknown(
            "host_role_binding",
            e,
            t,
            "Read the exact host LocalHostName",
        )),
    }
    match read_selected(&record.service_plist, model::MAX_RECORD_BYTES, false, false) {
        Ok((_, before)) => {
            let result = probe(
                "/usr/bin/plutil",
                &["-convert", "json", "-o", "-", "--", &record.service_plist],
                deadline,
            );
            let unchanged =
                read_selected(&record.service_plist, model::MAX_RECORD_BYTES, false, false)
                    .is_ok_and(|(_, h)| h == before);
            match result {
                Ok(p) if p.success && unchanged => {
                    let parsed = serde_json::from_slice::<serde_json::Value>(&p.stdout);
                    let matched = parsed.as_ref().is_ok_and(|v| {
                        let program = v.get("Program").and_then(|v| v.as_str()).or_else(|| {
                            v.get("ProgramArguments")
                                .and_then(|v| v.get(0))
                                .and_then(|v| v.as_str())
                        });
                        v.get("Label").and_then(|v| v.as_str())
                            == Some(record.service_label.as_str())
                            && program == Some(record.binary_path.as_str())
                    });
                    checks.push(Check::new("service_plist_binding",if matched{Conclusion::Observed}else{Conclusion::Refused},if matched{"plist_label_and_program_match_selected_deployment"}else{"plist_missing_or_contradictory_label_or_program"},t,Some(before),"Compare exact plist arguments, repository and native-route pins with current job"));
                }
                Ok(p) => checks.push(Check::new(
                    "service_plist_binding",
                    Conclusion::Unknown,
                    if unchanged {
                        "plist_query_failed"
                    } else {
                        "plist_changed_during_observation"
                    },
                    t,
                    Some(p.hash),
                    "Read the exact selected plist without changing it",
                )),
                Err(e) => checks.push(unknown(
                    "service_plist_binding",
                    e,
                    t,
                    "Read the exact selected plist without changing it",
                )),
            }
        }
        Err(e) => checks.push(unknown(
            "service_plist_binding",
            e,
            t,
            "Read the exact selected plist without changing it",
        )),
    }
    let target = format!("{}/{}", record.service_domain, record.service_label);
    match probe("/bin/launchctl", &["print", &target], deadline) {
        Ok(p) if p.success => {
            let text = std::str::from_utf8(&p.stdout).unwrap_or("");
            let target_matches = text
                .lines()
                .next()
                .is_some_and(|line| line.starts_with(&format!("{target} = {{")));
            let program_matches = text
                .lines()
                .any(|line| line.trim() == format!("program = {}", record.binary_path));
            let running = text.lines().any(|line| line.trim() == "state = running");
            checks.push(Check::new(
                "service_job",
                if target_matches && program_matches && running {
                    Conclusion::Observed
                } else {
                    Conclusion::Unknown
                },
                if target_matches && program_matches && running {
                    "exact_named_job_reports_running_and_selected_program"
                } else {
                    "job_output_does_not_prove_running_selected_program"
                },
                t,
                Some(p.hash),
                "Correlate current owned daemon handle, generation and selected native path",
            ));
        }
        Ok(p) => checks.push(Check::new(
            "service_job",
            Conclusion::Unknown,
            "exact_named_job_missing_inaccessible_or_not_loaded",
            t,
            Some(p.hash),
            "Read exact launchctl domain/label; do not bootstrap or kickstart",
        )),
        Err(e) => checks.push(unknown(
            "service_job",
            e,
            t,
            "Read exact launchctl domain/label; do not bootstrap or kickstart",
        )),
    }
}
pub fn diagnose(path: &str, offline: bool) -> Diagnosis {
    let t = now();
    let mut report = Diagnosis {
        schema: "chinwag.native-recovery-diagnosis.v1",
        side_effects: "NONE_READ_ONLY_NO_KEYS_NO_PUBLICATION_NO_RESTART",
        offline,
        record_sha256: None,
        record_claims_authenticated: false,
        selected_deployment: None,
        checks: Vec::new(),
        transport_recovery: "UNKNOWN",
        processing_or_task_start: "NOT_OBSERVED",
        effectful_recovery: "HELD_NO_OPERATOR_AUTHORITY_OR_EFFECTFUL_ADAPTER",
    };
    let (bytes, hash) = match read_selected(path, model::MAX_RECORD_BYTES, true, true) {
        Ok(v) => v,
        Err(e) => {
            report.checks.push(unknown(
                "deployment_record",
                e,
                t,
                "Select an absolute owner-controlled public deployment JSON record",
            ));
            return report;
        }
    };
    report.record_sha256 = Some(hash.clone());
    let record: DeploymentRecord = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => {
            report.checks.push(Check::new(
                "deployment_record",
                Conclusion::Refused,
                "invalid_json_duplicate_unknown_or_missing_fields",
                t,
                Some(hash),
                "Provide the strict deployment schema without secrets or authority claims",
            ));
            return report;
        }
    };
    if let Err(e) = record.validate() {
        report.checks.push(Check::new(
            "deployment_record",
            Conclusion::Refused,
            e,
            t,
            Some(hash),
            "Correct the exact public deployment bindings; no discovery or repair is performed",
        ));
        return report;
    }
    report.checks.push(Check::new(
        "deployment_record",
        Conclusion::Observed,
        "bounded_owner_controlled_record_read_input_claims_unauthenticated",
        t,
        Some(hash),
        "Compare observations below with current independent deployment inventory",
    ));
    report.checks.push(Check::new(
        "record_freshness",
        if record.captured_at_unix <= t && t < record.expires_at_unix {
            Conclusion::Observed
        } else {
            Conclusion::Refused
        },
        if record.captured_at_unix <= t && t < record.expires_at_unix {
            "record_within_declared_time_window"
        } else {
            "record_stale_or_future_dated"
        },
        t,
        None,
        "Acquire a fresh public record from the actual deployment owner",
    ));
    match read_selected(&record.binary_path, 536_870_912, false, false) {
        Ok((_, hash)) => {
            let matched = hash == record.binary_sha256;
            report.checks.push(Check::new(
                "binary_bytes",
                if matched {
                    Conclusion::Observed
                } else {
                    Conclusion::Refused
                },
                if matched {
                    "selected_binary_hash_matches_record_claim"
                } else {
                    "selected_binary_hash_mismatch"
                },
                t,
                Some(hash),
                "Verify signed build provenance for these exact bytes",
            ));
        }
        Err(e) => report.checks.push(unknown(
            "binary_bytes",
            e,
            t,
            "Read and hash only the exact selected binary",
        )),
    }
    report.checks.push(unknown(
        "build_provenance",
        "record_source_commit_is_an_unauthenticated_claim_not_a_build_attestation",
        t,
        "Verify signed source/tree/build/binary binding for the selected binary hash",
    ));
    report.checks.push(Check::new(
        "diagnostic_handler",
        Conclusion::Observed,
        "this_invoked_candidate_registered_recovery_handler_not_selected_service_binary_capability",
        t,
        None,
        "Run this command using the exact independently qualified deployment binary",
    ));
    report.checks.push(Check::new("native_route_configuration",Conclusion::Observed,"selected_relay_only_configuration_structurally_valid_not_live_protocol_proof",t,None,"Observe authenticated selected-relay connection against the exact endpoint/configuration/generation"));
    report.checks.push(Check::new(
        "route_lifecycle",
        match record.route_lifecycle {
            model::RouteLifecycle::Temporary => Conclusion::Refused,
            _ => Conclusion::Unknown,
        },
        match record.route_lifecycle {
            model::RouteLifecycle::Temporary => "temporary_origin_is_not_durable_hosting",
            _ => "declared_route_lifecycle_has_no_current_hosting_attestation",
        },
        t,
        None,
        "Qualify the required native blind-relay service and its current durable hosting record",
    ));
    if offline {
        for check in ["host_role_binding", "service_plist_binding", "service_job"] {
            report.checks.push(unknown(
                check,
                "offline_mode_no_child_or_network_probes",
                t,
                "Repeat the same selected-record diagnostic without --offline",
            ));
        }
    } else {
        live_checks(&record, t, &mut report.checks);
    }
    report.checks.push(unknown(
        "current_dns",
        "no_bounded_native_dns_adapter_registered",
        t,
        "Use an independently bounded read-only DNS observation for the selected native origin",
    ));
    report.checks.push(unknown(
        "native_protocol",
        "no_authenticated_daemon_independent_selected_relay_observation_adapter",
        t,
        "Read exact original ID/digest receipts; never resend to infer delivery",
    ));
    report.checks.push(unknown("operator_authority","public_record_and_actor_labels_cannot_grant_recovery_or_cloud_capability",t,"Obtain actual finite operator grant bound to exact hosts, operation, hashes, scope and deadline"));
    if let Some(capture) = &record.captured_failure {
        report.checks.push(Check::new(
            "captured_failure",
            Conclusion::Unknown,
            format!(
                "historical_unauthenticated_capture:{}:at:{};not_current_failure_proof",
                capture.category, capture.observed_at_unix
            ),
            t,
            Some(capture.evidence_sha256.clone()),
            "Correlate the exact historical receipt with a fresh bounded read-only observation",
        ));
    }
    report.selected_deployment = Some(record);
    report
}
pub fn run_recovery_cli(args: &[String], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let json = match args.first().map(String::as_str) {
        Some("sop") if args.len() == 2 && args[1] == "--json" => {
            serde_json::json!({"schema":"chinwag.native-recovery-sop.v1","side_effects":"NONE","steps":model::sop_steps()})
        }
        Some("diagnose") => {
            let mut deployment = None;
            let mut offline = false;
            let mut json = false;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--deployment" if deployment.is_none() && i + 1 < args.len() => {
                        deployment = Some(args[i + 1].as_str());
                        i += 2;
                    }
                    "--offline" if !offline => {
                        offline = true;
                        i += 1;
                    }
                    "--json" if !json => {
                        json = true;
                        i += 1;
                    }
                    _ => {
                        let _ = writeln!(stderr, "chinwag bus recovery: invalid_arguments");
                        return 2;
                    }
                }
            }
            let Some(path) = deployment.filter(|p| model::absolute_path(p)) else {
                let _ = writeln!(
                    stderr,
                    "chinwag bus recovery: absolute_deployment_record_required"
                );
                return 2;
            };
            if !json {
                let _ = writeln!(stderr, "chinwag bus recovery: --json_required");
                return 2;
            }
            match serde_json::to_value(diagnose(path, offline)) {
                Ok(v) => v,
                Err(_) => return 1,
            }
        }
        _ => {
            let _ = writeln!(
                stderr,
                "Usage: chinwag bus recovery diagnose --deployment ABSOLUTE_RECORD_JSON [--offline] --json\n       chinwag bus recovery sop --json"
            );
            return 2;
        }
    };
    if writeln!(stdout, "{json}").is_ok() {
        0
    } else {
        1
    }
}
#[cfg(test)]
mod probe_tests {
    use super::*;
    #[test]
    fn probe_deadline_and_output_cap_are_enforced() {
        assert!(matches!(
            probe("/bin/sleep", &["60"], Duration::from_millis(20)),
            Err("probe_deadline")
        ));
        assert!(matches!(
            probe("/usr/bin/yes", &[], Duration::from_secs(1)),
            Err("probe_output_limit")
        ));
    }
}
