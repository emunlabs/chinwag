use std::io::Write;
use std::time::{Duration, Instant};

use chinwag_confirmed_initial_private::{
    IntegrationFailure, IntegrationOwner, LocalInitializationReceipt, PrincipalLookup,
    PrincipalState, ResolvedPrincipal, SigningAttempt,
};
use chinwag_editor_config_private::install::configure_initialized;
use chinwag_signing::{GitNamespaceProof, InitMaterial, InitProgress, InitReceipt, TxState};
use serde_json::{Value, json};

use crate::{EditorSelection, InitPrincipal, InitRepository, InitRequest};

const PAUSE: Duration = Duration::from_millis(20);

pub fn run_init(request: InitRequest, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    // Reject unsupported ownership scopes before any filesystem or entropy call.
    if request.reuse.is_some() {
        return before_start_error("init_reuse_not_supported", request.reuse, out, err);
    }
    let repo = match request.repo {
        InitRepository::Explicit(repo) => repo,
        InitRepository::CurrentDirectory => match std::env::current_dir() {
            Ok(repo) => repo,
            Err(_) => return before_start_error("init_current_directory", None, out, err),
        },
    };
    let expected_private = repo.join(".chinwag");
    if request
        .private_leaf
        .as_ref()
        .is_some_and(|private| private != &expected_private)
    {
        return before_start_error("init_private_directory", None, out, err);
    }
    let started = match request.principal {
        InitPrincipal::Explicit(principal) => {
            SigningAttempt::start_fresh_private_fixture(&repo, &principal)
        }
        InitPrincipal::FromLocalConfig => {
            let resolved = match discover_principal(&repo, out, err) {
                Ok(resolved) => resolved,
                Err(code) => return code,
            };
            SigningAttempt::start_discovered(resolved)
        }
    };
    let mut attempt = match started {
        Ok(attempt) => attempt,
        Err(error) => return before_start_error(error.0, None, out, err),
    };
    loop {
        let receipt = attempt.poll(Instant::now());
        match receipt {
            InitReceipt::Config { transaction, .. }
                if matches!(transaction.state, TxState::Pending { .. }) =>
            {
                std::thread::sleep(PAUSE);
            }
            InitReceipt::Config { transaction, .. }
                if matches!(transaction.state, TxState::ChildUnknown { .. }) =>
            {
                let unknown = report(receipt, attempt.reason());
                // A failed write never releases this original unknown child.
                let _ = emit(out, &unknown);
                let _ = writeln!(err, "chinwag: {}", attempt.reason());
                loop {
                    if let Ok(Some(exit)) = attempt.observe_child() {
                        let mut observed = unknown;
                        observed["event"] = json!("original_child_observed");
                        observed["observed_exit"] = json!(exit);
                        let _ = emit(out, &observed);
                        return 3;
                    }
                    std::thread::sleep(PAUSE);
                }
            }
            InitReceipt::Config { transaction, .. }
                if matches!(transaction.state, TxState::Installed | TxState::Unchanged) =>
            {
                let mut value = report(receipt, attempt.reason());
                let token = match attempt.confirm() {
                    Ok(token) => token,
                    Err(failure) => {
                        value["result"] = json!("confirmation_failed");
                        value["stage"] = json!("confirmation");
                        value["reason"] = json!(failure.reason());
                        // Only a real terminal transaction reaches this branch.
                        drop(failure.into_original());
                        return failed_report(value, out, err);
                    }
                };
                value["signature_verified"] = json!(true);
                value["signing_confirmation"] = json!("confirmed_before_store");
                attach_proof(&mut value, token.proof());
                value["stage"] = json!("store");
                value["store_attempted"] = json!(true);
                let receipt = match token
                    .begin_initial()
                    .and_then(|owner| finish_initial(owner, request.editor, &mut value))
                {
                    Ok(receipt) => receipt,
                    Err(error) => {
                        value["result"] = json!("store_unconfirmed");
                        value["reason"] = json!(error.reason);
                        value["store_callee_completed"] =
                            json!(error.original_store_callee_completed);
                        return failed_report(value, out, err);
                    }
                };
                value["result"] = json!("local_initialized");
                value["reason"] = json!("local_initialization_confirmed");
                value["stage"] = json!("complete");
                let editor_refused = value["editor_configured"].as_bool() == Some(false);
                if editor_refused {
                    value["result"] = json!("local_initialized_editor_unconfirmed");
                    value["reason"] = value["editor"]["reason"].clone();
                    value["stage"] = json!("editor");
                }
                value["public_hex"] = json!(hex(&receipt.public_key()));
                attach_proof(&mut value, receipt.proof());
                value["store_callee_completed"] = json!(true);
                value["local_store_confirmed"] = json!(true);
                value["integrated_receipt"] = json!(true);
                value["signing_binding_current"] = json!(true);
                value["store"] = json!({
                    "site_id": hex(&receipt.store().site_id()),
                    "sha256": hex(&receipt.store().sha256()),
                    "bytes": receipt.store().bytes(),
                });
                if emit(out, &value).is_err() {
                    let _ = writeln!(err, "chinwag: output_failed");
                    return 1;
                }
                if editor_refused {
                    let reason = value["reason"].as_str().unwrap_or("editor_unconfirmed");
                    if writeln!(err, "chinwag: {reason}").is_err() {
                        return 1;
                    }
                    return 3;
                }
                return 0;
            }
            _ => return failed_report(report(receipt, attempt.reason()), out, err),
        }
    }
}

fn discover_principal(
    repo: &std::path::Path,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ResolvedPrincipal, u8> {
    let mut lookup =
        PrincipalLookup::start(repo).map_err(|error| principal_error(error.0, out, err))?;
    loop {
        match lookup.poll(Instant::now()) {
            PrincipalState::Pending { .. } => std::thread::sleep(PAUSE),
            PrincipalState::Ready => {
                return lookup.resolve().map_err(|failure| {
                    // Only the actual known terminal query reaches Ready. A failed
                    // release leaves remaining original query names occupied.
                    principal_error(failure.reason(), out, err)
                });
            }
            PrincipalState::Refused { reason } => return Err(principal_error(reason, out, err)),
            PrincipalState::Unknown { pid, reason } => {
                let mut value = principal_observation(reason);
                value["result"] = json!("principal_query_unknown");
                value["original_child_pid"] = json!(pid);
                let _ = emit(out, &value);
                let _ = writeln!(err, "chinwag: {reason}");
                // No retry, entropy, cleanup, or late Ready. Retain and observe
                // only the original child even if the output consumer is lost.
                loop {
                    if let Ok(Some(exit)) = lookup.observe_child() {
                        value["event"] = json!("original_principal_child_observed");
                        value["observed_exit"] = json!(format!("{exit:?}"));
                        let _ = emit(out, &value);
                        return Err(3);
                    }
                    std::thread::sleep(PAUSE);
                }
            }
        }
    }
}
fn principal_observation(reason: &str) -> Value {
    json!({
        "schema": 2, "event": "init_receipt", "result": "refused", "reason": reason,
        "stage": "principal_query", "principal_source": "repo_local_user_email",
        "material": "not_started", "public_hex": null,
        "signing_configured": false, "signature_verified": false,
        "signing_confirmation": "not_confirmed", "signing_binding_current": false,
        "store_attempted": false, "store_callee_completed": false, "local_store_confirmed": false,
        "integrated_receipt": false, "full_init_complete": false, "hosted_verified": false,
    })
}
fn principal_error(reason: &str, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    failed_report(principal_observation(reason), out, err)
}

fn finish_initial(
    owner: IntegrationOwner,
    editor: Option<EditorSelection>,
    value: &mut Value,
) -> Result<LocalInitializationReceipt, IntegrationFailure> {
    let Some(editor) = editor else {
        return owner.finish();
    };
    value["stage"] = json!("editor");
    value["editor_attempted"] = json!(false);
    let handoff = owner.finish_for_editor()?;
    value["store_callee_completed"] = json!(true);
    value["editor_attempted"] = json!(true);
    let configured = configure_initialized(&handoff, editor.into_editor());
    match configured {
        Ok(receipt) => {
            value["editor_configured"] = json!(true);
            value["editor"] = receipt.value().clone();
        }
        Err(failure) => {
            value["editor_configured"] = json!(false);
            value["editor"] = failure.observation().clone();
        }
    }
    // Even an editor refusal consumes the original live initializer through checked release.
    value["stage"] = json!("initial_editor_checked_finish");
    let receipt = handoff.finish()?;
    value["initial_editor_checked_fds"] = json!(receipt.directly_owned_checked_fds());
    value["initialization_binding"] = json!("original_live_signing_config_store_and_directories");
    value["local_editor_onboarding_complete"] = value["editor_configured"].clone();
    Ok(receipt)
}
fn attach_proof(value: &mut Value, proof: &GitNamespaceProof) {
    value["proof"] = json!({
        "public_hex": hex(&proof.public), "public_openssh": proof.public_openssh,
        "namespace": proof.namespace, "challenge": proof.challenge, "armored": proof.armored,
    });
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn emit(out: &mut dyn Write, value: &Value) -> std::io::Result<()> {
    writeln!(out, "{value}")?;
    out.flush()
}
fn failed_report(value: Value, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    if emit(out, &value).is_err() {
        let _ = writeln!(err, "chinwag: output_failed");
    } else {
        let reason = value["reason"].as_str().unwrap_or("init_unconfirmed");
        let _ = writeln!(err, "chinwag: {reason}");
    }
    1
}
fn before_start_error(
    reason: &str,
    pin: Option<[u8; 32]>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    failed_report(
        json!({
            "schema": 2, "event": "init_receipt", "result": "refused", "reason": reason,
            "public_hex": pin.map(|p| hex(&p)), "material": "not_started", "stage": "preflight",
            "signing_configured": false, "signature_verified": false,
            "signing_confirmation": "not_confirmed", "signing_binding_current": false,
            "store_attempted": false, "store_callee_completed": false, "local_store_confirmed": false,
            "integrated_receipt": false, "full_init_complete": false, "hosted_verified": false,
        }),
        out,
        err,
    )
}

fn report(receipt: InitReceipt, reason: &str) -> Value {
    let mut value = json!({
        "schema": 2, "event": "init_receipt", "reason": reason,
        "signing_configured": false, "signature_verified": false,
        "full_init_complete": false, "hosted_verified": false,
        "stage": "signing", "store_attempted": false,
        "store_callee_completed": false, "local_store_confirmed": false,
        "integrated_receipt": false, "signing_binding_current": false,
        "signing_confirmation": "not_confirmed",
    });
    match receipt {
        InitReceipt::Refused {
            expected_public, ..
        } => {
            value["result"] = json!("refused");
            value["material"] = json!("not_confirmed");
            value["public_hex"] = json!(hex(&expected_public));
        }
        InitReceipt::MaterialIncomplete {
            expected_public,
            progress,
            ..
        } => {
            value["result"] = json!("material_incomplete");
            value["public_hex"] = json!(hex(&expected_public));
            value["material"] = json!(match progress {
                InitProgress::LeafUnconfirmed => "leaf_unconfirmed",
                InitProgress::LeafConfirmed => "leaf_confirmed",
                InitProgress::KeyUnconfirmed => "key_unconfirmed",
                InitProgress::KeyConfirmed => "key_confirmed",
                InitProgress::AllowedUnconfirmed => "allowed_unconfirmed",
            });
        }
        InitReceipt::Config {
            material,
            transaction,
        } => {
            let state = match transaction.state {
                TxState::Pending { .. } => "pending",
                TxState::Refused => "refused",
                TxState::LockHeldElsewhere => "lock_held_elsewhere",
                TxState::Unchanged => "unchanged",
                TxState::ChildUnknown { .. } => "child_unknown",
                TxState::StagedRejected => "staged_rejected",
                TxState::OriginalChanged => "original_changed",
                TxState::RenameFailed => "rename_failed",
                TxState::InstallUnconfirmed => "install_unconfirmed",
                TxState::Installed => "installed",
            };
            value["result"] = json!(state);
            value["config_state"] = json!(state);
            value["material"] = json!(match material {
                InitMaterial::FreshCreated => "fresh_created",
                InitMaterial::ExistingKeyConfirmed => "existing_key_confirmed",
            });
            value["public_hex"] = json!(hex(&transaction.expected_public));
            value["signing_configured"] = json!(matches!(
                transaction.state,
                TxState::Installed | TxState::Unchanged
            ));
            if matches!(transaction.state, TxState::Installed | TxState::Unchanged) {
                value["config_confirmation"] = json!("original_transaction_completed");
            }
            value["child_pid"] = json!(transaction.child_pid);
            value["snapshot_config_identity"] =
                json!({"device": transaction.config_dev, "inode": transaction.config_ino});
            value["snapshot_sha256"] = json!(hex(&transaction.snapshot_sha256));
            value["staged_sha256"] = json!(hex(&transaction.staged_sha256));
        }
    }
    value
}
