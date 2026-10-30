//! Native exact-copy opening and optional human Cursor installation handoff.
//!
//! The host must already service Cocoa's main dispatch queue and call this
//! synchronous adapter from a worker. It does not create NSApplication or a run
//! loop. Before calling, the host must supply the coordinator with a fresh,
//! exact-target public metadata observation; a process sample is not asleep proof.
//! macOS may still show Gatekeeper UI despite `promptsUserIfNeeded = false`.

use crate::{
    CursorMcpInstall, LaunchFailure, LaunchTarget, NativeApplicationLauncher, OpenReceipt,
};
use block2::RcBlock;
use chinwag_client_discovery::ClientFamily;
use dispatch2::DispatchQueue;
use objc2::{MainThreadMarker, rc::autoreleasepool};
use objc2_app_kit::{NSRunningApplication, NSWorkspace, NSWorkspaceOpenConfiguration};
use objc2_foundation::{NSArray, NSError, NSString, NSURL};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError},
    },
    time::{Duration, Instant},
};

const MAX_WAIT: Duration = Duration::from_secs(10);
const CANCELLATION_POLL: Duration = Duration::from_millis(20);
const MAX_METADATA_UTF16: usize = 4096;
const QUEUED: u8 = 0;
const SUBMITTED: u8 = 1;
const CANCELLED: u8 = 2;

/// An opt-in for an existing native main-loop host, not proof a loop is running.
/// A plain Tokio daemon without a serviced main queue must not advertise this
/// adapter as available. Opened applications remain user-owned, including reuse.
pub struct MacOsApplicationLauncher {
    mode: OpenMode,
}

enum OpenMode {
    Ordinary,
    CursorMcpSetup(CursorMcpInstall),
}

impl OpenMode {
    fn setup_uri(&self, family: ClientFamily) -> Result<Option<String>, LaunchFailure> {
        match self {
            Self::Ordinary => Ok(None),
            Self::CursorMcpSetup(spec) if family == ClientFamily::Cursor => {
                Ok(Some(spec.install_uri().to_owned()))
            }
            Self::CursorMcpSetup(_) => Err(LaunchFailure::Rejected(
                "Cursor MCP setup requires the exact selected Cursor installation",
            )),
        }
    }
}

impl MacOsApplicationLauncher {
    /// The caller owns the serviced Cocoa main loop and exact metadata refresh.
    pub fn for_main_loop_host() -> Self {
        Self {
            mode: OpenMode::Ordinary,
        }
    }

    /// Opens Cursor's installation approval prompt in the exact selected copy.
    /// The host must revalidate the owner-declared MCP binary before each call,
    /// and retain the same human-operation, metadata and journal boundaries.
    /// An OS acknowledgement does not confirm installation or MCP connection.
    pub fn for_cursor_mcp_setup_host(spec: CursorMcpInstall) -> Self {
        Self {
            mode: OpenMode::CursorMcpSetup(spec),
        }
    }
}

#[derive(Clone)]
struct ExpectedApplication {
    application_path: PathBuf,
    executable_path: PathBuf,
    bundle_id: String,
}

struct Attempt {
    state: AtomicU8,
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}

impl Attempt {
    fn new(cancelled: Arc<AtomicBool>, deadline: Instant) -> Self {
        Self {
            state: AtomicU8::new(QUEUED),
            cancelled,
            deadline,
        }
    }

    fn begin_submission(&self, now: Instant) -> Result<(), LaunchFailure> {
        if self.cancelled.load(Ordering::Acquire) || now >= self.deadline {
            self.state
                .compare_exchange(QUEUED, CANCELLED, Ordering::AcqRel, Ordering::Acquire)
                .ok();
            return Err(LaunchFailure::Rejected(
                "operation cancelled or expired before submission",
            ));
        }
        self.state
            .compare_exchange(QUEUED, SUBMITTED, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                LaunchFailure::Rejected("queued opening was already consumed or cancelled")
            })?;
        // Check again after winning the submission slot. Cancellation after this
        // boundary cannot undo an OS operation and must never invite a retry.
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            return Err(LaunchFailure::Rejected(
                "operation cancelled or expired before OS call",
            ));
        }
        Ok(())
    }

    fn stop_waiting(&self, cancelled: bool) -> LaunchFailure {
        if self
            .state
            .compare_exchange(QUEUED, CANCELLED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            || self.state.load(Ordering::Acquire) == CANCELLED
        {
            if cancelled {
                LaunchFailure::Rejected("operation cancelled before main-queue submission")
            } else {
                LaunchFailure::Unavailable("main queue did not submit before the bounded deadline")
            }
        } else {
            LaunchFailure::Uncertain(
                "macOS opening may have been submitted; do not automatically retry",
            )
        }
    }
}

impl NativeApplicationLauncher for MacOsApplicationLauncher {
    fn open_or_reuse(
        &mut self,
        target: &LaunchTarget,
        deadline: Instant,
    ) -> Result<OpenReceipt, LaunchFailure> {
        let setup_uri = self.mode.setup_uri(target.installation().family)?;
        if MainThreadMarker::new().is_some() {
            return Err(LaunchFailure::Unavailable(
                "call from a worker while the host services its native main loop",
            ));
        }
        let now = Instant::now();
        if target.is_cancelled() || deadline <= now {
            return Err(LaunchFailure::Rejected(
                "operation cancelled or expired before queueing",
            ));
        }
        let expected = ExpectedApplication {
            application_path: target.application_path().to_owned(),
            executable_path: target.executable_path().to_owned(),
            bundle_id: target.bundle_id().to_owned(),
        };
        let application_path = expected
            .application_path
            .to_str()
            .filter(|path| {
                !path.is_empty() && path.len() <= MAX_METADATA_UTF16 && !path.contains('\0')
            })
            .ok_or(LaunchFailure::Rejected(
                "selected application path is not bounded Unicode",
            ))?
            .to_owned();
        let deadline = deadline.min(now + MAX_WAIT);
        let attempt = Arc::new(Attempt::new(target.cancellation_flag(), deadline));
        let (sender, receiver) = mpsc::sync_channel(1);
        let queued_attempt = Arc::clone(&attempt);
        DispatchQueue::main().exec_async(move || {
            autoreleasepool(|_| {
                // Objective-C objects are created, used and dropped on this queue;
                // the concurrent completion copies bounded values into Rust only.
                let application_url = NSURL::fileURLWithPath_isDirectory(
                    &NSString::from_str(&application_path),
                    true,
                );
                let setup_url = match setup_uri.as_deref() {
                    Some(uri) => match NSURL::URLWithString(&NSString::from_str(uri)) {
                        Some(url) => Some(url),
                        None => {
                            let _ = sender.try_send(Err(LaunchFailure::Rejected(
                                "fixed Cursor setup URL could not be represented",
                            )));
                            return;
                        }
                    },
                    None => None,
                };
                let setup_urls = setup_url.as_deref().map(|url| NSArray::from_slice(&[url]));
                let config = NSWorkspaceOpenConfiguration::new();
                config.setCreatesNewApplicationInstance(false);
                config.setAllowsRunningApplicationSubstitution(false);
                config.setPromptsUserIfNeeded(false);
                config.setAddsToRecentItems(false);
                config.setActivates(false);
                let pre_submission_sender = sender.clone();
                let completion = RcBlock::new(
                    move |application: *mut NSRunningApplication, error: *mut NSError| {
                        let result =
                            autoreleasepool(|_| completion_result(application, error, &expected));
                        // Late callbacks are discarded after the bounded caller leaves.
                        let _ = sender.try_send(result);
                    },
                );
                let workspace = NSWorkspace::sharedWorkspace();
                if let Err(error) = queued_attempt.begin_submission(Instant::now()) {
                    let _ = pre_submission_sender.try_send(Err(error));
                    return;
                }
                if let Some(urls) = setup_urls {
                    workspace.openURLs_withApplicationAtURL_configuration_completionHandler(
                        &urls,
                        &application_url,
                        &config,
                        Some(&completion),
                    );
                } else {
                    workspace.openApplicationAtURL_configuration_completionHandler(
                        &application_url,
                        &config,
                        Some(&completion),
                    );
                }
            })
        });
        wait_for_completion(&attempt, &receiver)
    }
}

fn wait_for_completion(
    attempt: &Attempt,
    receiver: &Receiver<Result<OpenReceipt, LaunchFailure>>,
) -> Result<OpenReceipt, LaunchFailure> {
    loop {
        let cancelled = attempt.cancelled.load(Ordering::Acquire);
        let now = Instant::now();
        if cancelled || now >= attempt.deadline {
            return Err(attempt.stop_waiting(cancelled));
        }
        match receiver.recv_timeout((attempt.deadline - now).min(CANCELLATION_POLL)) {
            Ok(result) => {
                if attempt.cancelled.load(Ordering::Acquire) || Instant::now() >= attempt.deadline {
                    return Err(attempt.stop_waiting(attempt.cancelled.load(Ordering::Acquire)));
                }
                return result;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Err(attempt.stop_waiting(false)),
        }
    }
}

#[allow(unsafe_code)]
fn completion_result(
    application: *mut NSRunningApplication,
    error: *mut NSError,
    expected: &ExpectedApplication,
) -> Result<OpenReceipt, LaunchFailure> {
    // SAFETY: NSWorkspace owns both nullable callback arguments throughout this
    // callback. We borrow only here and copy data, never retain/send raw objects.
    let (application, error) = unsafe { (application.as_ref(), error.as_ref()) };
    match (application, error) {
        (Some(application), None) => {
            let application_path = file_path(application.bundleURL().as_deref())?;
            let executable_path = file_path(application.executableURL().as_deref())?;
            let bundle_id = bounded_string(application.bundleIdentifier().as_deref())?;
            validate_receipt(
                expected,
                application_path,
                executable_path,
                bundle_id,
                application.processIdentifier(),
            )
        }
        (None, Some(error)) => {
            let domain = bounded_string(Some(&error.domain()))?;
            if (domain == "NSOSStatusErrorDomain" && error.code() == -10826)
                || (domain == "NSCocoaErrorDomain" && error.code() == 257)
            {
                Err(LaunchFailure::AccessRequired(
                    "macOS requires human access to the selected application",
                ))
            } else {
                Err(LaunchFailure::Rejected(
                    "macOS reported that the selected application could not be opened",
                ))
            }
        }
        _ => Err(LaunchFailure::Uncertain(
            "macOS returned an inconsistent opening acknowledgement",
        )),
    }
}

fn bounded_string(value: Option<&NSString>) -> Result<String, LaunchFailure> {
    let value = value
        .filter(|value| value.length() > 0 && value.length() <= MAX_METADATA_UTF16)
        .ok_or(LaunchFailure::Uncertain(
            "macOS acknowledgement metadata is missing or oversized",
        ))?;
    let value = value.to_string();
    if value.contains('\0') {
        return Err(LaunchFailure::Uncertain(
            "macOS acknowledgement metadata contains a NUL",
        ));
    }
    Ok(value)
}

fn file_path(value: Option<&NSURL>) -> Result<PathBuf, LaunchFailure> {
    let value = value
        .filter(|url| url.isFileURL())
        .ok_or(LaunchFailure::Uncertain(
            "macOS acknowledgement did not contain a file URL",
        ))?;
    Ok(PathBuf::from(bounded_string(value.path().as_deref())?))
}

fn validate_receipt(
    expected: &ExpectedApplication,
    application_path: PathBuf,
    executable_path: PathBuf,
    bundle_id: String,
    pid: i32,
) -> Result<OpenReceipt, LaunchFailure> {
    if application_path != expected.application_path
        || executable_path != expected.executable_path
        || bundle_id != expected.bundle_id
    {
        return Err(LaunchFailure::Uncertain(
            "macOS acknowledged a different application copy or executable",
        ));
    }
    Ok(OpenReceipt {
        application_path,
        bundle_id,
        process_id: u32::try_from(pid).ok().filter(|pid| *pid > 0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_setup_mode_rejects_other_families_before_any_native_submission() {
        let spec = CursorMcpInstall::new(
            "/owner/chinwag-native-inbox-mcp".into(),
            "http://127.0.0.1:4780".into(),
        )
        .unwrap();
        let launcher = MacOsApplicationLauncher::for_cursor_mcp_setup_host(spec);
        for family in [ClientFamily::GrokBot, ClientFamily::VisualStudioCode] {
            assert!(matches!(
                launcher.mode.setup_uri(family),
                Err(LaunchFailure::Rejected(_))
            ));
        }
        assert!(
            launcher
                .mode
                .setup_uri(ClientFamily::Cursor)
                .unwrap()
                .unwrap()
                .starts_with("cursor://anysphere.cursor-deeplink/mcp/install?")
        );
    }

    #[test]
    fn ordinary_open_never_attaches_an_install_uri() {
        let launcher = MacOsApplicationLauncher::for_main_loop_host();
        for family in [ClientFamily::Cursor, ClientFamily::GrokBot] {
            assert_eq!(launcher.mode.setup_uri(family), Ok(None));
        }
    }

    fn expected() -> ExpectedApplication {
        ExpectedApplication {
            application_path: "/Applications/Fixture.app".into(),
            executable_path: "/Applications/Fixture.app/Contents/MacOS/Fixture".into(),
            bundle_id: "test.fixture".into(),
        }
    }

    #[test]
    fn exact_copy_acknowledgement_never_substitutes_same_bundle_id() {
        let expected = expected();
        let receipt = validate_receipt(
            &expected,
            expected.application_path.clone(),
            expected.executable_path.clone(),
            expected.bundle_id.clone(),
            12,
        )
        .unwrap();
        assert_eq!(receipt.process_id, Some(12));
        for (app, exe, bundle) in [
            (
                "/Applications/Other.app",
                expected.executable_path.to_str().unwrap(),
                expected.bundle_id.as_str(),
            ),
            (
                expected.application_path.to_str().unwrap(),
                "/Applications/Fixture.app/Contents/MacOS/Other",
                expected.bundle_id.as_str(),
            ),
            (
                expected.application_path.to_str().unwrap(),
                expected.executable_path.to_str().unwrap(),
                "test.other",
            ),
        ] {
            assert!(matches!(
                validate_receipt(&expected, app.into(), exe.into(), bundle.into(), 12),
                Err(LaunchFailure::Uncertain(_))
            ));
        }
    }

    #[test]
    fn process_id_is_optional_metadata_not_a_connected_or_owned_claim() {
        let expected = expected();
        for pid in [-1, 0] {
            assert_eq!(
                validate_receipt(
                    &expected,
                    expected.application_path.clone(),
                    expected.executable_path.clone(),
                    expected.bundle_id.clone(),
                    pid
                )
                .unwrap()
                .process_id,
                None
            );
        }
    }

    #[test]
    fn delayed_queue_timeout_permanently_prevents_submission() {
        let attempt = Attempt::new(Arc::new(AtomicBool::new(false)), Instant::now() + MAX_WAIT);
        assert!(matches!(
            attempt.stop_waiting(false),
            LaunchFailure::Unavailable(_)
        ));
        assert!(attempt.begin_submission(Instant::now()).is_err());
    }

    #[test]
    fn cancellation_and_expiry_prevent_queued_submission() {
        let attempt = Attempt::new(Arc::new(AtomicBool::new(true)), Instant::now() + MAX_WAIT);
        assert!(attempt.begin_submission(Instant::now()).is_err());
        let attempt = Attempt::new(Arc::new(AtomicBool::new(false)), Instant::now());
        assert!(attempt.begin_submission(Instant::now()).is_err());
    }

    #[test]
    fn submitted_timeout_is_uncertain_and_duplicate_submission_is_rejected() {
        let attempt = Attempt::new(Arc::new(AtomicBool::new(false)), Instant::now() + MAX_WAIT);
        attempt.begin_submission(Instant::now()).unwrap();
        assert!(attempt.begin_submission(Instant::now()).is_err());
        assert!(matches!(
            attempt.stop_waiting(false),
            LaunchFailure::Uncertain(_)
        ));
        assert!(matches!(
            attempt.stop_waiting(true),
            LaunchFailure::Uncertain(_)
        ));
    }

    #[test]
    fn bounded_wait_returns_exact_acknowledgement_and_preserves_os_failure() {
        for result in [
            Ok(OpenReceipt {
                application_path: expected().application_path,
                bundle_id: expected().bundle_id,
                process_id: Some(12),
            }),
            Err(LaunchFailure::AccessRequired("fixture permission failure")),
        ] {
            let attempt = Attempt::new(Arc::new(AtomicBool::new(false)), Instant::now() + MAX_WAIT);
            attempt.begin_submission(Instant::now()).unwrap();
            let (sender, receiver) = mpsc::sync_channel(1);
            sender.send(result.clone()).unwrap();
            assert_eq!(wait_for_completion(&attempt, &receiver), result);
        }
    }

    #[test]
    fn caller_cancellation_discards_late_success_without_inviting_retry() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let attempt = Attempt::new(Arc::clone(&cancelled), Instant::now() + MAX_WAIT);
        attempt.begin_submission(Instant::now()).unwrap();
        let (sender, receiver) = mpsc::sync_channel(1);
        sender
            .send(Ok(OpenReceipt {
                application_path: expected().application_path,
                bundle_id: expected().bundle_id,
                process_id: Some(12),
            }))
            .unwrap();
        cancelled.store(true, Ordering::Release);
        assert!(matches!(
            wait_for_completion(&attempt, &receiver),
            Err(LaunchFailure::Uncertain(_))
        ));
    }
}
