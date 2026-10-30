//! A dedicated native main-loop owner for an explicitly opted-in host process.
//!
//! This is not an application launcher. The actual process main thread services
//! the native queue while one owned worker runs. Work must implement its own
//! cancellation and eventually return; Rust cannot forcibly cancel that thread.
//! No NSApplication, NSWorkspace, app, service or client is created here.

use core_foundation::{
    base::TCFType,
    runloop::{
        CFRunLoop, CFRunLoopRunResult, CFRunLoopSource, CFRunLoopSourceContext,
        CFRunLoopSourceCreate, CFRunLoopSourceInvalidate, CFRunLoopWakeUp, kCFRunLoopDefaultMode,
    },
};
use dispatch2::DispatchQueue;
use objc2::MainThreadMarker;
use std::{
    any::Any,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

static HOST_OWNED: AtomicBool = AtomicBool::new(false);
const IDLE_RUN_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const INITIAL_INTERRUPTION_BACKOFF: Duration = Duration::from_millis(10);
const MAX_INTERRUPTION_BACKOFF: Duration = Duration::from_millis(250);

#[derive(Debug, thiserror::Error)]
pub enum MainLoopHostError {
    #[error("native main-loop host must start on the actual process main thread")]
    NotMainThread,
    #[error("a native run loop or main-loop host already owns this thread")]
    AlreadyRunning,
    #[error("native main run loop is unavailable")]
    Unavailable,
    #[error("the native idle source could not be installed")]
    SourceUnavailable,
    #[error("owned native-host worker could not start: {0}")]
    WorkerSpawn(#[source] std::io::Error),
    #[error("owned native-host work panicked")]
    WorkerPanicked,
    #[error("native main loop stopped unexpectedly before work completed")]
    Interrupted,
}

struct OwnerGuard<'a>(&'a AtomicBool);

impl<'a> OwnerGuard<'a> {
    fn acquire(owned: &'a AtomicBool) -> Result<Self, MainLoopHostError> {
        owned
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| MainLoopHostError::AlreadyRunning)?;
        Ok(Self(owned))
    }
}

impl Drop for OwnerGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

struct Completion {
    finished: AtomicBool,
    active: AtomicBool,
}

impl Completion {
    fn new() -> Self {
        Self {
            finished: AtomicBool::new(false),
            active: AtomicBool::new(true),
        }
    }

    fn finish(&self) {
        self.finished.store(true, Ordering::Release);
    }

    fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }

    fn should_stop(&self) -> bool {
        self.active.load(Ordering::Acquire) && self.is_finished()
    }

    fn deactivate(&self) {
        self.active.store(false, Ordering::Release);
    }
}

/// The actual main thread must have no currently active native run-loop mode.
/// Work executes on a new owned thread; its result, including an inner Result,
/// is preserved. A caught worker panic becomes WorkerPanicked after cleanup.
///
/// The host has no forced thread cancellation or overall timeout. Work must own
/// cooperative cancellation and return. Unexpected foreign loop stops are
/// recorded and backed off while servicing continues, so work that awaits the
/// main queue is never detached or joined with that queue disabled.
pub fn run_main_loop_host<F, T>(work: F) -> Result<T, MainLoopHostError>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    if MainThreadMarker::new().is_none() {
        return Err(MainLoopHostError::NotMainThread);
    }
    let _owner = OwnerGuard::acquire(&HOST_OWNED)?;
    let run_loop = CFRunLoop::get_main();
    if run_loop.current_mode().is_some() {
        return Err(MainLoopHostError::AlreadyRunning);
    }
    let _source = IdleSource::install(run_loop.clone())?;
    let completion = Arc::new(Completion::new());
    let worker_completion = Arc::clone(&completion);
    let worker_loop = run_loop.clone();
    let worker = thread::Builder::new()
        .name("chinwag-native-host-work".into())
        .spawn(move || {
            let stop_completion = Arc::clone(&worker_completion);
            let stop_loop = worker_loop.clone();
            finish_work(work, &worker_completion, move || {
                // A pending block survives completion before Run starts. Its
                // active flag prevents stopping any later host activation.
                DispatchQueue::main().exec_async(move || {
                    if stop_completion.should_stop() {
                        stop_loop.stop();
                    }
                });
                wake(&worker_loop);
            })
        })
        .map_err(MainLoopHostError::WorkerSpawn)?;

    let mut interrupted = false;
    let mut backoff = INITIAL_INTERRUPTION_BACKOFF;
    while !completion.is_finished() {
        // SAFETY: this immutable CoreFoundation global is a valid mode; the
        // caller is the actual main thread and owns the installed idle source.
        let mode = unsafe { kCFRunLoopDefaultMode };
        let result = CFRunLoop::run_in_mode(mode, IDLE_RUN_INTERVAL, false);
        if !completion.is_finished() && result != CFRunLoopRunResult::TimedOut {
            interrupted = true;
            // An external stop/removed source must not create a rapid restart
            // loop. Continue servicing until the owned work cooperatively ends.
            thread::sleep(backoff);
            backoff = (backoff * 2).min(MAX_INTERRUPTION_BACKOFF);
        }
    }
    // The worker no longer awaits queue work after finish(). Join first, then
    // disarm its possibly pending stop block before any other activation.
    let result = worker.join();
    completion.deactivate();
    let value = result
        .map_err(|_| MainLoopHostError::WorkerPanicked)?
        .map_err(|_| MainLoopHostError::WorkerPanicked)?;
    if interrupted {
        return Err(MainLoopHostError::Interrupted);
    }
    Ok(value)
}

fn catch_work<F, T>(work: F) -> Result<T, Box<dyn Any + Send>>
where
    F: FnOnce() -> T,
{
    catch_unwind(AssertUnwindSafe(work))
}

fn finish_work<F, T, N>(
    work: F,
    completion: &Completion,
    notify: N,
) -> Result<T, Box<dyn Any + Send>>
where
    F: FnOnce() -> T,
    N: FnOnce(),
{
    let result = catch_work(work);
    completion.finish();
    notify();
    result
}

fn wake(run_loop: &CFRunLoop) {
    // SAFETY: CFRunLoop is retained by the caller. CoreFoundation permits wake
    // from other threads; its Rust wrapper already provides Send and Sync.
    unsafe { CFRunLoopWakeUp(run_loop.as_concrete_TypeRef()) }
}

struct IdleSource {
    run_loop: CFRunLoop,
    source: CFRunLoopSource,
}

impl IdleSource {
    fn install(run_loop: CFRunLoop) -> Result<Self, MainLoopHostError> {
        let mut context = CFRunLoopSourceContext {
            version: 0,
            info: ptr::null_mut(),
            retain: None,
            release: None,
            copyDescription: None,
            equal: None,
            hash: None,
            schedule: None,
            cancel: None,
            perform: idle_source_perform,
        };
        // SAFETY: context is initialized and copied by CoreFoundation. It holds
        // no borrowed info pointer. Null allocator requests the default.
        let raw = unsafe { CFRunLoopSourceCreate(ptr::null(), 0, &mut context) };
        if raw.is_null() {
            return Err(MainLoopHostError::SourceUnavailable);
        }
        // SAFETY: raw is non-null and the create-rule ownership is ours.
        let source = unsafe { CFRunLoopSource::wrap_under_create_rule(raw) };
        // SAFETY: the immutable mode global denotes the default native mode.
        let mode = unsafe { kCFRunLoopDefaultMode };
        run_loop.add_source(&source, mode);
        Ok(Self { run_loop, source })
    }
}

impl Drop for IdleSource {
    fn drop(&mut self) {
        // SAFETY: both objects are retained until after removal/invalidation.
        unsafe {
            self.run_loop
                .remove_source(&self.source, kCFRunLoopDefaultMode);
            CFRunLoopSourceInvalidate(self.source.as_concrete_TypeRef());
        }
    }
}

extern "C" fn idle_source_perform(_: *const std::ffi::c_void) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returned_value_and_inner_error_are_preserved() {
        let completion = Completion::new();
        let notified = AtomicBool::new(false);
        assert_eq!(
            finish_work(
                || Err::<(), _>("cancelled"),
                &completion,
                || {
                    assert!(completion.is_finished());
                    notified.store(true, Ordering::Release);
                }
            )
            .unwrap(),
            Err("cancelled")
        );
        assert!(notified.load(Ordering::Acquire));
        assert!(completion.is_finished());
    }

    #[test]
    fn work_panic_is_caught_at_the_owned_worker_boundary() {
        let completion = Completion::new();
        let notified = AtomicBool::new(false);
        assert!(
            finish_work(
                || panic!("fixture panic"),
                &completion,
                || {
                    assert!(completion.is_finished());
                    notified.store(true, Ordering::Release);
                }
            )
            .is_err()
        );
        assert!(notified.load(Ordering::Acquire));
        assert!(completion.is_finished());
    }

    #[test]
    fn successful_owned_work_notifies_only_after_its_result_is_ready() {
        let completion = Completion::new();
        let side_effect = AtomicBool::new(false);
        assert_eq!(
            finish_work(
                || {
                    side_effect.store(true, Ordering::Release);
                    42
                },
                &completion,
                || {
                    assert!(side_effect.load(Ordering::Acquire));
                    assert!(completion.is_finished());
                }
            )
            .unwrap(),
            42
        );
    }

    #[test]
    fn owner_rejects_nested_scope_and_releases_after_early_return() {
        let owned = AtomicBool::new(false);
        {
            let _guard = OwnerGuard::acquire(&owned).unwrap();
            assert!(matches!(
                OwnerGuard::acquire(&owned),
                Err(MainLoopHostError::AlreadyRunning)
            ));
        }
        assert!(OwnerGuard::acquire(&owned).is_ok());
    }

    #[test]
    fn completion_before_loop_entry_remains_visible_but_late_stop_is_disarmed() {
        let first = Completion::new();
        first.finish();
        assert!(first.is_finished());
        assert!(first.should_stop());
        first.deactivate();
        let second = Completion::new();
        assert!(!first.should_stop());
        assert!(!second.is_finished());
        assert!(!second.should_stop());
    }

    #[test]
    fn incomplete_work_cannot_stop_the_main_loop() {
        let completion = Completion::new();
        assert!(!completion.should_stop());
        completion.finish();
        assert!(completion.should_stop());
    }

    #[test]
    fn cooperative_cancel_result_does_not_destroy_other_state() {
        let cancelled = Arc::new(AtomicBool::new(true));
        let preserved = Arc::new(AtomicBool::new(true));
        let still_preserved = Arc::clone(&preserved);
        let result = catch_work(move || {
            if cancelled.load(Ordering::Acquire) {
                Err("cancelled")
            } else {
                preserved.store(false, Ordering::Release);
                Ok(())
            }
        });
        assert_eq!(result.unwrap(), Err("cancelled"));
        assert!(still_preserved.load(Ordering::Acquire));
    }
}
