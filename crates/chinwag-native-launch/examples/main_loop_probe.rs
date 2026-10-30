//! Opt-in native queue probe. No NSWorkspace, application opening or discovery.

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    use chinwag_native_launch::main_loop::run_main_loop_host;
    use dispatch2::DispatchQueue;
    use objc2::MainThreadMarker;
    use std::{sync::mpsc, thread, time::Duration};

    let expected_main = thread::current().id();
    if MainThreadMarker::new().is_none() {
        eprintln!("main-loop probe did not start on the process main thread");
        return std::process::ExitCode::FAILURE;
    }
    // Serial scopes exercise completion-before-entry and pending-stop cleanup
    // before the queue verification, without invoking any application API.
    if !matches!(run_main_loop_host(|| 42), Ok(42)) {
        eprintln!("native host did not preserve immediate successful work");
        return std::process::ExitCode::FAILURE;
    }
    if !matches!(
        run_main_loop_host(|| Err::<(), _>("fixture inner error")),
        Ok(Err("fixture inner error"))
    ) {
        eprintln!("native host did not preserve an inner work error");
        return std::process::ExitCode::FAILURE;
    }
    let result = run_main_loop_host(move || {
        let worker = thread::current().id();
        if MainThreadMarker::new().is_some() || worker == expected_main {
            return Err("probe work did not run on a separate owned worker");
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        DispatchQueue::main().exec_async(move || {
            let main_verified =
                MainThreadMarker::new().is_some() && thread::current().id() == expected_main;
            let _ = sender.try_send(main_verified);
        });
        match receiver.recv_timeout(Duration::from_secs(5)) {
            Ok(true) => Ok(()),
            Ok(false) => Err("native dispatch closure did not run on the verified main thread"),
            Err(_) => Err("native main-queue probe did not complete within five seconds"),
        }
    });
    match result {
        Ok(Ok(())) => {
            println!(
                "native_main_queue_probe_ok: owned worker -> verified process main thread; no apps opened"
            );
            std::process::ExitCode::SUCCESS
        }
        Ok(Err(error)) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn main() -> std::process::ExitCode {
    eprintln!("native main-loop probe is supported only on macOS");
    std::process::ExitCode::FAILURE
}
