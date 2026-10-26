use crate::ServeRequest;
use chinwag_mcp_private_anchored::{
    loopback_listener::LoopbackListener, repository_http::AccessSecret,
};
use serde_json::json;
use std::io::{Read, Write};

pub fn run_mcp_http(
    request: ServeRequest,
    input: &mut dyn Read,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let secret = match AccessSecret::read_exact_input(input) {
        Ok(secret) => secret,
        Err(reason) => {
            let _ = writeln!(err, "chinwag: context_http_input_failed: {reason}");
            return 2;
        }
    };
    let mut owner = match LoopbackListener::bind_private_repository(request.repo, secret) {
        Ok(owner) => owner,
        Err(error) => {
            let _ = writeln!(err, "chinwag: context_http_start_failed: {error}");
            return 1;
        }
    };
    // Readiness is emitted only AFTER the original runtime registered SIGINT.
    let served = owner.serve_until_interrupt_and_ready(|address| {
        let ready = json!({"schema":1,"event":"mcp_http_ready","url":format!("http://{address}/mcp"),"protocol":"2026-07-28","tool_completion_or_release_receipt":false});
        serde_json::to_writer(&mut *out, &ready)
            .map_err(std::io::Error::other)
            .and_then(|()| out.write_all(b"\n"))
            .and_then(|()| out.flush())
            .map_err(|_| "HTTP endpoint output failed".to_owned())
    });
    let finished = match owner.finish() {
        Err(failure) if failure.reason() == "Original listener has not been stopped" => {
            failure.into_original().cancel_before_serve()
        }
        result => result,
    };
    let stopped = match served {
        Ok(stopped) => stopped,
        Err(reason) => {
            let _ = writeln!(
                err,
                "chinwag: context_http_serve_failed: {reason}; original_worker_checked={}",
                finished.as_ref().is_ok_and(|r| r.original_worker_checked())
            );
            return 1;
        }
    };
    if let Err(failure) = finished {
        let _ = writeln!(
            err,
            "chinwag: context_http_finish_failed: {}",
            failure.reason()
        );
        return 1;
    }
    let receipt = json!({"schema":1,"event":"mcp_http_stopped","original_worker_checked":true,"connections":stopped.connections(),"transport_failures":stopped.transport_failures(),"tool_acknowledgment_or_release_receipt":false});
    if serde_json::to_writer(&mut *out, &receipt).is_err()
        || out.write_all(b"\n").is_err()
        || out.flush().is_err()
    {
        return 1;
    }
    0
}
