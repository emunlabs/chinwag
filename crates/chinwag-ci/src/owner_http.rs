// Copyright 2026 Emun Labs, Inc.
// 1401 Lavaca St STE 81335, Austin, TX 78701
// SPDX-License-Identifier: Apache-2.0

//! Explicitly owned HTTP connections. No detached Axum connection tasks.
use crate::{
    owner_lifecycle::OwnerBudget,
    runtime::{Result, RuntimeError},
};
use axum::Router;
use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::time::Duration;
use tokio::{
    net::TcpListener,
    task::JoinSet,
    time::{Instant, sleep_until},
};

pub(crate) async fn serve(listener: TcpListener, app: Router, budget: OwnerBudget) -> Result<()> {
    serve_with_header_limit(listener, app, budget, Duration::from_secs(5)).await
}
async fn serve_with_header_limit(
    listener: TcpListener,
    app: Router,
    budget: OwnerBudget,
    header_limit: Duration,
) -> Result<()> {
    let mut connections = JoinSet::new();
    let mut clean = true;
    loop {
        tokio::select! {
            biased;
            _ = budget.work_stopped() => break,
            result = connections.join_next(), if !connections.is_empty() => {
                clean &= matches!(result, Some(Ok(Ok(()))));
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(_) => { clean = false; budget.stop(); break; }
                };
                // Bound open sockets BEFORE parsing headers, not just handlers.
                if connections.len() >= 8 { drop(stream); continue; }
                let app = app.clone();
                let budget = budget.clone();
                connections.spawn(async move {
                    let mut builder = http1::Builder::new();
                    builder.timer(TokioTimer::new())
                        .header_read_timeout(header_limit)
                        .keep_alive(false).max_headers(64)
                        .max_header_size(16 * 1024).max_buf_size(32 * 1024);
                    let connection = builder.serve_connection(TokioIo::new(stream), TowerToHyperService::new(app));
                    tokio::pin!(connection);
                    tokio::select! {
                        // Even a refused/malformed HTTP request has a completed
                        // owned connection. This is closure, not request success.
                        _result = &mut connection => Ok(()),
                        _ = budget.work_stopped() => {
                            connection.as_mut().graceful_shutdown();
                            // The connection and its socket stay owned here.
                            tokio::select! {
                                _result = &mut connection => Ok(()),
                                _ = sleep_until(budget.close_until.min(Instant::now() + Duration::from_secs(10))) => Err(RuntimeError),
                            }
                        }
                    }
                });
            }
        }
    }
    drop(listener);
    let drain_until = budget
        .close_until
        .min(Instant::now() + Duration::from_secs(10));
    // No new accept. Every connection is joined, even after a forced abort.
    while !connections.is_empty() {
        if Instant::now() >= drain_until {
            clean = false;
            connections.abort_all();
            break;
        }
        tokio::select! {
            result = connections.join_next() => clean &= matches!(result, Some(Ok(Ok(())))),
            _ = sleep_until(drain_until) => {
                clean = false;
                connections.abort_all();
                break;
            }
        }
    }
    while let Some(result) = connections.join_next().await {
        clean &= matches!(result, Ok(Ok(())));
    }
    if clean { Ok(()) } else { Err(RuntimeError) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Bytes, routing::get};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn exercise(request: &[u8], active: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let budget = OwnerBudget::test(Duration::from_millis(100), Duration::from_millis(100));
        let app = Router::new().route(
            "/pending",
            get(|| async { std::future::pending::<Bytes>().await }),
        );
        let server = tokio::spawn(serve_with_header_limit(
            listener,
            app,
            budget,
            Duration::from_millis(40),
        ));
        let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
        client.write_all(request).await.unwrap();
        let mut response = Vec::new();
        // A timeout is a test failure, not an accepted connection-close witness.
        let read = tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .unwrap();
        assert!(read.is_ok() || read.unwrap_err().kind() == std::io::ErrorKind::ConnectionReset);
        let result = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        if active {
            assert!(result.is_err());
        }
        // Binding again proves the original listener was actually dropped.
        let _replacement = TcpListener::bind(address).await.unwrap();
    }
    #[tokio::test]
    async fn incomplete_headers_are_bounded_and_connection_task_is_joined() {
        exercise(b"GET /pending HTTP/1.1\r\nHost:", false).await;
    }
    #[tokio::test]
    async fn idle_socket_is_bounded_and_connection_task_is_joined() {
        exercise(b"", false).await;
    }
    #[tokio::test]
    async fn shutdown_drops_active_connection_and_joins_its_original_task() {
        exercise(b"GET /pending HTTP/1.1\r\nHost: localhost\r\n\r\n", true).await;
    }
}
