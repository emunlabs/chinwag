use super::*;
use futures_util::SinkExt;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

// Tungstenite requires its by-value ErrorResponse in this handshake callback.
#[allow(clippy::result_large_err)]
async fn pair() -> (WsRead, WsWrite, WebSocketStream<UnixStream>) {
    let (left, right) = UnixStream::pair().unwrap();
    let server = tokio::spawn(async move {
        tokio_tungstenite::accept_hdr_async(
            right,
            |request: &tokio_tungstenite::tungstenite::handshake::server::Request, response| {
                assert_eq!(request.uri().path(), "/");
                assert_eq!(request.headers().get("host").unwrap(), "localhost");
                assert!(!request.headers().contains_key("authorization"));
                assert!(!request.headers().contains_key("origin"));
                Ok(response)
            },
        )
        .await
        .unwrap()
    });
    let (read, write) = connect(left).await.unwrap();
    (read, write, server.await.unwrap())
}
#[tokio::test]
async fn normal_upgrade_pretty_text_and_actual_flush_preserve_exact_envelope() {
    let (read, mut write, mut peer) = pair().await;
    peer.send(Message::Text("{\n \"method\":\"turn/started\",\n \"params\":{\"threadId\":\"thread-a\",\"turn\":{\"id\":\"turn-a\",\"items\":[],\"status\":\"inProgress\"}}\n}".into())).await.unwrap();
    let mut reader = BufReader::new(read);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert_eq!(line.lines().count(), 1);
    assert!(matches!(
        wire::parse(line.as_bytes()).unwrap(),
        wire::Incoming::Started { .. }
    ));
    write
        .write_all(b"{\"method\":\"initialized\"}\n")
        .await
        .unwrap();
    write.flush().await.unwrap();
    let message = tokio::time::timeout(Duration::from_secs(1), peer.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(message.into_text().unwrap(), "{\"method\":\"initialized\"}");
}
#[tokio::test]
async fn duplicate_raw_keys_are_rejected_before_normalization() {
    let (mut read, _write, mut peer) = pair().await;
    peer.send(Message::Text("{\"method\":\"item/completed\",\"params\":{\"item\":{\"clientId\":\"original\",\"clientId\":\"replacement\"}}}".into())).await.unwrap();
    let mut byte = [0u8; 1];
    assert_eq!(
        read.read(&mut byte).await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}
#[tokio::test]
async fn binary_and_oversized_messages_fail_without_raw_fallback() {
    let (mut read, _write, mut peer) = pair().await;
    peer.send(Message::Binary(vec![b'{', b'}'].into()))
        .await
        .unwrap();
    assert!(read.read(&mut [0u8; 1]).await.is_err());
    let (mut read, write, mut peer) = pair().await;
    let huge = format!("{{\"text\":\"{}\"}}", "a".repeat(wire::MAX_FRAME_BYTES));
    // The peer cannot finish a large write until the bounded reader runs.
    // Its rejected frame may leave the peer write incomplete; release both
    // adapter halves before awaiting producer cleanup.
    let mut producer = tokio::spawn(async move { peer.send(Message::Text(huge.into())).await });
    assert!(
        tokio::time::timeout(Duration::from_secs(3), read.read(&mut [0u8; 1]))
            .await
            .expect("bounded oversized-frame rejection")
            .is_err()
    );
    drop(read);
    drop(write);
    match tokio::time::timeout(Duration::from_secs(3), &mut producer).await {
        Ok(result) => {
            let _send_result = result.expect("owned synthetic producer did not panic");
        }
        Err(_) => {
            producer.abort();
            let _joined = producer.await;
            panic!("owned synthetic producer did not finish after adapter close");
        }
    }
}
#[tokio::test]
async fn outbound_incomplete_and_oversized_frames_never_report_flushed() {
    let (_read, mut write, _peer) = pair().await;
    write
        .write_all(b"{\"method\":\"initialized\"}")
        .await
        .unwrap();
    assert!(write.flush().await.is_err());
    let (_read, mut write, _peer) = pair().await;
    assert!(
        write
            .write_all(&vec![b'a'; wire::MAX_OUTBOUND_BYTES + 1])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn close_never_flushes_a_staged_application_frame_after_the_write_waiter_is_gone() {
    let (_read, mut write, mut peer) = pair().await;
    // write_all only stages the frame in AsyncWrite. Model the caller being
    // cancelled before its required flush; Close must not become a new send.
    write
        .write_all(b"{\"id\":\"initial\",\"method\":\"turn/start\",\"params\":{}}\n")
        .await
        .unwrap();
    assert!(write.shutdown().await.is_err());
    drop(write);
    match tokio::time::timeout(Duration::from_secs(1), peer.next()).await {
        Ok(Some(Ok(Message::Text(_)))) => {
            panic!("Close dispatched an application frame that had never been flushed")
        }
        Ok(_) => {}
        Err(_) => {}
    }
}

#[tokio::test]
async fn close_drops_sink_staged_application_data_without_flushing_or_reencoding_it() {
    let (_read, mut write, mut peer) = pair().await;
    let text = "{\"id\":\"steer\",\"method\":\"turn/steer\",\"params\":{}}";
    std::future::poll_fn(|cx| Pin::new(&mut write.sink).poll_ready(cx))
        .await
        .unwrap();
    Pin::new(&mut write.sink)
        .start_send(Message::Text(text.into()))
        .unwrap();
    write.bytes = format!("{text}\n").into_bytes();
    write.submitted = true;
    assert!(write.shutdown().await.is_err());
    drop(write);
    if let Ok(Some(Ok(Message::Text(_)))) =
        tokio::time::timeout(Duration::from_millis(25), peer.next()).await
    {
        panic!("Close flushed the retained application frame");
    }
}
