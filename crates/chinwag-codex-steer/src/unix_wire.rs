//! Fixed normal WebSocket-over-Unix adapter. Socket selection and local owner
//! checks belong to the trusted host; this never discovers or reconnects.
use crate::{Result, SteerError, wire};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{Sink, Stream, StreamExt};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UnixStream,
};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, protocol::WebSocketConfig},
};

type Socket = WebSocketStream<UnixStream>;
pub(crate) struct WsRead {
    stream: SplitStream<Socket>,
    bytes: Vec<u8>,
    offset: usize,
    failed: bool,
}
pub(crate) struct WsWrite {
    sink: SplitSink<Socket, Message>,
    bytes: Vec<u8>,
    submitted: bool,
    failed: bool,
}

pub(crate) async fn connect(stream: UnixStream) -> Result<(WsRead, WsWrite)> {
    let config = WebSocketConfig::default()
        .max_frame_size(Some(wire::MAX_FRAME_BYTES))
        .max_message_size(Some(wire::MAX_FRAME_BYTES));
    let (socket, _) = tokio::time::timeout(
        Duration::from_secs(5),
        tokio_tungstenite::client_async_with_config("ws://localhost/", stream, Some(config)),
    )
    .await
    .map_err(|_| SteerError::Unavailable)?
    .map_err(|_| SteerError::Unavailable)?;
    let (sink, stream) = socket.split();
    Ok((
        WsRead {
            stream,
            bytes: Vec::new(),
            offset: 0,
            failed: false,
        },
        WsWrite {
            sink,
            bytes: Vec::new(),
            submitted: false,
            failed: false,
        },
    ))
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "bounded owned WebSocket unavailable",
    )
}
impl AsyncRead for WsRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.failed {
            return Poll::Ready(Err(invalid()));
        }
        loop {
            if self.offset < self.bytes.len() {
                let n = out.remaining().min(self.bytes.len() - self.offset);
                out.put_slice(&self.bytes[self.offset..self.offset + n]);
                self.offset += n;
                return Poll::Ready(Ok(()));
            }
            self.bytes.clear();
            self.offset = 0;
            match Pin::new(&mut self.stream).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None | Some(Ok(Message::Close(_)))) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Ok(Message::Text(text)))) => {
                    // Detect duplicate keys in ORIGINAL bytes before canonicalizing
                    // pretty JSON into the single-line existing core boundary.
                    let value = match wire::unique_value(text.as_bytes()) {
                        Ok(v) if v.is_object() => v,
                        _ => {
                            self.failed = true;
                            return Poll::Ready(Err(invalid()));
                        }
                    };
                    self.bytes = match serde_json::to_vec(&value) {
                        Ok(v) => v,
                        Err(_) => {
                            self.failed = true;
                            return Poll::Ready(Err(invalid()));
                        }
                    };
                    self.bytes.push(b'\n');
                    if self.bytes.len() > wire::MAX_FRAME_BYTES {
                        self.failed = true;
                        return Poll::Ready(Err(invalid()));
                    }
                }
                Poll::Ready(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
                _ => {
                    self.failed = true;
                    return Poll::Ready(Err(invalid()));
                }
            }
        }
    }
}
impl AsyncWrite for WsWrite {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.failed {
            return Poll::Ready(Err(invalid()));
        }
        if self.submitted || self.bytes.ends_with(b"\n") {
            match self.as_mut().poll_flush(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
        }
        let n = input
            .iter()
            .position(|b| *b == b'\n')
            .map_or(input.len(), |n| n + 1);
        if self.bytes.len() + n > wire::MAX_OUTBOUND_BYTES {
            self.failed = true;
            return Poll::Ready(Err(invalid()));
        }
        self.bytes.extend_from_slice(&input[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(invalid()));
        }
        if self.bytes.is_empty() {
            return match Pin::new(&mut self.sink).poll_flush(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                Poll::Ready(Err(_)) => {
                    self.failed = true;
                    Poll::Ready(Err(invalid()))
                }
            };
        }
        if !self.bytes.ends_with(b"\n") {
            self.failed = true;
            return Poll::Ready(Err(invalid()));
        }
        if !self.submitted {
            match Pin::new(&mut self.sink).poll_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => {
                    self.failed = true;
                    return Poll::Ready(Err(invalid()));
                }
                Poll::Ready(Ok(())) => {}
            }
            let value = match wire::unique_value(&self.bytes) {
                Ok(v) if v.is_object() => v,
                _ => {
                    self.failed = true;
                    return Poll::Ready(Err(invalid()));
                }
            };
            let text = match serde_json::to_string(&value) {
                Ok(v) => v,
                Err(_) => {
                    self.failed = true;
                    return Poll::Ready(Err(invalid()));
                }
            };
            if Pin::new(&mut self.sink)
                .start_send(Message::Text(text.into()))
                .is_err()
            {
                self.failed = true;
                return Poll::Ready(Err(invalid()));
            }
            self.submitted = true;
        }
        match Pin::new(&mut self.sink).poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => {
                self.failed = true;
                Poll::Ready(Err(invalid()))
            }
            Poll::Ready(Ok(())) => {
                self.bytes.clear();
                self.submitted = false;
                Poll::Ready(Ok(()))
            }
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // A cancelled write may leave data either here or staged in SplitSink.
        // Close must never initiate/finish a buffered application RPC. The core
        // drops this writer after shutdown, including on this error path.
        if self.failed || self.submitted || !self.bytes.is_empty() {
            self.failed = true;
            self.bytes.clear();
            return Poll::Ready(Err(invalid()));
        }
        match Pin::new(&mut self.sink).poll_close(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_)) => {
                self.failed = true;
                Poll::Ready(Err(invalid()))
            }
        }
    }
}
#[cfg(test)]
mod tests;
