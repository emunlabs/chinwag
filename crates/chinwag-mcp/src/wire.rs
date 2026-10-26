#![forbid(unsafe_code)]
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::AsyncWrite;

pub const MAX_INPUT_BYTES: usize = 1_048_576;
pub const MAX_OUTPUT_BYTES: usize = 2_097_152;
pub const MAX_TOOL_DATA_BYTES: usize = 65_536;

pub struct BoundedWriter<W> {
    inner: W,
    line_bytes: usize,
}
impl<W> BoundedWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            line_bytes: 0,
        }
    }
}
impl<W: AsyncWrite + Unpin> AsyncWrite for BoundedWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut prospective = self.line_bytes;
        for byte in bytes {
            if *byte == b'\n' {
                prospective = 0;
            } else {
                prospective += 1;
                if prospective > MAX_OUTPUT_BYTES {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Private MCP response line limit",
                    )));
                }
            }
        }
        match Pin::new(&mut self.inner).poll_write(cx, bytes) {
            Poll::Ready(Ok(written)) => {
                for byte in &bytes[..written] {
                    if *byte == b'\n' {
                        self.line_bytes = 0;
                    } else {
                        self.line_bytes += 1;
                    }
                }
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
