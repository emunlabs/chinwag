use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const MAX_INPUT_BYTES: usize = 16_384;
pub const MAX_OUTPUT_BYTES: usize = 262_144;
pub const MAX_TOOL_DATA_BYTES: usize = 65_536;
pub const OBSERVATION_BYTES: usize = 1024;

#[derive(Clone, Copy)]
pub enum InputEnd {
    Eof,
    Error,
}

/// Closes admission at observed input EOF/error, before the SDK response drain.
pub struct ClosingReader<R, F> {
    inner: R,
    close: F,
}

impl<R, F> ClosingReader<R, F> {
    pub fn new(inner: R, close: F) -> Self {
        Self { inner, close }
    }
}

impl<R: AsyncRead + Unpin, F: Fn(InputEnd) + Unpin> AsyncRead for ClosingReader<R, F> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let had_space = buffer.remaining() != 0;
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buffer);
        if matches!(&result, Poll::Ready(Err(_))) {
            (self.close)(InputEnd::Error);
        } else if had_space
            && matches!(&result, Poll::Ready(Ok(())))
            && buffer.filled().len() == before
        {
            (self.close)(InputEnd::Eof);
        }
        result
    }
}

/// Caps one protocol output line, including the structured/text compatibility pair.
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
        let mut length = self.line_bytes;
        for byte in bytes {
            if *byte == b'\n' {
                length = 0;
            } else {
                length += 1;
                if length > MAX_OUTPUT_BYTES {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "MCP response line limit",
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
