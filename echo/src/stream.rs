use std::{
    os::fd::{AsRawFd, RawFd},
    task,
};
use tokio::io::{AsyncRead, AsyncWrite};

pub struct SpyStream<IO>(pub IO);

impl<IO> AsyncRead for SpyStream<IO>
where
    IO: AsyncRead,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> task::Poll<std::io::Result<()>> {
        let res = unsafe {
            let io = self.map_unchecked_mut(|s| &mut s.0);
            io.poll_read(cx, buf)
        };

        match &res {
            task::Poll::Ready(res) => match res {
                Ok(_) => {
                    let msg = String::from_utf8_lossy(buf.filled());
                    tracing::debug!("read {}", msg.escape_default());
                }
                Err(e) => {
                    tracing::debug!("read errored: {e}");
                }
            },
            task::Poll::Pending => {
                tracing::debug!("read would've blocked")
            }
        }
        res
    }
}

impl<IO> AsyncWrite for SpyStream<IO>
where
    IO: AsyncWrite,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<Result<usize, std::io::Error>> {
        let res = unsafe {
            let io = self.map_unchecked_mut(|s| &mut s.0);
            io.poll_write(cx, buf)
        };

        match &res {
            task::Poll::Ready(res) => match res {
                Ok(n) => {
                    tracing::debug!("wrote {n} bytes");
                }
                Err(e) => {
                    tracing::debug!("writing errored: {e}");
                }
            },
            task::Poll::Pending => {
                tracing::debug!("writing would've blocked")
            }
        }
        res
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), std::io::Error>> {
        unsafe {
            let io = self.map_unchecked_mut(|s| &mut s.0);
            io.poll_flush(cx)
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<Result<(), std::io::Error>> {
        unsafe {
            let io = self.map_unchecked_mut(|s| &mut s.0);
            io.poll_shutdown(cx)
        }
    }
}

impl<IO> AsRawFd for SpyStream<IO>
where
    IO: AsRawFd,
{
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
