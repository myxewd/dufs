use bytes::{Bytes, BytesMut};
use futures_util::Stream;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Body;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::AsyncRead;
use tokio_util::io::poll_read_buf;

/// Turn any hyper request body into a stream of data frames.
///
/// The server normally receives a hyper Incoming body, but the tftp
/// dispatcher builds a synthetic request whose body is an empty body; keeping
/// this generic lets both use the same upload path.
#[derive(Debug)]
pub struct IncomingStream<B> {
    inner: B,
}

impl<B> IncomingStream<B> {
    pub fn new(inner: B) -> Self {
        Self { inner }
    }
}

impl<B> Stream for IncomingStream<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Item = Result<Bytes, B::Error>;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match futures_util::ready!(Pin::new(&mut self.inner).poll_frame(cx)?) {
                Some(frame) => match frame.into_data() {
                    Ok(data) => return Poll::Ready(Some(Ok(data))),
                    Err(_frame) => {}
                },
                None => return Poll::Ready(None),
            }
        }
    }
}

pin_project_lite::pin_project! {
    pub struct LengthLimitedStream<R> {
        #[pin]
        reader: Option<R>,
        remaining: usize,
        buf: BytesMut,
        capacity: usize,
    }
}

impl<R> LengthLimitedStream<R> {
    pub fn new(reader: R, limit: usize) -> Self {
        Self {
            reader: Some(reader),
            remaining: limit,
            buf: BytesMut::new(),
            capacity: 4096,
        }
    }
}

impl<R: AsyncRead> Stream for LengthLimitedStream<R> {
    type Item = std::io::Result<Bytes>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.as_mut().project();

        if *this.remaining == 0 {
            self.project().reader.set(None);
            return Poll::Ready(None);
        }

        let reader = match this.reader.as_pin_mut() {
            Some(r) => r,
            None => return Poll::Ready(None),
        };

        if this.buf.capacity() == 0 {
            this.buf.reserve(*this.capacity);
        }

        match poll_read_buf(reader, cx, &mut this.buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                self.project().reader.set(None);
                Poll::Ready(Some(Err(err)))
            }
            Poll::Ready(Ok(0)) => {
                self.project().reader.set(None);
                Poll::Ready(None)
            }
            Poll::Ready(Ok(_)) => {
                let mut chunk = this.buf.split();
                let chunk_size = (*this.remaining).min(chunk.len());
                chunk.truncate(chunk_size);
                *this.remaining -= chunk_size;
                Poll::Ready(Some(Ok(chunk.freeze())))
            }
        }
    }
}

pub fn body_full(content: impl Into<hyper::body::Bytes>) -> BoxBody<Bytes, anyhow::Error> {
    Full::new(content.into())
        .map_err(anyhow::Error::new)
        .boxed()
}
