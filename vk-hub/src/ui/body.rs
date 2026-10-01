//! Every UI response's body: whole, or a live page's stream of events.

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use hyper::body::{Frame, SizeHint};
use tokio::sync::mpsc;

pub enum Body {
    Full(Option<Bytes>),
    Stream(mpsc::Receiver<Bytes>),
}

impl Default for Body {
    fn default() -> Self {
        Body::Full(None)
    }
}

impl From<String> for Body {
    fn from(s: String) -> Self {
        Body::Full(Some(Bytes::from(s)))
    }
}

impl From<&'static [u8]> for Body {
    fn from(b: &'static [u8]) -> Self {
        Body::Full(Some(Bytes::from_static(b)))
    }
}

impl hyper::body::Body for Body {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match self.get_mut() {
            Body::Full(bytes) => Poll::Ready(bytes.take().map(|b| Ok(Frame::data(b)))),
            Body::Stream(rx) => rx.poll_recv(cx).map(|b| b.map(|b| Ok(Frame::data(b)))),
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self, Body::Full(None))
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Body::Full(None) => SizeHint::with_exact(0),
            Body::Full(Some(b)) => SizeHint::with_exact(b.len() as u64),
            Body::Stream(_) => SizeHint::default(),
        }
    }
}
