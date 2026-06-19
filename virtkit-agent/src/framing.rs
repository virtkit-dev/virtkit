use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio_serde::{Framed, formats::MessagePack};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

use crate::messages::Message;

/// Any bidirectional byte stream a virtkit-agent conversation can run over
/// (unix socket, vsock, ...).
pub trait Connection: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Connection for T {}

type WrappedStream = FramedRead<ReadHalf<Box<dyn Connection>>, LengthDelimitedCodec>;
type WrappedSink = FramedWrite<WriteHalf<Box<dyn Connection>>, LengthDelimitedCodec>;

// We use the unit type in place of the message types since we're
// only dealing with one half of the IO
pub type SerStream = Framed<WrappedStream, Message, (), MessagePack<Message, ()>>;
pub type DeSink = Framed<WrappedSink, (), Message, MessagePack<(), Message>>;

pub fn wrap_stream(stream: impl Connection + 'static) -> (SerStream, DeSink) {
    let (read, write) = tokio::io::split(Box::new(stream) as Box<dyn Connection>);
    let stream = WrappedStream::new(read, LengthDelimitedCodec::new());
    let sink = WrappedSink::new(write, LengthDelimitedCodec::new());
    (
        SerStream::new(stream, MessagePack::default()),
        DeSink::new(sink, MessagePack::default()),
    )
}
