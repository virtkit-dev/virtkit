//! `aws-chunked` bodies: the framing AWS SDKs and the CLI wrap a PutObject's bytes in, decoded
//! in one streaming pass by [`Decoder`], a [`Body`] over the request's own. The body is a run
//! of chunks, `<hex size>[;chunk-signature=<64 hex>]\r\n<data>\r\n`, ended by a chunk of size
//! zero; in the `-TRAILER` modes, `name:value\r\n` lines follow it (the checksum
//! `x-amz-trailer` announced, then `x-amz-trailer-signature` when signed), and a last `\r\n`.
//!
//! A signed body's signatures chain: each chunk's covers its data and the signature before
//! it, the first one's the request's own, and the trailer's the last chunk's. They are
//! checked when the request was signed with a secret this registry knows ([`Seed`]); a body
//! sent under a bearer, Basic or session credential, or to an open server, has its framing
//! decoded and its signatures read but not checked, as no seed is known.
//!
//! What is read is bounded as it is read: a chunk header of at most [`MAX_HEADER`] bytes, a
//! chunk no longer than what is left of `x-amz-decoded-content-length`, a trailer section of
//! at most [`MAX_TRAILER`], and nothing after its end. Memory is one frame of the inner body
//! and a line. Anything else stops the body with a [`Refusal`]; the data already passed on
//! is then in a staging file its caller drops, so nothing it decoded is ever tagged.

use std::error::Error as StdError;
use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf as _, Bytes};
use hyper::body::{Body, Frame};
use sha2::{Digest as _, Sha256};

use super::error::Code;
use super::sigv4::{self, SigningKey};

/// The longest chunk header taken, its CRLF included: a size and a signature need 91.
pub(crate) const MAX_HEADER: usize = 256;

/// The longest trailer section taken, every line's CRLF included.
pub(crate) const MAX_TRAILER: usize = 8 * 1024;

/// The trailer line carrying the trailer's signature.
const TRAILER_SIGNATURE: &str = "x-amz-trailer-signature";

/// The SHA-256 of nothing, which a chunk's string to sign carries where a header hash would be.
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// How a chunked body is framed and signed, from its `x-amz-content-sha256`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`: every chunk signed, no trailer
    Signed,
    /// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`: every chunk and the trailer signed
    SignedTrailer,
    /// `STREAMING-UNSIGNED-PAYLOAD-TRAILER`: no signature, a trailer
    UnsignedTrailer,
    /// `Content-Encoding: aws-chunked` with any other payload hash: no signature, no trailer
    Unsigned,
}

impl Mode {
    /// The mode an `x-amz-content-sha256` names, if it names one of the streaming modes.
    pub(crate) fn of(content_sha256: &str) -> Option<Mode> {
        match content_sha256 {
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" => Some(Mode::Signed),
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER" => Some(Mode::SignedTrailer),
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER" => Some(Mode::UnsignedTrailer),
            _ => None,
        }
    }

    /// Whether chunks and trailer carry signatures.
    pub(crate) fn signed(self) -> bool {
        matches!(self, Mode::Signed | Mode::SignedTrailer)
    }

    /// Whether trailer lines follow the last chunk.
    pub(crate) fn trailer(self) -> bool {
        matches!(self, Mode::SignedTrailer | Mode::UnsignedTrailer)
    }
}

/// What a request's headers say of its chunked body.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Framing {
    pub(crate) mode: Mode,
    /// `x-amz-decoded-content-length`: exactly how many bytes the chunks hold
    pub(crate) declared: u64,
    /// the checksum `x-amz-trailer` announced, the header of one of
    /// [`super::checksum::ALGORITHMS`]
    pub(crate) trailer: Option<&'static str>,
}

/// What a signed body's signatures are checked against: the request's signing key, time,
/// scope and signature, which seeds the chain. Its key is wiped when it is dropped.
pub(crate) struct Seed {
    key: SigningKey,
    stamp: String,
    scope: String,
    signature: String,
}

impl Seed {
    /// The seed of a request signed by `credential` with `secret` at `stamp`, its signature
    /// already checked. `None` only if no key could be derived.
    pub(crate) fn of(
        secret: &str,
        credential: &sigv4::Credential<'_>,
        stamp: &str,
    ) -> Option<Self> {
        let key = SigningKey::derive(
            secret,
            credential.date,
            credential.region,
            credential.service,
        )?;
        Some(Seed {
            key,
            stamp: stamp.to_string(),
            scope: credential.scope(),
            signature: credential.signature.to_string(),
        })
    }

    /// Whether `presented` is this key's signature of `string_to_sign`, in constant time.
    fn signs(&self, string_to_sign: &str, presented: &str) -> bool {
        self.key
            .sign(string_to_sign)
            .is_some_and(|ours| crate::auth::constant_eq(ours.as_bytes(), presented.as_bytes()))
    }
}

/// The string a chunk's signature signs: the chain's previous signature and the chunk's data.
fn chunk_string_to_sign(stamp: &str, scope: &str, previous: &str, data_sha256: &str) -> String {
    format!(
        "{}-PAYLOAD\n{stamp}\n{scope}\n{previous}\n{EMPTY_SHA256}\n{data_sha256}",
        sigv4::ALGORITHM
    )
}

/// The string the trailer's signature signs: the last chunk's signature and the trailer's
/// lines, hashed as `name:value\n` each.
fn trailer_string_to_sign(stamp: &str, scope: &str, previous: &str, lines_sha256: &str) -> String {
    format!(
        "{}-TRAILER\n{stamp}\n{scope}\n{previous}\n{lines_sha256}",
        sigv4::ALGORITHM
    )
}

/// Why a chunked body was refused: the S3 code it is answered with, and what was wrong with
/// it, which the answer leaves to the code's own message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub(crate) code: Code,
    pub(crate) message: &'static str,
}

impl Refusal {
    /// A chunk header that is malformed, too long, or sizes a chunk past the declared length.
    fn size(message: &'static str) -> Self {
        Refusal {
            code: Code::InvalidChunkSizeError,
            message,
        }
    }

    /// A body that ends early, or holds other than the declared length.
    fn incomplete(message: &'static str) -> Self {
        Refusal {
            code: Code::IncompleteBody,
            message,
        }
    }

    /// A trailer section that is malformed, too long, or followed by anything.
    fn trailer(message: &'static str) -> Self {
        Refusal {
            code: Code::MalformedTrailerError,
            message,
        }
    }

    /// A chunk or trailer signature that is not the seed's key's.
    fn signature(message: &'static str) -> Self {
        Refusal {
            code: Code::SignatureDoesNotMatch,
            message,
        }
    }
}

impl From<Refusal> for super::error::Refusal {
    fn from(r: Refusal) -> Self {
        super::error::Refusal::new(r.code)
    }
}

/// Why a [`Decoder`] stopped: its framing was refused, or the body under it failed.
#[derive(Debug)]
pub(crate) enum Error {
    Refused(Refusal),
    Body(Box<dyn StdError + Send + Sync>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Refused(r) => write!(f, "an aws-chunked body was refused: {}", r.message),
            Error::Body(e) => write!(f, "reading an aws-chunked body: {e}"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Refused(_) => None,
            Error::Body(e) => Some(&**e),
        }
    }
}

/// Where the decoder is in the body.
#[derive(Clone, Copy, Debug)]
enum State {
    /// reading a chunk header line
    Header,
    /// passing on this many more bytes of a chunk's data
    Data(u64),
    /// reading the CRLF after a chunk's data, this many of its bytes seen
    DataEnd(u8),
    /// reading trailer lines, after the last chunk's header
    Trailer,
    /// past the trailer's end: only the inner body's end may follow
    Done,
    /// refused or failed: nothing more is read
    Failed,
}

/// The trailer as read so far.
#[derive(Default)]
struct Trailer {
    /// bytes read, CRLFs included
    read: usize,
    /// the announced checksum's value
    value: Option<String>,
    /// the hash of the checksum lines as the trailer signature signs them
    lines: Sha256,
    signature: Option<String>,
}

/// What one step of decoding produced.
enum Step {
    Data(Bytes),
    More,
    End,
}

/// An `aws-chunked` body decoded: a [`Body`] of the chunks' data, over the body as sent. It
/// ends once the inner body has, after a well-formed end; [`Decoder::trailer`] then holds the
/// trailer's checksum.
pub(crate) struct Decoder<B> {
    inner: B,
    inner_done: bool,
    framing: Framing,
    /// set when signatures are checked: a signed mode, and a request signed with a known secret
    seed: Option<Seed>,
    /// the chain's previous signature: the request's, then each chunk's
    previous: String,
    state: State,
    /// what is left of the inner body's current frame
    pending: Bytes,
    /// the line being read, its CRLF not yet seen
    line: Vec<u8>,
    decoded: u64,
    /// the signature of the chunk being read and the hash of its data, when checked
    chunk: Option<(String, Sha256)>,
    trailer: Trailer,
}

impl<B> Decoder<B> {
    /// A decoder of `inner` framed as `framing`, checking its signatures against `seed` if
    /// there is one and the mode is signed.
    pub(crate) fn new(inner: B, framing: Framing, seed: Option<Seed>) -> Self {
        let seed = seed.filter(|_| framing.mode.signed());
        Decoder {
            inner,
            inner_done: false,
            framing,
            previous: seed
                .as_ref()
                .map(|s| s.signature.clone())
                .unwrap_or_default(),
            seed,
            state: State::Header,
            pending: Bytes::new(),
            line: Vec::new(),
            decoded: 0,
            chunk: None,
            trailer: Trailer::default(),
        }
    }

    /// The announced checksum and the value the trailer gave it, once the body has ended.
    pub(crate) fn trailer(&self) -> Option<(&'static str, &str)> {
        Some((self.framing.trailer?, self.trailer.value.as_deref()?))
    }

    /// Move the inner body's bytes into `line` up to a LF: `true` once a whole line is there,
    /// its CRLF dropped. A line of `max` bytes or more, CRLF included, is `too_long`.
    fn read_line(&mut self, max: usize, too_long: Refusal) -> Result<bool, Refusal> {
        let Some(end) = self.pending.iter().position(|&b| b == b'\n') else {
            if self.line.len().saturating_add(self.pending.len()) >= max {
                return Err(too_long);
            }
            self.line.extend_from_slice(&self.pending);
            self.pending.clear();
            return Ok(false);
        };
        if self.line.len().saturating_add(end) >= max {
            return Err(too_long);
        }
        self.line
            .extend_from_slice(self.pending.get(..end).unwrap_or_default());
        self.pending.advance(end.saturating_add(1));
        if self.line.pop() != Some(b'\r') {
            return Err(Refusal::size("a line of the body does not end in CRLF"));
        }
        Ok(true)
    }

    /// The chunk header in `line`: the next chunk's size, and its signature.
    fn header(&mut self) -> Result<(), Refusal> {
        let line = std::mem::take(&mut self.line);
        let text =
            std::str::from_utf8(&line).map_err(|_| Refusal::size("a chunk header is not text"))?;
        let (size, extension) = match text.split_once(';') {
            Some((size, extension)) => (size, Some(extension)),
            None => (text, None),
        };
        if size.is_empty() || size.len() > 16 || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Refusal::size("a chunk size is not a hex number"));
        }
        let size = u64::from_str_radix(size, 16)
            .map_err(|_| Refusal::size("a chunk size is not a hex number"))?;
        let signature = match (self.framing.mode.signed(), extension) {
            (true, Some(extension)) => Some(
                extension
                    .strip_prefix("chunk-signature=")
                    .filter(|s| is_signature(s))
                    .ok_or(Refusal::size(
                        "a signed chunk's header is its size and chunk-signature=<64 hex>",
                    ))?,
            ),
            (false, None) => None,
            (true, None) => {
                return Err(Refusal::size(
                    "a signed chunk's header has no chunk-signature",
                ));
            }
            (false, Some(_)) => {
                return Err(Refusal::size(
                    "an unsigned chunk's header is its size alone",
                ));
            }
        };
        let left = self.framing.declared.saturating_sub(self.decoded);
        if size > left {
            return Err(Refusal::size(
                "a chunk runs past x-amz-decoded-content-length",
            ));
        }
        self.chunk = signature
            .filter(|_| self.seed.is_some())
            .map(|s| (s.to_string(), Sha256::new()));
        if size == 0 {
            if left != 0 {
                return Err(Refusal::incomplete(
                    "the chunks hold fewer bytes than x-amz-decoded-content-length",
                ));
            }
            self.chunk_done()?;
            self.state = State::Trailer;
        } else {
            self.state = State::Data(size);
        }
        Ok(())
    }

    /// Check the chunk just read against the chain, which then moves on to its signature.
    fn chunk_done(&mut self) -> Result<(), Refusal> {
        let (Some((presented, data)), Some(seed)) = (self.chunk.take(), &self.seed) else {
            return Ok(());
        };
        let sts = chunk_string_to_sign(
            &seed.stamp,
            &seed.scope,
            &self.previous,
            &crate::hex_of(&data.finalize()),
        );
        if !seed.signs(&sts, &presented) {
            return Err(Refusal::signature(
                "a chunk signature does not match the one computed with the key's secret",
            ));
        }
        self.previous = presented;
        Ok(())
    }

    /// One trailer line, from `line`: the announced checksum, once, or the trailer's
    /// signature, last.
    fn trailer_line(&mut self) -> Result<(), Refusal> {
        let line = std::mem::take(&mut self.line);
        if !self.framing.mode.trailer() {
            return Err(Refusal::trailer("bytes follow the last chunk of the body"));
        }
        if self.trailer.signature.is_some() {
            return Err(Refusal::trailer(
                "x-amz-trailer-signature is the trailer's last line",
            ));
        }
        let (name, value) = std::str::from_utf8(&line)
            .ok()
            .and_then(|l| l.split_once(':'))
            .ok_or(Refusal::trailer("a trailer line is name:value"))?;
        if name.eq_ignore_ascii_case(TRAILER_SIGNATURE) {
            let value = value.trim();
            if !self.framing.mode.signed() || !is_signature(value) {
                return Err(Refusal::trailer(
                    "x-amz-trailer-signature is 64 hex digits, in a signed trailer only",
                ));
            }
            self.trailer.signature = Some(value.to_string());
            return Ok(());
        }
        if self.trailer.value.is_some()
            || !self
                .framing
                .trailer
                .is_some_and(|t| t.eq_ignore_ascii_case(name))
        {
            return Err(Refusal::trailer(
                "the trailer holds the checksum x-amz-trailer announced, once",
            ));
        }
        self.trailer.lines.update(&line);
        self.trailer.lines.update(b"\n");
        self.trailer.value = Some(value.trim().to_string());
        Ok(())
    }

    /// The trailer's end: the announced checksum sent, and the signature checked.
    fn trailer_done(&mut self) -> Result<(), Refusal> {
        if !self.framing.mode.trailer() {
            return Ok(());
        }
        if self.framing.trailer.is_some() && self.trailer.value.is_none() {
            return Err(Refusal::trailer(
                "the trailer does not hold the checksum x-amz-trailer announced",
            ));
        }
        if !self.framing.mode.signed() {
            return Ok(());
        }
        let Some(presented) = self.trailer.signature.take() else {
            return Err(Refusal::trailer(
                "a signed upload's trailer ends with x-amz-trailer-signature",
            ));
        };
        let Some(seed) = &self.seed else {
            return Ok(());
        };
        let lines = crate::hex_of(&std::mem::take(&mut self.trailer.lines).finalize());
        let sts = trailer_string_to_sign(&seed.stamp, &seed.scope, &self.previous, &lines);
        if !seed.signs(&sts, &presented) {
            return Err(Refusal::signature(
                "the trailer signature does not match the one computed with the key's secret",
            ));
        }
        Ok(())
    }

    /// Decode what `pending` holds, which is empty only at the inner body's end.
    fn step(&mut self) -> Result<Step, Refusal> {
        let end = self.pending.is_empty();
        let truncated = Refusal::incomplete("the body ends before its last chunk and trailer");
        match self.state {
            State::Failed => Ok(Step::End),
            State::Done if end => Ok(Step::End),
            State::Done => Err(Refusal::trailer("bytes follow the end of the body")),
            _ if end && !matches!(self.state, State::Trailer) => Err(truncated),
            State::Header => {
                let too_long = Refusal::size("a chunk header is longer than 256 bytes");
                if self.read_line(MAX_HEADER, too_long)? {
                    self.header()?;
                }
                Ok(Step::More)
            }
            State::Data(left) => {
                let n =
                    usize::try_from(left).map_or(self.pending.len(), |l| l.min(self.pending.len()));
                let data = self.pending.split_to(n);
                if let Some((_, hash)) = &mut self.chunk {
                    hash.update(&data);
                }
                let n = data.len() as u64;
                self.decoded = self.decoded.saturating_add(n);
                self.state = match left.saturating_sub(n) {
                    0 => State::DataEnd(0),
                    left => State::Data(left),
                };
                Ok(Step::Data(data))
            }
            State::DataEnd(seen) => {
                let want = if seen == 0 { b'\r' } else { b'\n' };
                if self.pending.first() != Some(&want) {
                    return Err(Refusal::incomplete(
                        "a chunk's data is not followed by CRLF",
                    ));
                }
                self.pending.advance(1);
                if seen == 0 {
                    self.state = State::DataEnd(1);
                } else {
                    self.chunk_done()?;
                    self.state = State::Header;
                }
                Ok(Step::More)
            }
            // The body may end without the last CRLF, though not inside a line.
            State::Trailer if end => {
                if !self.line.is_empty() {
                    return Err(truncated);
                }
                self.trailer_done()?;
                self.state = State::Done;
                Ok(Step::End)
            }
            State::Trailer => {
                let budget = MAX_TRAILER.saturating_sub(self.trailer.read);
                let too_long = Refusal::trailer("the trailer is longer than 8 KiB");
                if !self.read_line(budget, too_long)? {
                    return Ok(Step::More);
                }
                self.trailer.read = self
                    .trailer
                    .read
                    .saturating_add(self.line.len())
                    .saturating_add(2);
                if self.line.is_empty() {
                    self.trailer_done()?;
                    self.state = State::Done;
                } else {
                    self.trailer_line()?;
                }
                Ok(Step::More)
            }
        }
    }
}

/// Whether `s` is a signature as SigV4 writes one: 64 lowercase hex digits.
fn is_signature(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl<B> Body for Decoder<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        let this = self.get_mut();
        loop {
            if matches!(this.state, State::Failed) {
                return Poll::Ready(None);
            }
            if this.pending.is_empty() && !this.inner_done {
                match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                    None => this.inner_done = true,
                    Some(Err(e)) => {
                        this.state = State::Failed;
                        return Poll::Ready(Some(Err(Error::Body(e.into()))));
                    }
                    // HTTP trailers of the transfer itself carry no content.
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() {
                            this.pending = data;
                        }
                    }
                }
                continue;
            }
            match this.step() {
                Ok(Step::Data(data)) => return Poll::Ready(Some(Ok(Frame::data(data)))),
                Ok(Step::More) => {}
                Ok(Step::End) => return Poll::Ready(None),
                Err(refusal) => {
                    this.state = State::Failed;
                    return Poll::Ready(Some(Err(Error::Refused(refusal))));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::convert::Infallible;
    use std::task::Waker;

    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const STAMP: &str = "20130524T000000Z";
    const SCOPE: &str = "20130524/us-east-1/s3/aws4_request";

    /// A body handed over in frames of `size` bytes.
    struct Frames(VecDeque<Bytes>);

    impl Frames {
        fn of(body: &[u8], size: usize) -> Self {
            Frames(
                body.chunks(size.max(1))
                    .map(Bytes::copy_from_slice)
                    .collect(),
            )
        }
    }

    impl Body for Frames {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            Poll::Ready(self.get_mut().0.pop_front().map(|b| Ok(Frame::data(b))))
        }
    }

    fn seed(signature: &str) -> Seed {
        Seed {
            key: SigningKey::derive(SECRET, "20130524", "us-east-1", "s3").unwrap(),
            stamp: STAMP.to_string(),
            scope: SCOPE.to_string(),
            signature: signature.to_string(),
        }
    }

    /// What the decoder passes on and the trailer it read, or its refusal: never a panic.
    fn decode(
        body: &[u8],
        frame: usize,
        framing: Framing,
        seed: Option<Seed>,
    ) -> Result<(Vec<u8>, Option<String>), Refusal> {
        let mut dec = Decoder::new(Frames::of(body, frame), framing, seed);
        let mut cx = Context::from_waker(Waker::noop());
        let mut out = Vec::new();
        loop {
            match Pin::new(&mut dec).poll_frame(&mut cx) {
                Poll::Ready(None) => break,
                Poll::Ready(Some(Ok(f))) => out.extend_from_slice(&f.into_data().unwrap()),
                Poll::Ready(Some(Err(Error::Refused(r)))) => return Err(r),
                other => panic!("{other:?}"),
            }
        }
        let trailer = dec.trailer().map(|(_, v)| v.to_string());
        Ok((out, trailer))
    }

    const SEED: &str = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
    const CHUNK1: &str = "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648";
    const CHUNK2: &str = "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497";
    const FINAL: &str = "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9";

    /// AWS's chunked PutObject example: 66 560 bytes of `a`, in chunks of 64 KiB, 1 KiB and 0.
    fn example() -> Vec<u8> {
        let mut body = format!("10000;chunk-signature={CHUNK1}\r\n").into_bytes();
        body.extend_from_slice(&[b'a'; 65536]);
        body.extend_from_slice(format!("\r\n400;chunk-signature={CHUNK2}\r\n").as_bytes());
        body.extend_from_slice(&[b'a'; 1024]);
        body.extend_from_slice(format!("\r\n0;chunk-signature={FINAL}\r\n\r\n").as_bytes());
        body
    }

    fn signed(declared: u64) -> Framing {
        Framing {
            mode: Mode::Signed,
            declared,
            trailer: None,
        }
    }

    #[test]
    fn the_aws_chunked_example_decodes_and_verifies() {
        let body = example();
        assert_eq!(body.len(), 66_824, "the example's Content-Length");
        for frame in [1, 7, 91, 4096, 65_536, body.len()] {
            let (out, trailer) = decode(&body, frame, signed(66_560), Some(seed(SEED))).unwrap();
            assert_eq!(out, [b'a'; 66_560], "{frame}");
            assert_eq!(trailer, None);
        }
        // The last CRLF may be left out.
        let short = &body[..body.len() - 2];
        assert!(decode(short, 4096, signed(66_560), Some(seed(SEED))).is_ok());
        // Unchecked without a seed, and decoded the same.
        let (out, _) = decode(&body, 4096, signed(66_560), None).unwrap();
        assert_eq!(out.len(), 66_560);
    }

    /// The trailer example's three chunk signatures and its trailer's, from the hashes it
    /// documents: its second chunk's data is not given (its hash is not that of 1 KiB of `a`,
    /// nor is its checksum that of the first example's bytes), so the chain is checked from
    /// the hashes, and the decoder from the last chunk on.
    #[test]
    fn the_aws_trailer_example_verifies() {
        let key = seed("").key;
        let sign = |sts: &str| key.sign(sts).unwrap();
        let mut previous =
            "106e2a8a18243abcf37539882f36619c00e2dfc72633413f02d3b74544bfeb8e".to_string();
        for (hash, expect) in [
            (
                "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a",
                "b474d8862b1487a5145d686f57f013e54db672cee1c953b3010fb58501ef5aa2",
            ),
            (
                "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3",
                "041169d545f3f4a02fe2e3d066bfb1798dd5f3417ae8cecd0e43690aafbe79d1",
            ),
            (
                EMPTY_SHA256,
                "e05ab64fe1dfdbf0b5870abbaabdb063c371d4e96f2767e6934d90529c5ae850",
            ),
        ] {
            previous = sign(&chunk_string_to_sign(STAMP, SCOPE, &previous, hash));
            assert_eq!(previous, expect);
        }
        let lines = crate::hex_of(&Sha256::digest(b"x-amz-checksum-crc32c:wdBDMA==\n"));
        assert_eq!(
            lines,
            "2e4ab969aa65b1ad6def2db10e4d3a8260683d194dbaf757f90e8a37960a4b3c"
        );
        assert_eq!(
            sign(&trailer_string_to_sign(STAMP, SCOPE, &previous, &lines)),
            "41e14ac611e27a8bb3d66c3bad6856f209297767d5dd4fc87d8fa9e422e03faf"
        );

        // The body from its last chunk on, seeded with the chunk before it.
        let tail = "0;chunk-signature=e05ab64fe1dfdbf0b5870abbaabdb063c371d4e96f2767e6934d90529c5ae850\r\n\
                    x-amz-checksum-crc32c:wdBDMA==\r\n\
                    x-amz-trailer-signature:41e14ac611e27a8bb3d66c3bad6856f209297767d5dd4fc87d8fa9e422e03faf\r\n\r\n";
        let framing = Framing {
            mode: Mode::SignedTrailer,
            declared: 0,
            trailer: Some("x-amz-checksum-crc32c"),
        };
        let chunk2 = "041169d545f3f4a02fe2e3d066bfb1798dd5f3417ae8cecd0e43690aafbe79d1";
        for frame in [1, 5, tail.len()] {
            let (out, trailer) =
                decode(tail.as_bytes(), frame, framing, Some(seed(chunk2))).unwrap();
            assert!(out.is_empty());
            assert_eq!(trailer.as_deref(), Some("wdBDMA=="));
        }
        // Another trailer value, or another chain, does not verify.
        let other = tail.replace("wdBDMA==", "wdBDMQ==");
        assert_eq!(
            decode(other.as_bytes(), 64, framing, Some(seed(chunk2)))
                .unwrap_err()
                .code,
            Code::SignatureDoesNotMatch
        );
        assert_eq!(
            decode(tail.as_bytes(), 64, framing, Some(seed(SEED)))
                .unwrap_err()
                .code,
            Code::SignatureDoesNotMatch
        );
        // Without a seed the trailer is read, its signature not checked.
        let (_, trailer) = decode(other.as_bytes(), 64, framing, None).unwrap();
        assert_eq!(trailer.as_deref(), Some("wdBDMQ=="));
    }

    fn unsigned_trailer(declared: u64) -> Framing {
        Framing {
            mode: Mode::UnsignedTrailer,
            declared,
            trailer: Some("x-amz-checksum-crc32"),
        }
    }

    #[test]
    fn an_unsigned_trailer_carries_its_checksum() {
        let crc = vk_hub_proto::to_base64(&crc32fast::hash(b"hello world").to_be_bytes());
        let body = format!("5\r\nhello\r\n6\r\n world\r\n0\r\nx-amz-checksum-crc32:{crc}\r\n\r\n");
        for frame in [1, 3, body.len()] {
            // A seed changes nothing for a body that is not signed.
            let (out, trailer) = decode(
                body.as_bytes(),
                frame,
                unsigned_trailer(11),
                Some(seed(SEED)),
            )
            .unwrap();
            assert_eq!(out, b"hello world");
            assert_eq!(trailer.as_deref(), Some(crc.as_str()));
        }
        let code =
            |body: &str, framing| decode(body.as_bytes(), 4, framing, None).unwrap_err().code;
        // Not announced, missing, twice, or signed where nothing is.
        let t = unsigned_trailer(1);
        assert_eq!(
            code("1\r\na\r\n0\r\nx-amz-checksum-sha1:x\r\n\r\n", t),
            Code::MalformedTrailerError
        );
        assert_eq!(code("1\r\na\r\n0\r\n\r\n", t), Code::MalformedTrailerError);
        assert_eq!(
            code(
                "1\r\na\r\n0\r\nx-amz-checksum-crc32:a\r\nx-amz-checksum-crc32:a\r\n\r\n",
                t
            ),
            Code::MalformedTrailerError
        );
        let sig = format!("x-amz-trailer-signature:{FINAL}");
        assert_eq!(
            code(
                &format!("1\r\na\r\n0\r\nx-amz-checksum-crc32:a\r\n{sig}\r\n\r\n"),
                t
            ),
            Code::MalformedTrailerError
        );
        assert_eq!(
            code(&format!("1;chunk-signature={FINAL}\r\na\r\n0\r\n\r\n"), t),
            Code::InvalidChunkSizeError
        );
        // A plain aws-chunked body has no trailer.
        let plain = Framing {
            mode: Mode::Unsigned,
            declared: 1,
            trailer: None,
        };
        assert_eq!(
            decode(b"1\r\na\r\n0\r\n\r\n", 2, plain, None).unwrap().0,
            b"a"
        );
        assert_eq!(
            code("1\r\na\r\n0\r\nx-amz-checksum-crc32:a\r\n\r\n", plain),
            Code::MalformedTrailerError
        );
    }

    #[test]
    fn a_signed_trailer_needs_its_signature_last() {
        let framing = Framing {
            mode: Mode::SignedTrailer,
            declared: 0,
            trailer: None,
        };
        let code = |body: String| decode(body.as_bytes(), 8, framing, None).unwrap_err().code;
        let zero = format!("0;chunk-signature={FINAL}\r\n");
        assert_eq!(code(format!("{zero}\r\n")), Code::MalformedTrailerError);
        let sig = format!("x-amz-trailer-signature:{FINAL}\r\n");
        assert!(decode(format!("{zero}{sig}\r\n").as_bytes(), 8, framing, None).is_ok());
        assert_eq!(
            code(format!("{zero}{sig}{sig}\r\n")),
            Code::MalformedTrailerError
        );
        assert_eq!(
            code(format!(
                "{zero}x-amz-trailer-signature:{}\r\n\r\n",
                FINAL.to_uppercase()
            )),
            Code::MalformedTrailerError
        );
    }

    #[test]
    fn a_wrong_chunk_signature_is_refused() {
        let body = String::from_utf8(example()).unwrap();
        for wrong in [CHUNK1, CHUNK2, FINAL] {
            let mut flipped = wrong.to_string();
            flipped.replace_range(..1, if wrong.starts_with('0') { "1" } else { "0" });
            let mutated = body.replace(wrong, &flipped);
            let r = decode(mutated.as_bytes(), 4096, signed(66_560), Some(seed(SEED))).unwrap_err();
            assert_eq!(r.code, Code::SignatureDoesNotMatch, "{wrong}");
            assert_eq!(r.code.status(), hyper::StatusCode::FORBIDDEN);
        }
        // Another seed: another chain.
        let r = decode(body.as_bytes(), 4096, signed(66_560), Some(seed(CHUNK1))).unwrap_err();
        assert_eq!(r.code, Code::SignatureDoesNotMatch);
    }

    #[test]
    fn framing_is_bounded_and_complete() {
        let code = |body: &[u8], declared| {
            let framing = Framing {
                mode: Mode::Unsigned,
                declared,
                trailer: None,
            };
            decode(body, 3, framing, None).unwrap_err().code
        };
        // Past the declared length, short of it, or not the length a size says.
        assert_eq!(
            code(b"5\r\nhello\r\n0\r\n\r\n", 4),
            Code::InvalidChunkSizeError
        );
        assert_eq!(code(b"5\r\nhello\r\n0\r\n\r\n", 6), Code::IncompleteBody);
        assert_eq!(code(b"4\r\nhello\r\n0\r\n\r\n", 5), Code::IncompleteBody);
        assert_eq!(
            code(b"ffffffffffffffff\r\nhello\r\n0\r\n\r\n", 5),
            Code::InvalidChunkSizeError
        );
        assert_eq!(
            code(b"10000000000000000\r\n", 5),
            Code::InvalidChunkSizeError
        );
        // Sizes in hex only.
        for bad in [
            &b"x\r\n"[..],
            b"\r\n",
            b"-1\r\n",
            b" 5\r\nhello\r\n",
            b"+5\r\nhello\r\n",
        ] {
            assert_eq!(code(bad, 5), Code::InvalidChunkSizeError, "{bad:?}");
        }
        let plain = Framing {
            mode: Mode::Unsigned,
            declared: 10,
            trailer: None,
        };
        let (out, _) = decode(b"A\r\n0123456789\r\n0\r\n", 3, plain, None).unwrap();
        assert_eq!(out, b"0123456789");
        // A header line is at most 256 bytes, CRLF included: one of 256 is read (and its size
        // refused), one of 257 is refused for its length.
        let pad = |n: usize| {
            let mut h = vec![b'0'; n - 3];
            h.extend_from_slice(b"1\r\n");
            h.extend_from_slice(b"a\r\n0\r\n");
            h
        };
        let message = |body: &[u8]| decode(body, 3, signed(1), None).unwrap_err().message;
        assert!(
            !message(&pad(256)).contains("256"),
            "{}",
            message(&pad(256))
        );
        assert!(message(&pad(257)).contains("256"));
        assert_eq!(code(&pad(300), 1), Code::InvalidChunkSizeError);
        // A header whose LF never comes is refused at the bound, not read further.
        let mut endless = vec![b'0'; 10_000];
        endless.insert(0, b'1');
        assert_eq!(code(&endless, 1), Code::InvalidChunkSizeError);
        // LF without CR, or data not followed by CRLF.
        assert_eq!(
            code(b"5\nhello\r\n0\r\n\r\n", 5),
            Code::InvalidChunkSizeError
        );
        assert_eq!(code(b"5\r\nhello\n0\r\n\r\n", 5), Code::IncompleteBody);
        assert_eq!(code(b"5\r\nhelloXY0\r\n\r\n", 5), Code::IncompleteBody);
        // Anything after the end.
        assert_eq!(
            code(b"5\r\nhello\r\n0\r\n\r\n\r\n", 5),
            Code::MalformedTrailerError
        );
        assert_eq!(
            code(b"5\r\nhello\r\n0\r\n\r\nx", 5),
            Code::MalformedTrailerError
        );
        let mut garbage = example();
        garbage.push(b'x');
        let r = decode(&garbage, 4096, signed(66_560), Some(seed(SEED))).unwrap_err();
        assert_eq!(r.code, Code::MalformedTrailerError);
    }

    #[test]
    fn a_truncated_body_is_refused() {
        let body = example();
        let mut cuts: Vec<usize> = (0..120).collect();
        cuts.extend([
            65_620, 65_625, 65_626, 65_700, 66_700, 66_737, 66_738, 66_800, 66_821, 66_823,
        ]);
        for cut in cuts {
            let r = decode(&body[..cut], 4096, signed(66_560), Some(seed(SEED))).unwrap_err();
            assert_eq!(r.code, Code::IncompleteBody, "{cut}");
        }
    }

    #[test]
    fn a_trailer_is_at_most_8_kib() {
        let line = |len: usize| format!("x-amz-checksum-crc32:{}\r\n", "A".repeat(len - 23));
        let body = |len| format!("1\r\na\r\n0\r\n{}\r\n", line(len));
        // A line that fills the budget with the trailer's last CRLF is taken, one past is not.
        let ok = decode(
            body(MAX_TRAILER - 2).as_bytes(),
            512,
            unsigned_trailer(1),
            None,
        )
        .unwrap();
        assert_eq!(ok.1.map(|v| v.len()), Some(MAX_TRAILER - 2 - 23));
        for len in [MAX_TRAILER - 1, MAX_TRAILER, 100_000] {
            let r = decode(body(len).as_bytes(), 512, unsigned_trailer(1), None).unwrap_err();
            assert_eq!(r.code, Code::MalformedTrailerError, "{len}");
        }
    }

    /// Every single-byte change of the example's framing, and of a sample of its data, is
    /// refused: no change gives a body that decodes.
    #[test]
    fn any_one_byte_change_is_refused() {
        let body = example();
        let framing: Vec<usize> = (0..88)
            .chain(65_624..65_712)
            .chain(66_736..66_824)
            .collect();
        // A fixed LCG picks the data positions and the changes.
        let mut x: u32 = 0x2545_f491;
        let mut next = || {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            x >> 8
        };
        let mut positions = framing;
        for _ in 0..64 {
            positions.push(88 + (next() as usize) % 65_536);
            positions.push(65_712 + (next() as usize) % 1024);
        }
        for pos in positions {
            let mut mutated = body.clone();
            let change = 1 + (next() % 255) as u8;
            mutated[pos] ^= change;
            let r = decode(&mutated, 8192, signed(66_560), Some(seed(SEED)));
            assert!(r.is_err(), "byte {pos} ^ {change:#x} was taken");
        }
    }

    #[test]
    fn modes_are_named_by_the_payload_hash() {
        assert_eq!(
            Mode::of("STREAMING-AWS4-HMAC-SHA256-PAYLOAD"),
            Some(Mode::Signed)
        );
        assert_eq!(
            Mode::of("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"),
            Some(Mode::SignedTrailer)
        );
        assert_eq!(
            Mode::of("STREAMING-UNSIGNED-PAYLOAD-TRAILER"),
            Some(Mode::UnsignedTrailer)
        );
        assert_eq!(Mode::of("STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD"), None);
        assert_eq!(Mode::of("UNSIGNED-PAYLOAD"), None);
        // A seed is kept for signed modes only.
        let dec = Decoder::new(Frames::of(b"", 1), unsigned_trailer(0), Some(seed(SEED)));
        assert!(dec.seed.is_none());
    }
}
