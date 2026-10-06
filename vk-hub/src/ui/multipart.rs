//! A `multipart/form-data` body (RFC 7578) read as it arrives, part by part, so a file in it
//! is never held whole in memory: what a browser posts for a form with a file input.
//!
//! Only what such a form sends is taken — parts with a `Content-Disposition: form-data` and a
//! name, in the order of the form's fields — and the reading is bounded: the body's size, a
//! deadline for all of it, and how long it may go quiet.

use bytes::Bytes;
use futures::{Stream, StreamExt};
use tokio::time::Instant;

/// The longest a part's headers may be: a name, a file name and a type.
const MAX_HEADERS: usize = 8 * 1024;

/// What a browser may send before the first boundary: nothing, but a little is allowed.
const MAX_PREAMBLE: usize = 1024;

/// Why a body is refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Past the bytes allowed.
    TooLarge,
    /// Past its deadline, or quiet for too long.
    Slow,
    /// Not the multipart body a form sends.
    Malformed(&'static str),
    /// The connection failed under it.
    Broken,
}

/// The boundary a `Content-Type: multipart/form-data; boundary=…` names, checked to be one
/// (RFC 2046: 1 to 70 characters).
pub fn boundary(content_type: &str) -> Option<String> {
    let (kind, params) = content_type.split_once(';')?;
    if !kind.trim().eq_ignore_ascii_case("multipart/form-data") {
        return None;
    }
    let value = params
        .split(';')
        .filter_map(|p| p.trim().split_once('='))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("boundary"))?
        .1
        .trim();
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value);
    let ok = (1..=70).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"'()+_,-./:=? ".contains(&b))
        && !value.ends_with(' ');
    ok.then(|| value.to_string())
}

/// One part's name, and whether it is a file.
#[derive(Debug, PartialEq, Eq)]
pub struct Part {
    pub name: String,
    pub file: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Before the first boundary.
    Start,
    /// In a part's data.
    Data,
    /// Just past a boundary: the next part's headers, or the end.
    Boundary,
    End,
}

/// The body being read.
pub struct Multipart<S> {
    stream: S,
    /// `\r\n--<boundary>`: what ends a part's data.
    delimiter: Vec<u8>,
    /// Read and not yet taken; at the start, a `\r\n` the first boundary is taken to follow.
    buf: Vec<u8>,
    state: State,
    read: u64,
    max: u64,
    deadline: Instant,
    idle: std::time::Duration,
}

impl<S, E> Multipart<S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
{
    /// `stream`, a body of at most `max` bytes delimited by `boundary`, all of it to arrive by
    /// `deadline` and none of it more than `idle` after the last.
    pub fn new(
        stream: S,
        boundary: &str,
        max: u64,
        deadline: Instant,
        idle: std::time::Duration,
    ) -> Self {
        let mut delimiter = b"\r\n--".to_vec();
        delimiter.extend_from_slice(boundary.as_bytes());
        Multipart {
            stream,
            delimiter,
            buf: b"\r\n".to_vec(),
            state: State::Start,
            read: 0,
            max,
            deadline,
            idle,
        }
    }

    /// Read more into the buffer. `false` at the end of the body.
    async fn fill(&mut self) -> Result<bool, Refusal> {
        let wake = self.deadline.min(Instant::now() + self.idle);
        match tokio::time::timeout_at(wake, self.stream.next()).await {
            Err(_) => Err(Refusal::Slow),
            Ok(None) => Ok(false),
            Ok(Some(Err(_))) => Err(Refusal::Broken),
            Ok(Some(Ok(chunk))) => {
                self.read = self.read.saturating_add(chunk.len() as u64);
                if self.read > self.max {
                    return Err(Refusal::TooLarge);
                }
                self.buf.extend_from_slice(&chunk);
                Ok(true)
            }
        }
    }

    /// Fill until the buffer holds `n` bytes; it is malformed for the body to end first.
    async fn want(&mut self, n: usize, what: &'static str) -> Result<(), Refusal> {
        while self.buf.len() < n {
            if !self.fill().await? {
                return Err(Refusal::Malformed(what));
            }
        }
        Ok(())
    }

    /// The next part, the rest of the one before skipped; `None` past the last.
    pub async fn next_part(&mut self) -> Result<Option<Part>, Refusal> {
        loop {
            match self.state {
                State::End => return Ok(None),
                State::Data => while self.chunk().await?.is_some() {},
                State::Start => loop {
                    if let Some(at) = find(&self.buf, &self.delimiter) {
                        self.buf.drain(..at + self.delimiter.len());
                        self.state = State::Boundary;
                        break;
                    }
                    if self.buf.len() > MAX_PREAMBLE + self.delimiter.len() {
                        return Err(Refusal::Malformed("no boundary starts it"));
                    }
                    if !self.fill().await? {
                        return Err(Refusal::Malformed("no boundary starts it"));
                    }
                },
                State::Boundary => {
                    self.want(2, "it ends inside a boundary").await?;
                    if self.buf.starts_with(b"--") {
                        // What follows the last boundary is not the form's.
                        self.state = State::End;
                        return Ok(None);
                    }
                    let headers = self.headers().await?;
                    self.state = State::Data;
                    return Ok(Some(part(&headers)?));
                }
            }
        }
    }

    /// The headers of the part that starts the buffer, its boundary line's end included, as
    /// lines; the buffer is left at its data.
    async fn headers(&mut self) -> Result<Vec<String>, Refusal> {
        loop {
            if let Some(at) = find(&self.buf, b"\r\n\r\n") {
                let block: Vec<u8> = self.buf.drain(..at + 4).collect();
                // The boundary line's end first, after any padding before it.
                let text = std::str::from_utf8(&block)
                    .map_err(|_| Refusal::Malformed("a part's headers are not text"))?;
                let (line, rest) = text
                    .split_once("\r\n")
                    .ok_or(Refusal::Malformed("a boundary line does not end"))?;
                if !line.bytes().all(|b| b == b' ' || b == b'\t') {
                    return Err(Refusal::Malformed("a boundary line goes on past it"));
                }
                return Ok(rest
                    .split("\r\n")
                    .filter(|l| !l.is_empty())
                    .map(str::to_string)
                    .collect());
            }
            if self.buf.len() > MAX_HEADERS {
                return Err(Refusal::Malformed("a part's headers are too long"));
            }
            if !self.fill().await? {
                return Err(Refusal::Malformed("it ends inside a part's headers"));
            }
        }
    }

    /// The next piece of the current part's data; `None` at its end.
    pub async fn chunk(&mut self) -> Result<Option<Vec<u8>>, Refusal> {
        if self.state != State::Data {
            return Ok(None);
        }
        loop {
            if let Some(at) = find(&self.buf, &self.delimiter) {
                let data: Vec<u8> = self.buf.drain(..at).collect();
                self.buf.drain(..self.delimiter.len());
                self.state = State::Boundary;
                return Ok((!data.is_empty()).then_some(data));
            }
            // All but what could be the start of a delimiter split across reads.
            let keep = self.delimiter.len() - 1;
            if self.buf.len() > keep {
                let n = self.buf.len() - keep;
                return Ok(Some(self.buf.drain(..n).collect()));
            }
            if !self.fill().await? {
                return Err(Refusal::Malformed("it ends inside a part"));
            }
        }
    }

    /// The current part's data whole, as text of at most `max` bytes.
    pub async fn text(&mut self, max: usize) -> Result<String, Refusal> {
        let mut out = Vec::new();
        while let Some(c) = self.chunk().await? {
            out.extend_from_slice(&c);
            if out.len() > max {
                return Err(Refusal::Malformed("a field is too long"));
            }
        }
        String::from_utf8(out).map_err(|_| Refusal::Malformed("a field is not text"))
    }
}

/// Where `needle` first starts in `hay`.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    let first = *needle.first()?;
    let mut from = 0;
    while let Some(at) = hay.get(from..)?.iter().position(|&b| b == first) {
        let at = from + at;
        match hay.get(at..at + needle.len()) {
            Some(window) if window == needle => return Some(at),
            Some(_) => from = at + 1,
            // Too near the end to hold it.
            None => return None,
        }
    }
    None
}

/// The part `headers` describe: a `form-data` disposition with a name.
fn part(headers: &[String]) -> Result<Part, Refusal> {
    let disposition = headers
        .iter()
        .filter_map(|h| h.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-disposition"))
        .map(|(_, v)| v.trim())
        .ok_or(Refusal::Malformed("a part has no Content-Disposition"))?;
    let params = params(disposition);
    if !params
        .first()
        .is_some_and(|(k, v)| v.is_none() && k.eq_ignore_ascii_case("form-data"))
    {
        return Err(Refusal::Malformed("a part is not form-data"));
    }
    let value = |key: &str| {
        params
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .and_then(|(_, v)| v.clone())
    };
    let name = value("name").ok_or(Refusal::Malformed("a part has no name"))?;
    Ok(Part {
        name,
        file: value("filename").is_some(),
    })
}

/// A header's `;`-separated parameters, as `(key, value)`: the first is the value proper,
/// with none. A quoted value may hold `;`, and `\` escapes inside one.
fn params(header: &str) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    let mut chars = header.chars().peekable();
    loop {
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == ';' || c == '=' {
                break;
            }
            key.push(c);
            chars.next();
        }
        let value = if chars.peek() == Some(&'=') {
            chars.next();
            while chars.peek().is_some_and(|c| *c == ' ') {
                chars.next();
            }
            let mut value = String::new();
            if chars.peek() == Some(&'"') {
                chars.next();
                while let Some(c) = chars.next() {
                    match c {
                        '"' => break,
                        '\\' => value.extend(chars.next()),
                        c => value.push(c),
                    }
                }
                // Up to the next `;`: nothing belongs after the closing quote.
                while chars.peek().is_some_and(|c| *c != ';') {
                    chars.next();
                }
            } else {
                while let Some(&c) = chars.peek() {
                    if c == ';' {
                        break;
                    }
                    value.push(c);
                    chars.next();
                }
            }
            Some(value.trim_end().to_string())
        } else {
            None
        };
        out.push((key.trim().to_string(), value));
        if chars.next().is_none() {
            return out;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::time::Duration;

    use super::*;

    fn body(chunks: &[&[u8]]) -> impl Stream<Item = Result<Bytes, Infallible>> + Unpin + use<> {
        futures::stream::iter(
            chunks
                .iter()
                .map(|c| Ok(Bytes::copy_from_slice(c)))
                .collect::<Vec<_>>(),
        )
    }

    fn reader<S, E>(s: S, max: u64) -> Multipart<S>
    where
        S: Stream<Item = Result<Bytes, E>> + Unpin,
    {
        let deadline = Instant::now() + Duration::from_secs(5);
        Multipart::new(s, "XyZ", max, deadline, Duration::from_secs(5))
    }

    const FORM: &[u8] = b"--XyZ\r\n\
        Content-Disposition: form-data; name=\"_csrf\"\r\n\r\n\
        abc\r\n\
        --XyZ\r\n\
        Content-Disposition: form-data; name=\"version\"\r\n\r\n\
        0.85.0\r\n\
        --XyZ\r\n\
        Content-Disposition: form-data; name=\"file\"; filename=\"a;b\\\"c\"\r\n\
        Content-Type: application/octet-stream\r\n\r\n\
        \x7fELF\r\n--Xy\r\n-XyZ data\r\n\
        --XyZ--\r\nepilogue";

    async fn read_all<S, E>(m: &mut Multipart<S>) -> Vec<(Part, Vec<u8>)>
    where
        S: Stream<Item = Result<Bytes, E>> + Unpin,
    {
        let mut parts = Vec::new();
        while let Some(p) = m.next_part().await.unwrap() {
            let mut data = Vec::new();
            while let Some(c) = m.chunk().await.unwrap() {
                data.extend_from_slice(&c);
            }
            parts.push((p, data));
        }
        parts
    }

    /// The parts of a form come out whole whichever way the body is cut, a boundary split
    /// across reads and look-alikes of it in the data included.
    #[tokio::test]
    async fn a_form_is_read_part_by_part_however_it_arrives() {
        let want = vec![
            (
                Part {
                    name: "_csrf".into(),
                    file: false,
                },
                b"abc".to_vec(),
            ),
            (
                Part {
                    name: "version".into(),
                    file: false,
                },
                b"0.85.0".to_vec(),
            ),
            (
                Part {
                    name: "file".into(),
                    file: true,
                },
                b"\x7fELF\r\n--Xy\r\n-XyZ data".to_vec(),
            ),
        ];
        for size in 1..FORM.len() {
            let chunks: Vec<&[u8]> = FORM.chunks(size).collect();
            let mut m = reader(body(&chunks), 1 << 20);
            assert_eq!(read_all(&mut m).await, want, "chunks of {size}");
        }
        // A field read as text, and the rest skipped.
        let mut m = reader(body(&[FORM]), 1 << 20);
        m.next_part().await.unwrap().unwrap();
        assert_eq!(m.text(16).await.unwrap(), "abc");
        assert_eq!(m.next_part().await.unwrap().unwrap().name, "version");
        assert_eq!(m.next_part().await.unwrap().unwrap().name, "file");
        assert_eq!(m.next_part().await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_body_past_its_bounds_or_not_a_form_is_refused() {
        let mut m = reader(body(&[FORM]), 64);
        assert_eq!(m.next_part().await.unwrap_err(), Refusal::TooLarge);
        let cut = &FORM[..FORM.len() - 20];
        let mut m = reader(body(&[cut]), 1 << 20);
        let last = loop {
            match m.next_part().await {
                Ok(Some(_)) => {}
                other => break other,
            }
        };
        assert!(matches!(last, Err(Refusal::Malformed(_))), "{last:?}");
        for bad in [
            &b"no boundary at all"[..],
            b"--XyZ\r\nContent-Type: text/plain\r\n\r\nx\r\n--XyZ--",
            b"--XyZ\r\nContent-Disposition: attachment; name=\"a\"\r\n\r\nx\r\n--XyZ--",
            b"--XyZtrailing\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--XyZ--",
        ] {
            let mut m = reader(body(&[bad]), 1 << 20);
            assert!(
                matches!(m.next_part().await, Err(Refusal::Malformed(_))),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        // A body that stops arriving.
        let stalled = futures::stream::pending::<Result<Bytes, Infallible>>();
        let mut m = Multipart::new(
            stalled,
            "XyZ",
            1 << 20,
            Instant::now() + Duration::from_secs(5),
            Duration::from_millis(50),
        );
        assert_eq!(m.next_part().await.unwrap_err(), Refusal::Slow);
    }

    #[test]
    fn a_boundary_is_taken_from_the_content_type() {
        assert_eq!(
            boundary("multipart/form-data; boundary=----WebKitFormBoundaryAbc").as_deref(),
            Some("----WebKitFormBoundaryAbc")
        );
        assert_eq!(
            boundary("Multipart/Form-Data; charset=utf-8; boundary=\"a b\"").as_deref(),
            Some("a b")
        );
        for bad in [
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "multipart/form-data; boundary=",
            "multipart/mixed; boundary=x",
            &format!("multipart/form-data; boundary={}", "x".repeat(71)),
        ] {
            assert_eq!(boundary(bad), None, "{bad}");
        }
    }
}
