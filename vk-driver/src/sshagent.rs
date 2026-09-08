//! A filtering ssh-agent proxy. It speaks the ssh-agent protocol between the guest's
//! forwarded `SSH_AUTH_SOCK` and the host's real agent, exposing only an allowlisted subset
//! of keys: it answers `REQUEST_IDENTITIES` with just the allowed keys and refuses to sign
//! with (or otherwise touch) any other key. So a guest can use the host agent for a chosen
//! set of targets without gaining the ability to authenticate as every key you have loaded.
//!
//! The allowlist is the set of public-key blobs (the wire encoding the agent reports for a
//! key) read from `.pub` files — typically the `.pub` siblings of the `IdentityFile`s of the
//! `--ssh-host` aliases.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

// ssh-agent message types (OpenSSH PROTOCOL.agent).
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;

/// Read each `.pub` file and return the decoded key blobs (the allowlist). A `.pub` line is
/// `<type> <base64-blob> [comment]`; the blob is what the agent reports per key. Missing
/// files are skipped with a warning (a host whose key we can't see simply won't be offered).
pub fn load_allow(pub_files: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for p in pub_files {
        let text = match std::fs::read_to_string(p) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("virtkit: ssh-agent filter: skipping {} ({e})", p.display());
                continue;
            }
        };
        let b64 = text
            .split_whitespace()
            .nth(1)
            .with_context(|| format!("{}: not an OpenSSH public key", p.display()))?;
        out.push(b64_decode(b64).with_context(|| format!("{}: bad base64 key blob", p.display()))?);
    }
    Ok(out)
}

/// One identity the agent holds: its wire blob and comment.
#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    pub blob: Vec<u8>,
    pub comment: String,
}

/// Ask the agent at `upstream` for its identities (`REQUEST_IDENTITIES` → `IDENTITIES_ANSWER`).
pub fn list_identities(upstream: &Path) -> Result<Vec<Identity>> {
    let mut up = UnixStream::connect(upstream)
        .with_context(|| format!("connecting to the agent at {}", upstream.display()))?;
    write_msg(&mut up, &[SSH_AGENTC_REQUEST_IDENTITIES])?;
    let answer = read_msg(&mut up)?
        .ok_or_else(|| anyhow::anyhow!("the agent closed the connection before answering"))?;
    parse_identities(&answer)
}

/// Parse an `IDENTITIES_ANSWER`: the type byte, a `u32` count, then that many `(blob, comment)`
/// string pairs.
fn parse_identities(answer: &[u8]) -> Result<Vec<Identity>> {
    if answer.first().copied() != Some(SSH_AGENT_IDENTITIES_ANSWER) {
        bail!("the agent did not answer REQUEST_IDENTITIES with an identities list");
    }
    let (nkeys, mut rest) = answer
        .get(1..)
        .and_then(read_u32)
        .context("truncated identities answer")?;
    // `nkeys` is untrusted: never let it drive a preallocation (a bogus 0xFFFFFFFF would try a
    // multi-GB reserve). Grow as we actually read, like `filter_identities`.
    let mut out = Vec::new();
    for _ in 0..nkeys {
        let (blob, r1) = read_string(rest).context("truncated key blob in identities answer")?;
        let (comment, r2) =
            read_string(r1).context("truncated key comment in identities answer")?;
        rest = r2;
        // Agent comments are conventionally UTF-8; lossy decoding only risks a benign token
        // mismatch (a comment token that no longer compares equal), never memory unsafety.
        out.push(Identity {
            blob: blob.to_vec(),
            comment: String::from_utf8_lossy(comment).into_owned(),
        });
    }
    Ok(out)
}

/// Serve the filtering proxy on `listen`, relaying to the real agent at `upstream`, exposing
/// only keys in `allow`. One thread per client connection; runs until the socket is removed.
pub fn run_proxy(listen: &Path, upstream: &Path, allow: &[Vec<u8>]) -> Result<()> {
    let _ = std::fs::remove_file(listen);
    let l = UnixListener::bind(listen)
        .with_context(|| format!("binding ssh-agent proxy at {}", listen.display()))?;
    for conn in l.incoming() {
        let Ok(client) = conn else { continue };
        let upstream = upstream.to_path_buf();
        let allow = allow.to_vec();
        std::thread::spawn(move || {
            if let Err(e) = handle_conn(client, &upstream, &allow) {
                eprintln!("virtkit: ssh-agent filter: connection ended ({e:#})");
            }
        });
    }
    Ok(())
}

/// Relay one client connection: forward allowed requests to the upstream agent, answer the
/// rest with `SSH_AGENT_FAILURE` (fail closed). REQUEST_IDENTITIES is filtered to the
/// allowlist; SIGN_REQUEST is forwarded only for an allowed key.
fn handle_conn(mut client: UnixStream, upstream: &Path, allow: &[Vec<u8>]) -> Result<()> {
    let mut up = UnixStream::connect(upstream)
        .with_context(|| format!("connecting to the agent at {}", upstream.display()))?;
    while let Some(req) = read_msg(&mut client)? {
        let reply = match req.first().copied() {
            Some(SSH_AGENTC_REQUEST_IDENTITIES) => {
                write_msg(&mut up, &req)?;
                let answer = read_msg(&mut up)?.unwrap_or_default();
                if answer.first().copied() == Some(SSH_AGENT_IDENTITIES_ANSWER) {
                    filter_identities(&answer, allow)
                } else {
                    answer
                }
            }
            Some(SSH_AGENTC_SIGN_REQUEST) if sign_key_allowed(&req, allow) => {
                write_msg(&mut up, &req)?;
                read_msg(&mut up)?.unwrap_or_else(|| vec![SSH_AGENT_FAILURE])
            }
            // unknown / disallowed (sign with a filtered key, add, remove, lock, …)
            _ => vec![SSH_AGENT_FAILURE],
        };
        write_msg(&mut client, &reply)?;
    }
    Ok(())
}

/// Rebuild an `IDENTITIES_ANSWER`, keeping only keys whose blob is in `allow`. On any parse
/// error, return an empty (zero-key) answer — fail closed rather than leak unfiltered keys.
fn filter_identities(answer: &[u8], allow: &[Vec<u8>]) -> Vec<u8> {
    let empty = vec![SSH_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 0];
    let Some((nkeys, mut rest)) = answer.get(1..).and_then(read_u32) else {
        return empty;
    };
    let mut kept: Vec<(&[u8], &[u8])> = Vec::new();
    for _ in 0..nkeys {
        let Some((blob, r1)) = read_string(rest) else {
            return empty;
        };
        let Some((comment, r2)) = read_string(r1) else {
            return empty;
        };
        rest = r2;
        if allow.iter().any(|a| a == blob) {
            kept.push((blob, comment));
        }
    }
    let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
    out.extend_from_slice(&(kept.len() as u32).to_be_bytes());
    for (blob, comment) in kept {
        put_string(&mut out, blob);
        put_string(&mut out, comment);
    }
    out
}

/// The key blob a `SIGN_REQUEST` targets is its first string; is it in the allowlist?
fn sign_key_allowed(req: &[u8], allow: &[Vec<u8>]) -> bool {
    match req.get(1..).and_then(read_string) {
        Some((blob, _)) => allow.iter().any(|a| a == blob),
        None => false,
    }
}

fn read_msg(r: &mut impl Read) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    if let Err(e) = r.read_exact(&mut len) {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(None); // peer closed
        }
        return Err(e).context("reading agent message length");
    }
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > 256 * 1024 {
        bail!("implausible agent message length {n}");
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)
        .context("reading agent message body")?;
    Ok(Some(buf))
}

fn write_msg(w: &mut impl Write, payload: &[u8]) -> Result<()> {
    w.write_all(&(payload.len() as u32).to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

/// Read a big-endian u32 prefix, returning it and the remaining slice.
fn read_u32(b: &[u8]) -> Option<(u32, &[u8])> {
    let head = b.get(..4)?;
    Some((u32::from_be_bytes(head.try_into().unwrap()), &b[4..]))
}

/// Read an ssh `string` (u32 length + bytes), returning it and the remaining slice.
fn read_string(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = read_u32(b)?;
    let len = len as usize;
    let val = rest.get(..len)?;
    Some((val, &rest[len..]))
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// Encode bytes as standard base64 with `=` padding.
pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(ALPHABET[(n >> 18 & 0x3f) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6 & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Decode standard base64 (with optional `=` padding); `None` on any invalid input.
pub(crate) fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let s = s.trim().trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.chunks(4) {
        let mut acc = 0u32;
        for &c in chunk {
            acc = (acc << 6) | val(c)?;
        }
        // a chunk of k base64 chars carries k*6 bits -> (k*6)/8 bytes
        acc <<= 6 * (4 - chunk.len());
        for i in 0..(chunk.len() * 6 / 8) {
            out.push((acc >> (16 - 8 * i)) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident_answer(keys: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
        out.extend_from_slice(&(keys.len() as u32).to_be_bytes());
        for (blob, comment) in keys {
            put_string(&mut out, blob);
            put_string(&mut out, comment);
        }
        out
    }

    #[test]
    fn filters_identities_to_the_allowlist() {
        let answer = ident_answer(&[
            (b"KEYA", b"a@host"),
            (b"KEYB", b"b@host"),
            (b"KEYC", b"c@host"),
        ]);
        let out = filter_identities(&answer, &[b"KEYA".to_vec(), b"KEYC".to_vec()]);
        // exactly the two allowed keys survive, in order, with the count fixed
        assert_eq!(
            out,
            ident_answer(&[(b"KEYA", b"a@host"), (b"KEYC", b"c@host")])
        );
    }

    #[test]
    fn empty_allowlist_hides_every_key() {
        let answer = ident_answer(&[(b"KEYA", b"a"), (b"KEYB", b"b")]);
        assert_eq!(filter_identities(&answer, &[]), ident_answer(&[]));
    }

    #[test]
    fn malformed_answer_fails_closed() {
        // claims 2 keys but carries no key bodies
        let bad = vec![SSH_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 2];
        assert_eq!(
            filter_identities(&bad, &[b"KEYA".to_vec()]),
            ident_answer(&[])
        );
    }

    #[test]
    fn sign_request_gated_by_key() {
        let mut req = vec![SSH_AGENTC_SIGN_REQUEST];
        put_string(&mut req, b"KEYA"); // key blob
        put_string(&mut req, b"challenge"); // data
        req.extend_from_slice(&0u32.to_be_bytes()); // flags
        assert!(sign_key_allowed(&req, &[b"KEYA".to_vec()]));
        assert!(!sign_key_allowed(&req, &[b"KEYB".to_vec()]));
        assert!(!sign_key_allowed(
            &[SSH_AGENTC_SIGN_REQUEST],
            &[b"KEYA".to_vec()]
        )); // truncated
    }

    #[test]
    fn base64_decodes_known_vectors() {
        assert_eq!(b64_decode("").unwrap(), b"");
        assert_eq!(b64_decode("Zg==").unwrap(), b"f");
        assert_eq!(b64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(b64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(b64_decode("Zm9vYmFy").unwrap(), b"foobar");
        assert!(b64_decode("not base64!").is_none());
    }

    #[test]
    fn base64_encodes_known_vectors_and_round_trips() {
        assert_eq!(b64_encode(b""), "");
        assert_eq!(b64_encode(b"f"), "Zg==");
        assert_eq!(b64_encode(b"fo"), "Zm8=");
        assert_eq!(b64_encode(b"foo"), "Zm9v");
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
        for v in [
            b"".to_vec(),
            b"\x00\x01\x02\xff".to_vec(),
            b"a longer blob".to_vec(),
        ] {
            assert_eq!(b64_decode(&b64_encode(&v)).unwrap(), v);
        }
    }

    #[test]
    fn parses_an_identities_answer() {
        let answer = ident_answer(&[(b"BLOB1", b"a@host"), (b"BLOB2", b"b@host")]);
        let got = parse_identities(&answer).unwrap();
        assert_eq!(
            got,
            vec![
                Identity {
                    blob: b"BLOB1".to_vec(),
                    comment: "a@host".into()
                },
                Identity {
                    blob: b"BLOB2".to_vec(),
                    comment: "b@host".into()
                },
            ]
        );
        // Empty list, and a wrong type byte, are handled.
        assert!(parse_identities(&ident_answer(&[])).unwrap().is_empty());
        assert!(parse_identities(&[SSH_AGENT_FAILURE]).is_err());
        // A count larger than the body carries is a truncation error, not a panic.
        assert!(parse_identities(&[SSH_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 2]).is_err());
    }
}
