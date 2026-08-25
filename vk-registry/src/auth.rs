//! Client authentication for the network-exposed server. A single scheme at a time:
//! a static bearer token, or HTTP Basic — enough to gate a central registry shared by
//! many runners. When auth is configured every path needs credentials, including the
//! `GET /v2/` version probe — its 401 + `WWW-Authenticate` is how OCI clients discover
//! they must authenticate before the real blob requests.

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response};

/// The configured authentication scheme.
#[derive(Clone, Default)]
pub enum Auth {
    /// No authentication (loopback / trusted network).
    #[default]
    None,
    /// HTTP Basic: `Authorization: Basic base64(user:pass)`.
    Basic { user: String, pass: String },
    /// Static bearer: `Authorization: Bearer <token>`.
    Bearer { token: String },
}

impl Auth {
    pub fn enabled(&self) -> bool {
        !matches!(self, Auth::None)
    }

    /// Whether `req` carries valid credentials (always true when disabled).
    pub fn allows(&self, req: &Request<Incoming>) -> bool {
        match self {
            Auth::None => true,
            Auth::Bearer { token } => authorization(req)
                .and_then(|v| v.strip_prefix("Bearer "))
                .is_some_and(|t| constant_eq(t.as_bytes(), token.as_bytes())),
            Auth::Basic { user, pass } => authorization(req)
                .and_then(|v| v.strip_prefix("Basic "))
                .and_then(|b| base64_decode(b.trim()))
                .and_then(|raw| String::from_utf8(raw).ok())
                .is_some_and(|creds| match creds.split_once(':') {
                    Some((u, p)) => {
                        // avoid short-circuit so the pair is compared in full
                        constant_eq(u.as_bytes(), user.as_bytes())
                            & constant_eq(p.as_bytes(), pass.as_bytes())
                    }
                    None => false,
                }),
        }
    }

    /// The 401 challenge to return for an unauthenticated protected request.
    pub fn challenge(&self) -> Response<Full<Bytes>> {
        let challenge = match self {
            Auth::Basic { .. } => "Basic realm=\"vk-registry\"",
            _ => "Bearer realm=\"vk-registry\"",
        };
        crate::unauthorized(challenge, "authentication required")
    }
}

fn authorization(req: &Request<Incoming>) -> Option<&str> {
    req.headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
}

/// Length-checked byte comparison that does not short-circuit on the first differing
/// byte — a cheap constant-time-ish guard for secret comparison.
pub(crate) fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Minimal standard-alphabet base64 decode (for the Basic credentials); `None` on any
/// invalid input. Handles optional `=` padding.
pub(crate) fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let s = s.trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in s {
        let v = val(c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip_known_vectors() {
        assert_eq!(base64_decode("dXNlcjpwYXNz").unwrap(), b"user:pass");
        assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode("Zm9vYg==").unwrap(), b"foob");
        assert!(base64_decode("not base64!").is_none());
    }

    #[test]
    fn constant_eq_matches_only_equal() {
        assert!(constant_eq(b"secret", b"secret"));
        assert!(!constant_eq(b"secret", b"secreT"));
        assert!(!constant_eq(b"secret", b"secre"));
    }
}
