//! Client authentication for the network-exposed server. A single scheme at a time:
//! a static bearer token, or HTTP Basic — enough to gate a central registry shared by
//! many runners. When auth is configured every path needs credentials, including the
//! `GET /v2/` version probe — its 401 + `WWW-Authenticate` is how OCI clients discover
//! they must authenticate before the real blob requests.

use hyper::{HeaderMap, Response};

use crate::Body;

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

    /// Whether a request with `headers` carries valid credentials (always true when
    /// disabled).
    pub fn allows(&self, headers: &HeaderMap) -> bool {
        match self {
            Auth::None => true,
            Auth::Bearer { token } => authorization(headers)
                .and_then(|v| v.strip_prefix("Bearer "))
                .is_some_and(|t| constant_eq(t.as_bytes(), token.as_bytes())),
            Auth::Basic { user, pass } => authorization(headers)
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

    /// The secret a SigV4 access key id `id` signs with, when it is not `id` itself: in Basic
    /// mode, the password when `id` is the user (compared in constant time), so the secret
    /// never crosses the wire. `None` otherwise, a bearer included: its id is its secret.
    pub(crate) fn secret_for(&self, id: &str) -> Option<&str> {
        match self {
            Auth::Basic { user, pass } if constant_eq(id.as_bytes(), user.as_bytes()) => Some(pass),
            _ => None,
        }
    }

    /// The 401 challenge to return for an unauthenticated protected request.
    ///
    /// Each mode names its own scheme, unlike accounts mode, which challenges with `Basic`
    /// whatever the credential is (see [`crate::accounts::challenge`]): here a client is
    /// configured for one scheme and sends it unprompted, so the challenge is a statement of
    /// what this server takes rather than something a client has to be steered by.
    pub fn challenge(&self) -> Response<Body> {
        let challenge = self.challenge_value().unwrap_or(BEARER_CHALLENGE);
        crate::unauthorized(challenge, "authentication required")
    }

    /// The `WWW-Authenticate` value [`Self::challenge`] carries, `None` when anyone is let in.
    pub fn challenge_value(&self) -> Option<&'static str> {
        match self {
            Auth::None => None,
            Auth::Basic { .. } => Some(BASIC_CHALLENGE),
            Auth::Bearer { .. } => Some(BEARER_CHALLENGE),
        }
    }
}

/// The `WWW-Authenticate` values this server challenges with.
pub(crate) const BASIC_CHALLENGE: &str = "Basic realm=\"vk-registry\"";
const BEARER_CHALLENGE: &str = "Bearer realm=\"vk-registry\"";

fn authorization(headers: &HeaderMap) -> Option<&str> {
    headers
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
    fn only_the_basic_user_has_a_secret_other_than_itself() {
        let basic = Auth::Basic {
            user: "ci".into(),
            pass: "pa55".into(),
        };
        assert_eq!(basic.secret_for("ci"), Some("pa55"));
        assert_eq!(basic.secret_for("pa55"), None);
        assert_eq!(basic.secret_for("c"), None);
        let bearer = Auth::Bearer { token: "t".into() };
        assert_eq!(bearer.secret_for("t"), None);
        assert_eq!(Auth::None.secret_for("x"), None);
    }

    #[test]
    fn constant_eq_matches_only_equal() {
        assert!(constant_eq(b"secret", b"secret"));
        assert!(!constant_eq(b"secret", b"secreT"));
        assert!(!constant_eq(b"secret", b"secre"));
    }
}
