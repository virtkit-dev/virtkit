//! Hub tokens: a registry enrolled with `[hub] tokens = true` takes the tokens its hub signs
//! (`vk_hub_proto::token`), checked here against the keys the hub sent, without asking it.
//! A token is presented as a bearer, or as the password of a Basic pair, as docker-style
//! clients send a registry credential; it is told apart from every other credential by its
//! `vkt_` prefix.

use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use hyper::HeaderMap;
use vk_hub_proto::token::{Claims, TOKEN_PREFIX, TokenKey};
use vk_peer::token::Refused;

/// The tokens this registry takes: none until it is enrolled with `[hub] tokens = true`,
/// then those for its ID signed by a key the hub sent.
#[derive(Default)]
pub struct TokenGate {
    gate: RwLock<Option<Gate>>,
    /// Refusals logged and held back: anyone can send a `vkt_` credential, so the log
    /// takes a line per [`REFUSAL_LOG_EVERY`] at most.
    refusals: Mutex<Refusals>,
}

/// Shortest time between two lines logging a refused token.
const REFUSAL_LOG_EVERY: Duration = Duration::from_secs(60);

#[derive(Default)]
struct Refusals {
    last_logged: Option<Instant>,
    held_back: u64,
}

struct Gate {
    aud: String,
    keys: Vec<TokenKey>,
}

impl TokenGate {
    /// Take tokens for the registry `aud`, signed by one of `keys`.
    pub fn open(&self, aud: &str, keys: Vec<TokenKey>) {
        *self.gate.write().unwrap_or_else(|e| e.into_inner()) = Some(Gate {
            aud: aud.to_string(),
            keys,
        });
    }

    /// Refuse every token from now on, while still telling them apart: the keys go, so a
    /// token is a 401 rather than a credential the mode checks. Nothing changes when tokens
    /// are not taken.
    pub fn close(&self) {
        if let Some(gate) = self
            .gate
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
        {
            gate.keys.clear();
        }
    }

    /// The keys tokens are checked against, `None` when tokens are not taken.
    #[cfg(test)]
    pub(crate) fn keys(&self) -> Option<Vec<TokenKey>> {
        self.gate
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|g| g.keys.clone())
    }

    /// `token`'s claims, checked at `now`; `None` when tokens are not taken.
    pub(crate) fn check(&self, token: &str, now: u64) -> Option<Result<Claims, Refused>> {
        let gate = self.gate.read().unwrap_or_else(|e| e.into_inner());
        let gate = gate.as_ref()?;
        Some(vk_peer::token::verify(token, &gate.keys, &gate.aud, now))
    }

    /// Log that a token was refused for `why`, unless a refusal was logged less than
    /// [`REFUSAL_LOG_EVERY`] ago; the next line counts those held back.
    pub(crate) fn log_refusal(&self, why: &Refused) {
        if let Some(line) = self.refusal_line(why, Instant::now()) {
            eprintln!("{line}");
        }
    }

    /// The line [`TokenGate::log_refusal`] writes at `now`, if any. It names the reason,
    /// never the token.
    fn refusal_line(&self, why: &Refused, now: Instant) -> Option<String> {
        let mut r = self.refusals.lock().unwrap_or_else(|e| e.into_inner());
        if r.last_logged
            .is_some_and(|t| now.saturating_duration_since(t) < REFUSAL_LOG_EVERY)
        {
            r.held_back = r.held_back.saturating_add(1);
            return None;
        }
        let held_back = std::mem::take(&mut r.held_back);
        r.last_logged = Some(now);
        Some(if held_back == 0 {
            format!("vk-registry: a hub token refused: {why}")
        } else {
            format!(
                "vk-registry: a hub token refused: {why} ({held_back} more refused since the \
                 last such line)"
            )
        })
    }
}

/// The hub token a request presents: `Authorization: Bearer vkt_…`, or a Basic pair whose
/// password is one.
pub(crate) fn presented(headers: &HeaderMap) -> Option<String> {
    let value = headers
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    let (scheme, credential) = value.split_once(' ')?;
    let credential = credential.trim_start();
    if scheme.eq_ignore_ascii_case("bearer") {
        return credential
            .starts_with(TOKEN_PREFIX)
            .then(|| credential.to_string());
    }
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = crate::auth::base64_decode(credential.trim())?;
    let pair = String::from_utf8(raw).ok()?;
    let (_, pass) = pair.split_once(':')?;
    pass.starts_with(TOKEN_PREFIX).then(|| pass.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(hyper::header::AUTHORIZATION, value.parse().unwrap());
        h
    }

    #[test]
    fn a_token_is_found_as_a_bearer_or_a_basic_password_only() {
        assert_eq!(
            presented(&headers("Bearer vkt_a.b")).as_deref(),
            Some("vkt_a.b")
        );
        assert_eq!(
            presented(&headers("bearer  vkt_a.b")).as_deref(),
            Some("vkt_a.b")
        );
        let basic = format!("Basic {}", vk_hub_proto::to_base64(b"job:vkt_a.b"));
        assert_eq!(presented(&headers(&basic)).as_deref(), Some("vkt_a.b"));
        let user_half = format!("Basic {}", vk_hub_proto::to_base64(b"vkt_a.b:x"));
        assert_eq!(presented(&headers(&user_half)), None);
        assert_eq!(presented(&headers("Bearer vkr_key")), None);
        assert_eq!(presented(&HeaderMap::new()), None);
    }

    /// One line a minute at most, the next one counting those held back.
    #[test]
    fn refusals_are_logged_once_a_minute_with_a_count() {
        let gate = TokenGate::default();
        let t0 = Instant::now();
        let line = gate.refusal_line(&Refused::Expired, t0).unwrap();
        assert_eq!(line, "vk-registry: a hub token refused: expired");
        assert_eq!(gate.refusal_line(&Refused::Malformed, t0), None);
        let soon = t0 + Duration::from_secs(59);
        assert_eq!(gate.refusal_line(&Refused::Malformed, soon), None);
        let later = t0 + REFUSAL_LOG_EVERY;
        let line = gate.refusal_line(&Refused::Malformed, later).unwrap();
        assert!(line.contains("(2 more refused"), "{line}");
        assert_eq!(gate.refusal_line(&Refused::Malformed, later), None);
    }

    #[test]
    fn a_closed_gate_checks_nothing() {
        let gate = TokenGate::default();
        assert_eq!(gate.keys(), None);
        assert!(gate.check("vkt_a.b", 0).is_none());
        gate.open("9c2f4e1a7b3d5e60f1a2b3c4d5e6f708", Vec::new());
        assert_eq!(gate.keys(), Some(Vec::new()));
        assert_eq!(gate.check("vkt_a.b", 0), Some(Err(Refused::Malformed)));
    }
}
