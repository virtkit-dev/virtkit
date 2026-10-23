//! Registry tokens: what the hub signs for a registry to check, without asking the hub.
//!
//! A token is `vkt_<claims>.<signature>`: the claims as JSON, then an ed25519 signature over
//! [`signed_message`] of the claims part, both base64url without padding. The claims say who
//! the token is for (`sub`), which registry may accept it (`aud`, the registry's ID), until
//! when (`exp`), and what it grants: path prefixes, each with read, write and lock rights
//! ([`Grant`]). This module holds the formats; signing and checking are `vk-peer`'s.
//!
//! A grant's prefix covers every kind of reference beneath it alike:
//! - repositories `<prefix>` and `<prefix>/…`;
//! - plain files under `/dav/files/<prefix>/…`, which the registry stores as the repositories
//!   `files/<prefix>/…`;
//! - lock and failure-memo names `<prefix>:<key>`, or `<prefix>/…:<key>`.

use serde::{Deserialize, Serialize};

use crate::{SHA256_LEN, valid_id};

/// What every token starts with.
pub const TOKEN_PREFIX: &str = "vkt_";

/// The domain the signature is made in, so it is never valid as any other signed message.
pub const SIGNATURE_LABEL: &[u8] = b"vk-fleet registry-token v1\0";

/// The longest token a registry reads, so a header cannot make it parse megabytes. The
/// largest well-formed claims, [`MAX_GRANTS`] grants of [`MAX_PREFIX_LEN`]-byte prefixes with
/// every right, take about 26 KiB once encoded, so every well-formed token fits.
pub const MAX_TOKEN_LEN: usize = 32 * 1024;

/// The most grants a token carries.
pub const MAX_GRANTS: usize = 64;

/// The longest a grant's prefix may be, as a repository name may.
pub const MAX_PREFIX_LEN: usize = 255;

/// How far a registry's clock may be ahead of the hub's when it checks `exp`.
pub const SKEW_SECS: u64 = 60;

/// The longest a token may live, `exp - iat`.
pub const MAX_TTL_SECS: u64 = 7 * 24 * 3600;

/// The longest `sub` or `pipeline` may be.
pub const MAX_LABEL_LEN: usize = 128;

/// Where the files of `/dav/files/` are stored as repositories.
pub const FILES_REPO: &str = "files";

/// A token's claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    /// The signing key's ID ([`key_id`] of its public key).
    pub kid: String,
    /// The registry's ID: another registry refuses the token.
    pub aud: String,
    /// Who the token is for: `job:<hub job id>` for a placed job.
    pub sub: String,
    /// The token's own ID, for the audit log and revocation.
    pub jti: String,
    /// The pipeline the token's job belongs to, `<gitlab>/<pipeline id>`: a lock request's
    /// pipeline must be this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipeline: Option<String>,
    pub iat: u64,
    pub exp: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<Grant>,
}

/// What a token may do under a prefix.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub prefix: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub read: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub write: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub lock: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// What a request needs of a repository.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepoRight {
    Read,
    Write,
}

/// A token-signing public key, as the hub sends it to its registries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenKey {
    /// [`key_id`] of `public_key`.
    pub kid: String,
    /// The raw ed25519 public key, standard base64.
    pub public_key: String,
}

impl Grant {
    /// Whether this grant gives `right` on the repository `name`, a plain file's repository
    /// (`files/<prefix>/…`) included. A name outside the repository grammar gets nothing.
    pub fn allows_repo(&self, name: &str, right: RepoRight) -> bool {
        let has = match right {
            RepoRight::Read => self.read,
            RepoRight::Write => self.write,
        };
        if !has || !valid_path(name) {
            return false;
        }
        under(&self.prefix, name)
            || name
                .strip_prefix(FILES_REPO)
                .and_then(|rest| rest.strip_prefix('/'))
                .is_some_and(|rest| under(&self.prefix, rest))
    }

    /// Whether this grant lets its holder use the lock or failure memo `name`:
    /// `<prefix>:<key>`, or a name under a sub-path of the prefix. A path outside the
    /// repository grammar gets nothing.
    pub fn allows_lock(&self, name: &str) -> bool {
        self.lock
            && name.split_once(':').is_some_and(|(path, key)| {
                !key.is_empty() && valid_path(path) && under(&self.prefix, path)
            })
    }

    /// Rights as a short string, `r`, `w` and `l` in that order: `VK_REGISTRY_NAMESPACES`'s.
    pub fn rights(&self) -> String {
        [(self.read, 'r'), (self.write, 'w'), (self.lock, 'l')]
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, c)| *c)
            .collect()
    }
}

/// Whether `path` is `prefix` or beneath it, cut at a component: `p/1` covers `p/1` and
/// `p/1/x`, never `p/10`. It does not check either against the repository grammar; the
/// `allows_*` methods do, before calling it.
pub fn under(prefix: &str, path: &str) -> bool {
    !prefix.is_empty()
        && path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Whether `prefix` may be a grant's: a repository name's grammar, lowercase components of
/// `[a-z0-9]+` joined by `.`, `_`, `__` or `-` runs, separated by `/`, and not under
/// [`FILES_REPO`], which grants reach through their own prefix.
pub fn valid_prefix(prefix: &str) -> bool {
    prefix.len() <= MAX_PREFIX_LEN && valid_path(prefix) && !under(FILES_REPO, prefix)
}

/// Whether `path` is in the repository grammar: `/`-separated [`valid_component`]s.
fn valid_path(path: &str) -> bool {
    path.split('/').all(valid_component)
}

/// Whether `c` is a repository name component, OCI's `[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*`.
fn valid_component(c: &str) -> bool {
    let alnum = |x: &u8| x.is_ascii_lowercase() || x.is_ascii_digit();
    let mut rest = c.as_bytes();
    loop {
        let run = rest.iter().take_while(|x| alnum(x)).count();
        if run == 0 {
            return false;
        }
        rest = rest.get(run..).unwrap_or_default();
        let sep = match rest {
            [] => return true,
            [b'_', b'_', ..] => 2,
            [b'.' | b'_', ..] => 1,
            [b'-', ..] => rest.iter().take_while(|&&x| x == b'-').count(),
            _ => return false,
        };
        rest = rest.get(sep..).unwrap_or_default();
    }
}

/// Whether `s` may be a `sub` or `pipeline`: printable ASCII without spaces, at most
/// [`MAX_LABEL_LEN`] bytes.
fn valid_label(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_LABEL_LEN && s.bytes().all(|b| b.is_ascii_graphic())
}

impl Claims {
    /// Whether any grant gives `right` on the repository `name`.
    pub fn allows_repo(&self, name: &str, right: RepoRight) -> bool {
        self.grants.iter().any(|g| g.allows_repo(name, right))
    }

    /// Whether any grant covers the lock or memo `name`.
    pub fn allows_lock(&self, name: &str) -> bool {
        self.grants.iter().any(|g| g.allows_lock(name))
    }

    /// Whether the claims are well formed: IDs, bounded labels, a bounded list of valid
    /// prefixes, and an `exp` after `iat` by at most [`MAX_TTL_SECS`]. Says nothing of the
    /// signature or the time.
    pub fn well_formed(&self) -> bool {
        valid_id(&self.aud)
            && valid_id(&self.kid)
            && valid_id(&self.jti)
            && valid_label(&self.sub)
            && self.pipeline.as_deref().is_none_or(valid_label)
            && self
                .exp
                .checked_sub(self.iat)
                .is_some_and(|ttl| ttl > 0 && ttl <= MAX_TTL_SECS)
            && self.grants.len() <= MAX_GRANTS
            && self.grants.iter().all(|g| valid_prefix(&g.prefix))
    }

    /// Whether the claims are still valid at `now`, allowing [`SKEW_SECS`].
    pub fn live_at(&self, now: u64) -> bool {
        now <= self.exp.saturating_add(SKEW_SECS)
    }
}

/// The message a token's signature covers: [`SIGNATURE_LABEL`], then the claims part as it
/// appears in the token.
pub fn signed_message(claims_part: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIGNATURE_LABEL.len() + claims_part.len());
    m.extend_from_slice(SIGNATURE_LABEL);
    m.extend_from_slice(claims_part.as_bytes());
    m
}

/// A token's parts, not yet checked: the claims part as it appears, the claims it decodes
/// to, and the signature.
#[derive(Debug)]
pub struct Parsed {
    pub claims_part: String,
    pub claims: Claims,
    pub signature: Vec<u8>,
}

/// Split and decode a token; `None` unless it has the prefix, two base64url parts, claims
/// that parse and are [`Claims::well_formed`], and a 64-byte signature.
pub fn parse(token: &str) -> Option<Parsed> {
    if token.len() > MAX_TOKEN_LEN {
        return None;
    }
    let (claims_part, sig_part) = token.strip_prefix(TOKEN_PREFIX)?.split_once('.')?;
    let claims: Claims = serde_json::from_slice(&from_base64url(claims_part)?).ok()?;
    let signature = from_base64url(sig_part)?;
    (claims.well_formed() && signature.len() == 64).then(|| Parsed {
        claims_part: claims_part.to_string(),
        claims,
        signature,
    })
}

/// The claims part of a token for `claims`.
pub fn claims_part(claims: &Claims) -> String {
    // A struct of strings, numbers and bools always serializes.
    to_base64url(&serde_json::to_vec(claims).unwrap_or_default())
}

/// A token from its claims part and signature.
pub fn assemble(claims_part: &str, signature: &[u8]) -> String {
    format!("{TOKEN_PREFIX}{claims_part}.{}", to_base64url(signature))
}

/// A key's ID ([`valid_id`]): the first [`ID_BYTES`](crate::ID_BYTES) bytes of
/// its raw public key's sha256. The caller supplies the hash.
pub fn key_id(public_key_sha256: &[u8; SHA256_LEN]) -> String {
    const _: () = assert!(crate::ID_BYTES <= SHA256_LEN);
    let (id, _) = public_key_sha256.split_at(crate::ID_BYTES);
    crate::to_hex(id)
}

/// `bytes` as base64url without padding (RFC 4648 §5).
pub fn to_base64url(bytes: &[u8]) -> String {
    crate::to_base64(bytes)
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect()
}

/// Decode base64url without padding; `None` for padding, `+`, `/` or anything
/// [`from_base64`](crate::from_base64) refuses.
pub fn from_base64url(s: &str) -> Option<Vec<u8>> {
    if s.bytes()
        .any(|b| matches!(b, b'+' | b'/' | b'=') || b.is_ascii_whitespace())
    {
        return None;
    }
    let mut std: String = s
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    match std.len() % 4 {
        0 => {}
        2 => std.push_str("=="),
        3 => std.push('='),
        _ => return None,
    }
    crate::from_base64(&std)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(prefix: &str, rights: &str) -> Grant {
        Grant {
            prefix: prefix.into(),
            read: rights.contains('r'),
            write: rights.contains('w'),
            lock: rights.contains('l'),
        }
    }

    #[test]
    fn a_prefix_covers_its_subtree_cut_at_components() {
        assert!(under("p/1", "p/1"));
        assert!(under("p/1", "p/1/dev"));
        assert!(!under("p/1", "p/10"));
        assert!(!under("p/1", "p"));
        assert!(!under("", "p"));
        assert!(under("p/1", "p/1/"));
        assert!(!under("p/1/", "p/1"));
    }

    #[test]
    fn names_outside_the_repository_grammar_get_nothing() {
        let g = grant("p/1", "rwl");
        assert!(g.allows_repo("files/p/1", RepoRight::Read));
        for bad in [
            "p/1/../x",
            "p/1/.",
            "p/1/",
            "p/1//x",
            "p/1/X",
            "files/p/1/../y",
        ] {
            assert!(!g.allows_repo(bad, RepoRight::Read), "{bad}");
        }
        for bad in ["p/1/..:k", "p/1/:k", "p/1/A:k"] {
            assert!(!g.allows_lock(bad), "{bad}");
        }
    }

    #[test]
    fn a_grant_reaches_repositories_files_and_locks_under_its_prefix() {
        let g = grant("ci-pipeline/gl/42/7", "rwl");
        assert!(g.allows_repo("ci-pipeline/gl/42/7/cache", RepoRight::Write));
        assert!(g.allows_repo("files/ci-pipeline/gl/42/7/x", RepoRight::Read));
        assert!(!g.allows_repo("files", RepoRight::Read));
        assert!(!g.allows_repo("ci-pipeline/gl/42/8", RepoRight::Read));
        assert!(g.allows_lock("ci-pipeline/gl/42/7:abc"));
        assert!(g.allows_lock("ci-pipeline/gl/42/7/sub:abc:def"));
        assert!(!g.allows_lock("ci-pipeline/gl/42/7:"));
        assert!(!g.allows_lock("ci-pipeline/gl/42/70:abc"));
        assert!(!g.allows_lock("abc"));
        let r = grant("images", "r");
        assert!(r.allows_repo("images/debian", RepoRight::Read));
        assert!(!r.allows_repo("images/debian", RepoRight::Write));
        assert!(!r.allows_lock("images:k"));
        assert_eq!(g.rights(), "rwl");
        assert_eq!(r.rights(), "r");
        assert_eq!(grant("x", "").rights(), "");
        assert_eq!(grant("x", "wl").rights(), "wl");
    }

    #[test]
    fn prefixes_follow_the_repository_grammar() {
        assert!(valid_prefix("ci-cache/gl/42/protected"));
        assert!(valid_prefix("a.b_c-d/e"));
        assert!(valid_prefix("a__b/a---b/files2"));
        for bad in [
            "", "/a", "a/", "a//b", "A", "a/-b", "files", "files/x", "a:b", "a..b", "a___b",
            "a._b", "a_-b", "a-.b", "a.", "_a", ".", "..",
        ] {
            assert!(!valid_prefix(bad), "{bad}");
        }
    }

    #[test]
    fn base64url_round_trips_and_refuses_the_standard_alphabet() {
        for n in 0..40u8 {
            let bytes: Vec<u8> = (0..n)
                .map(|i| i.wrapping_mul(97).wrapping_add(250))
                .collect();
            let s = to_base64url(&bytes);
            assert!(!s.contains(['=', '+', '/']));
            assert_eq!(from_base64url(&s), Some(bytes));
        }
        assert_eq!(from_base64url("a+b/"), None);
        assert_eq!(from_base64url("YQ=="), None);
        assert_eq!(from_base64url("a"), None);
        assert_eq!(from_base64url("YW Jj"), None);
        assert_eq!(from_base64url("YWJj\n"), None);
    }

    fn claims() -> Claims {
        Claims {
            kid: "00112233445566778899aabbccddeeff".into(),
            aud: "9c2f4e1a7b3d5e60f1a2b3c4d5e6f708".into(),
            sub: "job:j1".into(),
            jti: "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4".into(),
            pipeline: Some("gl/1234".into()),
            iat: 100,
            exp: 200,
            grants: vec![grant("p/gl/42", "rwl"), grant("images", "r")],
        }
    }

    #[test]
    fn a_token_parses_back_into_its_claims() {
        let c = claims();
        let token = assemble(&claims_part(&c), &[7u8; 64]);
        assert!(token.starts_with(TOKEN_PREFIX));
        let p = parse(&token).expect("parses");
        assert_eq!(p.claims, c);
        assert_eq!(p.signature, vec![7u8; 64]);
        assert_eq!(p.claims_part, claims_part(&c));
        assert!(signed_message(&p.claims_part).starts_with(SIGNATURE_LABEL));
    }

    #[test]
    fn malformed_tokens_do_not_parse() {
        let c = claims();
        let part = claims_part(&c);
        assert!(parse(&assemble(&part, &[7u8; 63])).is_none());
        assert!(parse(&format!("vkr_{part}.{}", to_base64url(&[0; 64]))).is_none());
        assert!(parse(&format!("{TOKEN_PREFIX}{part}")).is_none());
        let mut bad = c.clone();
        bad.exp = bad.iat;
        assert!(parse(&assemble(&claims_part(&bad), &[0; 64])).is_none());
        let mut bad = c;
        bad.grants.push(grant("Upper", "r"));
        assert!(parse(&assemble(&claims_part(&bad), &[0; 64])).is_none());
        assert!(parse(&"x".repeat(MAX_TOKEN_LEN + 1)).is_none());
        let sig = to_base64url(&[0; 64]);
        assert!(parse(&format!("{TOKEN_PREFIX}{part}.{sig}.")).is_none());
        assert!(
            parse(&format!(
                "{TOKEN_PREFIX}{part}.{}.{}",
                &sig[..40],
                &sig[40..]
            ))
            .is_none()
        );
        assert!(parse(&format!("{TOKEN_PREFIX}{part}é.{sig}")).is_none());
        assert!(parse(&format!("{TOKEN_PREFIX}{part}.{sig}é")).is_none());
    }

    #[test]
    fn grants_are_bounded() {
        let mut c = claims();
        c.grants = (0..MAX_GRANTS)
            .map(|i| grant(&format!("p/{i}"), "r"))
            .collect();
        assert!(c.well_formed());
        c.grants.push(grant("q", "r"));
        assert!(!c.well_formed());
        assert!(parse(&assemble(&claims_part(&c), &[0; 64])).is_none());
    }

    #[test]
    fn labels_and_lifetime_are_bounded() {
        let ok = claims();
        assert!(ok.well_formed());
        for sub in [
            String::new(),
            "job j1".into(),
            "job:é".into(),
            "a".repeat(MAX_LABEL_LEN + 1),
        ] {
            let c = Claims { sub, ..ok.clone() };
            assert!(!c.well_formed(), "{:?}", c.sub);
        }
        let c = Claims {
            sub: "a".repeat(MAX_LABEL_LEN),
            ..ok.clone()
        };
        assert!(c.well_formed());
        let c = Claims {
            pipeline: Some("gl/1\t2".into()),
            ..ok.clone()
        };
        assert!(!c.well_formed());
        let c = Claims {
            pipeline: Some(String::new()),
            ..ok.clone()
        };
        assert!(!c.well_formed());
        let c = Claims {
            exp: ok.iat + MAX_TTL_SECS,
            ..ok.clone()
        };
        assert!(c.well_formed());
        let c = Claims {
            exp: ok.iat + MAX_TTL_SECS + 1,
            ..ok.clone()
        };
        assert!(!c.well_formed());
        let c = Claims {
            exp: ok.iat - 1,
            ..ok
        };
        assert!(!c.well_formed());
    }

    #[test]
    fn unknown_claims_are_refused() {
        let json = serde_json::to_string(&claims()).unwrap();
        let extra = json.replacen('{', r#"{"admin":true,"#, 1);
        assert!(serde_json::from_str::<Claims>(&extra).is_err());
        assert!(parse(&assemble(&to_base64url(extra.as_bytes()), &[0; 64])).is_none());
        let extra = json.replacen(r#""read":true"#, r#""read":true,"delete":true"#, 1);
        assert!(serde_json::from_str::<Claims>(&extra).is_err());
    }

    #[test]
    fn the_largest_well_formed_claims_fit_in_a_token() {
        let mut c = claims();
        let prefix = format!("{}/{}", "a".repeat(127), "b".repeat(127));
        assert_eq!(prefix.len(), MAX_PREFIX_LEN);
        c.grants = (0..MAX_GRANTS).map(|_| grant(&prefix, "rwl")).collect();
        assert!(c.well_formed());
        let token = assemble(&claims_part(&c), &[0; 64]);
        assert!(token.len() <= MAX_TOKEN_LEN, "{}", token.len());
        assert!(parse(&token).is_some());
    }

    #[test]
    fn claims_are_live_until_exp_and_the_skew() {
        let c = claims();
        assert!(c.live_at(200 + SKEW_SECS));
        assert!(!c.live_at(201 + SKEW_SECS));
    }

    #[test]
    fn the_claims_json_is_pinned() {
        let mut c = claims();
        c.grants.truncate(1);
        assert_eq!(
            serde_json::to_string(&c).unwrap(),
            r#"{"kid":"00112233445566778899aabbccddeeff","aud":"9c2f4e1a7b3d5e60f1a2b3c4d5e6f708","sub":"job:j1","jti":"a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4","pipeline":"gl/1234","iat":100,"exp":200,"grants":[{"prefix":"p/gl/42","read":true,"write":true,"lock":true}]}"#
        );
        assert_eq!(key_id(&[0xab; SHA256_LEN]), "ab".repeat(crate::ID_BYTES));
        assert_eq!(signed_message("abc"), b"vk-fleet registry-token v1\0abc");
    }
}
