//! Tokens: a redacting wrapper, and gitlab-runner's shortened form for logs.

use std::fmt;

/// A credential (runner or job token). `Debug` and `Display` print a placeholder, so a
/// token cannot reach a log line or an error message by accident; [`Secret::expose`] is
/// the one way to the value, for the request that sends it.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The prefix-stripped, nine-character form gitlab-runner logs a token as.
    pub fn short(&self) -> String {
        shorten_token(&self.0)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<'de> serde::Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Self)
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// `([A-Za-z0-9]+-)?`, the optional instance prefix GitLab can put before `glrt-`/`glcbt-`:
/// the length of that prefix at the start of `s`, if `s` continues with `rest`.
fn instance_prefixed<'a>(s: &'a str, rest: &str) -> Option<&'a str> {
    if let Some(tail) = s.strip_prefix(rest) {
        return Some(tail);
    }
    let dash = s.find('-')?;
    let (head, tail) = s.split_at(dash);
    if head.is_empty() || !head.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    tail.get(1..)?.strip_prefix(rest)
}

fn strip_partition(s: &str) -> Option<&str> {
    ["t1_", "t2_", "t3_"].iter().find_map(|p| s.strip_prefix(p))
}

/// Whether `token` is a runner authentication token created in the UI (`glrt-`), as
/// opposed to one obtained through a registration token. Port of
/// `helpers.IsCreatedRunnerToken`.
pub fn is_created_runner_token(token: &str) -> bool {
    instance_prefixed(token, "glrt-").is_some()
}

/// Port of gitlab-runner's `helpers.ShortenToken`: strip the known token prefixes, keep nine
/// characters, and make both ends alphanumeric (it doubles as a Kubernetes label value).
pub fn shorten_token(token: &str) -> String {
    // The three upstream regexps are applied in turn, each anchored at the start.
    let mut s = token;
    if let Some(tail) = instance_prefixed(s, "glrt-") {
        s = strip_partition(tail).unwrap_or(tail);
    } else if let Some(tail) = strip_partition(s) {
        s = tail;
    } else if let Some(tail) = s.strip_prefix("glrtr-") {
        s = tail;
    }
    if let Some(tail) = instance_prefixed(s, "glcbt-") {
        s = tail;
    }
    if let Some(rest) = s.strip_prefix("GR")
        && rest.len() >= 7
        && rest.bytes().take(7).all(|b| b.is_ascii_hexdigit())
    {
        s = rest.get(7..).unwrap_or("");
    }

    let mut out: Vec<char> = s.chars().take(9).collect();
    if out.first().is_some_and(|c| !c.is_ascii_alphanumeric()) {
        out.pop();
        out.insert(0, 'r');
    }
    if let Some(last) = out.last_mut()
        && !last.is_ascii_alphanumeric()
    {
        *last = 'r';
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from gitlab-runner v19.5.0 helpers/shorten_token_test.go, TestShortenToken
    // (MIT, Copyright (c) 2015-2019 GitLab Inc.).
    #[test]
    fn shorten_token_matches_upstream() {
        let cases = [
            ("short", "short"),
            ("veryverylongtoken", "veryveryl"),
            ("t1_t9Wkyj-HGRkqQ-VWTGAr", "t9Wkyj-HG"),
            ("t2_t9Wkyj-HGRkqQ-VWTGAr", "t9Wkyj-HG"),
            ("t3_t9Wkyj-HGRkqQ-VWTGAr", "t9Wkyj-HG"),
            ("t4_t9Wkyj-HGRkqQ-VWTGAr", "t4_t9Wkyj"),
            ("glrt-t9Wkyj-HGRkqQ-VWTGAr", "t9Wkyj-HG"),
            ("glrt-t1_t9Wkyj-HGRkqQ-VWTGAr", "t9Wkyj-HG"),
            ("glrtr-t9Wkyj-HGRkqQ-VWTGAr", "t9Wkyj-HG"),
            ("glrtr-t1_t9Wkyj-HGRkqQ-VWTGAr", "t1_t9Wkyj"),
            ("glcbt-t9Wkyj-HGRkqQ-VWTGAr", "t9Wkyj-HG"),
            ("glcbt-t2_t9Wkyj-HGRkqQ-VWTGAr", "t2_t9Wkyj"),
            ("acme-glrt-t9Wkyj-HGRkqQ-VWTGAr", "t9Wkyj-HG"),
            ("acme-glrt-t1_t9Wkyj-HGRkqQ-VWTGAr", "t9Wkyj-HG"),
            ("Acme-glrt-t2_t9Wkyj-HGRkqQ-VWTGAr", "t9Wkyj-HG"),
            ("Acme1-glrt-t3_t9Wkyj-HGRkqQ-VWTGAr", "t9Wkyj-HG"),
            ("acme-glcbt-t9Wkyj-HGRkqQ-VWTGAr", "t9Wkyj-HG"),
            ("123-glrt-t9Wkyj-HGRkqQ-VWTGAr", "t9Wkyj-HG"),
            ("acme-glrtr-t9Wkyj-HGRkqQ-VWTGAr", "acme-glrt"),
            ("GR1348941Z196cJVywzZpx_Ki_Cn2", "Z196cJVyw"),
            ("GR134894-196cJVywzZpx_Ki_Cn2", "GR134894r"),
            ("glrt--abcdefghijk", "r-abcdefg"),
            ("glcbt--abcdefghijk", "r-abcdefg"),
            ("-abcdefghijk", "r-abcdefg"),
            ("_abcdefghijk", "r_abcdefg"),
            (".abcdefghijk", "r.abcdefg"),
            ("abcdefgh-", "abcdefghr"),
            ("abcdefgh_", "abcdefghr"),
            ("_x", "rr"),
            ("-abc", "r-ab"),
        ];
        for (input, want) in cases {
            assert_eq!(shorten_token(input), want, "{input}");
        }
    }

    // Ported from gitlab-runner v19.5.0 network/gitlab_test.go, TestTokenIsCreatedRunnerToken.
    #[test]
    fn created_runner_token() {
        assert!(is_created_runner_token("glrt-t1_t9Wkyj-HGRkqQ-VWTGAr"));
        assert!(is_created_runner_token("acme-glrt-t1_t9Wkyj-HGRkqQ-VWTGAr"));
        assert!(!is_created_runner_token("glrtr-t9Wkyj-HGRkqQ-VWTGAr"));
        assert!(!is_created_runner_token("GR1348941Z196cJVywzZpx_Ki_Cn2"));
        assert!(!is_created_runner_token("acme-glcbt-t9Wkyj-HGRkqQ-VWTGAr"));
        assert!(!is_created_runner_token("ac_me-glrt-t9Wkyj-HGRkqQ-VWTGAr"));
        assert!(!is_created_runner_token(""));
    }

    #[test]
    fn secret_never_prints() {
        let s = Secret::new("glrt-supersecret");
        assert_eq!(format!("{s}"), "[REDACTED]");
        assert!(!format!("{s:?}").contains("supersecret"));
    }
}
