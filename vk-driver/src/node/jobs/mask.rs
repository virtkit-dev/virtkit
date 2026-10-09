//! Masking a job's output the way gitlab-runner masks its trace: the job's masked variables
//! replaced wherever they appear, the values of sensitive URL parameters, and whatever follows
//! a known token prefix (`glpat-` and the like). Each is a byte-stream filter that holds back
//! no more than a partial match, so output reaches the trace as it is written, and a secret
//! split across two writes is masked all the same.
//!
//! Ported from gitlab-runner v19.5's `common/buildlogger` — `internal/masker`,
//! `internal/urlsanitizer`, `internal/tokensanitizer` and `internal/unique.go` — keeping their
//! stacking and their quirks, so a trace reads the same as gitlab-runner's would.
//!
//! gitlab-runner is Copyright (c) 2015-2019 GitLab Inc., under the MIT License: permission is
//! hereby granted, free of charge, to any person obtaining a copy of this software and
//! associated documentation files (the "Software"), to deal in the Software without
//! restriction, including without limitation the rights to use, copy, modify, merge, publish,
//! distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom
//! the Software is furnished to do so, subject to the following conditions: The above
//! copyright notice and this permission notice shall be included in all copies or substantial
//! portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

/// What a masked secret is replaced with.
pub const MASK: &[u8] = b"[MASKED]";

/// The prefixes gitlab-runner masks by default (`FF_MASK_ALL_DEFAULT_TOKENS`, on by default).
const DEFAULT_PREFIXES: [&str; 14] = [
    "glpat-",
    "gloas-",
    "gldt-",
    "glrt-",
    "glcbt-",
    "glrtr-",
    "glptt-",
    "glft-",
    "glimt-",
    "glagent-",
    "glsoat-",
    "glffct-",
    "_gitlab_session=",
    "gltok-",
];

/// The most token prefixes masked, as gitlab-runner caps them.
const MAX_PREFIXES: usize = 15;

/// URL parameters whose values are masked (`urlsanitizer.tokenParamKeys`).
const PARAM_KEYS: [&str; 6] = [
    "private_token",
    "authenticity_token",
    "rss_token",
    "x-amz-signature",
    "x-amz-credential",
    "x-amz-security-token",
];

/// One filter of the chain: it passes what it does not mask on to `next`, write by write.
trait Filter: Send {
    fn write(&mut self, p: &[u8], next: &mut dyn FnMut(&[u8]));
    /// Pass on whatever a partial match still holds back.
    fn close(&mut self, next: &mut dyn FnMut(&[u8]));
}

/// The whole masking chain: phrases, then URL parameters, then token prefixes, each stage
/// writing into the next as gitlab-runner's writers do.
pub struct Masker {
    filters: Vec<Box<dyn Filter>>,
}

impl Masker {
    /// A chain masking `phrases` — the values of the job's masked variables — and the tokens
    /// after `prefixes` and gitlab-runner's default ones.
    pub fn new(phrases: &[String], prefixes: &[String]) -> Masker {
        let mut filters: Vec<Box<dyn Filter>> = Vec::new();
        // Longest first, outermost: gitlab-runner stacks each new writer over the last.
        for phrase in unique(phrases.iter().map(String::as_str)).into_iter().rev() {
            filters.push(Box::new(Phrase {
                borders: borders(&phrase),
                phrase,
                matching: 0,
            }));
        }
        filters.push(Box::new(UrlParams::default()));
        let all = prefixes
            .iter()
            .map(String::as_str)
            .chain(DEFAULT_PREFIXES.iter().copied());
        let prefixes = unique(all);
        let kept = prefixes.len().min(MAX_PREFIXES);
        for prefix in prefixes.into_iter().take(kept).rev() {
            filters.push(Box::new(Prefix {
                borders: borders(&prefix),
                prefix,
                matching: 0,
                masked: false,
            }));
        }
        Masker { filters }
    }

    /// Mask `p`, handing what is safe to emit to `out`.
    pub fn write(&mut self, p: &[u8], out: &mut dyn FnMut(&[u8])) {
        run(&mut self.filters, p, out);
    }

    /// Emit what partial matches hold back: at the end of the output, or of a stage.
    pub fn flush(&mut self, out: &mut dyn FnMut(&[u8])) {
        close(&mut self.filters, out);
    }
}

fn run(filters: &mut [Box<dyn Filter>], p: &[u8], out: &mut dyn FnMut(&[u8])) {
    match filters.split_first_mut() {
        None => {
            if !p.is_empty() {
                out(p)
            }
        }
        Some((first, rest)) => first.write(p, &mut |q| run(rest, q, out)),
    }
}

fn close(filters: &mut [Box<dyn Filter>], out: &mut dyn FnMut(&[u8])) {
    if let Some((first, rest)) = filters.split_first_mut() {
        first.close(&mut |q| run(rest, q, out));
        close(rest, out);
    }
}

/// Trimmed, deduplicated, empty ones dropped, shortest first (`internal.Unique`).
fn unique<'a>(tokens: impl Iterator<Item = &'a str>) -> Vec<Vec<u8>> {
    let mut tokens: Vec<&str> = tokens.map(str::trim).filter(|t| !t.is_empty()).collect();
    tokens.sort_by(|a, b| a.len().cmp(&b.len()).then(a.cmp(b)));
    tokens.dedup();
    tokens.into_iter().map(|t| t.as_bytes().to_vec()).collect()
}

/// For each prefix `pat[..=i]`, the length of its longest proper prefix that is also its
/// suffix: the KMP failure table.
fn borders(pat: &[u8]) -> Vec<usize> {
    let mut table = vec![0; pat.len()];
    let mut k = 0;
    for i in 1..pat.len() {
        while k > 0 && pat[i] != pat[k] {
            k = table[k - 1];
        }
        if pat[i] == pat[k] {
            k += 1;
        }
        table[i] = k;
    }
    table
}

/// Match `c` after `pat[..m]`, `m < pat.len()`, held back: on a mismatch, pass on the held
/// bytes no shorter match can use, as a KMP search falls back. How many bytes of `pat` are
/// matched with `c`; 0 when `c` is not held, and is the caller's to pass on.
///
/// gitlab-runner retries only the pattern's first byte, so a self-overlapping secret split
/// across writes (`aab` as `aa`, `ab`) leaks; the fallback masks it.
fn advance(
    pat: &[u8],
    borders: &[usize],
    mut m: usize,
    c: u8,
    next: &mut dyn FnMut(&[u8]),
) -> usize {
    while m > 0 && pat[m] != c {
        let keep = borders[m - 1];
        emit(next, &pat[..m - keep]);
        m = keep;
    }
    match pat[m] == c {
        true => m + 1,
        false => 0,
    }
}

/// One masked phrase (`masker.masker`).
struct Phrase {
    phrase: Vec<u8>,
    borders: Vec<usize>,
    /// How many of the phrase's bytes the last writes ended on.
    matching: usize,
}

impl Filter for Phrase {
    fn write(&mut self, p: &[u8], next: &mut dyn FnMut(&[u8])) {
        if p.is_empty() {
            return;
        }
        // An upper stage's mask is passed on whole.
        if p == MASK {
            next(p);
            return;
        }
        let phrase = &self.phrase;
        // `p[last..n]` is not passed on yet; while a match is held, `last == n`.
        let (mut n, mut last) = (0usize, 0usize);
        while n < p.len() {
            if self.matching == 0 {
                match p[n..].iter().position(|&b| b == phrase[0]) {
                    Some(off) => n += off,
                    None => {
                        n = p.len();
                        break;
                    }
                }
                emit(next, &p[last..n]);
                last = n;
            }
            self.matching = advance(phrase, &self.borders, self.matching, p[n], next);
            n += 1;
            if self.matching == 0 {
                continue;
            }
            last = n;
            if self.matching == phrase.len() {
                next(MASK);
                self.matching = 0;
            }
        }
        emit(next, &p[last..n]);
    }

    fn close(&mut self, next: &mut dyn FnMut(&[u8])) {
        if self.matching == self.phrase.len() {
            next(MASK);
        } else {
            emit(next, &self.phrase[..self.matching]);
        }
        self.matching = 0;
    }
}

/// Everything after one token prefix, up to the first byte no token has
/// (`tokensanitizer.tokenSanitizer`).
struct Prefix {
    prefix: Vec<u8>,
    borders: Vec<usize>,
    matching: usize,
    /// Whether token bytes have been swallowed since the prefix, and a mask is owed.
    masked: bool,
}

fn token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'=')
}

impl Filter for Prefix {
    fn write(&mut self, p: &[u8], next: &mut dyn FnMut(&[u8])) {
        if p.is_empty() {
            return;
        }
        if p == MASK {
            next(p);
            return;
        }
        let prefix = &self.prefix;
        let (mut n, mut last) = (0usize, 0usize);
        while n < p.len() {
            if self.matching == prefix.len() {
                if token_byte(p[n]) {
                    self.masked = true;
                    n += 1;
                    last = n;
                    continue;
                }
                if self.masked {
                    self.masked = false;
                    next(MASK);
                }
                self.matching = 0;
            }
            if self.matching == 0 {
                match p[n..].iter().position(|&b| b == prefix[0]) {
                    Some(off) => n += off,
                    None => {
                        n = p.len();
                        break;
                    }
                }
                emit(next, &p[last..n]);
                last = n;
            }
            self.matching = advance(prefix, &self.borders, self.matching, p[n], next);
            n += 1;
            if self.matching == 0 {
                continue;
            }
            last = n;
            if self.matching == prefix.len() {
                next(prefix);
            }
        }
        emit(next, &p[last..n]);
    }

    fn close(&mut self, next: &mut dyn FnMut(&[u8])) {
        if self.masked {
            next(MASK);
        } else if self.matching < self.prefix.len() {
            emit(next, &self.prefix[..self.matching]);
        }
        self.matching = 0;
        self.masked = false;
    }
}

/// The values of sensitive URL parameters (`urlsanitizer.URLSanitizer`).
#[derive(Default)]
struct UrlParams {
    /// The separator and key read so far, at most [`UrlParams::CAP`] bytes.
    key: Vec<u8>,
    masking: bool,
}

impl UrlParams {
    /// The longest key, plus its separator.
    const CAP: usize = 21;
}

/// Where a parameter's value ends. gitlab-runner tests whole runes for space and control
/// characters; this tests bytes, which agrees on every ASCII one.
fn param_end(b: u8) -> bool {
    b == b'?' || b == b'&' || b.is_ascii_whitespace() || b.is_ascii_control()
}

impl Filter for UrlParams {
    fn write(&mut self, p: &[u8], next: &mut dyn FnMut(&[u8])) {
        let (mut n, mut last) = (0usize, 0usize);
        while n < p.len() {
            if self.masking {
                match p[n..].iter().position(|&b| param_end(b)) {
                    None => {
                        n = p.len();
                        last = n;
                        break;
                    }
                    Some(off) => {
                        n += off;
                        last += off;
                        self.masking = false;
                        next(MASK);
                    }
                }
            }
            if self.key.len() == Self::CAP {
                self.key.clear();
            }
            if self.key.is_empty() {
                match p[n..].iter().position(|&b| b == b'?' || b == b'&') {
                    None => {
                        n = p.len();
                        break;
                    }
                    Some(off) => {
                        self.key.push(p[n + off]);
                        n += off + 1;
                    }
                }
            }
            if n >= p.len() {
                break;
            }
            let Some(off) = p[n..].iter().position(|&b| matches!(b, b'=' | b'?' | b'&')) else {
                self.key.push(p[n]);
                n += 1;
                continue;
            };
            if p[n + off] == b'?' || p[n + off] == b'&' {
                self.key.clear();
                n += off;
                continue;
            }
            if off + self.key.len() > Self::CAP {
                self.key.clear();
                n += 1;
                continue;
            }
            let mut key = std::mem::take(&mut self.key);
            key.extend_from_slice(&p[n..n + off]);
            n += off + 1;
            let name = key.get(1..).unwrap_or_default().to_ascii_lowercase();
            if PARAM_KEYS.iter().any(|k| k.as_bytes() == name.as_slice()) {
                emit(next, &p[last..n]);
                last = n;
                self.masking = true;
            }
        }
        emit(next, &p[last.min(n)..n]);
    }

    fn close(&mut self, next: &mut dyn FnMut(&[u8])) {
        if self.masking {
            next(MASK);
        }
        self.masking = false;
        self.key.clear();
    }
}

fn emit(next: &mut dyn FnMut(&[u8]), p: &[u8]) {
    if !p.is_empty() {
        next(p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `input` written in the pieces `|` separates, then flushed.
    fn masked(phrases: &[&str], prefixes: &[&str], input: &str) -> String {
        let phrases: Vec<String> = phrases.iter().map(|s| s.to_string()).collect();
        let prefixes: Vec<String> = prefixes.iter().map(|s| s.to_string()).collect();
        let mut m = Masker::new(&phrases, &prefixes);
        let mut out = Vec::new();
        for part in input.split('|') {
            m.write(part.as_bytes(), &mut |b| out.extend_from_slice(b));
        }
        m.flush(&mut |b| out.extend_from_slice(b));
        String::from_utf8(out).unwrap()
    }

    /// gitlab-runner's `masker_test.go` `TestMasking` cases.
    #[test]
    fn phrases_are_masked_as_gitlab_runner_masks_them() {
        let cases: &[(&str, &[&str], &str)] = &[
            (
                "empty secrets have no affect",
                &[""],
                "empty secrets have no affect",
            ),
            ("no escaping at all", &[], "no escaping at all"),
            ("secrets", &["secrets"], "[MASKED]"),
            ("secret|s", &["secrets"], "[MASKED]"),
            ("s|ecrets", &["secrets"], "[MASKED]"),
            ("secretssecrets", &["secrets"], "[MASKED][MASKED]"),
            ("ssecrets", &["secrets"], "s[MASKED]"),
            ("s|secrets", &["secrets"], "s[MASKED]"),
            (
                "at the start of the buffer",
                &["at"],
                "[MASKED] the start of the buffer",
            ),
            (
                "in the middle of the buffer",
                &["middle"],
                "in the [MASKED] of the buffer",
            ),
            (
                "at the end of the buffer",
                &["buffer"],
                "at the end of the [MASKED]",
            ),
            (
                "all values are masked",
                &["all", "values", "are", "masked"],
                "[MASKED] [MASKED] [MASKED] [MASKED]",
            ),
            (
                "prefixed and suffixed: xfoox ybary ffoo barr ffooo bbarr",
                &["foo", "bar"],
                "prefixed and suffixed: x[MASKED]x y[MASKED]y f[MASKED] [MASKED]r f[MASKED]o \
                 b[MASKED]r",
            ),
            (
                "prefix|ed, su|ffi|xed |and split|:| xfo|ox y|bary ffo|o ba|rr ffooo b|barr",
                &["foo", "bar"],
                "prefixed, suffixed and split: x[MASKED]x y[MASKED]y f[MASKED] [MASKED]r \
                 f[MASKED]o b[MASKED]r",
            ),
            (
                "sp|lit al|l val|ues ar|e |mask|ed",
                &["split", "all", "values", "are", "masked"],
                "[MASKED] [MASKED] [MASKED] [MASKED] [MASKED]",
            ),
            (
                "prefix_mask mask prefix_|mask prefix_ma|sk mas|k",
                &["mask", "prefix_mask"],
                "[MASKED] [MASKED] [MASKED] [MASKED] [MASKED]",
            ),
            (
                "overlap: this is the en| foobar",
                &["this is the end", "en foobar", "en"],
                "overlap: this is the [MASKED]",
            ),
        ];
        for (input, phrases, expected) in cases {
            assert_eq!(masked(phrases, &[], input), *expected, "{input:?}");
        }
        let half = "_".repeat(8000);
        let input = format!("large secret: {half}|{half}");
        assert_eq!(
            masked(&[&"_".repeat(16000)], &[], &input),
            "large secret: [MASKED]"
        );
    }

    /// gitlab-runner's `token_masker_test.go` cases with the default prefix.
    #[test]
    fn tokens_after_a_prefix_are_masked() {
        let cases = [
            (
                "Lorem ipsum dolor sit amet, ex ea commodo glpat-imperdiet in voluptate",
                "Lorem ipsum dolor sit amet, ex ea commodo glpat-[MASKED] in voluptate",
            ),
            ("velit esseglpat-imperdiet", "velit esseglpat-[MASKED]"),
            (
                "esseglpat-imperdiet=_-. end Lorem",
                "esseglpat-[MASKED] end Lorem",
            ),
            ("glpat-impglpat-erdiet Lorem", "glpat-[MASKED] Lorem"),
            (
                "glpat|-imperdiet Lorem ipsum dolor sit amet, ex ea commodo gl|pat-imperdiet in",
                "glpat-[MASKED] Lorem ipsum dolor sit amet, ex ea commodo glpat-[MASKED] in",
            ),
            (
                "glpat| -imperdiet Lorem ipsum dolor sit amet",
                "glpat -imperdiet Lorem ipsum dolor sit amet",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(masked(&[], &[], input), expected, "{input:?}");
        }
        assert_eq!(
            masked(&[], &["token-"], "token-imperdiet Lorem"),
            "token-[MASKED] Lorem"
        );
        // A job token, under the prefix GitLab gives it.
        assert_eq!(
            masked(&[], &[], "CI_JOB_TOKEN=glcbt-64_abcdef|ghij end"),
            "CI_JOB_TOKEN=glcbt-[MASKED] end"
        );
    }

    /// gitlab-runner's `urlsanitizer_test.go` cases.
    #[test]
    fn sensitive_url_parameters_are_masked() {
        let cases = [
            (
                "no escaping at all http://example.org/?test=foobar",
                "no escaping at all http://example.org/?test=foobar",
            ),
            (
                "multiple: &private_token=hello &?x-amz-security-token=hello \
                 &?x-amz-security-token=hello ?x-amz-security?x-amz-security-token=hello",
                "multiple: &private_token=[MASKED] &?x-amz-security-token=[MASKED] \
                 &?x-amz-security-token=[MASKED] ?x-amz-security?x-amz-security-token=[MASKED]",
            ),
            (
                "above known key size: http://example.org/?this-is-a-really-really-long-key-name=foobar",
                "above known key size: http://example.org/?this-is-a-really-really-long-key-name=foobar",
            ),
            (
                "http://example.com/?private_token=deadbeef sensitive URL at the start",
                "http://example.com/?private_token=[MASKED] sensitive URL at the start",
            ),
            (
                "a sensitive URL at the end http://example.com/?authenticity_token=deadbeef",
                "a sensitive URL at the end http://example.com/?authenticity_token=[MASKED]",
            ),
            (
                "a sensitive URL http://example.com/?X-AMZ-sigNATure=deadbeef with mixed case",
                "a sensitive URL http://example.com/?X-AMZ-sigNATure=[MASKED] with mixed case",
            ),
            (
                "a sensitive URL http://example.com/?rss_token=hide&x-amz-credential=deadbeef both",
                "a sensitive URL http://example.com/?rss_token=[MASKED]&x-amz-credential=[MASKED] both",
            ),
            (
                "split http://example.com/?rss_to|ken=hi|de end",
                "split http://example.com/?rss_token=[MASKED] end",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(masked(&[], &[], input), expected, "{input:?}");
        }
    }

    /// A secret whose start recurs in it, split where gitlab-runner's single-byte retry loses
    /// the match.
    #[test]
    fn a_self_overlapping_secret_split_across_writes_is_masked() {
        let cases: &[(&str, &[&str], &str)] = &[
            ("aa|ab", &["aab"], "a[MASKED]"),
            ("aaab", &["aab"], "a[MASKED]"),
            ("ab|abab", &["abab"], "[MASKED]ab"),
            ("aba|bab", &["abab"], "[MASKED]ab"),
            ("a|b|a|c|a|b|a|b|a|b|c", &["ababc"], "abacab[MASKED]"),
            ("xaa|aax", &["aaaa"], "x[MASKED]x"),
            ("aaa|aaa", &["aaaa"], "[MASKED]aa"),
            ("aa|ac", &["aab"], "aaac"),
            ("aa|", &["aab"], "aa"),
        ];
        for (input, phrases, expected) in cases {
            assert_eq!(masked(phrases, &[], input), *expected, "{input:?}");
        }
        assert_eq!(masked(&[], &["ggx-"], "gg|gx-tok end"), "gggx-[MASKED] end");
        assert_eq!(masked(&[], &["ggx-"], "gg|g end"), "ggg end");
    }

    #[test]
    fn a_phrase_and_a_token_in_one_stream_are_both_masked() {
        assert_eq!(
            masked(
                &["s3cr3t-value"],
                &[],
                "echo s3cr3t-|value and glpat-xyz|zy then ?private_token=abc"
            ),
            "echo [MASKED] and glpat-[MASKED] then ?private_token=[MASKED]"
        );
    }
}
