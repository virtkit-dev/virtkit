//! `.dockerignore` matching, shared by the host builder (to content-hash the files a
//! `COPY` references for its cache key) and the guest `copy` syscall (to filter what it
//! copies). Uses moby's parent-results model: exclusion is inherited from the parent
//! directory and overridden by each pattern matching the path (last match wins), so a
//! `!pattern` re-includes.

use std::path::Path;

/// A loaded `.dockerignore`: the context root (to make paths relative) and its ordered
/// patterns. Exclusion is computed per path as the parent directory's state overridden
/// by the patterns matching that path (last match wins), so a `!pattern` re-includes —
/// the model moby's pattern matcher uses (`MatchesUsingParentResults`).
pub struct Ignore {
    root: std::path::PathBuf,
    /// (negated, pattern) in source order. A `negated` pattern (`!…`) re-includes.
    patterns: Vec<(bool, String)>,
}

impl Ignore {
    /// Load `<root>/.dockerignore` (blank lines and `#` comments skipped; a leading `!`
    /// marks a re-include; leading/trailing `/` trimmed). Absent file → no patterns.
    pub fn load(root: &Path) -> Self {
        let patterns = std::fs::read_to_string(root.join(".dockerignore"))
            .unwrap_or_default()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter_map(|l| {
                let (neg, body) = match l.strip_prefix('!') {
                    Some(rest) => (true, rest.trim()),
                    None => (false, l),
                };
                let pat = body.trim_start_matches('/').trim_end_matches('/');
                (!pat.is_empty()).then(|| (neg, pat.to_string()))
            })
            .collect();
        Ignore {
            root: root.to_path_buf(),
            patterns,
        }
    }

    /// `path`'s context-relative form, or None if it is not under the root.
    fn rel<'a>(&self, path: &'a Path) -> Option<std::borrow::Cow<'a, str>> {
        path.strip_prefix(&self.root)
            .ok()
            .map(|r| r.to_string_lossy())
    }

    /// Whether `path` is excluded, given its parent directory's exclude state: inherit
    /// the parent, then let each pattern matching this path override it (last wins).
    pub fn excluded(&self, path: &Path, parent: bool) -> bool {
        let Some(rel) = self.rel(path) else {
            return parent;
        };
        let mut ex = parent;
        for (neg, pat) in &self.patterns {
            if glob_match(pat, &rel) {
                ex = !neg;
            }
        }
        ex
    }

    /// Collect the non-excluded regular files at or under `start` (within the context
    /// root) as absolute paths, sorted. Honors the parent-results model, so a `!`
    /// re-included file beneath an excluded directory is still returned. Used by the
    /// builder to content-hash a `COPY`'s referenced context files for its cache key.
    pub fn included_files(&self, start: &Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        self.collect(start, false, &mut out);
        out.sort();
        out
    }

    fn collect(&self, path: &Path, parent_excluded: bool, out: &mut Vec<std::path::PathBuf>) {
        let Ok(md) = std::fs::symlink_metadata(path) else {
            return;
        };
        let excluded = self.excluded(path, parent_excluded);
        if md.is_dir() {
            // a fully-excluded dir can be pruned unless a re-include could match below it
            if excluded && !self.could_reinclude_under(path) {
                return;
            }
            let Ok(rd) = std::fs::read_dir(path) else {
                return;
            };
            let mut kids: Vec<std::path::PathBuf> = rd.flatten().map(|e| e.path()).collect();
            kids.sort();
            for k in kids {
                self.collect(&k, excluded, out);
            }
        } else if md.is_file() && !excluded {
            out.push(path.to_path_buf());
        }
    }

    /// Could a re-include (`!`) pattern match something strictly under directory `path`?
    /// If so an excluded dir must still be descended into; otherwise it can be pruned.
    pub fn could_reinclude_under(&self, path: &Path) -> bool {
        let Some(rel) = self.rel(path) else {
            return false;
        };
        let d: Vec<&str> = rel.split('/').collect();
        self.patterns
            .iter()
            .filter(|(neg, _)| *neg)
            .any(|(_, pat)| can_match_under(&pat.split('/').collect::<Vec<_>>(), &d))
    }
}

/// Could pattern `p` match a path strictly *under* directory `d` (i.e. `d/<more>`)?
fn can_match_under(p: &[&str], d: &[&str]) -> bool {
    match (p.first(), d.first()) {
        (None, _) => false, // pattern exhausted: matches only d itself, not under it
        (Some(&"**"), _) => true, // `**` absorbs the rest of d and can match deeper
        (Some(_), None) => true, // d exhausted, pattern has ≥1 more segment → matches deeper
        (Some(seg), Some(ds)) => wildcard_match(seg, ds) && can_match_under(&p[1..], &d[1..]),
    }
}

/// Match a `.dockerignore` glob against a context-relative path: `/`-separated segments,
/// `*`/`?` within a segment, `**` spanning segments. Matches the whole path (ancestor
/// directories are handled by the parent-state inheritance in `excluded`).
fn glob_match(pattern: &str, path: &str) -> bool {
    let p: Vec<&str> = pattern.split('/').collect();
    let n: Vec<&str> = path.split('/').collect();
    seg_match(&p, &n)
}

fn seg_match(p: &[&str], n: &[&str]) -> bool {
    match p.first() {
        None => n.is_empty(),
        Some(&"**") => (0..=n.len()).any(|i| seg_match(&p[1..], &n[i..])),
        Some(seg) => !n.is_empty() && wildcard_match(seg, n[0]) && seg_match(&p[1..], &n[1..]),
    }
}

/// Glob one path segment: `*` matches any run (no `/`), `?` one char.
fn wildcard_match(pat: &str, s: &str) -> bool {
    let (p, s): (Vec<char>, Vec<char>) = (pat.chars().collect(), s.chars().collect());
    // dp[i][j] = pat[i..] matches s[j..]
    let mut dp = vec![vec![false; s.len() + 1]; p.len() + 1];
    dp[p.len()][s.len()] = true;
    for i in (0..p.len()).rev() {
        for j in (0..=s.len()).rev() {
            dp[i][j] = match p[i] {
                '*' => dp[i + 1][j] || (j < s.len() && dp[i][j + 1]),
                '?' => j < s.len() && dp[i + 1][j + 1],
                c => j < s.len() && s[j] == c && dp[i + 1][j + 1],
            };
        }
    }
    dp[0][0]
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn dockerignore_glob_patterns() {
        // patterns from the wab .dockerignore (leading '/' already stripped on load)
        assert!(glob_match("fat_tool/target", "fat_tool/target"));
        assert!(!glob_match("fat_tool/target", "fat_tool/src"));
        assert!(glob_match(
            "debian-repository/*-pool",
            "debian-repository/bookworm-pool"
        ));
        assert!(!glob_match(
            "debian-repository/*-pool",
            "debian-repository/pool"
        ));
        // `*` does not cross a path separator
        assert!(!glob_match(
            "debian-repository/*-pool",
            "debian-repository/a/b-pool"
        ));
        // `**` spans any number of segments (including zero)
        assert!(glob_match("task/**/*_test.go", "task/a/b/x_test.go"));
        assert!(glob_match("task/**/*_test.go", "task/x_test.go"));
        assert!(!glob_match("task/**/*_test.go", "task/x.go"));
        assert!(glob_match("task/**/.*", "task/a/.hidden"));
        assert!(glob_match("tests", "tests"));
        assert!(!glob_match("tests", "tests2"));
        // `?` matches exactly one char
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
    }

    /// Cases ported from moby's pattern matcher (github.com/moby/patternmatcher,
    /// `matchers_test.go` `TestWildcardMatches`/`TestMatches`) — the full-path-match
    /// subset that applies to our `glob_match`. Negation (`!`) and directory-prefix
    /// matching (a pattern matching an ancestor dir) are out of scope here: we don't
    /// support `!`, and the copy walk handles ancestor dirs by checking each as it
    /// descends, so `glob_match` only needs whole-path semantics.
    #[test]
    fn moby_patternmatcher_cases() {
        let yes: &[(&str, &str)] = &[
            ("**", "file"),
            ("**", "dir/file"),
            ("**/**", "dir/file"),
            ("dir/**", "dir/file"),
            ("dir/**", "dir/dir2/file"),
            ("**/file", "file"),
            ("**/file", "dir/file"),
            ("**/file", "dir/dir/file"),
            ("**/dir2/*", "dir/dir2/file"),
            ("**/dir2/**", "dir/dir2/dir3/file"),
            ("abc.def", "abc.def"),
            ("a*/b", "a/b"),
            ("a*/b", "abc/b"),
            ("a*b*c*d*e*/f", "axbxcxdxe/f"),
            ("a*b*c*d*e*/f", "axbxcxdxexxx/f"),
            ("a*b?c*x", "abxbbxdbxebxczzx"),
            ("*.txt", "file.txt"),
            ("*", "any"),
            ("*/*", "a/b"),
            ("?", "a"),
        ];
        let no: &[(&str, &str)] = &[
            ("a*/b", "a/c"),
            ("a*b?c*x", "abxbbxdbxebxczzy"),
            ("*.txt", "dir/file.txt"), // `*` does not cross `/`
            ("?", "ab"),
            ("abc", "abcd"),
        ];
        for (p, path) in yes {
            assert!(glob_match(p, path), "expected {p:?} to match {path:?}");
        }
        for (p, path) in no {
            assert!(!glob_match(p, path), "expected {p:?} NOT to match {path:?}");
        }
    }
}
