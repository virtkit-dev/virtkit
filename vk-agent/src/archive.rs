//! `vk-agent archive` and `vk-agent extract`: a CI job's caches and artifacts, packed and
//! unpacked inside its guest on the job's tree as the job left it, the tar streamed over the
//! exec channel to the host, which compresses it and moves it over the network. No archiver
//! has to be in the job's image.
//!
//! What an archive holds follows gitlab-runner v19.5's `commands/helpers/file_archiver.go`
//! (MIT, Copyright (c) 2015-2019 GitLab Inc.): `paths` are doublestar globs relative to the
//! project dir, a matching directory brings its whole tree, a path outside the project is
//! refused with a warning, `--untracked` adds what `git ls-files -o -z` lists, and `exclude`
//! globs drop matches. `--untracked` runs `git`, which the job's image then has to have. Its
//! log lines go to stderr as the helper prints them into the trace: warnings prefixed
//! `WARNING: `, the counts unprefixed.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    root: PathBuf,
    paths: Vec<String>,
    exclude: Vec<String>,
    untracked: bool,
}

fn parse_args(args: &[String]) -> Option<Args> {
    let mut it = args.iter();
    let mut out = Args {
        root: PathBuf::from(it.next()?),
        ..Args::default()
    };
    let mut rest = false;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            _ if rest => out.paths.push(arg.clone()),
            "--" => rest = true,
            "--untracked" => out.untracked = true,
            "--exclude" => out.exclude.push(it.next()?.clone()),
            _ => out.paths.push(arg.clone()),
        }
    }
    Some(out)
}

/// `vk-agent archive <root> [--untracked] [--exclude <glob>]... [--] <glob>...`: a tar of the
/// selection on stdout.
pub fn archive_main(args: &[String]) -> i32 {
    let Some(args) = parse_args(args) else {
        eprintln!(
            "usage: vk-agent archive <root> [--untracked] [--exclude <glob>]... [--] <glob>..."
        );
        return 2;
    };
    let mut log = |line: &str| eprintln!("{line}");
    let files = select(&args, &mut log);
    let stdout = std::io::stdout();
    let out = std::io::BufWriter::with_capacity(1 << 16, stdout.lock());
    match write_tar(&args.root, &files, out) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("archive: {e}");
            1
        }
    }
}

/// `vk-agent extract <root>`: unpack the tar on stdin under `root`.
pub fn extract_main(args: &[String]) -> i32 {
    let [root] = args else {
        eprintln!("usage: vk-agent extract <root>");
        return 2;
    };
    match extract(Path::new(root), std::io::stdin().lock()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("extract: {e}");
            1
        }
    }
}

/// Unpack `input` under `root`. The tar crate's `unpack` skips an entry naming `..` and takes
/// an absolute one relative to `root`; an entry that would land outside it through a symlink,
/// planted by the archive or already there, or a hard link to a file outside it, is an error.
/// Modes keep their permission bits only: no setuid, setgid or sticky bit, as extraction may run
/// as root.
fn extract(root: &Path, input: impl std::io::Read) -> std::io::Result<()> {
    std::fs::create_dir_all(root)?;
    let mut archive = tar::Archive::new(input);
    archive.set_overwrite(true);
    archive.set_preserve_mtime(true);
    // Not preserved, a mode is applied masked to 0o777.
    archive.set_preserve_permissions(false);
    archive.unpack(root)
}

/// Selected paths in order, relative to `root`, including directories and their trees.
fn select(args: &Args, log: &mut dyn FnMut(&str)) -> BTreeSet<String> {
    let mut exclude = Vec::new();
    for rule in &args.exclude {
        let Some(rel) = relative_in_project(&args.root, rule) else {
            log(&format!(
                "WARNING: isExcluded: exclude pattern is not a subpath of project directory: \
                 {rule}"
            ));
            continue;
        };
        match Pattern::new(&rel) {
            Some(pattern) => exclude.push((rule.clone(), pattern)),
            None => log(&format!("WARNING: isExcluded: {rule}: {BAD_PATTERN}")),
        }
    }
    let mut sel = Selector {
        root: &args.root,
        canon_root: std::fs::canonicalize(&args.root).unwrap_or_else(|_| args.root.clone()),
        exclude,
        files: BTreeSet::new(),
        excluded: BTreeMap::new(),
    };
    for path in &args.paths {
        sel.process_path(path, log);
    }
    if args.untracked {
        sel.process_untracked(log);
    }
    for (rule, count) in &sel.excluded {
        log(&format!("{rule}: excluded {count} files"));
    }
    sel.files
}

struct Selector<'a> {
    root: &'a Path,
    /// `root` with its symlinks resolved: what a selected path's directory must resolve under.
    canon_root: PathBuf,
    /// Each exclude rule as given, with its pattern relative to `root`.
    exclude: Vec<(String, Pattern)>,
    files: BTreeSet<String>,
    excluded: BTreeMap<String, u64>,
}

/// The characters that make a path a glob.
const GLOB: [char; 5] = ['*', '?', '[', '{', '\\'];

/// What doublestar's `ErrBadPattern` says.
const BAD_PATTERN: &str = "syntax error in pattern";

impl Selector<'_> {
    fn process_path(&mut self, path: &str, log: &mut dyn FnMut(&str)) {
        if path.is_empty() {
            log("WARNING: No matching files. Path is empty.");
            return;
        }
        let rel = relative_in_project(self.root, path);
        let Some(rel) = rel.filter(|rel| self.resolves_inside(glob_base(rel))) else {
            log(&format!(
                "WARNING: processPath: artifact path is not a subpath of project directory: {path}"
            ));
            return;
        };
        let Some(matched) = glob(self.root, &rel, log) else {
            log(&format!("WARNING: processPath: {path}: {BAD_PATTERN}"));
            return;
        };
        let mut found = 0u64;
        for m in matched {
            self.walk(&m, &mut found, log);
        }
        if found == 0 {
            log(&format!(
                "WARNING: {path}: no matching files. Ensure that the artifact path is relative to \
                 the working directory ({})",
                self.root.display()
            ));
        } else {
            log(&format!(
                "{path}: found {found} matching artifact files and directories"
            ));
        }
    }

    /// Whether the directory `dir`, relative to `root`, is still under it with its symlinks
    /// followed. One that does not exist is: nothing is found in it.
    fn resolves_inside(&self, dir: &str) -> bool {
        if dir.is_empty() || dir == "." {
            return true;
        }
        std::fs::canonicalize(self.root.join(dir)).map_or(true, |p| p.starts_with(&self.canon_root))
    }

    /// Select `rel` and its tree if it is a directory. Select symlinks without following them.
    fn walk(&mut self, rel: &str, found: &mut u64, log: &mut dyn FnMut(&str)) {
        if self.process(rel) {
            *found += 1;
        }
        let abs = self.root.join(rel);
        let is_dir = std::fs::symlink_metadata(&abs).is_ok_and(|m| m.is_dir());
        if !is_dir {
            return;
        }
        let mut names: Vec<String> = read_dir(&abs, rel, log)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        names.sort();
        for name in names {
            self.walk(&child(rel, &name), found, log);
        }
    }

    /// Add `rel` unless excluded; whether it was added.
    fn process(&mut self, rel: &str) -> bool {
        if rel == "." {
            // The project dir itself is the archive's root, not an entry of it.
            return std::fs::symlink_metadata(self.root).is_ok();
        }
        for (rule, pattern) in &self.exclude {
            if pattern.matches(rel) {
                *self.excluded.entry(rule.clone()).or_default() += 1;
                return false;
            }
        }
        if std::fs::symlink_metadata(self.root.join(rel)).is_err() {
            return false;
        }
        self.files.insert(rel.to_string());
        true
    }

    fn process_untracked(&mut self, log: &mut dyn FnMut(&str)) {
        let out = std::process::Command::new("git")
            .args(["ls-files", "-o", "-z"])
            .current_dir(self.root)
            .stderr(std::process::Stdio::inherit())
            .output();
        let out = match out {
            Ok(out) if out.status.success() => out.stdout,
            Ok(out) => {
                log(&format!("WARNING: untracked: {}", out.status));
                return;
            }
            Err(e) => {
                log(&format!("WARNING: untracked: {e}"));
                return;
            }
        };
        let mut found = 0u64;
        for name in out.split(|&b| b == 0).filter(|n| !n.is_empty()) {
            let Ok(name) = std::str::from_utf8(name) else {
                log(&format!(
                    "WARNING: {}: file name is not UTF-8",
                    String::from_utf8_lossy(name)
                ));
                continue;
            };
            let Some(rel) = relative_in_project(self.root, name) else {
                continue;
            };
            if self.process(&rel) {
                found += 1;
            }
        }
        if found == 0 {
            log("WARNING: untracked: no files");
        } else {
            log(&format!("untracked: found {found} files"));
        }
    }
}

/// `name` in the directory `dir`, both relative to the root.
fn child(dir: &str, name: &str) -> String {
    if dir.is_empty() || dir == "." {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

/// Entries of `abs` (`rel` relative to the root), with directory flags, without following
/// symlinks. Warn on non-UTF-8 names and read errors; missing directories and non-directories
/// read as empty.
fn read_dir(abs: &Path, rel: &str, log: &mut dyn FnMut(&str)) -> Vec<(String, bool)> {
    let entries = match std::fs::read_dir(abs) {
        Ok(entries) => entries,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Vec::new();
        }
        Err(e) => {
            log(&format!("WARNING: {rel}: {e}"));
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                log(&format!("WARNING: {rel}: {e}"));
                continue;
            }
        };
        match entry.file_name().into_string() {
            Ok(name) => out.push((name, entry.file_type().is_ok_and(|t| t.is_dir()))),
            Err(name) => log(&format!(
                "WARNING: {}: file name is not UTF-8",
                child(rel, &name.to_string_lossy())
            )),
        }
    }
    out
}

/// `path` — a glob or a plain path, relative to `root` or absolute under it — as a clean
/// relative pattern, or `None` when it reaches outside `root` (`findRelativePathInProject`).
fn relative_in_project(root: &Path, path: &str) -> Option<String> {
    let path = if path.starts_with('/') {
        // Compared by components: a trailing or doubled `/` in either does not matter.
        Path::new(path).strip_prefix(root).ok()?.to_str()?
    } else {
        path
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            p => parts.push(p),
        }
    }
    if parts.is_empty() {
        return Some(".".into());
    }
    Some(parts.join("/"))
}

/// Search directory: the literal prefix before the first glob character, up to its last
/// `/` (a plain path's parent).
fn glob_base(pattern: &str) -> &str {
    let meta = pattern.find(GLOB).unwrap_or(pattern.len());
    pattern
        .get(..meta)
        .and_then(|lit| lit.rfind('/'))
        .and_then(|i| pattern.get(..i))
        .unwrap_or("")
}

/// The paths under `root` that `pattern` names, relative to it, or `None` for a pattern that
/// is not a valid glob. A pattern without glob characters names itself.
fn glob(root: &Path, pattern: &str, log: &mut dyn FnMut(&str)) -> Option<Vec<String>> {
    if !pattern.contains(GLOB) {
        return Some(match std::fs::symlink_metadata(root.join(pattern)) {
            Ok(_) => vec![pattern.to_string()],
            Err(_) => Vec::new(),
        });
    }
    let compiled = Pattern::new(pattern)?;
    let base = glob_base(pattern);
    let mut out = Vec::new();
    if !base.is_empty() && compiled.matches(base) {
        match std::fs::symlink_metadata(root.join(base)) {
            // The caller walks a matching directory once, including a matching base
            // such as `target` for `target/**`.
            Ok(meta) if meta.is_dir() => return Some(vec![base.to_string()]),
            // A symlink is selected as a link, and the literal base is followed below.
            Ok(_) => out.push(base.to_string()),
            Err(_) => return Some(out),
        }
    }
    // Walk down from the base, not below the depth the pattern can reach; a symlink below it
    // is matched, not followed.
    let depth = compiled.depth();
    let mut stack = vec![base.to_string()];
    while let Some(dir) = stack.pop() {
        let abs = if dir.is_empty() {
            root.to_path_buf()
        } else {
            root.join(&dir)
        };
        for (name, is_dir) in read_dir(&abs, &dir, log) {
            let rel = child(&dir, &name);
            if compiled.matches(&rel) {
                out.push(rel);
            } else if is_dir && depth.is_none_or(|d| rel.split('/').count() < d) {
                stack.push(rel);
            }
        }
    }
    out.sort();
    Some(out)
}

/// A doublestar glob as gitlab-runner matches paths against it (doublestar v4): `*`, `?` and
/// `[...]` within a path segment, `**` as a whole segment for any number of them, `{a,b}`
/// alternatives, `\` escaping the next character. Matching is by character, not byte.
struct Pattern {
    /// Brace-expanded alternatives, each split into segments.
    alts: Vec<Vec<Segment>>,
}

enum Segment {
    /// `**`.
    Any,
    Tokens(Vec<Token>),
}

enum Token {
    /// `*`.
    Star,
    /// `?`.
    One,
    Lit(char),
    /// `[...]`: its ranges, single characters as one-character ranges.
    Class {
        negate: bool,
        ranges: Vec<(char, char)>,
    },
}

impl Pattern {
    /// `None` where doublestar returns `ErrBadPattern`: an unclosed `[` or `{`, an empty class,
    /// a trailing `\`.
    fn new(pattern: &str) -> Option<Self> {
        let alts = expand_braces(pattern)?
            .iter()
            .map(|alt| {
                alt.split('/')
                    .map(|seg| match seg {
                        "**" => Some(Segment::Any),
                        seg => tokens(seg).map(Segment::Tokens),
                    })
                    .collect::<Option<Vec<_>>>()
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self { alts })
    }

    fn matches(&self, path: &str) -> bool {
        let path: Vec<Vec<char>> = path.split('/').map(|s| s.chars().collect()).collect();
        self.alts.iter().any(|alt| match_segments(alt, &path))
    }

    /// Maximum matching path depth in segments, or `None` if `**` makes it unbounded.
    fn depth(&self) -> Option<usize> {
        self.alts.iter().try_fold(0, |depth, alt| {
            (!alt.iter().any(|s| matches!(s, Segment::Any))).then(|| depth.max(alt.len()))
        })
    }
}

/// A pattern segment's tokens, or `None` if it is malformed.
fn tokens(seg: &str) -> Option<Vec<Token>> {
    let c: Vec<char> = seg.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(&ch) = c.get(i) {
        i += 1;
        out.push(match ch {
            '*' => Token::Star,
            '?' => Token::One,
            '\\' => {
                i += 1;
                Token::Lit(*c.get(i - 1)?)
            }
            '[' => {
                let negate = matches!(c.get(i), Some('!' | '^'));
                if negate {
                    i += 1;
                }
                let mut ranges = Vec::new();
                loop {
                    let lo = match *c.get(i)? {
                        ']' => break,
                        '\\' => {
                            i += 1;
                            *c.get(i)?
                        }
                        lo => lo,
                    };
                    i += 1;
                    let mut hi = lo;
                    if c.get(i) == Some(&'-') && c.get(i + 1).is_some_and(|&n| n != ']') {
                        i += 1;
                        if c.get(i) == Some(&'\\') {
                            i += 1;
                        }
                        hi = *c.get(i)?;
                        i += 1;
                    }
                    ranges.push((lo, hi));
                }
                i += 1;
                if ranges.is_empty() {
                    return None;
                }
                Token::Class { negate, ranges }
            }
            ch => Token::Lit(ch),
        });
    }
    Some(out)
}

/// `pattern`'s segments against `path`'s, `**` taking any number of them. Backtracking only
/// to the last `**` seen is enough, as every other segment takes exactly one: linear in
/// practice, quadratic at worst.
fn match_segments(pattern: &[Segment], path: &[Vec<char>]) -> bool {
    let (mut p, mut s) = (0, 0);
    // After the last `**`: where the pattern resumes, and where in the path it last did.
    let mut star: Option<(usize, usize)> = None;
    while let Some(name) = path.get(s) {
        match pattern.get(p) {
            Some(Segment::Any) => {
                p += 1;
                star = Some((p, s));
            }
            Some(Segment::Tokens(t)) if match_tokens(t, name) => {
                p += 1;
                s += 1;
            }
            _ => match star {
                Some((sp, ss)) => {
                    p = sp;
                    s = ss + 1;
                    star = Some((sp, s));
                }
                None => return false,
            },
        }
    }
    pattern
        .get(p..)
        .unwrap_or_default()
        .iter()
        .all(|seg| matches!(seg, Segment::Any))
}

/// One path segment against a pattern segment's tokens: the same backtracking, `*` for any run
/// of characters.
fn match_tokens(p: &[Token], s: &[char]) -> bool {
    let (mut pi, mut si) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while let Some(&c) = s.get(si) {
        match p.get(pi) {
            Some(Token::Star) => {
                pi += 1;
                star = Some((pi, si));
            }
            Some(t) if match_one(t, c) => {
                pi += 1;
                si += 1;
            }
            _ => match star {
                Some((sp, ss)) => {
                    pi = sp;
                    si = ss + 1;
                    star = Some((sp, si));
                }
                None => return false,
            },
        }
    }
    p.get(pi..)
        .unwrap_or_default()
        .iter()
        .all(|t| matches!(t, Token::Star))
}

/// Whether the single-character token `t` matches `c`.
fn match_one(t: &Token, c: char) -> bool {
    match t {
        Token::Star => false,
        Token::One => true,
        Token::Lit(lit) => *lit == c,
        Token::Class { negate, ranges } => {
            ranges.iter().any(|&(lo, hi)| (lo..=hi).contains(&c)) != *negate
        }
    }
}

/// Index just past the class starting at `open`, or `None` if it is unclosed.
fn class_end(b: &[u8], open: usize) -> Option<usize> {
    let mut i = open + 1;
    if matches!(b.get(i), Some(b'!' | b'^')) {
        i += 1;
    }
    loop {
        match b.get(i)? {
            b'\\' => i += 2,
            b']' => return Some(i + 1),
            _ => i += 1,
        }
    }
}

/// Expand `{a,b}` alternatives, including nested braces. Escaped braces and braces in
/// classes are literal. Return `None` for an unclosed `{`.
fn expand_braces(p: &str) -> Option<Vec<String>> {
    let b = p.as_bytes();
    // Past an escape or a class from `i`, or `None` at a character to look at.
    let skip = |i: usize| match b.get(i) {
        Some(b'\\') => Some(i + 2),
        Some(b'[') => Some(class_end(b, i).unwrap_or(i + 1)),
        _ => None,
    };
    let mut i = 0;
    let open = loop {
        match b.get(i) {
            None => return Some(vec![p.to_string()]),
            Some(b'{') => break i,
            Some(_) => i = skip(i).unwrap_or(i + 1),
        }
    };
    let mut depth = 0;
    let mut commas = Vec::new();
    let mut i = open;
    let close = loop {
        match b.get(i)? {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    break i;
                }
            }
            b',' if depth == 1 => commas.push(i),
            _ => {
                if let Some(next) = skip(i) {
                    i = next;
                    continue;
                }
            }
        }
        i += 1;
    };
    let (head, tail) = (p.get(..open)?, p.get(close + 1..)?);
    let mut bounds = vec![open];
    bounds.extend(commas);
    bounds.push(close);
    let mut out = Vec::new();
    for w in bounds.windows(2) {
        let alt = p.get(w[0] + 1..w[1])?;
        out.extend(expand_braces(&format!("{head}{alt}{tail}"))?);
    }
    Some(out)
}

/// A tar of `files` under `root`: directories as directories, symlinks as symlinks, with
/// their modes and times; sockets, fifos and devices left out.
fn write_tar(root: &Path, files: &BTreeSet<String>, out: impl Write) -> std::io::Result<()> {
    let mut tar = tar::Builder::new(out);
    tar.follow_symlinks(false);
    for rel in files {
        let abs = root.join(rel);
        let meta = match std::fs::symlink_metadata(&abs) {
            Ok(meta) => meta,
            // Removed since it was selected.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let kind = meta.file_type();
        if !(kind.is_dir() || kind.is_file() || kind.is_symlink()) {
            continue;
        }
        if Path::new(rel)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        {
            continue;
        }
        tar.append_path_with_name(&abs, rel)?;
    }
    tar.into_inner()?.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    /// A scratch directory, removed when dropped.
    struct Tmp(PathBuf);

    impl Tmp {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("vk-archive-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A project tree at `<tmp>/p`, with room beside it for what must stay outside.
    fn tree(tag: &str) -> (Tmp, PathBuf) {
        let tmp = Tmp::new(tag);
        let root = tmp.0.join("p");
        for f in [
            "target/debug/app",
            "target/debug/deps/a.rlib",
            "target/tmp/x",
            "src/main.rs",
            "src/lib.rs",
            "report.xml",
            "logs/a.log",
            "logs/b.txt",
        ] {
            let p = root.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, f).unwrap();
        }
        (tmp, root)
    }

    fn select_with(args: Args) -> (Vec<String>, Vec<String>) {
        let mut lines = Vec::new();
        let files = select(&args, &mut |l: &str| lines.push(l.to_string()));
        (files.into_iter().collect(), lines)
    }

    fn sel(root: &Path, paths: &[&str], exclude: &[&str]) -> (Vec<String>, Vec<String>) {
        select_with(Args {
            root: root.to_path_buf(),
            paths: paths.iter().map(|s| s.to_string()).collect(),
            exclude: exclude.iter().map(|s| s.to_string()).collect(),
            untracked: false,
        })
    }

    fn matches(pattern: &str, path: &str) -> bool {
        Pattern::new(pattern).is_some_and(|p| p.matches(path))
    }

    #[test]
    fn doublestar_globs_match_as_gitlab_runner_matches_them() {
        assert!(matches("**/*.log", "logs/a.log"));
        assert!(matches("**/*.log", "a.log"));
        assert!(matches("target/**", "target"));
        assert!(matches("target/**", "target/debug/app"));
        assert!(!matches("target/*", "target/debug/app"));
        assert!(matches("src/*.{rs,toml}", "src/main.rs"));
        assert!(matches("logs/[ab].log", "logs/a.log"));
        assert!(!matches("logs/[!ab].log", "logs/a.log"));
        assert!(matches("logs/?.txt", "logs/b.txt"));
        assert!(!matches("*.xml", "dir/report.xml"));
    }

    #[test]
    fn wildcards_backtrack_correctly_and_in_linear_time() {
        assert!(matches("*a*b", "xaybab"));
        assert!(!matches("*a*b", "xaybaa"));
        assert!(matches("a*", "a"));
        assert!(matches("*.tar.*", "x.tar.tar.gz"));
        assert!(matches("[*]x", "*x"));
        assert!(!matches("[*]x", "ax"));
        assert!(matches("\\*x", "*x"));
        assert!(!matches("\\*x", "ax"));
        assert!(Pattern::new("a[b").is_none());
        assert!(matches("**/a/**/b", "a/b"));
        assert!(matches("**/a/**/b", "x/a/y/z/b"));
        assert!(!matches("**/a/**/b", "x/a/y/z/b/c"));
        assert!(matches("a/**/**/b", "a/b"));
        assert!(!matches("a/**/c", "a/b"));
        // Exponential for a naive recursive matcher.
        let long = "a".repeat(64);
        assert!(!matches(&format!("{}b", "a*".repeat(32)), &long));
        let deep = vec!["d"; 64].join("/");
        assert!(!matches(&format!("{}x", "**/".repeat(32)), &deep));
        assert!(matches(&format!("{}d", "**/".repeat(32)), &deep));
    }

    #[test]
    fn patterns_match_as_doublestar_v4_matches_them() {
        // (pattern, path, whether it matches); doublestar's results.
        for (pattern, path, want) in [
            // By character, not byte.
            ("?", "é", true),
            ("[!a]", "é", true),
            ("[é]", "é", true),
            ("a?c", "aéc", true),
            // Escapes in braces.
            ("{a\\,b,c}", "a,b", true),
            ("{a\\,b,c}", "c", true),
            ("{a\\,b,c}", "a", false),
            ("\\{a,b}", "a", false),
            ("\\{a,b}", "{a,b}", true),
            // Escapes in classes.
            ("[\\]]", "]", true),
            ("[\\-]", "-", true),
            ("[\\-]", "a", false),
            ("[\\a-\\c]", "b", true),
            ("[\\a-\\c]", "d", false),
            ("[a-]", "-", true),
            ("[^a]", "b", true),
            // A brace in a class is literal.
            ("[{]{a,b}", "{a", true),
            ("[{]{a,b}", "{b", true),
            ("[{]{a,b}", "a", false),
            // `**` only as a whole segment.
            ("a**", "abc", true),
            ("a**", "a/b", false),
            ("{a,b/**}", "b/c/d", true),
        ] {
            assert_eq!(matches(pattern, path), want, "{pattern} vs {path}");
        }
        for bad in ["a[", "[]a]", "[!]", "{a,b", "a\\", "x/[a-"] {
            assert!(Pattern::new(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn an_invalid_pattern_matches_nothing_and_is_warned_about() {
        let (_tmp, root) = tree("bad");
        let (files, lines) = sel(&root, &["logs/[", "report.xml"], &["{a"]);
        assert_eq!(files, ["report.xml"]);
        assert_eq!(
            lines[..2],
            [
                "WARNING: isExcluded: {a: syntax error in pattern",
                "WARNING: processPath: logs/[: syntax error in pattern",
            ],
            "{lines:?}"
        );
    }

    #[test]
    fn a_symlinked_base_is_followed_and_a_bounded_glob_stays_shallow() {
        let (_tmp, root) = tree("base");
        symlink("logs", root.join("link")).unwrap();
        let (files, _) = sel(&root, &["link/**"], &[]);
        assert_eq!(files, ["link", "link/a.log", "link/b.txt"]);
        // `target/*.rlib` reaches two segments deep: target/debug is not read.
        let locked = root.join("target/debug");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let readable = std::fs::read_dir(&locked).is_ok();
        let (files, bounded) = sel(&root, &["target/*.rlib"], &[]);
        let (_, unbounded) = sel(&root, &["target/**/*.rlib"], &[]);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(files.is_empty());
        let warned = |lines: &[String]| {
            lines
                .iter()
                .any(|l| l.starts_with("WARNING: target/debug:"))
        };
        assert!(!warned(&bounded), "{bounded:?}");
        // Root reads it regardless; anyone else is warned when it is walked.
        assert_eq!(warned(&unbounded), !readable, "{unbounded:?}");
    }

    #[test]
    fn a_directory_brings_its_tree_and_excludes_drop_matches() {
        let (_tmp, root) = tree("dirs");
        let (files, lines) = sel(&root, &["target/"], &["target/tmp/**", "../x"]);
        assert_eq!(
            files,
            [
                "target",
                "target/debug",
                "target/debug/app",
                "target/debug/deps",
                "target/debug/deps/a.rlib"
            ]
        );
        assert!(
            lines.contains(&"target/tmp/**: excluded 2 files".to_string()),
            "{lines:?}"
        );
        assert!(
            lines[0].starts_with("WARNING: ")
                && lines[0].ends_with("not a subpath of project directory: ../x"),
            "{lines:?}"
        );
        let (files, _) = sel(&root, &["**/*.log", "report.xml"], &[]);
        assert_eq!(files, ["logs/a.log", "report.xml"]);
        // `dir/**` matches the directory itself, which brings its tree once.
        let (files, lines) = sel(&root, &["logs/**"], &[]);
        assert_eq!(files, ["logs", "logs/a.log", "logs/b.txt"]);
        assert_eq!(
            lines,
            ["logs/**: found 3 matching artifact files and directories"]
        );
    }

    #[test]
    fn paths_outside_the_project_and_matching_nothing_are_warned_about() {
        let (_tmp, root) = tree("escape");
        let (files, lines) = sel(
            &root,
            &["../etc/passwd", "/etc/passwd", "nothing/*", ""],
            &[],
        );
        assert!(files.is_empty());
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert!(
            lines.iter().all(|l| l.starts_with("WARNING: ")),
            "{lines:?}"
        );
        assert!(lines[0].contains("not a subpath of project directory: ../etc/passwd"));
        assert!(lines[2].contains("nothing/*: no matching files"));
        // An absolute path inside the project is taken relative to it, however the root is
        // spelled.
        let abs = format!("{}/report.xml", root.display());
        for spelled in [
            root.clone(),
            PathBuf::from(format!("{}/", root.display())),
            PathBuf::from(format!("{}//.", root.display())),
        ] {
            let (files, lines) = sel(&spelled, &[&abs, "src/../report.xml"], &[]);
            assert_eq!(files, ["report.xml"], "{spelled:?}: {lines:?}");
        }
    }

    #[test]
    fn a_path_through_a_symlink_out_of_the_project_is_refused() {
        let (tmp, root) = tree("through");
        let outside = tmp.0.join("outside");
        std::fs::create_dir_all(outside.join("sub")).unwrap();
        std::fs::write(outside.join("secret"), "s").unwrap();
        symlink(&outside, root.join("out")).unwrap();
        symlink("src", root.join("inner")).unwrap();
        let (files, lines) = sel(&root, &["out/secret", "out/*", "out/sub/**"], &[]);
        assert!(files.is_empty(), "{files:?}");
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(
            lines
                .iter()
                .all(|l| l.contains("is not a subpath of project directory")),
            "{lines:?}"
        );
        // The link itself is selected as a link; one staying inside is followed.
        let (files, _) = sel(&root, &["out", "inner/main.rs"], &[]);
        assert_eq!(files, ["inner/main.rs", "out"]);
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_names_and_directories_are_warned_about() {
        use std::os::unix::ffi::OsStrExt;
        let (_tmp, root) = tree("names");
        std::fs::write(
            root.join("logs")
                .join(std::ffi::OsStr::from_bytes(b"bad\xff")),
            "",
        )
        .unwrap();
        let (files, lines) = sel(&root, &["logs"], &[]);
        assert_eq!(files, ["logs", "logs/a.log", "logs/b.txt"]);
        assert!(
            lines.contains(&"WARNING: logs/bad\u{fffd}: file name is not UTF-8".to_string()),
            "{lines:?}"
        );
        // Root ignores permissions: an unreadable directory only fails as another user.
        let locked = root.join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let readable = std::fs::read_dir(&locked).is_ok();
        let (files, lines) = sel(&root, &["locked"], &[]);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(files, ["locked"]);
        if !readable {
            assert!(
                lines.iter().any(|l| l.starts_with("WARNING: locked: ")),
                "{lines:?}"
            );
        }
    }

    #[test]
    fn untracked_adds_what_git_does_not_track() {
        let (_tmp, root) = tree("untracked");
        let git = |args: &[&str]| {
            std::process::Command::new("git")
                .args(args)
                .current_dir(&root)
                .output()
        };
        match git(&["init", "-q"]) {
            Ok(out) if out.status.success() => {}
            _ => {
                eprintln!("no git: skipped");
                return;
            }
        }
        assert!(git(&["add", "src", "target"]).unwrap().status.success());
        let (files, lines) = select_with(Args {
            root: root.clone(),
            paths: Vec::new(),
            exclude: vec!["logs/*.txt".into()],
            untracked: true,
        });
        assert_eq!(files, ["logs/a.log", "report.xml"], "{lines:?}");
        assert!(
            lines.contains(&"untracked: found 2 files".to_string()),
            "{lines:?}"
        );
    }

    #[test]
    fn an_archive_round_trips_without_setuid_setgid_or_sticky_bits() {
        let (tmp, root) = tree("tar");
        symlink("main.rs", root.join("src/link")).unwrap();
        let (files, _) = sel(&root, &["src"], &[]);
        let files: BTreeSet<String> = files.into_iter().collect();
        let mut tar = Vec::new();
        write_tar(&root, &files, &mut tar).unwrap();
        let dest = tmp.0.join("dest");
        extract(&dest, tar.as_slice()).unwrap();
        assert_eq!(
            std::fs::read_to_string(dest.join("src/main.rs")).unwrap(),
            "src/main.rs"
        );
        assert_eq!(
            std::fs::read_link(dest.join("src/link")).unwrap(),
            Path::new("main.rs")
        );

        let mut b = tar::Builder::new(Vec::new());
        append(&mut b, "suid", tar::EntryType::Regular, None, 0o4755);
        append(&mut b, "sgid", tar::EntryType::Directory, None, 0o3775);
        extract(&dest, b.into_inner().unwrap().as_slice()).unwrap();
        let mode = |p: &str| {
            std::fs::metadata(dest.join(p))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(mode("suid"), 0o755);
        assert_eq!(mode("sgid"), 0o775);
    }

    /// Append an entry named `name` verbatim, `..` and all, linking to `link`.
    fn append(
        b: &mut tar::Builder<Vec<u8>>,
        name: &str,
        kind: tar::EntryType,
        link: Option<&str>,
        mode: u32,
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_mode(mode);
        let data: &[u8] = if kind == tar::EntryType::Regular {
            b"x"
        } else {
            b""
        };
        header.set_size(data.len() as u64);
        header.as_gnu_mut().unwrap().name[..name.len()].copy_from_slice(name.as_bytes());
        if let Some(link) = link {
            header.set_link_name(link).unwrap();
        }
        header.set_cksum();
        b.append(&header, data).unwrap();
    }

    /// Extract `entries` into a fresh `<tmp>/dest`, with `<tmp>/outside` beside it.
    fn extract_evil(
        tmp: &Tmp,
        prepare: impl FnOnce(&Path, &Path),
        entries: &[(&str, tar::EntryType, Option<&str>)],
    ) -> (PathBuf, PathBuf, std::io::Result<()>) {
        let dest = tmp.0.join("dest");
        let outside = tmp.0.join("outside");
        let _ = std::fs::remove_dir_all(&dest);
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("file"), "outside").unwrap();
        prepare(&dest, &outside);
        let mut b = tar::Builder::new(Vec::new());
        for &(name, kind, link) in entries {
            append(&mut b, name, kind, link, 0o644);
        }
        let result = extract(&dest, b.into_inner().unwrap().as_slice());
        (dest, outside, result)
    }

    /// Sorted entry names in `dir`.
    fn listing(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn extraction_stays_inside_its_root() {
        use tar::EntryType::{Link, Regular, Symlink};
        let tmp = Tmp::new("evil");
        let parent_listing = || listing(&tmp.0);

        // A name above the root is skipped.
        let (_, outside, result) = extract_evil(&tmp, |_, _| {}, &[("../escape", Regular, None)]);
        result.unwrap();
        assert_eq!(parent_listing(), ["dest", "outside"]);
        assert_eq!(listing(&outside), ["file"]);

        // A path through a symlink the archive planted, to the parent or to `/`.
        for target in ["..", "/"] {
            let (dest, outside, result) = extract_evil(
                &tmp,
                |_, _| {},
                &[("l", Symlink, Some(target)), ("l/escape", Regular, None)],
            );
            let err = result.unwrap_err();
            assert!(err.to_string().contains("outside of destination"), "{err}");
            assert_eq!(
                std::fs::read_link(dest.join("l")).unwrap(),
                Path::new(target)
            );
            assert_eq!(parent_listing(), ["dest", "outside"]);
            assert_eq!(listing(&outside), ["file"]);
            assert!(!Path::new("/escape").exists());
        }

        // A hard link to a file outside.
        let (dest, _, result) =
            extract_evil(&tmp, |_, _| {}, &[("h", Link, Some("../outside/file"))]);
        assert!(result.is_err());
        assert!(std::fs::symlink_metadata(dest.join("h")).is_err());

        // A path through a symlink already in the root.
        let (_, outside, result) = extract_evil(
            &tmp,
            |dest, outside| symlink(outside, dest.join("s")).unwrap(),
            &[("s/x", Regular, None)],
        );
        assert!(result.is_err());
        assert_eq!(listing(&outside), ["file"]);

        // A file over a symlink already in the root replaces the link, not its target.
        let (dest, outside, result) = extract_evil(
            &tmp,
            |dest, outside| symlink(outside.join("file"), dest.join("f")).unwrap(),
            &[("f", Regular, None)],
        );
        result.unwrap();
        assert!(std::fs::symlink_metadata(dest.join("f")).unwrap().is_file());
        assert_eq!(std::fs::read_to_string(dest.join("f")).unwrap(), "x");
        assert_eq!(
            std::fs::read_to_string(outside.join("file")).unwrap(),
            "outside"
        );
    }

    #[test]
    fn arguments_parse_as_the_node_passes_them() {
        let args: Vec<String> = [
            "/b/p",
            "--untracked",
            "--exclude",
            "x/**",
            "--",
            "--odd",
            "a",
        ]
        .map(String::from)
        .to_vec();
        let parsed = parse_args(&args).unwrap();
        assert!(parsed.untracked);
        assert_eq!(parsed.exclude, ["x/**"]);
        assert_eq!(parsed.paths, ["--odd", "a"]);
    }
}
