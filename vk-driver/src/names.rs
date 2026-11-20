//! The index maps stable VM names to state directories. `vk dev list` displays environment
//! names, and `vk dev stop`, `gc` and `prune` accept them.
//!
//! Each `$XDG_STATE_HOME/virtkit/names/<name>` symlink points to a state directory.
//! Creating the link reserves the name atomically. The index's `.lock` serializes
//! claims so a directory receives only one name. Reverse lookups scan the links.
//!
//! An automatic name collision gives the newcomer `app-2`, `app-3`, and so on. The
//! first `app` keeps its name.

use std::ffi::{OsStr, OsString};
use std::os::fd::AsRawFd;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};

/// The longest name.
pub const MAX_LEN: usize = 40;

/// The index's lock file, inside the index directory. Not a valid name, so never a link.
const LOCK: &str = ".lock";

/// `$XDG_STATE_HOME/virtkit`, else `~/.local/state/virtkit`: the root `vk dev`'s state dirs,
/// managed run dirs and the name index share.
pub fn state_base() -> Result<PathBuf> {
    let dev = crate::dev::plan::dev_state_base()?;
    Ok(dev
        .parent()
        .context("the dev state base has no parent")?
        .to_path_buf())
}

/// Parent of the state directories allocated for runs without `--state-dir`.
pub fn run_base() -> Result<PathBuf> {
    Ok(state_base()?.join("run"))
}

/// A name refused for what the caller asked — invalid, taken, or naming nothing to boot —
/// rather than a failure to read or write the index.
#[derive(Debug)]
pub struct Refused(String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// A [`Refused`] error saying `why`.
pub fn refuse(why: impl Into<String>) -> anyhow::Error {
    Refused(why.into()).into()
}

/// Whether `name` is a VM name: `[a-z0-9][a-z0-9._-]*`, at most [`MAX_LEN`], not all digits
/// (which is a pid).
pub fn validate(name: &str) -> Result<()> {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > MAX_LEN {
        return Err(refuse(format!(
            "a VM name has 1 to {MAX_LEN} characters: {name:?}"
        )));
    }
    if !(b[0].is_ascii_lowercase() || b[0].is_ascii_digit()) {
        return Err(refuse(format!(
            "a VM name starts with a lowercase letter or a digit: {name:?}"
        )));
    }
    if !b
        .iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-'))
    {
        return Err(refuse(format!(
            "a VM name holds only a-z, 0-9, '.', '_' and '-': {name:?}"
        )));
    }
    if b.iter().all(u8::is_ascii_digit) {
        return Err(refuse(format!(
            "a VM name is not all digits, which reads as a pid: {name:?}"
        )));
    }
    Ok(())
}

/// `raw` made into a valid name base: lowercased, every other character turned into `-`,
/// runs of `-` folded, trimmed to [`MAX_LEN`]; `vm` when nothing is left, and `vm-<digits>`
/// for something all digits.
pub fn sanitize(raw: &str) -> String {
    let mut out = String::new();
    for c in raw.chars() {
        let c = c.to_ascii_lowercase();
        let keep = c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_');
        let c = if keep { c } else { '-' };
        if c == '-' && (out.is_empty() || out.ends_with('-')) {
            continue;
        }
        out.push(c);
    }
    let mut out: String = out
        .trim_start_matches(['.', '_', '-'])
        .chars()
        .take(MAX_LEN)
        .collect();
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        return "vm".into();
    }
    if out.bytes().all(|b| b.is_ascii_digit()) {
        out = format!("vm-{out}");
        out.truncate(MAX_LEN);
    }
    out
}

/// The state dir a word stands for: a name from the index, or the directory name a dev
/// environment's state dir has under the dev base (its name before names existed). `None`
/// when the word names nothing; an error when it names two different directories.
pub fn resolve(word: &str) -> Result<Option<PathBuf>> {
    crate::dev::list::name_unnamed();
    resolve_in(&Index::open()?, &crate::dev::plan::dev_state_base()?, word)
}

/// [`resolve`] against the index `idx` and the dev base `dev_base`.
pub(crate) fn resolve_in(idx: &Index, dev_base: &Path, word: &str) -> Result<Option<PathBuf>> {
    let named = idx.lookup(word);
    // Only an immediate directory of its own, never a link leading elsewhere.
    let own = is_dir_name(word)
        .then(|| dev_base.join(word))
        .filter(|dir| std::fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir()));
    match (named, own) {
        (Some(named), Some(own))
            if crate::vms::canonical(&named) != crate::vms::canonical(&own) =>
        {
            let other = idx
                .name_of(&own)
                .map_or_else(String::new, |n| format!(", named {n}"));
            Err(refuse(format!(
                "{word} is ambiguous: it names {} and is the state directory {}{other}",
                named.display(),
                own.display()
            )))
        }
        (named, own) => Ok(named.or(own)),
    }
}

/// Whether `word` could be a state dir's own name: one plain path component.
fn is_dir_name(word: &str) -> bool {
    let mut parts = Path::new(word).components();
    matches!(
        (parts.next(), parts.next()),
        (Some(Component::Normal(part)), None) if part == OsStr::new(word)
    )
}

/// The name index.
#[derive(Debug, Clone)]
pub struct Index {
    dir: PathBuf,
    /// names given through this handle are provisional (see [`Index::provisional`])
    provisional: bool,
}

/// The marker of a provisional name, beside its link. Not a valid name, so never a link.
fn marker(name: &str) -> String {
    format!(".claim-{name}")
}

/// The index lock, held for as long as this lives.
pub struct Locked(#[allow(dead_code)] std::fs::File);

impl Index {
    /// The user's index, `$XDG_STATE_HOME/virtkit/names`.
    pub fn open() -> Result<Index> {
        Ok(Index::at(state_base()?.join("names")))
    }

    /// The index in `dir`, for tests.
    pub fn at(dir: impl Into<PathBuf>) -> Index {
        Index {
            dir: dir.into(),
            provisional: false,
        }
    }

    /// Claim names provisionally until the VM is ready ([`Index::commit`]). A run holds
    /// its state directory lock until it ends. A later claim can reclaim an unlocked
    /// provisional name and remove an empty directory directly under `run/`, whoever
    /// created it. Other directories and their contents survive.
    pub fn provisional(&self) -> Index {
        Index {
            dir: self.dir.clone(),
            provisional: true,
        }
    }

    /// Make `name` a name for good: its run's VM is up.
    pub fn commit(&self, name: &str) -> Result<()> {
        let _lock = self.lock()?;
        match std::fs::remove_file(self.dir.join(marker(name))) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(e).with_context(|| format!("committing the name {name}"))
            }
            _ => Ok(()),
        }
    }

    /// Take the index lock, creating the index. Blocks while another claim holds it.
    pub fn lock(&self) -> Result<Locked> {
        crate::statefile::create_dir_all(&self.dir)?;
        let path = self.dir.join(LOCK);
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        // SAFETY: the fd is owned by `f`, which the returned guard keeps alive.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("locking {}", path.display()));
        }
        Ok(Locked(f))
    }

    /// The state dir `name` names, whether or not it still exists.
    pub fn lookup(&self, name: &str) -> Option<PathBuf> {
        validate(name).ok()?;
        std::fs::read_link(self.dir.join(name)).ok()
    }

    /// Every name and its state dir, by name.
    pub fn all(&self) -> Vec<(String, PathBuf)> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut out: Vec<(String, PathBuf)> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                validate(&name).ok()?;
                Some((name, std::fs::read_link(e.path()).ok()?))
            })
            .collect();
        out.sort();
        out
    }

    /// The name of `dir`, if it has one.
    pub fn name_of(&self, dir: &Path) -> Option<String> {
        let canonical = crate::vms::canonical(dir);
        self.all()
            .into_iter()
            .find(|(_, target)| target == dir || *target == canonical)
            .map(|(name, _)| name)
    }

    /// Give `dir` a name from `base` (`base`, `base-2`, `base-3`, …), or return the one it has.
    /// `true` with the name when this call gave it.
    pub fn claim(&self, dir: &Path, base: &str) -> Result<(String, bool)> {
        let _lock = self.lock()?;
        self.claim_locked(dir, base)
    }

    /// [`Index::claim`] with the lock already held.
    pub fn claim_locked(&self, dir: &Path, base: &str) -> Result<(String, bool)> {
        self.forget_removed();
        if let Some(name) = self.name_of(dir) {
            return Ok((name, false));
        }
        let base = sanitize(base);
        for n in 1u32.. {
            let name = match n {
                1 => base.clone(),
                n => {
                    let suffix = format!("-{n}");
                    let keep = MAX_LEN.saturating_sub(suffix.len()).min(base.len());
                    format!("{}{suffix}", base[..keep].trim_end_matches('-'))
                }
            };
            if self.link(&name, dir)? {
                return Ok((name, true));
            }
        }
        unreachable!("u32 suffixes exhausted")
    }

    /// Under the index lock, reclaim provisional names whose state directory is unlocked
    /// or missing. Reclaim committed names only for missing direct children of `run/`
    /// and `dev/`. A committed name on another mount survives an unmount, and scanning
    /// it must not block other claims on a hung mount.
    fn forget_removed(&self) {
        let Some(base) = self.dir.parent() else {
            return;
        };
        let roots = [
            crate::vms::canonical(&base.join("run")),
            crate::vms::canonical(&base.join("dev")),
        ];
        for (name, target) in self.all() {
            let managed = target
                .parent()
                .is_some_and(|p| roots.iter().any(|r| r == p));
            let provisional = self.dir.join(marker(&name));
            let dead = if std::fs::symlink_metadata(&provisional).is_ok() {
                // Its run holds the dir's lock until it ends.
                let ended =
                    crate::dev::list::try_lock_state_dir(&target).is_some() || !target.exists();
                if ended && target.parent() == Some(roots[0].as_path()) {
                    // All direct children of run/ are managed, whoever created them.
                    // remove_dir preserves nonempty directories.
                    let _ = std::fs::remove_dir(&target);
                }
                ended
            } else {
                managed
                    && matches!(
                        std::fs::symlink_metadata(&target),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound
                    )
            };
            if dead {
                // A link that stays only keeps a dead name taken; the next claim retries it.
                let _ = std::fs::remove_file(self.dir.join(&name));
                let _ = std::fs::remove_file(provisional);
            }
        }
    }

    /// Give `dir` exactly `name`. `true` when this call gave it, `false` when `name` already
    /// names `dir`; an error when it names another directory, or when `dir` already has
    /// another name.
    pub fn claim_exact(&self, dir: &Path, name: &str) -> Result<bool> {
        validate(name)?;
        let _lock = self.lock()?;
        self.forget_removed();
        let canonical = crate::vms::canonical(dir);
        if let Some(target) = self.lookup(name) {
            if target == canonical || target == dir {
                return Ok(false);
            }
            let gone = if target.exists() {
                String::new()
            } else {
                format!(
                    ", which is not there: if it was removed, deleting {} frees the name",
                    self.dir.join(name).display()
                )
            };
            return Err(refuse(format!(
                "the name {name} is taken by {}{gone}",
                target.display()
            )));
        }
        if let Some(other) = self.name_of(dir) {
            return Err(refuse(format!(
                "{} is already named {other}",
                dir.display()
            )));
        }
        if !self.link(name, dir)? {
            return Err(refuse(format!("the name {name} was just taken")));
        }
        Ok(true)
    }

    /// Link `name` to `dir`, provisionally if this handle gives provisional names; `false`
    /// when the name is taken. With the lock held.
    fn link(&self, name: &str, dir: &Path) -> Result<bool> {
        let target = crate::vms::canonical(dir);
        let path = self.dir.join(name);
        if std::fs::symlink_metadata(&path).is_ok() {
            return Ok(false);
        }
        if self.provisional {
            // Before the link, so a crash in between never leaves the name committed. One
            // already there with no link is a leftover of such a crash, and is reused.
            let mark = self.dir.join(marker(name));
            std::fs::write(&mark, b"").with_context(|| format!("writing {}", mark.display()))?;
        }
        std::os::unix::fs::symlink(&target, &path)
            .with_context(|| format!("naming {} {name}", target.display()))?;
        Ok(true)
    }

    /// Forget every name of `dir`, under the lock so no claim runs meanwhile.
    pub fn release(&self, dir: &Path) -> Result<()> {
        let _lock = self.lock()?;
        self.release_locked(dir)
    }

    /// [`Index::release`] with the lock already held.
    pub fn release_locked(&self, dir: &Path) -> Result<()> {
        let canonical = crate::vms::canonical(dir);
        for (name, target) in self.all() {
            if target == dir || target == canonical {
                std::fs::remove_file(self.dir.join(&name))
                    .with_context(|| format!("forgetting the name {name}"))?;
                let _ = std::fs::remove_file(self.dir.join(marker(&name)));
            }
        }
        Ok(())
    }
}

/// A remembered `vk run` while it starts: its state dir, whose lock it holds from before its
/// name was claimed until the run ends, so no other run shares the dir meanwhile; and what
/// it publishes once its VM is first ready — the name, committed, and its recipe.
#[derive(Debug)]
pub struct Remembered {
    dir: PathBuf,
    lock: std::fs::File,
    index: Index,
    name: String,
    recipe: Recipe,
    up: std::sync::atomic::AtomicBool,
}

impl Remembered {
    /// The run in `dir`, holding its `lock`, named `name` in `index`. Made before the run
    /// starts — before `--detach` forks — while the command line and the working directory
    /// in `recipe` are still the caller's.
    pub fn new(
        dir: PathBuf,
        lock: std::fs::File,
        index: Index,
        name: String,
        recipe: Recipe,
    ) -> Remembered {
        Remembered {
            dir,
            lock,
            index,
            name,
            recipe,
            up: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// The state dir.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The index it is named in.
    pub fn index(&self) -> &Index {
        &self.index
    }

    /// Another handle on the state dir's lock, for the run to hold.
    pub fn lock(&self) -> std::io::Result<std::fs::File> {
        self.lock.try_clone()
    }

    /// Called as the run's VM is first ready: commit its name and write the recipe. Only a
    /// run whose VM came up writes one, so a run that failed to boot never replaces the
    /// recipe of one that worked.
    pub fn publish(&self) -> Result<()> {
        self.up.store(true, std::sync::atomic::Ordering::Relaxed);
        self.index.commit(&self.name)?;
        self.recipe.write(&self.dir)
    }

    /// Whether the run's VM came up ([`Remembered::publish`]).
    pub fn up(&self) -> bool {
        self.up.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// How a remembered `vk run` was launched: its command line, where, and the project it is
/// about. Kept as `run.json` in the state dir. Each is kept byte for byte: a string when it
/// is UTF-8, else `{"bytes": [...]}`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Recipe {
    /// `vk`'s arguments, the program name left out
    #[serde(with = "os_strings")]
    pub args: Vec<OsString>,
    /// the directory it was launched from
    #[serde(with = "os_string")]
    pub cwd: PathBuf,
    /// `--workspace`, then `--workdir`, then `cwd`
    #[serde(with = "os_string")]
    pub project_dir: PathBuf,
}

/// An `OsStr` as JSON: a string when it is UTF-8, else its bytes.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
enum Raw {
    Text(String),
    Bytes { bytes: Vec<u8> },
}

impl Raw {
    fn of(s: &OsStr) -> Raw {
        use std::os::unix::ffi::OsStrExt;
        match s.to_str() {
            Some(text) => Raw::Text(text.to_string()),
            None => Raw::Bytes {
                bytes: s.as_bytes().to_vec(),
            },
        }
    }

    fn into_os(self) -> OsString {
        use std::os::unix::ffi::OsStringExt;
        match self {
            Raw::Text(text) => text.into(),
            Raw::Bytes { bytes } => OsString::from_vec(bytes),
        }
    }
}

/// `#[serde(with)]` for one `OsString` or `PathBuf`, as [`Raw`].
mod os_string {
    use super::{OsStr, OsString, Raw};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T: AsRef<OsStr>, S: Serializer>(v: &T, s: S) -> Result<S::Ok, S::Error> {
        Raw::of(v.as_ref()).serialize(s)
    }

    pub fn deserialize<'de, T: From<OsString>, D: Deserializer<'de>>(d: D) -> Result<T, D::Error> {
        Ok(Raw::deserialize(d)?.into_os().into())
    }
}

/// `#[serde(with)]` for a list of `OsString`s, each as [`Raw`].
mod os_strings {
    use super::{OsString, Raw};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[OsString], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().map(|a| Raw::of(a)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<OsString>, D::Error> {
        Ok(Vec::<Raw>::deserialize(d)?
            .into_iter()
            .map(Raw::into_os)
            .collect())
    }
}

/// The recipe's file in a state dir.
pub const RECIPE: &str = "run.json";

impl Recipe {
    /// This process's command line, working directory and `project` (default: the working
    /// directory).
    pub fn now(project: Option<PathBuf>) -> Result<Recipe> {
        let cwd = std::env::current_dir().context("resolving the current directory")?;
        Ok(Recipe {
            args: std::env::args_os().skip(1).collect(),
            project_dir: project.unwrap_or_else(|| cwd.clone()),
            cwd,
        })
    }

    /// Write it into `dir`, whole or not at all, for its owner alone: it holds the whole
    /// command line, whatever that carried.
    pub fn write(&self, dir: &Path) -> Result<()> {
        let json = serde_json::to_vec_pretty(self).context("encoding the run recipe")?;
        crate::statefile::write(&dir.join(RECIPE), &json)
            .with_context(|| format!("writing {}", dir.join(RECIPE).display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tmp(tag: &str) -> Tmp {
        let d = std::env::temp_dir().join(format!("vk-names-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Tmp(crate::vms::canonical(&d))
    }

    #[test]
    fn the_grammar_takes_short_lowercase_words_and_refuses_the_rest() {
        for ok in ["app", "wab-wt1", "a.b_c-d", "0x", "1-2"] {
            validate(ok).unwrap();
        }
        for bad in [
            "", "App", "-a", ".a", "_a", "a/b", "a:b", "a@b", "123", "a b", "é",
        ] {
            assert!(validate(bad).is_err(), "{bad:?}");
        }
        assert!(validate(&"a".repeat(MAX_LEN)).is_ok());
        assert!(validate(&"a".repeat(MAX_LEN + 1)).is_err());
    }

    #[test]
    fn sanitize_always_yields_a_valid_name() {
        assert_eq!(sanitize("alpine"), "alpine");
        assert_eq!(sanitize("My App!!"), "my-app");
        assert_eq!(sanitize("--x--"), "x");
        assert_eq!(sanitize(""), "vm");
        assert_eq!(sanitize("///"), "vm");
        assert_eq!(sanitize("2024"), "vm-2024");
        for raw in ["", "Ünïcode", &"x".repeat(100), "a/b:c@d", "9"] {
            validate(&sanitize(raw)).unwrap();
        }
    }

    #[test]
    fn a_claim_takes_the_base_then_numbered_suffixes_and_is_stable() {
        let t = tmp("claim");
        let idx = Index::at(t.0.join("names"));
        let (a, b, c) = (t.0.join("a"), t.0.join("b"), t.0.join("c"));
        for d in [&a, &b, &c] {
            std::fs::create_dir(d).unwrap();
        }
        assert_eq!(idx.claim(&a, "app").unwrap(), ("app".into(), true));
        assert_eq!(idx.claim(&b, "app").unwrap(), ("app-2".into(), true));
        assert_eq!(idx.claim(&c, "app").unwrap(), ("app-3".into(), true));
        // Asked again, a directory keeps the name it has, whatever the base.
        assert_eq!(idx.claim(&b, "other").unwrap(), ("app-2".into(), false));
        assert_eq!(idx.lookup("app-2").unwrap(), b);
        assert_eq!(idx.name_of(&c).as_deref(), Some("app-3"));
        assert_eq!(idx.all().len(), 3);
    }

    #[test]
    fn a_long_base_still_leaves_room_for_its_suffix() {
        let t = tmp("long");
        let idx = Index::at(t.0.join("names"));
        let base = "a".repeat(MAX_LEN);
        for d in ["1", "2"] {
            std::fs::create_dir(t.0.join(d)).unwrap();
        }
        idx.claim(&t.0.join("1"), &base).unwrap();
        let (second, _) = idx.claim(&t.0.join("2"), &base).unwrap();
        assert!(
            second.ends_with("-2") && second.len() <= MAX_LEN,
            "{second}"
        );
        validate(&second).unwrap();
    }

    #[test]
    fn an_exact_claim_refuses_a_taken_name_and_a_named_dir() {
        let t = tmp("exact");
        let idx = Index::at(t.0.join("names"));
        let (a, b) = (t.0.join("a"), t.0.join("b"));
        assert!(idx.claim_exact(&a, "x").unwrap());
        assert!(!idx.claim_exact(&a, "x").unwrap());
        for (dir, name) in [(&b, "x"), (&a, "y"), (&b, "Bad")] {
            let e = idx.claim_exact(dir, name).unwrap_err();
            assert!(e.downcast_ref::<Refused>().is_some(), "{e:#}");
        }
    }

    #[test]
    fn release_forgets_the_names_of_a_dir() {
        let t = tmp("release");
        let idx = Index::at(t.0.join("names"));
        let (a, b) = (t.0.join("a"), t.0.join("b"));
        for d in [&a, &b] {
            std::fs::create_dir(d).unwrap();
        }
        idx.claim(&a, "one").unwrap();
        idx.claim(&b, "two").unwrap();
        idx.release(&a).unwrap();
        assert_eq!(idx.name_of(&a), None);
        assert_eq!(idx.lookup("two").unwrap(), b);
    }

    /// Automatic and exact claims reclaim committed names for missing managed directories.
    /// A missing directory elsewhere may be on an unmounted disk and keeps its name.
    #[test]
    fn claims_forget_removed_managed_directories_but_not_ones_out_of_view() {
        let t = tmp("removed");
        let idx = Index::at(t.0.join("names"));
        let (run, mnt) = (t.0.join("run"), t.0.join("mnt"));
        let (a, b, c) = (run.join("a"), run.join("b"), run.join("c"));
        let away = mnt.join("vm");
        for d in [&a, &away] {
            std::fs::create_dir_all(d).unwrap();
        }
        // A committed name is kept while its directory is there, recipe or not.
        assert_eq!(idx.claim(&a, "app").unwrap().0, "app");
        assert!(idx.claim_exact(&away, "disk").unwrap());
        assert_eq!(idx.lookup("app").unwrap(), a);
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir(&away).unwrap();
        // An exact claim takes a removed run's name back.
        assert!(idx.claim_exact(&b, "app").unwrap());
        assert_eq!(idx.lookup("app").unwrap(), b);
        // `mnt` is still there, but says nothing about whether `vm` was removed.
        assert_eq!(idx.claim(&c, "disk").unwrap().0, "disk-2");
        assert_eq!(idx.lookup("disk").unwrap(), away);
        let e = idx.claim_exact(&c, "disk").unwrap_err();
        assert!(format!("{e}").contains("not there"), "{e}");
    }

    /// A word names one directory: an index name, or a dev state dir's own name — dotted ones
    /// included, as a workspace called `.dotfiles` gets — and is refused when it is both, for
    /// two different environments.
    #[test]
    fn resolve_takes_names_and_dir_names_and_refuses_ambiguity() {
        let t = tmp("resolve");
        let idx = Index::at(t.0.join("names"));
        let dev = t.0.join("dev");
        let (a, b, dot) = (
            dev.join("app-1111"),
            dev.join("app-1111-2222"),
            dev.join(".dotfiles-3333"),
        );
        for d in [&a, &b, &dot] {
            std::fs::create_dir_all(d).unwrap();
        }
        idx.claim_exact(&a, "app").unwrap();
        idx.claim_exact(&b, "app-1111").unwrap();
        assert_eq!(resolve_in(&idx, &dev, "app").unwrap(), Some(a.clone()));
        assert_eq!(
            resolve_in(&idx, &dev, "app-1111-2222").unwrap(),
            Some(b.clone())
        );
        assert_eq!(
            resolve_in(&idx, &dev, ".dotfiles-3333").unwrap(),
            Some(dot.clone())
        );
        let e = resolve_in(&idx, &dev, "app-1111").unwrap_err();
        assert!(format!("{e}").contains("ambiguous"), "{e}");
        for nothing in ["nope", ".", "..", "", "app-1111/", "./app-1111-2222", "x/y"] {
            assert_eq!(
                resolve_in(&idx, &dev, nothing).unwrap(),
                None,
                "{nothing:?}"
            );
        }
        assert!(is_dir_name("-leading") && is_dir_name(".dotfiles-3333"));
    }

    /// A recipe keeps every byte of its arguments and paths, UTF-8 or not.
    #[test]
    fn a_recipe_round_trips_non_utf8_bytes() {
        use std::os::unix::ffi::OsStringExt;
        let odd = OsString::from_vec(b"Docker\xfffile".to_vec());
        let recipe = Recipe {
            args: vec!["run".into(), "-f".into(), odd.clone()],
            cwd: PathBuf::from(odd.clone()),
            project_dir: "/home/me/shop".into(),
        };
        let json = serde_json::to_string(&recipe).unwrap();
        assert!(json.contains(r#""run""#), "{json}");
        let back: Recipe = serde_json::from_str(&json).unwrap();
        assert_eq!(back, recipe);
        assert_eq!(back.args[2], odd);
    }

    #[test]
    fn a_dangling_link_still_reads_back() {
        let t = tmp("dangling");
        let idx = Index::at(t.0.join("names"));
        let gone = t.0.join("gone");
        idx.claim(&gone, "ghost").unwrap();
        assert_eq!(idx.lookup("ghost").unwrap(), gone);
    }
}
