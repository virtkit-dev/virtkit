//! VM names: the short handle `vk list` prints and every VM command takes.
//!
//! The index is a directory of symlinks, `$XDG_STATE_HOME/virtkit/names/<name>` → the VM's
//! state dir. Claiming a name is `symlink(2)`, which fails when the name is taken, so two
//! claims never share one; a `.lock` beside the links serializes claims so one directory never
//! gets two names. The index is the only record: what a directory is called is found by
//! reading the links back, which is a few dozen `readlink`s.
//!
//! A name is chosen once and kept: computing it from a path at lookup time would rename the
//! first `app` the moment a second one appeared. A collision adds `-2`, `-3`, … to the base.

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

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

/// Where `vk run --name` and a detached run keep their state dirs.
pub fn run_base() -> Result<PathBuf> {
    Ok(state_base()?.join("run"))
}

/// Whether `name` is a VM name: `[a-z0-9][a-z0-9._-]*`, at most [`MAX_LEN`], not all digits
/// (which is a pid).
pub fn validate(name: &str) -> Result<()> {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > MAX_LEN {
        bail!("a VM name has 1 to {MAX_LEN} characters: {name:?}");
    }
    if !(b[0].is_ascii_lowercase() || b[0].is_ascii_digit()) {
        bail!("a VM name starts with a lowercase letter or a digit: {name:?}");
    }
    if !b
        .iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-'))
    {
        bail!("a VM name holds only a-z, 0-9, '.', '_' and '-': {name:?}");
    }
    if b.iter().all(u8::is_ascii_digit) {
        bail!("a VM name is not all digits, which reads as a pid: {name:?}");
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

/// The state dir a name stands for: a name from the index, else the directory name a dev
/// environment's state dir has under the dev base (its name before names existed). `None`
/// when the word names nothing.
pub fn resolve(name: &str) -> Result<Option<PathBuf>> {
    if let Some(dir) = Index::open()?.lookup(name) {
        return Ok(Some(dir));
    }
    if is_dir_name(name) {
        let dir = crate::dev::plan::dev_state_base()?.join(name);
        // Only a directory of its own, never a link leading elsewhere.
        if std::fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir()) {
            return Ok(Some(dir));
        }
    }
    Ok(None)
}

/// Whether `word` could be a dev state dir's own name: `[A-Za-z0-9._-]`, not starting with
/// `.` or `-`.
fn is_dir_name(word: &str) -> bool {
    !word.is_empty()
        && !word.starts_with(['.', '-'])
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The name index.
pub struct Index {
    dir: PathBuf,
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
        Index { dir: dir.into() }
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
    pub fn claim(&self, dir: &Path, base: &str) -> Result<String> {
        let _lock = self.lock()?;
        self.claim_locked(dir, base)
    }

    /// [`Index::claim`] with the lock already held.
    pub fn claim_locked(&self, dir: &Path, base: &str) -> Result<String> {
        if let Some(name) = self.name_of(dir) {
            return Ok(name);
        }
        self.forget_removed();
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
                return Ok(name);
            }
        }
        unreachable!("u32 suffixes exhausted")
    }

    /// Forget every name whose state dir was removed: the directory is gone while the one
    /// that held it is still there. A target whose parent is missing too is left alone —
    /// that is a tree not in view from here (an unmounted disk, another mount namespace),
    /// which says nothing about the VM. Call with the lock held.
    fn forget_removed(&self) {
        for (name, target) in self.all() {
            if removed(&target) {
                let _ = std::fs::remove_file(self.dir.join(name));
            }
        }
    }

    /// [`Index::forget_removed`] over `names`, as read before, for a pass that must end by
    /// `deadline`, if it has one: how many were forgotten, and whether it stopped early. The lock — and
    /// with it the index directory — is taken only once there is a name to forget, and
    /// each is looked at again under it.
    pub fn forget_removed_until(
        &self,
        names: &[(String, PathBuf)],
        deadline: Option<std::time::Instant>,
    ) -> (usize, bool) {
        let mut lock = None;
        let mut forgotten = 0;
        for (name, target) in names {
            if deadline.is_some_and(|d| std::time::Instant::now() >= d) {
                return (forgotten, true);
            }
            if !removed(target) {
                continue;
            }
            if lock.is_none() {
                match self.lock() {
                    Ok(held) => lock = Some(held),
                    Err(_) => return (forgotten, false),
                }
            }
            // Under the lock: still the same link, to a directory still gone.
            if self.lookup(name).as_ref() == Some(target)
                && removed(target)
                && std::fs::remove_file(self.dir.join(name)).is_ok()
            {
                forgotten += 1;
            }
        }
        (forgotten, false)
    }

    /// Give `dir` exactly `name`. Fine when `name` already names `dir`; an error when it names
    /// another directory, or when `dir` already has another name.
    pub fn claim_exact(&self, dir: &Path, name: &str) -> Result<()> {
        validate(name)?;
        let _lock = self.lock()?;
        let canonical = crate::vms::canonical(dir);
        if let Some(target) = self.lookup(name) {
            if target == canonical || target == dir {
                return Ok(());
            }
            bail!(
                "the name {name} is taken by {} — `vk start {name}`, or `vk delete {name}` first",
                target.display()
            );
        }
        if let Some(other) = self.name_of(dir) {
            bail!(
                "{} is already named {other} — `vk rename {other} {name}`",
                dir.display()
            );
        }
        if !self.link(name, dir)? {
            bail!("the name {name} was just taken");
        }
        Ok(())
    }

    /// Link `name` to `dir`; `false` when the name is taken.
    fn link(&self, name: &str, dir: &Path) -> Result<bool> {
        let target = crate::vms::canonical(dir);
        match std::os::unix::fs::symlink(&target, self.dir.join(name)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(e).with_context(|| format!("naming {} {name}", target.display())),
        }
    }

    /// Rename `old` to `new`.
    pub fn rename(&self, old: &str, new: &str) -> Result<()> {
        validate(new)?;
        let _lock = self.lock()?;
        let Some(dir) = self.lookup(old) else {
            bail!("no VM is named {old}");
        };
        if old == new {
            return Ok(());
        }
        if !self.link(new, &dir)? {
            bail!("the name {new} is taken");
        }
        std::fs::remove_file(self.dir.join(old))
            .with_context(|| format!("removing the name {old}"))?;
        Ok(())
    }

    /// Forget every name of `dir`.
    pub fn release(&self, dir: &Path) {
        let canonical = crate::vms::canonical(dir);
        for (name, target) in self.all() {
            if target == dir || target == canonical {
                let _ = std::fs::remove_file(self.dir.join(name));
            }
        }
    }

    /// Forget `name`, whatever it points to.
    pub fn remove(&self, name: &str) {
        if validate(name).is_ok() {
            let _ = std::fs::remove_file(self.dir.join(name));
        }
    }
}

/// Whether the directory `target` was removed from a parent that is still there.
fn removed(target: &Path) -> bool {
    let gone = |p: &Path| matches!(std::fs::symlink_metadata(p), Err(e) if e.kind() == std::io::ErrorKind::NotFound);
    gone(target) && target.parent().is_some_and(|parent| parent.is_dir())
}

/// The recipe this process's `vk run` leaves in its state dir once the dir is its own.
static PENDING: std::sync::OnceLock<(PathBuf, Recipe)> = std::sync::OnceLock::new();

/// Have [`write_pending_recipe`] write `recipe` into `dir` when this process's run takes it.
/// Set before the run starts — before `--detach` forks — while the command line and the
/// working directory are still the caller's.
pub fn set_pending_recipe(dir: &Path, recipe: Recipe) {
    let _ = PENDING.set((crate::vms::canonical(dir), recipe));
}

/// Write the recipe set for `dir`, if one was: called by the run once it holds the dir's
/// lock, so only the run that owns a state dir writes its recipe.
pub fn write_pending_recipe(dir: &Path) -> Result<()> {
    match PENDING.get() {
        Some((for_dir, recipe)) if *for_dir == crate::vms::canonical(dir) => recipe.write(dir),
        _ => Ok(()),
    }
}

/// What `vk start` replays to run a stopped `vk run` again: the command line it was
/// launched with, where, and the project it is about. Kept as `run.json` in the state dir.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Recipe {
    /// `vk`'s arguments, the program name left out
    pub args: Vec<String>,
    /// the directory it was launched from
    pub cwd: PathBuf,
    /// `--workspace`, then `--workdir`, then `cwd`
    pub project_dir: PathBuf,
}

/// The recipe's file in a state dir.
pub const RECIPE: &str = "run.json";

impl Recipe {
    /// This process's command line, working directory and `project` (default: the working
    /// directory).
    pub fn now(project: Option<PathBuf>) -> Result<Recipe> {
        let cwd = std::env::current_dir().context("resolving the current directory")?;
        Ok(Recipe {
            args: std::env::args_os()
                .skip(1)
                .map(|a| a.to_string_lossy().into_owned())
                .collect(),
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

    /// The recipe in `dir`, `None` when there is none.
    pub fn read(dir: &Path) -> Result<Option<Recipe>> {
        let path = dir.join(RECIPE);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes)
                    .with_context(|| format!("reading {}", path.display()))?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// The arguments that run it again in the background as `name`, in `dir`: the recorded
    /// ones with `--detach --state-dir DIR --name NAME` put before the guest command's `--`,
    /// where they override any the recording holds (`vk run` takes the last of each).
    pub fn replay_args(&self, dir: &Path, name: &str) -> Vec<String> {
        let ours = [
            "--detach".to_string(),
            "--state-dir".to_string(),
            dir.to_string_lossy().into_owned(),
            "--name".to_string(),
            name.to_string(),
        ];
        let mut args = self.args.clone();
        let run = args.iter().position(|a| a == "run").unwrap_or(0);
        let at = args
            .iter()
            .skip(run)
            .position(|a| a == "--")
            .map_or(args.len(), |i| run + i);
        args.splice(at..at, ours);
        args
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
        assert_eq!(idx.claim(&a, "app").unwrap(), "app");
        assert_eq!(idx.claim(&b, "app").unwrap(), "app-2");
        assert_eq!(idx.claim(&c, "app").unwrap(), "app-3");
        // Asked again, a directory keeps the name it has, whatever the base.
        assert_eq!(idx.claim(&b, "other").unwrap(), "app-2");
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
        let second = idx.claim(&t.0.join("2"), &base).unwrap();
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
        idx.claim_exact(&a, "x").unwrap();
        idx.claim_exact(&a, "x").unwrap();
        assert!(idx.claim_exact(&b, "x").is_err());
        assert!(idx.claim_exact(&a, "y").is_err());
        assert!(idx.claim_exact(&b, "Bad").is_err());
    }

    #[test]
    fn rename_moves_the_link_and_release_forgets_it() {
        let t = tmp("rename");
        let idx = Index::at(t.0.join("names"));
        let (a, b) = (t.0.join("a"), t.0.join("b"));
        for d in [&a, &b] {
            std::fs::create_dir(d).unwrap();
        }
        idx.claim(&a, "one").unwrap();
        idx.claim(&b, "two").unwrap();
        assert!(idx.rename("one", "two").is_err());
        assert!(idx.rename("nope", "three").is_err());
        idx.rename("one", "uno").unwrap();
        assert_eq!(idx.lookup("one"), None);
        assert_eq!(idx.lookup("uno").unwrap(), a);
        idx.release(&a);
        assert_eq!(idx.name_of(&a), None);
        assert_eq!(idx.lookup("two").unwrap(), b);
    }

    /// A claim forgets the names of directories that were removed, and so reuses them; a
    /// name whose target's parent is not there either is not in view, and is kept.
    #[test]
    fn a_claim_forgets_removed_directories_but_not_ones_out_of_view() {
        let t = tmp("removed");
        let idx = Index::at(t.0.join("names"));
        let (a, b) = (t.0.join("a"), t.0.join("b"));
        std::fs::create_dir(&a).unwrap();
        assert_eq!(idx.claim(&a, "app").unwrap(), "app");
        let away = t.0.join("unmounted/state");
        assert_eq!(idx.claim(&away, "elsewhere").unwrap(), "elsewhere");
        std::fs::remove_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        assert_eq!(idx.claim(&b, "app").unwrap(), "app");
        assert_eq!(idx.lookup("app").unwrap(), b);
        assert_eq!(idx.lookup("elsewhere").unwrap(), away);
    }

    /// A bounded pass forgets what was removed, creates nothing when there is nothing to
    /// forget, and stops at its deadline.
    #[test]
    fn a_bounded_pass_forgets_removed_names_and_stops_at_its_deadline() {
        let t = tmp("bounded");
        let idx = Index::at(t.0.join("names"));
        let later = || Some(std::time::Instant::now() + std::time::Duration::from_secs(60));
        assert_eq!(idx.forget_removed_until(&idx.all(), later()), (0, false));
        assert!(!t.0.join("names").exists(), "nothing to do writes nothing");
        let (a, b) = (t.0.join("a"), t.0.join("b"));
        for d in [&a, &b] {
            std::fs::create_dir(d).unwrap();
        }
        idx.claim(&a, "gone").unwrap();
        idx.claim(&b, "kept").unwrap();
        std::fs::remove_dir(&a).unwrap();
        let names = idx.all();
        assert_eq!(
            idx.forget_removed_until(&names, Some(std::time::Instant::now())),
            (0, true),
            "out of time before the first"
        );
        assert_eq!(idx.forget_removed_until(&names, None), (1, false));
        assert_eq!(idx.lookup("gone"), None);
        assert_eq!(idx.lookup("kept").unwrap(), b);
    }

    #[test]
    fn a_replay_puts_its_flags_before_the_guest_command() {
        let recipe = |args: &[&str]| Recipe {
            args: args.iter().map(|a| a.to_string()).collect(),
            cwd: "/w".into(),
            project_dir: "/w".into(),
        };
        let dir = Path::new("/s/x");
        let ours = ["--detach", "--state-dir", "/s/x", "--name", "x"];
        let got = recipe(&["--config", "c", "run", "alpine", "--", "sh", "-c", "--"])
            .replay_args(dir, "x");
        let mut want = vec!["--config", "c", "run", "alpine"];
        want.extend(ours);
        want.extend(["--", "sh", "-c", "--"]);
        assert_eq!(got, want);
        let got = recipe(&["run", "alpine"]).replay_args(dir, "x");
        let mut want = vec!["run", "alpine"];
        want.extend(ours);
        assert_eq!(got, want);
    }

    #[test]
    fn a_recipe_reads_back_what_was_written() {
        let t = tmp("recipe");
        assert_eq!(Recipe::read(&t.0).unwrap(), None);
        let r = Recipe {
            args: vec!["run".into(), "alpine".into()],
            cwd: "/w".into(),
            project_dir: "/p".into(),
        };
        r.write(&t.0).unwrap();
        assert_eq!(Recipe::read(&t.0).unwrap(), Some(r));
    }

    #[test]
    fn a_dangling_link_still_reads_back_and_can_be_removed() {
        let t = tmp("dangling");
        let idx = Index::at(t.0.join("names"));
        let gone = t.0.join("gone");
        idx.claim(&gone, "ghost").unwrap();
        assert_eq!(idx.lookup("ghost").unwrap(), gone);
        idx.remove("ghost");
        assert!(idx.all().is_empty());
    }
}
