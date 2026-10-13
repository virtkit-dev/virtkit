//! Helpers the end-to-end tests (`tests/*.sh`) run on the host, so a test needs nothing of
//! the host but a shell: built in the development VM (`./dev.sh build -p vk-testkit`).
//!
//! `vk-testkit git-repo <src> <repo> <branch>` writes the files under `<src>` as the sole
//! commit of `<branch>` in a new bare repository `<repo>` for git's dumb HTTP transport:
//! loose objects, `HEAD`, `info/refs` and an empty `objects/info/packs`. Served as plain
//! files, it can be cloned. Prints the commit's id. The same files make the same commit.

use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha1::{Digest, Sha1};

fn main() -> std::process::ExitCode {
    match run(&std::env::args_os().skip(1).collect::<Vec<_>>()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // Not `eprintln!`, which panics when the write fails.
            let _ = writeln!(std::io::stderr(), "vk-testkit: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(args: &[std::ffi::OsString]) -> Result<()> {
    match args {
        [cmd, src, repo, branch] if cmd == "git-repo" => {
            let branch = branch.to_str().context("the branch name is not UTF-8")?;
            let commit = git_repo(Path::new(src), Path::new(repo), branch)?;
            writeln!(std::io::stdout(), "{commit}")?;
            Ok(())
        }
        _ => bail!("usage: vk-testkit git-repo <src> <repo> <branch>"),
    }
}

/// Whether git takes `branch` as a branch name of one component: an allowlist narrower than
/// `git check-ref-format`, which is all a test needs.
fn plain_branch(branch: &str) -> bool {
    !branch.is_empty()
        && branch
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && !branch.starts_with(['.', '-'])
        && !branch.ends_with('.')
        && !branch.ends_with(".lock")
        && !branch.contains("..")
}

/// Write the bare repository `repo`, which must not exist, holding the files under `src` as
/// the one commit of `branch`; returns the commit's id. A failure removes what it wrote, as
/// far as it can.
fn git_repo(src: &Path, repo: &Path, branch: &str) -> Result<String> {
    if !plain_branch(branch) {
        bail!("{branch:?}: a branch name of one plain component, please");
    }
    std::fs::create_dir(repo).with_context(|| format!("creating {}", repo.display()))?;
    let written = (|| {
        // Inside `src`, the repository would commit itself as it is being written.
        if repo.canonicalize()?.starts_with(src.canonicalize()?) {
            bail!("{} is inside {}", repo.display(), src.display());
        }
        fill_repo(src, repo, branch)
    })();
    if written.is_err() {
        // Best effort: the error says what went wrong, a leftover only costs the caller disk.
        let _ = std::fs::remove_dir_all(repo);
    }
    written
}

/// [`git_repo`] into the directory `repo` it just made.
fn fill_repo(src: &Path, repo: &Path, branch: &str) -> Result<String> {
    let objects = repo.join("objects");
    // An empty `src` commits the empty tree, as `git commit --allow-empty` would.
    let tree = match write_tree(&objects, src)? {
        Some(id) => id,
        None => write_object(&objects, "tree", b"")?,
    };
    let tree = hex(&tree);
    let commit = write_object(
        &objects,
        "commit",
        format!(
            "tree {tree}\nauthor e2e <e2e@example.invalid> 0 +0000\n\
             committer e2e <e2e@example.invalid> 0 +0000\n\ne2e\n"
        )
        .as_bytes(),
    )?;
    let commit = hex(&commit);
    write_file(
        &repo.join("HEAD"),
        format!("ref: refs/heads/{branch}\n").as_bytes(),
    )?;
    write_file(
        &repo.join("refs/heads").join(branch),
        format!("{commit}\n").as_bytes(),
    )?;
    write_file(
        &repo.join("info/refs"),
        format!("{commit}\trefs/heads/{branch}\n").as_bytes(),
    )?;
    write_file(&objects.join("info/packs"), b"")?;
    Ok(commit)
}

struct Entry {
    name: Vec<u8>,
    mode: &'static str,
    id: [u8; 20],
    dir: bool,
}

/// Write the tree of the directory `dir` and everything under it; returns its id, or `None`
/// for a tree with nothing in it, which `git add` never makes.
fn write_tree(objects: &Path, dir: &Path) -> Result<Option<[u8; 20]>> {
    let mut entries: Vec<Entry> = Vec::new();
    let paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()
        .with_context(|| format!("reading {}", dir.display()))?;
    for path in paths {
        let name = path
            .file_name()
            .context("a directory entry with no name")?
            .as_bytes()
            .to_vec();
        // git refuses a tree naming `.git` (fsck's hasDotgit), whatever its case.
        if name.eq_ignore_ascii_case(b".git") {
            bail!("{}: git does not take a .git in a tree", path.display());
        }
        // The tree is a test's own fixture, so a file swapped for a symlink between this look
        // and the read below is not a case to defend against.
        let meta = std::fs::symlink_metadata(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let (mode, id, dir) = if meta.is_dir() {
            let Some(id) = write_tree(objects, &path)? else {
                continue;
            };
            ("40000", id, true)
        } else if meta.is_file() {
            let bytes =
                std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            // Git looks at the owner's execute bit only.
            let mode = if meta.permissions().mode() & 0o100 != 0 {
                "100755"
            } else {
                "100644"
            };
            (mode, write_object(objects, "blob", &bytes)?, false)
        } else {
            bail!(
                "{}: only files and directories are committed",
                path.display()
            );
        };
        entries.push(Entry {
            name,
            mode,
            id,
            dir,
        });
    }
    if entries.is_empty() {
        return Ok(None);
    }
    // Git orders a tree's entries by name, a directory's as if it ended in `/`.
    let key = |e: &Entry| {
        let mut k = e.name.clone();
        if e.dir {
            k.push(b'/');
        }
        k
    };
    entries.sort_by_key(key);
    let mut body = Vec::new();
    for e in &entries {
        body.extend_from_slice(e.mode.as_bytes());
        body.push(b' ');
        body.extend_from_slice(&e.name);
        body.push(0);
        body.extend_from_slice(&e.id);
    }
    write_object(objects, "tree", &body).map(Some)
}

/// Store `body` as a loose object of `kind`; returns its id.
fn write_object(objects: &Path, kind: &str, body: &[u8]) -> Result<[u8; 20]> {
    let mut object = format!("{kind} {}\0", body.len()).into_bytes();
    object.extend_from_slice(body);
    let id: [u8; 20] = Sha1::digest(&object).into();
    let name = hex(&id);
    let (dir, file) = name.split_at(2);
    let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    zlib.write_all(&object)?;
    write_file(&objects.join(dir).join(file), &zlib.finish()?)?;
    Ok(id)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory, removed when the test ends, passed or not.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Scratch {
            let dir =
                std::env::temp_dir().join(format!("vk-testkit-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A commit's ids are git's: these are what `git hash-object`, `git mktree` and
    /// `git commit-tree` give for the same content.
    #[test]
    fn objects_are_named_as_git_names_them() {
        let dir = Scratch::new("objects");
        // `printf 'hi\n' | git hash-object --stdin`
        assert_eq!(
            hex(&write_object(&dir.0, "blob", b"hi\n").unwrap()),
            "45b983be36b73c0788dc9cbcb76cbb80fc7bb057"
        );
        // The empty tree.
        assert_eq!(
            hex(&write_object(&dir.0, "tree", b"").unwrap()),
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
        );
        let stored =
            std::fs::read(dir.0.join("45/b983be36b73c0788dc9cbcb76cbb80fc7bb057")).unwrap();
        let mut plain = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::ZlibDecoder::new(&stored[..]), &mut plain)
            .unwrap();
        assert_eq!(plain, b"blob 3\0hi\n");
    }

    /// A directory sorts as if its name ended in `/`, so `a.txt` comes before the directory
    /// `a`: the commit is the one git makes of the same files. The repository gets its refs,
    /// and the same files make the same commit.
    #[test]
    fn a_repository_holds_one_commit_of_the_files() {
        let dir = Scratch::new("repo");
        let src = dir.0.join("src");
        std::fs::create_dir_all(src.join("a")).unwrap();
        std::fs::create_dir_all(src.join("empty")).unwrap();
        std::fs::write(src.join("a/x"), b"x\n").unwrap();
        std::fs::write(src.join("a.txt"), b"t\n").unwrap();
        let commit = git_repo(&src, &dir.0.join("one.git"), "main").unwrap();
        // `git commit` of a/x and a.txt (0644), author and committer
        // `e2e <e2e@example.invalid>` at `@0 +0000`, message `e2e`: an empty directory is
        // not committed.
        assert_eq!(commit, "d89b6ef9e56cb0b0a725ac7fe84b81f71ad6d29f");
        let again = git_repo(&src, &dir.0.join("two.git"), "main").unwrap();
        assert_eq!(commit, again);
        let repo = dir.0.join("one.git");
        assert_eq!(
            std::fs::read_to_string(repo.join("info/refs")).unwrap(),
            format!("{commit}\trefs/heads/main\n")
        );
        assert_eq!(
            std::fs::read_to_string(repo.join("HEAD")).unwrap(),
            "ref: refs/heads/main\n"
        );
        assert!(
            git_repo(&src, &repo, "main").is_err(),
            "an existing repository"
        );
    }

    /// A file its owner can execute is committed with mode 100755; one only others can
    /// execute is not, as git decides.
    #[test]
    fn an_executable_keeps_its_mode() {
        let dir = Scratch::new("exec");
        let src = dir.0.join("src");
        std::fs::create_dir_all(&src).unwrap();
        let script = src.join("run");
        std::fs::write(&script, b"x\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o744)).unwrap();
        // Executable by its group only: git commits that as a plain file.
        let shared = src.join("shared");
        std::fs::write(&shared, b"x\n").unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o654)).unwrap();
        let tree = write_tree(&dir.0.join("objects"), &src).unwrap().unwrap();
        let blob = write_object(&dir.0.join("scratch"), "blob", b"x\n").unwrap();
        let mut body = b"100755 run\0".to_vec();
        body.extend_from_slice(&blob);
        body.extend_from_slice(b"100644 shared\0");
        body.extend_from_slice(&blob);
        assert_eq!(
            tree,
            write_object(&dir.0.join("scratch"), "tree", &body).unwrap()
        );
    }

    /// What git would refuse fails the write, and leaves nothing behind.
    #[test]
    fn what_git_refuses_is_refused() {
        let dir = Scratch::new("refuse");
        let src = dir.0.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("f"), b"f\n").unwrap();
        for bad in [
            "", "a/b", ".hidden", "-x", "a..b", "x.lock", "a~1", "a^", "a:b", "a?", "a*", "a[",
            "@{", "end.", "a b",
        ] {
            assert!(!plain_branch(bad), "{bad:?}");
        }
        assert!(plain_branch("release-1.2_x"));
        let repo = dir.0.join("bad.git");
        assert!(git_repo(&src, &repo, "a/b").is_err());
        assert!(!repo.exists());
        std::fs::create_dir_all(src.join(".GIT")).unwrap();
        std::fs::write(src.join(".GIT/config"), b"").unwrap();
        assert!(git_repo(&src, &repo, "main").is_err());
        assert!(!repo.exists(), "a failed write leaves no repository");
        std::fs::remove_dir_all(src.join(".GIT")).unwrap();
        let inside = src.join("in.git");
        assert!(git_repo(&src, &inside, "main").is_err());
        assert!(!inside.exists());
    }
}
