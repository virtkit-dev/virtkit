//! The CI tools definitions the hub holds for its nodes, in `<data_dir>/tools/`, each a tar
//! named by its sha256 beside its row in the database.
//!
//! **A definition, not binaries.** A definition is a build context: a directory holding a
//! `Dockerfile` whose `tools` stage has the tools at its root, and the files it copies. A node
//! builds it with `vk build` in microVMs and installs what the stage holds; the hub never
//! builds or runs anything of it.
//!
//! **Packed reproducibly.** The same tree packs to the same bytes, so its sha256 names the
//! definition whatever the clock, the umask or the order the filesystem lists names in:
//! entries in byte order of their paths, each directory before what it holds, owner 0,
//! mtime 0, mode `0755` for a directory and for a file any execute bit is set on, `0644` for
//! any other file. Only regular files and directories are taken, at most
//! [`vk_hub_proto::MAX_TOOLS_DEFINITION`] bytes packed: a symlink, a device or a FIFO is
//! refused rather than followed or packed, and so is a file with more than one hard link.
//!
//! **Read without following anything.** The hub reads the tree as its own user, who can read
//! its TLS key and database: a name swapped for a symlink mid-walk would pack one of those
//! into what every node downloads. So the tree is walked from descriptors, each name opened
//! `O_NOFOLLOW` in the directory already open, and what was opened is checked again from its
//! descriptor. A hard link is followed by no flag, so a file with another name is refused.

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use vk_hub_proto::MAX_TOOLS_DEFINITION;

use crate::server::Hub;
use crate::store::{Tools, ToolsRow};

/// The most entries a definition holds: a Dockerfile and a few files, not a source tree.
const MAX_ENTRIES: usize = 4096;

/// The deepest a definition's directories nest.
const MAX_DEPTH: usize = 32;

/// The file at a definition's root that a node builds.
pub const DOCKERFILE: &str = "Dockerfile";

/// Where definition `sha256`'s tar is.
pub fn path(dir: &Path, sha256: &str) -> PathBuf {
    dir.join(sha256)
}

/// A packed definition: its tar, its sha256 in hex, and how many files it holds.
#[derive(Debug)]
pub struct Packed {
    pub tar: Vec<u8>,
    pub sha256: String,
    pub files: u32,
}

/// Pack the build context at `dir` into a definition. Follow `dir` itself if it is a symlink
/// the operator named, but refuse symlinks inside it.
pub fn pack(dir: &Path) -> Result<Packed> {
    let root = vk_fs::open_dir(dir).with_context(|| format!("opening {}", dir.display()))?;
    let mut entries = Vec::new();
    walk(root.as_fd(), Path::new(""), 0, &mut entries, &mut 0)?;
    finish(&entries, &dir.display().to_string())
}

/// `entries`, in the order [`walk`] gives them, as a definition, refused without a
/// [`DOCKERFILE`] at its root or past [`MAX_TOOLS_DEFINITION`] packed. `shown` names it.
fn finish(entries: &[Entry], shown: &str) -> Result<Packed> {
    if !entries
        .iter()
        .any(|e| e.path.as_os_str() == DOCKERFILE && e.data.is_some())
    {
        bail!(
            "{shown} has no {DOCKERFILE} at its root: a tools definition is a build context \
             whose {DOCKERFILE} has a `tools` stage"
        );
    }
    let packed = write_tar(entries)?;
    if packed.tar.len() as u64 > MAX_TOOLS_DEFINITION {
        bail!(
            "{shown} packs to {} bytes, past the {MAX_TOOLS_DEFINITION} a tools definition may be",
            packed.tar.len()
        );
    }
    Ok(packed)
}

/// Pack the build context `archive` holds, a tar or a gzipped tar as an operator uploads one,
/// into a definition: by the rules and in the order of [`pack`], so a context packs the same
/// whether added from a directory or uploaded. Its entries are regular files and directories at
/// plain relative paths, each once, the directories a path implies taken as there; anything
/// else is refused. A context whose root holds one directory alone, with the [`DOCKERFILE`] in
/// it, is that directory's.
pub fn pack_archive(archive: &[u8]) -> Result<Packed> {
    // What a tar of the most a definition may hold can come to: its headers, padding and
    // long names. Past it, a gzip is refused rather than inflated on.
    const MAX_TAR: u64 = MAX_TOOLS_DEFINITION.saturating_mul(2);
    let reader: Box<dyn Read + '_> = if archive.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::read::GzDecoder::new(archive))
    } else {
        Box::new(archive)
    };
    let mut limited = reader.take(MAX_TAR.saturating_add(1));
    let mut tar = Vec::new();
    limited
        .read_to_end(&mut tar)
        .context("reading the archive: it is neither a tar nor a gzipped tar")?;
    if tar.len() as u64 > MAX_TAR {
        bail!("the archive holds more than a tools definition may");
    }
    let mut files: std::collections::BTreeMap<Vec<OsString>, Entry> = Default::default();
    let mut taken = 0u64;
    let mut archive = tar::Archive::new(tar.as_slice());
    for entry in archive.entries().context("reading the archive")? {
        let mut entry = entry.context("reading the archive")?;
        let kind = entry.header().entry_type();
        let raw = entry
            .path()
            .context("reading a name in the archive")?
            .into_owned();
        let mut parts = Vec::new();
        for c in raw.components() {
            match c {
                std::path::Component::Normal(n) => parts.push(n.to_os_string()),
                std::path::Component::CurDir => {}
                _ => bail!(
                    "{} is not a plain relative path",
                    vk_hub_proto::display_safe(&raw.display().to_string())
                ),
            }
        }
        let path: PathBuf = parts.iter().collect();
        let shown = || vk_hub_proto::display_safe(&path.display().to_string());
        if parts.len() > MAX_DEPTH.saturating_add(1) {
            bail!("{} nests deeper than {MAX_DEPTH} directories", shown());
        }
        let found = match kind {
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                let left = MAX_TOOLS_DEFINITION.saturating_sub(taken);
                if entry.size() > left {
                    bail!(
                        "the context holds more than the {MAX_TOOLS_DEFINITION} bytes a \
                         definition may"
                    );
                }
                let mut data = Vec::new();
                entry
                    .read_to_end(&mut data)
                    .with_context(|| format!("reading {}", shown()))?;
                taken = taken.saturating_add(data.len() as u64);
                let executable = entry.header().mode().is_ok_and(|m| m & 0o111 != 0);
                Entry {
                    path: path.clone(),
                    data: Some(data),
                    executable,
                }
            }
            tar::EntryType::Directory => Entry {
                path: path.clone(),
                data: None,
                executable: true,
            },
            // Metadata of the archive's own, not entries of the context.
            tar::EntryType::XGlobalHeader | tar::EntryType::XHeader => continue,
            tar::EntryType::Symlink | tar::EntryType::Link => bail!(
                "{} is a link: a tools definition holds regular files and directories only",
                shown()
            ),
            _ => bail!("{} is neither a regular file nor a directory", shown()),
        };
        if parts.is_empty() {
            if found.data.is_some() {
                bail!("the archive holds a file with no name");
            }
            continue;
        }
        if files.contains_key(&parts) {
            bail!("{} is in the archive twice", shown());
        }
        files.insert(parts, found);
        if files.len() > MAX_ENTRIES {
            bail!("it holds more than {MAX_ENTRIES} entries");
        }
    }
    // The directories the paths imply, and no file where a directory must be.
    let mut implied = Vec::new();
    for parts in files.keys() {
        for depth in 1..parts.len() {
            let dir = &parts[..depth];
            match files.get(dir) {
                Some(e) if e.data.is_some() => bail!(
                    "{} is a file and a directory in the archive",
                    vk_hub_proto::display_safe(
                        &dir.iter().collect::<PathBuf>().display().to_string()
                    )
                ),
                Some(_) => {}
                None => implied.push(dir.to_vec()),
            }
        }
    }
    for parts in implied {
        let path = parts.iter().collect();
        files.entry(parts).or_insert(Entry {
            path,
            data: None,
            executable: true,
        });
    }
    if files.len() > MAX_ENTRIES {
        bail!("it holds more than {MAX_ENTRIES} entries");
    }
    // One directory alone at the root, holding the Dockerfile: the context is in it.
    let top: Vec<&Vec<OsString>> = files.keys().filter(|p| p.len() == 1).collect();
    if let [only] = top.as_slice()
        && files[*only].data.is_none()
    {
        let inner = vec![only[0].clone(), OsString::from(DOCKERFILE)];
        if files.get(&inner).is_some_and(|e| e.data.is_some()) {
            files = files
                .into_iter()
                .filter(|(p, _)| p.len() > 1)
                .map(|(p, mut e)| {
                    let parts = p[1..].to_vec();
                    e.path = parts.iter().collect();
                    (parts, e)
                })
                .collect();
        }
    }
    // Ordered by component, byte by byte: each directory before what it holds, its entries in
    // byte order, as `walk` lists a directory.
    let mut entries: Vec<(Vec<OsString>, Entry)> = files.into_iter().collect();
    entries.sort_by(|a, b| {
        let a = a.0.iter().map(|c| c.as_bytes());
        let b = b.0.iter().map(|c| c.as_bytes());
        a.cmp(b)
    });
    let entries: Vec<Entry> = entries.into_iter().map(|(_, e)| e).collect();
    finish(&entries, "the archive")
}

/// `entries`, in the order given, as a definition's tar.
fn write_tar(entries: &[Entry]) -> Result<Packed> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut files = 0u32;
    for e in entries {
        let mut header = tar::Header::new_gnu();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        match &e.data {
            Some(data) => {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_mode(if e.executable { 0o755 } else { 0o644 });
                header.set_size(data.len() as u64);
                builder
                    .append_data(&mut header, &e.path, data.as_slice())
                    .with_context(|| format!("packing {}", e.path.display()))?;
                files = files.saturating_add(1);
            }
            None => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_mode(0o755);
                header.set_size(0);
                builder
                    .append_data(&mut header, &e.path, std::io::empty())
                    .with_context(|| format!("packing {}", e.path.display()))?;
            }
        }
    }
    let tar = builder.into_inner().context("finishing the tar")?;
    let sha256 = vk_hub_proto::to_hex(&Sha256::digest(&tar));
    Ok(Packed { tar, sha256, files })
}

/// The definition built into the hub, `vk-hub/ci-tools/`: its files, in byte order, as
/// [`pack`] would find them there.
const BUILTIN_FILES: [(&str, &[u8]); 3] = [
    ("Dockerfile", include_bytes!("../ci-tools/Dockerfile")),
    ("flake.lock", include_bytes!("../ci-tools/flake.lock")),
    ("flake.nix", include_bytes!("../ci-tools/flake.nix")),
];

/// The tool versions the built-in definition's label names, by the `ARG` that holds each.
const BUILTIN_VERSIONS: [(&str, &str); 2] = [("git", "GIT_VERSION"), ("lfs", "GIT_LFS_VERSION")];

/// The definition built into the hub: packed as `vk-hub tools add vk-hub/ci-tools` packs it,
/// and its label, the versions of the tools it builds.
pub struct Builtin {
    pub packed: Packed,
    pub version: String,
}

/// The built-in definition, packed once.
pub fn builtin() -> &'static Builtin {
    static BUILTIN: std::sync::OnceLock<Builtin> = std::sync::OnceLock::new();
    BUILTIN.get_or_init(|| {
        let entries: Vec<Entry> = BUILTIN_FILES
            .iter()
            .map(|(name, data)| Entry {
                path: PathBuf::from(name),
                data: Some(data.to_vec()),
                executable: false,
            })
            .collect();
        // Both are checked by the tests: the files are the hub's own.
        let packed = write_tar(&entries).expect("the built-in tools definition packs");
        let dockerfile = std::str::from_utf8(BUILTIN_FILES[0].1).unwrap_or_default();
        let version = builtin_version(dockerfile).expect("the built-in tools are labelled");
        Builtin { packed, version }
    })
}

/// The label of a definition whose Dockerfile is `dockerfile`: each tool of
/// [`BUILTIN_VERSIONS`] and the version its `ARG` gives, e.g. `git-2.56.0-lfs-3.8.0`.
fn builtin_version(dockerfile: &str) -> Result<String> {
    let mut parts = Vec::new();
    for (tool, arg) in BUILTIN_VERSIONS {
        let prefix = format!("ARG {arg}=");
        let Some(version) = dockerfile
            .lines()
            .find_map(|l| l.trim().strip_prefix(&prefix))
        else {
            bail!("the Dockerfile has no {prefix}");
        };
        parts.push(format!("{tool}-{}", version.trim()));
    }
    let version = parts.join("-");
    crate::releases::check_version(&version)?;
    Ok(version)
}

/// One entry of a definition: a file with its contents, or a directory.
struct Entry {
    path: PathBuf,
    /// `None` for a directory.
    data: Option<Vec<u8>>,
    executable: bool,
}

/// Add what the directory `dir`, at `rel` in the definition, holds to `out`, in byte order,
/// each directory before its contents. `taken` counts the bytes of file contents taken so far.
fn walk(
    dir: BorrowedFd<'_>,
    rel: &Path,
    depth: usize,
    out: &mut Vec<Entry>,
    taken: &mut u64,
) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!(
            "{} nests deeper than {MAX_DEPTH} directories",
            rel.display()
        );
    }
    // The directory already open, listed through its descriptor rather than by its path.
    let listed = std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))
        .with_context(|| format!("listing {}", shown(rel)))?;
    let mut names: Vec<OsString> = listed
        .map(|e| e.map(|e| e.file_name()))
        .collect::<std::io::Result<_>>()
        .with_context(|| format!("listing {}", shown(rel)))?;
    names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    for name in names {
        let path = rel.join(&name);
        if out.len() >= MAX_ENTRIES {
            bail!("it holds more than {MAX_ENTRIES} entries");
        }
        let st = stat_at(dir, &name).with_context(|| format!("reading {}", path.display()))?;
        match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                let sub = vk_fs::open_dir_in(dir, &name)
                    .with_context(|| format!("opening {}", path.display()))?;
                out.push(Entry {
                    path: path.clone(),
                    data: None,
                    executable: true,
                });
                walk(sub.as_fd(), &path, depth.saturating_add(1), out, taken)?;
            }
            libc::S_IFREG => {
                let (data, executable) = read_file_at(dir, &name, *taken)
                    .with_context(|| format!("reading {}", path.display()))?;
                *taken = taken.saturating_add(data.len() as u64);
                out.push(Entry {
                    path,
                    data: Some(data),
                    executable,
                });
            }
            libc::S_IFLNK => bail!(
                "{} is a symlink: a tools definition holds regular files and directories only",
                path.display()
            ),
            _ => bail!(
                "{} is neither a regular file nor a directory",
                path.display()
            ),
        }
    }
    Ok(())
}

fn shown(rel: &Path) -> String {
    if rel.as_os_str().is_empty() {
        "the context".to_string()
    } else {
        rel.display().to_string()
    }
}

/// `name` in `dir`, not followed.
fn stat_at(dir: BorrowedFd<'_>, name: &OsStr) -> Result<libc::stat> {
    let c = std::ffi::CString::new(name.as_bytes()).context("a name holds a NUL")?;
    // SAFETY: `stat` is plain old data, for which all-zero bytes are a valid value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is live, the name NUL-terminated, and `st` writable.
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            c.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(st)
}

/// Read regular file `name` in `dir` without following symlinks, and return its contents and
/// whether any execute bit is set. Refuse multiple hard links or contents that, with `taken`,
/// exceed the limit.
fn read_file_at(dir: BorrowedFd<'_>, name: &OsStr, taken: u64) -> Result<(Vec<u8>, bool)> {
    let c = std::ffi::CString::new(name.as_bytes()).context("a name holds a NUL")?;
    // Non-blocking, so a FIFO swapped in opens at once, to be refused as not a regular file.
    // SAFETY: the descriptor is live and the name NUL-terminated; the result is owned below.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: `fd` is a fresh descriptor this call owns.
    let file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let meta = file.metadata()?;
    if !meta.is_file() {
        bail!("it is no longer a regular file");
    }
    if meta.nlink() > 1 {
        bail!(
            "it has {} hard links: a tools definition holds no hard-linked file, which could \
             be another name for one outside it",
            meta.nlink()
        );
    }
    let left = MAX_TOOLS_DEFINITION.saturating_sub(taken);
    let mut data = Vec::new();
    file.take(left.saturating_add(1)).read_to_end(&mut data)?;
    if data.len() as u64 > left {
        bail!("the context holds more than the {MAX_TOOLS_DEFINITION} bytes a definition may");
    }
    Ok((data, meta.permissions().mode() & 0o111 != 0))
}

/// The tools directory, created private if it is not there yet.
fn tools_dir(hub: &Hub) -> Result<&Path> {
    let dir = hub.tools_dir()?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

/// Pack the build context at `from` as definition `version`, named by its sha256 and audited
/// as `actor`. Publish the complete tar by rename before writing its database row. Adding
/// the same tree with the same version returns the stored definition, restoring its tar if
/// missing or the wrong size.
pub fn add(hub: &Hub, actor: &str, from: &Path, version: &str) -> Result<Tools> {
    crate::releases::check_version(version)?;
    let packed = pack(from)?;
    hold(hub, actor, &packed, version, false)
}

/// Hold the build context in `archive` ([`pack_archive`]) as definition `version`, audited as
/// `actor`, as [`add`] holds one from a directory.
pub fn add_archive(hub: &Hub, actor: &str, archive: &[u8], version: &str) -> Result<Tools> {
    crate::releases::check_version(version)?;
    let packed = pack_archive(archive)?;
    hold(hub, actor, &packed, version, false)
}

/// Hold the definition built into the hub, as `actor`: added under its label unless already
/// held, under whatever label it was given.
pub fn add_builtin(hub: &Hub, actor: &str) -> Result<Tools> {
    let builtin = builtin();
    hold(hub, actor, &builtin.packed, &builtin.version, true)
}

/// Hold `packed` as definition `version`, as [`add`] does. One already held under another
/// label is refused, unless `any_label`, which takes it as it is.
fn hold(hub: &Hub, actor: &str, packed: &Packed, version: &str, any_label: bool) -> Result<Tools> {
    let dir = tools_dir(hub)?;
    let row = ToolsRow {
        version: version.to_string(),
        size: packed.tar.len() as u64,
        files: packed.files,
        added_at: crate::now_secs(),
        added_by: actor.to_string(),
    };
    let sha256 = packed.sha256.clone();
    let _held = hub.tools_lock();
    let dest = path(dir, &sha256);
    let existing = hub.db.tools(&sha256)?;
    if let Some(existing) = &existing {
        if existing.version != row.version && !any_label {
            bail!(
                "tools {} are already held, as version {}",
                crate::store::short(&sha256),
                existing.version
            );
        }
        if std::fs::metadata(&dest).is_ok_and(|m| m.is_file() && m.len() == existing.size) {
            return Ok(Tools {
                sha256,
                row: existing.clone(),
            });
        }
    }
    publish(dir, &dest, &packed.tar)?;
    if let Some(existing) = existing {
        eprintln!(
            "vk-hub: {actor} restored the tar of tools {}",
            crate::store::short(&sha256)
        );
        return Ok(Tools {
            sha256,
            row: existing,
        });
    }
    // A tar with no row is harmless — nothing serves it — and the next add of the same tree
    // replaces it.
    hub.db.add_tools(&sha256, &row, actor)?;
    hub.touch();
    eprintln!(
        "vk-hub: {actor} added tools {} as version {version}",
        crate::store::short(&sha256)
    );
    Ok(Tools { sha256, row })
}

/// Write `tar` to a private file in `dir`, flushed, and rename it to `dest`.
fn publish(dir: &Path, dest: &Path, tar: &[u8]) -> Result<()> {
    let tmp = dir.join(format!(".add-{}.tmp", crate::random_hex(8)?));
    let written = (|| {
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        out.write_all(tar)
            .and_then(|()| out.sync_all())
            .with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, dest).with_context(|| format!("publishing {}", dest.display()))
    })();
    if written.is_err() {
        // Best effort: the error is what matters, and the next start sweeps what is left.
        let _ = std::fs::remove_file(&tmp);
        return written;
    }
    if let Ok(d) = std::fs::File::open(dir) {
        // Best effort, as a release's publish: the rename has happened.
        let _ = d.sync_all();
    }
    Ok(())
}

/// The largest Dockerfile [`dockerfile`] reads.
const MAX_DOCKERFILE: u64 = 1 << 20;

/// The Dockerfile of definition `sha256`, read from its tar in `dir`.
pub fn dockerfile(dir: &Path, sha256: &str) -> Result<String> {
    let file = path(dir, sha256);
    let tar = std::fs::File::open(&file).with_context(|| format!("opening {}", file.display()))?;
    let mut archive = tar::Archive::new(tar);
    for entry in archive.entries()? {
        let entry = entry?;
        if entry.path()?.as_os_str() != DOCKERFILE {
            continue;
        }
        let mut text = String::new();
        entry
            .take(MAX_DOCKERFILE)
            .read_to_string(&mut text)
            .context("reading its Dockerfile")?;
        return Ok(text);
    }
    bail!("it holds no {DOCKERFILE}")
}

/// Forget definition `sha256` and delete its tar, unless it is built into the hub. `Ok(false)`
/// when there was none.
pub fn remove(hub: &Hub, actor: &str, sha256: &str) -> Result<bool> {
    if sha256 == builtin().packed.sha256 {
        bail!(
            "tools {} are built into this hub, which holds them again at its next start",
            crate::store::short(sha256)
        );
    }
    let _held = hub.tools_lock();
    let removed = hub.db.remove_tools(sha256, actor, crate::now_secs())?;
    if removed {
        hub.touch();
        let file = path(hub.tools_dir()?, sha256);
        match std::fs::remove_file(&file) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", file.display())),
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-hub-tools-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn context(dir: &Path, umask_like: u32) {
        std::fs::create_dir_all(dir.join("sub/deeper")).unwrap();
        std::fs::write(dir.join("Dockerfile"), "FROM scratch AS tools\n").unwrap();
        std::fs::write(dir.join("apk-pins.txt"), "git=2.49.0\n").unwrap();
        std::fs::write(dir.join("update.sh"), "#!/bin/sh\n").unwrap();
        std::fs::write(dir.join("sub/deeper/a"), "a").unwrap();
        std::fs::set_permissions(
            dir.join("update.sh"),
            std::fs::Permissions::from_mode(0o750 & !umask_like),
        )
        .unwrap();
        std::fs::set_permissions(
            dir.join("apk-pins.txt"),
            std::fs::Permissions::from_mode(0o666 & !umask_like),
        )
        .unwrap();
    }

    #[test]
    fn the_same_tree_packs_to_the_same_bytes_whatever_its_times_and_modes() {
        let (a, b) = (scratch("a"), scratch("b"));
        context(&a, 0o022);
        // Created in another order, with another umask, at another time.
        std::fs::create_dir_all(b.join("sub")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        context(&b, 0o077);
        let (pa, pb) = (pack(&a).unwrap(), pack(&b).unwrap());
        assert_eq!(pa.sha256, pb.sha256);
        assert_eq!(pa.tar, pb.tar);
        assert_eq!(pa.files, 4);
        assert_eq!(pa.sha256, vk_hub_proto::to_hex(&Sha256::digest(&pa.tar)));

        let mut archive = tar::Archive::new(pa.tar.as_slice());
        let listed: Vec<(String, u32, u64, u64)> = archive
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                let h = e.header();
                (
                    e.path().unwrap().display().to_string(),
                    h.mode().unwrap(),
                    h.mtime().unwrap(),
                    h.uid().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            listed,
            [
                ("Dockerfile".into(), 0o644, 0, 0),
                ("apk-pins.txt".into(), 0o644, 0, 0),
                ("sub".into(), 0o755, 0, 0),
                ("sub/deeper".into(), 0o755, 0, 0),
                ("sub/deeper/a".into(), 0o644, 0, 0),
                ("update.sh".into(), 0o755, 0, 0),
            ]
        );

        // Any change of content moves the digest.
        std::fs::write(b.join("apk-pins.txt"), "git=2.49.1\n").unwrap();
        assert_ne!(pack(&b).unwrap().sha256, pa.sha256);
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    #[test]
    fn the_builtin_definition_is_the_directory_it_comes_from() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("ci-tools");
        let on_disk = pack(&dir).unwrap();
        let builtin = builtin();
        assert_eq!(builtin.packed.sha256, on_disk.sha256);
        assert_eq!(builtin.packed.tar, on_disk.tar);
        assert_eq!(builtin.packed.files, on_disk.files);
        let names: Vec<_> = BUILTIN_FILES.iter().map(|(n, _)| *n).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
        assert!(
            builtin.version.starts_with("git-") && builtin.version.contains("-lfs-"),
            "{}",
            builtin.version
        );
    }

    /// `dir`'s tree as `tar -czf` or `tar -cf` would archive it, with the given prefix and
    /// in another order than a pack's.
    fn archived(dir: &Path, prefix: &str, gzip: bool) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        builder.mode(tar::HeaderMode::Complete);
        builder.append_dir_all(prefix, dir).unwrap();
        let tar = builder.into_inner().unwrap();
        if !gzip {
            return tar;
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn an_uploaded_context_packs_as_its_directory_does() {
        let dir = scratch("archive");
        context(&dir, 0o022);
        let packed = pack(&dir).unwrap();
        for (prefix, gzip) in [(".", false), ("", true), ("ci-tools", true)] {
            let got = pack_archive(&archived(&dir, prefix, gzip)).unwrap();
            assert_eq!(got.sha256, packed.sha256, "{prefix:?}, gzip {gzip}");
            assert_eq!(got.tar, packed.tar);
        }
        // A file named as a directory sorts by component, as a directory lists it.
        std::fs::write(dir.join("sub.txt"), "x").unwrap();
        assert_eq!(
            pack_archive(&archived(&dir, "", false)).unwrap().sha256,
            pack(&dir).unwrap().sha256
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_archive_of_anything_but_plain_files_and_directories_is_refused() {
        let entry = |builder: &mut tar::Builder<Vec<u8>>, path: &str, kind, data: &[u8]| {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_mode(0o644);
            header.set_size(data.len() as u64);
            // Set raw: `set_path` refuses `..`, which an archive may still hold.
            let name = &mut header.as_old_mut().name;
            name[..path.len()].copy_from_slice(path.as_bytes());
            header.set_cksum();
            builder.append(&header, data).unwrap();
        };
        let refused = |entries: &[(&str, tar::EntryType, &[u8])]| {
            let mut builder = tar::Builder::new(Vec::new());
            entry(
                &mut builder,
                "Dockerfile",
                tar::EntryType::Regular,
                b"FROM scratch AS tools\n",
            );
            for (path, kind, data) in entries {
                entry(&mut builder, path, *kind, data);
            }
            format!(
                "{:#}",
                pack_archive(&builder.into_inner().unwrap()).unwrap_err()
            )
        };
        assert!(refused(&[("link", tar::EntryType::Symlink, b"")]).contains("is a link"));
        assert!(refused(&[("hard", tar::EntryType::Link, b"")]).contains("is a link"));
        assert!(refused(&[("fifo", tar::EntryType::Fifo, b"")]).contains("neither"));
        assert!(refused(&[("../x", tar::EntryType::Regular, b"")]).contains("plain relative"));
        assert!(refused(&[("/etc/x", tar::EntryType::Regular, b"")]).contains("plain relative"));
        assert!(refused(&[("./Dockerfile", tar::EntryType::Regular, b"")]).contains("twice"));
        assert!(
            refused(&[
                ("a", tar::EntryType::Regular, b""),
                ("a/b", tar::EntryType::Regular, b"")
            ])
            .contains("a file and a directory")
        );
        let err =
            pack_archive(b"not an archive at all, but long enough to be read as one").unwrap_err();
        assert!(!format!("{err:#}").is_empty());
        // No Dockerfile at its root, nor in one directory alone there.
        let mut builder = tar::Builder::new(Vec::new());
        entry(&mut builder, "a/b/Dockerfile", tar::EntryType::Regular, b"");
        let err = pack_archive(&builder.into_inner().unwrap()).unwrap_err();
        assert!(format!("{err:#}").contains("no Dockerfile"), "{err:#}");
        // A gzip that inflates past what a definition may hold.
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        let zeros = vec![0u8; 1 << 20];
        for _ in 0..(2 * (MAX_TOOLS_DEFINITION >> 20) + 1) {
            gz.write_all(&zeros).unwrap();
        }
        let bomb = gz.finish().unwrap();
        let err = pack_archive(&bomb).unwrap_err();
        assert!(format!("{err:#}").contains("more than"), "{err:#}");
    }

    #[test]
    fn a_label_names_each_tool_s_version() {
        let dockerfile = "FROM x\nARG GIT_VERSION=2.56.0\n  ARG GIT_LFS_VERSION=3.8.0\n";
        assert_eq!(builtin_version(dockerfile).unwrap(), "git-2.56.0-lfs-3.8.0");
        let err = builtin_version("ARG GIT_VERSION=2\n").unwrap_err();
        assert!(format!("{err:#}").contains("GIT_LFS_VERSION"), "{err:#}");
        let bad = "ARG GIT_VERSION=2 3\nARG GIT_LFS_VERSION=3\n";
        assert!(builtin_version(bad).is_err());
    }

    #[test]
    fn only_regular_files_and_directories_under_a_dockerfile_are_packed() {
        let dir = scratch("refused");
        let err = pack(&dir).unwrap_err();
        assert!(format!("{err:#}").contains("no Dockerfile"), "{err:#}");
        context(&dir, 0o022);
        std::os::unix::fs::symlink("/etc/passwd", dir.join("sub/link")).unwrap();
        let err = pack(&dir).unwrap_err();
        assert!(
            format!("{err:#}").contains("sub/link is a symlink"),
            "{err:#}"
        );
        std::fs::remove_file(dir.join("sub/link")).unwrap();
        std::fs::hard_link(dir.join("sub/deeper/a"), dir.join("sub/hard")).unwrap();
        let err = pack(&dir).unwrap_err();
        assert!(format!("{err:#}").contains("hard links"), "{err:#}");
        std::fs::remove_file(dir.join("sub/hard")).unwrap();
        // The context itself may be reached through a link: the operator named it.
        let link = dir.with_extension("link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert_eq!(pack(&link).unwrap().sha256, pack(&dir).unwrap().sha256);
        let _ = std::fs::remove_file(&link);
        let big = std::fs::File::create(dir.join("big")).unwrap();
        big.set_len(MAX_TOOLS_DEFINITION + 1).unwrap();
        let err = pack(&dir).unwrap_err();
        assert!(format!("{err:#}").contains("more than"), "{err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
