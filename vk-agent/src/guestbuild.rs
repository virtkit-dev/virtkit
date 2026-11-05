//! `vk-agent build`: a CI job's build request and context tar, streamed to its host in the
//! [`vk_core::guest_build`] format. The host builds the image, publishes it in the job's
//! pipeline and returns its reference.

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use vk_core::dockerignore::Ignore;
use vk_core::guest_build::{CONTEXT, DOCKERFILE};

/// What `vk-agent build` sends, with the context it reads.
#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    /// The Dockerfile: `-f`, else `<context>/Dockerfile`.
    pub dockerfile: PathBuf,
    pub context: PathBuf,
    /// The host's `vk build …`, `vk` first.
    pub argv: Vec<String>,
}

impl Request {
    pub fn new(
        file: Option<PathBuf>,
        target: Option<String>,
        build_args: &[String],
        name: String,
        context: PathBuf,
    ) -> Request {
        let mut argv = vec!["vk".to_string(), "build".to_string()];
        if let Some(t) = target {
            argv.extend(["--target".to_string(), t]);
        }
        for a in build_args {
            argv.extend(["--build-arg".to_string(), a.clone()]);
        }
        argv.extend(["--as".to_string(), name]);
        Request {
            dockerfile: file.unwrap_or_else(|| context.join("Dockerfile")),
            context,
            argv,
        }
    }
}

/// One entry of a context, by its path below the context root.
#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    pub rel: PathBuf,
    pub dir: bool,
}

/// The entries of `context` its `.dockerignore` leaves in, parents before what they hold:
/// regular files and directories, an excluded directory kept when a `!` pattern could take
/// something below it back. A symlink or a special file left in is refused, naming it, and so
/// is a path a ustar header cannot hold.
pub fn entries(context: &Path) -> Result<Vec<Entry>> {
    let meta = std::fs::metadata(context)
        .with_context(|| format!("the build context {}", context.display()))?;
    if !meta.is_dir() {
        bail!("the build context {} is not a directory", context.display());
    }
    let ignore = Ignore::load(context);
    let mut out = Vec::new();
    walk(&ignore, context, Path::new(""), false, &mut out)?;
    for e in &out {
        header(
            tar::EntryType::Regular,
            0,
            0,
            &Path::new(CONTEXT).join(&e.rel),
        )?;
    }
    Ok(out)
}

fn walk(
    ignore: &Ignore,
    root: &Path,
    rel: &Path,
    parent_excluded: bool,
    out: &mut Vec<Entry>,
) -> Result<()> {
    let dir = root.join(rel);
    let mut names = std::fs::read_dir(&dir)
        .and_then(|d| {
            d.map(|e| e.map(|e| e.file_name()))
                .collect::<std::io::Result<Vec<_>>>()
        })
        .with_context(|| format!("reading {}", dir.display()))?;
    names.sort();
    for name in names {
        let rel = rel.join(&name);
        let path = root.join(&rel);
        let meta = std::fs::symlink_metadata(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let excluded = ignore.excluded(&path, parent_excluded);
        let kind = meta.file_type();
        if kind.is_dir() {
            if excluded && !ignore.could_reinclude_under(&path) {
                continue;
            }
            out.push(Entry {
                rel: rel.clone(),
                dir: true,
            });
            walk(ignore, root, &rel, excluded, out)?;
        } else if excluded {
            continue;
        } else if kind.is_file() {
            out.push(Entry { rel, dir: false });
        } else {
            let what = if kind.is_symlink() {
                "a symlink"
            } else {
                "a special file"
            };
            bail!(
                "{}: {what}; the build context sends regular files and directories only \
                 (leave it out with .dockerignore)",
                path.display()
            );
        }
    }
    Ok(())
}

/// Write the tar of `entries` of `context` and of `dockerfile` to `out`: modes kept to the
/// permission bits, no owner, no time.
pub fn write_tar(
    context: &Path,
    entries: &[Entry],
    dockerfile: &Path,
    out: impl Write,
) -> Result<()> {
    let mut tar = tar::Builder::new(out);
    for e in entries {
        let path = context.join(&e.rel);
        let name = Path::new(CONTEXT).join(&e.rel);
        if e.dir {
            let meta = std::fs::symlink_metadata(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            if !meta.is_dir() {
                bail!("{}: no longer a directory", path.display());
            }
            let h = header(tar::EntryType::Directory, meta.mode(), 0, &name)?;
            tar.append(&h, std::io::empty())
                .with_context(|| format!("sending {}", path.display()))?;
        } else {
            append_file(&mut tar, &path, &name)?;
        }
    }
    append_file(&mut tar, dockerfile, Path::new(DOCKERFILE))?;
    tar.into_inner()
        .and_then(|mut w| w.flush())
        .context("sending the context")
}

/// A plain ustar header for the entry `name`: the host refuses the extension records a longer
/// path would need, so a path that does not fit the header's name and prefix is refused here.
fn header(kind: tar::EntryType, mode: u32, size: u64, name: &Path) -> Result<tar::Header> {
    let mut h = tar::Header::new_ustar();
    h.set_entry_type(kind);
    h.set_mode(mode & 0o777);
    h.set_size(size);
    h.set_mtime(0);
    h.set_path(name).with_context(|| {
        format!(
            "{}: the path is too long for the build context (plain ustar: split at a `/`, at most \
             155 bytes before it and 100 after)",
            name.display()
        )
    })?;
    h.set_cksum();
    Ok(h)
}

/// `path`, a regular file and not a link to one, as the tar entry `name`.
fn append_file<W: Write>(tar: &mut tar::Builder<W>, path: &Path, name: &Path) -> Result<()> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| {
            format!(
                "opening {} (a symlink is not sent: the build context sends regular files and \
                 directories only)",
                path.display()
            )
        })?;
    let meta = file
        .metadata()
        .with_context(|| format!("reading {}", path.display()))?;
    if !meta.is_file() {
        bail!("{}: not a regular file", path.display());
    }
    let h = header(tar::EntryType::Regular, meta.mode(), meta.len(), name)?;
    let data = Exact {
        inner: file.take(meta.len()),
        left: meta.len(),
    };
    tar.append(&h, data)
        .with_context(|| format!("sending {}", path.display()))
}

/// `inner`, failing when it ends before `left` bytes: a file that shrank while it was sent
/// would otherwise leave its entry short of the size its header gives.
struct Exact<R> {
    inner: R,
    left: u64,
}

impl<R: Read> Read for Exact<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 && self.left > 0 && !buf.is_empty() {
            return Err(std::io::Error::other("the file shrank while it was sent"));
        }
        self.left = self.left.saturating_sub(n as u64);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct Tmp(PathBuf);

    impl Tmp {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("vk-gbuild-{tag}-{}", std::process::id()));
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

    fn write(root: &Path, rel: &str, data: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }

    #[test]
    fn the_request_names_no_path() {
        let r = Request::new(
            None,
            Some("runner".into()),
            &["V=1".to_string()],
            "img".into(),
            "./out".into(),
        );
        assert_eq!(
            r.argv,
            [
                "vk",
                "build",
                "--target",
                "runner",
                "--build-arg",
                "V=1",
                "--as",
                "img"
            ]
        );
        assert_eq!(r.dockerfile, Path::new("./out/Dockerfile"));
        let r = Request::new(
            Some("docker/x.Dockerfile".into()),
            None,
            &[],
            "img".into(),
            "out".into(),
        );
        assert_eq!(r.argv, ["vk", "build", "--as", "img"]);
        assert_eq!(r.dockerfile, Path::new("docker/x.Dockerfile"));
    }

    /// What `.dockerignore` excludes is left out, a `!` pattern taking a file back below an
    /// excluded directory, which is then sent too; parents come before their entries.
    #[test]
    fn the_context_follows_its_dockerignore() {
        let tmp = Tmp::new("ignore");
        let ctx = tmp.0.join("ctx");
        write(&ctx, ".dockerignore", "*.log\nbuild\n!build/keep.deb\n");
        write(&ctx, "a.log", "x");
        write(&ctx, "pkg/a.deb", "x");
        write(&ctx, "build/tmp.o", "x");
        write(&ctx, "build/keep.deb", "x");
        let got: Vec<(String, bool)> = entries(&ctx)
            .unwrap()
            .into_iter()
            .map(|e| (e.rel.display().to_string(), e.dir))
            .collect();
        assert_eq!(
            got,
            [
                (".dockerignore".to_string(), false),
                ("build".to_string(), true),
                ("build/keep.deb".to_string(), false),
                ("pkg".to_string(), true),
                ("pkg/a.deb".to_string(), false),
            ]
        );
    }

    /// A symlink or a FIFO left in the context is refused, by its path; excluded, it is not.
    #[test]
    fn links_and_special_files_are_refused_by_name() {
        let tmp = Tmp::new("refuse");
        let ctx = tmp.0.join("ctx");
        write(&ctx, "a", "x");
        symlink("/etc/passwd", ctx.join("link")).unwrap();
        let err = format!("{:#}", entries(&ctx).unwrap_err());
        assert!(err.contains("link") && err.contains("a symlink"), "{err}");
        write(&ctx, ".dockerignore", "link\n");
        entries(&ctx).unwrap();
        let fifo =
            std::ffi::CString::new(ctx.join("fifo").into_os_string().into_encoded_bytes()).unwrap();
        // SAFETY: a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let err = format!("{:#}", entries(&ctx).unwrap_err());
        assert!(
            err.contains("fifo") && err.contains("special file"),
            "{err}"
        );
    }

    /// A path a ustar header holds is sent, split between its prefix and name; a longer one
    /// is refused before anything is sent.
    #[test]
    fn a_path_past_ustar_is_refused() {
        let tmp = Tmp::new("long");
        let ctx = tmp.0.join("ctx");
        let fits = format!("{}/{}", "a".repeat(90), "b".repeat(90));
        write(&ctx, &fits, "x");
        write(&tmp.0, "Dockerfile", "FROM scratch\n");
        let list = entries(&ctx).unwrap();
        let mut out = Vec::new();
        write_tar(&ctx, &list, &tmp.0.join("Dockerfile"), &mut out).unwrap();
        let mut archive = tar::Archive::new(out.as_slice());
        let paths: Vec<String> = archive
            .entries()
            .unwrap()
            .raw(true)
            .map(|e| {
                let e = e.unwrap();
                assert!(e.header().as_ustar().is_some());
                String::from_utf8(e.path_bytes().into_owned()).unwrap()
            })
            .collect();
        assert!(paths.contains(&format!("context/{fits}")), "{paths:?}");
        write(&ctx, &"c".repeat(101), "x");
        let err = format!("{:#}", entries(&ctx).unwrap_err());
        assert!(err.contains("too long"), "{err}");
    }

    /// The tar holds the context under `context/` and the Dockerfile beside it, from wherever
    /// `-f` named it; a symlinked Dockerfile is refused.
    #[test]
    fn the_tar_holds_the_context_and_the_dockerfile_apart() {
        let tmp = Tmp::new("tar");
        let ctx = tmp.0.join("ctx");
        write(&ctx, "pkg/a.deb", "deb");
        std::fs::set_permissions(
            ctx.join("pkg/a.deb"),
            std::fs::Permissions::from_mode(0o4755),
        )
        .unwrap();
        write(&tmp.0, "docker/x.Dockerfile", "FROM scratch\n");
        let list = entries(&ctx).unwrap();
        let mut out = Vec::new();
        write_tar(&ctx, &list, &tmp.0.join("docker/x.Dockerfile"), &mut out).unwrap();
        let mut archive = tar::Archive::new(out.as_slice());
        let got: Vec<(String, tar::EntryType, u32, Vec<u8>)> = archive
            .entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let mut data = Vec::new();
                e.read_to_end(&mut data).unwrap();
                let h = e.header();
                (
                    String::from_utf8(e.path_bytes().into_owned()).unwrap(),
                    h.entry_type(),
                    h.mode().unwrap(),
                    data,
                )
            })
            .collect();
        assert_eq!(got.len(), 3);
        assert_eq!(
            (got[0].0.trim_end_matches('/'), got[0].1),
            ("context/pkg", tar::EntryType::Directory)
        );
        assert_eq!(
            got[1],
            (
                "context/pkg/a.deb".to_string(),
                tar::EntryType::Regular,
                0o755,
                b"deb".to_vec()
            )
        );
        assert_eq!(got[2].0, "Dockerfile");
        assert_eq!(got[2].3, b"FROM scratch\n");

        symlink(tmp.0.join("docker/x.Dockerfile"), tmp.0.join("linked")).unwrap();
        let err = write_tar(&ctx, &list, &tmp.0.join("linked"), Vec::new()).unwrap_err();
        assert!(format!("{err:#}").contains("symlink"), "{err:#}");
    }
}
