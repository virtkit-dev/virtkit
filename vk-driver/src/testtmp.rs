//! Private test fixtures under the system temp directory. Scoped fixtures are removed on
//! drop. The process cleans up its scratch directory on normal exit, even after test failures.

use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static ROOT: OnceLock<PathBuf> = OnceLock::new();

/// Create the process's private directory on first use. mkdtemp(3) avoids PID-reuse collisions.
pub(crate) fn root() -> &'static Path {
    ROOT.get_or_init(|| {
        let template = std::env::temp_dir().join("vk-driver-test-XXXXXX");
        let mut template = std::ffi::CString::new(template.as_os_str().as_bytes())
            .unwrap()
            .into_bytes_with_nul();
        // SAFETY: `template` is a NUL-terminated buffer mkdtemp rewrites in place.
        let made = unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) };
        assert!(
            !made.is_null(),
            "mkdtemp: {}",
            std::io::Error::last_os_error()
        );
        template.pop();
        let dir = PathBuf::from(std::ffi::OsString::from_vec(template));
        // SAFETY: atexit(3) only records the function, which takes no arguments.
        if unsafe { libc::atexit(remove_root) } != 0 {
            let _ = std::fs::remove_dir(&dir); // just made, still empty
            panic!("atexit: cannot register the removal of {}", dir.display());
        }
        dir
    })
}

extern "C" fn remove_root() {
    use std::io::Write as _;
    if let Some(dir) = ROOT.get()
        && let Err(err) = std::fs::remove_dir_all(dir)
    {
        // Not eprintln!: a panic cannot unwind out of this callback.
        let _ = writeln!(std::io::stderr(), "cannot remove {}: {err}", dir.display());
    }
}

/// Remove this path and its contents on drop.
#[derive(Debug)]
pub(crate) struct Scratch(PathBuf);

impl Scratch {
    /// Create an empty directory under [`root`]. Panics if the name already exists.
    pub(crate) fn dir(name: impl AsRef<Path>) -> Scratch {
        // Create the guard only after creation succeeds so a collision leaves the existing tree alone.
        let dir = root().join(name);
        std::fs::create_dir(&dir).unwrap();
        Scratch(dir)
    }

    /// Guard a path under [`root`] that the test will create.
    pub(crate) fn path(name: impl AsRef<Path>) -> Scratch {
        Scratch(root().join(name))
    }
}

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // The exit handler retries cleanup of anything left under the root.
        match std::fs::symlink_metadata(&self.0) {
            Ok(meta) if meta.is_dir() => {
                let _ = std::fs::remove_dir_all(&self.0);
            }
            Ok(_) => {
                let _ = std::fs::remove_file(&self.0);
            }
            Err(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_already_taken_leaves_the_other_tree_alone() {
        let first = Scratch::dir("taken");
        std::fs::write(first.join("sentinel"), b"").unwrap();
        assert!(std::panic::catch_unwind(|| Scratch::dir("taken")).is_err());
        assert!(first.join("sentinel").exists());
    }
}
