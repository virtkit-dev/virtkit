//! Private scratch space under the system temp directory, cleaned up on normal process exit.

use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static ROOT: OnceLock<PathBuf> = OnceLock::new();

/// Create the process's private directory on first use. mkdtemp(3) avoids PID-reuse collisions.
pub(crate) fn root() -> &'static Path {
    ROOT.get_or_init(|| {
        let template = std::env::temp_dir().join("vk-agent-test-XXXXXX");
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
