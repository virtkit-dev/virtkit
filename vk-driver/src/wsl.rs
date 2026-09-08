//! WSL2 distro names and Windows environment paths.
//!
//! Only Windows knows its own paths: interop uses `cmd.exe` to expand environment variables
//! and `wslpath` to translate paths. The trait lets callers test writes against a scratch tree.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

/// Where a WSL install keeps `wsl.exe`, for a PATH without the interop directories.
pub(crate) const WSL_EXE: &str = r"C:\Windows\System32\wsl.exe";

/// The Windows facts this side cannot work out on its own, each an interop call.
pub(crate) trait Windows {
    /// `%USERPROFILE%`, as a path this distro can open.
    fn user_profile(&self) -> Result<PathBuf>;
    /// `%APPDATA%`, likewise — where a Windows VS Code keeps its user settings.
    fn app_data(&self) -> Result<PathBuf>;
    /// The Windows spelling of a path in this distro.
    fn to_windows(&self, path: &Path) -> Result<String>;
    /// `wsl.exe`, as Windows spells it.
    fn wsl_exe(&self) -> Result<String>;
}

/// Detect WSL by its distro name, or by the binfmt handler if the shell lost the name.
pub(crate) fn in_wsl() -> bool {
    std::env::var_os("WSL_DISTRO_NAME").is_some_and(|name| !name.is_empty())
        || Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists()
}

/// Require the distro name for `wsl.exe -d`; fail rather than guess a default.
pub(crate) fn distro() -> Result<String> {
    let name = std::env::var("WSL_DISTRO_NAME").unwrap_or_default();
    if !name.is_empty() {
        return Ok(name);
    }
    if in_wsl() {
        bail!(
            "WSL_DISTRO_NAME is not set, so there is no distro to name — run this from a WSL \
             shell"
        );
    }
    bail!("this is not a WSL2 distro");
}

/// The Windows side, reached through WSL interop.
pub(crate) struct Interop;

impl Windows for Interop {
    fn user_profile(&self) -> Result<PathBuf> {
        win_env("USERPROFILE")
    }

    fn app_data(&self) -> Result<PathBuf> {
        win_env("APPDATA")
    }

    fn to_windows(&self, path: &Path) -> Result<String> {
        let win = wslpath("-w", path.as_os_str())?;
        String::from_utf8(win).with_context(|| {
            format!(
                "the Windows spelling of {} is not valid UTF-8",
                path.display()
            )
        })
    }

    fn wsl_exe(&self) -> Result<String> {
        // The well-known path covers a PATH without the interop directories, and a
        // translation that fails on the one we found.
        Ok(crate::shell::which("wsl.exe")
            .and_then(|p| self.to_windows(&p).ok())
            .unwrap_or_else(|| WSL_EXE.to_string()))
    }
}

/// One Windows environment variable, as a path this distro can open. Only Windows knows its
/// own environment, so cmd.exe expands it — echoing the value with a trailing CRLF, and the
/// name back when it is unset. Bytes throughout: a directory spelled in the console codepage
/// is not UTF-8.
fn win_env(name: &str) -> Result<PathBuf> {
    let out = output(Command::new("cmd.exe").args(["/c", &format!("echo %{name}%")]))
        .with_context(|| format!("asking Windows for %{name}% (WSL interop has to be enabled)"))?;
    let value = out.trim_ascii();
    if value.is_empty() || value == format!("%{name}%").as_bytes() {
        bail!("Windows reports no %{name}%");
    }
    Ok(PathBuf::from(OsString::from_vec(wslpath(
        "-u",
        OsStr::from_bytes(value),
    )?)))
}

fn wslpath(flag: &str, value: &OsStr) -> Result<Vec<u8>> {
    let out = output(Command::new("wslpath").arg(flag).arg(value))?;
    let path = out.trim_ascii();
    if path.is_empty() {
        bail!("wslpath {flag} {value:?} returned nothing");
    }
    Ok(path.to_vec())
}

/// Run an interop helper and return its stdout, reporting its own complaint on failure.
fn output(cmd: &mut Command) -> Result<Vec<u8>> {
    let out = cmd
        .output()
        .with_context(|| format!("running {:?}", cmd.get_program()))?;
    if !out.status.success() {
        bail!(
            "{:?} failed ({}): {}",
            cmd.get_program(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}
