//! The WSL host facts `vk` reads on a WSL2 distro: the distro name, what Windows says about
//! its own environment, and the `.wslconfig` / `wsl.conf` settings that decide whether the
//! distro can host KVM.
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
/// The Windows-side file that turns nested virtualization on, under `%USERPROFILE%`.
const WSLCONFIG: &str = ".wslconfig";
/// The `[wsl2]` key that decides whether this distro's CPUs expose virtualization at all.
const NESTED: &str = "nestedVirtualization";
/// The distro-side settings WSL applies to every boot of it.
pub(crate) const WSL_CONF: &str = "/etc/wsl.conf";

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

/// Detect WSL by its distro name, or by the binfmt handler if the shell lost the name. This
/// answers for interop; [`is_wsl2`] answers for the kernel underneath.
pub(crate) fn in_wsl() -> bool {
    std::env::var_os("WSL_DISTRO_NAME").is_some_and(|name| !name.is_empty())
        || Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists()
}

/// Whether this is a WSL kernel — WSL2 for any host that could reach KVM, since WSL1 has no
/// `/dev/kvm` and never gets this far. Read from the kernel's release string rather than the
/// environment, so a distro shell carrying neither `WSL_DISTRO_NAME` nor interop is still
/// recognised; the loose `microsoft` match also keeps a custom-built WSL2 kernel in scope.
pub(crate) fn is_wsl2() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/osrelease").is_ok_and(|s| osrelease_is_wsl(&s))
}

/// Microsoft's kernels carry `microsoft` in their release string
/// (`5.15.167.4-microsoft-standard-WSL2`), which a distribution kernel does not.
fn osrelease_is_wsl(osrelease: &str) -> bool {
    osrelease.to_ascii_lowercase().contains("microsoft")
}

/// A CPU's virtualization extension, which also names the KVM module that drives it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Virt {
    Intel,
    Amd,
}

impl Virt {
    /// The KVM module for this vendor, as `modprobe` spells it.
    pub(crate) fn module(self) -> &'static str {
        match self {
            Virt::Intel => "kvm_intel",
            Virt::Amd => "kvm_amd",
        }
    }
}

/// The virtualization extension this host's CPUs expose, or `None` when they expose neither.
/// Under WSL2 both are absent until `nestedVirtualization` takes effect, so this is what
/// separates a distro that cannot host KVM at all from one that only lacks the module.
pub(crate) fn cpu_virt() -> Option<Virt> {
    cpu_virt_of(&std::fs::read_to_string("/proc/cpuinfo").ok()?)
}

/// The first `flags` line's verdict. Every processor in the file carries the same extension,
/// so the first one answers for the host.
fn cpu_virt_of(cpuinfo: &str) -> Option<Virt> {
    let flags = cpuinfo
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.trim() == "flags")?
        .1;
    flags.split_ascii_whitespace().find_map(|flag| match flag {
        "vmx" => Some(Virt::Intel),
        "svm" => Some(Virt::Amd),
        _ => None,
    })
}

/// `%USERPROFILE%\.wslconfig`'s `[wsl2] nestedVirtualization`. `None` when the file, the key,
/// or a value WSL would read as a boolean is absent — all of which leave nesting off.
pub(crate) fn wslconfig_nested(w: &impl Windows) -> Result<Option<bool>> {
    let text = read_or_empty(&wslconfig(w)?)?;
    Ok(ini_get(&text, "wsl2", NESTED).and_then(ini_bool))
}

/// `%USERPROFILE%\.wslconfig`, as a path this distro can open.
fn wslconfig(w: &impl Windows) -> Result<PathBuf> {
    Ok(w.user_profile()?.join(WSLCONFIG))
}

/// The same file as Windows spells it, for a message a user has to act on there. Built from
/// the profile's Windows path rather than translated from its own, so it can be named before
/// it exists; the literal stands in when interop cannot say.
pub(crate) fn wslconfig_win_path(w: &impl Windows) -> String {
    match w.user_profile().and_then(|p| w.to_windows(&p)) {
        Ok(profile) => format!("{}\\{WSLCONFIG}", profile.trim_end_matches('\\')),
        Err(_) => format!(r"%USERPROFILE%\{WSLCONFIG}"),
    }
}

/// `/etc/wsl.conf`'s `[boot] command`, the one hook WSL runs as root on every boot of this
/// distro. `Ok(None)` when the file or the key is absent; `Err` only when the file exists but
/// cannot be read, since then what it already runs cannot be judged. Read as bytes like
/// `.wslconfig`, so a non-UTF-8 byte elsewhere in the file does not hide an ASCII command.
pub(crate) fn wsl_conf_boot_command() -> Result<Option<String>> {
    let text = read_or_empty(Path::new(WSL_CONF))?;
    Ok(ini_get(&text, "boot", "command")
        .and_then(|v| std::str::from_utf8(v).ok())
        .map(str::to_string))
}

/// A file's bytes, or none when it does not exist yet.
fn read_or_empty(path: &Path) -> Result<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(anyhow::Error::new(e).context(format!("reading {}", path.display()))),
    }
}

/// One `key = value` from `[section]`. Both WSL configuration files are INI, and WSL reads
/// their keys without regard to case.
///
/// A commented-out line needs no handling: `#` or `;` ends up part of the key, which then
/// matches nothing.
fn ini_get<'a>(text: &'a [u8], section: &str, key: &str) -> Option<&'a [u8]> {
    let mut here = false;
    for line in text.split(|b| *b == b'\n') {
        let body = line.trim_ascii();
        if let Some(name) = ini_section(body) {
            here = name.eq_ignore_ascii_case(section.as_bytes());
            continue;
        }
        if here
            && let Some((k, v)) = ini_entry(body)
            && k.eq_ignore_ascii_case(key.as_bytes())
        {
            return Some(v);
        }
    }
    None
}

/// The name in a `[section]` header line.
fn ini_section(body: &[u8]) -> Option<&[u8]> {
    body.strip_prefix(b"[")?
        .strip_suffix(b"]")
        .map(|name| name.trim_ascii())
}

/// A line's key and value, split on its first `=`.
fn ini_entry(body: &[u8]) -> Option<(&[u8], &[u8])> {
    let eq = body.iter().position(|b| *b == b'=')?;
    let (key, rest) = body.split_at(eq);
    Some((key.trim_ascii(), rest.get(1..)?.trim_ascii()))
}

/// A value as WSL reads a boolean, and `None` for one it would not.
fn ini_bool(value: &[u8]) -> Option<bool> {
    if value.eq_ignore_ascii_case(b"true") {
        Some(true)
    } else if value.eq_ignore_ascii_case(b"false") {
        Some(false)
    } else {
        None
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A Windows side standing in for interop, answering only what these tests read.
    struct Fake(Option<&'static str>);

    impl Windows for Fake {
        fn user_profile(&self) -> Result<PathBuf> {
            Ok(PathBuf::from("/mnt/c/Users/dev"))
        }
        fn app_data(&self) -> Result<PathBuf> {
            unimplemented!("not read here")
        }
        fn to_windows(&self, _: &Path) -> Result<String> {
            self.0.map(str::to_string).context("no interop")
        }
        fn wsl_exe(&self) -> Result<String> {
            unimplemented!("not read here")
        }
    }

    /// The release string is the kernel's own answer, so no environment a shell lost or
    /// inherited can make a distribution kernel look like WSL's, or the other way round.
    #[test]
    fn a_wsl_kernel_is_recognised_by_its_release_string() {
        for wsl in [
            "5.15.167.4-microsoft-standard-WSL2\n",
            "4.4.0-19041-Microsoft\n",
            "6.6.87.2-MICROSOFT-standard-WSL2",
        ] {
            assert!(osrelease_is_wsl(wsl), "{wsl}");
        }
        for other in ["6.12.9-arch1-1\n", "5.15.0-91-generic\n", ""] {
            assert!(!osrelease_is_wsl(other), "{other}");
        }
    }

    /// The vendor comes from the first `flags` line, and a CPU exposing neither extension —
    /// which is what WSL2 shows until nested virtualization is on — answers `None`.
    #[test]
    fn the_cpu_virtualization_flag_names_the_vendor() {
        let cpuinfo = |flags: &str| {
            format!(
                "processor\t: 0\nmodel name\t: CPU\nflags\t\t: fpu {flags} lm\nbugs\t\t: none\n"
            )
        };
        assert_eq!(cpu_virt_of(&cpuinfo("vmx ept")), Some(Virt::Intel));
        assert_eq!(cpu_virt_of(&cpuinfo("svm npt")), Some(Virt::Amd));
        assert_eq!(cpu_virt_of(&cpuinfo("aes sse2")), None);
        assert_eq!(cpu_virt_of(""), None);
        // A flag another word merely starts is not the flag, and no field but `flags` counts.
        assert_eq!(cpu_virt_of(&cpuinfo("vmxnet3")), None);
        assert_eq!(cpu_virt_of("model name\t: vmx svm\n"), None);
        assert_eq!(Virt::Intel.module(), "kvm_intel");
        assert_eq!(Virt::Amd.module(), "kvm_amd");
    }

    /// Keys are read case-insensitively out of their own section only, a commented line sets
    /// nothing, and only a value WSL would read as a boolean is one.
    #[test]
    fn an_ini_key_is_read_from_its_own_section() {
        let text = b"[wsl2]\r\nmemory=8GB\r\nNestedVirtualization = True\r\n\r\n\
                     [experimental]\r\nsparseVhd=true\r\n";
        assert_eq!(ini_get(text, "wsl2", NESTED), Some(&b"True"[..]));
        assert_eq!(ini_get(text, "wsl2", "memory"), Some(&b"8GB"[..]));
        assert_eq!(ini_get(text, "boot", NESTED), None);
        assert_eq!(ini_get(text, "wsl2", "sparseVhd"), None);
        assert_eq!(
            ini_get(b"nestedVirtualization=true\n", "wsl2", NESTED),
            None
        );
        assert_eq!(
            ini_get(b"[wsl2]\n#nestedVirtualization=true\n", "wsl2", NESTED),
            None
        );
        assert_eq!(
            ini_get(b"[boot]\ncommand = modprobe kvm_intel\n", "boot", "command"),
            Some(&b"modprobe kvm_intel"[..])
        );
        assert_eq!(ini_bool(b"TRUE"), Some(true));
        assert_eq!(ini_bool(b"false"), Some(false));
        assert_eq!(ini_bool(b"1"), None);
    }

    /// The path a user has to open on Windows, with the literal for a distro whose interop
    /// cannot answer — where `vk check` would otherwise name nothing to act on.
    #[test]
    fn the_wslconfig_is_named_as_windows_spells_it() {
        assert_eq!(
            wslconfig_win_path(&Fake(Some(r"C:\Users\dev"))),
            r"C:\Users\dev\.wslconfig"
        );
        // A profile Windows spells with a trailing separator does not gain a second one.
        assert_eq!(wslconfig_win_path(&Fake(Some(r"C:\\"))), r"C:\.wslconfig");
        assert_eq!(wslconfig_win_path(&Fake(None)), r"%USERPROFILE%\.wslconfig");
    }

    /// `nestedVirtualization` is read out of the real `.wslconfig` under the profile the
    /// Windows side hands back: an absent file leaves nesting simply off, a present key answers
    /// as WSL reads it, and a non-boolean value is no answer at all.
    #[test]
    fn nested_virtualization_is_read_from_the_wslconfig_file() {
        /// A Windows side whose profile is a scratch directory these fs reads can reach.
        struct AtProfile(PathBuf);
        impl Windows for AtProfile {
            fn user_profile(&self) -> Result<PathBuf> {
                Ok(self.0.clone())
            }
            fn app_data(&self) -> Result<PathBuf> {
                unimplemented!("not read here")
            }
            fn to_windows(&self, _: &Path) -> Result<String> {
                unimplemented!("not read here")
            }
            fn wsl_exe(&self) -> Result<String> {
                unimplemented!("not read here")
            }
        }

        let dir = std::env::temp_dir().join(format!("vk-wslconfig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let w = AtProfile(dir.clone());
        let cfg = dir.join(WSLCONFIG);

        let _ = std::fs::remove_file(&cfg);
        assert_eq!(wslconfig_nested(&w).unwrap(), None, "no file");
        std::fs::write(&cfg, "[wsl2]\nnestedVirtualization=true\n").unwrap();
        assert_eq!(wslconfig_nested(&w).unwrap(), Some(true), "true");
        std::fs::write(&cfg, "[wsl2]\nnestedVirtualization = False\n").unwrap();
        assert_eq!(wslconfig_nested(&w).unwrap(), Some(false), "false");
        std::fs::write(&cfg, "[wsl2]\nmemory=8GB\n").unwrap();
        assert_eq!(wslconfig_nested(&w).unwrap(), None, "key absent");
        std::fs::write(&cfg, "[wsl2]\nnestedVirtualization=1\n").unwrap();
        assert_eq!(wslconfig_nested(&w).unwrap(), None, "non-boolean value");

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
