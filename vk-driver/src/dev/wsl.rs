//! The Windows-side SSH setup `vk dev code` needs when the editor is a *Windows* VS Code
//! reached from a WSL2 distro.
//!
//! A `code` under `/mnt/<drive>/` is a Windows program, so Remote-SSH runs on Windows: it
//! spawns `C:\Windows\System32\OpenSSH\ssh.exe`, which reads `%USERPROFILE%\.ssh\config` and
//! sees neither this distro's PATH — so not the run's shims — nor the run's config. The
//! alias then resolves to nothing at all. This writes the same host block where that ssh.exe
//! does read it, dialling back into this distro through `wsl.exe -d <distro> -e vk connect`,
//! and points it at a copy of the run's managed key, since a Linux path is not one Windows
//! ssh can open.
//!
//! Written on every launch, like the Linux config it mirrors: the run rewrites its own setup
//! on each boot, and the two have to agree.

use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::dev::editor::Channel;
use crate::sshclient::{Managed, Parts};
use crate::wsl::{Interop, Windows, distro, in_wsl};

/// The line that makes the user's own `ssh_config` read the stanzas written here.
const INCLUDE: &str = "Include vk/*.conf";
/// What that line is, for whoever reads the file next.
const INCLUDE_NOTE: &str = "# Added by vk dev code: per-environment hosts.";

/// What the bridge left on the Windows side.
#[derive(Debug)]
pub struct Written {
    /// the stanza, as Windows spells its path
    conf: String,
    /// the user's `ssh_config`, if this run added the include line to it
    included: Option<String>,
}

impl Written {
    /// The one line `vk dev code` prints about the Windows side.
    pub fn note(&self) -> String {
        match &self.included {
            Some(config) => format!("ssh bridge in {} ({INCLUDE} added to {config})", self.conf),
            None => format!("ssh bridge in {}", self.conf),
        }
    }
}

/// Whether `vk dev code` has to bridge for `editor`: a Windows VS Code launched from a WSL2
/// distro. Anything else reaches the VM through the run's PATH shims, as it always has.
pub fn bridge_needed(editor: &Path) -> bool {
    in_wsl() && is_windows_binary(editor)
}

/// Write this run's Windows-side setup and say where it landed.
pub fn install(managed: &Managed) -> Result<Written> {
    write_bridge(&Interop, &entry()?, &managed.parts()?, &managed.key())
}

/// `vk dev ssh-config --windows`: print the Windows SSH stanza and its key-copy path
/// without writing the config or copying the key.
pub fn print_stanza(state_dir: &Path) -> Result<()> {
    let interop = Interop;
    let managed = Managed::new(state_dir)?;
    let text = stanza(
        &interop,
        &entry()?,
        &managed.parts()?,
        &interop.user_profile()?,
    )?;
    // Report a closed pipe as an error instead of panicking.
    std::io::stdout()
        .write_all(text.as_bytes())
        .context("writing the stanza to stdout")
}

/// The quick pick Remote-SSH stops on before installing its server: it asks what platform a
/// host it has not seen runs, and hangs on "Initializing VS Code Server" until answered. Best
/// effort — a settings file this cannot locate or read yields no hint, never an error.
pub fn platform_hint(alias: &str, channel: Channel) -> Option<String> {
    hint_for(&Interop, alias, channel)
}

fn hint_for(w: &impl Windows, alias: &str, channel: Channel) -> Option<String> {
    let settings = settings_path(&w.app_data().ok()?, channel)?;
    let text = match std::fs::read_to_string(&settings) {
        Ok(text) => text,
        // No settings file yet is a fresh install — the launch that most surely meets the
        // prompt — so treat it as unanswered. An unreadable one stays silent instead.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(_) => return None,
    };
    (!platform_known(&text, alias)).then(|| {
        format!(
            "Remote-SSH will ask for the platform of '{alias}' (a quick pick at the top of \
             the window); answer Linux, or add to the Windows VS Code user settings: \
             \"remote.SSH.remotePlatform\": {{ \"vk-*\": \"linux\" }}"
        )
    })
}

/// Windows VS Code user settings for `channel`, under `%APPDATA%`.
/// Return `None` rather than guess an unknown build's settings directory.
fn settings_path(app_data: &Path, channel: Channel) -> Option<PathBuf> {
    let dir = match channel {
        Channel::Stable => "Code",
        Channel::Insiders => "Code - Insiders",
        Channel::Codium | Channel::Oss => return None,
    };
    Some(app_data.join(dir).join("User/settings.json"))
}

/// Whether the settings already answer the platform question for `alias`: named outright, or
/// covered by the `vk-*` pattern every alias written here matches.
fn platform_known(settings: &str, alias: &str) -> bool {
    settings.contains(&format!("\"{alias}\"")) || settings.contains("\"vk-*\"")
}

/// Where the ProxyCommand comes back in: `wsl.exe -d <distro> -u <user>`.
struct Entry {
    distro: String,
    user: String,
}

fn entry() -> Result<Entry> {
    Ok(Entry {
        // The ProxyCommand requires a distro name; stop the bridge if it is missing.
        distro: distro().context("there is no Windows ssh to write a bridge for")?,
        user: unix_user()?,
    })
}

/// The distro user `wsl.exe -u` has to enter as. Named rather than left to the distro's
/// default user: the state directory, its key and the socket the ProxyCommand dials are this
/// user's, and another one reaches none of them.
fn unix_user() -> Result<String> {
    // No passwd entry (an LDAP lookup that is down, a uid nothing maps) leaves `$USER`,
    // the name the shell was started with. `self_passwd` reads it through the reentrant
    // `getpwuid_r`, the same lookup the rest of the crate uses.
    let name = match crate::hostpolicy::self_passwd() {
        Ok((name, _)) if !name.is_empty() => name,
        _ => std::env::var("USER").unwrap_or_default(),
    };
    if name.is_empty() {
        bail!("this uid has no user name to run the Windows ProxyCommand's `wsl.exe -u` as");
    }
    Ok(name)
}

/// Whether `binary` is a Windows program: DrvFs mounts each drive at `/mnt/<letter>`, and
/// nothing else there is a single-letter directory. Judged on the resolved path — a `code` on
/// PATH is usually a link — falling back to the path as given when it cannot be resolved.
fn is_windows_binary(binary: &Path) -> bool {
    let resolved = std::fs::canonicalize(binary);
    let mut parts = resolved.as_deref().unwrap_or(binary).components();
    let drive = |part: Option<Component>| {
        matches!(part, Some(Component::Normal(d))
            if d.to_str().is_some_and(|d| d.len() == 1 && d.starts_with(|c: char| c.is_ascii_alphabetic())))
    };
    parts.next() == Some(Component::RootDir)
        && parts.next() == Some(Component::Normal(OsStr::new("mnt")))
        && drive(parts.next())
        && parts.next().is_some()
}

/// Write the stanza, the key beside it and the include line that reaches them. Idempotent:
/// the stanza is rewritten, the key copied only when it differs, and the include added once.
fn write_bridge(w: &impl Windows, entry: &Entry, parts: &Parts, key: &Path) -> Result<Written> {
    let profile = w.user_profile()?;
    // Validate Windows arguments before creating any files or directories.
    let text = stanza(w, entry, parts, &profile)?;
    let ssh = profile.join(".ssh");
    if !ssh.is_dir() {
        bail!(
            "{} does not exist — create %USERPROFILE%\\.ssh on Windows (running `ssh` there \
             once is enough). The key copied into it inherits that directory's permissions, \
             and Windows OpenSSH refuses a private key other accounts can read",
            ssh.display()
        );
    }
    let dir = ssh.join("vk");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    copy_key(key, &dir.join(format!("{}.key", parts.alias)))?;
    let conf = dir.join(format!("{}.conf", parts.alias));
    vk_fs::write_atomic(&conf, text.as_bytes(), 0o600)
        .with_context(|| format!("writing {}", conf.display()))?;
    let config = ssh.join("config");
    let included = ensure_include(&config)?;
    Ok(Written {
        conf: w.to_windows(&conf)?,
        included: included.then(|| w.to_windows(&config)).transpose()?,
    })
}

/// The host block for Windows ssh.exe. `-e` runs `vk` in this distro with no shell in
/// between, so every word of the ProxyCommand travels as written — and Windows OpenSSH
/// splits that line on whitespace itself, so a value it would mangle is quoted or refused.
fn stanza(w: &impl Windows, entry: &Entry, parts: &Parts, profile: &Path) -> Result<String> {
    let vk = parts
        .vk
        .to_str()
        .with_context(|| format!("{} is not valid UTF-8", parts.vk.display()))?;
    Ok(format!(
        "# Written by `vk dev code`; rewritten on every launch.\n\
         Host {alias}\n    \
             User {user}\n    \
             IdentityFile {key}\n    \
             IdentitiesOnly yes\n    \
             IdentityAgent none\n    \
             StrictHostKeyChecking no\n    \
             UserKnownHostsFile NUL\n    \
             ProxyCommand {wsl} -d {distro} -u {as_user} -e {vk} connect {target}\n\
         \n\
         # Closes the Host block: the user's ssh_config includes this file at its top, and\n\
         # ssh keeps a block's match active across an Include, so without this its own later\n\
         # global options would be read inside this VM's Host block.\n\
         Match all\n",
        alias = parts.alias,
        user = bare(&parts.user, "the ssh user")?,
        key = win_arg(&win_key(w, profile, &parts.alias)?, "the copied key's path")?,
        wsl = win_arg(&w.wsl_exe()?, "the wsl.exe path")?,
        distro = win_arg(&entry.distro, "the WSL distro name")?,
        as_user = bare(&entry.user, "this user's name")?,
        vk = bare(vk, "this vk binary's path")?,
        target = bare(&parts.target, "the ssh proxy target")?,
    ))
}

/// The copied key, as Windows spells it. Built from the profile's Windows path rather than
/// translated from its own, so it can be named before it exists.
fn win_key(w: &impl Windows, profile: &Path, alias: &str) -> Result<String> {
    let profile = w.to_windows(profile)?;
    Ok(format!(
        "{}\\.ssh\\vk\\{alias}.key",
        profile.trim_end_matches('\\')
    ))
}

/// Copy the run's private key beside the stanza: it is the key the guest authorises, and
/// Windows ssh.exe cannot open the Linux path it lives at. Left alone when it already
/// matches — the managed key is stable across boots, so a relaunch normally writes nothing
/// on the Windows filesystem.
fn copy_key(src: &Path, dst: &Path) -> Result<()> {
    let key = std::fs::read(src).with_context(|| format!("reading {}", src.display()))?;
    if std::fs::read(dst).is_ok_and(|current| current == key) {
        return Ok(());
    }
    vk_fs::write_atomic(dst, &key, 0o600).with_context(|| format!("writing {}", dst.display()))
}

/// Make the user's `ssh_config` read the stanzas written here, and put the line at the top:
/// ssh reads an `Include` inside whatever `Host` block precedes it, so appended it would
/// scope these hosts to the user's last one. Returns whether it was added; what is already
/// in the file is preserved byte for byte, line endings included.
fn ensure_include(config: &Path) -> Result<bool> {
    let existing = match std::fs::read(config) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            return Err(anyhow::Error::new(e).context(format!("reading {}", config.display())));
        }
    };
    if existing
        .split(|b| *b == b'\n')
        .any(|line| line.trim_ascii() == INCLUDE.as_bytes())
    {
        return Ok(false);
    }
    // Match the file's own line ending so a CRLF ssh_config keeps consistent endings.
    let eol: &[u8] = if existing.windows(2).any(|w| w == b"\r\n") {
        b"\r\n"
    } else {
        b"\n"
    };
    let mut text = Vec::new();
    for line in [INCLUDE_NOTE.as_bytes(), INCLUDE.as_bytes(), b""] {
        text.extend_from_slice(line);
        text.extend_from_slice(eol);
    }
    text.extend_from_slice(&existing);
    vk_fs::write_atomic(config, &text, 0o600)
        .with_context(|| format!("writing {}", config.display()))?;
    Ok(true)
}

/// One `ssh_config` argument — a Windows path, or a distro name, both of which may hold a
/// space: double-quoted when it does, which is how it survives both the split Windows
/// OpenSSH does on `IdentityFile` and `ProxyCommand` and the `CreateProcess` that follows.
fn win_arg(value: &str, what: &str) -> Result<String> {
    if let Some(bad) = value
        .chars()
        .find(|c| matches!(c, '"' | '\'' | '%') || c.is_control())
    {
        bail!("{what} ({value:?}) contains {bad:?}, which cannot be quoted in an ssh config");
    }
    Ok(match value.contains(' ') {
        true => format!("\"{value}\""),
        false => value.to_string(),
    })
}

/// A value that has to reach `wsl.exe` as one unquoted word.
fn bare<'a>(value: &'a str, what: &str) -> Result<&'a str> {
    if let Some(bad) = value
        .chars()
        .find(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '%') || c.is_control())
    {
        bail!(
            "{what} ({value:?}) contains {bad:?}: a Windows ProxyCommand word is split on \
             whitespace, stripped of quotes, and percent-expanded by ssh, so it cannot carry one"
        );
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::testutil::{TmpDir, scratch};
    use crate::wsl::WSL_EXE;

    /// Fake interop with a real scratch profile and test-supplied Windows paths.
    struct Fake {
        profile: PathBuf,
        win_profile: String,
        wsl_exe: String,
    }

    impl Windows for Fake {
        fn user_profile(&self) -> Result<PathBuf> {
            Ok(self.profile.clone())
        }

        fn app_data(&self) -> Result<PathBuf> {
            Ok(self.profile.join("AppData/Roaming"))
        }

        fn to_windows(&self, path: &Path) -> Result<String> {
            let rel = path
                .strip_prefix(&self.profile)
                .with_context(|| format!("{} is outside the profile", path.display()))?;
            let mut win = self.win_profile.clone();
            for part in rel.components() {
                win.push('\\');
                win.push_str(part.as_os_str().to_str().unwrap());
            }
            Ok(win)
        }

        fn wsl_exe(&self) -> Result<String> {
            Ok(self.wsl_exe.clone())
        }
    }

    fn fake(profile: &Path, win_profile: &str, wsl_exe: &str) -> Fake {
        Fake {
            profile: profile.to_path_buf(),
            win_profile: win_profile.into(),
            wsl_exe: wsl_exe.into(),
        }
    }

    /// The distro to come back into, as the current user.
    fn entry(distro: &str) -> Entry {
        Entry {
            distro: distro.into(),
            user: "dev".into(),
        }
    }

    fn parts() -> Parts {
        Parts {
            alias: "vk-dev".into(),
            user: "dev".into(),
            vk: PathBuf::from("/usr/bin/vk"),
            target: "vsock-auto:///state/vsock.sock:2222".into(),
        }
    }

    /// A profile with `.ssh` in it and the run's key, as `write_bridge` expects to find them.
    fn profile_with_ssh(tag: &str) -> (TmpDir, PathBuf) {
        let t = scratch(tag);
        let profile = t.0.join("profile");
        std::fs::create_dir_all(profile.join(".ssh")).unwrap();
        std::fs::create_dir_all(t.0.join("state")).unwrap();
        std::fs::write(t.0.join("state/id_ed25519"), "PRIVATE\n").unwrap();
        (t, profile)
    }

    #[test]
    fn the_stanza_names_the_copied_key_and_proxies_back_into_the_distro() {
        let t = scratch("wsl-stanza");
        let w = fake(&t.0, r"C:\Users\dev", WSL_EXE);
        assert_eq!(
            stanza(&w, &entry("Ubuntu"), &parts(), &t.0).unwrap(),
            "# Written by `vk dev code`; rewritten on every launch.\n\
             Host vk-dev\n    \
                 User dev\n    \
                 IdentityFile C:\\Users\\dev\\.ssh\\vk\\vk-dev.key\n    \
                 IdentitiesOnly yes\n    \
                 IdentityAgent none\n    \
                 StrictHostKeyChecking no\n    \
                 UserKnownHostsFile NUL\n    \
                 ProxyCommand C:\\Windows\\System32\\wsl.exe -d Ubuntu -u dev -e /usr/bin/vk \
                 connect vsock-auto:///state/vsock.sock:2222\n\
             \n\
             # Closes the Host block: the user's ssh_config includes this file at its top, and\n\
             # ssh keeps a block's match active across an Include, so without this its own later\n\
             # global options would be read inside this VM's Host block.\n\
             Match all\n"
        );

        // Windows OpenSSH splits both keywords on whitespace, and hands the ProxyCommand to
        // CreateProcess, which keeps a quoted argument whole — so a value holding a space is
        // quoted, and only then.
        let w = fake(&t.0, r"C:\Users\Foo Bar", r"C:\Program Files\WSL\wsl.exe");
        let text = stanza(&w, &entry("My Distro"), &parts(), &t.0).unwrap();
        assert!(
            text.contains("IdentityFile \"C:\\Users\\Foo Bar\\.ssh\\vk\\vk-dev.key\"\n"),
            "{text}"
        );
        assert!(
            text.contains(
                "ProxyCommand \"C:\\Program Files\\WSL\\wsl.exe\" -d \"My Distro\" -u dev -e "
            ),
            "{text}"
        );
    }

    #[test]
    fn a_value_the_windows_proxycommand_cannot_carry_is_refused() {
        let t = scratch("wsl-refuse");
        let w = fake(&t.0, r"C:\Users\dev", WSL_EXE);
        // `-e` adds no shell to quote for, and ssh.exe strips quotes off the words it splits,
        // so whitespace or a quote in any of these has nowhere to hide.
        assert!(stanza(&w, &entry("Ubu\"ntu"), &parts(), &t.0).is_err());
        let mut spaced = entry("Ubuntu");
        spaced.user = "dev user".into();
        assert!(stanza(&w, &spaced, &parts(), &t.0).is_err());
        let mangles: [fn(&mut Parts); 3] = [
            |p| p.vk = PathBuf::from("/opt/vk tools/vk"),
            |p| p.target = "vsock-auto:///a b/v.sock:22".into(),
            |p| p.user = "dev user".into(),
        ];
        for mangle in mangles {
            let mut bad = parts();
            mangle(&mut bad);
            assert!(stanza(&w, &entry("Ubuntu"), &bad, &t.0).is_err(), "{bad:?}");
        }
        // A Windows path that cannot be quoted either way is refused rather than truncated.
        let w = fake(&t.0, "C:\\Users\\o\"dd", WSL_EXE);
        assert!(stanza(&w, &entry("Ubuntu"), &parts(), &t.0).is_err());
        // ssh percent-expands IdentityFile and ProxyCommand, so a `%` in an environment-
        // derived value — the distro name, or the profile baked into the key path — is
        // refused rather than silently expanded.
        let w = fake(&t.0, r"C:\Users\dev", WSL_EXE);
        assert!(stanza(&w, &entry("%h"), &parts(), &t.0).is_err());
        // The same guard on a `bare` value: a `%` in the proxy target ssh would expand.
        let mut pct = parts();
        pct.target = "vsock-auto:///a%h/x.sock:22".into();
        assert!(stanza(&w, &entry("Ubuntu"), &pct, &t.0).is_err());
        let w = fake(&t.0, r"C:\Users\de%v", WSL_EXE);
        assert!(stanza(&w, &entry("Ubuntu"), &parts(), &t.0).is_err());
    }

    #[test]
    fn the_bridge_is_written_once_and_rewritten_without_touching_the_key() {
        use std::os::unix::fs::MetadataExt;

        let (t, profile) = profile_with_ssh("wsl-write");
        let w = fake(&profile, r"C:\Users\dev", WSL_EXE);
        let key = t.0.join("state/id_ed25519");

        let written = write_bridge(&w, &entry("Ubuntu"), &parts(), &key).unwrap();
        assert_eq!(
            written.note(),
            "ssh bridge in C:\\Users\\dev\\.ssh\\vk\\vk-dev.conf \
             (Include vk/*.conf added to C:\\Users\\dev\\.ssh\\config)"
        );
        let copied = profile.join(".ssh/vk/vk-dev.key");
        assert_eq!(std::fs::read(&copied).unwrap(), b"PRIVATE\n");
        assert!(
            std::fs::read_to_string(profile.join(".ssh/vk/vk-dev.conf"))
                .unwrap()
                .contains("Host vk-dev\n")
        );
        let ino = std::fs::metadata(&copied).unwrap().ino();

        // A relaunch rewrites the stanza and leaves the identical key where it is: the
        // include line is already there, so it is not reported again either.
        let again = write_bridge(&w, &entry("Ubuntu"), &parts(), &key).unwrap();
        assert_eq!(
            again.note(),
            "ssh bridge in C:\\Users\\dev\\.ssh\\vk\\vk-dev.conf"
        );
        assert_eq!(std::fs::metadata(&copied).unwrap().ino(), ino);

        // A key that has changed — a state directory rebuilt from scratch — is copied again.
        std::fs::write(&key, "OTHER\n").unwrap();
        write_bridge(&w, &entry("Ubuntu"), &parts(), &key).unwrap();
        assert_eq!(std::fs::read(&copied).unwrap(), b"OTHER\n");
        assert_ne!(std::fs::metadata(&copied).unwrap().ino(), ino);
    }

    #[test]
    fn a_profile_without_a_ssh_directory_says_to_make_one() {
        let t = scratch("wsl-no-ssh");
        let profile = t.0.join("profile");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::write(t.0.join("key"), "PRIVATE\n").unwrap();
        let w = fake(&profile, r"C:\Users\dev", WSL_EXE);

        // The copied key inherits the directory's permissions, so vk does not invent it.
        let err = write_bridge(&w, &entry("Ubuntu"), &parts(), &t.0.join("key")).unwrap_err();
        assert!(format!("{err:#}").contains(".ssh"), "{err:#}");
        assert!(!profile.join(".ssh").exists());
    }

    #[test]
    fn the_include_goes_in_at_the_top_and_only_once() {
        let t = scratch("wsl-include");
        let config = t.0.join("config");

        // No config at all: one is created with nothing but the include.
        assert!(ensure_include(&config).unwrap());
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            "# Added by vk dev code: per-environment hosts.\nInclude vk/*.conf\n\n"
        );
        assert!(!ensure_include(&config).unwrap());

        // An existing config keeps its bytes and gains the line above them — an Include
        // appended after a Host block would be read inside it.
        let existing = "Host build\n    User ci\n";
        std::fs::write(&config, existing).unwrap();
        assert!(ensure_include(&config).unwrap());
        let text = std::fs::read_to_string(&config).unwrap();
        assert!(text.ends_with(existing), "{text}");
        assert!(text.starts_with(INCLUDE_NOTE), "{text}");

        // A CRLF config gets CRLF-terminated injected lines, not mixed endings.
        let crlf = "Host build\r\n    User ci\r\n";
        std::fs::write(&config, crlf).unwrap();
        assert!(ensure_include(&config).unwrap());
        let text = std::fs::read_to_string(&config).unwrap();
        assert!(text.ends_with(crlf), "{text:?}");
        assert!(
            text.starts_with(&format!("{INCLUDE_NOTE}\r\nInclude vk/*.conf\r\n\r\n")),
            "{text:?}"
        );

        // A line already there in either line ending leaves the file exactly as it is.
        for content in [
            "Include vk/*.conf\nHost build\n",
            "# mine\r\n    Include vk/*.conf\r\nHost build\r\n",
        ] {
            std::fs::write(&config, content).unwrap();
            assert!(!ensure_include(&config).unwrap());
            assert_eq!(std::fs::read_to_string(&config).unwrap(), content);
        }
    }

    #[test]
    fn the_platform_quick_pick_is_pointed_out_until_the_settings_answer_it() {
        let t = scratch("wsl-hint");
        let w = fake(&t.0, r"C:\Users\dev", WSL_EXE);
        let settings = settings_path(&w.app_data().unwrap(), Channel::Stable).unwrap();
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();

        // No settings file yet — a fresh install, the launch that most surely meets the
        // prompt — is unanswered, so it gets the hint (and never fails on the missing file).
        let hint = hint_for(&w, "vk-dev", Channel::Stable).expect("a hint on a missing file");
        assert!(hint.contains("platform of 'vk-dev'"), "{hint}");

        std::fs::write(&settings, "{\n  \"editor.formatOnSave\": true\n}\n").unwrap();
        let hint = hint_for(&w, "vk-dev", Channel::Stable).expect("a hint");
        assert!(hint.contains("platform of 'vk-dev'"), "{hint}");
        assert!(hint.contains("\"vk-*\": \"linux\""), "{hint}");

        // Either the alias itself or the pattern that covers every one of these aliases is
        // an answer already given.
        for answered in [
            "{ \"remote.SSH.remotePlatform\": { \"vk-*\": \"linux\" } }",
            "{ \"remote.SSH.remotePlatform\": { \"vk-dev\": \"linux\" } }",
        ] {
            std::fs::write(&settings, answered).unwrap();
            assert_eq!(hint_for(&w, "vk-dev", Channel::Stable), None, "{answered}");
        }

        // Insiders uses a separate settings directory. Do not guess the other channels'
        // directories; they get no hint.
        assert!(
            settings_path(Path::new("/a"), Channel::Insiders)
                .unwrap()
                .ends_with("Code - Insiders/User/settings.json")
        );
        assert_eq!(settings_path(Path::new("/a"), Channel::Codium), None);
        assert_eq!(hint_for(&w, "vk-dev", Channel::Oss), None);
    }

    #[test]
    fn only_an_editor_under_a_drive_mount_is_a_windows_one() {
        for windows in [
            "/mnt/c/Users/dev/AppData/Local/Programs/Microsoft VS Code/bin/code",
            "/mnt/d/tools/code",
        ] {
            assert!(is_windows_binary(Path::new(windows)), "{windows}");
        }
        // A Linux editor, a mount that is not a drive, and the mount point itself.
        for linux in [
            "/usr/bin/code",
            "/opt/vscode/code",
            "/mnt/data/code",
            "/mnt/c",
            "mnt/c/code",
        ] {
            assert!(!is_windows_binary(Path::new(linux)), "{linux}");
        }
    }
}
