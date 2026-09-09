//! Managed SSH client artifacts created by `vk run --ssh-client`: a keypair,
//! `ssh-config`, and `ssh`, `scp` and `sftp` shims in the run's state dir.
//!
//! Unlike `vk run --ssh`, which authorises the user's `~/.ssh` keys and prints a command,
//! this mode supports tools that cannot pass `-F` (such as VS Code Remote-SSH and Emacs
//! TRAMP). The shims supply a config containing the managed key and `vsock-auto://`
//! ProxyCommand. VS Code connects with bare `ssh` but copies its server with bare `scp`,
//! so all three OpenSSH client programs are shimmed, not `ssh` alone.
//!
//! The state dir must remain host-owned because the host executes the ProxyCommand and
//! owns the private key. [`check_state_dir_is_host_only`] rejects writable guest shares
//! that contain the state dir or target a managed artifact.

use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// The managed private key; the public half is this plus `.pub`.
const KEY: &str = "id_ed25519";
/// The generated client config — what `ssh -F` (and `vk ssh`) reads.
pub const CONFIG: &str = "ssh-config";
/// Directory holding the client shims, meant to be prepended to PATH.
const SHIM_DIR: &str = "bin";
/// The OpenSSH client programs shimmed into [`SHIM_DIR`]. VS Code Remote-SSH spawns
/// bare `ssh` to connect and bare `scp` to copy its server; TRAMP and others reach for
/// `sftp`. Each takes `-F`, so every shim points the system tool at this run's config.
const SHIMMED: [&str; 3] = ["ssh", "scp", "sftp"];

/// The managed client artifacts of one run, addressed by its state dir.
pub struct Managed {
    dir: PathBuf,
}

impl Managed {
    /// Resolve the state dir so the config and shim work from any directory.
    pub fn new(state_dir: &Path) -> Result<Self> {
        let dir = std::fs::canonicalize(state_dir)
            .with_context(|| format!("resolving the state directory {}", state_dir.display()))?;
        Ok(Self { dir })
    }

    pub fn key(&self) -> PathBuf {
        self.dir.join(KEY)
    }

    pub fn pubkey(&self) -> PathBuf {
        self.dir.join(format!("{KEY}.pub"))
    }

    pub fn config(&self) -> PathBuf {
        self.dir.join(CONFIG)
    }

    /// The directory to prepend to PATH so a program that spawns bare `ssh`, `scp` or
    /// `sftp` reaches this run's VM. Each program is shimmed as a file of the same name
    /// under here.
    pub fn shim_dir(&self) -> PathBuf {
        self.dir.join(SHIM_DIR)
    }

    /// The config as written by the run that owns this state dir.
    fn read_config(&self) -> Result<String> {
        std::fs::read_to_string(self.config()).with_context(|| {
            format!(
                "no managed SSH setup in {} — boot the VM with `vk run --ssh-client \
                 --state-dir {}`",
                self.dir.display(),
                self.dir.display()
            )
        })
    }

    /// Read the run's alias from its config so `vk ssh` need not receive it separately.
    fn alias(&self) -> Result<String> {
        host_alias(&self.read_config()?).with_context(|| self.config().display().to_string())
    }

    /// The pieces of the config another ssh client needs to reach the same VM. Read back as
    /// data and revalidated: the config is the host's, but a client built from it runs the
    /// ProxyCommand, so nothing goes through unchecked.
    pub fn parts(&self) -> Result<Parts> {
        parse_parts(&self.read_config()?).with_context(|| self.config().display().to_string())
    }

    /// Create or reuse the keypair, rewrite the config and shim, and return the public key.
    /// The stable key keeps authorization valid across boots; regenerated client files
    /// pick up fixes.
    pub fn provision(
        &self,
        alias: &str,
        user: &str,
        ssh_target: &str,
        path_var: Option<&OsStr>,
    ) -> Result<String> {
        validate_alias(alias)?;
        let vk = std::env::current_exe().context("locating this vk binary")?;
        // Reject values that cannot be quoted safely in the shell-run ProxyCommand.
        quotable(&self.dir, "the state directory")?;
        quotable(&vk, "this vk binary's path")?;
        quotable(Path::new(ssh_target), "the ssh proxy target")?;
        // Keep this module safe independently of clap's --ssh-user parser.
        quotable_str(user, "the ssh user")?;

        let pubkey = self.ensure_key(alias, path_var)?;
        write_atomic(
            &self.config(),
            &self.config_text(alias, user, &vk, ssh_target),
            0o600,
        )
        .with_context(|| format!("writing {}", self.config().display()))?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(self.shim_dir())
            .with_context(|| format!("creating {}", self.shim_dir().display()))?;
        for tool in SHIMMED {
            let path = self.shim_dir().join(tool);
            write_atomic(&path, &self.shim_text(tool, path_var)?, 0o755)
                .with_context(|| format!("writing {}", path.display()))?;
        }
        Ok(pubkey)
    }

    /// The keypair, generated on first use and reused after. Returns the public key.
    fn ensure_key(&self, alias: &str, path_var: Option<&OsStr>) -> Result<String> {
        if self.key().is_file() && self.pubkey().is_file() {
            return read_pubkey(&self.pubkey());
        }
        // Generate in a private directory and publish the private key last, so its
        // presence means the pair is complete.
        let tmp = self.dir.join(format!(".ssh-key.{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        // Refuse a leftover directory whose mode and owner are unknown.
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        let keygen = which("ssh-keygen", path_var, None).map_err(|_| {
            anyhow::anyhow!(
                "--ssh-client needs `ssh-keygen` on PATH to make its key (it ships with \
                 the OpenSSH client the mode is for)"
            )
        })?;
        let result = generate_key(&keygen, &tmp.join(KEY), alias).and_then(|()| {
            std::fs::rename(tmp.join(format!("{KEY}.pub")), self.pubkey())?;
            std::fs::rename(tmp.join(KEY), self.key())?;
            read_pubkey(&self.pubkey())
        });
        let _ = std::fs::remove_dir_all(&tmp);
        result
    }

    /// The client config. The `Host` block pins everything about this one connection —
    /// notably the managed key first and no agent at all (`IdentityAgent none`), so ssh
    /// never asks the user to unlock a hardware key for a VM that does not want it.
    /// `IdentitiesOnly yes` restricts ssh to configured identities, not to this one:
    /// `IdentityFile` accumulates, so a `Host *` identity in the included user config is
    /// still offered — after the managed key, which is the one the guest authorises. The
    /// host key is ephemeral, generated per boot and reached over a private vsock, so
    /// there is nothing to remember about it.
    fn config_text(&self, alias: &str, user: &str, vk: &Path, ssh_target: &str) -> String {
        format!(
            "# Written by `vk run --ssh-client`; rewritten on every boot of this run.\n\
             Host {alias}\n    \
                 User {user}\n    \
                 IdentityFile \"{key}\"\n    \
                 IdentitiesOnly yes\n    \
                 IdentityAgent none\n    \
                 StrictHostKeyChecking no\n    \
                 UserKnownHostsFile /dev/null\n    \
                 ProxyCommand '{vk}' connect '{ssh_target}'\n\
             \n\
             # Closes the Host block above. Without it the include below would be read\n\
             # inside it, and the user's own hosts would apply to this VM alone.\n\
             Match all\n\
             \n\
             Include ~/.ssh/config\n",
            key = self.key().display(),
            vk = vk.display(),
        )
    }

    /// Build a shim for one OpenSSH tool that supplies this run's config. Resolve the real
    /// client to an absolute path now so later PATH changes cannot recurse into the shim.
    fn shim_text(&self, tool: &str, path_var: Option<&OsStr>) -> Result<String> {
        let real = real_tool(tool, &self.shim_dir(), path_var)?;
        quotable(&real, "the system OpenSSH client path")?;
        Ok(format!(
            "#!/bin/sh\n\
             # Written by `vk run --ssh-client`: the system {tool}, pointed at this run's VM.\n\
             # Put this directory first on PATH for a program that spawns bare `{tool}`.\n\
             # A caller passing its own -F wins: {tool} takes the last one.\n\
             exec '{real}' -F '{config}' \"$@\"\n",
            real = real.display(),
            config = self.config().display(),
        ))
    }
}

/// Replace this process with system ssh using the run's managed config and alias.
/// Append `args` without shell parsing; return only if exec fails.
pub fn exec_ssh(state_dir: &Path, args: &[String]) -> Result<std::convert::Infallible> {
    use std::os::unix::process::CommandExt;
    let m = Managed::new(state_dir)?;
    let alias = m.alias()?;
    let real = real_ssh(&m.shim_dir(), std::env::var_os("PATH").as_deref())?;
    let mut cmd = std::process::Command::new(&real);
    cmd.arg("-F").arg(m.config()).arg(alias).args(args);
    Err(anyhow::Error::new(cmd.exec()).context(format!("running {}", real.display())))
}

/// `vk ssh-config`: the run's stanza, as written.
pub fn print_config(state_dir: &Path) -> Result<()> {
    let m = Managed::new(state_dir)?;
    // Written, not `print!`ed: a closed pipe (`vk ssh-config DIR | head -1`) is an error to
    // report, not a panic.
    std::io::stdout()
        .write_all(m.read_config()?.as_bytes())
        .context("writing the ssh config to stdout")
}

/// Connection data read from a run's config to build an equivalent host block for a client
/// without access to that config or filesystem.
#[derive(Debug, PartialEq)]
pub struct Parts {
    /// the run's `Host` alias
    pub alias: String,
    /// the `User` ssh connects as
    pub user: String,
    /// the `vk` the ProxyCommand runs
    pub vk: PathBuf,
    /// what that `vk connect` dials
    pub target: String,
}

/// The run's `Host` alias, revalidated before it reaches ssh as an argument.
fn host_alias(config: &str) -> Result<String> {
    let alias = config
        .lines()
        .find_map(|l| l.strip_prefix("Host ").map(str::trim))
        .filter(|a| !a.is_empty())
        .context("declares no Host alias")?;
    validate_alias(alias)?;
    Ok(alias.to_string())
}

fn parse_parts(config: &str) -> Result<Parts> {
    // First occurrence wins, as ssh reads it. `User ` cannot match `UserKnownHostsFile`.
    let value = |key: &str| {
        config
            .lines()
            .find_map(|l| l.trim_start().strip_prefix(key))
            .map(str::trim)
            .filter(|v| !v.is_empty())
    };
    let user = value("User ").context("declares no User")?;
    quotable_str(user, "the ssh user")?;
    let proxy = value("ProxyCommand ").context("declares no ProxyCommand")?;
    let (vk, target) = parse_proxy(proxy)
        .with_context(|| format!("ProxyCommand {proxy:?} is not one this vk wrote"))?;
    quotable(&vk, "this vk binary's path")?;
    quotable_str(&target, "the ssh proxy target")?;
    Ok(Parts {
        alias: host_alias(config)?,
        user: user.to_string(),
        vk,
        target,
    })
}

/// Split `'<vk>' connect '<target>'` — what [`Managed::config_text`] writes — back into its
/// two values. Neither can contain a single quote ([`quotable`] refuses one), so the next
/// quote is always the closing one.
fn parse_proxy(command: &str) -> Option<(PathBuf, String)> {
    let (vk, rest) = command.strip_prefix('\'')?.split_once('\'')?;
    let target = rest.strip_prefix(" connect '")?.strip_suffix('\'')?;
    Some((PathBuf::from(vk), target.to_string()))
}

/// Resolve a system OpenSSH client program (`ssh`, `scp` or `sftp`), skipping the shim's
/// own directory so a PATH with it prepended resolves to the real tool rather than back
/// into the shim. Directories are compared as paths after resolution, not as strings:
/// `bin`, `./bin` and a symlink to it are the same directory.
pub fn real_tool(tool: &str, shim_dir: &Path, path_var: Option<&OsStr>) -> Result<PathBuf> {
    which(tool, path_var, Some(shim_dir)).map_err(|_| {
        anyhow::anyhow!(
            "no `{tool}` on PATH (other than the shim in {}) — the managed SSH client needs \
             an OpenSSH client (ssh, scp and sftp) installed",
            shim_dir.display()
        )
    })
}

/// The system `ssh`. See [`real_tool`].
pub fn real_ssh(shim_dir: &Path, path_var: Option<&OsStr>) -> Result<PathBuf> {
    real_tool("ssh", shim_dir, path_var)
}

/// Resolve `name` on `path_var`, skipping `skip_dir`, and return an absolute path suitable
/// for a shim that may run from another directory.
fn which(name: &str, path_var: Option<&OsStr>, skip_dir: Option<&Path>) -> Result<PathBuf> {
    crate::shell::which_all(name, path_var, skip_dir)
        .find_map(|candidate| std::fs::canonicalize(candidate).ok())
        .with_context(|| format!("no `{name}` on PATH"))
}

/// Reject config metacharacters and patterns in an `ssh_config` `Host` alias. For example,
/// `Host dev *` would apply this VM's identity and ProxyCommand to every host.
pub fn validate_alias(alias: &str) -> Result<()> {
    if alias.is_empty() || alias.len() > 64 {
        bail!("ssh alias {alias:?} must be 1..=64 characters");
    }
    if let Some(bad) = alias
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
    {
        bail!("ssh alias {alias:?}: {bad:?} is not allowed (want letters, digits, '.', '_', '-')");
    }
    Ok(())
}

/// Refuse a state dir the guest can write. The config's ProxyCommand and the shim are
/// executed on the *host*, and the private key is the host's: a guest able to rewrite them
/// would be running commands on the host, not merely misconfiguring itself.
///
/// Writable is the line, not readable: a guest that can *read* the state dir through a
/// read-only share learns the key, and the key is deliberately reused, so it could reach a
/// later boot of the same state dir. Sharing a tree that holds host private keys already
/// says that much, so the check does not go further.
pub fn check_state_dir_is_host_only<'a>(
    state_dir: &Path,
    volumes: impl IntoIterator<Item = &'a crate::compose::Volume>,
    extra_rw: impl IntoIterator<Item = (&'a Path, &'a str)>,
) -> Result<()> {
    // Resolve every path and reject failures so symlink aliases cannot bypass the check.
    let resolve = |p: &Path| -> Result<PathBuf> {
        std::fs::canonicalize(p).with_context(|| format!("resolving {}", p.display()))
    };
    let dir = resolve(state_dir)?;
    // Reject both a state dir inside a share and a share targeting a managed artifact.
    let managed = [
        dir.join(KEY),
        dir.join(format!("{KEY}.pub")),
        dir.join(CONFIG),
        dir.join(SHIM_DIR),
    ];
    let from_volumes = volumes.into_iter().filter_map(|v| {
        // These modes cannot modify a shared host tree; socket volumes expose only bytes.
        (!(v.read_only || v.overlay || v.disk || v.socket))
            .then_some((v.host.as_path(), v.guest.as_str()))
    });
    for (host, guest) in from_volumes.chain(extra_rw) {
        let host = resolve(host)?;
        // Other shares below the state dir remain allowed.
        let hits_managed = |a: &Path| a.starts_with(&host) || host.starts_with(a);
        if dir.starts_with(&host) || managed.iter().any(|a| hits_managed(a)) {
            bail!(
                "the state dir {} overlaps {}, which the guest mounts read-write at {guest}: \
                 its SSH key and ProxyCommand are the host's, so the guest must not be able \
                 to rewrite them — put the state dir outside every writable share",
                dir.display(),
                host.display(),
            );
        }
    }
    Ok(())
}

/// Reject a path that cannot be written into the config verbatim. The `ProxyCommand` line
/// is handed to `/bin/sh`, so `$` and a backtick would run something; ssh percent-expands
/// `IdentityFile` and `ProxyCommand`, so a `%` either dies on an unknown token or silently
/// names another file; and a quote, a backslash or a control character ends the value
/// somewhere other than where it reads.
fn quotable(p: &Path, what: &str) -> Result<()> {
    let s = p
        .to_str()
        .with_context(|| format!("{what} ({}) is not valid UTF-8", p.display()))?;
    quotable_str(s, what)
}

fn quotable_str(s: &str, what: &str) -> Result<()> {
    if let Some(bad) = s
        .chars()
        .find(|c| matches!(c, '"' | '\'' | '\\' | '%' | '$' | '`') || c.is_control())
    {
        bail!("{what} ({s:?}) contains {bad:?}, which cannot be quoted in an ssh config");
    }
    Ok(())
}

fn read_pubkey(path: &Path) -> Result<String> {
    let key = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?
        .trim()
        .to_string();
    if key.is_empty() {
        bail!("{} is empty — delete it and boot again", path.display());
    }
    Ok(key)
}

/// Generate the keypair with the caller-resolved `ssh-keygen`. Managed mode already
/// requires the OpenSSH client, which also provides this tool.
fn generate_key(keygen: &Path, at: &Path, comment: &str) -> Result<()> {
    let out = std::process::Command::new(keygen)
        .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"])
        .arg(at)
        .output()
        .with_context(|| format!("running {}", keygen.display()))?;
    if !out.status.success() {
        bail!(
            "ssh-keygen failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Write `contents` at `path`, private from the moment it exists and published whole.
fn write_atomic(path: &Path, contents: &str, mode: u32) -> Result<()> {
    vk_fs::write_atomic(path, contents.as_bytes(), mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TmpDir(PathBuf);
    impl Drop for TmpDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    fn tmpdir(tag: &str) -> TmpDir {
        let dir = std::env::temp_dir().join(format!("vk-sshclient-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TmpDir(dir)
    }

    // Stand in for ssh-keygen so the test does not depend on the host's OpenSSH install.
    fn fake_ssh_keygen(dir: &Path) -> PathBuf {
        let p = dir.join("ssh-keygen");
        std::fs::write(
            &p,
            "#!/bin/sh\n\
             while [ $# -gt 0 ]; do case \"$1\" in -f) f=$2; shift ;; esac; shift; done\n\
             [ -n \"$f\" ] || exit 2\n\
             (umask 077; printf 'PRIVATE\\n' > \"$f\")\n\
             printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAtest fake\\n' > \"$f.pub\"\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn fake_tool(dir: &Path, name: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, "#!/bin/sh\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn fake_ssh(dir: &Path) -> PathBuf {
        fake_tool(dir, "ssh")
    }

    // Stand-ins for every OpenSSH client program the shims point at, so `provision` can
    // resolve `scp` and `sftp` as well as `ssh`.
    fn fake_openssh(dir: &Path) {
        for tool in SHIMMED {
            fake_tool(dir, tool);
        }
    }

    #[test]
    fn the_real_ssh_is_never_the_shim_itself() {
        let t = tmpdir("realssh");
        let shim_dir = t.0.join("state/bin");
        let system = t.0.join("usr/bin");
        fake_ssh(&shim_dir);
        let real = fake_ssh(&system);

        // A prepended shim directory resolves past itself to the system client.
        let path = std::env::join_paths([shim_dir.clone(), system.clone()]).unwrap();
        assert_eq!(real_ssh(&shim_dir, Some(&path)).unwrap(), real);

        // Named differently but the same directory: a trailing `/.`, and a symlink to it.
        let aliased = t.0.join("link-to-bin");
        std::os::unix::fs::symlink(&shim_dir, &aliased).unwrap();
        let path = std::env::join_paths([shim_dir.join("."), aliased, system.clone()]).unwrap();
        assert_eq!(real_ssh(&shim_dir, Some(&path)).unwrap(), real);

        // Nothing but the shim: an error, rather than a shim that would exec itself.
        let path = std::env::join_paths([shim_dir.clone()]).unwrap();
        assert!(real_ssh(&shim_dir, Some(&path)).is_err());
        // A mangled PATH — empty entries, a directory that does not exist — is skipped,
        // not fatal.
        let path = std::env::join_paths([
            PathBuf::from(""),
            t.0.join("nowhere"),
            shim_dir.clone(),
            system.clone(),
        ])
        .unwrap();
        assert_eq!(real_ssh(&shim_dir, Some(&path)).unwrap(), real);
        assert!(real_ssh(&shim_dir, None).is_err());

        // A relative PATH entry still resolves absolutely: the answer is written into the
        // shim, which runs from whatever directory the spawning program happens to be in.
        let here = std::env::current_dir().unwrap();
        let path = std::env::join_paths([pathdiff_from_cwd(&system)]).unwrap();
        let found = real_ssh(&shim_dir, Some(&path)).unwrap();
        assert!(found.is_absolute(), "{}", found.display());
        assert_eq!(std::env::current_dir().unwrap(), here);
    }

    #[test]
    fn an_alias_may_not_carry_a_pattern_or_metacharacters() {
        assert!(validate_alias("vm-microvm").is_ok());
        assert!(validate_alias("wab.dev_1").is_ok());
        for bad in ["", "a b", "*", "vm?", "vm\nHost *", "vm\"", "vm#c", "="] {
            assert!(validate_alias(bad).is_err(), "{bad:?} should be refused");
        }
        assert!(validate_alias(&"a".repeat(65)).is_err());
    }

    #[test]
    fn a_state_dir_inside_a_writable_share_is_refused() {
        let t = tmpdir("statedir");
        let repo = t.0.join("repo");
        std::fs::create_dir_all(repo.join("state")).unwrap();
        let vol = |host: &Path, mode: &str| {
            crate::compose::parse_volume(
                &format!("{}:/workdir:{mode}", host.display()),
                Path::new("/b"),
            )
            .unwrap()
            .unwrap()
        };

        let none: [(&Path, &str); 0] = [];

        // Inside a read-write share: the guest could rewrite the key and the ProxyCommand.
        let err = check_state_dir_is_host_only(&repo.join("state"), &[vol(&repo, "rw")], none)
            .unwrap_err();
        assert!(format!("{err:#}").contains("read-write"), "{err:#}");

        // The `--workdir` share is not in the volume list and is always read-write, so a
        // state dir under it is the same escalation.
        let err =
            check_state_dir_is_host_only(&repo.join("state"), &[], [(repo.as_path(), "/work")])
                .unwrap_err();
        assert!(format!("{err:#}").contains("/work"), "{err:#}");

        // Nested the other way: a share aimed at a managed artifact from inside the state
        // dir rewrites the very files the host runs.
        std::fs::create_dir_all(repo.join("state/bin")).unwrap();
        let err = check_state_dir_is_host_only(
            &repo.join("state"),
            &[vol(&repo.join("state/bin"), "rw")],
            none,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("overlaps"), "{err:#}");
        // A share elsewhere under the state dir is the caller's business.
        std::fs::create_dir_all(repo.join("state/data")).unwrap();
        assert!(
            check_state_dir_is_host_only(
                &repo.join("state"),
                &[vol(&repo.join("state/data"), "rw")],
                none
            )
            .is_ok()
        );

        // A share path that cannot be resolved fails the check rather than passing it.
        assert!(
            check_state_dir_is_host_only(
                &repo.join("state"),
                &[],
                [(t.0.join("gone").as_path(), "/x")]
            )
            .is_err()
        );

        // The same tree shared read-only, or behind an overlay, cannot be written back.
        assert!(
            check_state_dir_is_host_only(&repo.join("state"), &[vol(&repo, "ro")], none).is_ok()
        );
        assert!(
            check_state_dir_is_host_only(&repo.join("state"), &[vol(&repo, "overlay")], none)
                .is_ok()
        );
        // Outside every share.
        std::fs::create_dir_all(t.0.join("elsewhere")).unwrap();
        assert!(
            check_state_dir_is_host_only(&t.0.join("elsewhere"), &[vol(&repo, "rw")], none).is_ok()
        );
    }

    #[test]
    fn provisioning_writes_a_reusable_key_and_a_config_that_pins_it() {
        let t = tmpdir("provision");
        let system = t.0.join("usr/bin");
        fake_openssh(&system);
        fake_ssh_keygen(&system);
        // Pass a private PATH to avoid the host's OpenSSH without mutating process state.
        let path = std::env::join_paths([&system]).unwrap();
        let path = Some(path.as_os_str());

        let m = Managed::new(&t.0).unwrap();
        let key = m
            .provision("vm-test", "dev", "vsock-auto:///tmp/v.sock:2222", path)
            .unwrap();
        assert!(key.starts_with("ssh-ed25519 "), "{key}");

        use std::os::unix::fs::PermissionsExt;
        let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(m.key()), 0o600);
        assert_eq!(mode(m.config()), 0o600);
        // Every OpenSSH client program is shimmed, not `ssh` alone: VS Code Remote-SSH
        // copies its server with bare `scp`, which reads the user's ~/.ssh/config and
        // cannot resolve the run's alias unless it too goes through the shim. Each shim
        // runs the system tool with the config applied — single quotes, so nothing in
        // either path is expanded by the shell that runs it.
        for tool in SHIMMED {
            let shim = m.shim_dir().join(tool);
            assert_eq!(mode(shim.clone()), 0o755, "{tool} shim");
            let text = std::fs::read_to_string(&shim).unwrap();
            assert!(
                text.contains(&format!(
                    "exec '{}' -F '{}'",
                    system.join(tool).display(),
                    m.config().display()
                )),
                "{tool} shim points at the system {tool} with -F: {text}"
            );
        }

        let cfg = std::fs::read_to_string(m.config()).unwrap();
        assert!(cfg.contains("Host vm-test\n"));
        assert!(cfg.contains("IdentitiesOnly yes"));
        assert!(cfg.contains("IdentityAgent none"));
        assert!(cfg.contains("vsock-auto:///tmp/v.sock:2222"));
        // The include must sit outside the Host block, or the user's own hosts would be
        // scoped to this VM.
        let (host_block, rest) = cfg.split_once("Match all").expect("a Match all");
        assert!(!host_block.contains("Include"));
        assert!(rest.contains("Include ~/.ssh/config"));

        // Re-provisioning keeps the key (the alias stays reachable across reboots) and
        // rewrites the config.
        let again = m
            .provision("vm-test", "root", "vsock-auto:///tmp/v.sock:2222", path)
            .unwrap();
        assert_eq!(key, again);
        assert!(
            std::fs::read_to_string(m.config())
                .unwrap()
                .contains("User root")
        );
    }

    #[test]
    fn a_relative_state_dir_still_yields_absolute_paths() {
        let t = tmpdir("relative");
        let system = t.0.join("usr/bin");
        fake_openssh(&system);
        fake_ssh_keygen(&system);
        let path = std::env::join_paths([&system]).unwrap();

        // The shim and the config are read by an ssh run from an unrelated directory, so
        // a relative `--state-dir` must not survive into either.
        let rel = pathdiff_from_cwd(&t.0);
        let m = Managed::new(&rel).unwrap();
        m.provision(
            "vm-test",
            "dev",
            "vsock-auto:///tmp/v.sock:2222",
            Some(&path),
        )
        .unwrap();
        assert!(m.config().is_absolute(), "{}", m.config().display());
        for line in std::fs::read_to_string(m.config()).unwrap().lines() {
            if let Some(f) = line.trim().strip_prefix("IdentityFile ") {
                assert!(f.starts_with('"') && f[1..].starts_with('/'), "{line}");
            }
        }
        assert!(
            std::fs::read_to_string(m.shim_dir().join("ssh"))
                .unwrap()
                .contains("-F '/"),
            "the shim must name the config absolutely"
        );
    }

    // The temp dir as a path relative to the current directory, so the test can hand
    // `Managed` a relative `--state-dir` without moving the process's cwd.
    fn pathdiff_from_cwd(dir: &Path) -> PathBuf {
        let cwd = std::env::current_dir().unwrap();
        let mut rel = PathBuf::new();
        for _ in cwd.components() {
            rel.push("..");
        }
        rel.join(dir.strip_prefix("/").unwrap())
    }

    #[test]
    fn the_alias_is_read_back_out_of_the_config() {
        let t = tmpdir("alias");
        let m = Managed::new(&t.0).unwrap();

        // No setup yet: the error says how to make one, rather than naming a missing file.
        let err = m.alias().unwrap_err();
        assert!(format!("{err:#}").contains("--ssh-client"), "{err:#}");

        // `vk ssh` takes the alias from the config, so the caller need not repeat it.
        write_atomic(&m.config(), "Host vm-test\n    User dev\n", 0o600).unwrap();
        assert_eq!(m.alias().unwrap(), "vm-test");
        // An alias the config cannot have been written with is refused on the way back
        // out, rather than handed to ssh as an argument.
        write_atomic(&m.config(), "Host vm *\n", 0o600).unwrap();
        assert!(m.alias().is_err());
        // `vk ssh-config` on a directory with no setup names the flag that makes one.
        assert!(print_config(&t.0.join("nothing-here")).is_err());

        // A config with no Host line is a corrupt setup, not an empty alias.
        write_atomic(&m.config(), "User dev\n", 0o600).unwrap();
        assert!(m.alias().is_err());
    }

    #[test]
    fn the_config_is_read_back_into_its_parts() {
        let m = Managed {
            dir: PathBuf::from("/state"),
        };
        let cfg = m.config_text(
            "vm-test",
            "dev",
            Path::new("/usr/bin/vk"),
            "vsock-auto:///state/vsock.sock:2222",
        );
        assert_eq!(
            parse_parts(&cfg).unwrap(),
            Parts {
                alias: "vm-test".into(),
                user: "dev".into(),
                vk: PathBuf::from("/usr/bin/vk"),
                target: "vsock-auto:///state/vsock.sock:2222".into(),
            }
        );

        // Rebuilding a connection requires Host, User and ProxyCommand.
        for cfg in [
            "Host vm\n    User dev\n",
            "Host vm\n    ProxyCommand '/usr/bin/vk' connect 'x'\n",
            "User dev\n    ProxyCommand '/usr/bin/vk' connect 'x'\n",
        ] {
            assert!(parse_parts(cfg).is_err(), "{cfg:?} should be refused");
        }
        // Revalidate the alias and user even in a well-formed on-disk config.
        for cfg in [
            "Host vm*\n    User dev\n    ProxyCommand '/usr/bin/vk' connect 'x'\n",
            "Host vm\n    User de$v\n    ProxyCommand '/usr/bin/vk' connect 'x'\n",
        ] {
            assert!(parse_parts(cfg).is_err(), "{cfg:?} should be refused");
        }
        // Reject unexpected ProxyCommand syntax and values that cannot be safely quoted.
        for proxy in [
            "/usr/bin/vk connect x",
            "'/usr/bin/vk' 'connect' 'x'",
            "'/usr/bin/vk' connect 'a b' extra",
            "'/tmp/$(id)/vk' connect 'x'",
        ] {
            let cfg = format!("Host vm\n    User dev\n    ProxyCommand {proxy}\n");
            assert!(parse_parts(&cfg).is_err(), "{proxy:?} should be refused");
        }
        // `UserKnownHostsFile` is not the `User` line.
        let cfg = "Host vm\n    UserKnownHostsFile /dev/null\n    User dev\n    ProxyCommand \
                   '/usr/bin/vk' connect 'x'\n";
        assert_eq!(parse_parts(cfg).unwrap().user, "dev");
    }

    #[test]
    fn a_path_that_a_shell_or_ssh_would_expand_is_refused() {
        // `$(…)` and a backtick would run in the ProxyCommand's shell; `%h` is an ssh
        // percent-expansion; a quote or a newline ends the value early.
        for bad in [
            "/tmp/$(touch pwned)/state",
            "/tmp/`id`/state",
            "/tmp/%h/state",
            "/tmp/a\"b/state",
            "/tmp/a\nHost */state",
        ] {
            assert!(
                quotable(Path::new(bad), "the state directory").is_err(),
                "{bad:?} should be refused"
            );
        }
        assert!(quotable(Path::new("/home/u/.local/state/vk-1"), "x").is_ok());
    }
}
