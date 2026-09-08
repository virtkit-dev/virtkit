//! Resolve `[dev.ssh]` into `vk run` inputs: the agent-filter allowlist (`.pub` paths)
//! and generated guest `~/.ssh/config`.
//!
//! A whitelist token names an identity the forwarded agent may offer. It is one of:
//!   * a `SHA256:…` fingerprint, matched against the running agent's keys;
//!   * a path — one holding a `/` or starting with `~` — taken as a `.pub` file;
//!   * a bare name (`work` or `work.pub`), taken as `~/.ssh/<name>.pub` when that exists, else
//!     as a key comment matched against the agent.
//!
//! Fingerprint and comment matches yield wire blobs, written to scratch `.pub` files for
//! the filtering proxy shared with `--ssh-host`. Private keys stay on the host; only the
//! agent socket is forwarded.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::dev::config::{Ssh, SshHost};
use crate::run::GUEST_SSH_AGENT_SOCK;
use crate::sshagent::{Identity, b64_encode};

/// OpenSSH's `ssh-add -l` SHA256 fingerprint: `SHA256:` followed by the unpadded standard
/// base64 of the raw SHA-256 of the key's wire blob.
fn fingerprint(blob: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(blob);
    let digest = h.finalize();
    format!("SHA256:{}", b64_encode(&digest).trim_end_matches('='))
}

/// Boot inputs from [`resolve`]: the agent-filter allowlist (`None` = whole agent),
/// guest `~/.ssh/config`, and warnings for unresolved tokens.
type ResolvedSsh = (Option<Vec<PathBuf>>, Option<String>, Vec<String>);

/// What a whitelist token resolved to.
#[derive(Debug, PartialEq)]
enum Resolved {
    /// a `.pub` file on the host (the caller warns if it is missing)
    File(PathBuf),
    /// an agent key held only as its wire blob
    Blob(Vec<u8>),
    /// nothing matched
    NotFound,
}

/// Expand a leading `~` in `token` against `home`.
fn expand_home(token: &str, home: &Path) -> PathBuf {
    if let Some(rest) = token.strip_prefix("~/") {
        home.join(rest)
    } else if token == "~" {
        home.to_path_buf()
    } else {
        PathBuf::from(token)
    }
}

/// Resolve one whitelist token against the agent's `ids` and the host's `home`. See the
/// module docs for the token forms.
fn match_token(token: &str, ids: &[Identity], home: &Path) -> Resolved {
    if token.starts_with("SHA256:") {
        return match ids.iter().find(|i| fingerprint(&i.blob) == token) {
            Some(i) => Resolved::Blob(i.blob.clone()),
            None => Resolved::NotFound,
        };
    }
    if token.contains('/') || token.starts_with('~') {
        return Resolved::File(expand_home(token, home));
    }
    // Bare names (no `/` or leading `~`) try a `~/.ssh` file before agent key comments:
    // both `work` and `work.pub` look for `~/.ssh/work.pub`.
    let base = if token.ends_with(".pub") {
        token.to_string()
    } else {
        format!("{token}.pub")
    };
    let cand = home.join(".ssh").join(base);
    if cand.exists() {
        return Resolved::File(cand);
    }
    match ids.iter().find(|i| i.comment == token) {
        Some(i) => Resolved::Blob(i.blob.clone()),
        None => Resolved::NotFound,
    }
}

/// Guest `~/.ssh/config`: a global `IdentityAgent` block, then one block per host alias,
/// separated by blank lines. The forwarded socket lets SSH-server sessions use the agent
/// even though `SSH_AUTH_SOCK` is unset.
fn build_guest_config(hosts: &BTreeMap<String, SshHost>, sock: &str) -> String {
    let mut blocks = vec![format!("Host *\n    IdentityAgent {sock}\n")];
    for (alias, h) in hosts {
        let mut b = format!(
            "Host {alias}\n    HostName {}\n",
            h.hostname.as_deref().unwrap_or(alias)
        );
        if let Some(u) = &h.user {
            b.push_str(&format!("    User {u}\n"));
        }
        if let Some(p) = h.port {
            b.push_str(&format!("    Port {p}\n"));
        }
        b.push_str(&format!("    IdentityAgent {sock}\n"));
        blocks.push(b);
    }
    blocks.join("\n")
}

/// The whitelist tokens: `ssh.keys` followed by each host's `key`, deduplicated with order
/// preserved.
fn union_tokens(ssh: &Ssh) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in ssh
        .keys
        .iter()
        .chain(ssh.host.values().filter_map(|h| h.key.as_ref()))
    {
        if !out.contains(t) {
            out.push(t.clone());
        }
    }
    out
}

/// Reject a value with a control character (newline, CR, tab, …) before it is written verbatim
/// into the guest `~/.ssh/config`, so a crafted config cannot inject extra directives.
fn reject_control(field: &str, value: &str) -> Result<()> {
    if let Some(c) = value.chars().find(|c| c.is_control()) {
        anyhow::bail!("[dev.ssh] {field} {value:?} contains a control character ({c:?})");
    }
    Ok(())
}

/// Write `blob` as a minimal `.pub` line (`key <base64>`) the filtering proxy can read, at
/// `scratch/allow-<idx>.pub` (dir 0700, file 0600). `create_new` refuses a pre-existing path
/// (a planted symlink included); the caller clears the scratch dir first so this never
/// collides with its own earlier write.
fn write_allow_pub(scratch: &Path, idx: usize, blob: &[u8]) -> Result<PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(scratch)
        .with_context(|| format!("creating {}", scratch.display()))?;
    let path = scratch.join(format!("allow-{idx}.pub"));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("writing {}", path.display()))?;
    writeln!(f, "key {}", b64_encode(blob))
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Resolve `[dev.ssh]` into an agent-filter allowlist, guest `~/.ssh/config`, and warnings
/// for unresolved tokens. `None` forwards the whole agent; `Some(v)` filters to `v`, failing
/// closed when `v` is empty (e.g. all explicit keys failed to resolve). The returned config
/// is always present because a written `[dev.ssh]` enables forwarding.
pub fn resolve(
    ssh: &Ssh,
    home: &Path,
    upstream: Option<&Path>,
    scratch: &Path,
) -> Result<ResolvedSsh> {
    let mut warnings = Vec::new();

    // These values reach the guest ~/.ssh/config verbatim; a control character in one would
    // let a crafted config inject extra directives. Reject before writing anything.
    for (alias, h) in &ssh.host {
        reject_control("host alias", alias)?;
        if let Some(hn) = &h.hostname {
            reject_control(&format!("host {alias:?} hostname"), hn)?;
        }
        if let Some(u) = &h.user {
            reject_control(&format!("host {alias:?} user"), u)?;
        }
    }
    let guest_config = Some(build_guest_config(&ssh.host, GUEST_SSH_AGENT_SOCK));

    let tokens = union_tokens(ssh);
    // Empty union: forward the whole agent (None), still inject the guest config.
    if tokens.is_empty() {
        return Ok((None, guest_config, warnings));
    }

    // The agent's identities, needed to resolve fingerprint and comment tokens. File tokens
    // resolve without it, so an absent agent still exposes whatever keys are named by path.
    let ids = match upstream {
        Some(sock) => crate::sshagent::list_identities(sock).unwrap_or_else(|e| {
            warnings.push(format!(
                "could not list agent identities ({e:#}); only key files will be exposed"
            ));
            Vec::new()
        }),
        None => {
            warnings.push("SSH_AUTH_SOCK is unset; only key files will be exposed".to_string());
            Vec::new()
        }
    };

    // Blob-resolved tokens land in the scratch dir as synthetic `.pub` files. Clear it once so
    // a filtered forward never offers a stale key a previous boot wrote, and so this boot's
    // `create_new` writes never collide with leftovers.
    let _ = std::fs::remove_dir_all(scratch);
    let mut allow_pub = Vec::new();
    let mut blobs = 0;
    for token in &tokens {
        match match_token(token, &ids, home) {
            Resolved::File(path) => {
                if !path.exists() {
                    warnings.push(format!("{token}: {} does not exist", path.display()));
                }
                allow_pub.push(path);
            }
            Resolved::Blob(blob) => {
                allow_pub.push(write_allow_pub(scratch, blobs, &blob)?);
                blobs += 1;
            }
            Resolved::NotFound => {
                warnings.push(format!("{token}: no matching key in the agent"));
            }
        }
    }
    // Explicit keys always yield `Some`: if none resolve, fail closed instead of forwarding
    // the whole agent.
    Ok((Some(allow_pub), guest_config, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(blob: &[u8], comment: &str) -> Identity {
        Identity {
            blob: blob.to_vec(),
            comment: comment.into(),
        }
    }

    /// A fresh scratch directory unique across this binary's parallel tests.
    fn tmp(tag: &str) -> PathBuf {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("vk-sshsetup-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn fingerprint_matches_the_openssh_formula() {
        // Pinned known-answer vector: `ssh-keygen -lf` prints exactly this `SHA256:…` string
        // for a key whose wire blob is these bytes (the fingerprint is SHA-256 over the blob).
        assert_eq!(
            fingerprint(b"virtkit pinned key blob"),
            "SHA256:ZHA4QJoxbtI62SQc8jzjGLZia8ikm3/tM64SqG0fp9c"
        );

        use sha2::{Digest, Sha256};
        let blob = b"a key blob";
        let fp = fingerprint(blob);
        // `SHA256:` + unpadded standard base64 of the raw SHA-256.
        let want = {
            let mut h = Sha256::new();
            h.update(blob);
            format!("SHA256:{}", b64_encode(&h.finalize()).trim_end_matches('='))
        };
        assert_eq!(fp, want);
        // Structural: a 32-byte digest is 43 unpadded base64 chars, no `=`.
        let body = fp.strip_prefix("SHA256:").unwrap();
        assert_eq!(body.len(), 43);
        assert!(!body.contains('='));
    }

    #[test]
    fn match_token_fingerprint() {
        let ids = [id(b"blobA", "a@host"), id(b"blobB", "b@host")];
        let fp = fingerprint(b"blobB");
        assert_eq!(
            match_token(&fp, &ids, Path::new("/h")),
            Resolved::Blob(b"blobB".to_vec())
        );
        assert_eq!(
            match_token("SHA256:deadbeef", &ids, Path::new("/h")),
            Resolved::NotFound
        );
    }

    #[test]
    fn match_token_paths_pass_through_with_home_expansion() {
        let home = Path::new("/home/u");
        // A `~` path expands against home; any `/` path passes through verbatim.
        assert_eq!(
            match_token("~/.ssh/id_ed25519.pub", &[], home),
            Resolved::File(PathBuf::from("/home/u/.ssh/id_ed25519.pub"))
        );
        assert_eq!(
            match_token("/etc/keys/host.pub", &[], home),
            Resolved::File(PathBuf::from("/etc/keys/host.pub"))
        );
    }

    #[test]
    fn match_token_bare_name_file_then_comment() {
        let dir = tmp("bare");
        std::fs::create_dir_all(dir.join(".ssh")).unwrap();
        std::fs::write(dir.join(".ssh/work.pub"), "ssh-ed25519 AAAA work\n").unwrap();

        // A bare name with a matching ~/.ssh/<name>.pub resolves to that file, even if a
        // comment would also match — with or without the explicit `.pub` suffix.
        let ids = [id(b"blobW", "work")];
        assert_eq!(
            match_token("work", &ids, &dir),
            Resolved::File(dir.join(".ssh/work.pub"))
        );
        assert_eq!(
            match_token("work.pub", &ids, &dir),
            Resolved::File(dir.join(".ssh/work.pub"))
        );
        // A bare name with no file falls back to a comment match.
        assert_eq!(
            match_token("a@host", &[id(b"blobA", "a@host")], &dir),
            Resolved::Blob(b"blobA".to_vec())
        );
        // Neither a file nor a comment: NotFound.
        assert_eq!(match_token("nope", &[], &dir), Resolved::NotFound);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn build_guest_config_global_only() {
        let cfg = build_guest_config(&BTreeMap::new(), "/run/sock");
        assert_eq!(cfg, "Host *\n    IdentityAgent /run/sock\n");
    }

    #[test]
    fn build_guest_config_with_hosts() {
        let mut hosts = BTreeMap::new();
        hosts.insert(
            "gitlab".to_string(),
            SshHost {
                hostname: Some("gitlab.internal".into()),
                user: Some("git".into()),
                port: Some(2222),
                key: Some("work".into()),
            },
        );
        hosts.insert("plain".to_string(), SshHost::default());
        let cfg = build_guest_config(&hosts, "/run/sock");
        assert_eq!(
            cfg,
            "Host *\n    IdentityAgent /run/sock\n\
             \n\
             Host gitlab\n    HostName gitlab.internal\n    User git\n    Port 2222\n    \
             IdentityAgent /run/sock\n\
             \n\
             Host plain\n    HostName plain\n    IdentityAgent /run/sock\n"
        );
    }

    #[test]
    fn union_dedups_keys_and_host_keys_in_order() {
        let mut ssh = Ssh {
            keys: vec!["work".into(), "SHA256:x".into()],
            host: BTreeMap::new(),
        };
        ssh.host.insert(
            "a".into(),
            SshHost {
                key: Some("work".into()),
                ..Default::default()
            },
        );
        ssh.host.insert(
            "b".into(),
            SshHost {
                key: Some("home".into()),
                ..Default::default()
            },
        );
        assert_eq!(union_tokens(&ssh), ["work", "SHA256:x", "home"]);
    }

    #[test]
    fn resolve_empty_union_forwards_the_whole_agent_with_a_config() {
        let home = tmp("whole-home");
        let scratch = tmp("whole-scratch").join("allow");
        // A present but empty [dev.ssh]: no tokens ⇒ whole agent (None), config still injected.
        let (allow, cfg, warnings) = resolve(&Ssh::default(), &home, None, &scratch).unwrap();
        assert_eq!(allow, None);
        assert!(
            cfg.unwrap()
                .contains("IdentityAgent /run/virtkit-ssh-agent.sock")
        );
        assert!(warnings.is_empty());
        // Nothing to write, so no scratch dir is created.
        assert!(!scratch.exists());
    }

    #[test]
    fn resolve_fails_closed_when_a_named_key_does_not_resolve() {
        let home = tmp("closed-home"); // no ~/.ssh, so a bare name finds no file
        let scratch = tmp("closed-scratch").join("allow");
        let ssh = Ssh {
            keys: vec!["ghost".into()],
            host: BTreeMap::new(),
        };
        let (allow, cfg, warnings) = resolve(&ssh, &home, None, &scratch).unwrap();
        // A named-but-unresolved key: Some(empty) — fail closed, NOT the whole agent.
        assert_eq!(allow, Some(Vec::new()));
        assert!(cfg.is_some());
        assert!(warnings.iter().any(|w| w.contains("ghost")), "{warnings:?}");
    }

    #[test]
    fn resolve_rejects_control_chars_reaching_the_guest_config() {
        let home = tmp("ctl-home");
        let scratch = tmp("ctl-scratch").join("allow");
        let with_host = |alias: &str, h: SshHost| {
            let mut ssh = Ssh::default();
            ssh.host.insert(alias.into(), h);
            ssh
        };
        // A newline in hostname, user, or the alias itself is refused before anything is built.
        for ssh in [
            with_host(
                "h",
                SshHost {
                    hostname: Some("a\nProxyCommand evil".into()),
                    ..Default::default()
                },
            ),
            with_host(
                "h",
                SshHost {
                    user: Some("root\nProxyCommand evil".into()),
                    ..Default::default()
                },
            ),
            with_host("a\nb", SshHost::default()),
        ] {
            assert!(resolve(&ssh, &home, None, &scratch).is_err());
        }
    }
}
