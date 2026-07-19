//! Host-side git checkout for the GitLab executor's `[gitlab] host_checkout` mode.
//!
//! `prepare` checks the job's sources out ON THE HOST and shares the tree into the guest, so
//! the git credential (embedded by GitLab in `CI_REPOSITORY_URL`) never enters the guest and
//! the host has the tree to build a git-defined image (see the `ci-boots-git-defined-images`
//! design). virtkit runs `git` itself with fixed arguments — never a configured hook command,
//! which would be an injection surface for the runner user. Only `http(s)` URLs are accepted:
//! an `ext::`/`file::` transport would let a crafted `CI_REPOSITORY_URL` run an arbitrary
//! remote helper (a git-remote-ext RCE). The token-bearing URL is never rendered into an error
//! or log — only its redacted form — so a git failure cannot spill the credential into the
//! runner's job trace.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

/// Clone-or-fetch `url` into `dest` and hard-checkout `sha`. Idempotent: a populated `dest` is
/// fetched and re-pointed at `sha` rather than re-cloned (so a reused per-slot dir amortises the
/// clone). `ref_name` (the branch/tag) is fetched first so a bare commit resolves without
/// server-side `uploadpack.allowAnySHA1InWant`. The tree is cleaned to match a fresh CI
/// checkout. Submodules and LFS are not handled here — add them if a job needs them.
pub fn ensure(url: &str, ref_name: &str, sha: &str, dest: &Path) -> Result<()> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        bail!(
            "refusing to clone {}: only http(s) URLs are allowed for host_checkout",
            redact_url(url)
        );
    }
    if sha.is_empty() || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid commit sha {sha:?}");
    }
    // `ref_name` is `--`-guarded below, so it can never be read as an option; validating it
    // against git's own ref-name rules is defence-in-depth against a crafted refspec (a glob
    // or `remote:local` pair) fetching extra refs into the reused per-slot repo.
    if !ref_name.is_empty() && !ref_name_ok(ref_name) {
        bail!("invalid ref name {ref_name:?}");
    }

    if dest.join(".git").is_dir() {
        // Re-point at the current URL (the embedded token rotates per job), then fetch.
        git(
            dest,
            &["remote", "set-url", "origin", url],
            "remote set-url",
        )?;
    } else {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        // clone without checkout; the explicit detach below pins the exact commit.
        let dest_s = dest.to_str().context("checkout dir is not utf-8")?;
        run(
            Command::new("git").args(["clone", "--no-checkout", "--", url, dest_s]),
            "clone",
        )?;
    }
    // The checkout's `.git/config` records the token-bearing remote URL; keep the tree private
    // to the runner user so a co-tenant on the host cannot read the credential at rest.
    std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("securing {}", dest.display()))?;
    // Fetch the ref tip so `sha` is reachable, then detach onto exactly that commit. `--`
    // guards a ref that begins with '-'; `sha` is validated hex above.
    if ref_name.is_empty() {
        git(dest, &["fetch", "--prune", "origin"], "fetch")?;
    } else {
        git(
            dest,
            &["fetch", "--prune", "origin", "--", ref_name],
            "fetch",
        )?;
    }
    git(dest, &["checkout", "--detach", "--force", sha], "checkout")?;
    git(dest, &["clean", "-ffdx"], "clean")?;
    Ok(())
}

/// A git ref name safe to pass as a fetch argument: git's own rules already forbid these in a
/// branch/tag, so rejecting them cannot turn away a legitimate ref. `/` stays allowed
/// (`feature/x`); a leading `-`/`+` and refspec/glob metacharacters are refused.
fn ref_name_ok(r: &str) -> bool {
    !r.starts_with('-')
        && !r.starts_with('+')
        && r.chars().all(|c| {
            !c.is_control() && !matches!(c, ':' | '?' | '*' | '[' | '\\' | '~' | '^' | ' ')
        })
}

/// Strip `user[:password]@` userinfo from an http(s) URL so the embedded job token never
/// reaches a log or error. A URL without userinfo is returned unchanged.
fn redact_url(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => match rest.split_once('@') {
            Some((_userinfo, host)) => format!("{scheme}://<redacted>@{host}"),
            // No `@` means no `user:token@` userinfo, so there is no credential to hide.
            None => url.to_string(),
        },
        None => "<redacted>".to_string(),
    }
}

/// Run `git -C <dir> <args…>`, erroring on a non-zero exit. `what` is a fixed, secret-free
/// label for diagnostics — the command (which may carry the token-bearing URL) is never
/// rendered.
fn git(dir: &Path, args: &[&str], what: &str) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(dir).args(args);
    run(&mut cmd, what)
}

fn run(cmd: &mut Command, what: &str) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("spawning git {what}"))?;
    if !status.success() {
        bail!("git {what} failed ({status})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_url_strips_the_embedded_token() {
        assert_eq!(
            redact_url("https://gitlab-ci-token:secrettoken@gitlab.example.com/g/p.git"),
            "https://<redacted>@gitlab.example.com/g/p.git"
        );
        // No userinfo: nothing to hide, returned unchanged.
        assert_eq!(
            redact_url("https://gitlab.example.com/g/p.git"),
            "https://gitlab.example.com/g/p.git"
        );
        // A non-URL never echoes back verbatim.
        assert_eq!(redact_url("gitlab-ci-token:secret"), "<redacted>");
    }

    #[test]
    fn ref_name_rejects_injection_but_keeps_real_branches() {
        for ok in [
            "main",
            "feature/foo",
            "release-1.2.3",
            "v1.0",
            "user/fix.bug",
        ] {
            assert!(ref_name_ok(ok), "{ok:?} is a legitimate ref");
        }
        for bad in [
            "-upload-pack=x",
            "+refs/heads/*",
            "evil:refs/heads/x",
            "a b",
            "glob*",
            "q?",
            "ca^ret",
            "ti~lde",
            "back\\slash",
        ] {
            assert!(!ref_name_ok(bad), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn ensure_refuses_non_http_and_bad_sha_before_touching_git() {
        let dest = Path::new("/nonexistent/vk-checkout-test");
        // A non-http(s) transport (git-remote-ext RCE vector) is refused, and the error is
        // redacted — never echoing the raw ref back verbatim.
        let err = ensure("ext::sh -c whoami", "main", "abcdef", dest).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("only http(s)"), "got: {msg}");
        assert!(!msg.contains("ext::sh"), "raw ext URL leaked: {msg}");
        // A non-hex sha is refused before any git runs.
        assert!(ensure("https://h/p.git", "main", "deadbeefZZ", dest).is_err());
        // An option-injection ref is refused before any git runs.
        assert!(ensure("https://h/p.git", "-x", "deadbeef", dest).is_err());
    }
}
