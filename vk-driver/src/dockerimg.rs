//! Boot a `docker/<name>[:tag|@sha256:…]` job image DIRECTLY from its registry.
//!
//! The reference is resolved against the host-configured `[docker] repo` (the
//! allowlist, same model as `[registry]`), pulled with the native OCI client, and
//! flattened into a bootable ext4 with the embedded vk-agent injected as PID 1 and
//! booted on the embedded kernel. The image's Config.Env/User are captured into
//! `/etc/virtkit/{env,user}` so the guest runs like `docker run` would. Results cache
//! under `<state_dir>/docker/<name>/<digest>-<agentfp>/` with the same pull lock + GC as
//! the bundle registry.
//!
//! This is the OCI-direct path `vk run --source oci` uses, wired into the executor, so a
//! runner host provisions the guest with just the `vk` binary.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::image::{self, BootKind, Reference, ResolvedImage};
use crate::jobctx::JobCtx;

/// `MICROVM_IMAGE: docker/<name>[:tag|@digest]` — a name under the `[docker] repo`.
pub fn resolve(ctx: &JobCtx, image_ref: &str) -> Result<ResolvedImage> {
    let dk = docker_cfg(ctx)?;
    let (name, reference) = image::parse_ref(image_ref)?;
    let full = match &reference {
        Reference::Digest(d) => format!("{}/{}@{}", dk.repo, name, d),
        Reference::Tag(t) => format!("{}/{}:{}", dk.repo, name, t),
    };
    resolve_full(ctx, dk, &name, &full)
}

/// The job's GitLab `image:` (CI_JOB_IMAGE): a full or bare OCI ref, accepted only when it
/// resolves under the `[docker] repo` allowlist — a bare docker-hub-style name maps onto
/// the repo, a ref naming another registry is refused.
pub fn resolve_image(ctx: &JobCtx, image: &str) -> Result<ResolvedImage> {
    let dk = docker_cfg(ctx)?;
    let (full, name) = normalize(&dk.repo, image)?;
    resolve_full(ctx, dk, &name, &full)
}

fn docker_cfg(ctx: &JobCtx) -> Result<&crate::config::Docker> {
    ctx.cfg
        .docker
        .as_ref()
        .context("the job selects an image but the host has no [docker] configured")
}

/// Pull + cache + boot the registry ref `full` (cache-keyed by `name` + digest).
fn resolve_full(
    ctx: &JobCtx,
    dk: &crate::config::Docker,
    name: &str,
    full: &str,
) -> Result<ResolvedImage> {
    let ca_pem = dk
        .ca_file
        .as_ref()
        .map(|p| std::fs::read(p).with_context(|| format!("reading {}", p.display())))
        .transpose()?;
    let password = dk
        .password_file
        .as_ref()
        .map(|p| {
            std::fs::read_to_string(p)
                .map(|s| s.trim_end().to_string())
                .with_context(|| format!("reading {}", p.display()))
        })
        .transpose()?;
    let username = (!dk.username.is_empty()).then(|| dk.username.clone());

    // the embedded vk-agent (or the `[build] agent` override) is injected as PID 1;
    // fold its identity into the cache key so a vk update re-bakes the rootfs.
    let agent = crate::embed::resolve(crate::embed::Asset::Agent, ctx.cfg.build.agent.as_deref())?;
    let agent_bytes =
        std::fs::read(&agent.path).context("reading the vk-agent to inject as PID 1")?;
    let agent_fp = image::fnv64(&[agent_bytes.as_slice()]);

    let digest = crate::registry::block_on(crate::oci::resolve_digest_auth(
        full,
        username.as_deref(),
        password.as_deref(),
        ca_pem.clone(),
        dk.insecure,
    ))
    .with_context(|| format!("resolving {full}"))?;

    // pull by the resolved digest, not the tag, so the digest-keyed cache dir is always
    // populated with exactly that content even if the tag moves under us (mirrors the
    // registry bundle path, which pulls via make_digest_ref). `full` always starts with
    // `{repo}/`, so `{repo}/{name}` reconstructs the same ref with the tag dropped.
    let pinned = format!("{}/{}@{}", dk.repo, name, digest);

    let images_dir = ctx.cfg.state_dir().join("docker").join(name);
    let dir = images_dir.join(format!(
        "{}-{agent_fp:016x}",
        digest.trim_start_matches("sha256:")
    ));
    if !dir.join("runner.ext4").is_file() {
        let _lock = image::acquire_pull_lock(&dir, name, &digest)?;
        if !dir.join("runner.ext4").is_file() {
            build(
                &pinned,
                &agent.path,
                username,
                password,
                ca_pem,
                dk.insecure,
                &dir,
            )?;
            image::gc(&images_dir, &dir, dk.keep);
        }
    }
    println!("virtkit: image {full}@{digest} (OCI direct boot)");
    // generic-disk boot: the embedded kernel (kernel=None), the agent as PID 1.
    Ok(ResolvedImage::Disk {
        rootfs: dir.join("runner.ext4"),
        kernel: None,
        initrd: None,
        generic: true,
        // Env/User are baked into the rootfs as /etc/virtkit/{env,user} at build time.
        config: None,
    })
}

/// Pull + flatten the image into `dir/runner.ext4`, injecting the agent and the captured
/// Env/User. A tmp sibling is promoted on success so a killed prepare never leaves a
/// half-built rootfs a cache check would trust.
fn build(
    full: &str,
    agent_path: &Path,
    username: Option<String>,
    password: Option<String>,
    ca_pem: Option<Vec<u8>>,
    insecure: bool,
    dir: &Path,
) -> Result<()> {
    let tmp = dir.with_extension("tmp");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    println!("virtkit: pulling {full} ...");
    crate::registry::block_on(build_async(
        full.to_string(),
        agent_path.to_path_buf(),
        username,
        password,
        ca_pem,
        insecure,
        tmp.clone(),
    ))?;
    std::fs::write(
        tmp.join("boot.kind"),
        image::boot_kind_tag(BootKind::GenericDisk),
    )
    .with_context(|| format!("writing the boot marker in {}", tmp.display()))?;
    if !tmp.join("runner.ext4").is_file() {
        bail!("OCI direct build of {full} produced no rootfs");
    }
    let _ = std::fs::remove_dir_all(dir);
    std::fs::rename(&tmp, dir)
        .with_context(|| format!("promoting {} to {}", tmp.display(), dir.display()))
}

async fn build_async(
    full: String,
    agent_path: PathBuf,
    username: Option<String>,
    password: Option<String>,
    ca_pem: Option<Vec<u8>>,
    insecure: bool,
    tmp: PathBuf,
) -> Result<()> {
    // capture the image config a plain rootfs tar drops, so the guest runs like
    // `docker run`: the agent restores Config.Env (PATH, …) and drops the stage
    // scripts to Config.User. Injected as /etc/virtkit/{env,user} next to the agent.
    let cfg = crate::oci::pull_config(
        &full,
        username.as_deref(),
        password.as_deref(),
        ca_pem.clone(),
        insecure,
    )
    .await?;
    let env_file = tmp.join("virtkit.env");
    let user_file = tmp.join("virtkit.user");
    std::fs::write(&env_file, render_env(&cfg.env))?;
    std::fs::write(&user_file, format!("{}\n", cfg.user.unwrap_or_default()))?;
    let rootfs = tmp.join("runner.ext4");
    let injects: [(&str, &Path, u16); 3] = [
        ("usr/local/bin/vk-agent", agent_path.as_path(), 0o755),
        ("etc/virtkit/env", env_file.as_path(), 0o644),
        ("etc/virtkit/user", user_file.as_path(), 0o644),
    ];
    let source = crate::source::Source::Oci {
        reference: full,
        username,
        password,
        ca_pem,
        insecure,
    };
    source
        .stream_tar(&tmp, |tar, hints| {
            crate::ext4::build_from_tar_stream(
                tar,
                &injects,
                hints.image_bytes(),
                0,
                Some(hints.inode_count()),
                &crate::ext4::FsId {
                    with_journal: true,
                    ..Default::default()
                },
                &rootfs,
            )
        })
        .await?;
    let _ = std::fs::remove_file(&env_file);
    let _ = std::fs::remove_file(&user_file);
    Ok(())
}

/// Render `Config.Env` as raw KEY=VALUE lines (the agent splits on the first '=' and
/// takes the rest of the line verbatim).
fn render_env(env: &[(String, String)]) -> String {
    env.iter()
        .map(|(k, v)| format!("{k}={v}\n"))
        .collect::<String>()
}

/// Map a job's `image:` onto the `[docker] repo` allowlist. A ref already under the repo
/// passes through; a bare docker-hub-style name (no registry host) maps onto the repo; a
/// ref naming a different registry is refused. Returns `(full registry ref, cache name)`.
fn normalize(repo: &str, image: &str) -> Result<(String, String)> {
    let prefix = format!("{repo}/");
    if let Some(rest) = image.strip_prefix(&prefix) {
        return Ok((image.to_string(), name_of(rest)?));
    }
    // A registry host is the first `/`-segment carrying a `.`/`:` (or `localhost`); absent
    // one this is a bare docker-hub name, which we map onto the repo.
    if let Some((host, _)) = image.split_once('/')
        && (host.contains('.') || host.contains(':') || host == "localhost")
    {
        bail!(
            "image {image:?} is not under the allowed registry {repo:?} — push it there, \
             or set MICROVM_IMAGE for another source"
        );
    }
    Ok((format!("{prefix}{image}"), name_of(image)?))
}

/// The cache-key name for a repo-relative ref: its repository path with any `:tag`/
/// `@digest` stripped (`wabbuilder:v1` → `wabbuilder`, `team/img@sha256:…` → `team/img`).
/// The job controls this string (it comes from `image:`) and it is joined straight into
/// host cache/lock paths, so every `/`-segment is validated as a safe path component —
/// the same contract `parse_ref` enforces for the `docker/` form — refusing `..`,
/// embedded separators and empty segments so a crafted ref cannot escape the cache root.
fn name_of(reporel: &str) -> Result<String> {
    let base = reporel.split('@').next().unwrap_or(reporel);
    let name = match base.rsplit_once('/') {
        Some((dir, last)) => format!("{dir}/{}", last.split(':').next().unwrap_or(last)),
        None => base.split(':').next().unwrap_or(base).to_string(),
    };
    let component_ok = |v: &str| {
        !v.is_empty()
            && !v.starts_with('.')
            && v.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    if !name.split('/').all(component_ok) {
        bail!("invalid image name {name:?} (unsafe path component)");
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_maps_bare_names_onto_the_repo() {
        let repo = "10.10.140.49/common/wab-ci";
        // bare docker-hub-style name → mapped onto the repo
        assert_eq!(
            normalize(repo, "wabbuilder:v1").unwrap(),
            (format!("{repo}/wabbuilder:v1"), "wabbuilder".into())
        );
        assert_eq!(
            normalize(repo, "alpine").unwrap(),
            (format!("{repo}/alpine"), "alpine".into())
        );
        // already under the repo → passes through
        assert_eq!(
            normalize(repo, &format!("{repo}/team/img:t")).unwrap(),
            (format!("{repo}/team/img:t"), "team/img".into())
        );
        // a different registry → refused
        assert!(normalize(repo, "docker.io/library/alpine:3.20").is_err());
        assert!(normalize(repo, "evil.example.com/x").is_err());
    }

    #[test]
    fn normalize_refuses_path_traversal() {
        let repo = "10.10.140.49/common/wab-ci";
        // `..` in a bare name maps onto the repo but must not escape the cache root.
        assert!(normalize(repo, "foo/../../../bar").is_err());
        // `..` in the tail of a repo-prefixed ref (the pass-through branch) is refused too.
        assert!(normalize(repo, &format!("{repo}/../evil/x")).is_err());
        assert!(normalize(repo, &format!("{repo}/team/../evil")).is_err());
        // a bare `..` component is refused.
        assert!(normalize(repo, "..").is_err());
    }

    #[test]
    fn name_of_strips_tag_and_digest() {
        assert_eq!(name_of("wabbuilder:v1").unwrap(), "wabbuilder");
        assert_eq!(name_of("img@sha256:dead").unwrap(), "img");
        assert_eq!(name_of("team/img:t").unwrap(), "team/img");
        assert_eq!(name_of("plain").unwrap(), "plain");
        // unsafe path components are refused.
        assert!(name_of("foo/../bar").is_err());
        assert!(name_of("..").is_err());
        assert!(name_of("").is_err());
    }

    #[test]
    fn render_env_emits_key_equals_value_lines() {
        let env = [
            ("PATH".to_string(), "/usr/bin:/bin".to_string()),
            // values may themselves contain '=' — the agent splits on the first one,
            // so the rest must be emitted verbatim.
            ("OPTS".to_string(), "a=b=c".to_string()),
            ("EMPTY".to_string(), String::new()),
        ];
        assert_eq!(render_env(&env), "PATH=/usr/bin:/bin\nOPTS=a=b=c\nEMPTY=\n");
    }

    #[test]
    fn render_env_empty_is_empty() {
        assert_eq!(render_env(&[]), "");
    }
}
