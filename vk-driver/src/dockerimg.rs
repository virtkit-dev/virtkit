//! Boot a `docker/<name>[:tag|@sha256:…]` (or bare `image:`) job image DIRECTLY from its
//! registry.
//!
//! By default the reference is pulled directly from whatever registry it names — the
//! microVM boundary is the security model, so the image source is not gated. An optional
//! `[docker]` proxy only *routes* bare names through a shared pull-through cache; it never
//! refuses an image (see `route`). The image is pulled with the native OCI client and
//! flattened into a byte-clean bootable ext4 booted on the embedded kernel (the agent
//! rides the boot initramfs, nothing is injected into the rootfs). The image's
//! Config.Env/User/WorkingDir/Entrypoint/Cmd are captured into a `runner.ext4.json`
//! sidecar the boot applies, so the guest runs like `docker run` would. Results cache
//! under `<state_dir>/docker/<name>/<digest>/` with the same pull lock + GC as the
//! bundle registry.
//!
//! This is the OCI-direct path `vk run --source oci` uses, wired into the executor, so a
//! runner host provisions the guest with just the `vk` binary.

use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::config::Config;
use crate::image::{self, BootKind, Reference, ResolvedImage};

/// `MICROVM_IMAGE: docker/<name>[:tag|@digest]`. With a `[docker]` proxy configured the
/// name is repo-relative (routed onto the proxy's repo); with none it is a raw OCI ref
/// pulled directly.
pub fn resolve(cfg: &Config, state_dir: &Path, image_ref: &str) -> Result<ResolvedImage> {
    let (name, reference) = image::parse_ref(image_ref)?;
    let (full, creds) = match &cfg.docker {
        Some(dk) => {
            let full = match &reference {
                Reference::Digest(d) => format!("{}/{}@{}", dk.repo, name, d),
                Reference::Tag(t) => format!("{}/{}:{}", dk.repo, name, t),
            };
            (full, Creds::from_docker(dk)?)
        }
        None => {
            let full = match &reference {
                Reference::Digest(d) => format!("{name}@{d}"),
                Reference::Tag(t) => format!("{name}:{t}"),
            };
            (full, Creds::anon())
        }
    };
    resolve_full(cfg, state_dir, &name, &full, &creds)
}

/// The job's GitLab `image:` (CI_JOB_IMAGE): a full or bare OCI ref. Pulled directly by
/// default (the microVM boundary is the security model, not an image-source allowlist).
/// A `[docker]` proxy only *routes* pulls: a bare docker-hub-style name is fetched through
/// the configured repo (with its credentials); a ref that names its own registry is pulled
/// from there directly. Nothing is refused on the basis of where the image lives.
pub fn resolve_image(cfg: &Config, state_dir: &Path, image: &str) -> Result<ResolvedImage> {
    let (full, name, creds) = match &cfg.docker {
        Some(dk) => match route(&dk.repo, image)? {
            Route::Repo { full, name } => (full, name, Creds::from_docker(dk)?),
            Route::Direct => (image.to_string(), ref_cache_name(image)?, Creds::anon()),
        },
        None => (image.to_string(), ref_cache_name(image)?, Creds::anon()),
    };
    resolve_full(cfg, state_dir, &name, &full, &creds)
}

/// Registry credentials for one pull. Anonymous for a direct pull; from `[docker]` when a
/// bare name is routed onto the configured proxy repo.
struct Creds {
    username: Option<String>,
    password: Option<String>,
    ca_pem: Option<Vec<u8>>,
    insecure: bool,
}

impl Creds {
    fn anon() -> Creds {
        Creds {
            username: None,
            password: None,
            ca_pem: None,
            insecure: false,
        }
    }

    fn from_docker(dk: &crate::config::Docker) -> Result<Creds> {
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
        Ok(Creds {
            username,
            password,
            ca_pem,
            insecure: dk.insecure,
        })
    }
}

/// Pull + cache + boot the OCI ref `full` with `creds` (cache-keyed by `name` + digest).
fn resolve_full(
    cfg: &Config,
    state_dir: &Path,
    name: &str,
    full: &str,
    creds: &Creds,
) -> Result<ResolvedImage> {
    let digest = crate::registry::block_on(crate::oci::resolve_digest_auth(
        full,
        creds.username.as_deref(),
        creds.password.as_deref(),
        creds.ca_pem.clone(),
        creds.insecure,
    ))
    .with_context(|| format!("resolving {full}"))?;

    // Pull by the resolved digest, not the tag, so the digest-keyed cache dir is always
    // populated with exactly that content even if the tag moves under us (mirrors the
    // registry bundle path, which pulls via make_digest_ref). The rootfs is a byte-clean
    // flatten (the embedded agent rides the boot initramfs), so the digest keys the cache
    // — a vk update changes the boot agent, not the image.
    let pinned = pin_digest(full, &digest);

    let images_dir = state_dir.join("docker").join(name);
    let dir = images_dir.join(digest.trim_start_matches("sha256:"));
    if !dir.join("runner.ext4").is_file() {
        let _lock = image::acquire_pull_lock(&dir, name, &digest)?;
        if !dir.join("runner.ext4").is_file() {
            build(
                &pinned,
                creds.username.clone(),
                creds.password.clone(),
                creds.ca_pem.clone(),
                creds.insecure,
                &dir,
            )?;
            image::gc_idle(&state_dir.join("docker"), cfg.image_cache_idle());
        }
    }
    image::mark_used(&dir);
    println!("virtkit: image {full}@{digest} (OCI direct boot)");
    // generic-disk boot: the boot applies the image's Env/User/WorkingDir/Entrypoint/Cmd
    // from the runner.ext4.json sidecar (`resolved_from_dir` loads it) — no baking.
    Ok(image::resolved_from_dir(&dir, BootKind::GenericDisk))
}

/// Pull + flatten the image into `dir/runner.ext4` (byte-clean) and write its captured
/// runtime config to `runner.ext4.json`. A tmp sibling is promoted on success so a killed
/// prepare never leaves a half-built rootfs a cache check would trust.
fn build(
    full: &str,
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
    // Flatten the image byte-clean (the agent rides the boot initramfs) and capture its
    // Config into the runner.ext4.json sidecar — the shared OCI-flatten core. A journalled
    // fs and no freshness UUID: the digest-keyed cache dir is this image's identity.
    let rootfs = tmp.join("runner.ext4");
    crate::registry::block_on(crate::source::oci_flatten(
        full,
        username.as_deref(),
        password.as_deref(),
        ca_pem,
        insecure,
        0,
        &crate::ext4::FsId {
            with_journal: true,
            ..Default::default()
        },
        &rootfs,
    ))?;
    std::fs::write(
        tmp.join("boot.kind"),
        image::boot_kind_tag(BootKind::GenericDisk),
    )
    .with_context(|| format!("writing the boot marker in {}", tmp.display()))?;
    if !rootfs.is_file() {
        bail!("OCI direct build of {full} produced no rootfs");
    }
    let _ = std::fs::remove_dir_all(dir);
    std::fs::rename(&tmp, dir)
        .with_context(|| format!("promoting {} to {}", tmp.display(), dir.display()))
}

/// How an `image:` resolves against a configured `[docker]` proxy repo.
#[derive(Debug, PartialEq)]
enum Route {
    /// Fetch through the proxy repo (its credentials): the full ref + the cache name.
    Repo { full: String, name: String },
    /// The ref names its own registry — pull it from there directly (anonymous).
    Direct,
}

/// Route a job's `image:` against a `[docker]` proxy `repo`. A ref already under the repo,
/// or a bare docker-hub-style name (no registry host), is fetched *through* the repo; a ref
/// that names its own registry is pulled directly. Nothing is refused — the proxy routes,
/// it does not gate.
fn route(repo: &str, image: &str) -> Result<Route> {
    let prefix = format!("{repo}/");
    if let Some(rest) = image.strip_prefix(&prefix) {
        return Ok(Route::Repo {
            full: image.to_string(),
            name: name_of(rest)?,
        });
    }
    // A registry host is the first `/`-segment carrying a `.`/`:` (or `localhost`); a ref
    // that names one is pulled from there directly, otherwise it is a bare docker-hub name
    // routed onto the proxy repo.
    if let Some((host, _)) = image.split_once('/')
        && (host.contains('.') || host.contains(':') || host == "localhost")
    {
        return Ok(Route::Direct);
    }
    Ok(Route::Repo {
        full: format!("{prefix}{image}"),
        name: name_of(image)?,
    })
}

/// Pin a resolved digest onto `full`, dropping any existing `:tag`/`@digest`, so the pull
/// fetches exactly the resolved content even if the tag moves. The tag is a `:` after the
/// last `/` (a registry-host `:port` before the first `/` is left intact).
fn pin_digest(full: &str, digest: &str) -> String {
    let base = full.split('@').next().unwrap_or(full);
    let tag_at = match base.rfind('/') {
        Some(slash) => base[slash..].find(':').map(|i| slash + i),
        None => base.find(':'),
    };
    let repo = tag_at.map_or(base, |i| &base[..i]);
    format!("{repo}@{digest}")
}

/// The cache-key name for any OCI ref: drop a leading registry host, then defer to
/// `name_of` for the tag/digest strip and path-component validation.
fn ref_cache_name(image: &str) -> Result<String> {
    let repo_rel = match image.split_once('/') {
        Some((host, rest)) if host.contains('.') || host.contains(':') || host == "localhost" => {
            rest
        }
        _ => image,
    };
    name_of(repo_rel)
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
    fn route_maps_bare_names_but_passes_other_registries_through() {
        let repo = "10.10.140.49/common/wab-ci";
        // bare docker-hub-style name → routed onto the proxy repo
        assert_eq!(
            route(repo, "wabbuilder:v1").unwrap(),
            Route::Repo {
                full: format!("{repo}/wabbuilder:v1"),
                name: "wabbuilder".into()
            }
        );
        assert_eq!(
            route(repo, "alpine").unwrap(),
            Route::Repo {
                full: format!("{repo}/alpine"),
                name: "alpine".into()
            }
        );
        // already under the repo → passes through the proxy
        assert_eq!(
            route(repo, &format!("{repo}/team/img:t")).unwrap(),
            Route::Repo {
                full: format!("{repo}/team/img:t"),
                name: "team/img".into()
            }
        );
        // a different registry → pulled directly, NOT refused (isolation is the boundary)
        assert_eq!(
            route(repo, "docker.io/library/alpine:3.20").unwrap(),
            Route::Direct
        );
        assert_eq!(route(repo, "evil.example.com/x").unwrap(), Route::Direct);
    }

    #[test]
    fn route_refuses_path_traversal_when_mapping_onto_the_repo() {
        let repo = "10.10.140.49/common/wab-ci";
        // `..` in a bare name maps onto the repo but must not escape the cache root.
        assert!(route(repo, "foo/../../../bar").is_err());
        // `..` in the tail of a repo-prefixed ref (the pass-through branch) is refused too.
        assert!(route(repo, &format!("{repo}/../evil/x")).is_err());
        assert!(route(repo, &format!("{repo}/team/../evil")).is_err());
        // a bare `..` component is refused.
        assert!(route(repo, "..").is_err());
    }

    #[test]
    fn ref_cache_name_drops_registry_host_and_validates() {
        // bare and repo-relative refs keep their repository path
        assert_eq!(ref_cache_name("redis:7").unwrap(), "redis");
        assert_eq!(ref_cache_name("library/redis:7").unwrap(), "library/redis");
        // a registry host is stripped for the cache key
        assert_eq!(ref_cache_name("ghcr.io/foo/bar:1").unwrap(), "foo/bar");
        assert_eq!(
            ref_cache_name("localhost:5000/img@sha256:d").unwrap(),
            "img"
        );
        // traversal in the repository path is still refused
        assert!(ref_cache_name("ghcr.io/../evil").is_err());
    }

    #[test]
    fn pin_digest_replaces_tag_and_keeps_host_port() {
        assert_eq!(pin_digest("redis:7", "sha256:d"), "redis@sha256:d");
        assert_eq!(
            pin_digest("ghcr.io/foo/bar:1", "sha256:d"),
            "ghcr.io/foo/bar@sha256:d"
        );
        // an existing @digest is dropped before re-pinning
        assert_eq!(pin_digest("img@sha256:old", "sha256:new"), "img@sha256:new");
        // a registry-host :port (before the first '/') is preserved; no tag to strip
        assert_eq!(
            pin_digest("localhost:5000/img", "sha256:d"),
            "localhost:5000/img@sha256:d"
        );
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
}
