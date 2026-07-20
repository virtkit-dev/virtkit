//! Boot a `docker/<name>[:tag|@sha256:…]` (or bare `image:`) job image DIRECTLY from its
//! registry.
//!
//! By default the reference is pulled directly from whatever registry it names — the
//! microVM boundary is the security model, so the image source is not gated. An optional
//! `[docker]` proxy only *routes* pulls (bare names through its `repo`, Docker Hub refs
//! through a `[docker.mirror]`); it never refuses an image (see `route`). The image is
//! pulled with the native OCI client and
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

use crate::config::{Config, Docker};
use crate::image::{self, BootKind, Reference, ResolvedImage};

/// `MICROVM_IMAGE: docker/<name>[:tag|@digest]`. Routed onto `[docker].repo` (with its
/// credentials) when that is set; with no repo — an absent `[docker]`, or one carrying only
/// a `[docker.mirror]` — it is a raw OCI ref pulled directly. The Docker-Hub-only mirror
/// does not apply to this explicit form.
pub fn resolve(cfg: &Config, state_dir: &Path, image_ref: &str) -> Result<ResolvedImage> {
    let (name, reference) = image::parse_ref(image_ref)?;
    let (full, creds) = match cfg.docker.as_ref().filter(|d| d.repo.is_some()) {
        Some(dk) => {
            let repo = dk.repo.as_deref().unwrap();
            let full = match &reference {
                Reference::Digest(d) => format!("{repo}/{name}@{d}"),
                Reference::Tag(t) => format!("{repo}/{name}:{t}"),
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
/// A `[docker]` proxy only *routes* pulls (see `route`): a bare docker-hub-style name is
/// fetched through the configured repo, a Docker Hub ref through the `[docker.mirror]` when
/// one is set, and a ref that names another registry is pulled from there directly. Nothing
/// is refused on the basis of where the image lives.
pub fn resolve_image(cfg: &Config, state_dir: &Path, image: &str) -> Result<ResolvedImage> {
    let (full, name, creds) = match &cfg.docker {
        Some(dk) => match route(dk, image)? {
            Route::Repo { full, name } => (full, name, Creds::from_docker(dk)?),
            // route() only returns Mirror when dk.mirror is Some.
            Route::Mirror { full, name } => {
                (full, name, Creds::from_mirror(dk.mirror.as_ref().unwrap())?)
            }
            Route::Direct => (image.to_string(), ref_cache_name(image)?, Creds::anon()),
        },
        None => (image.to_string(), ref_cache_name(image)?, Creds::anon()),
    };
    resolve_full(cfg, state_dir, &name, &full, &creds)
}

/// Registry credentials for one pull. Anonymous for a direct pull; from `[docker]` when a
/// bare name is routed onto the configured proxy repo, or from `[docker.mirror]` when a
/// Docker Hub ref is routed through the mirror.
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

    fn from_parts(
        ca_file: Option<&Path>,
        username: &str,
        password_file: Option<&Path>,
        insecure: bool,
    ) -> Result<Creds> {
        let ca_pem = ca_file
            .map(|p| std::fs::read(p).with_context(|| format!("reading {}", p.display())))
            .transpose()?;
        let password = password_file
            .map(|p| {
                std::fs::read_to_string(p)
                    .map(|s| s.trim_end().to_string())
                    .with_context(|| format!("reading {}", p.display()))
            })
            .transpose()?;
        let username = (!username.is_empty()).then(|| username.to_string());
        Ok(Creds {
            username,
            password,
            ca_pem,
            insecure,
        })
    }

    fn from_docker(dk: &crate::config::Docker) -> Result<Creds> {
        Self::from_parts(
            dk.ca_file.as_deref(),
            &dk.username,
            dk.password_file.as_deref(),
            dk.insecure,
        )
    }

    fn from_mirror(m: &crate::config::Mirror) -> Result<Creds> {
        Self::from_parts(
            m.ca_file.as_deref(),
            &m.username,
            m.password_file.as_deref(),
            m.insecure,
        )
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

/// How an `image:` resolves against a configured `[docker]`.
#[derive(Debug, PartialEq)]
enum Route {
    /// Fetch through the `repo` proxy (its credentials): the full ref + the cache name.
    Repo { full: String, name: String },
    /// Fetch through the Docker Hub `mirror` (its credentials): the full ref + cache name.
    Mirror { full: String, name: String },
    /// The ref names its own registry — pull it from there directly (anonymous).
    Direct,
}

/// Route a job's `image:` against a configured `[docker]`. Precedence:
///   1. a ref already under `repo` → through the repo proxy;
///   2. a Docker Hub ref (bare name or explicit docker.io host) with a `[docker.mirror]`
///      set → through the mirror, `library/`-normalized (the registry-mirrors behaviour);
///   3. otherwise the legacy routing — a ref naming its own registry is pulled directly, a
///      bare docker-hub name is routed onto `repo` (or pulled directly if there is no repo).
///
/// Nothing is refused — the proxy routes, it does not gate.
fn route(dk: &Docker, image: &str) -> Result<Route> {
    if let Some(repo) = dk.repo.as_deref() {
        let prefix = format!("{repo}/");
        if let Some(rest) = image.strip_prefix(&prefix) {
            return Ok(Route::Repo {
                full: image.to_string(),
                name: name_of(rest)?,
            });
        }
    }
    let (repo_path, suffix) = split_ref(image);
    if let Some(m) = &dk.mirror
        && let Some(hub) = docker_hub_repo(repo_path)
    {
        return Ok(Route::Mirror {
            full: format!("{}/{hub}{suffix}", m.repo),
            name: name_of(&hub)?,
        });
    }
    if host_qualified(repo_path) {
        return Ok(Route::Direct);
    }
    match dk.repo.as_deref() {
        Some(repo) => Ok(Route::Repo {
            full: format!("{repo}/{image}"),
            name: name_of(image)?,
        }),
        // A bare docker-hub name with nothing to route through: pulled directly from Hub.
        None => Ok(Route::Direct),
    }
}

/// Docker Hub host aliases a ref may spell out — all normalize to the same registry.
const DOCKER_HUB_HOSTS: &[&str] = &["docker.io", "index.docker.io", "registry-1.docker.io"];

/// Split an OCI ref into its repository path and the `:tag`/`@digest` suffix (`""` if none).
/// A registry-host `:port` before the first `/` stays part of the repository (same rule as
/// `pin_digest`), so it is not mistaken for a tag.
fn split_ref(image: &str) -> (&str, &str) {
    if let Some(i) = image.find('@') {
        return (&image[..i], &image[i..]);
    }
    let tag_at = match image.rfind('/') {
        Some(slash) => image[slash..].find(':').map(|i| slash + i),
        None => image.find(':'),
    };
    match tag_at {
        Some(i) => (&image[..i], &image[i..]),
        None => (image, ""),
    }
}

/// Whether a ref's first `/`-segment names a registry host: it carries a `.`/`:` or is
/// `localhost` (Docker's own heuristic).
fn is_registry_host(host: &str) -> bool {
    host.contains('.') || host.contains(':') || host == "localhost"
}

/// Whether a ref's first `/`-segment names a registry host (see `is_registry_host`).
fn host_qualified(repo_path: &str) -> bool {
    matches!(repo_path.split_once('/'), Some((host, _)) if is_registry_host(host))
}

/// If `repo_path` (no tag/digest) is a Docker Hub repository — a bare name with no registry
/// host, or one explicitly under a Docker Hub host — return its canonical repository path
/// with `library/` prepended for single-segment official images (the normalization Docker's
/// client applies before talking to a mirror). `None` for any other registry.
fn docker_hub_repo(repo_path: &str) -> Option<String> {
    let bare = match repo_path.split_once('/') {
        Some((host, rest)) if is_registry_host(host) => {
            if DOCKER_HUB_HOSTS.contains(&host) {
                rest
            } else {
                return None;
            }
        }
        _ => repo_path,
    };
    if bare.contains('/') {
        Some(bare.to_string())
    } else {
        Some(format!("library/{bare}"))
    }
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
        Some((host, rest)) if is_registry_host(host) => rest,
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

    /// A `[docker]` with the given `repo` and optional Hub `mirror`, no auth — for `route`.
    fn dk(repo: Option<&str>, mirror: Option<&str>) -> Docker {
        Docker {
            repo: repo.map(String::from),
            ca_file: None,
            username: String::new(),
            password_file: None,
            insecure: false,
            mirror: mirror.map(|r| crate::config::Mirror {
                repo: r.to_string(),
                ca_file: None,
                username: String::new(),
                password_file: None,
                insecure: false,
            }),
        }
    }

    #[test]
    fn route_maps_bare_names_but_passes_other_registries_through() {
        let repo = "10.10.140.49/common/wab-ci";
        let d = dk(Some(repo), None);
        // bare docker-hub-style name → routed onto the proxy repo (no library/ rewrite)
        assert_eq!(
            route(&d, "wabbuilder:v1").unwrap(),
            Route::Repo {
                full: format!("{repo}/wabbuilder:v1"),
                name: "wabbuilder".into()
            }
        );
        assert_eq!(
            route(&d, "alpine").unwrap(),
            Route::Repo {
                full: format!("{repo}/alpine"),
                name: "alpine".into()
            }
        );
        // already under the repo → passes through the proxy
        assert_eq!(
            route(&d, &format!("{repo}/team/img:t")).unwrap(),
            Route::Repo {
                full: format!("{repo}/team/img:t"),
                name: "team/img".into()
            }
        );
        // a different registry → pulled directly, NOT refused (isolation is the boundary)
        assert_eq!(
            route(&d, "docker.io/library/alpine:3.20").unwrap(),
            Route::Direct
        );
        assert_eq!(route(&d, "evil.example.com/x").unwrap(), Route::Direct);
    }

    #[test]
    fn route_sends_docker_hub_through_the_mirror() {
        let d = dk(Some("10.10.140.49/common/wab-ci"), Some("hq-nexus:8440"));
        // bare official image → library/ prefix, onto the mirror
        assert_eq!(
            route(&d, "alpine:3.20").unwrap(),
            Route::Mirror {
                full: "hq-nexus:8440/library/alpine:3.20".into(),
                name: "library/alpine".into()
            }
        );
        // bare user image → no library/ prefix
        assert_eq!(
            route(&d, "grafana/grafana:11").unwrap(),
            Route::Mirror {
                full: "hq-nexus:8440/grafana/grafana:11".into(),
                name: "grafana/grafana".into()
            }
        );
        // explicit docker.io host, official image, @digest → normalized onto the mirror
        let dg = "@sha256:0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(
            route(&d, &format!("docker.io/redis{dg}")).unwrap(),
            Route::Mirror {
                full: format!("hq-nexus:8440/library/redis{dg}"),
                name: "library/redis".into()
            }
        );
        // explicit index.docker.io host, already namespaced → kept as-is
        assert_eq!(
            route(&d, "index.docker.io/library/nginx:1.27").unwrap(),
            Route::Mirror {
                full: "hq-nexus:8440/library/nginx:1.27".into(),
                name: "library/nginx".into()
            }
        );
        // a CI image already under repo still goes through the repo, not the mirror
        assert_eq!(
            route(&d, "10.10.140.49/common/wab-ci/wabbuilder:v1").unwrap(),
            Route::Repo {
                full: "10.10.140.49/common/wab-ci/wabbuilder:v1".into(),
                name: "wabbuilder".into()
            }
        );
        // a non-Hub registry has no mirror → still pulled directly
        assert_eq!(route(&d, "ghcr.io/foo/bar:1").unwrap(), Route::Direct);
    }

    #[test]
    fn route_mirror_only_config_has_no_repo() {
        // [docker] carrying only a [docker.mirror] (repo unused): Hub refs → mirror; a
        // non-Hub registry → direct.
        let d = dk(None, Some("hq-nexus:8440"));
        assert_eq!(
            route(&d, "alpine").unwrap(),
            Route::Mirror {
                full: "hq-nexus:8440/library/alpine".into(),
                name: "library/alpine".into()
            }
        );
        assert_eq!(route(&d, "ghcr.io/foo/bar:1").unwrap(), Route::Direct);
    }

    #[test]
    fn route_refuses_path_traversal_when_mapping_onto_the_repo() {
        let repo = "10.10.140.49/common/wab-ci";
        let d = dk(Some(repo), None);
        // `..` in a bare name maps onto the repo but must not escape the cache root.
        assert!(route(&d, "foo/../../../bar").is_err());
        // `..` in the tail of a repo-prefixed ref (the pass-through branch) is refused too.
        assert!(route(&d, &format!("{repo}/../evil/x")).is_err());
        assert!(route(&d, &format!("{repo}/team/../evil")).is_err());
        // a bare `..` component is refused.
        assert!(route(&d, "..").is_err());
        // `..` routed onto the mirror is refused as well.
        let m = dk(None, Some("hq-nexus:8440"));
        assert!(route(&m, "foo/../evil").is_err());
    }

    #[test]
    fn split_ref_separates_tag_and_digest_keeping_host_port() {
        assert_eq!(split_ref("alpine"), ("alpine", ""));
        assert_eq!(split_ref("alpine:3.20"), ("alpine", ":3.20"));
        assert_eq!(split_ref("team/img@sha256:d"), ("team/img", "@sha256:d"));
        // a registry-host :port before the first '/' is not a tag
        assert_eq!(split_ref("hq-nexus:8440/img"), ("hq-nexus:8440/img", ""));
        assert_eq!(
            split_ref("hq-nexus:8440/img:v1"),
            ("hq-nexus:8440/img", ":v1")
        );
    }

    #[test]
    fn docker_hub_repo_normalizes_official_images() {
        assert_eq!(docker_hub_repo("alpine").as_deref(), Some("library/alpine"));
        assert_eq!(
            docker_hub_repo("grafana/grafana").as_deref(),
            Some("grafana/grafana")
        );
        assert_eq!(
            docker_hub_repo("docker.io/redis").as_deref(),
            Some("library/redis")
        );
        assert_eq!(
            docker_hub_repo("registry-1.docker.io/library/nginx").as_deref(),
            Some("library/nginx")
        );
        // a non-Hub registry is not a Hub repo
        assert_eq!(docker_hub_repo("ghcr.io/foo/bar"), None);
        assert_eq!(docker_hub_repo("localhost:5000/img"), None);
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
