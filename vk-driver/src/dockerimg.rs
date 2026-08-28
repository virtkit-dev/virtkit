//! Boot a `docker/<name>[:tag|@sha256:…]` (or bare `image:`) job image DIRECTLY from its
//! registry.
//!
//! Where it is pulled *from* is only a routing question — the microVM boundary is the
//! security model, so the image source is not gated and nothing here refuses an image. An
//! optional `[docker]` proxy routes bare names through its `repo` and Docker Hub refs
//! through a `[docker.mirror]` (see `route`); anything it does not claim is offered to the
//! vk-registry this host already uses, which relays and caches the upstreams it is
//! configured for, and pulled from its own registry otherwise (see `resolve_unrouted`).
//! The image is pulled with the native OCI client and flattened into a byte-clean bootable
//! ext4 booted on the embedded kernel (the agent rides the boot initramfs, nothing is
//! injected into the rootfs). The image's Config.Env/User/WorkingDir/Entrypoint/Cmd are
//! captured into a `runner.ext4.json` sidecar the boot applies, so the guest runs like
//! `docker run` would. Results cache under `<state_dir>/docker/<name>/<digest>/` with the
//! same pull lock + GC as the bundle registry.
//!
//! This is the OCI-direct path `vk run --source oci` uses, wired into the executor, so a
//! runner host provisions the guest with just the `vk` binary.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::blockrt::block_on;
use crate::config::{Build, Config, Docker, Registry};
use crate::image::{self, BootKind, Reference, ResolvedImage};
use crate::oci::Creds;

/// `MICROVM_IMAGE: docker/<name>[:tag|@digest]`. Routed onto `[docker].repo` (with its
/// credentials) when that is set; with no repo — an absent `[docker]`, or one carrying only
/// a `[docker.mirror]` — it is a raw OCI ref, offered to the configured vk-registry first
/// (see [`relayed`]) and pulled from its own registry otherwise. The Docker-Hub-only
/// mirror does not apply to this explicit form.
pub fn resolve(cfg: &Config, state_dir: &Path, image_ref: &str) -> Result<ResolvedImage> {
    let (name, reference) = image::parse_ref(image_ref)?;
    match cfg.docker.as_ref().filter(|d| d.repo.is_some()) {
        Some(dk) => {
            let repo = dk.repo.as_deref().unwrap();
            let full = match &reference {
                Reference::Digest(d) => format!("{repo}/{name}@{d}"),
                Reference::Tag(t) => format!("{repo}/{name}:{t}"),
            };
            resolve_full(cfg, state_dir, &name, &full, &Creds::from_docker(dk)?)
        }
        None => {
            let full = match &reference {
                Reference::Digest(d) => format!("{name}@{d}"),
                Reference::Tag(t) => format!("{name}:{t}"),
            };
            resolve_unrouted(cfg, state_dir, &name, &full)
        }
    }
}

/// The job's GitLab `image:` (CI_JOB_IMAGE): a full or bare OCI ref. A `[docker]` proxy
/// *routes* pulls when one is configured (see `route`): a bare docker-hub-style name is
/// fetched through the configured repo, a Docker Hub ref through the `[docker.mirror]` when
/// one is set. A ref nothing routes goes to [`resolve_unrouted`] — the configured
/// vk-registry, else the registry the ref names. Nothing is refused on the basis of where
/// the image lives; the microVM boundary is the security model, not an image-source
/// allowlist.
pub fn resolve_image(cfg: &Config, state_dir: &Path, image: &str) -> Result<ResolvedImage> {
    let (full, name, creds) = match &cfg.docker {
        Some(dk) => match route(dk, image)? {
            Route::Repo { full, name } => (full, name, Creds::from_docker(dk)?),
            // route() only returns Mirror when dk.mirror is Some.
            Route::Mirror { full, name } => {
                (full, name, Creds::from_mirror(dk.mirror.as_ref().unwrap())?)
            }
            Route::Direct => {
                return resolve_unrouted(cfg, state_dir, &ref_cache_name(image)?, image);
            }
        },
        None => return resolve_unrouted(cfg, state_dir, &ref_cache_name(image)?, image),
    };
    resolve_full(cfg, state_dir, &name, &full, &creds)
}

/// A ref no `[docker]` routing claims: offer it to the vk-registry this host already uses for its
/// build cache, and fall back to the registry the ref itself names.
fn resolve_unrouted(
    cfg: &Config,
    state_dir: &Path,
    name: &str,
    image: &str,
) -> Result<ResolvedImage> {
    // A digest-pinned ref already names its content, so a warm cache settles it without
    // asking anyone — the no-network path pinning buys, which the relay must not cost.
    // The digest is validated first: it comes from the job's own `image:`, and everything
    // below joins it onto a path.
    if let Some((_, digest)) = image.rsplit_once('@')
        && image::parse_digest(digest).is_some()
        && image_cache_dir(state_dir, name, digest)
            .join("runner.ext4")
            .is_file()
    {
        return resolve_pinned(cfg, state_dir, name, image, &Creds::anonymous(), digest);
    }
    if let Some((host, relay)) = relay_target(cfg)
        && let Some(via) = relayed(&host, image)
    {
        // The credential is read only now, once this ref really is going to that registry:
        // an unreadable file must not keep a ref the relay would have declined anyway —
        // nor any ref — from being pulled where it lives.
        let asked = relay.creds().and_then(|creds| {
            let digest = block_on(crate::oci::resolve_digest_if_present(&via, &creds))?;
            Ok((digest, creds))
        });
        match asked {
            Ok((Some(digest), creds)) => {
                return resolve_pinned(cfg, state_dir, name, &via, &creds, &digest);
            }
            // Not one of the upstreams it relays: ordinary, and not worth a line.
            Ok((None, _)) => {}
            // Nor is a key scoped to this runner's own repositories being refused the
            // relay namespace — that is how a scoped API key is meant to behave.
            Err(e) if crate::oci::is_access_denied(&e) => {}
            // Reachable-but-failing (an expired key, TLS, DNS, an unreadable credential
            // file) is not ordinary. Say it, and still pull the image rather than failing
            // a job over a cache.
            Err(e) => {
                eprintln!("virtkit: {host} could not serve {image} ({e:#}) — pulling it directly")
            }
        }
    }
    resolve_full(cfg, state_dir, name, image, &Creds::anonymous())
}

/// The config section [`relay_target`] picked the registry from, so its credential files
/// are read only once a ref is actually offered to that registry.
enum Relay<'a> {
    BuildCache(&'a Build),
    Registry(&'a Registry),
}

impl Relay<'_> {
    fn creds(&self) -> Result<Creds> {
        match self {
            Relay::BuildCache(b) => Creds::from_build_cache(b),
            Relay::Registry(rg) => Creds::from_registry(rg),
        }
    }
}

/// The vk-registry this host is already configured against: the host to offer a pull to, and the
/// section its credential comes from. `[build] cache_registry` (what a CI runner is given) wins
/// over `[registry]`.
fn relay_target(cfg: &Config) -> Option<(String, Relay<'_>)> {
    // A host oci-spec would not read as one is worse than no relay: a dotless
    // `cache_registry = "buildcache/…"` makes `buildcache/docker.io/library/alpine` parse
    // as a Docker Hub repository, which would send this runner's key to Docker Hub.
    let host_of = |repo: &str| {
        Registry::local_root_of(repo)
            .is_none()
            .then(|| repo.split('/').next())
            .flatten()
            .filter(|h| registry_host_name(h))
            .map(str::to_string)
    };
    if let Some(repo) = crate::build::cache_repo(cfg.build.cache_registry.as_deref())
        .ok()
        .flatten()
        && let Some(host) = host_of(&repo)
    {
        return Some((host, Relay::BuildCache(&cfg.build)));
    }
    let rg = cfg.registry.as_ref()?;
    Some((host_of(&rg.repo)?, Relay::Registry(rg)))
}

/// `image` as this vk-registry would name it: the registry it lives in becomes the first
/// path component, so `alpine:3` is `<host>/docker.io/library/alpine:3` and
/// `ghcr.io/o/i:1` is `<host>/ghcr.io/o/i:1` — the shape a relay `[[upstream]] prefix`
/// matches and strips before forwarding.
///
/// `None` for a ref that cannot be named that way — an origin the registry could not take
/// as a path component (see [`relayable_origin`]), or a repository path that is not itself
/// legal (see [`repo_component`]) — which is then pulled directly.
fn relayed(host: &str, image: &str) -> Option<String> {
    let (repo_path, suffix) = split_ref(image);
    let (origin, rest) = match repo_path.split_once('/') {
        Some((h, rest)) if is_registry_host(h) && !DOCKER_HUB_HOSTS.contains(&h) => {
            (h.to_string(), rest.to_string())
        }
        // A bare name is a Docker Hub reference, `library/` and all — and so is one under
        // any Hub alias. Every alias lands on the one prefix, so a relay needs one entry
        // and the cache is not split three ways for the same image. `docker_hub_repo`
        // returns `None` only for a non-Hub registry host, which this arm cannot see.
        _ => ("docker.io".to_string(), docker_hub_repo(repo_path)?),
    };
    (relayable_origin(&origin, host) && rest.split('/').all(repo_component))
        .then(|| format!("{host}/{origin}/{rest}{suffix}"))
}

/// Whether `origin` can name the registry a ref comes from as the first path component of
/// a repository on `host`. It cannot when:
///
/// - it carries a `:port`, since a repository name has no place for a colon;
/// - it is `host` itself, which would nest that registry under its own name — compared
///   case-insensitively, as registry hosts are;
/// - it is a loopback name, which means nothing to a registry on another machine;
/// - it is not a legal repository path component (see [`repo_component`]).
fn relayable_origin(origin: &str, host: &str) -> bool {
    // The relay may be reached on a port; a ref's origin never carries one, so compare the
    // bare names — either spelling would still nest that registry under its own name.
    let bare = host.split(':').next().unwrap_or(host);
    repo_component(origin)
        && !origin.eq_ignore_ascii_case(bare)
        && origin != "localhost"
        && !origin.starts_with("127.")
}

/// Whether `s` is one legal component of a repository path: lowercase alphanumerics with
/// single `.`, `-` or `_` separators between them. Anything else the registry answers with
/// `NAME_INVALID`, which is a wasted round trip and a warning line rather than a pull.
fn repo_component(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-._".contains(&b))
        && !s.starts_with(['-', '.', '_'])
        && !s.ends_with(['-', '.', '_'])
        && !s.contains("..")
}

/// Whether `h` is a registry host this can namespace a ref under: one oci-spec reads as a
/// host at all (see [`is_registry_host`]), whose name is a legal repository component and
/// whose `:port`, if any, is a number.
fn registry_host_name(h: &str) -> bool {
    let (name, port) = h.split_once(':').map_or((h, None), |(n, p)| (n, Some(p)));
    is_registry_host(h)
        && repo_component(name)
        && port.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Where a pulled image lands: `<state_dir>/docker/<name>/<digest>/`, holding the
/// `runner.ext4` rootfs and its config sidecar.
fn image_cache_dir(state_dir: &Path, name: &str, digest: &str) -> PathBuf {
    state_dir
        .join("docker")
        .join(name)
        .join(digest.trim_start_matches("sha256:"))
}

/// Pull + cache + boot the OCI ref `full` with `creds` (cache-keyed by `name` + digest).
fn resolve_full(
    cfg: &Config,
    state_dir: &Path,
    name: &str,
    full: &str,
    creds: &Creds,
) -> Result<ResolvedImage> {
    let digest = block_on(crate::oci::resolve_digest_auth(full, creds))
        .with_context(|| format!("resolving {full}"))?;
    resolve_pinned(cfg, state_dir, name, full, creds, &digest)
}

/// [`resolve_full`] from its resolved digest on — split out so the relay path, which
/// learns the digest while asking whether the registry holds the image at all, does not
/// resolve it a second time.
fn resolve_pinned(
    cfg: &Config,
    state_dir: &Path,
    name: &str,
    full: &str,
    creds: &Creds,
    digest: &str,
) -> Result<ResolvedImage> {
    // Every path below is built from `digest`, which reaches here from a job's `image:` or
    // from a registry's `Docker-Content-Digest` — neither is ours. A digest that is not
    // one is a bug or an attempt at one, not a cache miss to paper over.
    if image::parse_digest(digest).is_none() {
        bail!("{full} resolved to {digest:?}, which is not a sha256 digest");
    }
    // Pull by the resolved digest, not the tag, so the digest-keyed cache dir is always
    // populated with exactly that content even if the tag moves under us (mirrors the
    // registry bundle path, which pulls via make_digest_ref). The rootfs is a byte-clean
    // flatten (the embedded agent rides the boot initramfs), so the digest keys the cache
    // — a vk update changes the boot agent, not the image.
    let pinned = pin_digest(full, digest);

    let dir = image_cache_dir(state_dir, name, digest);
    if !dir.join("runner.ext4").is_file() {
        let _lock = image::acquire_pull_lock(&dir, "pull", name, digest)?;
        if !dir.join("runner.ext4").is_file() {
            // Reclaim scratch orphaned by earlier failed/killed pulls of *other* images
            // before asking for more space ourselves — otherwise a tier stuck failing
            // (e.g. ENOSPC) never gets a chance to recover.
            image::sweep_orphaned_build_tmp(&state_dir.join("docker"));
            build(&pinned, creds, &dir)?;
            let docker_root = state_dir.join("docker");
            image::gc_idle(&docker_root, cfg.image_cache_idle());
            image::sweep_orphaned_build_tmp(&docker_root);
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
fn build(full: &str, creds: &Creds, dir: &Path) -> Result<()> {
    let tmp = dir.with_extension("tmp");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    // Wipe `tmp` the instant the pull below fails (or panics) — don't leave that for a
    // later sweep to notice. `image::sweep_orphaned_build_tmp` backstops the case nothing
    // can run at all (SIGKILL/OOM).
    let cleanup = image::TmpGuard::new(&tmp);
    println!("virtkit: pulling {full} ...");
    // Flatten the image byte-clean (the agent rides the boot initramfs) and capture its
    // Config into the runner.ext4.json sidecar — the shared OCI-flatten core. A journalled
    // fs and no freshness UUID: the digest-keyed cache dir is this image's identity.
    let rootfs = tmp.join("runner.ext4");
    block_on(crate::source::oci_flatten(
        full,
        creds,
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
    cleanup.keep(); // pulled successfully: the rename below takes ownership of `tmp`.
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

/// If `repo_path` (a repository path, though `split_ref` leaves a `:tag` on it when an
/// `@digest` follows) is a Docker Hub repository — a bare name with no registry
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
            token_file: None,
            insecure: false,
            mirror: mirror.map(|r| crate::config::Mirror {
                repo: r.to_string(),
                ca_file: None,
                username: String::new(),
                password_file: None,
                token_file: None,
                insecure: false,
            }),
        }
    }

    /// Every registry a ref can name becomes a path component under the vk-registry, so
    /// one `[[upstream]] prefix` per upstream matches it — and the Hub aliases collapse
    /// onto one prefix rather than caching the same image three times.
    #[test]
    fn a_relayed_ref_namespaces_the_origin_registry() {
        let reg = "ci-repositories.corp.wallix.com";
        let via = |image: &str| relayed(reg, image);
        assert_eq!(
            via("alpine:3.20").as_deref(),
            Some("ci-repositories.corp.wallix.com/docker.io/library/alpine:3.20")
        );
        assert_eq!(
            via("grafana/grafana").as_deref(),
            Some("ci-repositories.corp.wallix.com/docker.io/grafana/grafana")
        );
        for hub in DOCKER_HUB_HOSTS {
            assert_eq!(
                via(&format!("{hub}/library/alpine:3")).as_deref(),
                Some("ci-repositories.corp.wallix.com/docker.io/library/alpine:3"),
                "{hub}"
            );
        }
        assert_eq!(
            via("ghcr.io/o/i@sha256:dead").as_deref(),
            Some("ci-repositories.corp.wallix.com/ghcr.io/o/i@sha256:dead")
        );
        // A digest-pinned bare name is still a Hub reference, `library/` and all.
        assert_eq!(
            via("alpine@sha256:dead").as_deref(),
            Some("ci-repositories.corp.wallix.com/docker.io/library/alpine@sha256:dead")
        );
        // A Hub-hosted repository that is not an official image keeps its namespace.
        assert_eq!(
            via("docker.io/grafana/grafana:11").as_deref(),
            Some("ci-repositories.corp.wallix.com/docker.io/grafana/grafana:11")
        );
        // A relay reached on a port is still a registry host; only the *origin* may not
        // carry one.
        assert_eq!(
            relayed("127.0.0.1:5000", "alpine:3").as_deref(),
            Some("127.0.0.1:5000/docker.io/library/alpine:3")
        );
    }

    /// The refs whose origin cannot be a path component on the registry, and so are pulled
    /// where they live: a host with a port (a repository name has no place for a colon), a
    /// loopback name (meaningless to a registry on another machine), one the registry would
    /// reject as `NAME_INVALID`, and one already served by this very registry.
    #[test]
    fn a_ref_that_cannot_be_namespaced_is_not_relayed() {
        let reg = "ci-repositories.corp.wallix.com";
        assert_eq!(relayed(reg, "myreg.corp:5000/team/img:v1"), None);
        assert_eq!(relayed(reg, "localhost:5000/img"), None);
        assert_eq!(relayed(reg, "localhost/img"), None);
        assert_eq!(relayed(reg, "127.0.0.1/img:v1"), None);
        assert_eq!(relayed(reg, "MyReg.corp/img"), None);
        // The repository path is checked too, not only the registry it comes from.
        assert_eq!(relayed(reg, "ghcr.io/O/I:1"), None);
        assert_eq!(relayed(reg, "ghcr.io/o/..%2fi"), None);
        assert_eq!(
            relayed(reg, &format!("{reg}/docker.io/library/alpine:3")),
            None
        );
        assert_eq!(relayed(reg, &format!("{reg}/virtkit/build-cache:x")), None);
        // Registry hosts are case-insensitive, so this one still nests under itself.
        assert_eq!(relayed(reg, &format!("{}/o/i", reg.to_uppercase())), None);
    }

    /// A ref pinned to something that is not a digest never becomes a cache path: it
    /// arrives from a job's own `image:`, and every path below `resolve_pinned` is built
    /// by joining it.
    #[test]
    fn a_ref_pinned_to_a_non_digest_is_refused() {
        let state_dir = std::env::temp_dir().join(format!("vk-dockerimg-{}", std::process::id()));
        let err = resolve_pinned(
            &Config::default(),
            &state_dir,
            "foo/bar",
            "foo/bar@../../../../var/tmp/evil",
            &Creds::anonymous(),
            "../../../../var/tmp/evil",
        )
        .err()
        .expect("a non-digest must not become a cache path");
        assert!(err.to_string().contains("not a sha256 digest"), "{err}");
        assert!(
            !state_dir.exists(),
            "it must not touch the filesystem either"
        );
    }

    /// `[build] cache_registry` is what a CI runner is handed, so it wins; `[registry]` is
    /// the fallback. Neither a local store nor a spelling that names no server is a relay,
    /// and working that out never fails — an image is pulled either way.
    #[test]
    fn the_relay_target_prefers_the_build_cache_registry() {
        let cfg = |cache: Option<&str>, registry: Option<&str>| Config {
            build: crate::config::Build {
                cache_registry: cache.map(String::from),
                ..crate::config::Build::default()
            },
            registry: registry.map(|repo| {
                Registry::for_share(
                    repo.to_string(),
                    false,
                    None,
                    String::new(),
                    None,
                    None,
                    None,
                )
            }),
            ..Config::default()
        };
        let host = |c: Config| relay_target(&c).map(|(h, _)| h);

        assert_eq!(
            host(cfg(Some("cache.corp/virtkit"), Some("other.corp/team"))).as_deref(),
            Some("cache.corp")
        );
        assert!(matches!(
            relay_target(&cfg(Some("cache.corp/virtkit"), None)),
            Some((_, Relay::BuildCache(_)))
        ));
        assert!(matches!(
            relay_target(&cfg(Some("none"), Some("other.corp/team"))),
            Some((_, Relay::Registry(_)))
        ));
        assert_eq!(host(cfg(Some("none"), None)), None);
        // A local store is not a registry to ask, spelled either way.
        assert_eq!(host(cfg(Some("/var/lib/vk/store"), None)), None);
        assert_eq!(host(cfg(Some("file:///var/lib/vk/store"), None)), None);
        assert_eq!(
            host(cfg(Some("none"), Some("file:///var/lib/vk/store"))),
            None
        );
        assert_eq!(host(cfg(Some("none"), Some("/var/lib/vk/store"))), None);
        // A malformed cache_registry is `vk build`'s to report, not this pull's.
        assert_eq!(host(cfg(Some("./cache"), None)), None);
        // The default: no cache_registry named, so `[registry]` answers.
        assert_eq!(
            host(cfg(None, Some("other.corp/team"))).as_deref(),
            Some("other.corp")
        );
        // A host oci-spec would read as a repository, not a registry, is no relay at all —
        // namespacing under it would send this runner's credential to Docker Hub.
        assert_eq!(host(cfg(Some("buildcache/virtkit"), None)), None);
        assert_eq!(host(cfg(Some("none"), Some("https://reg.corp/team"))), None);
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
