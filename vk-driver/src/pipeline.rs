//! A hub-placed job's pipeline scope: the images the pipeline's jobs built, named
//! `pipeline/build/<name>[:job-<id>][@sha256:…]`, which live in the pipeline namespace the
//! hub named in the job's start ([`JobRegistry::pipeline_prefix`]) under
//! `<prefix>/builds/<name>`, and the refusal of any reference written straight into that
//! namespace. See `docs/pipeline-images-design.md`.

use std::path::Path;

use anyhow::{Context, Result, bail};
use vk_hub_proto::dispatch::JobRegistry;

use crate::config::Config;
use crate::image::ResolvedImage;

/// What a pipeline's built images are named by.
pub const BUILD_REF: &str = "pipeline/build/";

/// The prefix reserved for a pipeline's images, built ones and captures.
const PIPELINE_REF: &str = "pipeline/";

/// The repository holding a pipeline's built images, one per name, below its prefix.
const BUILDS: &str = "builds";

/// The tag of the image last published under a name.
const CURRENT: &str = "current";

/// `pipeline/build/<name>[:job-<id>][@sha256:…]`.
#[derive(Debug, PartialEq, Eq)]
pub struct BuildRef {
    pub name: String,
    /// The producer job, from `:job-<id>`.
    pub job: Option<String>,
    pub digest: Option<String>,
}

impl BuildRef {
    /// Parse what follows [`BUILD_REF`].
    pub fn parse(spec: &str) -> Result<BuildRef> {
        let (rest, digest) = match spec.split_once('@') {
            // Lowercase only, as OCI writes digests: the registry's is compared to it as a string.
            Some((rest, d)) => match crate::image::parse_digest(d) {
                Some(d) => (rest, Some(d)),
                None => {
                    bail!("invalid pipeline image digest {d:?} (want sha256:<64 lowercase hex>)")
                }
            },
            None => (spec, None),
        };
        let (name, job) = match rest.split_once(':') {
            Some((name, tag)) => match tag.strip_prefix("job-").filter(|id| job_id_ok(id)) {
                Some(id) => (name, Some(id.to_string())),
                None => bail!("invalid pipeline image tag {tag:?} (want job-<job id>)"),
            },
            None => (rest, None),
        };
        if !vk_hub_proto::token::valid_component(name) {
            bail!("invalid pipeline image name {name:?} (want one repository name component)");
        }
        Ok(BuildRef {
            name: name.to_string(),
            job,
            digest,
        })
    }

    /// The tag it resolves by: the producer's, else [`CURRENT`].
    fn tag(&self) -> String {
        match &self.job {
            Some(id) => job_tag(id),
            None => CURRENT.to_string(),
        }
    }
}

impl std::fmt::Display for BuildRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{BUILD_REF}{}", self.name)?;
        if let Some(id) = &self.job {
            write!(f, ":job-{id}")?;
        }
        if let Some(d) = &self.digest {
            write!(f, "@{d}")?;
        }
        Ok(())
    }
}

/// GitLab job IDs are numbers, written without leading zeros so one job has one tag.
fn job_id_ok(id: &str) -> bool {
    (1..=20).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_digit()) && !id.starts_with('0')
}

fn job_tag(id: &str) -> String {
    format!("job-{id}")
}

/// The pipeline prefix the hub gave the job, checked against the repository grammar.
fn prefix(job: Option<&JobRegistry>) -> Result<&str> {
    let Some(prefix) = job.and_then(|j| j.pipeline_prefix.as_deref()) else {
        bail!(
            "{BUILD_REF} images need a job the hub placed with a pipeline namespace; this job has \
             none"
        );
    };
    checked(prefix)
}

/// `prefix`, refused unless it is in the repository grammar.
fn checked(prefix: &str) -> Result<&str> {
    if !vk_hub_proto::token::valid_prefix(prefix) {
        bail!("the hub named {prefix:?} for the job's pipeline namespace, not a repository name");
    }
    Ok(prefix)
}

/// The node's `[registry]` at `<prefix>/builds`, with `token` in place of its credential when
/// given.
fn builds(cfg: &Config, prefix: &str, token: Option<&str>) -> Result<crate::config::Registry> {
    let rg = cfg
        .registry
        .as_ref()
        .with_context(|| format!("{BUILD_REF} images need a [registry] on this node"))?;
    crate::registry::at_path(rg, &format!("{prefix}/{BUILDS}"), token)
        .with_context(|| format!("{BUILD_REF} images need a remote [registry] on this node"))
}

/// Resolve a job's or one of its services' image: `pipeline/build/…` in the job's pipeline
/// namespace, any other `pipeline/…` refused as reserved, anything else through
/// [`crate::image::resolve_ref`] once [`refuse_direct`] has let it through. `job` is the
/// registry access in the job's start.
pub fn resolve_ref(
    cfg: &Config,
    state_dir: &Path,
    job: Option<&JobRegistry>,
    image: &str,
) -> Result<ResolvedImage> {
    if let Some(spec) = image.strip_prefix(BUILD_REF) {
        return resolve_build(cfg, state_dir, job, spec);
    }
    if image.starts_with(PIPELINE_REF) {
        bail!(
            "image {image}: {PIPELINE_REF} is reserved for the pipeline's images, and \
             `pipeline/<name>` captures are not supported yet"
        );
    }
    refuse_direct(cfg, job, image)?;
    crate::image::resolve_ref(cfg, state_dir, image)
}

/// `pipeline/build/<spec>`, pulled with the node's credential, always by tag.
fn resolve_build(
    cfg: &Config,
    state_dir: &Path,
    job: Option<&JobRegistry>,
    spec: &str,
) -> Result<ResolvedImage> {
    let r = BuildRef::parse(spec)?;
    let rg = builds(cfg, prefix(job)?, None)?;
    let found =
        crate::registry::resolve_tag(cfg, state_dir, &rg, &r.name, &r.tag(), r.digest.as_deref())
            .with_context(|| format!("image {r}"))?;
    match (found, &r.job) {
        (Some(image), _) => Ok(image),
        (None, Some(id)) => bail!(
            "image {r} is not in this pipeline: it expired or was never published; rerun job {id}, \
             which publishes it"
        ),
        (None, None) => {
            bail!("image {r} is not in this pipeline: it expired or was never published")
        }
    }
}

/// Refuse `image` when one of the node's credentials would pull it from a repository in the
/// pipeline namespace, by tag or by digest: a job reaches pipeline images through
/// `pipeline/build/` alone, which stays inside its own pipeline.
///
/// The node does not know the namespace's path template, so it cannot tell which components
/// name a pipeline. It refuses everything under `[registry] pipeline_root`, the path's root as
/// the operator gives it (`ci-pipeline` by default), whether or not the job has a pipeline, and
/// for a job that has one, everything under its prefix's first component too. That is more
/// than the namespace when an operator's path shares its root with other repositories.
pub fn refuse_direct(cfg: &Config, job: Option<&JobRegistry>, image: &str) -> Result<()> {
    let root = cfg
        .registry
        .as_ref()
        .map_or("ci-pipeline", |rg| rg.pipeline_root());
    let first = match job.and_then(|j| j.pipeline_prefix.as_deref()) {
        Some(prefix) => {
            let prefix = checked(prefix)?;
            Some(prefix.split_once('/').map_or(prefix, |(first, _)| first))
        }
        None => None,
    };
    let Some(repo) = lent_repository(cfg, image) else {
        return Ok(());
    };
    for root in std::iter::once(root).chain(first) {
        if vk_hub_proto::token::under(root, &repo) {
            bail!(
                "image {image}: {repo} is in the pipeline namespace ({root}/); name the \
                 pipeline's images as {BUILD_REF}<name>"
            );
        }
    }
    Ok(())
}

/// The repository path `image` is pulled from, when that is on the host of the section whose
/// credential the pull sends: `[registry]` for `virtkit/`, the `[docker]` repo or mirror for
/// what they route. A ref nothing routes is held to `[registry]`'s host, where the namespace
/// lives; the relay it is offered first files it under its origin's name, outside any
/// namespace. `None` for a local bundle and a pull from any other host.
fn lent_repository(cfg: &Config, image: &str) -> Option<String> {
    use crate::dockerimg::Via;
    let registry = cfg
        .registry
        .as_ref()
        .filter(|rg| rg.local_root().is_none())
        .map(|rg| Via {
            repo: &rg.repo,
            insecure: rg.insecure,
        });
    let (full, via) = match image.split_once('/') {
        Some(("local", _)) => return None,
        Some(("virtkit", rest)) => {
            let via = registry?;
            let (name, _) = crate::image::parse_ref(rest).ok()?;
            (format!("{}/{name}", via.repo), via)
        }
        // Without a `[docker]` repo, `docker/<name>` is a one-component Docker Hub name.
        Some(("docker", rest)) => {
            let dk = cfg.docker.as_ref()?;
            let via = Via {
                repo: dk.repo.as_deref()?,
                insecure: dk.insecure,
            };
            let (name, _) = crate::image::parse_ref(rest).ok()?;
            (format!("{}/{name}", via.repo), via)
        }
        _ => match crate::dockerimg::routed_repository(cfg, image) {
            (full, Some(via)) => (full, via),
            (full, None) => (full, registry?),
        },
    };
    let (host, path) = host_and_path(&full, via.insecure)?;
    let (lender, _) = host_and_path(via.repo, via.insecure)?;
    (host == lender).then(|| path.to_string())
}

/// `[<scheme>://]<host>[:<port>][/<path>]` as its host, lowercased and without the default
/// port of the scheme `insecure` picks (`:80` for HTTP, `:443` for HTTPS), and its path.
fn host_and_path(repo: &str, insecure: bool) -> Option<(String, &str)> {
    let repo = repo
        .strip_prefix("https://")
        .or_else(|| repo.strip_prefix("http://"))
        .unwrap_or(repo);
    let (authority, path) = repo.split_once('/').unwrap_or((repo, ""));
    if authority.is_empty() {
        return None;
    }
    let default = if insecure { "80" } else { "443" };
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if port == default => host,
        _ => authority,
    };
    Some((host.to_ascii_lowercase(), path.trim_matches('/')))
}

/// Publish the bundle `dir` as the image `name` of the job `job_id`'s pipeline: pushed to
/// `<prefix>/builds/<name>` with the job's token, tagged `job-<job id>`, then `current` moved
/// onto it. Refused when the job already published `name`. Returns the reference to it,
/// `pipeline/build/<name>:job-<job id>@<digest>`.
pub fn publish_build(
    cfg: &Config,
    job: Option<&JobRegistry>,
    job_id: &str,
    name: &str,
    dir: &Path,
) -> Result<BuildRef> {
    let rg = publication(cfg, job, job_id, name)?;
    let digest = crate::registry::push_once_then_tag(&rg, dir, name, &job_tag(job_id), CURRENT)
        .with_context(|| format!("publishing {BUILD_REF}{name}:{}", job_tag(job_id)))?;
    Ok(BuildRef {
        name: name.to_string(),
        job: Some(job_id.to_string()),
        digest: Some(digest),
    })
}

/// Refuse, before anything is built, what [`publish_build`] would: a job without a pipeline
/// namespace or a live token, and a name the job already published. `Ok(Err(why))` when
/// refused, `Err` when the registry could not say.
pub fn check_publishable(
    cfg: &Config,
    job: Option<&JobRegistry>,
    job_id: &str,
    name: &str,
) -> Result<Result<()>> {
    let rg = match publication(cfg, job, job_id, name) {
        Ok(rg) => rg,
        Err(why) => return Ok(Err(why)),
    };
    let tag = job_tag(job_id);
    Ok(match crate::registry::tag_digest_of(&rg, name, &tag)? {
        Some(digest) => Err(anyhow::anyhow!(
            "this job already published {BUILD_REF}{name}:{tag} ({digest}); a job publishes a name once"
        )),
        None => Ok(()),
    })
}

/// Where the job `job_id` publishes `name`: its pipeline's `builds/` with its token.
fn publication(
    cfg: &Config,
    job: Option<&JobRegistry>,
    job_id: &str,
    name: &str,
) -> Result<crate::config::Registry> {
    if !vk_hub_proto::token::valid_component(name) {
        bail!("invalid pipeline image name {name:?} (want one repository name component)");
    }
    if !job_id_ok(job_id) {
        bail!("invalid job id {job_id:?} for a pipeline image tag");
    }
    let prefix = prefix(job)?;
    let token = job
        .filter(|j| vk_peer::now_secs() < j.expires_at)
        .map(|j| j.token.as_str())
        .context("the job's registry token has expired")?;
    builds(cfg, prefix, Some(token))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(prefix: Option<&str>) -> JobRegistry {
        JobRegistry {
            registry_id: "9c2f4e1a7b3d5e60f1a2b3c4d5e6f708".into(),
            token: "vkt_x.y".into(),
            expires_at: u64::MAX,
            grants: Vec::new(),
            cache_repo: None,
            pipeline_prefix: prefix.map(str::to_string),
            areas: vec![],
        }
    }

    fn cfg(toml: &str) -> Config {
        toml::from_str(toml).unwrap()
    }

    /// The error a resolution ends in, `{:#}`-formatted.
    fn refusal(r: Result<ResolvedImage>) -> String {
        match r {
            Ok(_) => panic!("resolved"),
            Err(e) => format!("{e:#}"),
        }
    }

    const D: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn build_refs_parse_in_every_form() {
        let r = BuildRef::parse("runner").unwrap();
        assert_eq!(
            (r.name.as_str(), r.job.as_deref(), r.digest.as_deref()),
            ("runner", None, None)
        );
        assert_eq!(r.tag(), "current");
        let r = BuildRef::parse("runner:job-1234").unwrap();
        assert_eq!(r.job.as_deref(), Some("1234"));
        assert_eq!(r.tag(), "job-1234");
        let r = BuildRef::parse(&format!("runner:job-1234@{D}")).unwrap();
        assert_eq!(
            (r.job.as_deref(), r.digest.as_deref()),
            (Some("1234"), Some(D))
        );
        assert_eq!(r.to_string(), format!("pipeline/build/runner:job-1234@{D}"));
        let r = BuildRef::parse(&format!("my_img.v2@{D}")).unwrap();
        assert_eq!(
            (r.tag().as_str(), r.digest.as_deref()),
            ("current", Some(D))
        );
    }

    #[test]
    fn bad_build_refs_are_refused() {
        for bad in [
            "",
            "Runner",
            "a/b",
            "../x",
            "-x",
            "x-",
            "runner:latest",
            "runner:current",
            "runner:job-",
            "runner:job-12a",
            "runner:job-123456789012345678901",
            "runner:job-0",
            "runner:job-0123",
            "runner@sha256:abc",
            "runner@md5:0123",
            &format!("runner:job-1@{D}0"),
            &format!("runner@{D}@{D}"),
            &format!(
                "runner@{}",
                D.to_ascii_uppercase().replacen("SHA256", "sha256", 1)
            ),
            &format!("runner@{}F", &D[..D.len() - 1]),
        ] {
            assert!(BuildRef::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn build_refs_need_a_pipeline_prefix() {
        let c = cfg("[registry]\nrepo = \"reg.example/team\"\n");
        let dir = std::env::temp_dir();
        for job in [None, Some(job(None))] {
            let msg = refusal(resolve_ref(&c, &dir, job.as_ref(), "pipeline/build/runner"));
            assert!(msg.contains("pipeline namespace"), "{msg}");
        }
        let bad = job(Some("../x"));
        let msg = refusal(resolve_ref(&c, &dir, Some(&bad), "pipeline/build/runner"));
        assert!(msg.contains("not a repository name"), "{msg}");
        let err = publish_build(&c, None, "7", "runner", &dir).unwrap_err();
        assert!(format!("{err:#}").contains("pipeline namespace"), "{err:#}");
        let err = check_publishable(&c, Some(&job(None)), "7", "runner")
            .unwrap()
            .unwrap_err();
        assert!(format!("{err:#}").contains("pipeline namespace"), "{err:#}");
    }

    /// Every other `pipeline/` name is reserved, refused before anything is pulled.
    #[test]
    fn other_pipeline_refs_are_reserved() {
        let c = cfg("[registry]\nrepo = \"reg.example/team\"\n");
        let own = job(Some("ci-pipeline/gl/42/7"));
        for image in [
            "pipeline/runner",
            "pipeline/runner:current",
            "pipeline/build",
        ] {
            let msg = refusal(resolve_ref(&c, &std::env::temp_dir(), Some(&own), image));
            assert!(msg.contains("not supported yet"), "{image}: {msg}");
        }
    }

    #[test]
    fn direct_refs_into_the_pipeline_namespace_are_refused() {
        let own = job(Some("ci-pipeline/gl/42/7"));
        let refused =
            |c: &Config, j: Option<&JobRegistry>, image: &str| refuse_direct(c, j, image).is_err();
        // The node's registry repo inside the namespace: every `virtkit/` name lands there.
        let inside = cfg("[registry]\nrepo = \"reg.example:5000/ci-pipeline/gl/42/7/builds\"\n");
        assert!(refused(&inside, Some(&own), "virtkit/runner:current"));
        assert!(refused(&inside, Some(&own), &format!("virtkit/runner@{D}")));
        // Under a host-only repo, the namespace root itself is a refused repository.
        let host = cfg("[registry]\nrepo = \"reg.example:5000\"\n");
        assert!(refused(&host, Some(&own), "virtkit/ci-pipeline"));
        assert!(!refused(&host, Some(&own), "virtkit/ci-pipeline2"));
        assert!(!refused(&host, Some(&own), "virtkit/runner"));
        // A raw ref naming the registry: own pipeline, another one, by tag or digest.
        for image in [
            "reg.example:5000/ci-pipeline/gl/42/7/builds/runner:current".to_string(),
            "REG.example:5000/ci-pipeline/gl/43/9/builds/runner".to_string(),
            format!("reg.example:5000/ci-pipeline/gl/42/8/builds/runner:job-1@{D}"),
        ] {
            assert!(refused(&host, Some(&own), &image), "{image}");
        }
        assert!(!refused(
            &host,
            Some(&own),
            "reg.example:5000/images/runner:1"
        ));
        assert!(!refused(
            &host,
            Some(&own),
            "other.example/ci-pipeline/gl/42/7/x"
        ));
        assert!(!refused(&host, Some(&own), "local/default"));
        // A bare name the [docker] repo routes onto the registry.
        let routed = cfg("[registry]\nrepo = \"reg.example:5000/team\"\n\
             [docker]\nrepo = \"reg.example:5000\"\n");
        assert!(refused(
            &routed,
            Some(&own),
            "ci-pipeline/gl/43/9/builds/runner"
        ));
        assert!(refused(&routed, Some(&own), "docker/ci-pipeline"));
        assert!(!refused(&routed, Some(&own), "alpine:3"));
        // A prefix's first component is refused beside `pipeline_root`.
        let custom = job(Some("pipelines/gl/42/7"));
        assert!(refused(
            &host,
            Some(&custom),
            "reg.example:5000/pipelines/gl/1/2/x"
        ));
        assert!(refused(
            &host,
            Some(&custom),
            "reg.example:5000/ci-pipeline/gl/1/2/x"
        ));
        // An operator's path, named by `pipeline_root`, is refused to every job, one without a
        // pipeline prefix included.
        let rooted =
            cfg("[registry]\nrepo = \"reg.example:5000\"\npipeline_root = \"org/pipelines\"\n");
        for j in [None, Some(job(None)), Some(own.clone())] {
            assert!(refused(
                &rooted,
                j.as_ref(),
                "reg.example:5000/org/pipelines/gl/1/2/builds/x"
            ));
            assert!(!refused(
                &rooted,
                j.as_ref(),
                "reg.example:5000/org/other/x"
            ));
        }
        assert!(!refused(
            &rooted,
            None,
            "reg.example:5000/ci-pipeline/gl/1/2/x"
        ));
        // No prefix: the default path's root.
        assert!(refused(
            &host,
            None,
            "reg.example:5000/ci-pipeline/gl/1/2/x"
        ));
        assert!(refused(
            &host,
            Some(&job(None)),
            "reg.example:5000/ci-pipeline/gl/1/2/x"
        ));
        // `pipeline/build/` is the way in.
        assert!(!refused(&host, Some(&own), "pipeline/build/runner"));
        // A prefix outside the repository grammar refuses every image.
        for bad in ["../x", "Ci-pipeline/gl/1/2", "/ci-pipeline", ""] {
            assert!(refused(&host, Some(&job(Some(bad))), "alpine:3"), "{bad:?}");
        }
    }

    /// The host compared is that of the section whose credential the pull sends, `[registry]`
    /// or not, its default port implied.
    #[test]
    fn refusal_follows_the_credential_a_pull_sends() {
        let own = job(Some("ci-pipeline/gl/42/7"));
        let refused = |c: &Config, image: &str| refuse_direct(c, Some(&own), image).is_err();
        // `[docker] repo` on the registry's host, no `[registry]`.
        let docker = cfg("[docker]\nrepo = \"reg.example:5000\"\n");
        assert!(refused(&docker, "ci-pipeline/gl/43/9/builds/runner"));
        assert!(refused(&docker, "docker/ci-pipeline"));
        assert!(refused(
            &docker,
            "reg.example:5000/ci-pipeline/gl/43/9/builds/runner"
        ));
        assert!(!refused(&docker, "alpine:3"));
        assert!(!refused(&docker, "virtkit/ci-pipeline"));
        // A pull nothing routes, from the `[docker]` host: no credential goes with it.
        let team = cfg("[docker]\nrepo = \"reg.example:5000/team\"\n");
        assert!(!refused(
            &team,
            "reg.example:5000/ci-pipeline/gl/43/9/builds/runner"
        ));
        // `[docker.mirror] repo` on that host, for a Docker Hub name.
        let mirror = cfg("[docker.mirror]\nrepo = \"reg.example:5000\"\n");
        assert!(refused(&mirror, "ci-pipeline/gl/43/9/builds/runner"));
        assert!(refused(
            &mirror,
            "docker.io/ci-pipeline/gl/43/9/builds/runner"
        ));
        assert!(!refused(&mirror, "alpine:3"));
        let hub = cfg("[docker.mirror]\nrepo = \"reg.example:5000/hub\"\n");
        assert!(!refused(&hub, "ci-pipeline/gl/43/9/builds/runner"));
        // An explicit default port is the same host, for the section's scheme.
        let tls = cfg("[registry]\nrepo = \"reg.example\"\n");
        assert!(refused(
            &tls,
            "reg.example:443/ci-pipeline/gl/43/9/builds/runner"
        ));
        assert!(!refused(
            &tls,
            "reg.example:80/ci-pipeline/gl/43/9/builds/runner"
        ));
        let tls = cfg("[registry]\nrepo = \"reg.example:443/team\"\n");
        assert!(refused(
            &tls,
            "reg.example/ci-pipeline/gl/43/9/builds/runner"
        ));
        let http = cfg("[registry]\nrepo = \"reg.example\"\ninsecure = true\n");
        assert!(refused(
            &http,
            "reg.example:80/ci-pipeline/gl/43/9/builds/runner"
        ));
        assert!(!refused(
            &http,
            "reg.example:443/ci-pipeline/gl/43/9/builds/runner"
        ));
        let docker = cfg("[docker]\nrepo = \"reg.example:443\"\n");
        assert!(refused(&docker, "ci-pipeline/gl/43/9/builds/runner"));
        assert!(refused(&docker, "docker/ci-pipeline"));
    }

    /// A bundle as `vk build` leaves one, with `seed` making its content its own.
    fn bundle(dir: &Path, seed: u8) -> std::path::PathBuf {
        let b = dir.join(format!("bundle-{seed}"));
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(b.join("boot.kind"), "generic-disk").unwrap();
        std::fs::write(b.join("runner.ext4"), vec![seed; 100_000]).unwrap();
        b
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("vk-pipeline-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    const BUILDS_REPO: &str = "ci-pipeline/gl/42/7/builds/runner";

    fn tag_file(store: &Path, tag: &str) -> std::path::PathBuf {
        store.join("repos").join(BUILDS_REPO).join("tags").join(tag)
    }

    /// Published under the job's tag, then `current`; once per job and name.
    #[test]
    fn a_job_publishes_a_name_once() {
        let dir = tmpdir("publish");
        let store = dir.join("store");
        let c = Config {
            registry: Some(crate::registry::tests::served_store(&store)),
            ..Default::default()
        };
        let own = job(Some("ci-pipeline/gl/42/7"));
        check_publishable(&c, Some(&own), "11", "runner")
            .unwrap()
            .unwrap();
        let r1 = publish_build(&c, Some(&own), "11", "runner", &bundle(&dir, 1)).unwrap();
        let d1 = r1.digest.clone().unwrap();
        assert_eq!(r1.to_string(), format!("pipeline/build/runner:job-11@{d1}"));
        assert_eq!(
            std::fs::read_to_string(tag_file(&store, "job-11")).unwrap(),
            d1
        );
        assert_eq!(
            std::fs::read_to_string(tag_file(&store, "current")).unwrap(),
            d1
        );

        // A job publishes a name once, refused before a build as at the push.
        let err = check_publishable(&c, Some(&own), "11", "runner")
            .unwrap()
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("publishes a name once"),
            "{err:#}"
        );
        check_publishable(&c, Some(&own), "11", "other")
            .unwrap()
            .unwrap();
        // A registry that does not answer is a failure, not a refusal.
        let down = cfg("[registry]\nrepo = \"127.0.0.1:1/team\"\ninsecure = true\n");
        assert!(check_publishable(&down, Some(&own), "11", "runner").is_err());
        let err = publish_build(&c, Some(&own), "11", "runner", &bundle(&dir, 2)).unwrap_err();
        assert!(format!("{err:#}").contains("already exists"), "{err:#}");
        assert_eq!(
            std::fs::read_to_string(tag_file(&store, "current")).unwrap(),
            d1
        );

        let d2 = publish_build(&c, Some(&own), "12", "runner", &bundle(&dir, 2))
            .unwrap()
            .digest
            .unwrap();
        assert_ne!(d1, d2);
        assert_eq!(
            std::fs::read_to_string(tag_file(&store, "current")).unwrap(),
            d2
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Resolved by tag in the pipeline, the tag dated on every resolution, cached or not.
    #[test]
    fn a_published_image_resolves_in_its_pipeline() {
        let dir = tmpdir("resolve");
        let store = dir.join("store");
        let c = Config {
            registry: Some(crate::registry::tests::served_store(&store)),
            ..Default::default()
        };
        let state = dir.join("state");
        let own = job(Some("ci-pipeline/gl/42/7"));
        let d1 = publish_build(&c, Some(&own), "11", "runner", &bundle(&dir, 1))
            .unwrap()
            .digest
            .unwrap();
        let d2 = publish_build(&c, Some(&own), "12", "runner", &bundle(&dir, 2))
            .unwrap()
            .digest
            .unwrap();

        let rootfs = |image: &str| {
            let ResolvedImage::Disk { rootfs, .. } =
                resolve_ref(&c, &state, Some(&own), image).unwrap();
            std::fs::read(rootfs).unwrap()
        };
        assert_eq!(rootfs("pipeline/build/runner"), vec![2u8; 100_000]);
        assert_eq!(rootfs("pipeline/build/runner:job-11"), vec![1u8; 100_000]);
        assert_eq!(
            rootfs(&format!("pipeline/build/runner:job-11@{d1}")),
            vec![1u8; 100_000]
        );

        // Cached now, and still the tag is read.
        let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1 << 30);
        let set_old = || {
            std::fs::File::options()
                .write(true)
                .open(tag_file(&store, "job-11"))
                .unwrap()
                .set_modified(old)
                .unwrap()
        };
        set_old();
        rootfs("pipeline/build/runner:job-11");
        let mtime = || {
            std::fs::metadata(tag_file(&store, "job-11"))
                .unwrap()
                .modified()
                .unwrap()
        };
        assert!(mtime() > old, "a cached image's tag is read");
        set_old();
        rootfs(&format!("pipeline/build/runner:job-11@{d1}"));
        assert!(
            mtime() > old,
            "a digest-pinned image is resolved by its tag"
        );

        // The digest must be the tag's.
        let pinned = format!("pipeline/build/runner:job-11@{d2}");
        let msg = refusal(resolve_ref(&c, &state, Some(&own), &pinned));
        assert!(msg.contains(&format!("not {d2}")), "{msg}");

        // Missing: named, with the producer to rerun when the ref carries it.
        let msg = refusal(resolve_ref(
            &c,
            &state,
            Some(&own),
            "pipeline/build/runner:job-99",
        ));
        assert!(
            msg.contains("pipeline/build/runner:job-99") && msg.contains("rerun job 99"),
            "{msg}"
        );
        let msg = refusal(resolve_ref(&c, &state, Some(&own), "pipeline/build/other"));
        assert!(
            msg.contains("pipeline/build/other") && !msg.contains("rerun"),
            "{msg}"
        );

        // Another pipeline's job resolves in its own namespace only.
        let other = job(Some("ci-pipeline/gl/42/8"));
        assert!(resolve_ref(&c, &state, Some(&other), "pipeline/build/runner").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The job's tag goes first: a `current` that cannot move leaves the job's tag in place
    /// and fails the publication.
    #[test]
    fn the_job_tag_is_written_before_current() {
        let dir = tmpdir("order");
        let store = dir.join("store");
        let c = Config {
            registry: Some(crate::registry::tests::served_store(&store)),
            ..Default::default()
        };
        // A directory where the `current` tag file goes, so the store cannot write it.
        std::fs::create_dir_all(tag_file(&store, "current").join("blocker")).unwrap();
        let own = job(Some("ci-pipeline/gl/42/7"));
        assert!(publish_build(&c, Some(&own), "11", "runner", &bundle(&dir, 1)).is_err());
        assert!(tag_file(&store, "job-11").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Configs for two servers sharing a store. Each accepts only one bearer token: the
    /// first the job's, the second the node's. Both configs carry the node's token as their
    /// `[registry]` credential.
    fn token_gated(dir: &Path) -> (Config, Config) {
        let store = std::sync::Arc::new(vk_registry::Store::new(dir.join("store")).unwrap());
        let node_token = dir.join("node-token");
        std::fs::write(&node_token, "node-secret").unwrap();
        let gated = |token: &str| {
            let auth = vk_registry::auth::Auth::Bearer {
                token: token.into(),
            };
            let url = crate::registry::tests::serve_store(store.clone(), auth);
            Config {
                registry: Some(crate::config::Registry::for_share(
                    url,
                    true,
                    None,
                    String::new(),
                    None,
                    Some(node_token.clone()),
                    None,
                )),
                ..Default::default()
            }
        };
        (gated(&job(None).token), gated("node-secret"))
    }

    /// Every request of a publication, the push and both tags, carries
    /// `Authorization: Bearer <job token>` in place of the node's credential.
    #[test]
    fn publication_sends_the_job_token() {
        let dir = tmpdir("job-token");
        let (for_job, for_node) = token_gated(&dir);
        let own = job(Some("ci-pipeline/gl/42/7"));
        let d = publish_build(&for_job, Some(&own), "11", "runner", &bundle(&dir, 1)).unwrap();
        for tag in ["job-11", "current"] {
            let held = std::fs::read_to_string(tag_file(&dir.join("store"), tag)).unwrap();
            assert_eq!(Some(held), d.digest.clone(), "{tag}");
        }
        assert!(publish_build(&for_node, Some(&own), "12", "runner", &bundle(&dir, 2)).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A resolution sends the node's credential, not the job's token.
    #[test]
    fn resolution_sends_the_nodes_credential() {
        let dir = tmpdir("node-cred");
        let (for_job, for_node) = token_gated(&dir);
        let own = job(Some("ci-pipeline/gl/42/7"));
        let d = publish_build(&for_job, Some(&own), "11", "runner", &bundle(&dir, 1))
            .unwrap()
            .digest
            .unwrap();
        let state = dir.join("state");
        let pinned = format!("pipeline/build/runner:job-11@{d}");
        assert!(resolve_ref(&for_job, &state, Some(&own), &pinned).is_err());
        resolve_ref(&for_node, &state, Some(&own), &pinned).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn publication_checks_its_name_job_and_token() {
        let c = cfg("[registry]\nrepo = \"reg.example/team\"\n");
        let dir = std::env::temp_dir();
        let own = job(Some("ci-pipeline/gl/42/7"));
        for bad in ["", "a/b", "Up", "x:y"] {
            assert!(
                publish_build(&c, Some(&own), "7", bad, &dir).is_err(),
                "{bad:?}"
            );
        }
        for bad in ["", "dev", "7a", "-7", "0", "07"] {
            assert!(
                publish_build(&c, Some(&own), bad, "runner", &dir).is_err(),
                "{bad:?}"
            );
        }
        let expired = JobRegistry {
            expires_at: 0,
            ..own
        };
        let err = publish_build(&c, Some(&expired), "7", "runner", &dir).unwrap_err();
        assert!(format!("{err:#}").contains("expired"), "{err:#}");
        let err = publish_build(&c, None, "7", "runner", &dir).unwrap_err();
        assert!(format!("{err:#}").contains("pipeline namespace"), "{err:#}");
    }
}
