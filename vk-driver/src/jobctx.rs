//! Per-job context: the gitlab-runner custom-executor environment
//! (CUSTOM_ENV_*, failure exit codes) plus the job's on-disk state layout.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::config::Config;

pub struct JobCtx {
    pub cfg: Config,
    pub job_id: String,
    pub job_dir: PathBuf,
    /// MICROVM_IMAGE job variable, when set
    pub image_ref: Option<String>,
    /// MICROVM_CPUS / MICROVM_MEM job variables (clamped by vm.max_*)
    pub cpus_req: Option<String>,
    pub mem_req: Option<String>,
    /// MICROVM_USER job variable: run the stage scripts as this user, overriding
    /// the guest image's baked default (VIRTKIT_DEFAULT_RUN_USER). None = use
    /// that default.
    pub user_req: Option<String>,
    /// MICROVM_EGRESS_ALLOW_IP / _ALLOW_NAME job variables (space/comma separated): this job's
    /// own run-phase filter, which the switch checks beside the host `[egress]` cap and the
    /// hub's layer, each apart, so a job can restrict but never widen its egress. None = no
    /// filter of its own; once either is set, the other's dimension allows none.
    pub egress_allow_ip_req: Option<String>,
    pub egress_allow_name_req: Option<String>,
    /// MICROVM_BUILD_EGRESS_ALLOW_IP / _ALLOW_NAME: the same, for the build phase (git-defined
    /// image / compose `build:` RUN steps), beside the `[egress.build]` cap.
    pub egress_build_allow_ip_req: Option<String>,
    pub egress_build_allow_name_req: Option<String>,
    /// MICROVM_EGRESS_AUDIT job variable: when truthy, audit this job's run-phase egress even
    /// if the host `[egress] audit` toggle is off. Auditing only observes (it never widens
    /// egress), so a job may turn it on for itself.
    pub egress_audit_req: bool,
    /// MICROVM_BUILD_EGRESS_AUDIT: the same, for the build phase (`[egress.build] audit`).
    pub egress_build_audit_req: bool,
    /// MICROVM_EGRESS_DRY_RUN: request dry-run; gated, see [`JobCtx::egress_run_dry_run`].
    pub egress_dry_run_req: bool,
    /// Whether the identity above came from the runner's own account of the job rather than
    /// from the variables beside it. Anything that hands a job data keyed on that identity has
    /// to check it: the fallback is the job naming a project for itself.
    pub identity_from_runner: bool,
    /// MICROVM_USAGE_REPORT: end this job's trace with what every job of its project has
    /// been using, not just this one. Meant for a `when: manual` job an operator runs to size
    /// a project, without needing a shell on the runner.
    pub usage_report_req: bool,
    /// Exit code telling gitlab-runner the *script* failed (job failure)
    pub build_failure: i32,
    /// Exit code telling gitlab-runner the *environment* failed (retryable)
    pub system_failure: i32,

    // `[executor] host_checkout`: the job's git sources, checked out on the host at prepare and
    // shared into the guest, instead of the in-guest `get_sources` clone (see checkout.rs).
    /// CI_REPOSITORY_URL (GitLab embeds the job token) — the clone source.
    pub ci_repo_url: Option<String>,
    /// CI_COMMIT_SHA — the exact commit checked out.
    pub ci_commit_sha: Option<String>,
    /// CI_COMMIT_REF_NAME — the branch/tag fetched so the sha resolves.
    pub ci_commit_ref: Option<String>,
    /// CI_PROJECT_DIR — the guest path GitLab expects the checkout at (the virtio-fs mount point).
    pub ci_project_dir: Option<String>,
    /// CI_CONCURRENT_ID + CI_PROJECT_PATH_SLUG, keying the reused host checkout dir.
    concurrent_id: String,
    project_slug: String,
    /// CI_JOB_NAME — with the project, what makes two runs "the same job" for the memory
    /// history (`[executor.schedule] from_history`). The job id cannot: it is unique per run.
    job_name: Option<String>,
    /// CI_PROJECT_ID — unique on the GitLab instance, where the slug beside it is not: it is
    /// lower-cased, punctuation-folded and cut to 63 characters, so two projects can share
    /// one. The id scopes the history; the slug only makes the directory readable.
    project_id: Option<String>,
    /// The project's full path (`group/sub/project`), for display only: what the job record
    /// names the job's project as. From the runner's account of the job, or `CI_PROJECT_PATH`
    /// where there is none.
    project_path: Option<String>,
    /// Display-only link in the job record, built for hub-placed jobs from the runner's
    /// job data and the driver-supplied [`JOB_SERVER_URL`]. The host's gitlab-runner jobs
    /// get no link: jobs can override `CI_SERVER_URL` and `CI_JOB_URL`.
    job_url: Option<String>,
    /// Whether a hub placed the job: its driver names the GitLab ([`JOB_SERVER_URL`]). The
    /// node transfers such a job's artifacts and caches, so it needs no gitlab-runner.
    pub hub_placed: bool,
    /// The registry access the hub gave a placed job, read from its journaled start
    /// ([`JOB_START`]): the token its guest's registry proxy injects under
    /// `[registry] guest_credential = "job"`.
    pub job_registry: Option<vk_hub_proto::dispatch::JobRegistry>,
    /// The hub's egress layer for a placed job, from the same start: what the rules that select
    /// it allow, enforced below the node's cap, and what its dry-run rules would. For any other
    /// job, the hub's Fallback its node applied, as its prepare took it
    /// ([`JobCtx::take_fallback`]) and its supervisor and run stages read it back
    /// ([`JobCtx::load_fallback`]).
    pub hub_egress: Option<vk_hub_proto::egress::HubEgress>,
    /// Where a placed job's executor commands keep what its node reports of its egress
    /// ([`JOB_EGRESS`]): its builds' records, its refused declarations, and at cleanup the run
    /// phase's, which would otherwise go with the job dir. For a job under the Fallback, a
    /// directory in its job dir, which no report reads.
    pub egress_record: Option<PathBuf>,
}

/// The GitLab URL the runner took the job from, passed by a placed job's driver to its
/// executor commands. Job variables cannot override it.
pub const JOB_SERVER_URL: &str = "VK_JOB_SERVER_URL";

/// The path of a placed job's journaled start, passed by its driver to its executor commands,
/// which read the job's registry access from it. Job variables cannot override it either:
/// they arrive prefixed.
pub const JOB_START: &str = "VK_JOB_START";

/// The directory a placed job's executor commands record its egress in for the node's report,
/// in the job's journal: passed by its driver like [`JOB_START`], and as far from the job's
/// reach.
pub const JOB_EGRESS: &str = "VK_JOB_EGRESS";

/// Where a job no hub placed keeps the hub's Fallback its prepare took, in its job dir.
const HUB_FALLBACK: &str = "hub-fallback.json";

/// Where such a job's switches record what the Fallback refuses, in its job dir: its build
/// phase's layer rides on it.
const FALLBACK_RECORD: &str = "hub-fallback-egress";

/// The Fallback kept at `path`; `None` when there is none.
fn read_fallback(path: &Path) -> Result<Option<vk_hub_proto::egress::HubEgress>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .with_context(|| format!("reading the hub's Fallback {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading the hub's Fallback {}", path.display())),
    }
}

/// The journaled start at `path`.
fn read_job_start(path: &Path) -> Result<vk_hub_proto::dispatch::JobStart> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading the job's start {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("reading the job's start {}", path.display()))
}

/// Use the hub-provided job token for registry access, including image pulls, when `[registry]`
/// lends it to guests and has no node credential. The token's grants govern which images the
/// job may pull; past its expiry, requests go with the node's own token from its hub, if it
/// holds one, else anonymously. A node with its own credential keeps using it; the token from
/// its hub is not one.
fn with_job_token(
    mut cfg: Config,
    registry: Option<&vk_hub_proto::dispatch::JobRegistry>,
) -> Config {
    if let (Some(rg), Some(job)) = (cfg.registry.as_mut(), registry)
        && rg.lends_job_token()
        && !rg.has_credential()
    {
        rg.job_token = Some(crate::config::JobToken::of(job));
    }
    cfg
}

/// [`JobCtx::images_dir`] of any job run with `cfg`.
pub fn images_dir(cfg: &Config) -> PathBuf {
    cfg.state_dir().join("job-images")
}

impl JobCtx {
    pub fn new(cfg: Config) -> Result<JobCtx> {
        Self::from_lookup(cfg, &process_env)
    }

    /// Build the context from `env`, as a placed job's driver does for its executor commands,
    /// rather than this process's environment. Later entries win.
    pub fn for_env(cfg: Config, env: &[(String, String)]) -> Result<JobCtx> {
        Self::from_lookup(cfg, &|name| {
            env.iter()
                .rev()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        })
    }

    /// [`JobCtx::usage_key`] of the job GitLab's `response` (the job response file's JSON)
    /// describes, before the job has an environment of its own to build a context from.
    pub fn usage_key_of(response: &serde_json::Value) -> Result<PathBuf> {
        use serde::Deserialize;
        let response = JobResponse::deserialize(response)?;
        // The key is the job's identity alone; no setting plays a part in it.
        let ctx = Self::with_response(
            Config::default(),
            response.id.to_string(),
            Some(response),
            &|_| None,
        )?;
        Ok(ctx.usage_key())
    }

    fn from_lookup(cfg: Config, env: &Lookup<'_>) -> Result<JobCtx> {
        // The runner's own account of the job first; CI_JOB_ID is the same number where
        // there is no job response to read, and VM_JOB_ID covers manual runs outside
        // gitlab-runner.
        // Read once and threaded down: two reads of the same path are two chances to get two
        // different answers, and the job id and the project identity have to come from one.
        let response = JobResponse::read(env);
        let job_id = match &response {
            Some(r) => r.id.to_string(),
            None => env("CUSTOM_ENV_CI_JOB_ID")
                .or_else(|| env("VM_JOB_ID"))
                .unwrap_or_else(|| "dev".into()),
        };
        Self::with_response(cfg, job_id, response, env)
    }

    /// A context for a named job id, reading whatever job response the environment offers.
    /// Test-only since [`JobCtx::new`] threads its own single read down: two reads of the same
    /// path are two chances to get two different answers.
    #[cfg(test)]
    pub fn new_for_job(cfg: Config, job_id: String) -> Result<JobCtx> {
        let response = JobResponse::read(&process_env);
        Self::with_response(cfg, job_id, response, &process_env)
    }

    fn with_response(
        cfg: Config,
        job_id: String,
        response: Option<JobResponse>,
        env: &Lookup<'_>,
    ) -> Result<JobCtx> {
        // The id lands in a filesystem path: keep it to one sane path component.
        if job_id.is_empty()
            || !job_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            || job_id.starts_with('.')
        {
            bail!("invalid job id {job_id:?}");
        }
        let job_dir = cfg.state_dir().join("jobs").join(&job_id);
        // The job's image, in precedence order: MICROVM_IMAGE (explicit source override,
        // VM_IMAGE for manual runs) → the GitLab `image:` (CI_JOB_IMAGE) → unset, which
        // image::resolve treats as local/default. A bare `image:` is booted directly under
        // the [docker] repo allowlist; the local/virtkit/docker/ forms select a source.
        let image_ref = env("CUSTOM_ENV_MICROVM_IMAGE")
            .or_else(|| env("VM_IMAGE"))
            .or_else(|| env("CUSTOM_ENV_CI_JOB_IMAGE"))
            .filter(|s| !s.is_empty());
        let job_var = |name: &str| env(&format!("CUSTOM_ENV_{name}")).filter(|s| !s.is_empty());
        let server = env(JOB_SERVER_URL).filter(|s| !s.is_empty());
        let hub_placed = server.is_some();
        let job_url = response.as_ref().and_then(|r| {
            let server = server?;
            vk_hub_proto::gitlab_job_url(&server, &r.job_info.project_full_path, &r.id.to_string())
        });
        // A placed job's driver journals its start before any executor command runs, so one
        // it cannot read is an error, whatever `guest_credential` says.
        let (job_registry, hub_egress) = match env(JOB_START).filter(|_| hub_placed) {
            Some(path) => {
                let start = read_job_start(Path::new(&path))?;
                (start.registry, start.egress)
            }
            None => (None, None),
        };
        let cfg = with_job_token(cfg, job_registry.as_ref());
        let egress_record = env(JOB_EGRESS)
            .filter(|_| hub_placed)
            .filter(|p| !p.is_empty())
            .map(PathBuf::from);
        Ok(JobCtx {
            cfg,
            job_id,
            job_dir,
            image_ref,
            cpus_req: job_var("MICROVM_CPUS"),
            mem_req: job_var("MICROVM_MEM"),
            user_req: job_var("MICROVM_USER"),
            egress_allow_ip_req: job_var("MICROVM_EGRESS_ALLOW_IP"),
            egress_allow_name_req: job_var("MICROVM_EGRESS_ALLOW_NAME"),
            egress_build_allow_ip_req: job_var("MICROVM_BUILD_EGRESS_ALLOW_IP"),
            egress_build_allow_name_req: job_var("MICROVM_BUILD_EGRESS_ALLOW_NAME"),
            egress_audit_req: job_var("MICROVM_EGRESS_AUDIT").is_some_and(|v| is_truthy(&v)),
            egress_build_audit_req: job_var("MICROVM_BUILD_EGRESS_AUDIT")
                .is_some_and(|v| is_truthy(&v)),
            egress_dry_run_req: job_var("MICROVM_EGRESS_DRY_RUN").is_some_and(|v| is_truthy(&v)),
            identity_from_runner: response.is_some(),
            usage_report_req: job_var("MICROVM_USAGE_REPORT").is_some_and(|v| is_truthy(&v)),
            build_failure: exit_code_env(env, "BUILD_FAILURE_EXIT_CODE", 1),
            system_failure: exit_code_env(env, "SYSTEM_FAILURE_EXIT_CODE", 2),
            ci_repo_url: job_var("CI_REPOSITORY_URL"),
            ci_commit_sha: job_var("CI_COMMIT_SHA"),
            ci_commit_ref: job_var("CI_COMMIT_REF_NAME"),
            ci_project_dir: job_var("CI_PROJECT_DIR"),
            // Slug + concurrent id are safe path components by GitLab's own rules; sanitize
            // defensively so a surprising value can never escape the checkouts root.
            concurrent_id: safe_component(job_var("CI_CONCURRENT_ID"), "0"),
            // Identity, unlike everything above it, is not the job's to choose: it keys what
            // this host keeps about the job between runs. Taken from the runner's account of
            // the job where there is one, and from the variables only where there is not —
            // which is no job at all (`vk` run from an operator's shell, a manual run), since a
            // job cannot stop the runner writing it.
            project_slug: safe_component(
                match &response {
                    Some(r) => Some(r.job_info.project_slug()),
                    None => job_var("CI_PROJECT_PATH_SLUG"),
                },
                "repo",
            ),
            job_name: match &response {
                Some(r) => Some(r.job_info.name.clone()),
                None => job_var("CI_JOB_NAME"),
            },
            project_id: match &response {
                Some(r) => Some(r.job_info.project_id.to_string()),
                None => job_var("CI_PROJECT_ID"),
            },
            project_path: match &response {
                Some(r) => Some(r.job_info.project_full_path.clone()),
                None => job_var("CI_PROJECT_PATH"),
            },
            job_url,
            hub_placed,
            job_registry,
            hub_egress,
            egress_record,
        })
    }

    /// Take the hub's Fallback for a job no hub placed, from what its node last applied
    /// ([`crate::node::hub_fallback`]): its prepare does, and [`JobCtx::keep_fallback`] keeps it
    /// for the job's later commands, so that a change to it never reaches a job under way. A job
    /// a hub placed keeps the layer its start carries.
    pub fn take_fallback(&mut self) -> Result<()> {
        if self.hub_placed {
            return Ok(());
        }
        self.hub_egress = crate::node::hub_fallback(&self.cfg)?;
        self.egress_record = self
            .hub_egress
            .as_ref()
            .map(|_| self.job_dir.join(FALLBACK_RECORD));
        Ok(())
    }

    /// Read back the Fallback [`JobCtx::take_fallback`] took for a job no hub placed, as its
    /// prepare kept it ([`JobCtx::keep_fallback`]): its supervisor does, for the run phase's
    /// switch, and a run stage for its trace. Only its commands that need it read it, so that
    /// one it cannot read never stands in the way of another's, its cleanup's least of all.
    pub fn load_fallback(&mut self) -> Result<()> {
        if self.hub_placed {
            return Ok(());
        }
        self.hub_egress = read_fallback(&self.job_dir.join(HUB_FALLBACK))?;
        self.egress_record = self
            .hub_egress
            .as_ref()
            .map(|_| self.job_dir.join(FALLBACK_RECORD));
        Ok(())
    }

    /// Keep the Fallback [`JobCtx::take_fallback`] took in the job dir, with the egress record
    /// its builds' layer rides on, once prepare has made the dir.
    pub fn keep_fallback(&self) -> Result<()> {
        let Some(egress) = self.hub_egress.as_ref().filter(|_| !self.hub_placed) else {
            return Ok(());
        };
        if let Some(record) = &self.egress_record {
            crate::egress_report::create_record_dir(record)
                .with_context(|| format!("creating {}", record.display()))?;
        }
        let path = self.job_dir.join(HUB_FALLBACK);
        vk_fs::write_atomic(&path, &serde_json::to_vec(egress)?, 0o600)
            .with_context(|| format!("writing {}", path.display()))
    }

    /// Where this job's builds cache ([`cache_dest`]) under this node's config.
    pub fn cache_dest(&self) -> JobCacheDest {
        cache_dest(
            &self.cfg,
            self.hub_placed,
            self.job_registry.as_ref(),
            crate::node::caches_jobs_by_scope(&self.cfg),
            vk_peer::now_secs(),
            &self.private_scope(),
        )
    }

    /// Resolve this job's Windows media registry ([`media_registry`]); `approved` restricts
    /// media outside the build context to `[executor] windows_media`'s digests.
    pub fn media_registry(
        &self,
        approved: bool,
    ) -> Result<std::result::Result<crate::config::Registry, String>> {
        media_registry(
            &self.cfg,
            self.job_registry.as_ref(),
            approved,
            vk_peer::now_secs(),
        )
    }

    /// The local scope of this job alone: no other job on this node has it.
    fn private_scope(&self) -> String {
        use std::os::unix::ffi::OsStrExt;
        scope_hash(&[
            b"job",
            self.job_id.as_bytes(),
            self.job_dir.as_os_str().as_bytes(),
        ])
    }

    /// The root every `[executor] host_checkout` tree on this host lives under — the unit the idle
    /// checkout sweep walks. `[executor] checkout_dir` (e.g. the RAM-backed /builds tmpfs) puts it
    /// in a private subtree there, so the clone and the job's writes stay in host RAM without
    /// bringing sibling trees from another executor into the sweep.
    pub fn host_checkout_root(&self) -> PathBuf {
        self.cfg.checkout_root()
    }

    /// The host directory this job's sources are checked out into, keyed by the runner's
    /// concurrent slot + project so sequential jobs reuse it (a fetch, not a re-clone) while
    /// concurrent jobs on the same runner stay isolated. The project is its id and slug
    /// ([`JobCtx::usage_project`]): the slug alone folds `a/my.proj` and `a/my-proj` into one
    /// tree, and the next project's guest would see the last one's objects.
    pub fn host_checkout_dir(&self) -> PathBuf {
        // The slot/project key comes from sanitized env, never a job-controlled absolute path.
        self.host_checkout_root()
            .join(&self.concurrent_id)
            .join(self.usage_project())
    }

    /// Where this host remembers what jobs used, keyed by [`JobCtx::usage_key`]. Shared by
    /// every runner on the host, like the ledger beside it.
    pub fn history_dir(&self) -> PathBuf {
        self.cfg.state_dir().join("history")
    }

    /// The project half of [`JobCtx::usage_key`]: what a report covering every job of this
    /// job's project is keyed on.
    pub fn usage_project(&self) -> String {
        // The id is joined to the slug with the separator both halves may contain, so it is
        // used only when it is what GitLab documents it to be — a number. Anything else and the
        // slug stands alone: `42-x` + `y` and `42` + `x-y` must not be one project.
        let project = match &self.project_id {
            Some(id) if !id.is_empty() && id.chars().all(|c| c.is_ascii_digit()) => {
                format!("{id}-{}", self.project_slug)
            }
            _ => self.project_slug.clone(),
        };
        path_component(&project, "repo")
    }

    /// Where this host remembers the cached images each job last booted, keyed by
    /// [`JobCtx::usage_key`] like the run history: what its admission keeps out of an eviction
    /// for its own room (see `image::evict_for_room`). Never pruned, like the run history: one
    /// small file per job that ever ran here, rewritten on each run.
    pub fn images_dir(&self) -> PathBuf {
        images_dir(&self.cfg)
    }

    /// Where this host remembers what each job contacts, keyed by [`JobCtx::usage_key`] like
    /// the run history. Its own root rather than a file beside each history: what a job used
    /// and what it reached are read by different callers, and a scan of one must not have to
    /// step over the other.
    pub fn sites_dir(&self) -> PathBuf {
        self.cfg.state_dir().join("sites")
    }

    /// What makes two runs the same job for the memory history: `<project>/<job name>`.
    ///
    /// Two components rather than one joined string, because both halves may contain the
    /// separator — a GitLab slug is made of them (`group/sub/proj` slugs to `group-sub-proj`)
    /// and job names are full of them too, so `acme-web` + `build` and `acme` + `web-build`
    /// would be the same key and share one history. The project is scoped by its numeric id
    /// where there is one, since the slug alone is not unique; a project renamed under the
    /// same id starts a fresh history, which costs it one run at its declared size.
    pub fn usage_key(&self) -> PathBuf {
        PathBuf::from(self.usage_project())
            .join(job_component(self.job_name.as_deref().unwrap_or("job")))
    }

    /// The host-wide memory ledger (`[executor.schedule] mem_budget`), shared by every job on this
    /// host — including those of another runner sharing the state dir. Outside the job dir
    /// on purpose: a job's own dir is wiped and recreated by its prepare.
    pub fn admit_dir(&self) -> PathBuf {
        self.cfg.state_dir().join("admit")
    }

    /// The directory every job's dir is made in, and so the filesystem their overlays fill.
    pub fn jobs_dir(&self) -> &Path {
        self.job_dir.parent().unwrap_or(&self.job_dir)
    }

    pub fn overlay(&self) -> PathBuf {
        self.job_dir.join("overlay.qcow2")
    }
    pub fn vsock_sock(&self) -> PathBuf {
        self.job_dir.join("vsock.sock")
    }
    /// The job supervisor — the ONE detached process owning every helper (switch,
    /// forwards, the VMM) as tied children. It writes this pidfile
    /// itself at startup; cleanup and the stale-state sweep signal it, and
    /// everything else cascades (PDEATHSIG).
    pub fn supervisor_pidfile(&self) -> PathBuf {
        Self::supervisor_pidfile_in(&self.job_dir)
    }
    /// [`Self::supervisor_pidfile`] of the job in `job_dir`.
    pub fn supervisor_pidfile_in(job_dir: &Path) -> PathBuf {
        job_dir.join("supervisor.pid")
    }
    pub fn supervisor_log(&self) -> PathBuf {
        self.job_dir.join("supervisor.log")
    }

    pub fn console_log(&self) -> PathBuf {
        self.job_dir.join(crate::run::CONSOLE_LOG)
    }
    /// The VMM subprocess's own stdout/stderr (vk's boot errors), written by `spawn_vmm`
    /// next to the guest serial console.
    pub fn vmm_log(&self) -> PathBuf {
        self.job_dir.join("console.vmm.log")
    }
    /// What the VMM's threads were doing when the supervisor stopped it ([`crate::vmmthreads`]).
    pub fn vmm_threads_file(&self) -> PathBuf {
        self.job_dir.join(crate::vmmthreads::FILE_NAME)
    }
    pub fn net_lease(&self) -> PathBuf {
        self.job_dir.join("net.lease")
    }
    /// The directory `[executor] tools_dir` resolved to at boot, recorded by the supervisor.
    /// Prepare runs separately and must report that directory even if the link is repointed.
    pub fn tools_root_file(&self) -> PathBuf {
        Self::tools_root_file_in(&self.job_dir)
    }
    /// [`Self::tools_root_file`] of the job in `job_dir`.
    pub fn tools_root_file_in(job_dir: &Path) -> PathBuf {
        job_dir.join("tools.root")
    }
    /// Where prepare records the archive directory this job's guest statistics go to
    /// (`[executor] atop`), for the supervisor and the final stage — separate processes,
    /// which must not each derive a date of their own around midnight.
    pub fn atop_dir_file(&self) -> PathBuf {
        Self::atop_dir_file_in(&self.job_dir)
    }
    /// [`Self::atop_dir_file`] of the job in `job_dir`.
    pub fn atop_dir_file_in(job_dir: &Path) -> PathBuf {
        job_dir.join("atop.dir")
    }
    /// This job's directory inside a day of the statistics archive:
    /// `<job id>-<project>-<job name>`. The id leads because it is unique per CI run — two
    /// runs of the same pipeline job never share a directory — and reads first when the
    /// archive is listed or a job is looked up by number.
    pub fn atop_component(&self) -> String {
        format!(
            "{}-{}-{}",
            self.job_id,
            self.project_slug,
            path_component(self.job_name.as_deref().unwrap_or("job"), "job")
        )
    }
    /// Host side of the SSH-agent forward (`vk forward` splicing to the runner's
    /// `$SSH_AUTH_SOCK`, a supervisor child).
    pub fn ssh_agent_forward_log(&self) -> PathBuf {
        self.job_dir.join("ssh-agent-forward.log")
    }
    /// Per-job switch (net.mode = "switch"): a `vk switch` child of the supervisor
    /// giving the VM a userspace LAN over vsock + the egress allowlist.
    pub fn switch_log(&self) -> PathBuf {
        self.job_dir.join("switch.log")
    }
    /// Where the per-job switch publishes the bytes it has forwarded, for the end-of-job
    /// resource line. Always written when there is a switch: what a job moved over the
    /// network is part of what it cost, not something to opt into.
    pub fn net_bytes_log(&self) -> PathBuf {
        self.job_dir.join("net.bytes")
    }
    /// Checkout seed size and packing time (`<bytes> <seconds>`) for the guest tmpfs.
    /// Cleanup reads this for the end-of-job trace; the supervisor's own log is outside it.
    pub fn checkout_seed_log(&self) -> PathBuf {
        self.job_dir.join("checkout.seed")
    }
    /// Typed egress-denial records the switch appends and each `run` stage drains into the
    /// job trace (see egress_report). Separate from the human `switch.log`.
    pub fn egress_denied_log(&self) -> PathBuf {
        Self::egress_denied_log_in(&self.job_dir)
    }
    /// [`Self::egress_denied_log`] of the job in `job_dir`.
    pub fn egress_denied_log_in(job_dir: &Path) -> PathBuf {
        job_dir.join("egress-denied.log")
    }
    /// Audit channel: every allowed external domain the switch saw this job's guest
    /// resolve, appended one-per-line and drained into the end-of-job "domains contacted"
    /// summary (see egress_report). Written for every job, audit or not: the standing list of
    /// names a job contacts is read from it too (see sites).
    pub fn egress_audit_log(&self) -> PathBuf {
        Self::egress_audit_log_in(&self.job_dir)
    }
    /// [`Self::egress_audit_log`] of the job in `job_dir` — named as a `vk run --audit-egress`
    /// names its own in its state dir.
    pub fn egress_audit_log_in(job_dir: &Path) -> PathBuf {
        job_dir.join(crate::run::AUDIT_LOG)
    }
    /// Whether this job audits its run-phase egress: the host `[egress] audit` toggle or the
    /// job's own `MICROVM_EGRESS_AUDIT` request (either enables it — audit only observes).
    pub fn egress_audit(&self) -> bool {
        self.cfg.egress.audit || self.egress_audit_req
    }
    /// Whether this job audits its build-phase egress: `[egress.build] audit` or the job's
    /// own `MICROVM_BUILD_EGRESS_AUDIT` request.
    pub fn egress_build_audit(&self) -> bool {
        self.cfg.egress.build.audit || self.egress_build_audit_req
    }
    /// Whether this job's run-phase allowlist is dry-run (evaluated and its would-be denials
    /// reported, but not enforced). The host `[egress] dry_run` toggle always applies; the
    /// job's own `MICROVM_EGRESS_DRY_RUN` only when the host set no run-phase cap (both lists
    /// absent): the allowlist is then entirely job-defined, so dry-running it relaxes nothing
    /// the host enforces.
    pub fn egress_run_dry_run(&self) -> bool {
        self.cfg.egress.dry_run
            || (self.egress_dry_run_req
                && self.cfg.egress.allow_ip.is_none()
                && self.cfg.egress.allow_name.is_none())
    }
    /// The host unix socket the switch listens on for host vsock port `port`
    /// (`<vsock.sock>_<port>`). The guest's virtio-net backend in libkrun dials it
    /// directly.
    pub fn net_vsock_sock(&self, port: u32) -> PathBuf {
        let mut p = self.vsock_sock().into_os_string();
        p.push(format!("_{port}"));
        PathBuf::from(p)
    }

    /// Record what this job is in its job dir ([`JobRecord`]), for a reader outside the job to
    /// say what the VM beside it belongs to. `cpus` and `mem` are the size its primary VM
    /// boots at.
    pub fn record(&self, cpus: u32, mem: &str) -> Result<()> {
        let record = JobRecord {
            job_id: self.job_id.clone(),
            project: self.project_path.clone(),
            job_name: self.job_name.clone(),
            image: self.image_ref.clone(),
            cpus,
            mem: mem.to_string(),
            job_url: self.job_url.clone(),
        };
        let json = serde_json::to_vec(&record)?;
        // Not synced: after a crash the VM this describes is gone too, so a reader must check
        // the job is live before trusting it, and treat a record it cannot parse as absent.
        vk_fs::write_atomic_unsynced(&self.job_dir.join(JOB_RECORD), &json, 0o600)
    }
}

/// What `prepare` records of a job in its job dir: the identity the runner gave it (the
/// `CI_*` variables where there is no job response) and the size its primary VM boots at.
/// Written once, before the VM exists, and removed with the job dir at cleanup.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JobRecord {
    pub job_id: String,
    /// The project's full path; `None` outside gitlab-runner with no `CI_PROJECT_PATH`.
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub job_name: Option<String>,
    /// The image reference the job asked for, as it asked.
    #[serde(default)]
    pub image: Option<String>,
    pub cpus: u32,
    /// The `vm.mem`-style size token the primary VM boots with.
    pub mem: String,
    /// The job's GitLab page, or `None` when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_url: Option<String>,
}

/// The [`JobRecord`]'s name in a job dir.
pub const JOB_RECORD: &str = "job.json";

/// The largest job record read back: a few hundred bytes are written.
const JOB_RECORD_MAX: u64 = 64 * 1024;

impl JobRecord {
    /// The record in `job_dir`, or `None` where there is none that parses — a job prepared by
    /// a `vk` from before records were written, or one still waiting on admission.
    pub fn read(job_dir: &Path) -> Option<JobRecord> {
        use std::io::Read;
        let mut text = Vec::new();
        std::fs::File::open(job_dir.join(JOB_RECORD))
            .ok()?
            .take(JOB_RECORD_MAX)
            .read_to_end(&mut text)
            .ok()?;
        serde_json::from_slice(&text).ok()
    }
}

/// A job's own component: its name reduced to a filename, followed by a short digest of the
/// name as written. The digest is what makes two names that reduce to the same filename —
/// `test:unit` and `test/unit`, or two long names sharing their first hundred characters —
/// keep their own histories, while the readable part still says which job the directory is.
fn job_component(raw: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(raw.as_bytes());
    // Sixteen bytes. Eight would separate names that merely reduce alike, but its birthday
    // bound is only 2^32 — within reach of anyone who can pick both names, and two names
    // sharing a history is what the whole key scheme exists to prevent.
    let short: String = digest[..JOB_DIGEST_HEX / 2]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{}-{short}", path_component(raw, "job"))
}

/// How many hex characters [`job_component`] appends. Named because the report that reads
/// these directories back has to take the same number off again (see `admit::readable_job`),
/// and a digest that grew without the reader knowing would print raw directory names.
pub(crate) const JOB_DIGEST_HEX: usize = 32;

/// One safe path component out of free text: a job name can be anything (`test:unit 1/3`),
/// so everything outside a plain filename becomes `_`, leading dots go, and a long name is
/// cut. Falls back to `default` when nothing usable is left — `..` must never come out of
/// here as a component of its own.
fn path_component(raw: &str, default: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .take(100)
        .collect();
    let cleaned = cleaned.trim_start_matches('.').to_string();
    match cleaned.is_empty() {
        true => default.to_string(),
        false => cleaned,
    }
}

/// The runner's own account of the job. gitlab-runner writes it as JSON and names the path
/// in `JOB_RESPONSE_FILE` — a bare name, where everything a job can set arrives prefixed
/// `CUSTOM_ENV_`, so a job can neither shadow the variable nor choose what is inside the
/// file. Its own documentation points here for "the trusted job context".
///
/// Only the fields that name the job are read. Everything a job is *meant* to decide —
/// `MICROVM_*`, the egress requests — stays on the variables, where a job overriding a value
/// is the feature and not a hole. The file also carries the job token, so it is parsed and
/// dropped: never logged, never quoted into an error.
#[derive(serde::Deserialize)]
struct JobResponse {
    id: u64,
    job_info: JobInfo,
}

#[derive(serde::Deserialize)]
struct JobInfo {
    name: String,
    project_id: u64,
    project_full_path: String,
}

impl JobResponse {
    /// `None` where there is no job response to read, which means no job: `vk` run from an
    /// operator's shell, or a manual run outside gitlab-runner. A real job always
    /// has one, so nothing a job does can take this path.
    fn read(env: &Lookup<'_>) -> Option<JobResponse> {
        // Errors are swallowed rather than reported: the text holds the job token, so nothing
        // from it goes near a log, and the caller falls back to the variables. But falling back
        // *inside a job* means keying that job's stored state on values the job itself can set,
        // which is what this exists to stop — so say so once, where an operator will see it.
        let parsed = env("JOB_RESPONSE_FILE")
            .and_then(|path| std::fs::read_to_string(&path).ok())
            .and_then(|text| serde_json::from_str::<JobResponse>(&text).ok());
        if parsed.is_none() && env("CUSTOM_ENV_CI_JOB_ID").is_some() {
            eprintln!(
                "virtkit: warning: no readable JOB_RESPONSE_FILE — keying this job's stored \
                 state on its own CI_* variables (gitlab-runner 15.0 or newer writes one)"
            );
        }
        parsed
    }
}

impl JobInfo {
    /// The project half of a key, spelled as GitLab spells `CI_PROJECT_PATH_SLUG`: the full
    /// path lowercased, every character outside `a-z0-9` becoming a `-`, cut to 63 and the
    /// dashes trimmed off either end. Runs are deliberately *not* folded, because GitLab does
    /// not fold them — an operator reading a directory name should see the slug they know.
    /// Derived here rather than read from the variable of that name, which a job can set to
    /// anything it likes.
    fn project_slug(&self) -> String {
        let mapped: String = self
            .project_full_path
            .to_lowercase()
            .chars()
            .map(|c| match c {
                'a'..='z' | '0'..='9' => c,
                _ => '-',
            })
            .take(63)
            .collect();
        mapped.trim_matches('-').to_string()
    }
}

/// A single safe path component from an optional env value: keep only alphanumerics, `-`, `_`
/// and `.`, reject a leading dot / emptiness, and fall back to `default` otherwise. Guards the
/// `host_checkout` cache path against a crafted CI_CONCURRENT_ID / CI_PROJECT_PATH_SLUG.
fn safe_component(v: Option<String>, default: &str) -> String {
    match v {
        Some(s)
            if !s.is_empty()
                && !s.starts_with('.')
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) =>
        {
            s
        }
        _ => default.to_string(),
    }
}

/// A truthy job-variable value (`1`/`true`/`yes`/`on`, case-insensitive). Anything else —
/// including `0`/`false` — is false, so `MICROVM_EGRESS_AUDIT: "0"` disables it explicitly.
fn is_truthy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// A job's environment variable by name: this process's own, or one computed for the job.
type Lookup<'a> = dyn Fn(&str) -> Option<String> + 'a;

fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn exit_code_env(env: &Lookup<'_>, name: &str, fallback: i32) -> i32 {
    env(name).and_then(|v| v.parse().ok()).unwrap_or(fallback)
}

/// The current job's identity for lock-holder reporting: its GitLab job URL (clickable) when
/// the executor exported one, else the job id, else the pid — never empty. Shared by both
/// the image pull lock and the vk-registry build-once lock so a waiter names who holds it.
pub(crate) fn job_identity() -> String {
    if let Ok(url) = std::env::var("CUSTOM_ENV_CI_JOB_URL")
        && !url.is_empty()
    {
        return url;
    }
    if let Ok(id) = std::env::var("CUSTOM_ENV_CI_JOB_ID")
        && !id.is_empty()
    {
        return format!("job {id}");
    }
    format!("pid {}", std::process::id())
}

/// The current pipeline's identity, scoping a build-failure memo (see
/// `registry::report_build_failure`/`check_build_failure`) to "this pipeline" — a restart
/// always gets a new id, so a fresh attempt is never blocked by an earlier run's failure.
/// `None` outside GitLab CI (no `CUSTOM_ENV_CI_PIPELINE_ID`), which keeps the whole feature
/// inert for local `vk build`/`vk run`: every local invocation always retries.
pub(crate) fn pipeline_identity() -> Option<String> {
    std::env::var("CUSTOM_ENV_CI_PIPELINE_ID")
        .ok()
        .filter(|id| !id.is_empty())
}

/// Where a job's builds cache, in the registry and on the node.
#[derive(Debug)]
pub struct JobCacheDest {
    pub dest: crate::build::CacheDest,
    /// Where the node's build tier keeps the job's builds ([`crate::ensure::build_tier_dir`]).
    pub local: LocalScope,
    /// Why the cache is off, when it is.
    pub why_off: Option<String>,
}

/// The local scope a job's builds are kept under on the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalScope {
    /// The unscoped tier, which builds outside placed jobs share.
    Unscoped,
    /// The scope of a cache destination, which every job building there shares.
    Shared(String),
    /// The job's own: its cleanup removes its entries, and the idle GC any it misses.
    Private(String),
}

impl LocalScope {
    /// The scope's key, `None` for the unscoped tier.
    pub fn key(&self) -> Option<&str> {
        match self {
            LocalScope::Unscoped => None,
            LocalScope::Shared(k) | LocalScope::Private(k) => Some(k),
        }
    }
}

/// The SHA-256 of `parts`, each length-prefixed so no two lists encode alike, in hex. The
/// first part tags what the scope is of, so a job's scope and a cache destination's differ.
fn scope_hash(parts: &[&[u8]]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    for p in parts {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p);
    }
    vk_hub_proto::to_hex(&h.finalize())
}

/// The job's cache destination and local scope at `now`:
/// - jobs not placed by a hub, or on nodes without scoped caching (`by_scope`), use
///   `[build] cache_registry` and the node's unscoped tier;
/// - placed jobs on nodes with scoped caching use their build prefix and token on the
///   node's registry. Jobs sharing that registry and prefix share a local scope.
///   Missing inputs disable caching and select the job's `private` scope, never the
///   node's shared cache or unscoped tier.
///
/// The token is checked once, here: the hub has it live for the job's timeout and 15 minutes
/// more, so it outlasts the job's builds unless `max_job_token_secs` cuts it shorter; a build
/// past its expiry, and the registry's 60 s of skew, then fails its cache requests.
fn cache_dest(
    cfg: &Config,
    hub_placed: bool,
    registry: Option<&vk_hub_proto::dispatch::JobRegistry>,
    by_scope: bool,
    now: u64,
    private: &str,
) -> JobCacheDest {
    use crate::build::CacheDest;
    if !hub_placed || !by_scope {
        return JobCacheDest {
            dest: CacheDest::Configured(crate::build::CacheOpts::from_config(&cfg.build)),
            local: LocalScope::Unscoped,
            why_off: None,
        };
    }
    let off = |why: &str| JobCacheDest {
        dest: CacheDest::Off,
        local: LocalScope::Private(private.to_string()),
        why_off: Some(why.to_string()),
    };
    let Some(registry) = registry else {
        return off("the hub gave this job no registry token");
    };
    let Some(prefix) = registry.build_prefix.as_deref() else {
        return off(
            "the hub gave this job no build cache: its registry has no ci-build namespace for \
             it, or the hub predates build caches",
        );
    };
    if !vk_hub_proto::token::valid_prefix(prefix) {
        return off("the hub named a build cache that is not a repository name");
    }
    if now >= registry.expires_at {
        return off("the job's registry token has expired");
    }
    let Some(rg) = cfg.registry.as_ref() else {
        return off("this node has no [registry]");
    };
    let token = crate::config::JobToken::of(registry).required();
    match crate::registry::at_path(rg, prefix, Some(token)) {
        Some(rg) => JobCacheDest {
            dest: CacheDest::Scoped(rg),
            local: LocalScope::Shared(scope_hash(&[
                b"build",
                registry.registry_id.as_bytes(),
                prefix.as_bytes(),
            ])),
            why_off: None,
        },
        None => off("this node's [registry] is not a remote registry"),
    }
}

/// Resolve the registry for fetching Windows media by digest at `now`, or explain its absence:
/// - the node's remote `[build] cache_registry` takes precedence for every job;
/// - otherwise, `approved` jobs (placed jobs on nodes caching by scope) use the root of
///   `[registry]` with the hub's media token. The file store holds arbitrary uploads, so the
///   node accepts only `[executor] windows_media`'s digests. The ordinary job token is not
///   used for these fetches because its guest's proxy lends it.
///
/// The outer error reports invalid node configuration, independent of the job.
pub(crate) fn media_registry(
    cfg: &Config,
    registry: Option<&vk_hub_proto::dispatch::JobRegistry>,
    approved: bool,
    now: u64,
) -> Result<std::result::Result<crate::config::Registry, String>> {
    use crate::winiso::NO_REGISTRY;
    if let Some(rg) = crate::windows_registry(None, false, &cfg.build)? {
        return Ok(Ok(rg));
    }
    if !approved {
        return Ok(Err(NO_REGISTRY.to_string()));
    }
    let none = |why: &str| Ok(Err(format!("{NO_REGISTRY}: {why}")));
    let Some(media) = registry.and_then(|r| r.media.as_ref()) else {
        return none(
            "this node has no [build] cache_registry, and the hub gave this job no media token \
             (a hub that predates them, a registry it mints no tokens for, or one that has not \
             yet heard this node lists [executor] windows_media)",
        );
    };
    if now >= media.expires_at {
        return none("the job's media token has expired");
    }
    let Some(rg) = cfg.registry.as_ref() else {
        return none("this node has no [registry] to use the hub's media token on");
    };
    match crate::registry::at_path(rg, "", Some(crate::config::JobToken::of_media(media))) {
        Some(rg) => Ok(Ok(rg)),
        None => none("this node's [registry] is not a remote registry"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Executor;
    use std::path::Path;

    /// A placed job's driver gives its context an environment of its own, not this
    /// process's: the job response it names and the variables in it decide.
    #[test]
    fn a_context_reads_a_given_environment() {
        let dir = std::env::temp_dir().join(format!("vk-jobctx-env-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let response = dir.join("job_response.json");
        std::fs::write(
            &response,
            r#"{"id": 77, "job_info": {"name": "e", "project_id": 12, "project_full_path": "a/b"}}"#,
        )
        .unwrap();
        let env = |k: &str, v: &str| (k.to_string(), v.to_string());
        let ctx = JobCtx::for_env(
            Config::default(),
            &[
                env("CUSTOM_ENV_MICROVM_USER", "nobody"),
                env("JOB_RESPONSE_FILE", &response.display().to_string()),
                env("BUILD_FAILURE_EXIT_CODE", "5"),
                env("CUSTOM_ENV_MICROVM_USER", "1000"),
                env("CUSTOM_ENV_CI_SERVER_URL", "https://elsewhere.example"),
                env(JOB_SERVER_URL, "http://gitlab.internal:8080"),
            ],
        )
        .unwrap();
        assert_eq!(ctx.job_id, "77");
        assert_eq!(
            ctx.job_url.as_deref(),
            Some("http://gitlab.internal:8080/a/b/-/jobs/77"),
            "the driver's GitLab, not the job's variable"
        );
        assert_eq!(ctx.user_req.as_deref(), Some("1000"), "the last one wins");
        assert_eq!(ctx.build_failure, 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A node with no registry credential of its own pulls a placed job's images with the
    /// job's token, under `guest_credential = "job"` alone; a node with one keeps it.
    #[test]
    fn a_node_without_a_credential_pulls_with_the_jobs_token() {
        let job = vk_hub_proto::dispatch::JobRegistry {
            registry_id: "9c2f4e1a7b3d5e60f1a2b3c4d5e6f708".into(),
            token: "vkt_x.y".into(),
            expires_at: u64::MAX,
            grants: Vec::new(),
            cache_repo: None,
            pipeline_prefix: None,
            areas: vec![],
            build_prefix: None,
            media: None,
        };
        let token = |registry: &str, job: Option<&vk_hub_proto::dispatch::JobRegistry>| {
            let cfg = crate::config::from_table(toml::from_str(registry).unwrap()).unwrap();
            with_job_token(cfg, job)
                .registry
                .and_then(|rg| Some(rg.job_token?.live()?.to_string()))
        };
        let lends = "[registry]\nrepo = \"reg.example.com/ci\"\nguest_credential = \"job\"\n";
        assert_eq!(token(lends, Some(&job)).as_deref(), Some("vkt_x.y"));
        assert_eq!(token(lends, None), None);
        let own = format!("{lends}token_file = \"/t\"\n");
        assert_eq!(token(&own, Some(&job)), None);
        let node = "[registry]\nrepo = \"reg.example.com/ci\"\n";
        assert_eq!(token(node, Some(&job)), None);
        let rg = with_job_token(
            crate::config::from_table(toml::from_str(lends).unwrap()).unwrap(),
            Some(&job),
        )
        .registry
        .unwrap();
        // Every client of the section sends it: a repository on the same registry, and the
        // relay.
        let at = crate::registry::at_path(&rg, "ci-pipeline/gl/1/2/builds", None).unwrap();
        assert_eq!(
            at.job_token.as_ref().and_then(|t| t.live()),
            Some("vkt_x.y")
        );
        let creds = crate::oci::Creds::from_registry(&rg).unwrap();
        assert_eq!(creds.token.as_deref(), Some("vkt_x.y"));
        // Expired, it is no longer sent: the node pulls as nobody.
        let expired = vk_hub_proto::dispatch::JobRegistry {
            expires_at: vk_peer::now_secs(),
            ..job
        };
        assert_eq!(token(lends, Some(&expired)), None);
        let rg = with_job_token(
            crate::config::from_table(toml::from_str(lends).unwrap()).unwrap(),
            Some(&expired),
        )
        .registry
        .unwrap();
        let creds = crate::oci::Creds::from_registry(&rg).unwrap();
        assert_eq!(creds.token, None);
        assert!(matches!(
            crate::registry::cred(&rg).unwrap(),
            crate::registry::Cred::None
        ));
    }

    /// The node's own token from its hub is no credential of its own: a placed job's ordinary
    /// pulls go with the job's token while it is live, and with the node's once it expired.
    #[test]
    fn a_jobs_pulls_take_the_nodes_token_once_the_jobs_expired() {
        let dir = std::env::temp_dir().join(format!("vk-jobctx-node-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let lends = "[registry]\nrepo = \"reg.example.com/ci\"\nguest_credential = \"job\"\n";
        let job = |expires_at| vk_hub_proto::dispatch::JobRegistry {
            registry_id: "9c2f4e1a7b3d5e60f1a2b3c4d5e6f708".into(),
            token: "vkt_job".into(),
            expires_at,
            grants: Vec::new(),
            cache_repo: None,
            pipeline_prefix: None,
            areas: vec![],
            build_prefix: None,
            media: None,
        };
        let sent = |job: &vk_hub_proto::dispatch::JobRegistry| {
            let mut cfg = crate::config::from_table(toml::from_str(lends).unwrap()).unwrap();
            cfg.registry.as_mut().unwrap().node_access = Some(
                crate::node::registry_access::tests::held(&dir, "vkt_node", u64::MAX),
            );
            let rg = with_job_token(cfg, Some(job)).registry.unwrap();
            let (cred, whose) = crate::registry::credential(&rg).unwrap();
            let token = match cred {
                crate::registry::Cred::Bearer { token } => token,
                _ => panic!("expected a bearer token"),
            };
            assert_eq!(
                crate::oci::Creds::from_registry(&rg)
                    .unwrap()
                    .token
                    .as_deref(),
                Some(token.as_str())
            );
            (token, whose)
        };
        assert_eq!(
            sent(&job(u64::MAX)),
            ("vkt_job".to_string(), crate::registry::Whose::Job)
        );
        assert_eq!(
            sent(&job(vk_peer::now_secs())),
            ("vkt_node".to_string(), crate::registry::Whose::Node)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A placed job's registry access and egress layer come from the start its driver names,
    /// and only for a placed job: anywhere else the variable is not the driver's.
    #[test]
    fn a_placed_job_reads_its_registry_access_and_egress_from_its_start() {
        use vk_hub_proto::dispatch::{JobRegistry, JobStart};
        let dir = std::env::temp_dir().join(format!("vk-jobctx-start-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let start = dir.join("start.json");
        let registry = JobRegistry {
            registry_id: "9c2f4e1a7b3d5e60f1a2b3c4d5e6f708".into(),
            token: "vkt_x.y".into(),
            expires_at: 99,
            grants: Vec::new(),
            cache_repo: Some("ci-cache/gl/42/protected".into()),
            pipeline_prefix: None,
            areas: vec![],
            build_prefix: None,
            media: None,
        };
        let job = JobStart {
            job: "j".into(),
            reservation: None,
            envelope: Default::default(),
            spec: vk_hub_proto::job::JobSpec::GitlabCi(Default::default()),
            registry: Some(registry.clone()),
            egress: Some(vk_hub_proto::egress::HubEgress {
                rules: vec!["default".into()],
                run: vk_hub_proto::egress::HubPhase::Unrestricted,
                build: vk_hub_proto::egress::HubPhase::Unrestricted,
                dry_run: Vec::new(),
            }),
        };
        std::fs::write(&start, serde_json::to_vec(&job).unwrap()).unwrap();
        let env = |k: &str, v: &str| (k.to_string(), v.to_string());
        let path = start.display().to_string();
        let placed = JobCtx::for_env(
            Config::default(),
            &[
                env("CUSTOM_ENV_CI_JOB_ID", "5"),
                env(JOB_SERVER_URL, "https://gitlab.example"),
                env(JOB_START, &path),
                env(JOB_EGRESS, "/n/j/egress"),
            ],
        )
        .unwrap();
        assert_eq!(placed.job_registry, Some(registry));
        assert_eq!(placed.hub_egress, job.egress);
        assert_eq!(placed.egress_record, Some(PathBuf::from("/n/j/egress")));
        // A job no hub placed records nothing for a report, whatever its environment says.
        let unplaced = JobCtx::for_env(
            Config::default(),
            &[
                env("CUSTOM_ENV_CI_JOB_ID", "5"),
                env(JOB_START, &path),
                env(JOB_EGRESS, "/n/j/egress"),
            ],
        )
        .unwrap();
        assert_eq!(unplaced.job_registry, None);
        assert_eq!(unplaced.hub_egress, None);
        assert_eq!(unplaced.egress_record, None);
        let missing = JobCtx::for_env(
            Config::default(),
            &[
                env("CUSTOM_ENV_CI_JOB_ID", "5"),
                env(JOB_SERVER_URL, "https://gitlab.example"),
                env(JOB_START, &dir.join("nope").display().to_string()),
            ],
        );
        assert!(missing.is_err(), "a start it cannot read is an error");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The identity a job keys its stored state on comes from the runner's account of the
    /// job, not from the variables beside it — which a job sets itself, as it sets the
    /// `MICROVM_*` knobs. A forged `CI_PROJECT_ID` in the payload's own variable list must
    /// therefore change nothing: it is what a job would use to read, and pollute, the
    /// history of a project whose pipelines it cannot even see.
    #[test]
    fn identity_comes_from_the_job_response_not_the_variables() {
        let json = r#"{
            "id": 4242,
            "token": "a-job-token-that-must-not-be-logged",
            "job_info": {
                "name": "test:unit",
                "project_id": 42,
                "project_full_path": "Acme  Corp/Web_Team/my.project"
            },
            "variables": [
                {"key": "CI_PROJECT_ID", "value": "14", "public": true},
                {"key": "CI_PROJECT_PATH_SLUG", "value": "acme-web", "public": true},
                {"key": "CI_JOB_NAME", "value": "someone-elses-job", "public": true}
            ]
        }"#;
        let r: JobResponse = serde_json::from_str(json).expect("a job response parses");
        assert_eq!(r.id, 4242);
        assert_eq!(r.job_info.project_id, 42, "not the 14 the variables claim");
        assert_eq!(r.job_info.name, "test:unit");
        // Spelled as GitLab spells the slug: lowercased, every other character a dash, runs
        // left alone — `Acme  Corp` has two spaces and keeps both dashes.
        assert_eq!(r.job_info.project_slug(), "acme--corp-web-team-my-project");

        // And the context built from it keys on those, not on the variables of the same names —
        // which is the whole property, and is not tested by reading the struct's own fields.
        let ctx = JobCtx::with_response(Config::default(), "4242".into(), Some(r), &process_env)
            .expect("a context for a real job");
        assert_eq!(ctx.project_id.as_deref(), Some("42"));
        assert_eq!(ctx.job_name.as_deref(), Some("test:unit"));
        assert_eq!(ctx.project_slug, "acme--corp-web-team-my-project");
        assert!(
            ctx.usage_key()
                .starts_with("42-acme--corp-web-team-my-project"),
            "{:?}",
            ctx.usage_key()
        );
    }

    /// A job's record names the project by its full path from the runner's account, and is
    /// private to the node's user. It links the job's page only for a job the hub placed, on
    /// the GitLab its driver names: never from `CI_SERVER_URL` or `CI_JOB_URL`, which the job
    /// may set itself.
    #[test]
    fn a_job_record_names_the_job_as_the_runner_does() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("vk-job-record-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = Config {
            state_dir: Some(dir.clone()),
            ..Default::default()
        };
        let response = || JobResponse {
            id: 7,
            job_info: JobInfo {
                name: "test:unit".into(),
                project_id: 42,
                project_full_path: "acme/web".into(),
            },
        };
        // The host's own runner: the job's variables name its GitLab, so no link.
        let own = |name: &str| match name {
            "CUSTOM_ENV_CI_SERVER_URL" => Some("https://evil.example/".to_string()),
            "CUSTOM_ENV_CI_JOB_URL" => Some("https://evil.example/".to_string()),
            _ => None,
        };
        let own_cfg = Config {
            state_dir: Some(dir.clone()),
            ..Default::default()
        };
        let own_ctx = JobCtx::with_response(own_cfg, "7".into(), Some(response()), &own).unwrap();
        assert_eq!(own_ctx.job_url, None);
        // A placed job: its driver names the GitLab, whatever the job's variables say.
        let env = |name: &str| match name {
            JOB_SERVER_URL => Some("https://gitlab.example.com/".to_string()),
            _ => own(name),
        };
        let ctx = JobCtx::with_response(cfg, "7".into(), Some(response()), &env).unwrap();
        std::fs::create_dir_all(&ctx.job_dir).unwrap();
        ctx.record(4, "8G").unwrap();
        let written = std::fs::read(ctx.job_dir.join(JOB_RECORD)).unwrap();
        let record: JobRecord = serde_json::from_slice(&written).unwrap();
        assert_eq!(
            record,
            JobRecord {
                job_id: "7".into(),
                project: Some("acme/web".into()),
                job_name: Some("test:unit".into()),
                image: ctx.image_ref.clone(),
                cpus: 4,
                mem: "8G".into(),
                job_url: Some("https://gitlab.example.com/acme/web/-/jobs/7".into()),
            }
        );
        let mode = std::fs::metadata(ctx.job_dir.join(JOB_RECORD))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(JobRecord::read(&ctx.job_dir), Some(record));
        // Garbage is no record, not an error, and so is none at all.
        std::fs::write(ctx.job_dir.join(JOB_RECORD), "{").unwrap();
        assert_eq!(JobRecord::read(&ctx.job_dir), None);
        assert_eq!(JobRecord::read(&dir), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The slug is a path component, so the edges matter: a leading or trailing run of
    /// non-alphanumerics must not survive as dots or dashes around the name, and a very long
    /// path is cut where GitLab cuts it.
    #[test]
    fn a_project_slug_is_a_safe_path_component() {
        let slug = |path: &str| {
            JobInfo {
                name: String::new(),
                project_id: 1,
                project_full_path: path.to_string(),
            }
            .project_slug()
        };

        assert_eq!(slug("../../etc/passwd"), "etc-passwd");
        assert_eq!(slug("...leading"), "leading");
        assert_eq!(slug("trailing///"), "trailing");
        // One dash per character outside `a-z0-9`, as GitLab's own gsub gives: the slash and
        // each accented letter contribute their own.
        assert_eq!(slug("Group/Ünïcode"), "group--n-code");
        assert_eq!(slug(&"a".repeat(80)), "a".repeat(63));
        // Whatever comes out still passes the component guard the key is built with.
        for path in ["../../etc/passwd", "...leading", "trailing///"] {
            let s = slug(path);
            assert_eq!(safe_component(Some(s.clone()), "repo"), s, "{path}");
        }
    }

    /// The two ends of a job directory name. `job_component` writes `<readable>-<digest>` and
    /// `admit::readable_job` takes the digest back off; only [`JOB_DIGEST_HEX`] ties them, so a
    /// digest that changed on one side without the other would have the report printing raw
    /// directory names — and a job whose own name ends in something digest-shaped must not be
    /// split at the wrong dash.
    #[test]
    fn a_job_component_reads_back_as_its_name_and_digest() {
        for name in [
            "build",
            "test:unit 1/3",
            "..",
            &"x".repeat(120),
            "foo-0123456789abcdef0123456789abcdef",
            "",
        ] {
            let component = job_component(name);
            let (readable, digest) = crate::admit::readable_job(&component);
            assert_eq!(digest.len(), JOB_DIGEST_HEX, "{component}");
            assert_eq!(component, format!("{readable}-{digest}"), "{component}");
            assert_eq!(readable, path_component(name, "job"), "{component}");
        }
        // Two names that reduce alike keep distinct components, which is what the digest is for.
        assert_ne!(job_component("deploy:prod"), job_component("deploy prod"));
    }

    /// A placed job on a node caching by scope builds at its prefix with its token, or with no
    /// cache, never in `[build] cache_registry`; any other job takes `[build] cache_registry`.
    #[test]
    fn a_placed_jobs_builds_cache_at_its_prefix_or_nowhere() {
        use crate::build::CacheDest;
        use vk_hub_proto::dispatch::JobRegistry;
        let cfg: Config = toml::from_str(
            "state_dir = \"/s\"\n[build]\ncache_registry = \"cache.example/shared\"\n\
             [registry]\nrepo = \"reg.example/node\"\n",
        )
        .unwrap();
        let job = JobRegistry {
            registry_id: "r".into(),
            token: "vkt_x.y".into(),
            expires_at: 100,
            grants: Vec::new(),
            cache_repo: None,
            pipeline_prefix: None,
            areas: vec![],
            build_prefix: Some("ci-build/gl/42/protected/all".into()),
            media: None,
        };
        let configured = |d: &CacheDest| match d {
            CacheDest::Configured(c) => c.registry.clone(),
            other => panic!("{other:?}"),
        };
        // Not placed, or not caching by scope: the shared cache and the unscoped tier.
        for (placed, by_scope) in [(false, true), (true, false), (false, false)] {
            let c = cache_dest(&cfg, placed, Some(&job), by_scope, 1, "mine");
            assert_eq!(configured(&c.dest).as_deref(), Some("cache.example/shared"));
            assert_eq!((c.local, c.why_off), (LocalScope::Unscoped, None));
        }
        // Placed, by scope: the job's prefix and token, with a local scope shared only
        // by jobs of the same prefix.
        let c = cache_dest(&cfg, true, Some(&job), true, 1, "mine");
        let CacheDest::Scoped(rg) = &c.dest else {
            panic!("{:?}", c.dest)
        };
        assert_eq!(rg.repo, "reg.example/ci-build/gl/42/protected/all");
        assert_eq!(rg.job_token.as_ref().map(|t| t.secret()), Some("vkt_x.y"));
        assert_eq!(c.why_off, None);
        assert!(matches!(c.local, LocalScope::Shared(_)), "{:?}", c.local);
        let other_job = cache_dest(&cfg, true, Some(&job), true, 1, "theirs");
        assert_eq!(other_job.local, c.local);
        let branch = JobRegistry {
            build_prefix: Some("ci-build/gl/42/protected/ref-x-0".into()),
            ..job.clone()
        };
        let other = cache_dest(&cfg, true, Some(&branch), true, 1, "mine");
        assert!(matches!(other.local, LocalScope::Shared(_)) && other.local != c.local);
        // Anything missing turns the cache off, saying why.
        let bad_prefix = JobRegistry {
            build_prefix: Some("../x".into()),
            ..job.clone()
        };
        let no_prefix = JobRegistry {
            build_prefix: None,
            ..job.clone()
        };
        let local: Config =
            toml::from_str("state_dir = \"/s\"\n[registry]\nrepo = \"/srv/store\"\n").unwrap();
        let none: Config = toml::from_str("state_dir = \"/s\"\n").unwrap();
        for (cfg, registry, now, want) in [
            (&cfg, None, 1, "no registry token"),
            (&cfg, Some(&no_prefix), 1, "no ci-build namespace"),
            (&cfg, Some(&bad_prefix), 1, "not a repository name"),
            (&cfg, Some(&job), 100, "expired"),
            (&none, Some(&job), 1, "no [registry]"),
            (&local, Some(&job), 1, "not a remote registry"),
        ] {
            let c = cache_dest(cfg, true, registry, true, now, "mine");
            assert!(matches!(c.dest, CacheDest::Off), "{want}: {:?}", c.dest);
            assert!(
                c.why_off.as_deref().is_some_and(|w| w.contains(want)),
                "{c:?}"
            );
            assert_eq!(c.local, LocalScope::Private("mine".into()));
        }
    }

    /// A remote `[build] cache_registry` takes precedence. Otherwise, approved-media jobs use
    /// the root of `[registry]` with the hub's media token, never the ordinary job token.
    /// Missing prerequisites produce specific errors.
    #[test]
    fn media_come_from_the_nodes_cache_registry_else_the_hubs_media_token() {
        use vk_hub_proto::dispatch::{JobRegistry, MediaToken};
        let configless: Config = toml::from_str(
            "state_dir = \"/s\"\n[registry]\nrepo = \"reg.example/node\"\n\
             guest_credential = \"job\"\n",
        )
        .unwrap();
        let job = JobRegistry {
            registry_id: "r".into(),
            token: "vkt_job.x".into(),
            expires_at: 100,
            grants: Vec::new(),
            cache_repo: None,
            pipeline_prefix: None,
            areas: vec![],
            build_prefix: None,
            media: Some(MediaToken {
                token: "vkt_media.x".into(),
                expires_at: 100,
            }),
        };
        let rg = media_registry(&configless, Some(&job), true, 1)
            .unwrap()
            .unwrap();
        assert_eq!(rg.repo, "reg.example");
        assert_eq!(
            rg.job_token.as_ref().map(|t| t.secret()),
            Some("vkt_media.x")
        );
        // The media token replaces the job's own, which a placed job's [registry] carries.
        let mut placed: Config = toml::from_str(
            "state_dir = \"/s\"\n[registry]\nrepo = \"reg.example/node\"\n\
             guest_credential = \"job\"\n",
        )
        .unwrap();
        placed.registry.as_mut().unwrap().job_token = Some(crate::config::JobToken::of(&job));
        let rg = media_registry(&placed, Some(&job), true, 1)
            .unwrap()
            .unwrap();
        assert_eq!(
            rg.job_token.as_ref().map(|t| t.secret()),
            Some("vkt_media.x")
        );
        // Expiry after selection must not fall back to another credential.
        let expired = JobRegistry {
            media: Some(MediaToken {
                token: "vkt_media.x".into(),
                expires_at: 1,
            }),
            ..job.clone()
        };
        let rg = media_registry(&configless, Some(&expired), true, 0)
            .unwrap()
            .unwrap();
        let e = crate::registry::credential(&rg).err().unwrap();
        assert!(format!("{e:#}").contains("has expired"), "{e:#}");
        // The node's own cache registry comes first, with its own credential.
        let own: Config = toml::from_str(
            "state_dir = \"/s\"\n[build]\ncache_registry = \"cache.example\"\n\
             [registry]\nrepo = \"reg.example/node\"\n",
        )
        .unwrap();
        for approved in [true, false] {
            let rg = media_registry(&own, Some(&job), approved, 1)
                .unwrap()
                .unwrap();
            assert_eq!(rg.repo, "cache.example");
            assert!(rg.job_token.is_none());
        }
        // Missing prerequisites produce specific errors.
        let no_media = JobRegistry {
            media: None,
            ..job.clone()
        };
        let local: Config =
            toml::from_str("state_dir = \"/s\"\n[registry]\nrepo = \"/srv/store\"\n").unwrap();
        let none: Config = toml::from_str("state_dir = \"/s\"\n").unwrap();
        for (cfg, registry, approved, now, want) in [
            (
                &configless,
                Some(&job),
                false,
                1,
                crate::winiso::NO_REGISTRY,
            ),
            (&configless, None, true, 1, "no media token"),
            (&configless, Some(&no_media), true, 1, "no media token"),
            (
                &configless,
                Some(&job),
                true,
                100,
                "media token has expired",
            ),
            (&none, Some(&job), true, 1, "no [registry]"),
            (&local, Some(&job), true, 1, "not a remote registry"),
        ] {
            let why = media_registry(cfg, registry, approved, now)
                .unwrap()
                .unwrap_err();
            assert!(why.contains(want), "{why}");
            assert!(why.starts_with(crate::winiso::NO_REGISTRY), "{why}");
        }
    }

    // A JobCtx with a fixed slot/project key, built directly so `host_checkout_dir` is
    // exercised without depending on the ambient CI_* env.
    fn ctx(cfg: Config) -> JobCtx {
        JobCtx {
            cfg,
            job_id: "job1".into(),
            job_dir: PathBuf::from("/tmp/job1"),
            image_ref: None,
            cpus_req: None,
            mem_req: None,
            user_req: None,
            egress_allow_ip_req: None,
            egress_allow_name_req: None,
            egress_build_allow_ip_req: None,
            egress_build_allow_name_req: None,
            egress_audit_req: false,
            egress_build_audit_req: false,
            egress_dry_run_req: false,
            identity_from_runner: false,
            usage_report_req: false,
            build_failure: 1,
            system_failure: 2,
            ci_repo_url: None,
            ci_commit_sha: None,
            ci_commit_ref: None,
            ci_project_dir: None,
            concurrent_id: "0".into(),
            project_slug: "myproj".into(),
            job_name: Some("test:unit 1/3".into()),
            project_id: Some("42".into()),
            project_path: None,
            job_url: None,
            hub_placed: false,
            job_registry: None,
            hub_egress: None,
            egress_record: None,
        }
    }

    /// The history key is a filename, and a GitLab job name is free text — parallel matrix
    /// jobs carry slashes and spaces, and a crafted one must not walk out of the directory.
    #[test]
    fn the_usage_key_scopes_a_job_to_its_project() {
        let key = ctx(Config::default()).usage_key();
        let job = key.file_name().unwrap().to_string_lossy();
        assert_eq!(key.parent().unwrap(), Path::new("42-myproj"));
        assert!(job.starts_with("test_unit_1_3-"), "{job}");

        // Both halves may contain the separator a single string would join them with, so
        // they are separate components: these two would otherwise share one history.
        let mut a = ctx(Config::default());
        a.project_slug = "acme-web".into();
        a.job_name = Some("build".into());
        let mut b = ctx(Config::default());
        b.project_slug = "acme".into();
        b.job_name = Some("web-build".into());
        assert_ne!(a.usage_key(), b.usage_key());

        // Slugs are not unique — lower-cased, punctuation-folded, cut at 63 characters — so
        // the project's own id is what separates two that fold together.
        let mut same_slug = ctx(Config::default());
        same_slug.project_id = Some("77".into());
        assert_ne!(same_slug.usage_key(), ctx(Config::default()).usage_key());
    }

    /// Dry-run suspends enforcement, so — unlike audit — a job may not turn it on for itself
    /// when the host has set a run-phase cap: that would let the job escape the host's policy.
    #[test]
    fn dry_run_job_var_cannot_relax_a_host_cap() {
        // Host toggle always applies.
        let mut cfg = Config::default();
        cfg.egress.dry_run = true;
        assert!(ctx(cfg).egress_run_dry_run());

        // Job var, host set no run-phase cap: honored (the allowlist is job-defined).
        let mut c = ctx(Config::default());
        c.egress_dry_run_req = true;
        assert!(c.egress_run_dry_run());

        // Job var, but the host set a cap: ignored, so the job cannot relax it.
        let mut cfg = Config::default();
        cfg.egress.allow_name = Some(vec!["corp.example.com".into()]);
        let mut c = ctx(cfg);
        c.egress_dry_run_req = true;
        assert!(!c.egress_run_dry_run());

        // An empty host list is a cap too (deny-all), not an absent one.
        let mut cfg = Config::default();
        cfg.egress.allow_ip = Some(vec![]);
        let mut c = ctx(cfg);
        c.egress_dry_run_req = true;
        assert!(!c.egress_run_dry_run());

        // Neither set: enforced.
        assert!(!ctx(Config::default()).egress_run_dry_run());
    }

    /// Names that reduce to the same filename are still different jobs, and the digest of
    /// the name as written is what keeps them apart.
    #[test]
    fn job_names_that_reduce_alike_keep_their_own_history() {
        let key = |name: &str| {
            let mut c = ctx(Config::default());
            c.job_name = Some(name.into());
            c.usage_key()
        };
        // Same filename, different jobs.
        assert_ne!(key("test:unit"), key("test/unit"));
        // Same first hundred characters, different jobs.
        assert_ne!(
            key(&format!("{}a", "x".repeat(100))),
            key(&format!("{}b", "x".repeat(100)))
        );
        // And the same name is always the same history, run after run.
        assert_eq!(key("test:unit"), key("test:unit"));
    }

    /// A job name is free text and lands in a path: no component may escape the directory,
    /// and none may be empty.
    #[test]
    fn the_usage_key_stays_inside_its_directory() {
        let mut escaping = ctx(Config::default());
        escaping.job_name = Some("../../etc/passwd".into());
        let key = escaping.usage_key();
        assert_eq!(key.components().count(), 2);
        let job = key.file_name().unwrap().to_string_lossy();
        assert!(job.starts_with("_.._etc_passwd-"), "{job}");

        // A name that sanitizes away entirely must still leave a component behind.
        let mut dots = ctx(Config::default());
        dots.job_name = Some("..".into());
        let key = dots.usage_key();
        assert!(
            key.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("job-"),
            "{key:?}"
        );

        // A manual run outside gitlab-runner has neither id nor name.
        let mut bare = ctx(Config::default());
        bare.project_id = None;
        bare.job_name = None;
        assert_eq!(bare.usage_key().parent().unwrap(), Path::new("myproj"));
    }

    /// The archive directory name is a path component built from free text — a GitLab
    /// job name carries slashes and spaces — so it must stay one readable component
    /// that cannot walk out of the day's directory.
    #[test]
    fn the_atop_component_is_one_safe_path_component() {
        assert_eq!(
            ctx(Config::default()).atop_component(),
            "job1-myproj-test_unit_1_3"
        );

        let mut escaping = ctx(Config::default());
        escaping.job_name = Some("../../etc/passwd".into());
        assert_eq!(escaping.atop_component(), "job1-myproj-_.._etc_passwd");

        // A name that sanitizes away entirely still leaves the two halves that name the run.
        let mut dots = ctx(Config::default());
        dots.job_name = Some("..".into());
        assert_eq!(dots.atop_component(), "job1-myproj-job");
        let mut bare = ctx(Config::default());
        bare.job_name = None;
        assert_eq!(bare.atop_component(), "job1-myproj-job");
    }

    #[test]
    fn host_checkout_dir_defaults_under_state_dir() {
        let cfg = Config {
            state_dir: Some(PathBuf::from("/var/lib/vk")),
            ..Default::default()
        };
        assert_eq!(
            ctx(cfg).host_checkout_dir(),
            PathBuf::from("/var/lib/vk/checkouts/0/42-myproj")
        );
    }

    #[test]
    fn host_checkout_dir_honors_checkout_dir_override() {
        let cfg = Config {
            state_dir: Some(PathBuf::from("/var/lib/vk")),
            executor: Executor {
                host_checkout: true,
                checkout_dir: Some(PathBuf::from("/builds")),
                ..Default::default()
            },
            ..Default::default()
        };
        // The override replaces the `<state_dir>/checkouts` root; the slot/project key is unchanged.
        assert_eq!(
            ctx(cfg).host_checkout_dir(),
            PathBuf::from("/builds/vk/0/42-myproj")
        );
    }
}
