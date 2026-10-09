//! `vk node job <dir>` runs one placed job from executor prepare to cleanup in a detached
//! process. Jobs survive `vk node run` restarts outside `vk node service`; stopping the
//! service ends its whole cgroup. The executor environment comes from the journal, as in
//! [`env::of_journal`].
//!
//! It runs gitlab-runner's stages in gitlab-runner's order (`common/build.go`
//! `executeScript`, `executeUserScripts`; MIT, see [`super::mask`]): `prepare_executor`
//! (`vk gitlab prepare`), `prepare_script`, `get_sources`, `restore_cache`,
//! `download_artifacts`, each `step_<name>`, `after_script`, `archive_cache` or
//! `archive_cache_on_failure`, `upload_artifacts_on_success` or `_on_failure`, then
//! `cleanup_file_variables` and `vk gitlab cleanup`. The guest stages are scripts
//! ([`super::script`]) run through `vk gitlab run`, as gitlab-runner runs a custom executor's;
//! caches and artifacts are moved by the node itself. Everything the job's readers see goes
//! through [`Trace`], masked; how the job ended goes to `result.json`, last.
//!
//! A cancel is read from the journal's `cancel` file: graceful stops the running step and
//! runs `after_script`, then ends the job without archiving caches or artifacts; immediate
//! stops whatever runs and goes straight to cleanup. The job's timeout ends it likewise,
//! `after_script` included, as gitlab-runner's job context does.

use std::fs::File;
use std::io::Read;
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;
use vk_hub_proto::dispatch::CancelMode;
use vk_hub_proto::job::{
    ArtifactOutcome, CiJob, FailureClass, JobResult, JobSpec, STEP_AFTER_SCRIPT, UploadState,
};

use super::journal::{self, Meta};
use super::settings::{Settings, Submodules};
use super::trace::{ANSI_BOLD_CYAN, ANSI_RESET, Trace};
use super::vars::Vars;
use super::{StageCtx, artifacts, cache, env, script};
use crate::config::Config;
use crate::jobctx::JobCtx;

/// The trace limit when GitLab's runner gave none: gitlab-runner's `output_limit` default.
const DEFAULT_TRACE_LIMIT: u64 = 4 << 20;

/// GitLab's minimum length for a masked variable's value: the shortest credential masked.
const MIN_MASKED_LEN: usize = 8;

/// How long a stopped executor command has to exit before it is killed.
pub(super) const KILL_GRACE: Duration = Duration::from_secs(10);

/// How long `vk gitlab cleanup` may take before it is stopped.
pub(super) const CLEANUP_TIMEOUT: Duration = Duration::from_secs(300);

/// Why a stage was stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    Cancel(CancelMode),
    /// The job's own timeout.
    Timeout,
    /// A stage's own bound: the steps' `RUNNER_SCRIPT_TIMEOUT` or after_script's.
    StageTimeout,
}

/// How a stage ended.
#[derive(Debug, PartialEq, Eq)]
enum End {
    Ok,
    /// The guest script failed with this exit code.
    Script(Option<i32>),
    /// The executor, the VM or the node failed it.
    System(String),
    Stopped(Stop),
}

/// What a stop applies to: graceful cancels stop only the steps and what precedes them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Before the steps: any cancel stops it, and nothing else runs.
    Before,
    Steps,
    /// after_script: only an immediate cancel or the job's timeout stops it.
    After,
    /// Caches and artifacts at the end: any cancel stops them.
    Archive,
    /// The file-variable cleanup: nothing stops it but its own bound.
    Cleanup,
}

struct Driver {
    /// The executor's view of the job, from `env`.
    ctx: JobCtx,
    /// The environment of the job's executor commands.
    env: Vec<(String, String)>,
    dir: PathBuf,
    job: CiJob,
    trace: Arc<Trace>,
    /// When the job's timeout runs out.
    deadline: Instant,
    timeout: Duration,
    /// Raised when a stage is stopped, for the host-side transfers.
    stopped: CancellationToken,
}

/// What the driver works from, read from the journal.
struct Setup {
    driver: Driver,
    vars: Vars,
    settings: Settings,
    place: super::vars::Place,
    meta: Meta,
}

/// `vk node job <dir>`: run the job journaled in `dir`, holding the admission ledger entry on
/// `ledger_fd` (inherited from `vk node run`) for the job's life.
pub async fn run(cfg: Config, dir: &Path, ledger_fd: Option<i32>) -> Result<()> {
    // SAFETY: the session passes the descriptor of the ledger entry it opened for this job,
    // inherited across exec, and nothing else in this process owns it.
    let _ledger = ledger_fd.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
    // The session writes it too, after the spawn; this one holds whatever became of that.
    let _ = vk_fs::write_atomic(
        &dir.join(journal::PID),
        std::process::id().to_string().as_bytes(),
        0o600,
    );
    let Setup {
        mut driver,
        mut vars,
        settings,
        place,
        meta,
    } = match setup(cfg, dir) {
        Ok(setup) => setup,
        Err(e) => {
            // A job without a result would read as interrupted, without the reason.
            let result = JobResult {
                failure: Some(FailureClass::System),
                exit_code: None,
                message: Some(format!("the job's driver could not start: {e:#}")),
                output_len: journal::output_len(dir),
                artifacts: Vec::new(),
            };
            journal::write_json(&dir.join(journal::RESULT), &result)?;
            return Err(e);
        }
    };
    let result = driver.run_job(&mut vars, &settings, &place, &meta).await;
    journal::write_json(&dir.join(journal::RESULT), &result)
}

fn setup(cfg: Config, dir: &Path) -> Result<Setup> {
    let start = journal::read_start(dir)?;
    let meta = journal::read_meta(dir)?;
    let JobSpec::GitlabCi(job) = start.spec;
    let limit = match job.trace.limit_bytes {
        0 => DEFAULT_TRACE_LIMIT,
        n => n,
    };
    let place = env::place(&cfg, &job, &meta)?;
    let vars = Vars::of(&job, &place);
    let settings = Settings::of(&job, &vars);
    let child_env = env::child_env(&job, &vars, &place, dir)?;
    let mut phrases = vars.masked();
    // Credentials shorter than GitLab's shortest masked value would mask every occurrence of
    // some common word instead.
    let credentials = std::iter::once(&job.token)
        .chain(job.dependencies.iter().map(|d| &d.token))
        .chain(job.registry_credentials.iter().map(|c| &c.password));
    phrases.extend(credentials.filter(|c| c.len() >= MIN_MASKED_LEN).cloned());
    let trace = Arc::new(Trace::open(
        &dir.join(journal::OUTPUT),
        &phrases,
        &job.trace.mask_prefixes,
        limit,
        job.trace.sections,
    )?);
    let timeout = Duration::from_secs(job.timeout_secs.max(1));
    let ctx = JobCtx::for_env(cfg, &child_env)?;
    let driver = Driver {
        ctx,
        env: child_env,
        dir: dir.to_path_buf(),
        job,
        trace,
        deadline: Instant::now() + timeout,
        timeout,
        stopped: CancellationToken::new(),
    };
    Ok(Setup {
        driver,
        vars,
        settings,
        place,
        meta,
    })
}

impl Driver {
    async fn run_job(
        &mut self,
        vars: &mut Vars,
        settings: &Settings,
        place: &super::vars::Place,
        meta: &Meta,
    ) -> JobResult {
        let t = self.trace.clone();
        t.print(&format!("Running with vk {}", env!("CARGO_PKG_VERSION")));
        t.print(&format!(
            "  on node {}, GitLab job {}",
            super::super::inventory::hostname(),
            meta.gitlab_id
        ));
        for w in &settings.warnings {
            t.warning(w);
        }
        let (end, class, artifacts) = self.stages(vars, settings, place).await;
        self.set_stage("cleanup");
        match self.executor("cleanup", &[], None).await {
            Ok(End::Ok) => {}
            Ok(end) => say_log(&self.dir, &format!("cleanup: {end:?}")),
            Err(e) => say_log(&self.dir, &format!("cleanup: {e:#}")),
        }
        let (failure, exit_code, message) = match (&end, class) {
            (End::Ok, None) => {
                t.notice("Job succeeded");
                (None, None, None)
            }
            (end, class) => {
                let (class, code, why) = describe(end, class, self.timeout);
                t.error(&format!("Job failed: {why}"));
                (Some(class), code, Some(why))
            }
        };
        t.flush();
        JobResult {
            failure,
            exit_code,
            message,
            output_len: t.len(),
            artifacts,
        }
    }

    /// Every stage up to cleanup: how the job ended, a class when it was not a stage's own
    /// end that decided it, and the artifacts' outcomes.
    async fn stages(
        &mut self,
        vars: &mut Vars,
        settings: &Settings,
        place: &super::vars::Place,
    ) -> (End, Option<FailureClass>, Vec<ArtifactOutcome>) {
        let skipped = |job: &CiJob| -> Vec<ArtifactOutcome> {
            job.artifacts
                .iter()
                .map(|a| ArtifactOutcome {
                    name: a.name.clone(),
                    artifact_type: a.artifact_type.clone(),
                    state: UploadState::Skipped,
                })
                .collect()
        };
        let host_checkout = self.ctx.cfg.executor.host_checkout;
        if host_checkout
            && matches!(
                settings.submodules,
                Submodules::Normal | Submodules::Recursive
            )
        {
            let why = "GIT_SUBMODULE_STRATEGY needs the checkout in the guest on vk nodes \
                       ([executor] host_checkout = false)";
            self.trace.error(why);
            return (
                End::System(why.into()),
                Some(FailureClass::Configuration),
                skipped(&self.job),
            );
        }

        // prepare_executor
        self.set_stage("prepare_executor");
        self.trace.section_start("prepare_executor");
        self.header("Preparing the \"vk\" executor");
        let prepared = self
            .executor("prepare", &[], Some((Phase::Before, None)))
            .await;
        self.trace.section_end("prepare_executor");
        match prepared {
            Ok(End::Ok) => {}
            Ok(End::Stopped(stop)) => return (End::Stopped(stop), None, skipped(&self.job)),
            Ok(_) => {
                return (
                    End::System("preparing the environment failed".into()),
                    Some(FailureClass::System),
                    skipped(&self.job),
                );
            }
            Err(e) => return (End::System(format!("{e:#}")), None, skipped(&self.job)),
        }
        let posix = std::fs::read_to_string(self.ctx.job_dir.join("guest.shell"))
            .is_ok_and(|s| s.trim() == "sh");
        let hostname = super::super::inventory::hostname();
        let job = self.job.clone();

        // prepare_script, get_sources
        let mut end = {
            let info = info(&job, vars, settings, place, posix, &hostname, host_checkout);
            let s = script::prepare(&info);
            self.guest_stage(
                "prepare_script",
                "Preparing environment",
                s,
                None,
                Phase::Before,
            )
            .await
        };
        let mut class = None;
        if end == End::Ok {
            let info = info(&job, vars, settings, place, posix, &hostname, host_checkout);
            let s = script::get_sources(&info);
            for attempt in 1..=settings.get_sources_attempts {
                if attempt > 1 {
                    self.trace.warning(&format!(
                        "Retrying get_sources (attempt {attempt} of {})",
                        settings.get_sources_attempts
                    ));
                }
                end = self
                    .guest_stage(
                        "get_sources",
                        "Getting source from Git repository",
                        s.clone(),
                        None,
                        Phase::Before,
                    )
                    .await;
                if !matches!(end, End::Script(_)) {
                    break;
                }
            }
            if matches!(end, End::Script(_)) {
                class = Some(FailureClass::ExternalDependency);
            }
        }

        let scratch = journal::scratch_dir(&self.dir);
        let _ = std::fs::create_dir_all(&scratch);
        let addr = crate::executor::vsock_addr(&self.ctx);
        let user = self.ctx.user_req.clone();

        // restore_cache, download_artifacts
        if end == End::Ok {
            let stage_ctx = self.stage_ctx(&job, vars, &addr, &user, place, &scratch);
            if cache::restore_applies(&stage_ctx) {
                end = self
                    .host_stage("restore_cache", "Restoring cache", Phase::Before, async {
                        let attempts = settings.restore_cache_attempts;
                        stage_ctx
                            .attempted("restore_cache", attempts, || cache::restore(&stage_ctx))
                            .await
                    })
                    .await;
                if matches!(end, End::System(_)) {
                    class = Some(FailureClass::ExternalDependency);
                }
            }
        }
        if end == End::Ok {
            let stage_ctx = self.stage_ctx(&job, vars, &addr, &user, place, &scratch);
            if artifacts::download_applies(&stage_ctx) {
                end = self
                    .host_stage(
                        "download_artifacts",
                        "Downloading artifacts",
                        Phase::Before,
                        async {
                            let attempts = settings.artifact_download_attempts;
                            stage_ctx
                                .attempted("download_artifacts", attempts, || {
                                    artifacts::download(&stage_ctx)
                                })
                                .await
                        },
                    )
                    .await;
                if matches!(end, End::System(_)) {
                    class = Some(FailureClass::ExternalDependency);
                }
            }
        }

        // The steps, under the job's timeout and RUNNER_SCRIPT_TIMEOUT.
        let steps_started = end == End::Ok;
        if steps_started {
            let script_deadline = settings.script_timeout.map(|d| Instant::now() + d);
            for step in job.steps.iter().filter(|s| s.name != STEP_AFTER_SCRIPT) {
                let name = format!("step_{}", step.name.to_lowercase());
                let info = info(&job, vars, settings, place, posix, &hostname, host_checkout);
                let s = script::step(&info, step);
                let header = format!("Executing \"{name}\" stage of the job script");
                end = self
                    .guest_stage(&name, &header, s, script_deadline, Phase::Steps)
                    .await;
                if end != End::Ok {
                    break;
                }
            }
            if end == End::Stopped(Stop::Cancel(CancelMode::Graceful)) {
                self.trace.warning("script canceled externally (UI, API)");
            }
        }

        // after_script: whatever the steps did, unless the job's own time is up or it is
        // stopped outright.
        let after = job.steps.iter().find(|s| s.name == STEP_AFTER_SCRIPT);
        let after_runs = steps_started
            && !matches!(
                end,
                End::Stopped(Stop::Timeout | Stop::Cancel(CancelMode::Immediate))
            );
        if after_runs {
            let status = match &end {
                End::Ok => "success",
                End::Stopped(Stop::Cancel(_)) => "canceled",
                _ => "failed",
            };
            vars.overwrite("CI_JOB_STATUS", status);
            let info = info(&job, vars, settings, place, posix, &hostname, host_checkout);
            if let Some(s) = script::after_script(&info, after) {
                let deadline = Some(Instant::now() + settings.after_script_timeout);
                let after_end = self
                    .guest_stage(
                        "after_script",
                        "Running after_script",
                        s,
                        deadline,
                        Phase::After,
                    )
                    .await;
                match after_end {
                    End::Ok => {}
                    End::Stopped(stop @ (Stop::Timeout | Stop::Cancel(CancelMode::Immediate))) => {
                        end = End::Stopped(stop)
                    }
                    other if settings.after_script_ignore_errors => self.trace.warning(&format!(
                        "after_script failed, but job will continue unaffected: {}",
                        describe(&other, None, self.timeout).2
                    )),
                    other => {
                        if end == End::Ok {
                            end = other;
                        }
                    }
                }
            }
        }

        // Caches and artifacts, for a job that ended on its own.
        let mut outcomes = skipped(&job);
        let archive = matches!(end, End::Ok | End::Script(_))
            || (matches!(end, End::System(_)) && class == Some(FailureClass::ExternalDependency));
        if archive && steps_started {
            let succeeded = end == End::Ok;
            let stage_ctx = self.stage_ctx(&job, vars, &addr, &user, place, &scratch);
            if cache::archive_applies(&stage_ctx, succeeded) {
                let (name, header) = match succeeded {
                    true => ("archive_cache", "Saving cache for successful job"),
                    false => ("archive_cache_on_failure", "Saving cache for failed job"),
                };
                let saved = self
                    .host_stage(name, header, Phase::Archive, async {
                        cache::archive(&stage_ctx, succeeded).await
                    })
                    .await;
                if let End::Stopped(stop) = saved {
                    end = End::Stopped(stop);
                }
            }
            if artifacts::upload_applies(&stage_ctx, succeeded) && !matches!(end, End::Stopped(_)) {
                let (name, header) = match succeeded {
                    true => (
                        "upload_artifacts_on_success",
                        "Uploading artifacts for successful job",
                    ),
                    false => (
                        "upload_artifacts_on_failure",
                        "Uploading artifacts for failed job",
                    ),
                };
                let mut uploaded = Vec::new();
                let up = self
                    .host_stage(name, header, Phase::Archive, async {
                        let (o, r) = artifacts::upload(&stage_ctx, succeeded).await;
                        uploaded = o;
                        r
                    })
                    .await;
                if !uploaded.is_empty() {
                    outcomes = uploaded;
                }
                match up {
                    End::Ok => {}
                    End::Stopped(stop) => end = End::Stopped(stop),
                    other if end == End::Ok => {
                        end = other;
                        class = Some(FailureClass::ExternalDependency);
                    }
                    _ => {}
                }
            }
        }

        // cleanup_file_variables: the last stage the trace keeps, where the executor prints
        // its once-per-job summaries. Skipped, as gitlab-runner's expired job context skips
        // it, once the job's time is up or it is stopped outright.
        if !matches!(
            end,
            End::Stopped(Stop::Timeout | Stop::Cancel(CancelMode::Immediate))
        ) {
            let info = info(&job, vars, settings, place, posix, &hostname, host_checkout);
            let s = script::cleanup(&info);
            self.stopped = CancellationToken::new();
            let cleaned = self
                .guest_stage(
                    "cleanup_file_variables",
                    "Cleaning up project directory and file based variables",
                    s,
                    Some(Instant::now() + Duration::from_secs(300)),
                    Phase::Cleanup,
                )
                .await;
            if cleaned != End::Ok {
                say_log(&self.dir, &format!("cleanup_file_variables: {cleaned:?}"));
            }
        }
        (end, class, outcomes)
    }

    fn stage_ctx<'a>(
        &'a self,
        job: &'a CiJob,
        vars: &'a Vars,
        addr: &vk_core::addr::SocketAddr,
        user: &Option<String>,
        place: &super::vars::Place,
        scratch: &'a Path,
    ) -> StageCtx<'a> {
        StageCtx {
            cfg: &self.ctx.cfg,
            job,
            vars,
            addr: addr.clone(),
            user: user.clone(),
            project_dir: place.project_dir.clone(),
            trace: &self.trace,
            scratch,
            cancel: &self.stopped,
        }
    }

    fn set_stage(&self, stage: &str) {
        // Best effort: the stage is for the hub's display, the trace says it too.
        let _ = vk_fs::write_atomic(&self.dir.join(journal::STAGE), stage.as_bytes(), 0o600);
    }

    /// A stage's header, as gitlab-runner prints its description.
    fn header(&self, text: &str) {
        self.trace
            .print(&format!("{ANSI_BOLD_CYAN}{text}{ANSI_RESET}"));
    }

    /// What stops a stage of `phase` now, if anything.
    fn stop(&self, phase: Phase, stage_deadline: Option<Instant>) -> Option<Stop> {
        let now = Instant::now();
        if phase != Phase::Cleanup && now >= self.deadline {
            return Some(Stop::Timeout);
        }
        if stage_deadline.is_some_and(|d| now >= d) {
            return Some(Stop::StageTimeout);
        }
        match (journal::read_cancel(&self.dir), phase) {
            (_, Phase::Cleanup) => None,
            (Some(CancelMode::Immediate | CancelMode::Other), _) => {
                Some(Stop::Cancel(CancelMode::Immediate))
            }
            (Some(CancelMode::Graceful), Phase::After) => None,
            (Some(CancelMode::Graceful), _) => Some(Stop::Cancel(CancelMode::Graceful)),
            (None, _) => None,
        }
    }

    /// A stage run as a script in the guest, through `vk gitlab run`.
    async fn guest_stage(
        &self,
        stage: &str,
        header: &str,
        script: String,
        stage_deadline: Option<Instant>,
        phase: Phase,
    ) -> End {
        if let Some(stop) = self.stop(phase, stage_deadline) {
            return End::Stopped(stop);
        }
        self.set_stage(stage);
        self.trace.section_start(stage);
        self.header(header);
        let scripts = journal::scripts_dir(&self.dir);
        let path = scripts.join(format!("{stage}.sh"));
        let written = std::fs::DirBuilder::new()
            .recursive(true)
            .create(&scripts)
            .map_err(anyhow::Error::from)
            .and_then(|()| vk_fs::write_atomic(&path, script.as_bytes(), 0o600));
        let end = match written {
            Err(e) => End::System(format!("writing the {stage} script: {e:#}")),
            Ok(()) => {
                let _ = std::fs::remove_file(self.dir.join(env::EXIT_CODE_FILE));
                let args = [path.as_os_str().to_owned(), stage.into()];
                match self
                    .executor("run", &args, Some((phase, stage_deadline)))
                    .await
                {
                    Ok(end) => end,
                    Err(e) => End::System(format!("{e:#}")),
                }
            }
        };
        // The script holds the job's variables, secrets among them.
        let _ = std::fs::remove_file(&path);
        self.trace.flush();
        self.trace.section_end(stage);
        if let End::Stopped(_) = end {
            self.stopped.cancel();
        }
        end
    }

    /// A stage the node runs itself.
    async fn host_stage(
        &self,
        stage: &str,
        header: &str,
        phase: Phase,
        work: impl std::future::Future<Output = Result<()>>,
    ) -> End {
        if let Some(stop) = self.stop(phase, None) {
            return End::Stopped(stop);
        }
        self.set_stage(stage);
        self.trace.section_start(stage);
        self.header(header);
        tokio::pin!(work);
        let end = loop {
            tokio::select! {
                r = &mut work => break match r {
                    Ok(()) => End::Ok,
                    Err(e) => {
                        self.trace.error(&format!("{e:#}"));
                        End::System(format!("{stage}: {e:#}"))
                    }
                },
                () = tokio::time::sleep(Duration::from_millis(500)) => {
                    if let Some(stop) = self.stop(phase, None) {
                        self.stopped.cancel();
                        break End::Stopped(stop);
                    }
                }
            }
        };
        self.trace.flush();
        self.trace.section_end(stage);
        end
    }

    /// `vk gitlab <cmd> <args>` with the job's executor environment, its output into the
    /// trace — or, for cleanup (`phase` `None`, bounded by [`CLEANUP_TIMEOUT`]), into the
    /// driver's log, as gitlab-runner keeps cleanup's output out of a job's trace.
    async fn executor(
        &self,
        cmd: &str,
        args: &[std::ffi::OsString],
        phase: Option<(Phase, Option<Instant>)>,
    ) -> Result<End> {
        let mut command = Command::new(crate::spawn::self_exe());
        if let Some(src) = &self.ctx.cfg.source {
            command.arg("--config").arg(src);
        }
        command
            .args(["gitlab", cmd])
            .args(args)
            .stdin(Stdio::null());
        env::apply(&mut command, &self.env);
        let (reader, writer) = pipe()?;
        command
            .stdout(Stdio::from(writer.try_clone()?))
            .stderr(Stdio::from(writer));
        let mut child = command
            .spawn()
            .with_context(|| format!("starting `vk gitlab {cmd}`"))?;
        // The parent's copies of the write end are gone with `command`.
        drop(command);
        let trace = self.trace.clone();
        let log = self.dir.join(journal::DRIVER_LOG);
        let to_trace = phase.is_some();
        let pump = tokio::task::spawn_blocking(move || {
            let mut reader = File::from(reader);
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let chunk = buf.get(..n).unwrap_or_default();
                        if to_trace {
                            trace.write(chunk);
                        } else {
                            append_log(&log, chunk);
                        }
                    }
                }
            }
        });
        let mut stopped = None;
        let cleanup_deadline = Instant::now() + CLEANUP_TIMEOUT;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            let stop = match phase {
                Some((phase, deadline)) => self.stop(phase, deadline),
                None => (Instant::now() >= cleanup_deadline).then_some(Stop::StageTimeout),
            };
            if stopped.is_none()
                && let Some(stop) = stop
            {
                stopped = Some(stop);
                kill(&mut child).await;
                continue;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        // The pipe closes once every process holding it is gone; a guest command's own
        // children never get it.
        let _ = pump.await;
        if let Some(stop) = stopped {
            return Ok(End::Stopped(stop));
        }
        Ok(match status.code() {
            Some(0) => End::Ok,
            Some(env::BUILD_FAILURE_EXIT_CODE) => {
                let code = std::fs::read_to_string(self.dir.join(env::EXIT_CODE_FILE))
                    .ok()
                    .and_then(|s| s.trim().parse().ok());
                End::Script(code)
            }
            Some(code) => End::System(format!("`vk gitlab {cmd}` exited {code}")),
            None => End::System(format!("`vk gitlab {cmd}` was killed by a signal")),
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn info<'a>(
    job: &'a CiJob,
    vars: &'a Vars,
    settings: &'a Settings,
    place: &'a super::vars::Place,
    posix: bool,
    hostname: &'a str,
    host_checkout: bool,
) -> script::Info<'a> {
    script::Info {
        job,
        vars,
        settings,
        project_dir: &place.project_dir,
        builds_dir: &place.builds_dir,
        posix,
        hostname,
        host_checkout,
    }
}

/// The failure class, exit code and words for how a job ended, gitlab-runner's where it has
/// them.
fn describe(
    end: &End,
    class: Option<FailureClass>,
    timeout: Duration,
) -> (FailureClass, Option<i32>, String) {
    match end {
        End::Ok => (class.unwrap_or(FailureClass::Other), None, "unknown".into()),
        End::Script(code) => (
            class.unwrap_or(FailureClass::Script),
            *code,
            match code {
                Some(c) => format!("exit code {c}"),
                None => "exit code 1".into(),
            },
        ),
        End::System(why) => (class.unwrap_or(FailureClass::System), None, why.clone()),
        End::Stopped(Stop::Cancel(_)) => (FailureClass::Canceled, None, "canceled".into()),
        End::Stopped(Stop::Timeout) => (
            FailureClass::Timeout,
            None,
            format!(
                "execution took longer than {} seconds",
                go_duration(timeout)
            ),
        ),
        End::Stopped(Stop::StageTimeout) => (
            FailureClass::Timeout,
            None,
            "the script exceeded its timeout".into(),
        ),
    }
}

/// Go's `time.Duration` string for whole seconds: `1h0m0s`, `5m0s`, `30s`.
fn go_duration(d: Duration) -> String {
    let s = d.as_secs();
    let (h, m, s) = (s / 3600, s / 60 % 60, s % 60);
    match (h, m) {
        (0, 0) => format!("{s}s"),
        (0, m) => format!("{m}m{s}s"),
        (h, m) => format!("{h}h{m}m{s}s"),
    }
}

/// SIGTERM, then SIGKILL after [`KILL_GRACE`]: `vk gitlab run` dropping its exec channel
/// ends the guest command.
async fn kill(child: &mut std::process::Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: plain kill(2) on our own child, which has not been reaped.
        unsafe { libc::kill(pid, libc::SIGTERM) };
    }
    let until = Instant::now() + KILL_GRACE;
    while Instant::now() < until {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Already gone if this fails: nothing left to kill.
    let _ = child.kill();
}

fn pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe2 fills both descriptors on success, which we then own.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error()).context("making a pipe");
    }
    // SAFETY: just created, owned by nothing else.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn append_log(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
    {
        // Nowhere else to report a log that cannot be written.
        let _ = f.write_all(bytes);
    }
}

fn say_log(dir: &Path, line: &str) {
    append_log(
        &dir.join(journal::DRIVER_LOG),
        format!("{line}\n").as_bytes(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_print_as_go_prints_them() {
        assert_eq!(go_duration(Duration::from_secs(3600)), "1h0m0s");
        assert_eq!(go_duration(Duration::from_secs(300)), "5m0s");
        assert_eq!(go_duration(Duration::from_secs(42)), "42s");
    }

    #[test]
    fn a_job_ends_with_gitlab_runners_words_and_class() {
        let t = Duration::from_secs(3600);
        assert_eq!(
            describe(&End::Script(Some(3)), None, t),
            (FailureClass::Script, Some(3), "exit code 3".into())
        );
        assert_eq!(
            describe(&End::Stopped(Stop::Timeout), None, t).2,
            "execution took longer than 1h0m0s seconds"
        );
        assert_eq!(
            describe(&End::Stopped(Stop::Cancel(CancelMode::Graceful)), None, t).0,
            FailureClass::Canceled
        );
        assert_eq!(
            describe(
                &End::Script(Some(1)),
                Some(FailureClass::ExternalDependency),
                t
            )
            .0,
            FailureClass::ExternalDependency
        );
    }
}
