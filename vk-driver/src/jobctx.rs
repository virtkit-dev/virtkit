//! Per-job context: the gitlab-runner custom-executor environment
//! (CUSTOM_ENV_*, failure exit codes) plus the job's on-disk state layout.

use std::path::PathBuf;

use anyhow::{Result, bail};

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
    /// MICROVM_EGRESS_ALLOW_IP / _ALLOW_NAME job variables (space/comma separated): narrow
    /// this job's run-phase switch egress to a subset of the host `[egress]` allow_ip /
    /// allow_name cap. None = use the cap unchanged. A request outside the cap fails the job
    /// (a job can narrow but never widen its egress); against an absent (unconstrained) cap
    /// dimension the variable defines the list freely.
    pub egress_allow_ip_req: Option<String>,
    pub egress_allow_name_req: Option<String>,
    /// MICROVM_BUILD_EGRESS_ALLOW_IP / _ALLOW_NAME: the same, for the build phase (git-defined
    /// image / compose `build:` RUN steps), narrowing the `[egress.build]` cap.
    pub egress_build_allow_ip_req: Option<String>,
    pub egress_build_allow_name_req: Option<String>,
    /// MICROVM_EGRESS_AUDIT job variable: when truthy, audit this job's run-phase egress even
    /// if the host `[egress] audit` toggle is off. Auditing only observes (it never widens
    /// egress), so a job may turn it on for itself.
    pub egress_audit_req: bool,
    /// MICROVM_BUILD_EGRESS_AUDIT: the same, for the build phase (`[egress.build] audit`).
    pub egress_build_audit_req: bool,
    /// Exit code telling gitlab-runner the *script* failed (job failure)
    pub build_failure: i32,
    /// Exit code telling gitlab-runner the *environment* failed (retryable)
    pub system_failure: i32,

    // `[gitlab] host_checkout`: the job's git sources, checked out on the host at prepare and
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
}

impl JobCtx {
    pub fn new(cfg: Config) -> Result<JobCtx> {
        // CI_JOB_ID is unique across the GitLab instance; VM_JOB_ID covers manual
        // runs outside gitlab-runner.
        let job_id = std::env::var("CUSTOM_ENV_CI_JOB_ID")
            .or_else(|_| std::env::var("VM_JOB_ID"))
            .unwrap_or_else(|_| "dev".into());
        Self::new_for_job(cfg, job_id)
    }

    pub fn new_for_job(cfg: Config, job_id: String) -> Result<JobCtx> {
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
        let image_ref = std::env::var("CUSTOM_ENV_MICROVM_IMAGE")
            .or_else(|_| std::env::var("VM_IMAGE"))
            .or_else(|_| std::env::var("CUSTOM_ENV_CI_JOB_IMAGE"))
            .ok()
            .filter(|s| !s.is_empty());
        let job_var = |name: &str| {
            std::env::var(format!("CUSTOM_ENV_{name}"))
                .ok()
                .filter(|s| !s.is_empty())
        };
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
            build_failure: exit_code_env("BUILD_FAILURE_EXIT_CODE", 1),
            system_failure: exit_code_env("SYSTEM_FAILURE_EXIT_CODE", 2),
            ci_repo_url: job_var("CI_REPOSITORY_URL"),
            ci_commit_sha: job_var("CI_COMMIT_SHA"),
            ci_commit_ref: job_var("CI_COMMIT_REF_NAME"),
            ci_project_dir: job_var("CI_PROJECT_DIR"),
            // Slug + concurrent id are safe path components by GitLab's own rules; sanitize
            // defensively so a surprising value can never escape the checkouts root.
            concurrent_id: safe_component(job_var("CI_CONCURRENT_ID"), "0"),
            project_slug: safe_component(job_var("CI_PROJECT_PATH_SLUG"), "repo"),
        })
    }

    /// The host directory the job's sources are checked out into for `[gitlab] host_checkout`,
    /// keyed by the runner's concurrent slot + project so sequential jobs reuse it (a fetch, not
    /// a re-clone) while concurrent jobs on the same runner stay isolated.
    pub fn host_checkout_dir(&self) -> PathBuf {
        // `[gitlab] checkout_dir` (e.g. the RAM-backed /builds tmpfs) overrides the on-disk
        // default so the clone and the job's writes to the shared tree stay in host RAM. The
        // slot/project key still comes from sanitized env, never a job-controlled absolute path.
        let root = match self
            .cfg
            .gitlab
            .as_ref()
            .and_then(|g| g.checkout_dir.as_ref())
        {
            Some(dir) => dir.clone(),
            None => self.cfg.state_dir().join("checkouts"),
        };
        root.join(&self.concurrent_id).join(&self.project_slug)
    }

    pub fn overlay(&self) -> PathBuf {
        self.job_dir.join("overlay.qcow2")
    }
    pub fn api_sock(&self) -> PathBuf {
        self.job_dir.join("api.sock")
    }
    pub fn vsock_sock(&self) -> PathBuf {
        self.job_dir.join("vsock.sock")
    }
    pub fn vfsd_sock(&self) -> PathBuf {
        self.job_dir.join("vfsd.sock")
    }
    /// The job supervisor — the ONE detached process owning every helper (switch,
    /// virtiofsds, forwards, the VMM) as tied children. It writes this pidfile
    /// itself at startup; cleanup and the stale-state sweep signal it, and
    /// everything else cascades (PDEATHSIG).
    pub fn supervisor_pidfile(&self) -> PathBuf {
        self.job_dir.join("supervisor.pid")
    }
    pub fn supervisor_log(&self) -> PathBuf {
        self.job_dir.join("supervisor.log")
    }
    pub fn console_log(&self) -> PathBuf {
        self.job_dir.join("console.log")
    }
    /// The VMM subprocess's own stdout/stderr (vk's boot errors), written by `spawn_vmm`
    /// next to the guest serial console.
    pub fn vmm_log(&self) -> PathBuf {
        self.job_dir.join("console.vmm.log")
    }
    pub fn net_lease(&self) -> PathBuf {
        self.job_dir.join("net.lease")
    }
    pub fn vfsd_log(&self) -> PathBuf {
        self.job_dir.join("vfsd.log")
    }
    /// Second virtiofsd, read-only, exporting the `[gitlab] dir` CI tools into the
    /// job VM (the agent links them onto the guest PATH). Separate socket/pid/log
    /// from the dev `[share]` virtiofsd.
    pub fn tools_vfsd_sock(&self) -> PathBuf {
        self.job_dir.join("tools-vfsd.sock")
    }
    pub fn tools_vfsd_log(&self) -> PathBuf {
        self.job_dir.join("tools-vfsd.log")
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
    /// Typed egress-denial records the switch appends and each `run` stage drains into the
    /// job trace (see egress_report). Separate from the human `switch.log`.
    pub fn egress_denied_log(&self) -> PathBuf {
        self.job_dir.join("egress-denied.log")
    }
    /// Audit channel: every allowed external domain the switch saw this job's guest
    /// resolve, appended one-per-line and drained into the end-of-job "domains contacted"
    /// summary (see egress_report). Written only when audit is on.
    pub fn egress_audit_log(&self) -> PathBuf {
        self.job_dir.join("egress-audit.log")
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
    /// The host unix socket Cloud Hypervisor surfaces a guest connection to host
    /// vsock port `port` on (`<vsock.sock>_<port>`) — where the switch listens
    /// for the in-guest agent's eth0 bridge.
    pub fn net_vsock_sock(&self, port: u32) -> PathBuf {
        let mut p = self.vsock_sock().into_os_string();
        p.push(format!("_{port}"));
        PathBuf::from(p)
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

fn exit_code_env(name: &str, fallback: i32) -> i32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Gitlab;

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
            build_failure: 1,
            system_failure: 2,
            ci_repo_url: None,
            ci_commit_sha: None,
            ci_commit_ref: None,
            ci_project_dir: None,
            concurrent_id: "0".into(),
            project_slug: "myproj".into(),
        }
    }

    #[test]
    fn host_checkout_dir_defaults_under_state_dir() {
        let cfg = Config {
            state_dir: Some(PathBuf::from("/var/lib/vk")),
            ..Default::default()
        };
        assert_eq!(
            ctx(cfg).host_checkout_dir(),
            PathBuf::from("/var/lib/vk/checkouts/0/myproj")
        );
    }

    #[test]
    fn host_checkout_dir_honors_checkout_dir_override() {
        let cfg = Config {
            state_dir: Some(PathBuf::from("/var/lib/vk")),
            gitlab: Some(Gitlab {
                host_checkout: true,
                checkout_dir: Some(PathBuf::from("/builds")),
                ..Default::default()
            }),
            ..Default::default()
        };
        // The override replaces the `<state_dir>/checkouts` root; the slot/project key is unchanged.
        assert_eq!(
            ctx(cfg).host_checkout_dir(),
            PathBuf::from("/builds/0/myproj")
        );
    }
}
