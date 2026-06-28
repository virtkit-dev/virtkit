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
    /// MICROVM_EGRESS_ALLOW_NAME job variable (space/comma separated): narrow this
    /// job's switch egress to a subset of the host [egress] allow_name cap. None =
    /// use the full cap. A name outside the cap fails the job (a job can narrow but
    /// never widen its egress).
    pub egress_allow_name_req: Option<String>,
    /// Exit code telling gitlab-runner the *script* failed (job failure)
    pub build_failure: i32,
    /// Exit code telling gitlab-runner the *environment* failed (retryable)
    pub system_failure: i32,
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
        // MICROVM_IMAGE job variable (VM_IMAGE for manual runs); parsed and
        // validated by image::resolve
        let image_ref = std::env::var("CUSTOM_ENV_MICROVM_IMAGE")
            .or_else(|_| std::env::var("VM_IMAGE"))
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
            egress_allow_name_req: job_var("MICROVM_EGRESS_ALLOW_NAME"),
            build_failure: exit_code_env("BUILD_FAILURE_EXIT_CODE", 1),
            system_failure: exit_code_env("SYSTEM_FAILURE_EXIT_CODE", 2),
        })
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
    pub fn ch_pidfile(&self) -> PathBuf {
        self.job_dir.join("ch.pid")
    }
    pub fn vfsd_pidfile(&self) -> PathBuf {
        self.job_dir.join("vfsd.pid")
    }
    pub fn console_log(&self) -> PathBuf {
        self.job_dir.join("console.log")
    }
    pub fn ch_log(&self) -> PathBuf {
        self.job_dir.join("ch.log")
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
    pub fn tools_vfsd_pidfile(&self) -> PathBuf {
        self.job_dir.join("tools-vfsd.pid")
    }
    pub fn tools_vfsd_log(&self) -> PathBuf {
        self.job_dir.join("tools-vfsd.log")
    }
    /// Host side of the services registry forward (a detached `virtkit
    /// forward` child, like the VMM): killed in cleanup, found via its pidfile.
    pub fn svc_forward_pidfile(&self) -> PathBuf {
        self.job_dir.join("svc-forward.pid")
    }
    pub fn svc_forward_log(&self) -> PathBuf {
        self.job_dir.join("svc-forward.log")
    }
    /// Per-job switch (net.mode = "switch"): a detached `virtkit switch` child
    /// giving the VM a userspace LAN over vsock + the egress allowlist; killed
    /// in cleanup, found via its pidfile.
    pub fn switch_pidfile(&self) -> PathBuf {
        self.job_dir.join("switch.pid")
    }
    pub fn switch_log(&self) -> PathBuf {
        self.job_dir.join("switch.log")
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

fn exit_code_env(name: &str, fallback: i32) -> i32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}
