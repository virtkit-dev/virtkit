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
    /// CI_JOB_NAME — with the project, what makes two runs "the same job" for the memory
    /// history (`[schedule] from_history`). The job id cannot: it is unique per run.
    job_name: Option<String>,
    /// CI_PROJECT_ID — unique on the GitLab instance, where the slug beside it is not: it is
    /// lower-cased, punctuation-folded and cut to 63 characters, so two projects can share
    /// one. The id scopes the history; the slug only makes the directory readable.
    project_id: Option<String>,
}

impl JobCtx {
    pub fn new(cfg: Config) -> Result<JobCtx> {
        // The runner's own account of the job first; CI_JOB_ID is the same number where
        // there is no job response to read, and VM_JOB_ID covers manual runs outside
        // gitlab-runner.
        // Read once and threaded down: two reads of the same path are two chances to get two
        // different answers, and the job id and the project identity have to come from one.
        let response = JobResponse::read();
        let job_id = match &response {
            Some(r) => r.id.to_string(),
            None => std::env::var("CUSTOM_ENV_CI_JOB_ID")
                .or_else(|_| std::env::var("VM_JOB_ID"))
                .unwrap_or_else(|_| "dev".into()),
        };
        Self::with_response(cfg, job_id, response)
    }

    /// A context for a named job id, reading whatever job response the environment offers.
    /// Test-only since [`JobCtx::new`] threads its own single read down: two reads of the same
    /// path are two chances to get two different answers.
    #[cfg(test)]
    pub fn new_for_job(cfg: Config, job_id: String) -> Result<JobCtx> {
        let response = JobResponse::read();
        Self::with_response(cfg, job_id, response)
    }

    fn with_response(cfg: Config, job_id: String, response: Option<JobResponse>) -> Result<JobCtx> {
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
            identity_from_runner: response.is_some(),
            usage_report_req: job_var("MICROVM_USAGE_REPORT").is_some_and(|v| is_truthy(&v)),
            build_failure: exit_code_env("BUILD_FAILURE_EXIT_CODE", 1),
            system_failure: exit_code_env("SYSTEM_FAILURE_EXIT_CODE", 2),
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
        })
    }

    /// The root every `[gitlab] host_checkout` tree on this host lives under — the unit the idle
    /// checkout sweep walks. `[gitlab] checkout_dir` (e.g. the RAM-backed /builds tmpfs) overrides
    /// the on-disk default so the clone and the job's writes to the shared tree stay in host RAM.
    pub fn host_checkout_root(&self) -> PathBuf {
        self.cfg.checkout_root()
    }

    /// The host directory this job's sources are checked out into, keyed by the runner's
    /// concurrent slot + project so sequential jobs reuse it (a fetch, not a re-clone) while
    /// concurrent jobs on the same runner stay isolated.
    pub fn host_checkout_dir(&self) -> PathBuf {
        // The slot/project key comes from sanitized env, never a job-controlled absolute path.
        self.host_checkout_root()
            .join(&self.concurrent_id)
            .join(&self.project_slug)
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

    /// The host-wide memory ledger (`[schedule] mem_budget`), shared by every job on this
    /// host — including those of another runner sharing the state dir. Outside the job dir
    /// on purpose: a job's own dir is wiped and recreated by its prepare.
    pub fn admit_dir(&self) -> PathBuf {
        self.cfg.state_dir().join("admit")
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
    /// Where the per-job switch publishes the bytes it has forwarded, for the end-of-job
    /// resource line. Always written when there is a switch: what a job moved over the
    /// network is part of what it cost, not something to opt into.
    pub fn net_bytes_log(&self) -> PathBuf {
        self.job_dir.join("net.bytes")
    }
    /// Typed egress-denial records the switch appends and each `run` stage drains into the
    /// job trace (see egress_report). Separate from the human `switch.log`.
    pub fn egress_denied_log(&self) -> PathBuf {
        self.job_dir.join("egress-denied.log")
    }
    /// Audit channel: every allowed external domain the switch saw this job's guest
    /// resolve, appended one-per-line and drained into the end-of-job "domains contacted"
    /// summary (see egress_report). Written for every job, audit or not: the standing list of
    /// names a job contacts is read from it too (see sites).
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
    fn read() -> Option<JobResponse> {
        // Errors are swallowed rather than reported: the text holds the job token, so nothing
        // from it goes near a log, and the caller falls back to the variables. But falling back
        // *inside a job* means keying that job's stored state on values the job itself can set,
        // which is what this exists to stop — so say so once, where an operator will see it.
        let parsed = std::env::var("JOB_RESPONSE_FILE")
            .ok()
            .and_then(|path| std::fs::read_to_string(&path).ok())
            .and_then(|text| serde_json::from_str::<JobResponse>(&text).ok());
        if parsed.is_none() && std::env::var_os("CUSTOM_ENV_CI_JOB_ID").is_some() {
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
    use std::path::Path;

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
        let ctx = JobCtx::with_response(Config::default(), "4242".into(), Some(r))
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
