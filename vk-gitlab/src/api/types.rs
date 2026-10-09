//! Request and response bodies of the runner API, and the outcome of each call. Port of
//! gitlab-runner's `common/network.go`; field names and `omitempty` behaviour match, since
//! GitLab reads absent and zero fields differently.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::failure::{FailureReason, JobState};
use crate::secret::Secret;

/// What the runner can do, advertised with every request. GitLab only hands a job to a
/// runner whose features cover what the job needs. All fields are always sent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FeaturesInfo {
    pub variables: bool,
    pub image: bool,
    pub services: bool,
    pub artifacts: bool,
    pub cache: bool,
    pub fallback_cache_keys: bool,
    pub shared: bool,
    pub upload_multiple_artifacts: bool,
    pub upload_raw_artifacts: bool,
    pub session: bool,
    pub terminal: bool,
    pub refspecs: bool,
    pub masking: bool,
    pub proxy: bool,
    pub raw_variables: bool,
    pub artifacts_exclude: bool,
    pub multi_build_steps: bool,
    pub trace_reset: bool,
    pub trace_checksum: bool,
    pub trace_size: bool,
    pub vault_secrets: bool,
    pub cancelable: bool,
    pub return_exit_code: bool,
    pub service_variables: bool,
    pub service_multiple_aliases: bool,
    pub image_executor_opts: bool,
    pub service_executor_opts: bool,
    pub cancel_gracefully: bool,
    pub native_steps_integration: bool,
    pub two_phase_job_commit: bool,
    pub job_inputs: bool,
}

impl FeaturesInfo {
    /// What a vk fleet runner advertises (virtkit's `docs/gitlab-dispatch.md`, "Daemon ↔
    /// GitLab"): the network side's trace and cancellation features, `two_phase_job_commit`
    /// (the job is committed only once a node accepted it), and what the node's executor
    /// runs. Not `session`, `terminal`, `proxy`, `shared`, `vault_secrets`,
    /// `service_multiple_aliases` (a node's executor takes one alias per service),
    /// `image_executor_opts`, `service_executor_opts`, `native_steps_integration` or
    /// `job_inputs`.
    pub fn vk_fleet() -> Self {
        Self {
            variables: true,
            image: true,
            services: true,
            artifacts: true,
            cache: true,
            fallback_cache_keys: true,
            upload_multiple_artifacts: true,
            upload_raw_artifacts: true,
            refspecs: true,
            masking: true,
            raw_variables: true,
            artifacts_exclude: true,
            multi_build_steps: true,
            trace_reset: true,
            trace_checksum: true,
            trace_size: true,
            cancelable: true,
            cancel_gracefully: true,
            return_exit_code: true,
            service_variables: true,
            two_phase_job_commit: true,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigInfo {
    pub gpus: String,
}

/// The runner's description of itself (`info`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Info {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub revision: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub platform: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub architecture: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub executor: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub shell: String,
    pub features: FeaturesInfo,
    pub config: ConfigInfo,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

/// The commit this binary was built from, as the build passed it in `VK_GITLAB_COMMIT`;
/// only its last line, which ends up in a header.
pub fn revision() -> String {
    option_env!("VK_GITLAB_COMMIT")
        .and_then(|c| c.lines().map(str::trim).rfind(|l| !l.is_empty()))
        .filter(|c| c.chars().all(|ch| ch.is_ascii_graphic() || ch == ' '))
        .unwrap_or("unknown")
        .to_owned()
}

impl Info {
    /// This binary's identity, in Go's platform and architecture names: executor `vk`, shell
    /// `bash`, the fleet's features.
    pub fn this_runner() -> Self {
        let architecture = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            "x86" => "386",
            other => other,
        };
        Self {
            name: "vk-gitlab".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            revision: revision(),
            platform: std::env::consts::OS.to_owned(),
            architecture: architecture.to_owned(),
            executor: "vk".to_owned(),
            shell: "bash".to_owned(),
            features: FeaturesInfo::vk_fleet(),
            config: ConfigInfo::default(),
            labels: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct VerifyRunnerRequest<'a> {
    pub info: &'a Info,
    #[serde(skip_serializing_if = "is_empty")]
    pub token: &'a str,
    #[serde(skip_serializing_if = "is_empty")]
    pub system_id: &'a str,
}

/// `POST /api/v4/runners/verify`'s answer. Legacy servers answer with no body, which leaves
/// every field at its default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct VerifyRunnerResponse {
    pub id: i64,
    pub token: Option<Secret>,
    pub token_expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct JobRequest<'a> {
    pub info: &'a Info,
    #[serde(skip_serializing_if = "is_empty")]
    pub token: &'a str,
    #[serde(skip_serializing_if = "is_empty")]
    pub system_id: &'a str,
    #[serde(skip_serializing_if = "is_empty")]
    pub last_update: &'a str,
}

/// The log's state as the runner sees it, sent with each job update.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct JobTraceOutput {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub checksum: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub bytesize: usize,
}

fn is_empty(s: &&str) -> bool {
    s.is_empty()
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

fn is_zero_i32(n: &i32) -> bool {
    *n == 0
}

#[derive(Debug, Serialize)]
pub(crate) struct UpdateJobRequest<'a> {
    pub info: &'a Info,
    #[serde(skip_serializing_if = "is_empty")]
    pub token: &'a str,
    pub state: JobState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<&'a FailureReason>,
    /// Deprecated duplicate of `output.checksum`, still sent by gitlab-runner.
    #[serde(skip_serializing_if = "is_empty")]
    pub checksum: &'a str,
    pub output: &'a JobTraceOutput,
    #[serde(skip_serializing_if = "is_zero_i32")]
    pub exit_code: i32,
    #[serde(skip_serializing_if = "is_empty")]
    pub runtime_environment_key: &'a str,
}

/// The job a call acts for: its ID and the job token GitLab issued with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobCredentials {
    pub id: i64,
    pub token: Secret,
}

/// A job update to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateJobInfo {
    pub id: i64,
    pub state: JobState,
    pub failure_reason: Option<FailureReason>,
    pub output: JobTraceOutput,
    pub exit_code: i32,
    pub runtime_environment_key: String,
}

impl UpdateJobInfo {
    pub fn new(id: i64, state: JobState) -> Self {
        Self {
            id,
            state,
            failure_reason: None,
            output: JobTraceOutput::default(),
            exit_code: 0,
            runtime_environment_key: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateState {
    Succeeded,
    /// 202: GitLab has the state but still processes the log; ask again.
    AcceptedButNotCompleted,
    /// 412: GitLab's copy of the log does not match the checksum; send it all again.
    TraceValidationFailed,
    NotFound,
    /// Stop reporting: the job is gone, failed, canceled, or no longer ours.
    Abort,
    /// Try again.
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateJobResult {
    pub state: UpdateState,
    /// `Job-Status: canceling`: GitLab asks for a graceful cancel.
    pub cancel_requested: bool,
    /// `X-GitLab-Trace-Update-Interval` in seconds; 0 when absent or unparsable. Only a
    /// positive value is applied.
    pub new_update_interval: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchState {
    Succeeded,
    NotFound,
    Abort,
    /// 416: GitLab holds a different length; resume from [`PatchTraceResult::sent_offset`].
    RangeMismatch,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatchTraceResult {
    /// Where the next patch starts: past this one on success, GitLab's length on a range
    /// mismatch, the unchanged start otherwise.
    pub sent_offset: usize,
    pub cancel_requested: bool,
    pub state: PatchState,
    pub new_update_interval: i64,
}

impl PatchTraceResult {
    pub fn new(sent_offset: usize, state: PatchState, new_update_interval: i64) -> Self {
        Self {
            sent_offset,
            cancel_requested: false,
            state,
            new_update_interval,
        }
    }
}

/// The outcome of a job request.
#[derive(Debug)]
pub struct JobRequestResult {
    pub job: Option<Box<crate::job::Job>>,
    /// False when the request says the runner itself is broken (403, unusable URL); repeated
    /// failures mark the runner unhealthy and slow its polling down.
    pub healthy: bool,
}
