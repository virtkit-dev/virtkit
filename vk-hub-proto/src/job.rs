//! A job the hub places on a node: what to run ([`JobSpec`]), the resources set aside for it
//! ([`Envelope`]), and how it ended ([`JobResult`]). The same spec rides on the hub's client
//! API ([`crate::client`]) and on the node session ([`crate::dispatch`]).
//!
//! A GitLab CI job ([`CiJob`]) is translated by `vk-gitlab` from GitLab's `jobs/request`
//! response: every field the node acts on is carried in a vk type of its own, normalized
//! (defaults filled in, cache keys sanitized, nothing left for the node to expand), and what
//! concerns only the conversation with GitLab — the runner token, the failure reasons GitLab
//! accepts, queue metrics — stays with the daemon. `docs/gitlab-dispatch.md` accounts for
//! every field of the response. The failure-reason mapping ports gitlab-runner's
//! `common/failure_reason_mapper.go` (MIT).
//!
//! A job spec carries secrets — the job token, dependency tokens, masked and file variables,
//! registry passwords — so whoever logs one prints [`CiJob::redacted`] instead.

use serde::{Deserialize, Serialize};

/// The maximum serialized [`JobSpec`] size in bytes. It travels in one session message;
/// the gap to [`crate::MAX_MESSAGE`] leaves room for the enclosing message.
pub const MAX_JOB_SPEC: usize = 512 * 1024;
const _: () = assert!(MAX_JOB_SPEC < crate::MAX_MESSAGE);

/// Resources a reservation sets aside on a node, and a job holds once it starts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub mem_mib: u64,
    pub cpus: u32,
    /// Job-dir disk, as admission counts it.
    pub disk_bytes: u64,
}

impl Envelope {
    /// Whether `self` fits inside `other` on every resource.
    pub fn fits_in(self, other: Envelope) -> bool {
        self.mem_mib <= other.mem_mib
            && self.cpus <= other.cpus
            && self.disk_bytes <= other.disk_bytes
    }
}

/// What a job runs. A kind an older node cannot parse takes a new protocol version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JobSpec {
    /// A GitLab CI job, run stage by stage the way gitlab-runner runs it.
    GitlabCi(CiJob),
}

/// A GitLab CI job, as the node needs it. Lists keep GitLab's order: variables are exported
/// in it, so a later one overrides an earlier one of the same key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiJob {
    /// GitLab's base URL, from the daemon's runner configuration (`CI_SERVER_URL`): where
    /// the node clones from and downloads and uploads artifacts.
    pub server_url: String,
    /// GitLab's TLS chain as the daemon verified it, PEM, for `CI_SERVER_TLS_CA_FILE`;
    /// `None` when the system roots verify it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ca_pem: Option<String>,
    pub job: CiJobInfo,
    /// `CI_JOB_TOKEN`: authenticates the clone, dependency downloads and artifact uploads,
    /// and is valid only while the job runs.
    pub token: String,
    /// GitLab's `runner_info.timeout`: the job's whole run, every stage included.
    pub timeout_secs: u64,
    pub sources: Sources,
    pub image: Image,
    #[serde(default)]
    pub services: Vec<Image>,
    #[serde(default)]
    pub variables: Vec<Variable>,
    /// The user steps in GitLab's order, `after_script` among them.
    pub steps: Vec<Step>,
    #[serde(default)]
    pub hooks: Vec<Hook>,
    #[serde(default)]
    pub artifacts: Vec<ArtifactSpec>,
    #[serde(default)]
    pub caches: Vec<CacheSpec>,
    #[serde(default)]
    pub dependencies: Vec<Dependency>,
    /// From GitLab's `credentials`, those of type `registry`: for pulling the job's and its
    /// services' images.
    #[serde(default)]
    pub registry_credentials: Vec<RegistryCredential>,
    pub trace: TraceOptions,
}

impl CiJob {
    /// The job's page on its GitLab, if one can be named ([`crate::gitlab_job_url`]).
    pub fn job_url(&self) -> Option<String> {
        crate::gitlab_job_url(
            &self.server_url,
            &self.job.project_path,
            &self.job.id.to_string(),
        )
    }

    /// This job with every secret replaced, fit for a log.
    pub fn redacted(&self) -> CiJob {
        const HIDDEN: &str = "[MASKED]";
        let mut job = self.clone();
        job.token = HIDDEN.into();
        let hide = |vars: &mut Vec<Variable>| {
            for v in vars.iter_mut().filter(|v| !v.public || v.masked || v.file) {
                v.value = HIDDEN.into();
            }
        };
        hide(&mut job.variables);
        hide(&mut job.image.variables);
        for service in &mut job.services {
            hide(&mut service.variables);
        }
        for dependency in &mut job.dependencies {
            dependency.token = HIDDEN.into();
        }
        for credential in &mut job.registry_credentials {
            credential.password = HIDDEN.into();
        }
        job
    }
}

/// Who the job is, for the job's predefined variables, its workload entry, history and
/// display. From GitLab's `id` and `job_info`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiJobInfo {
    /// GitLab's job ID.
    pub id: u64,
    pub name: String,
    pub stage: String,
    pub pipeline_id: u64,
    pub project_id: u64,
    pub project_name: String,
    /// `project_full_path`, `group/subgroup/project`.
    pub project_path: String,
    pub namespace_id: u64,
    pub root_namespace_id: u64,
    pub user_id: u64,
    /// The GitLab runner the daemon took the job as (`CI_RUNNER_ID`).
    pub runner_id: u64,
}

/// What `get_sources` checks out. From GitLab's `git_info` and `allow_git_fetch`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sources {
    /// The project's clone URL, without credentials: the node adds the job token.
    pub repo_url: String,
    pub object_format: ObjectFormat,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub ref_type: RefType,
    pub sha: String,
    pub before_sha: String,
    #[serde(default)]
    pub refspecs: Vec<String>,
    /// Shallow-clone depth; 0 for the whole history.
    pub depth: u32,
    /// Whether the ref is protected: protected and unprotected jobs never share a cache.
    /// `None` when GitLab did not say, which counts as unprotected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected: Option<bool>,
    /// Whether GitLab allows `GIT_STRATEGY: fetch` for this job.
    pub allow_fetch: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectFormat {
    #[default]
    Sha1,
    Sha256,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefType {
    #[default]
    Branch,
    Tag,
}

/// A job's image or one of its services. The node resolves `name` under its own image rules,
/// as the executor does (`MICROVM_IMAGE` and its allowlists still apply).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Image {
    /// Empty for the job image when the job names none: the node's default applies.
    pub name: String,
    /// The names a service answers to on the job's network, split from GitLab's
    /// comma-or-space-separated `alias`.
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub entrypoint: Vec<String>,
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub ports: Vec<Port>,
    /// A service's own variables, on top of the job's.
    #[serde(default)]
    pub variables: Vec<Variable>,
    #[serde(default)]
    pub pull_policy: Vec<PullPolicy>,
    /// `executor_opts.docker.platform`, e.g. `linux/amd64`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// `executor_opts.docker.user` (or `.kubernetes.user`): the guest user steps run as.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Port {
    pub number: u16,
    /// `http` when GitLab gave none, as gitlab-runner defaults it.
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PullPolicy {
    Always,
    IfNotPresent,
    Never,
}

/// A CI variable. `raw` ones are exported as given; the rest are expanded by the shell the
/// way gitlab-runner's are.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Variable {
    pub key: String,
    pub value: String,
    pub public: bool,
    /// Written to a file whose path the variable holds instead.
    pub file: bool,
    /// Masked in the trace.
    pub masked: bool,
    pub raw: bool,
}

/// A boolean variable's value as gitlab-runner reads one, with Go's `strconv.ParseBool`.
pub fn parse_bool(raw: &str) -> Option<bool> {
    match raw {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// A user step. GitLab names them: `script`, `after_script`, `release` and others to come;
/// [`STEP_AFTER_SCRIPT`] runs after the others whatever their outcome, every other step in
/// order while the job is succeeding.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub name: String,
    pub script: Vec<String>,
    /// 0 for the job's own timeout.
    pub timeout_secs: u64,
    pub when: When,
    pub allow_failure: bool,
}

/// The step GitLab names `after_script`.
pub const STEP_AFTER_SCRIPT: &str = "after_script";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum When {
    #[default]
    OnSuccess,
    OnFailure,
    Always,
}

impl When {
    /// Whether something with this condition runs, given whether the job is succeeding.
    pub fn applies(self, succeeding: bool) -> bool {
        match self {
            When::OnSuccess => succeeding,
            When::OnFailure => !succeeding,
            When::Always => true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hook {
    pub name: HookName,
    pub script: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookName {
    PreGetSourcesScript,
    PostGetSourcesScript,
}

/// One `artifacts:` entry, uploaded by the node to GitLab with the job token.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactSpec {
    /// The archive's base name; `artifacts` when GitLab gave none.
    pub name: String,
    pub untracked: bool,
    pub paths: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    pub when: When,
    /// `archive`, `junit`, `dotenv` and the other report types, as GitLab names them.
    pub artifact_type: String,
    pub format: ArtifactFormat,
    /// GitLab's duration string, passed back as given; empty for the project default.
    #[serde(default)]
    pub expire_in: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFormat {
    /// Also GitLab's empty format.
    #[default]
    Zip,
    Gzip,
    Raw,
    #[serde(rename = "zipzstd")]
    ZipZstd,
    #[serde(rename = "tarzstd")]
    TarZstd,
}

/// One `cache:` entry, kept in the registry the node uses.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheSpec {
    /// Sanitized as gitlab-runner sanitizes it, defaulted to `<job name>/<ref>`; the node
    /// stores it apart per project and protection.
    pub key: String,
    #[serde(default)]
    pub fallback_keys: Vec<String>,
    pub untracked: bool,
    pub paths: Vec<String>,
    pub policy: CachePolicy,
    pub when: When,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CachePolicy {
    #[default]
    PullPush,
    Pull,
    Push,
}

/// A job whose artifacts this one downloads, with its own token.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    pub id: u64,
    pub token: String,
    pub name: String,
    /// `None` when the job left no artifacts archive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts_file: Option<DependencyFile>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyFile {
    pub filename: String,
    pub size: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryCredential {
    /// The registry host, as GitLab gives it.
    pub url: String,
    pub username: String,
    pub password: String,
}

/// How the node writes the job's output.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceOptions {
    /// Mark each stage with GitLab's collapsible section markers.
    pub sections: bool,
    /// Prefixes of tokens masked wherever they appear (`glpat-` and the like), from GitLab's
    /// `features.token_mask_prefixes`.
    #[serde(default)]
    pub mask_prefixes: Vec<String>,
    /// The most output the job keeps; past it, the node writes a notice and drops the rest,
    /// as gitlab-runner's `output_limit` does.
    pub limit_bytes: u64,
}

/// How a job ended, from the node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobResult {
    /// `None` on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<FailureClass>,
    /// The failing step's exit code, when a step's process ended with one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Why it failed, in words; the trace already says so to the job's readers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The output's final length: every byte before it was sent.
    pub output_len: u64,
    /// What became of each artifact upload, in the spec's order.
    #[serde(default)]
    pub artifacts: Vec<ArtifactOutcome>,
    /// What the job used on its node; absent from the hub's own results (`no_capacity`, `lost`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<JobUsage>,
}

/// Resource usage on the node, for the hub's history. Unavailable measurements are absent:
/// a job whose VM never booted has no CPU time or memory to report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobUsage {
    /// Wall-clock time from the job's driver starting it to its end, cleanup included.
    #[serde(default)]
    pub wall_ms: u64,
    /// User and system CPU time of the job's VM and its host helpers, including guest execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_ms: Option<u64>,
    /// Sum of host memory high-water marks for the job's VM and helpers, in bytes:
    /// an upper bound when the processes did not peak together.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_mem_bytes: Option<u64>,
    /// The guest's vCPUs, as the node sized it from the job's request and its ceilings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpus: Option<u32>,
    /// The guest's memory in MiB, sized the same way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_mib: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactOutcome {
    pub name: String,
    pub artifact_type: String,
    pub state: UploadState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UploadState {
    Uploaded,
    /// Its `when` did not apply, or its paths matched nothing.
    Skipped,
    /// GitLab answered 413.
    TooLarge,
    Failed,
    /// A state from a later peer.
    #[serde(other)]
    Other,
}

/// Why a job failed, as vk classes it. [`FailureClass::gitlab_reason`] maps it to GitLab's
/// `failure_reason`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    /// A step failed: the job's own doing.
    Script,
    /// The job ran past its timeout.
    Timeout,
    /// Canceled through GitLab or the hub.
    Canceled,
    /// The job's image or a service's could not be pulled or built.
    ImagePull,
    /// The job asks for something this fleet does not do, or the node's configuration
    /// refuses it.
    Configuration,
    /// GitLab, a registry or another dependency outside the node failed it: the clone,
    /// an artifact or cache transfer.
    ExternalDependency,
    /// The node failed it: the VM, the agent, the host.
    System,
    /// The node was stopped or drained hard while the job ran.
    Interrupted,
    /// No node took the job before its placement deadline. Set by the hub.
    NoCapacity,
    /// The node holding the job was lost, its outcome unknown. Set by the hub.
    Lost,
    /// A class from a later peer.
    #[serde(other)]
    Other,
}

/// GitLab's `failure_reason`s gitlab-runner knows. Every GitLab accepts the first three.
pub const GITLAB_SCRIPT_FAILURE: &str = "script_failure";
pub const GITLAB_RUNNER_SYSTEM_FAILURE: &str = "runner_system_failure";
pub const GITLAB_JOB_EXECUTION_TIMEOUT: &str = "job_execution_timeout";
pub const GITLAB_IMAGE_PULL_FAILURE: &str = "image_pull_failure";
pub const GITLAB_UNKNOWN_FAILURE: &str = "unknown_failure";
pub const GITLAB_RUNNER_CONFIGURATION_ERROR: &str = "runner_configuration_error";
pub const GITLAB_RUNNER_EXTERNAL_DEPENDENCY_FAILURE: &str = "runner_external_dependency_failure";
pub const GITLAB_RUNNER_INTERRUPTED: &str = "runner_interrupted";
/// gitlab-runner's own reason for a canceled job; GitLab knows none, and keeps the job's
/// canceled state whatever the runner reports.
pub const GITLAB_JOB_CANCELED: &str = "job_canceled";

const GITLAB_ALWAYS_SUPPORTED: [&str; 3] = [
    GITLAB_SCRIPT_FAILURE,
    GITLAB_RUNNER_SYSTEM_FAILURE,
    GITLAB_JOB_EXECUTION_TIMEOUT,
];

impl FailureClass {
    /// GitLab's name for this class, before [`gitlab_failure_reason`] fits it to what a
    /// given GitLab accepts.
    pub fn gitlab_reason(self) -> &'static str {
        match self {
            FailureClass::Script => GITLAB_SCRIPT_FAILURE,
            FailureClass::Timeout => GITLAB_JOB_EXECUTION_TIMEOUT,
            FailureClass::Canceled => GITLAB_JOB_CANCELED,
            FailureClass::ImagePull => GITLAB_IMAGE_PULL_FAILURE,
            FailureClass::Configuration => GITLAB_RUNNER_CONFIGURATION_ERROR,
            FailureClass::ExternalDependency => GITLAB_RUNNER_EXTERNAL_DEPENDENCY_FAILURE,
            FailureClass::System | FailureClass::NoCapacity | FailureClass::Lost => {
                GITLAB_RUNNER_SYSTEM_FAILURE
            }
            FailureClass::Interrupted => GITLAB_RUNNER_INTERRUPTED,
            FailureClass::Other => GITLAB_UNKNOWN_FAILURE,
        }
    }
}

/// The older reason to use when GitLab does not know a newer one, as gitlab-runner maps it.
fn gitlab_older_reason(reason: &str) -> Option<&'static str> {
    match reason {
        GITLAB_IMAGE_PULL_FAILURE | GITLAB_RUNNER_EXTERNAL_DEPENDENCY_FAILURE => {
            Some(GITLAB_RUNNER_SYSTEM_FAILURE)
        }
        GITLAB_RUNNER_CONFIGURATION_ERROR => Some(GITLAB_SCRIPT_FAILURE),
        _ => None,
    }
}

/// The `failure_reason` to report for `class` to a GitLab that accepts `supported` — its
/// job's `features.failure_reasons` — besides the three every GitLab accepts: the class's
/// own reason, else the older one it was split from, else `unknown_failure`.
pub fn gitlab_failure_reason(class: FailureClass, supported: &[String]) -> &'static str {
    let accepted =
        |r: &str| GITLAB_ALWAYS_SUPPORTED.contains(&r) || supported.iter().any(|s| s == r);
    let mut reason = class.gitlab_reason();
    loop {
        if accepted(reason) {
            return reason;
        }
        match gitlab_older_reason(reason) {
            Some(older) => reason = older,
            None => return GITLAB_UNKNOWN_FAILURE,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::json;

    use super::*;

    /// A job using every field, as `vk-gitlab` would translate a busy GitLab job.
    pub(crate) fn ci_job() -> CiJob {
        let var = |key: &str, value: &str| Variable {
            key: key.into(),
            value: value.into(),
            public: true,
            ..Variable::default()
        };
        CiJob {
            server_url: "https://gitlab.example.com".into(),
            server_ca_pem: None,
            job: CiJobInfo {
                id: 4242,
                name: "test:unit".into(),
                stage: "test".into(),
                pipeline_id: 77,
                project_id: 12,
                project_name: "web".into(),
                project_path: "acme/web".into(),
                namespace_id: 3,
                root_namespace_id: 1,
                user_id: 9,
                runner_id: 5,
            },
            token: "glcbt-64_secret".into(),
            timeout_secs: 3600,
            sources: Sources {
                repo_url: "https://gitlab.example.com/acme/web.git".into(),
                object_format: ObjectFormat::Sha1,
                git_ref: "main".into(),
                ref_type: RefType::Branch,
                sha: "ab".repeat(20),
                before_sha: "cd".repeat(20),
                refspecs: vec!["+refs/heads/main:refs/remotes/origin/main".into()],
                depth: 20,
                protected: Some(true),
                allow_fetch: true,
            },
            image: Image {
                name: "rust:1.90".into(),
                user: Some("1000".into()),
                ..Image::default()
            },
            services: vec![Image {
                name: "postgres:17".into(),
                aliases: vec!["db".into(), "postgres".into()],
                ports: vec![Port {
                    number: 5432,
                    protocol: "tcp".into(),
                    name: None,
                }],
                variables: vec![Variable {
                    public: false,
                    ..var("POSTGRES_PASSWORD", "pw")
                }],
                pull_policy: vec![PullPolicy::IfNotPresent],
                ..Image::default()
            }],
            variables: vec![
                var("CI_JOB_ID", "4242"),
                Variable {
                    key: "DEPLOY_KEY".into(),
                    value: "s3cret".into(),
                    file: true,
                    masked: true,
                    ..Variable::default()
                },
            ],
            steps: vec![
                Step {
                    name: "script".into(),
                    script: vec!["cargo test".into()],
                    timeout_secs: 3600,
                    when: When::OnSuccess,
                    allow_failure: false,
                },
                Step {
                    name: STEP_AFTER_SCRIPT.into(),
                    script: vec!["echo done".into()],
                    timeout_secs: 300,
                    when: When::Always,
                    allow_failure: true,
                },
            ],
            hooks: vec![Hook {
                name: HookName::PreGetSourcesScript,
                script: vec!["git config --global http.version HTTP/1.1".into()],
            }],
            artifacts: vec![ArtifactSpec {
                name: "artifacts".into(),
                untracked: false,
                paths: vec!["target/report".into()],
                exclude: vec!["target/report/tmp/**".into()],
                when: When::OnSuccess,
                artifact_type: "archive".into(),
                format: ArtifactFormat::Zip,
                expire_in: "7d".into(),
            }],
            caches: vec![CacheSpec {
                key: "test:unit/main".into(),
                fallback_keys: vec!["main".into()],
                untracked: false,
                paths: vec!["target/".into()],
                policy: CachePolicy::PullPush,
                when: When::OnSuccess,
            }],
            dependencies: vec![Dependency {
                id: 4241,
                token: "glcbt-64_dep".into(),
                name: "build".into(),
                artifacts_file: Some(DependencyFile {
                    filename: "artifacts.zip".into(),
                    size: 1024,
                }),
            }],
            registry_credentials: vec![RegistryCredential {
                url: "registry.example.com".into(),
                username: "gitlab-ci-token".into(),
                password: "glcbt-64_secret".into(),
            }],
            trace: TraceOptions {
                sections: true,
                mask_prefixes: vec!["glpat-".into()],
                limit_bytes: 4 << 20,
            },
        }
    }

    #[test]
    fn a_ci_job_round_trips() {
        let spec = JobSpec::GitlabCi(ci_job());
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.len() < MAX_JOB_SPEC);
        assert_eq!(serde_json::from_str::<JobSpec>(&json).unwrap(), spec);
    }

    #[test]
    fn a_ci_job_keeps_its_wire_shape() {
        let value = serde_json::to_value(JobSpec::GitlabCi(ci_job())).unwrap();
        assert_eq!(value["kind"], "gitlab_ci");
        assert_eq!(value["sources"]["ref"], "main");
        assert_eq!(value["sources"]["object_format"], "sha1");
        assert_eq!(value["sources"]["ref_type"], "branch");
        assert_eq!(
            value["services"][0]["pull_policy"],
            json!(["if-not-present"])
        );
        assert_eq!(value["steps"][1]["when"], "always");
        assert_eq!(value["hooks"][0]["name"], "pre_get_sources_script");
        assert_eq!(value["artifacts"][0]["format"], "zip");
        assert_eq!(value["caches"][0]["policy"], "pull-push");
        assert!(value["image"].get("platform").is_none());
        let formats = [
            (ArtifactFormat::Zip, "zip"),
            (ArtifactFormat::Gzip, "gzip"),
            (ArtifactFormat::Raw, "raw"),
            (ArtifactFormat::ZipZstd, "zipzstd"),
            (ArtifactFormat::TarZstd, "tarzstd"),
        ];
        for (format, name) in formats {
            assert_eq!(serde_json::to_value(format).unwrap(), json!(name));
        }
    }

    #[test]
    fn a_ci_job_reads_without_its_optional_lists() {
        let mut value = serde_json::to_value(JobSpec::GitlabCi(ci_job())).unwrap();
        let object = value.as_object_mut().unwrap();
        for key in [
            "server_ca_pem",
            "services",
            "variables",
            "hooks",
            "artifacts",
            "caches",
            "dependencies",
            "registry_credentials",
        ] {
            object.remove(key);
        }
        object["sources"]
            .as_object_mut()
            .unwrap()
            .remove("protected");
        let JobSpec::GitlabCi(job) = serde_json::from_value(value).unwrap();
        assert!(job.services.is_empty() && job.caches.is_empty());
        assert_eq!(job.sources.protected, None);
    }

    #[test]
    fn redaction_hides_every_secret() {
        let job = ci_job();
        let shown = serde_json::to_string(&job.redacted()).unwrap();
        for secret in ["glcbt-64_secret", "glcbt-64_dep", "s3cret", "\"pw\""] {
            assert!(!shown.contains(secret), "{secret} in {shown}");
        }
        assert!(shown.contains("rust:1.90") && shown.contains("\"4242\""));
    }

    #[test]
    fn when_applies_as_gitlab_runner_decides() {
        assert!(When::OnSuccess.applies(true) && !When::OnSuccess.applies(false));
        assert!(!When::OnFailure.applies(true) && When::OnFailure.applies(false));
        assert!(When::Always.applies(true) && When::Always.applies(false));
    }

    #[test]
    fn an_envelope_fits_only_on_every_resource() {
        let big = Envelope {
            mem_mib: 8192,
            cpus: 4,
            disk_bytes: 1 << 33,
        };
        assert!(big.fits_in(big));
        assert!(Envelope::default().fits_in(big));
        let more_cpus = Envelope { cpus: 5, ..big };
        assert!(!more_cpus.fits_in(big));
    }

    /// Mapped as gitlab-runner's `common/failure_reason_mapper.go` maps them.
    #[test]
    fn failure_reasons_fall_back_as_gitlab_runner_maps_them() {
        let all: Vec<String> = [
            GITLAB_IMAGE_PULL_FAILURE,
            GITLAB_RUNNER_CONFIGURATION_ERROR,
            GITLAB_RUNNER_EXTERNAL_DEPENDENCY_FAILURE,
            GITLAB_RUNNER_INTERRUPTED,
            GITLAB_UNKNOWN_FAILURE,
        ]
        .map(String::from)
        .to_vec();
        let cases = [
            (FailureClass::Script, "script_failure", "script_failure"),
            (
                FailureClass::Timeout,
                "job_execution_timeout",
                "job_execution_timeout",
            ),
            (
                FailureClass::System,
                "runner_system_failure",
                "runner_system_failure",
            ),
            (
                FailureClass::Lost,
                "runner_system_failure",
                "runner_system_failure",
            ),
            (
                FailureClass::NoCapacity,
                "runner_system_failure",
                "runner_system_failure",
            ),
            (
                FailureClass::ImagePull,
                "image_pull_failure",
                "runner_system_failure",
            ),
            (
                FailureClass::Configuration,
                "runner_configuration_error",
                "script_failure",
            ),
            (
                FailureClass::ExternalDependency,
                "runner_external_dependency_failure",
                "runner_system_failure",
            ),
            (
                FailureClass::Interrupted,
                "runner_interrupted",
                "unknown_failure",
            ),
            (FailureClass::Canceled, "unknown_failure", "unknown_failure"),
            (FailureClass::Other, "unknown_failure", "unknown_failure"),
        ];
        for (class, new_gitlab, old_gitlab) in cases {
            assert_eq!(gitlab_failure_reason(class, &all), new_gitlab, "{class:?}");
            assert_eq!(gitlab_failure_reason(class, &[]), old_gitlab, "{class:?}");
        }
    }

    #[test]
    fn a_failure_class_from_a_later_peer_reads_as_other() {
        let class: FailureClass = serde_json::from_value(json!("cosmic_ray")).unwrap();
        assert_eq!(class, FailureClass::Other);
    }

    #[test]
    fn an_upload_state_from_a_later_peer_reads_as_other() {
        let state: UploadState = serde_json::from_value(json!("quarantined")).unwrap();
        assert_eq!(state, UploadState::Other);
    }

    /// Older results decode without usage; measured usage round-trips. Unavailable figures
    /// are omitted rather than sent as zero.
    #[test]
    fn a_result_reads_with_or_without_usage() {
        let old: JobResult = serde_json::from_value(json!({"output_len": 7})).unwrap();
        assert_eq!(old.usage, None);
        assert!(!serde_json::to_string(&old).unwrap().contains("usage"));
        let measured = JobResult {
            usage: Some(JobUsage {
                wall_ms: 61_000,
                cpu_ms: Some(120_500),
                peak_mem_bytes: Some(3 << 30),
                cpus: Some(4),
                mem_mib: Some(8192),
            }),
            ..old.clone()
        };
        let wire = serde_json::to_value(&measured).unwrap();
        assert_eq!(
            wire["usage"],
            json!({"wall_ms": 61_000, "cpu_ms": 120_500, "peak_mem_bytes": 3u64 << 30,
                   "cpus": 4, "mem_mib": 8192})
        );
        assert_eq!(serde_json::from_value::<JobResult>(wire).unwrap(), measured);
        let unbooted = JobResult {
            usage: Some(JobUsage {
                wall_ms: 900,
                ..JobUsage::default()
            }),
            ..old
        };
        assert_eq!(
            serde_json::to_value(&unbooted).unwrap()["usage"],
            json!({"wall_ms": 900})
        );
        // Unknown measurements from newer nodes are ignored.
        let later: JobUsage = serde_json::from_value(json!({"wall_ms": 1, "gpu_ms": 5})).unwrap();
        assert_eq!(later.wall_ms, 1);
    }
}
