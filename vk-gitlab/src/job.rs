//! The job payload GitLab returns from `POST /api/v4/jobs/request`. Port of gitlab-runner's
//! `common/spec/spec.go` (`spec.Job` and the types under it), field for field.
//!
//! Decoding is as lenient as Go's `encoding/json`: unknown fields are ignored (and kept in
//! [`Job::extra`] at the top level, so a payload forwards to the hub without loss), a missing
//! field takes its zero value, and so does an explicit `null` — which serde would otherwise
//! reject for a string, number or list.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::failure::FailureReason;
use crate::secret::Secret;

/// `null` decodes to the type's zero value, as in Go.
fn nd<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

fn secret_nd<'de, D: Deserializer<'de>>(d: D) -> Result<Secret, D::Error> {
    Ok(Secret::new(
        Option::<String>::deserialize(d)?.unwrap_or_default(),
    ))
}

fn secret_ser<S: serde::Serializer>(s: &Secret, ser: S) -> Result<S::Ok, S::Error> {
    ser.serialize_str(s.expose())
}

/// A string GitLab may send as a JSON number (`executor_opts.*.user`). Port of
/// `spec.StringOrInt64`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(transparent)]
pub struct StringOrInt64(pub String);

impl<'de> Deserialize<'de> for StringOrInt64 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match Value::deserialize(d)? {
            Value::Null => Ok(Self::default()),
            Value::String(s) => Ok(Self(s)),
            Value::Number(n) if n.is_i64() => Ok(Self(n.to_string())),
            _ => Err(serde::de::Error::custom(
                "StringOrInt: input not string or integer",
            )),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct JobInfo {
    #[serde(deserialize_with = "nd")]
    pub name: String,
    #[serde(deserialize_with = "nd")]
    pub stage: String,
    #[serde(deserialize_with = "nd")]
    pub pipeline_id: i64,
    #[serde(deserialize_with = "nd")]
    pub project_id: i64,
    #[serde(deserialize_with = "nd")]
    pub project_name: String,
    #[serde(deserialize_with = "nd")]
    pub project_full_path: String,
    #[serde(deserialize_with = "nd")]
    pub namespace_id: i64,
    #[serde(deserialize_with = "nd")]
    pub root_namespace_id: i64,
    #[serde(deserialize_with = "nd")]
    pub organization_id: i64,
    #[serde(deserialize_with = "nd")]
    pub instance_id: String,
    #[serde(deserialize_with = "nd")]
    pub instance_uuid: String,
    #[serde(deserialize_with = "nd")]
    pub user_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scoped_user_id: Option<i64>,
    #[serde(deserialize_with = "nd")]
    pub time_in_queue_seconds: f64,
    #[serde(deserialize_with = "nd")]
    pub project_jobs_running_on_instance_runners_count: String,
    #[serde(deserialize_with = "nd")]
    pub queue_size: i64,
    #[serde(deserialize_with = "nd")]
    pub queue_depth: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GitInfo {
    #[serde(deserialize_with = "nd")]
    pub repo_url: String,
    #[serde(deserialize_with = "nd")]
    pub repo_object_format: String,
    #[serde(rename = "ref", deserialize_with = "nd")]
    pub git_ref: String,
    #[serde(deserialize_with = "nd")]
    pub sha: String,
    #[serde(deserialize_with = "nd")]
    pub before_sha: String,
    /// `branch` or `tag`.
    #[serde(deserialize_with = "nd")]
    pub ref_type: String,
    #[serde(deserialize_with = "nd")]
    pub refspecs: Vec<String>,
    #[serde(deserialize_with = "nd")]
    pub depth: i64,
    pub protected: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RunnerInfo {
    #[serde(deserialize_with = "nd")]
    pub uuid: String,
    /// The job timeout, in seconds.
    #[serde(deserialize_with = "nd")]
    pub timeout: i64,
}

/// A CI/CD variable. `Debug` leaves the value out: masked or not, a variable can hold a
/// credential.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Variable {
    #[serde(deserialize_with = "nd")]
    pub key: String,
    #[serde(deserialize_with = "nd")]
    pub value: String,
    #[serde(deserialize_with = "nd")]
    pub public: bool,
    #[serde(deserialize_with = "nd")]
    pub file: bool,
    #[serde(deserialize_with = "nd")]
    pub masked: bool,
    #[serde(deserialize_with = "nd")]
    pub raw: bool,
}

impl fmt::Debug for Variable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Variable")
            .field("key", &self.key)
            .field("public", &self.public)
            .field("file", &self.file)
            .field("masked", &self.masked)
            .field("raw", &self.raw)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Step {
    /// `script`, `after_script`, `run`, or a release step's name.
    #[serde(deserialize_with = "nd")]
    pub name: String,
    #[serde(deserialize_with = "nd")]
    pub script: Vec<String>,
    #[serde(deserialize_with = "nd")]
    pub timeout: i64,
    /// `on_success` (the default when empty), `on_failure` or `always`.
    #[serde(deserialize_with = "nd")]
    pub when: String,
    #[serde(deserialize_with = "nd")]
    pub allow_failure: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Port {
    #[serde(deserialize_with = "nd")]
    pub number: i64,
    #[serde(deserialize_with = "nd")]
    pub protocol: String,
    #[serde(deserialize_with = "nd")]
    pub name: String,
}

/// `image.executor_opts.docker`. Keys other than the supported ones land in `unsupported`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerOptions {
    #[serde(deserialize_with = "nd")]
    pub platform: String,
    pub user: StringOrInt64,
    #[serde(flatten)]
    pub unsupported: Map<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct KubernetesOptions {
    pub user: StringOrInt64,
    #[serde(flatten)]
    pub unsupported: Map<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ImageExecutorOptions {
    #[serde(deserialize_with = "nd")]
    pub docker: DockerOptions,
    #[serde(deserialize_with = "nd")]
    pub kubernetes: KubernetesOptions,
    #[serde(flatten)]
    pub unsupported: Map<String, Value>,
}

impl ImageExecutorOptions {
    /// The unsupported keys, worded as gitlab-runner's `UnsuportedExecutorOptionsError`.
    fn unsupported(&self, out: &mut Vec<String>) {
        fn push(out: &mut Vec<String>, keys: &Map<String, Value>, executor: &str, supported: &str) {
            if keys.is_empty() {
                return;
            }
            let names: Vec<&str> = keys.keys().map(String::as_str).collect();
            out.push(format!(
                "Unsupported \"image\" options [{}] for \"{executor}\"; supported options are [{supported}]",
                names.join(" ")
            ));
        }
        push(out, &self.unsupported, "executor_opts", "docker kubernetes");
        push(
            out,
            &self.docker.unsupported,
            "docker executor",
            "platform user",
        );
        push(
            out,
            &self.kubernetes.unsupported,
            "kubernetes executor",
            "user",
        );
    }
}

/// `image`, and each entry of `services`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Image {
    #[serde(deserialize_with = "nd")]
    pub name: String,
    #[serde(deserialize_with = "nd", skip_serializing_if = "String::is_empty")]
    pub alias: String,
    #[serde(deserialize_with = "nd", skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    #[serde(deserialize_with = "nd", skip_serializing_if = "Vec::is_empty")]
    pub entrypoint: Vec<String>,
    #[serde(deserialize_with = "nd", skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<Port>,
    #[serde(deserialize_with = "nd", skip_serializing_if = "Vec::is_empty")]
    pub variables: Vec<Variable>,
    #[serde(
        rename = "pull_policy",
        deserialize_with = "nd",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub pull_policies: Vec<String>,
    #[serde(rename = "executor_opts", deserialize_with = "nd")]
    pub executor_options: ImageExecutorOptions,
}

impl Image {
    /// The service aliases: `alias` split on commas and whitespace.
    pub fn aliases(&self) -> Vec<&str> {
        self.alias
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|s| !s.is_empty())
            .collect()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Artifact {
    #[serde(deserialize_with = "nd")]
    pub name: String,
    #[serde(deserialize_with = "nd")]
    pub untracked: bool,
    #[serde(deserialize_with = "nd")]
    pub paths: Vec<String>,
    #[serde(deserialize_with = "nd")]
    pub exclude: Vec<String>,
    #[serde(deserialize_with = "nd")]
    pub when: String,
    #[serde(rename = "artifact_type", deserialize_with = "nd")]
    pub artifact_type: String,
    /// `zip`, `gzip`, `raw`, `zipzstd` or `tarzstd`; empty for the default.
    #[serde(rename = "artifact_format", deserialize_with = "nd")]
    pub artifact_format: String,
    #[serde(deserialize_with = "nd")]
    pub expire_in: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Cache {
    #[serde(deserialize_with = "nd")]
    pub key: String,
    #[serde(deserialize_with = "nd")]
    pub untracked: bool,
    /// `pull-push` (the default when empty), `pull` or `push`.
    #[serde(deserialize_with = "nd")]
    pub policy: String,
    #[serde(deserialize_with = "nd")]
    pub paths: Vec<String>,
    #[serde(deserialize_with = "nd")]
    pub when: String,
    #[serde(deserialize_with = "nd")]
    pub fallback_keys: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Credentials {
    #[serde(rename = "type", deserialize_with = "nd")]
    pub kind: String,
    #[serde(deserialize_with = "nd")]
    pub url: String,
    #[serde(deserialize_with = "nd")]
    pub username: String,
    #[serde(deserialize_with = "secret_nd", serialize_with = "secret_ser")]
    pub password: Secret,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DependencyArtifactsFile {
    #[serde(deserialize_with = "nd")]
    pub filename: String,
    #[serde(deserialize_with = "nd")]
    pub size: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Dependency {
    #[serde(deserialize_with = "nd")]
    pub id: i64,
    #[serde(deserialize_with = "secret_nd", serialize_with = "secret_ser")]
    pub token: Secret,
    #[serde(deserialize_with = "nd")]
    pub name: String,
    #[serde(deserialize_with = "nd")]
    pub artifacts_file: DependencyArtifactsFile,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpBearerGcpOidcAuth {
    #[serde(deserialize_with = "nd")]
    pub audience: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct OtelEndpointAuth {
    #[serde(rename = "type", deserialize_with = "nd")]
    pub kind: String,
    pub http_bearer_gcp_oidc: Option<HttpBearerGcpOidcAuth>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct OtelEndpoint {
    #[serde(deserialize_with = "nd")]
    pub url: String,
    pub auth: Option<OtelEndpointAuth>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Tracing {
    #[serde(deserialize_with = "nd")]
    pub trace_id: String,
    #[serde(deserialize_with = "nd")]
    pub span_parent_id: String,
    #[serde(deserialize_with = "nd")]
    pub otel_endpoints: Vec<OtelEndpoint>,
}

/// `features`: what GitLab tells the runner about itself for this job.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GitlabFeatures {
    #[serde(deserialize_with = "nd")]
    pub trace_sections: bool,
    /// Extra token prefixes to mask in the job log, on top of the default ones.
    #[serde(deserialize_with = "nd")]
    pub token_mask_prefixes: Vec<String>,
    /// The failure reasons this GitLab accepts in a job update.
    #[serde(deserialize_with = "nd")]
    pub failure_reasons: Vec<FailureReason>,
    pub tracing: Option<Tracing>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Hook {
    /// `pre_get_sources_script` or `post_get_sources_script`.
    #[serde(deserialize_with = "nd")]
    pub name: String,
    #[serde(deserialize_with = "nd")]
    pub script: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyOptions {
    #[serde(rename = "execution_policy_job", deserialize_with = "nd")]
    pub policy_job: bool,
    #[serde(rename = "policy_name", deserialize_with = "nd")]
    pub name: String,
    #[serde(
        rename = "policy_variables_override_allowed",
        skip_serializing_if = "Option::is_none"
    )]
    pub variable_override_allowed: Option<bool>,
    #[serde(
        rename = "policy_variables_override_exceptions",
        deserialize_with = "nd",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub variable_override_exceptions: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SuspendOptions {
    #[serde(deserialize_with = "nd", skip_serializing_if = "is_false")]
    pub suspend_on_success: bool,
    #[serde(deserialize_with = "nd", skip_serializing_if = "is_false")]
    pub suspend_on_failure: bool,
    #[serde(deserialize_with = "nd", skip_serializing_if = "String::is_empty")]
    pub runtime_environment_key: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// One entry of `secrets`: where to fetch the value from.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct JobSecret {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault: Option<VaultSecret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gcp_secret_manager: Option<GcpSecretManagerSecret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azure_key_vault: Option<AzureKeyVaultSecret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws_secrets_manager: Option<AwsSecret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gitlab_secrets_manager: Option<GitLabSecretsManagerSecret>,
    /// Expose the value as a file variable; `None` means yes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VaultSecret {
    #[serde(deserialize_with = "nd")]
    pub server: VaultServer,
    #[serde(deserialize_with = "nd")]
    pub engine: NamePath,
    #[serde(deserialize_with = "nd")]
    pub path: String,
    #[serde(deserialize_with = "nd")]
    pub field: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VaultServer {
    #[serde(deserialize_with = "nd")]
    pub url: String,
    #[serde(deserialize_with = "nd")]
    pub auth: VaultAuth,
    #[serde(deserialize_with = "nd")]
    pub namespace: String,
}

/// `Debug` lists only the keys of `data`, which holds the auth method's credentials (a JWT).
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VaultAuth {
    #[serde(deserialize_with = "nd")]
    pub name: String,
    #[serde(deserialize_with = "nd")]
    pub path: String,
    #[serde(deserialize_with = "nd")]
    pub data: Map<String, Value>,
}

impl std::fmt::Debug for VaultAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultAuth")
            .field("name", &self.name)
            .field("path", &self.path)
            .field("data", &self.data.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// A secret engine (`engine`): its name and mount path.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NamePath {
    #[serde(deserialize_with = "nd")]
    pub name: String,
    #[serde(deserialize_with = "nd")]
    pub path: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GcpSecretManagerSecret {
    #[serde(deserialize_with = "nd")]
    pub name: String,
    #[serde(deserialize_with = "nd")]
    pub version: String,
    #[serde(deserialize_with = "nd")]
    pub server: GcpSecretManagerServer,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GcpSecretManagerServer {
    #[serde(deserialize_with = "nd")]
    pub project_number: String,
    #[serde(deserialize_with = "nd")]
    pub workload_identity_federation_pool_id: String,
    #[serde(deserialize_with = "nd")]
    pub workload_identity_federation_provider_id: String,
    #[serde(deserialize_with = "secret_nd", serialize_with = "secret_ser")]
    pub jwt: Secret,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AzureKeyVaultSecret {
    #[serde(deserialize_with = "nd")]
    pub name: String,
    #[serde(deserialize_with = "nd", skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(deserialize_with = "nd")]
    pub server: AzureKeyVaultServer,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AzureKeyVaultServer {
    #[serde(deserialize_with = "nd")]
    pub client_id: String,
    #[serde(deserialize_with = "nd")]
    pub tenant_id: String,
    #[serde(deserialize_with = "secret_nd", serialize_with = "secret_ser")]
    pub jwt: Secret,
    #[serde(deserialize_with = "nd")]
    pub url: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AwsSecret {
    #[serde(deserialize_with = "nd")]
    pub secret_id: String,
    #[serde(deserialize_with = "nd", skip_serializing_if = "String::is_empty")]
    pub version_id: String,
    #[serde(deserialize_with = "nd", skip_serializing_if = "String::is_empty")]
    pub version_stage: String,
    #[serde(deserialize_with = "nd", skip_serializing_if = "String::is_empty")]
    pub field: String,
    #[serde(deserialize_with = "nd", skip_serializing_if = "String::is_empty")]
    pub region: String,
    #[serde(deserialize_with = "nd", skip_serializing_if = "String::is_empty")]
    pub role_arn: String,
    #[serde(deserialize_with = "nd", skip_serializing_if = "String::is_empty")]
    pub role_session_name: String,
    #[serde(deserialize_with = "nd")]
    pub server: AwsServer,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AwsServer {
    #[serde(deserialize_with = "nd")]
    pub region: String,
    #[serde(
        deserialize_with = "secret_nd",
        serialize_with = "secret_ser",
        skip_serializing_if = "Secret::is_empty"
    )]
    pub jwt: Secret,
    #[serde(deserialize_with = "nd", skip_serializing_if = "String::is_empty")]
    pub role_arn: String,
    #[serde(deserialize_with = "nd", skip_serializing_if = "String::is_empty")]
    pub role_session_name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GitLabSecretsManagerSecret {
    #[serde(deserialize_with = "nd")]
    pub server: GitLabSecretsManagerServer,
    #[serde(deserialize_with = "nd")]
    pub engine: NamePath,
    #[serde(deserialize_with = "nd")]
    pub path: String,
    #[serde(deserialize_with = "nd")]
    pub field: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GitLabSecretsManagerServer {
    #[serde(deserialize_with = "nd")]
    pub url: String,
    #[serde(deserialize_with = "nd")]
    pub inline_auth: GitLabSecretsManagerInlineAuth,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GitLabSecretsManagerInlineAuth {
    #[serde(deserialize_with = "nd")]
    pub path: String,
    #[serde(deserialize_with = "secret_nd", serialize_with = "secret_ser")]
    pub jwt: Secret,
    #[serde(deserialize_with = "nd")]
    pub role: String,
    #[serde(deserialize_with = "nd")]
    pub auth_mount: String,
}

/// One entry of `inputs`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct JobInput {
    #[serde(deserialize_with = "nd")]
    pub key: String,
    #[serde(deserialize_with = "nd")]
    pub value: JobInputValue,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct JobInputValue {
    /// `string`, `number`, `boolean`, `array` or `struct`.
    #[serde(rename = "type", deserialize_with = "nd")]
    pub kind: String,
    pub content: Value,
    #[serde(deserialize_with = "nd")]
    pub sensitive: bool,
}

/// A job, as `POST /api/v4/jobs/request` returns it. `Debug` prints only what identifies
/// the job: the payload carries the job token (in `repo_url` too), credentials and secrets.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Job {
    #[serde(deserialize_with = "nd")]
    pub id: i64,
    #[serde(deserialize_with = "secret_nd", serialize_with = "secret_ser")]
    pub token: Secret,
    #[serde(deserialize_with = "nd")]
    pub allow_git_fetch: bool,
    #[serde(deserialize_with = "nd")]
    pub job_info: JobInfo,
    #[serde(deserialize_with = "nd")]
    pub git_info: GitInfo,
    #[serde(deserialize_with = "nd")]
    pub runner_info: RunnerInfo,
    #[serde(deserialize_with = "nd")]
    pub inputs: Vec<JobInput>,
    #[serde(deserialize_with = "nd")]
    pub variables: Vec<Variable>,
    #[serde(deserialize_with = "nd")]
    pub steps: Vec<Step>,
    #[serde(deserialize_with = "nd")]
    pub image: Image,
    #[serde(deserialize_with = "nd")]
    pub services: Vec<Image>,
    #[serde(deserialize_with = "nd")]
    pub artifacts: Vec<Artifact>,
    #[serde(deserialize_with = "nd")]
    pub cache: Vec<Cache>,
    #[serde(deserialize_with = "nd")]
    pub credentials: Vec<Credentials>,
    #[serde(deserialize_with = "nd")]
    pub dependencies: Vec<Dependency>,
    #[serde(deserialize_with = "nd")]
    pub features: GitlabFeatures,
    #[serde(deserialize_with = "nd", skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, JobSecret>,
    #[serde(deserialize_with = "nd", skip_serializing_if = "Vec::is_empty")]
    pub hooks: Vec<Hook>,
    /// The `run:` keyword's steps, as GitLab sends them: a JSON document in a string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    #[serde(deserialize_with = "nd")]
    pub policy_options: PolicyOptions,
    #[serde(deserialize_with = "nd")]
    pub suspend_options: SuspendOptions,
    /// Fields this version does not model, kept so the payload forwards whole.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl fmt::Debug for Job {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Job")
            .field("id", &self.id)
            .field("name", &self.job_info.name)
            .field("project", &self.job_info.project_full_path)
            .field("repo", &self.repo_clean_url())
            .finish_non_exhaustive()
    }
}

/// gitlab-runner's `Variables.Bool`: `strconv.ParseBool` on the lowercased value, else an
/// integer equal to 1.
fn variable_bool(value: &str) -> bool {
    match value.to_ascii_lowercase().as_str() {
        "1" | "t" | "true" => true,
        "0" | "f" | "false" => false,
        other => other.parse::<i32>() == Ok(1),
    }
}

/// `FF_TIMESTAMPS` among `vars`: the last one, expanded against them unless raw, as the node
/// reads it (variables only the node sets expand to nothing here); on when absent. A file
/// variable expands to a path on the node, never a bool, so to a placeholder path here.
pub fn timestamps(vars: &[Variable]) -> bool {
    let flag = vars
        .iter()
        .rev()
        .find(|v| v.key == vk_hub_proto::stamp::FLAG)
        .map(|v| match v.raw {
            true => v.value.clone(),
            false => {
                let paths: Vec<Variable> = vars
                    .iter()
                    .map(|w| match w.file {
                        true => Variable {
                            value: format!("/{}", w.key),
                            ..w.clone()
                        },
                        false => w.clone(),
                    })
                    .collect();
                crate::spec::expand(&v.value, &paths)
            }
        });
    vk_hub_proto::stamp::enabled(flag.as_deref()).0
}

impl Job {
    /// The value of the last variable named `key`, as gitlab-runner resolves duplicates.
    pub fn variable(&self, key: &str) -> Option<&str> {
        self.variables
            .iter()
            .rev()
            .find(|v| v.key == key)
            .map(|v| v.value.as_str())
    }

    /// `CI_DEBUG_TRACE` or `CI_DEBUG_SERVICES`: sent as `debug_trace` on trace patches.
    pub fn debug_mode_enabled(&self) -> bool {
        ["CI_DEBUG_TRACE", "CI_DEBUG_SERVICES"]
            .iter()
            .any(|k| self.variable(k).is_some_and(variable_bool))
    }

    /// `FF_TIMESTAMPS`: whether the job's log lines are stamped. The node warns about invalid
    /// values if the job reaches it.
    pub fn timestamps(&self) -> bool {
        timestamps(&self.variables)
    }

    /// The repository URL without credentials, query or fragment (gitlab-runner's
    /// `RepoCleanURL`), for logs.
    pub fn repo_clean_url(&self) -> String {
        clean_url(&self.git_info.repo_url)
    }

    /// Image and service `executor_opts` keys this runner does not support, one message per
    /// offending map; `None` when all are supported.
    pub fn unsupported_options(&self) -> Option<String> {
        let mut msgs = Vec::new();
        self.image.executor_options.unsupported(&mut msgs);
        for service in &self.services {
            service.executor_options.unsupported(&mut msgs);
        }
        (!msgs.is_empty()).then(|| msgs.join("\n"))
    }
}

/// gitlab-runner's `url_helpers.CleanURL`: drop userinfo, query and fragment. A value that
/// does not parse yields an empty string, as upstream.
pub fn clean_url(value: &str) -> String {
    let Ok(mut url) = reqwest::Url::parse(value) else {
        return String::new();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from gitlab-runner v19.5.0 common/network_test.go,
    // Test_Image_ExecutorOptions_UnmarshalJSON (MIT, Copyright (c) 2015-2019 GitLab Inc.).
    #[test]
    fn image_executor_options() {
        struct Case {
            json: &'static str,
            platform: &'static str,
            docker_user: &'static str,
            k8s_user: &'static str,
            errors: &'static [&'static str],
        }
        let cases = [
            Case {
                json: r#"{"executor_opts":{}}"#,
                platform: "",
                docker_user: "",
                k8s_user: "",
                errors: &[],
            },
            Case {
                json: r#"{"executor_opts":{"docker": {}}}"#,
                platform: "",
                docker_user: "",
                k8s_user: "",
                errors: &[],
            },
            Case {
                json: r#"{"executor_opts":{"docker": {"user": "ubuntu"}}}"#,
                platform: "",
                docker_user: "ubuntu",
                k8s_user: "",
                errors: &[],
            },
            Case {
                json: r#"{"executor_opts":{"docker": {"platform": "amd64"}}}"#,
                platform: "amd64",
                docker_user: "",
                k8s_user: "",
                errors: &[],
            },
            Case {
                json: r#"{"executor_opts":{"docker": {"platform": "arm64", "user": "ubuntu"}}}"#,
                platform: "arm64",
                docker_user: "ubuntu",
                k8s_user: "",
                errors: &[],
            },
            Case {
                json: r#"{"executor_opts":{"docker": {"foobar": 1234}}}"#,
                platform: "",
                docker_user: "",
                k8s_user: "",
                errors: &[
                    r#"Unsupported "image" options [foobar] for "docker executor"; supported options are [platform user]"#,
                ],
            },
            Case {
                json: r#"{"executor_opts":{"kubernetes": {}}}"#,
                platform: "",
                docker_user: "",
                k8s_user: "",
                errors: &[],
            },
            Case {
                json: r#"{"executor_opts":{"kubernetes": {"user": "1000"}}}"#,
                platform: "",
                docker_user: "",
                k8s_user: "1000",
                errors: &[],
            },
            Case {
                json: r#"{"executor_opts":{"kubernetes": {"user": 1000}}}"#,
                platform: "",
                docker_user: "",
                k8s_user: "1000",
                errors: &[],
            },
            Case {
                json: r#"{"executor_opts":{"kubernetes": {"foobar": 1234}}}"#,
                platform: "",
                docker_user: "",
                k8s_user: "",
                errors: &[
                    r#"Unsupported "image" options [foobar] for "kubernetes executor"; supported options are [user]"#,
                ],
            },
            Case {
                json: r#"{"executor_opts":{"k8s": {}}}"#,
                platform: "",
                docker_user: "",
                k8s_user: "",
                errors: &[
                    r#"Unsupported "image" options [k8s] for "executor_opts"; supported options are [docker kubernetes]"#,
                ],
            },
            Case {
                json: r#"{"executor_opts":{"k8s": {}, "docker": {"platform": "amd64", "foobar": 1234}}}"#,
                platform: "amd64",
                docker_user: "",
                k8s_user: "",
                errors: &[
                    r#"Unsupported "image" options [k8s] for "executor_opts"; supported options are [docker kubernetes]"#,
                    r#"Unsupported "image" options [foobar] for "docker executor"; supported options are [platform user]"#,
                ],
            },
            Case {
                json: r#"{"executor_opts":{"dockers": {}, "kubernetes": {"user": "1000", "foobar": 1234}}}"#,
                platform: "",
                docker_user: "",
                k8s_user: "1000",
                errors: &[
                    r#"Unsupported "image" options [dockers] for "executor_opts"; supported options are [docker kubernetes]"#,
                    r#"Unsupported "image" options [foobar] for "kubernetes executor"; supported options are [user]"#,
                ],
            },
        ];
        for c in cases {
            let image: Image =
                serde_json::from_str(c.json).unwrap_or_else(|e| panic!("{}: {e}", c.json));
            let opts = &image.executor_options;
            assert_eq!(opts.docker.platform, c.platform, "{}", c.json);
            assert_eq!(opts.docker.user.0, c.docker_user, "{}", c.json);
            assert_eq!(opts.kubernetes.user.0, c.k8s_user, "{}", c.json);
            let job = Job {
                image,
                ..Job::default()
            };
            match job.unsupported_options() {
                None => assert!(c.errors.is_empty(), "{}", c.json),
                Some(msg) => {
                    assert!(!c.errors.is_empty(), "{}: {msg}", c.json);
                    for e in c.errors {
                        assert!(msg.contains(e), "{}: {msg}", c.json);
                    }
                }
            }
        }
    }

    #[test]
    fn null_scalars_decode_to_zero_values() {
        let job: Job = serde_json::from_str(
            r#"{"id": 1, "token": null, "git_info": {"before_sha": null, "depth": null, "refspecs": null},
                "variables": null, "image": null, "features": {"failure_reasons": null}}"#,
        )
        .unwrap();
        assert_eq!(job.id, 1);
        assert!(job.token.is_empty());
        assert_eq!(job.git_info.before_sha, "");
        assert_eq!(job.git_info.depth, 0);
        assert!(job.variables.is_empty());
        assert!(job.features.failure_reasons.is_empty());
    }

    #[test]
    fn the_timestamps_flag_is_expanded_unless_raw() {
        let var = |key: &str, value: &str, raw| Variable {
            key: key.into(),
            value: value.into(),
            raw,
            ..Variable::default()
        };
        assert!(timestamps(&[]));
        let off = var("OFF", "false", false);
        assert!(!timestamps(&[
            off.clone(),
            var("FF_TIMESTAMPS", "$OFF", false)
        ]));
        assert!(timestamps(&[off, var("FF_TIMESTAMPS", "$OFF", true)]));
        let file = Variable {
            file: true,
            ..var("OFF", "false", false)
        };
        assert!(timestamps(&[file, var("FF_TIMESTAMPS", "$OFF", false)]));
    }

    #[test]
    fn variable_bool_matches_go() {
        for v in ["1", "t", "T", "TRUE", "true", "True"] {
            assert!(variable_bool(v), "{v}");
        }
        for v in ["0", "f", "false", "2", "", "yes"] {
            assert!(!variable_bool(v), "{v}");
        }
    }

    #[test]
    fn clean_url_strips_credentials() {
        assert_eq!(
            clean_url(
                "https://gitlab-ci-token:testTokenHere1234@gitlab.example.com/test/test-project.git"
            ),
            "https://gitlab.example.com/test/test-project.git"
        );
        assert_eq!(clean_url("not a url"), "");
    }
}
