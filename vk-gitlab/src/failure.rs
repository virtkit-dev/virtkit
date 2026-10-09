//! Job states and failure reasons as GitLab knows them, and the mapping of a runner-side
//! failure reason onto one the GitLab instance supports. Port of gitlab-runner's
//! `common/network.go` constants and `common/failure_reason_mapper.go`.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The `state` of a job update (`PUT /api/v4/jobs/:id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobState {
    Pending,
    Running,
    Failed,
    Success,
}

impl JobState {
    pub fn as_str(self) -> &'static str {
        match self {
            JobState::Pending => "pending",
            JobState::Running => "running",
            JobState::Failed => "failed",
            JobState::Success => "success",
        }
    }
}

impl fmt::Display for JobState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A `failure_reason`. A string rather than an enum: GitLab advertises the reasons it
/// accepts in each job's `features.failure_reasons`, and that list grows independently of
/// this runner.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FailureReason(pub String);

impl FailureReason {
    pub const SCRIPT_FAILURE: &str = "script_failure";
    pub const RUNNER_SYSTEM_FAILURE: &str = "runner_system_failure";
    pub const JOB_EXECUTION_TIMEOUT: &str = "job_execution_timeout";
    pub const IMAGE_PULL_FAILURE: &str = "image_pull_failure";
    pub const UNKNOWN_FAILURE: &str = "unknown_failure";
    /// A configuration error only the runner can detect; GitLab does not know it, so it maps
    /// to `script_failure`.
    pub const CONFIGURATION_ERROR: &str = "runner_configuration_error";
    /// A failure of something the runner depends on (registry, clone, HTTP); maps to
    /// `runner_system_failure` where GitLab does not know it yet.
    pub const RUNNER_EXTERNAL_DEPENDENCY_FAILURE: &str = "runner_external_dependency_failure";
    /// The runner process was told to stop while the job ran.
    pub const RUNNER_INTERRUPTED: &str = "runner_interrupted";
    /// Runner-internal in gitlab-runner; reported for a job GitLab asked to cancel.
    pub const JOB_CANCELED: &str = "job_canceled";

    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }

    pub fn script_failure() -> Self {
        Self::new(Self::SCRIPT_FAILURE)
    }

    pub fn runner_system_failure() -> Self {
        Self::new(Self::RUNNER_SYSTEM_FAILURE)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<&str> for FailureReason {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for FailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Reasons every GitLab version accepts, whatever a job's feature list says.
const ALWAYS_SUPPORTED: [&str; 3] = [
    FailureReason::SCRIPT_FAILURE,
    FailureReason::RUNNER_SYSTEM_FAILURE,
    FailureReason::JOB_EXECUTION_TIMEOUT,
];

/// Newer runner-side reasons and the older one each falls back to.
const COMPATIBILITY: [(&str, &str); 3] = [
    (
        FailureReason::IMAGE_PULL_FAILURE,
        FailureReason::RUNNER_SYSTEM_FAILURE,
    ),
    (
        FailureReason::CONFIGURATION_ERROR,
        FailureReason::SCRIPT_FAILURE,
    ),
    (
        FailureReason::RUNNER_EXTERNAL_DEPENDENCY_FAILURE,
        FailureReason::RUNNER_SYSTEM_FAILURE,
    ),
];

const MAX_MAPPING_DEPTH: usize = 10;

/// Maps a failure reason onto one the GitLab instance accepts, given the job's
/// `features.failure_reasons`.
#[derive(Debug, Clone)]
pub struct FailureReasonMapper {
    supported: Vec<String>,
    compatibility: Vec<(String, String)>,
    max_depth: usize,
}

impl FailureReasonMapper {
    pub fn new(supported_by_gitlab: &[FailureReason]) -> Self {
        let mut supported: Vec<String> = supported_by_gitlab.iter().map(|r| r.0.clone()).collect();
        supported.extend(ALWAYS_SUPPORTED.iter().map(|s| (*s).to_owned()));
        Self {
            supported,
            compatibility: COMPATIBILITY
                .iter()
                .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
                .collect(),
            max_depth: MAX_MAPPING_DEPTH,
        }
    }

    /// The reason to send: unchanged when GitLab supports it, an older equivalent when one
    /// is, `unknown_failure` otherwise. No reason at all is a script failure.
    pub fn map(&self, reason: &FailureReason) -> FailureReason {
        self.map_checked(reason).0
    }

    /// [`Self::map`], plus whether the compatibility chain exceeded the depth limit (a loop).
    fn map_checked(&self, reason: &FailureReason) -> (FailureReason, bool) {
        if reason.is_empty() {
            return (FailureReason::script_failure(), false);
        }
        if self.is_supported(reason.as_str()) {
            return (reason.clone(), false);
        }
        let mut current = reason.as_str();
        for _ in 0..self.max_depth {
            let Some((_, older)) = self.compatibility.iter().find(|(k, _)| k == current) else {
                return (FailureReason::new(FailureReason::UNKNOWN_FAILURE), false);
            };
            if self.is_supported(older) {
                return (FailureReason::new(older.clone()), false);
            }
            current = older;
        }
        (FailureReason::new(FailureReason::UNKNOWN_FAILURE), true)
    }

    fn is_supported(&self, reason: &str) -> bool {
        self.supported.iter().any(|s| s == reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from gitlab-runner v19.5.0 common/failure_reason_mapper_test.go,
    // TestFailureReasonMapper_Map (MIT, Copyright (c) 2015-2019 GitLab Inc.).
    fn upstream_mapper() -> FailureReasonMapper {
        let mut m = FailureReasonMapper::new(&["fr_one".into(), "fr_two".into()]);
        m.compatibility = [
            ("fr_three", "fr_one"),
            ("fr_five", "fr_four"),
            ("fr_four", "fr_two"),
            ("fr_seven", "fr_six"),
            ("fr_eight", "fr_seven"),
            ("fr_loop_one", "fr_loop_one"),
            ("fr_loop_four", "fr_loop_three"),
            ("fr_loop_three", "fr_loop_two"),
            ("fr_loop_two", "fr_loop_three"),
        ]
        .iter()
        .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
        .collect();
        m.max_depth = 3;
        m
    }

    fn check(m: &FailureReasonMapper, input: &str, want: &str, want_loop: bool) {
        let (got, looped) = m.map_checked(&input.into());
        assert_eq!(got.as_str(), want, "{input}");
        assert_eq!(looped, want_loop, "{input}");
    }

    #[test]
    fn map_matches_upstream() {
        let m = upstream_mapper();
        check(&m, "", "script_failure", false);
        check(&m, "script_failure", "script_failure", false);
        check(&m, "runner_system_failure", "runner_system_failure", false);
        check(&m, "job_execution_timeout", "job_execution_timeout", false);
        check(&m, "fr_one", "fr_one", false);
        check(&m, "fr_two", "fr_two", false);
        check(&m, "fr_six", "unknown_failure", false);
        check(&m, "fr_three", "fr_one", false);
        check(&m, "fr_four", "fr_two", false);
        check(&m, "fr_five", "fr_two", false);
        check(&m, "fr_seven", "unknown_failure", false);
        check(&m, "fr_eight", "unknown_failure", false);
        check(&m, "fr_totally_unknown", "unknown_failure", false);
        check(&m, "fr_loop_one", "unknown_failure", true);
        check(&m, "fr_loop_four", "unknown_failure", true);
    }

    // TestFailureReasonsCompatibilityMap: the built-in map has no loop.
    #[test]
    fn builtin_compatibility_map_terminates() {
        let m = FailureReasonMapper::new(&[]);
        for reason in [
            FailureReason::SCRIPT_FAILURE,
            FailureReason::RUNNER_SYSTEM_FAILURE,
            FailureReason::JOB_EXECUTION_TIMEOUT,
            FailureReason::IMAGE_PULL_FAILURE,
            FailureReason::UNKNOWN_FAILURE,
            FailureReason::CONFIGURATION_ERROR,
            FailureReason::RUNNER_EXTERNAL_DEPENDENCY_FAILURE,
            FailureReason::RUNNER_INTERRUPTED,
            FailureReason::JOB_CANCELED,
        ] {
            assert!(!m.map_checked(&reason.into()).1, "{reason}");
        }
        assert_eq!(
            m.map(&FailureReason::IMAGE_PULL_FAILURE.into()).as_str(),
            "runner_system_failure"
        );
        assert_eq!(
            m.map(&FailureReason::CONFIGURATION_ERROR.into()).as_str(),
            "script_failure"
        );
        assert_eq!(
            m.map(&FailureReason::JOB_CANCELED.into()).as_str(),
            "unknown_failure"
        );
    }
}
