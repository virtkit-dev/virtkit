//! How a workload reads in a table: its columns, its kind's name, what it belongs to.

use vk_hub_proto::{Workload, WorkloadKind};

/// The columns a table of workloads has.
pub(crate) const COLUMNS: [&str; 9] = [
    "KIND",
    "ID",
    "FOR",
    "PID",
    "CPUS",
    "RESERVED",
    "IN USE",
    "STARTED",
    "STATE DIR",
];

pub(crate) fn kind_name(kind: WorkloadKind) -> &'static str {
    match kind {
        WorkloadKind::CiJob => "ci-job",
        WorkloadKind::Dev => "dev",
        WorkloadKind::Run => "run",
        WorkloadKind::Other => "other",
    }
}

/// What a workload belongs to, in words: a CI job's project, name and ID, a dev
/// environment's workspace and name, a run's image and directory. The host's strings.
pub(crate) fn owner(w: &Workload) -> String {
    let join = |parts: &[Option<String>]| {
        let words: Vec<&str> = parts.iter().flatten().map(String::as_str).collect();
        if words.is_empty() {
            "-".to_string()
        } else {
            words.join(" ")
        }
    };
    match w.kind {
        WorkloadKind::CiJob => join(&[
            w.project.clone(),
            w.job_name.clone(),
            w.job_id.as_ref().map(|id| format!("#{id}")),
        ]),
        WorkloadKind::Dev => join(&[
            w.workspace.clone(),
            w.environment.as_ref().map(|e| format!("({e})")),
        ]),
        WorkloadKind::Run | WorkloadKind::Other => join(&[
            w.label.clone(),
            w.workspace.as_ref().map(|d| format!("in {d}")),
        ]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workload(kind: WorkloadKind) -> Workload {
        Workload {
            id: "ab".repeat(8),
            kind,
            state_dir: "/s".into(),
            label: Some("alpine:3.20".into()),
            project: Some("acme/web".into()),
            job_name: Some("test".into()),
            job_id: Some("42".into()),
            workspace: Some("/src/app".into()),
            environment: Some("dev".into()),
            pid: Some(7),
            cpus: Some(2),
            mem_reserved_mib: Some(2048),
            started_at: Some(100),
            ssh_alias: None,
            guest_workspace: None,
        }
    }

    #[test]
    fn a_workload_is_named_by_what_it_belongs_to() {
        assert_eq!(owner(&workload(WorkloadKind::CiJob)), "acme/web test #42");
        assert_eq!(owner(&workload(WorkloadKind::Dev)), "/src/app (dev)");
        assert_eq!(
            owner(&workload(WorkloadKind::Run)),
            "alpine:3.20 in /src/app"
        );
    }
}
