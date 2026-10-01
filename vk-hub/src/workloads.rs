//! How a workload reads in a table — `vk-hub workloads`, a node's page, local mode's list:
//! its kind's name, what it belongs to, its figures.

use vk_fleet_proto::{Workload, WorkloadKind};

/// The columns a table of workloads has; `vk-hub workloads` puts the node's before them.
pub(crate) const COLUMNS: [&str; 9] = [
    "KIND",
    "ID",
    "FOR",
    "PID",
    "CPUS",
    "RESERVED",
    "IN USE",
    "UP",
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

/// `mib` in the unit it reads best in: whole GiB, else MiB.
pub(crate) fn size_mib(mib: u64) -> String {
    if mib >= 1024 && mib.is_multiple_of(1024) {
        format!("{}G", mib / 1024)
    } else {
        format!("{mib}M")
    }
}

/// One workload's cells under [`COLUMNS`], with what it holds now.
pub(crate) fn cells(w: &Workload, mem_bytes: Option<u64>, now: u64) -> [String; 9] {
    let dash = || "-".to_string();
    [
        kind_name(w.kind).to_string(),
        w.id.clone(),
        owner(w),
        w.pid.map_or_else(dash, |p| p.to_string()),
        w.cpus.map_or_else(dash, |c| c.to_string()),
        w.mem_reserved_mib.map_or_else(dash, size_mib),
        mem_bytes.map_or_else(dash, |b| size_mib(b >> 20)),
        w.started_at
            .map_or_else(dash, |t| crate::human_duration(crate::ago(now, t))),
        w.state_dir.clone(),
    ]
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
        let cells = cells(&workload(WorkloadKind::Run), Some(3 << 30), 220);
        assert_eq!(cells[0], "run");
        assert_eq!((cells[5].as_str(), cells[6].as_str()), ("2G", "3G"));
        assert_eq!(cells[7], "2m");
    }
}
