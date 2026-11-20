//! Workload columns, kind names and ownership labels for the CLI, node pages and local list.
//! Row cells are shared by `vk-hub workloads` and node pages.

use vk_hub_proto::{Workload, WorkloadKind};

/// The columns a table of workloads has; `vk-hub workloads` puts the node's before them.
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

/// Host-reported workload description, prefixed with the indexed VM name when present
/// (`staging — /src/app (dev)`). CI jobs show project, job name and ID, dev environments
/// show workspace and environment, and runs show image and project directory.
pub(crate) fn owner(w: &Workload) -> String {
    let join = |parts: &[Option<String>]| {
        let words: Vec<&str> = parts.iter().flatten().map(String::as_str).collect();
        (!words.is_empty()).then(|| words.join(" "))
    };
    let about = match w.kind {
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
    };
    match (w.name.as_deref(), about) {
        (Some(name), Some(about)) => format!("{name} — {about}"),
        (Some(name), None) => name.to_string(),
        (None, about) => about.unwrap_or_else(|| "-".to_string()),
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
pub(crate) fn cells(w: &Workload, mem_bytes: Option<u64>) -> [String; 9] {
    let dash = || "-".to_string();
    [
        kind_name(w.kind).to_string(),
        w.id.clone(),
        owner(w),
        w.pid.map_or_else(dash, |p| p.to_string()),
        w.cpus.map_or_else(dash, |c| c.to_string()),
        w.mem_reserved_mib.map_or_else(dash, size_mib),
        mem_bytes.map_or_else(dash, |b| match b {
            // Not shown as nothing at all.
            1..0x10_0000 => "<1M".to_string(),
            b => size_mib(b >> 20),
        }),
        w.started_at.map_or_else(dash, crate::utc),
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
            job_url: None,
            name: None,
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
        let cells = cells(&workload(WorkloadKind::Run), Some(3 << 30));
        assert_eq!(cells[0], "run");
        assert_eq!((cells[5].as_str(), cells[6].as_str()), ("2G", "3G"));
        assert_eq!(cells[7], "1970-01-01T00:01:40Z");
        let small = super::cells(&workload(WorkloadKind::Run), Some(4096));
        assert_eq!(small[6], "<1M");
    }

    #[test]
    fn a_named_vm_is_shown_by_its_name() {
        let named = |kind| Workload {
            name: Some("staging".into()),
            ..workload(kind)
        };
        assert_eq!(owner(&named(WorkloadKind::Dev)), "staging — /src/app (dev)");
        assert_eq!(
            owner(&named(WorkloadKind::Run)),
            "staging — alpine:3.20 in /src/app"
        );
        assert_eq!(
            cells(&named(WorkloadKind::Dev), None)[2],
            "staging — /src/app (dev)"
        );
        let bare = Workload {
            label: None,
            workspace: None,
            ..named(WorkloadKind::Run)
        };
        assert_eq!(owner(&bare), "staging");
        assert_eq!(owner(&Workload { name: None, ..bare }), "-");
    }
}
