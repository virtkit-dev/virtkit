//! The VMs running on this host for its user, as `vk workloads` lists them: pinned `vk run`s
//! and `vk dev` environments from the VM registry, CI jobs from the executor's job dirs.
//!
//! Everything is read from what those already keep, never kept apart: the registry's entries,
//! checked against their state-dir locks as `vk list` checks them (and pruned as it prunes
//! them); the running dev state dirs' identities, as `vk dev list` reads them; each job dir's
//! live supervisor and the record `prepare` leaves beside it; the admission ledger's
//! reservations. Nothing is read for a VM that is not running: a stopped dev environment's
//! directory and its workspace — perhaps on a share nobody else is holding up — stay
//! untouched.
//!
//! What a VM holds on the host is its managing process's whole tree, counted proportionally
//! — the figure `vk list` and `vk dev list` show. Reading it walks every process's page
//! tables, so a [`Meter`] measures at its own cadence and repeats the last figures between.
//!
//! Compose services are not listed apart from the VM that runs them: whether a declared
//! service is up takes a question to its run's control socket, and what a running one holds
//! is already in its primary's process tree.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Result;
use vk_fleet_proto::{MAX_WORKLOADS, MAX_WORKLOADS_BYTES, Workload, WorkloadKind, WorkloadList};

use crate::config::Config;
use crate::dev::list::Row;
use crate::jobctx::JobRecord;
use crate::vms::VmEntry;

/// How far after its registry entry was written a `vk run` may seem to have started, in
/// seconds, before its pid is taken as reused: the entry's time and the process's start are
/// read off two clocks, one of them in ticks.
const START_SLACK: u64 = 2;

/// A CI job whose supervisor is alive.
pub struct Job {
    pub dir: PathBuf,
    pub supervisor: i32,
    /// What `prepare` recorded of it; `None` for a job prepared by an older `vk`.
    pub record: Option<JobRecord>,
    /// When its supervisor started, from its pidfile.
    pub started_at: Option<u64>,
}

/// What the workloads are made from.
#[derive(Default)]
pub struct Sources {
    /// The live entries of the VM registry.
    pub vms: Vec<VmEntry>,
    /// Of those, the ones whose recorded pid now names a process started after the entry was
    /// written: the lock is still held — by a child that inherited it — but the pid is some
    /// other process's.
    pub reused_pids: HashSet<u32>,
    /// The running dev environments, by state dir — the canonical path the registry records.
    pub dev: Vec<Row>,
    /// Of those, the state dirs with an SSH setup, which `vk dev ssh` and an editor reach the
    /// environment through.
    pub ssh: HashSet<PathBuf>,
    pub jobs: Vec<Job>,
    /// Each granted reservation in the admission ledger, in MiB, by job ID.
    pub reserved_mib: HashMap<OsString, u64>,
}

impl Sources {
    /// Read this host's. `held` is the admission ledger as the heartbeat read it; `None`
    /// when it could not be.
    pub fn read(cfg: &Config, held: Option<&crate::admit::Held>) -> Sources {
        let vms = crate::vms::running();
        let dev = dev_rows(&vms);
        Sources {
            ssh: dev
                .iter()
                .filter(|row| {
                    crate::sshclient::Managed::new(&row.dir).is_ok_and(|m| m.config().is_file())
                })
                .map(|row| row.dir.clone())
                .collect(),
            reused_pids: vms
                .iter()
                .filter(|e| !started_by(e.pid, e.created_secs))
                .map(|e| e.pid)
                .collect(),
            dev,
            jobs: jobs(&cfg.state_dir().join("jobs")),
            reserved_mib: held
                .map(|h| h.mem.iter().cloned().collect())
                .unwrap_or_default(),
            vms,
        }
    }
}

/// Whether `pid` is still the process that recorded an entry at `created_secs`: a process
/// that started after the entry was written cannot be the `vk run` that wrote it.
fn started_by(pid: u32, created_secs: u64) -> bool {
    let Some(age) = i32::try_from(pid).ok().and_then(crate::usage::proc_age) else {
        return false;
    };
    crate::vms::unix_now().saturating_sub(age.as_secs()) <= created_secs.saturating_add(START_SLACK)
}

/// The running dev environments' rows, read from their own state dirs alone.
fn dev_rows(vms: &[VmEntry]) -> Vec<Row> {
    let Ok(base) = crate::dev::plan::dev_state_base() else {
        return Vec::new();
    };
    let running: Vec<crate::dev::list::Running> = vms
        .iter()
        .map(|e| crate::dev::list::Running {
            state_dir: e.state_dir.clone(),
            // Measured by the [`Meter`], for every kind alike.
            mem_used: None,
            mem: e.mem.clone(),
        })
        .collect();
    crate::dev::list::running_rows(&base, &running)
}

/// The job dirs under `jobs_dir` with a live supervisor.
fn jobs(jobs_dir: &Path) -> Vec<Job> {
    let live = match crate::vm::live_job_supervisors(jobs_dir) {
        Ok(live) => live,
        Err(e) => {
            eprintln!("virtkit: cannot list the CI jobs: {e:#}");
            return Vec::new();
        }
    };
    live.into_iter()
        .map(|(dir, supervisor)| Job {
            record: JobRecord::read(&dir),
            started_at: std::fs::metadata(dir.join("supervisor.pid"))
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs()),
            supervisor,
            dir,
        })
        .collect()
}

/// The workloads a list carries, and how many running ones it leaves out.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Listed {
    pub workloads: Vec<Workload>,
    pub omitted: u32,
}

/// Every workload on this host, bounded as [`bound`] bounds them, with what each holds on
/// the host by ID as `meter` last measured it.
pub fn collect(
    cfg: &Config,
    held: Option<&crate::admit::Held>,
    meter: &mut Meter,
) -> (Listed, BTreeMap<String, u64>) {
    let (found, omitted) = bound(workloads(&Sources::read(cfg, held)));
    // Read once for every tree measured, and only when one is: without the kernel's child
    // lists it is a scan of every process on the host.
    let mut links = None;
    let mem = meter.readings(&found, Instant::now(), |root| {
        let links = links.get_or_insert_with(crate::usage::Links::read);
        crate::usage::tree_resident_in(root, links)
    });
    let listed = Listed {
        workloads: found.into_iter().map(|(w, _)| w).collect(),
        omitted,
    };
    (listed, mem)
}

/// The workloads `sources` describe, each with the process whose tree it holds. Pure.
pub fn workloads(sources: &Sources) -> Vec<(Workload, Option<i32>)> {
    let text = |p: &Path| p.display().to_string();
    let mut out: Vec<(Workload, Option<i32>)> = Vec::new();
    for e in &sources.vms {
        let dev = sources.dev.iter().find(|row| row.dir == e.state_dir);
        // A reused pid is some other process's: neither named nor measured.
        let pid = Some(e.pid).filter(|p| !sources.reused_pids.contains(p));
        let workload = Workload {
            id: crate::vms::slug(&e.state_dir),
            kind: match dev {
                Some(_) => WorkloadKind::Dev,
                None => WorkloadKind::Run,
            },
            state_dir: text(&e.state_dir),
            label: Some(e.label.clone()).filter(|l| !l.is_empty()),
            project: None,
            job_name: None,
            job_id: None,
            workspace: match dev {
                Some(row) => row.workspace.as_deref().map(text),
                None => e.project_dir.as_deref().map(text),
            },
            environment: dev.and_then(|row| row.environment.clone()),
            pid,
            cpus: e.cpus,
            mem_reserved_mib: e.mem.as_deref().and_then(crate::run::parse_mem_mib),
            started_at: Some(e.created_secs),
            ssh_alias: dev
                .filter(|row| sources.ssh.contains(&row.dir))
                .map(|row| crate::dev::alias_for(&row.dir)),
            guest_workspace: dev.and_then(|row| row.workspace_folder.clone()),
        };
        out.push((workload, pid.and_then(|p| i32::try_from(p).ok())));
    }
    for j in &sources.jobs {
        let record = j.record.as_ref();
        let name = j.dir.file_name().unwrap_or_default();
        let workload = Workload {
            id: crate::vms::slug(&j.dir),
            kind: WorkloadKind::CiJob,
            state_dir: text(&j.dir),
            label: record.and_then(|r| r.image.clone()),
            project: record.and_then(|r| r.project.clone()),
            job_name: record.and_then(|r| r.job_name.clone()),
            job_id: Some(match record {
                Some(r) => r.job_id.clone(),
                None => name.to_string_lossy().into_owned(),
            }),
            workspace: None,
            environment: None,
            pid: u32::try_from(j.supervisor).ok(),
            cpus: record.map(|r| r.cpus),
            // The reservation where admission holds one, else the size the job boots at.
            mem_reserved_mib: sources
                .reserved_mib
                .get(name)
                .copied()
                .or_else(|| record.and_then(|r| crate::run::parse_mem_mib(&r.mem))),
            started_at: j.started_at,
            ssh_alias: None,
            guest_workspace: None,
        };
        out.push((workload, Some(j.supervisor)));
    }
    out
}

/// `found` made fit for a list: every string display-safe, at most [`MAX_WORKLOADS`] and
/// [`MAX_WORKLOADS_BYTES`] of them — CI jobs kept first, since they are what the host's
/// capacity is steered by, then the newest of the rest — and oldest first. Returns how many
/// were left out.
pub fn bound(found: Vec<(Workload, Option<i32>)>) -> (Vec<(Workload, Option<i32>)>, u32) {
    let mut found: Vec<(Workload, Option<i32>)> = found
        .into_iter()
        .map(|(w, root)| (display_safe(w), root))
        .collect();
    found.sort_by(|(a, _), (b, _)| {
        let key = |w: &Workload| {
            (
                w.kind != WorkloadKind::CiJob,
                std::cmp::Reverse(w.started_at),
            )
        };
        key(a).cmp(&key(b)).then_with(|| a.id.cmp(&b.id))
    });
    let total = found.len();
    let mut bytes = 0usize;
    let mut kept = Vec::new();
    for (w, root) in found {
        let size = serde_json::to_vec(&w).map_or(usize::MAX, |j| j.len());
        if kept.len() == MAX_WORKLOADS || bytes.saturating_add(size) > MAX_WORKLOADS_BYTES {
            continue;
        }
        bytes = bytes.saturating_add(size);
        kept.push((w, root));
    }
    let omitted = u32::try_from(total.saturating_sub(kept.len())).unwrap_or(u32::MAX);
    kept.sort_by(|(a, _), (b, _)| (a.started_at, &a.id).cmp(&(b.started_at, &b.id)));
    (kept, omitted)
}

fn display_safe(mut w: Workload) -> Workload {
    use vk_fleet_proto::display_safe as safe;
    w.id = safe(&w.id);
    w.state_dir = safe(&w.state_dir);
    for s in [
        &mut w.label,
        &mut w.project,
        &mut w.job_name,
        &mut w.job_id,
        &mut w.workspace,
        &mut w.environment,
        &mut w.ssh_alias,
        &mut w.guest_workspace,
    ]
    .into_iter()
    .flatten()
    {
        *s = safe(s);
    }
    w
}

/// The share of a workload's last figure its memory must move by before a new one is sent.
const SETTLE: u64 = 16;

/// What each workload holds on the host, measured every `every` and when a workload first
/// appears, and repeated from the last measurement in between — or past it, while a new
/// measurement stays within a sixteenth of it.
pub struct Meter {
    every: Duration,
    at: Option<Instant>,
    mem: BTreeMap<String, u64>,
}

impl Meter {
    pub fn new(every: Duration) -> Self {
        Meter {
            every,
            at: None,
            mem: BTreeMap::new(),
        }
    }

    /// The figures for `found` at `now`, taking each from `measure` — given the process a
    /// workload's tree hangs from — when one is due.
    pub fn readings(
        &mut self,
        found: &[(Workload, Option<i32>)],
        now: Instant,
        mut measure: impl FnMut(i32) -> Option<u64>,
    ) -> BTreeMap<String, u64> {
        let due = self
            .at
            .is_none_or(|at| now.saturating_duration_since(at) >= self.every);
        let mut next = BTreeMap::new();
        for (w, root) in found {
            let known = self.mem.get(&w.id).copied();
            let value = match known {
                Some(known) if !due => Some(known),
                _ => root.and_then(&mut measure).map(|v| match known {
                    // Moved by less than a sixteenth: the last figure stands, so a VM whose
                    // memory only jitters sends, and shows, the same figure.
                    Some(k) if v.abs_diff(k) < k / SETTLE => k,
                    _ => v,
                }),
            };
            if let Some(v) = value {
                next.insert(w.id.clone(), v);
            }
        }
        if due {
            self.at = Some(now);
        }
        self.mem = next.clone();
        next
    }
}

/// The host's workloads now, with what each holds as `meter` last measured it. A ledger that
/// cannot be read leaves the CI jobs unreserved, said once to `warned` until it reads again.
pub fn list(cfg: &Config, meter: &mut Meter, warned: &mut Option<String>) -> WorkloadList {
    let held = match crate::admit::committed(&cfg.state_dir().join("admit")) {
        Ok(held) => {
            *warned = None;
            Some(held)
        }
        Err(e) => {
            let e = format!("{e:#}");
            if warned.as_deref() != Some(e.as_str()) {
                eprintln!("virtkit: cannot read the admission ledger: {e}");
                *warned = Some(e);
            }
            None
        }
    };
    let (listed, mem_bytes) = collect(cfg, held.as_ref(), meter);
    WorkloadList {
        version: vk_fleet_proto::WORKLOADS_VERSION,
        workloads: listed.workloads,
        omitted: listed.omitted,
        mem_bytes,
    }
}

/// `vk workloads`: print the list as one line of JSON — and with `watch`, a new line each time
/// it changes, looking every `every`, until stdin closes or stdout's reader goes. The memory
/// figures are measured every `mem_every` and as a VM appears.
pub fn run(cfg: &Config, watch: bool, every: Duration, mem_every: Duration) -> Result<()> {
    use std::io::Write;
    if watch {
        // The reader holds stdin open for as long as it wants lists: its end is ours, even
        // when nothing changes and there is no write to fail.
        std::thread::spawn(|| {
            let _ = std::io::copy(&mut std::io::stdin().lock(), &mut std::io::sink());
            std::process::exit(0);
        });
    }
    let mut meter = Meter::new(mem_every);
    let mut warned = None;
    let mut last = None;
    loop {
        let list = list(cfg, &mut meter, &mut warned);
        if last.as_ref() != Some(&list) {
            let mut line = serde_json::to_vec(&list)?;
            line.push(b'\n');
            let mut out = std::io::stdout().lock();
            // The reader has gone: nothing is left to do.
            if out.write_all(&line).and_then(|()| out.flush()).is_err() {
                return Ok(());
            }
            last = Some(list);
        }
        if !watch {
            return Ok(());
        }
        std::thread::sleep(every);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("vk-wl-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(std::fs::canonicalize(&dir).unwrap())
    }

    fn entry(state_dir: &Path, created_secs: u64) -> VmEntry {
        serde_json::from_value(serde_json::json!({
            "state_dir": state_dir,
            "project_dir": "/src/app",
            "pid": std::process::id(),
            "label": "alpine:3.20",
            "exec_addr": "vsock-auto:///x/vsock.sock:4444",
            "created_secs": created_secs,
            "cpus": 2,
            "mem": "2G",
        }))
        .unwrap()
    }

    fn record(dir: &Path, entry: &VmEntry) {
        let registry = dir.join("vms");
        std::fs::create_dir_all(&registry).unwrap();
        std::fs::write(
            registry.join(format!("{}.json", crate::vms::slug(&entry.state_dir))),
            serde_json::to_vec(entry).unwrap(),
        )
        .unwrap();
    }

    /// Hold `dir`'s lock as a live `vk run` does, for as long as the file lives.
    fn hold(dir: &Path) -> std::fs::File {
        let f = std::fs::File::open(dir).unwrap();
        // SAFETY: the fd is owned by `f`, alive across the call.
        assert_eq!(
            unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        f
    }

    /// A registry entry counts only while its state dir's lock is held: a stale one is not
    /// reported, and is pruned as `vk list` prunes it.
    #[test]
    fn only_a_live_registry_entry_is_a_workload() {
        let tmp = scratch("registry");
        let live = tmp.0.join("live");
        let stale = tmp.0.join("stale");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::create_dir_all(&stale).unwrap();
        record(&tmp.0, &entry(&live, 100));
        record(&tmp.0, &entry(&stale, 50));
        let _lock = hold(&live);
        let vms = crate::vms::running_in(&tmp.0.join("vms"));
        assert_eq!(vms.len(), 1);
        let found = workloads(&Sources {
            vms,
            ..Sources::default()
        });
        assert_eq!(found.len(), 1);
        let (w, root) = &found[0];
        assert_eq!(w.kind, WorkloadKind::Run);
        assert_eq!(w.id, crate::vms::slug(&live));
        assert_eq!(w.state_dir, live.display().to_string());
        assert_eq!(w.workspace.as_deref(), Some("/src/app"));
        assert_eq!(w.label.as_deref(), Some("alpine:3.20"));
        assert_eq!((w.cpus, w.mem_reserved_mib), (Some(2), Some(2048)));
        assert_eq!(w.started_at, Some(100));
        assert_eq!(*root, i32::try_from(std::process::id()).ok());
        // The stale entry went with the read.
        assert_eq!(std::fs::read_dir(tmp.0.join("vms")).unwrap().count(), 1);
    }

    /// A live entry on a dev state dir is that environment, named as `vk dev list` names it.
    #[test]
    fn a_dev_environment_is_named_by_its_workspace_and_environment() {
        let tmp = scratch("dev");
        let base = tmp.0.join("dev");
        let env = base.join("app-dev");
        std::fs::create_dir_all(&env).unwrap();
        std::fs::write(
            env.join("dev.json"),
            serde_json::json!({
                "digest": "d",
                "booted_secs": 10,
                "created_by": "vk 0.80.0",
                "manifest": {"workspace": "/src/app", "environment": "dev", "workspace_folder": "/workdir"},
            })
            .to_string(),
        )
        .unwrap();
        let e = entry(&env, 200);
        let running = [crate::dev::list::Running {
            state_dir: env.clone(),
            mem_used: None,
            mem: e.mem.clone(),
        }];
        let dev = crate::dev::list::running_rows(&base, &running);
        let found = workloads(&Sources {
            vms: vec![e.clone()],
            dev: dev.clone(),
            ..Sources::default()
        });
        let (w, _) = &found[0];
        assert_eq!(w.kind, WorkloadKind::Dev);
        assert_eq!(w.workspace.as_deref(), Some("/src/app"));
        assert_eq!(w.environment.as_deref(), Some("dev"));
        assert_eq!(w.guest_workspace.as_deref(), Some("/workdir"));
        // An alias only where there is an SSH setup to reach it through.
        assert_eq!(w.ssh_alias, None);
        let found = workloads(&Sources {
            vms: vec![e],
            ssh: HashSet::from([env.clone()]),
            dev,
            ..Sources::default()
        });
        assert_eq!(found[0].0.ssh_alias.as_deref(), Some("vk-app-dev"));
    }

    /// A CI job is named from its record and reserved at its ledger entry; one prepared by an
    /// older `vk`, with no record, is still reported, by its job dir's name.
    #[test]
    fn a_ci_job_is_named_by_its_record_and_reserved_by_the_ledger() {
        let tmp = scratch("jobs");
        let recorded = tmp.0.join("4242");
        let bare = tmp.0.join("77");
        let (found, omitted) = bound(workloads(&Sources {
            jobs: vec![
                Job {
                    dir: recorded.clone(),
                    supervisor: 11,
                    record: Some(JobRecord {
                        job_id: "4242".into(),
                        project: Some("acme/web".into()),
                        job_name: Some("test:unit".into()),
                        image: Some("rust:1.90".into()),
                        cpus: 4,
                        mem: "8G".into(),
                    }),
                    started_at: Some(300),
                },
                Job {
                    dir: bare.clone(),
                    supervisor: 12,
                    record: None,
                    started_at: Some(5),
                },
            ],
            reserved_mib: HashMap::from([("4242".into(), 6144)]),
            ..Sources::default()
        }));
        assert_eq!(omitted, 0);
        // Oldest first.
        let (old, new) = (&found[0], &found[1]);
        assert_eq!(old.0.job_id.as_deref(), Some("77"));
        assert_eq!((old.0.project.as_ref(), old.0.cpus), (None, None));
        assert_eq!(old.0.mem_reserved_mib, None);
        assert_eq!(old.1, Some(12));
        let w = &new.0;
        assert_eq!(w.kind, WorkloadKind::CiJob);
        assert_eq!(w.id, crate::vms::slug(&recorded));
        assert_eq!(w.project.as_deref(), Some("acme/web"));
        assert_eq!(w.job_name.as_deref(), Some("test:unit"));
        assert_eq!(w.label.as_deref(), Some("rust:1.90"));
        assert_eq!((w.pid, w.cpus), (Some(11), Some(4)));
        assert_eq!(
            w.mem_reserved_mib,
            Some(6144),
            "the ledger's, not the 8G asked"
        );
        // Without a reservation, the size it boots at.
        let unreserved = workloads(&Sources {
            jobs: vec![Job {
                dir: recorded,
                supervisor: 11,
                record: Some(JobRecord {
                    job_id: "4242".into(),
                    project: None,
                    job_name: None,
                    image: None,
                    cpus: 4,
                    mem: "8G".into(),
                }),
                started_at: None,
            }],
            ..Sources::default()
        });
        assert_eq!(unreserved[0].0.mem_reserved_mib, Some(8192));
    }

    /// A job dir counts only while its supervisor runs and names it.
    #[test]
    fn only_a_job_with_a_live_supervisor_is_a_workload() {
        let tmp = scratch("supervisors");
        let dead = tmp.0.join("1");
        let reused = tmp.0.join("2");
        std::fs::create_dir_all(&dead).unwrap();
        std::fs::create_dir_all(&reused).unwrap();
        std::fs::create_dir_all(tmp.0.join(".shared")).unwrap();
        std::fs::write(dead.join("supervisor.pid"), "999999999").unwrap();
        // A live pid that is not this job's supervisor: this test process.
        std::fs::write(
            reused.join("supervisor.pid"),
            std::process::id().to_string(),
        )
        .unwrap();
        assert!(jobs(&tmp.0).is_empty());
        assert!(jobs(&tmp.0.join("missing")).is_empty());

        // A process whose arguments name the job dir, as a supervisor's do.
        let live = tmp.0.join("3");
        std::fs::create_dir_all(&live).unwrap();
        let mut child = std::process::Command::new("sh")
            // Not a lone command, which a shell may exec in its own place, argv and all.
            .args(["-c", "sleep 30; :"])
            .arg(&live)
            .spawn()
            .unwrap();
        std::fs::write(live.join("supervisor.pid"), child.id().to_string()).unwrap();
        // Until the child has exec'd, its argv is still this process's.
        let mut found = jobs(&tmp.0);
        for _ in 0..100 {
            if !found.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
            found = jobs(&tmp.0);
        }
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].dir, live);
        assert_eq!(u32::try_from(found[0].supervisor).ok(), Some(child.id()));
        assert!(found[0].record.is_none() && found[0].started_at.is_some());
    }

    /// A registry entry whose pid now names a process started after it was written — the
    /// lock outlived the run in a child — is reported without that pid, and not measured.
    #[test]
    fn a_reused_pid_is_neither_named_nor_measured() {
        let e = entry(Path::new("/s/x"), 100);
        let found = workloads(&Sources {
            reused_pids: HashSet::from([e.pid]),
            vms: vec![e],
            ..Sources::default()
        });
        assert_eq!((found[0].0.pid, found[0].1), (None, None));
        // This process started long after 100 and before now.
        let me = std::process::id();
        assert!(!started_by(me, 100));
        assert!(started_by(me, crate::vms::unix_now()));
        assert!(!started_by(999_999_999, crate::vms::unix_now()));
    }

    fn vm(i: usize, kind: WorkloadKind) -> (Workload, Option<i32>) {
        let mut w = workloads(&Sources {
            vms: vec![entry(&PathBuf::from(format!("/s/{i}")), i as u64)],
            ..Sources::default()
        })
        .remove(0);
        w.0.kind = kind;
        w
    }

    /// Past the cap CI jobs are kept first, then the newest of the rest; what is left out is
    /// counted, and what is kept is oldest first.
    #[test]
    fn the_list_is_capped_keeping_ci_jobs_then_the_newest() {
        let mut all: Vec<_> = (0..MAX_WORKLOADS + 10)
            .map(|i| vm(i, WorkloadKind::Run))
            .collect();
        all.push(vm(0, WorkloadKind::CiJob));
        all[0].0.id = "oldest-run".into();
        let (kept, omitted) = bound(all);
        assert_eq!((kept.len(), omitted), (MAX_WORKLOADS, 11));
        assert_eq!(
            kept[0].0.kind,
            WorkloadKind::CiJob,
            "the oldest, but a CI job"
        );
        assert!(kept.iter().all(|(w, _)| w.id != "oldest-run"));
        assert_eq!(kept[1].0.started_at, Some(11));
        assert!(
            kept.windows(2)
                .all(|p| p[0].0.started_at <= p[1].0.started_at)
        );
    }

    /// Long strings are made display-safe and cut, and the list stops at its byte budget.
    #[test]
    fn the_list_fits_its_budget() {
        let long = format!("a\u{1b}[2J{}", "é".repeat(10_000));
        let all: Vec<_> = (0..MAX_WORKLOADS)
            .map(|i| {
                let mut w = vm(i, WorkloadKind::Run);
                w.0.label = Some(long.clone());
                w.0.workspace = Some(long.clone());
                w.0.state_dir = long.clone();
                w
            })
            .collect();
        let (kept, omitted) = bound(all);
        assert!(omitted > 0 && !kept.is_empty());
        assert_eq!(kept.len() + omitted as usize, MAX_WORKLOADS);
        let w = &kept[0].0;
        assert_eq!(w.state_dir.chars().count(), vk_fleet_proto::MAX_DISPLAY);
        assert!(!w.state_dir.contains('\u{1b}'));
        let list = WorkloadList {
            workloads: kept.into_iter().map(|(w, _)| w).collect(),
            ..Default::default()
        };
        assert!(serde_json::to_vec(&list).unwrap().len() <= MAX_WORKLOADS_BYTES + 64);
    }

    /// A workload is measured when it first appears and then once every interval; between,
    /// the last figure is repeated. One gone is dropped.
    #[test]
    fn memory_is_measured_at_its_own_cadence() {
        let mut meter = Meter::new(Duration::from_secs(30));
        let t0 = Instant::now();
        let calls = std::cell::Cell::new(0);
        let mut measure = |root: i32| {
            calls.set(calls.get() + 1);
            Some(u64::try_from(root).unwrap() * 10)
        };
        let a = vm(1, WorkloadKind::Run);
        let mut b = vm(2, WorkloadKind::Run);
        b.1 = Some(2);
        let mut a1 = a.clone();
        a1.1 = Some(1);
        let first = meter.readings(std::slice::from_ref(&a1), t0, &mut measure);
        assert_eq!(first.get(&a1.0.id), Some(&10));
        // Between: the new one alone is measured.
        let second = meter.readings(
            &[a1.clone(), b.clone()],
            t0 + Duration::from_secs(5),
            &mut measure,
        );
        assert_eq!(second.len(), 2);
        assert_eq!(second.get(&b.0.id), Some(&20));
        let _ = meter.readings(
            &[a1.clone(), b.clone()],
            t0 + Duration::from_secs(10),
            &mut measure,
        );
        // Due again: both.
        let later = meter.readings(
            std::slice::from_ref(&b),
            t0 + Duration::from_secs(31),
            &mut measure,
        );
        assert_eq!(later.len(), 1, "a is gone");
        assert_eq!(calls.get(), 3);
    }

    /// A new measurement within a sixteenth of the last figure leaves it standing; one past
    /// that replaces it.
    #[test]
    fn a_jittering_figure_stays_put() {
        let mut meter = Meter::new(Duration::from_secs(1));
        let t0 = Instant::now();
        let mut w = vm(1, WorkloadKind::Run);
        w.1 = Some(1);
        let at = |secs| t0 + Duration::from_secs(secs);
        let read = |meter: &mut Meter, secs, v: u64| {
            meter.readings(std::slice::from_ref(&w), at(secs), |_| Some(v))[&w.0.id]
        };
        assert_eq!(read(&mut meter, 0, 1600), 1600);
        assert_eq!(read(&mut meter, 2, 1690), 1600);
        assert_eq!(read(&mut meter, 4, 1510), 1600);
        assert_eq!(read(&mut meter, 6, 1700), 1700);
    }

    /// Wired to the process tree: a live child is measured, a dead root is not.
    #[test]
    fn a_live_process_tree_is_measured() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let mut w = vm(1, WorkloadKind::Run);
        w.1 = i32::try_from(child.id()).ok();
        let mut gone = vm(2, WorkloadKind::Run);
        gone.1 = Some(i32::MAX);
        let mut meter = Meter::new(Duration::from_secs(30));
        let links = crate::usage::Links::read();
        let mem = meter.readings(&[w.clone(), gone.clone()], Instant::now(), |root| {
            crate::usage::tree_resident_in(root, &links)
        });
        let _ = child.kill();
        let _ = child.wait();
        assert!(mem.get(&w.0.id).is_some_and(|&b| b > 0), "{mem:?}");
        assert!(!mem.contains_key(&gone.0.id));
    }
}
