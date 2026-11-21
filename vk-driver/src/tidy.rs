//! `vk stop --tidy` repairs stale VM records across the host. `vk list` only reports them.
//!
//! Apply the name index's reclamation rules, prune dead registry entries under their state
//! directory locks, clear stale `starting` and `stopping` records, and name unindexed dev
//! environments with a recorded boot. Ask before killing a run whose stop timed out or
//! was interrupted.

use std::path::PathBuf;

use crate::vms::Pruned;
use crate::vmstate::{Standing, Transient};

/// Maximum wait for a killed run to exit, in seconds.
const KILL_WAIT_SECS: u64 = 10;

/// A VM whose recorded stop is overdue while its run is still there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overdue {
    /// how `vk list` names it
    pub name: String,
    pub dir: PathBuf,
    pub record: Transient,
}

/// What `vk stop --tidy` does about an overdue run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// asked, and told to kill it
    End,
    /// asked, and told to leave it
    Leave,
    /// nobody to ask: left, and said so
    NoTerminal,
}

/// Repair records before passing overdue runs to `decide`. Return the report and whether
/// every repair succeeded and every overdue stop was resolved.
pub fn thorough(decide: impl Fn(&Overdue) -> Decision) -> (String, bool) {
    let mut left = Vec::new();
    // Collect directories before forgetting names. A claim may be the only way to find
    // the state record of a run that died before registering.
    let mut dirs: Vec<(String, PathBuf)> = Vec::new();
    let idx = crate::names::Index::open()
        .inspect_err(|e| left.push(format!("names not tidied: {e:#}")))
        .ok();
    if let Some(idx) = &idx {
        match idx.try_all() {
            Ok(all) => dirs = all,
            Err(e) => left.push(format!("names not read: {e:#}")),
        }
    }
    let mut entries = 0;
    let mut dead = Vec::new();
    match crate::vms::prune_dead() {
        Ok((pruned, unread)) => {
            for (dir, outcome) in pruned {
                let shown = dir.display();
                let why = match outcome {
                    Pruned::Removed => {
                        entries += 1;
                        None
                    }
                    // The original entry was removed or replaced.
                    Pruned::Replaced => None,
                    // A new run may be recreating the directory.
                    Pruned::DirGone => Some(format!(
                        "registry entry of {shown} left: its run and its state directory are gone"
                    )),
                    Pruned::Held => Some(format!(
                        "registry entry of {shown} left: its run is gone and its state directory \
                         could not be locked"
                    )),
                    Pruned::Failed(e) => {
                        Some(format!("registry entry of {shown} not removed: {e}"))
                    }
                };
                left.extend(why);
                dead.push(dir);
            }
            left.extend(unread);
        }
        Err(e) => left.push(format!("registry not tidied: {e:#}")),
    }
    for e in crate::vms::registered().0 {
        if !dirs.iter().any(|(_, d)| *d == e.state_dir) {
            dirs.push((crate::vms::display_name(&e), e.state_dir.clone()));
        }
    }
    // A first dev boot can leave a state record before it acquires a name.
    match crate::dev::list::unnamed_dirs(&dirs) {
        Ok(unnamed) => dirs.extend(unnamed.into_iter().map(|(own, dir, _)| (own, dir))),
        Err(e) => left.push(format!("dev environments not read: {e:#}")),
    }
    let mut states = 0;
    let mut uncleared = Vec::new();
    for dir in dirs.iter().map(|(_, d)| d).chain(&dead) {
        match crate::vmstate::clear_if_stale(dir) {
            Ok(cleared) => states += usize::from(cleared),
            Err(e) => {
                left.push(format!(
                    "{}: state record not cleared: {e:#}",
                    dir.display()
                ));
                uncleared.push(dir.clone());
            }
        }
    }
    let mut names = 0;
    if let Some(idx) = &idx {
        // Keep the claim so the next tidy can find the record that failed to clear.
        match idx.forget_all_removed(|dir| uncleared.iter().any(|u| u == dir)) {
            Ok((forgotten, failed)) => {
                names = forgotten;
                left.extend(failed);
            }
            Err(e) => left.push(format!("names not tidied: {e:#}")),
        }
        if let Err(e) = crate::dev::list::name_unnamed() {
            left.push(format!("dev environments not named: {e:#}"));
        }
        // Use newly assigned names in overdue-stop prompts.
        match idx.try_all() {
            Ok(all) => {
                for (name, dir) in all {
                    if let Some(row) = dirs.iter_mut().find(|(_, d)| *d == dir) {
                        row.0 = name;
                    }
                }
            }
            Err(e) => left.push(format!("names not read: {e:#}")),
        }
    }
    let mut out = format!(
        "tidied: {names} name(s) forgotten, {entries} registry entry(ies) and {states} state \
         record(s) cleared\n"
    );
    let overdue: Vec<Overdue> = (dirs.into_iter())
        .filter_map(|(name, dir)| match crate::vmstate::peek(&dir)? {
            (record, Standing::Overdue) => Some(Overdue { name, dir, record }),
            _ => None,
        })
        .collect();
    for o in overdue {
        let pid = o.record.pid;
        match decide(&o) {
            Decision::End => match end(&o) {
                Ok(done) => out.push_str(&format!("{} (pid {pid}): {done}\n", o.name)),
                Err(why) => left.push(format!("{} (pid {pid}) left: {why}", o.name)),
            },
            Decision::Leave => left.push(format!("{} (pid {pid}) left, still stopping", o.name)),
            Decision::NoTerminal => left.push(format!(
                "{name} is still stopping: a stop {} and its run (pid {pid}) is still there. To \
                 review it interactively, run `vk stop --tidy` on a terminal; `vk stop --force \
                 {name}` insists then kills it",
                o.record.lapse(crate::vms::unix_now()),
                name = o.name,
            )),
        }
    }
    for line in &left {
        out.push_str(line);
        out.push('\n');
    }
    (out, left.is_empty())
}

/// Use `vk stop --kill` only for the registered run identified by the recorded PID and
/// start time. Claim the exact record under lock before signalling so an answer to the
/// prompt cannot override a newer stop. Return the outcome or the reason for leaving it.
fn end(o: &Overdue) -> Result<&'static str, &'static str> {
    let r = &o.record;
    let went = || {
        crate::vmstate::clear_of(&o.dir, r.pid, r.pid_start_ticks);
        Ok("its run went meanwhile")
    };
    let entry = crate::vms::registered().0.into_iter().find(|e| {
        e.state_dir == o.dir
            && e.pid == r.pid
            && r.pid_start_ticks.is_some()
            && e.pid_start_ticks == r.pid_start_ticks
    });
    let Some(entry) = entry else {
        return match r.run_gone() {
            true => went(),
            false => Err("no registered run is the one its record names"),
        };
    };
    let deadline = crate::vms::Deadline::in_secs(KILL_WAIT_SECS);
    match crate::vmstate::claim(&o.dir, r, deadline.left()) {
        Ok(true) => {}
        Ok(false) if r.run_gone() => return went(),
        Ok(false) => return Err("its record changed meanwhile"),
        Err(_) => return Err("its stop record could not be claimed"),
    }
    let stops =
        crate::vms::Stops::begin(vec![entry], Vec::new(), deadline, crate::vms::StopHow::Kill);
    match stops.finish().1 {
        true => Ok("killed"),
        false => Err("it is still there"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::testutil::{Homes, StandIn};
    use crate::vmstate::State;
    use std::path::Path;

    /// A named run of `stand_in` on `dir`, whose stop timed out a minute ago.
    fn overdue(
        homes: &Homes,
        dir: &Path,
        name: &str,
        stand_in: &StandIn,
    ) -> crate::vms::Registration {
        let mut e = crate::vms::tests::entry(dir.to_path_buf(), None);
        e.pid = stand_in.id();
        e.pid_start_ticks = crate::usage::proc_starttime(i32::try_from(e.pid).unwrap());
        let reg = crate::vms::register(e.clone());
        homes.name(dir, name);
        let now = crate::vms::unix_now();
        let record = Transient {
            state: State::Stopping,
            pid: e.pid,
            pid_start_ticks: e.pid_start_ticks,
            since_secs: now - 270,
            deadline_secs: Some(now - 60),
            by_pid: None,
            by_start_ticks: None,
        };
        write_record(dir, &record);
        reg
    }

    fn write_record(dir: &Path, record: &Transient) {
        let json = serde_json::to_vec(record).unwrap();
        std::fs::write(dir.join(crate::vmstate::FILE), json).unwrap();
    }

    /// Without a terminal, tidy reports overdue runs and fails. With consent, it kills
    /// only a run that still matches the prompt.
    #[test]
    fn tidy_repairs_records_and_kills_only_what_it_was_told_to() {
        let homes = Homes::new("tidy");
        let run = |name: &str| {
            let dir = crate::names::run_base().unwrap().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            crate::vms::canonical(&dir)
        };
        let removed = run("removed");
        homes.name(&removed, "removed");
        let lapsed = run("lapsed");
        homes.name(&lapsed, "lapsed");
        let mut record = Transient {
            state: State::Starting,
            pid: std::process::id(),
            pid_start_ticks: Some(1),
            since_secs: 0,
            deadline_secs: None,
            by_pid: None,
            by_start_ticks: None,
        };
        write_record(&lapsed, &record);
        let (went, killed) = (run("went"), run("killed"));
        let (mut a, mut b) = (
            StandIn::locking(&went, true),
            StandIn::locking(&killed, true),
        );
        let _regs = [
            overdue(&homes, &went, "went", &a),
            overdue(&homes, &killed, "killed", &b),
        ];

        // Remove the directory after setup so a name claim cannot reclaim it before tidy.
        std::fs::remove_dir(&removed).unwrap();
        let (out, settled) = thorough(|_| Decision::NoTerminal);
        assert!(!settled, "{out}");
        assert!(
            out.starts_with(
                "tidied: 1 name(s) forgotten, 0 registry entry(ies) and 1 state record(s) cleared\n"
            ),
            "{out}"
        );
        let said = format!(
            "went is still stopping: a stop timed out 1m ago and its run (pid {}) is still \
             there. To review it interactively, run `vk stop --tidy` on a terminal",
            a.id()
        );
        assert!(out.contains(&said), "{out}");
        assert!(a.alive() && b.alive());
        assert_eq!(crate::vmstate::peek(&lapsed), None);

        // If the run exits during the prompt, tidy treats its stop as settled.
        let a_pid = a.id();
        let (out, settled) = thorough(|o| {
            if o.name == "went" {
                let pid = i32::try_from(a_pid).unwrap();
                // SAFETY: a signal to the stand-in this test spawned.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                let ticks = o.record.pid_start_ticks.unwrap();
                assert!(crate::testutil::released(|| crate::usage::proc_exited(
                    pid, ticks
                )));
            }
            Decision::End
        });
        assert!(settled, "{out}");
        assert!(
            out.contains(&format!("went (pid {a_pid}): its run went meanwhile")),
            "{out}"
        );
        assert!(
            out.contains(&format!("killed (pid {}): killed", b.id())),
            "{out}"
        );
        assert!(!a.alive() && !b.alive());
        assert_eq!(crate::vmstate::peek(&killed), None);

        // A second stop of the same run invalidates the first prompt.
        let late = run("late");
        let mut c = StandIn::locking(&late, true);
        let _reg = overdue(&homes, &late, "late", &c);
        let (asked, _) = crate::vmstate::peek(&late).unwrap();
        let o = Overdue {
            name: "late".into(),
            dir: late.clone(),
            record: asked.clone(),
        };
        record = asked;
        record.since_secs += 1;
        write_record(&late, &record);
        assert_eq!(end(&o), Err("its record changed meanwhile"));
        assert!(c.alive());
        assert_eq!(crate::vmstate::peek(&late).map(|(r, _)| r), Some(record));
    }

    /// A failed state-lock open leaves the claim in place for a retry. Tidy also finds
    /// the state record of a first dev boot that died before it acquired a name.
    #[test]
    fn tidy_reaches_every_record_and_reports_what_it_cannot_repair() {
        let _homes = Homes::new("tidy-fail");
        let stale = |pid_start_ticks| Transient {
            state: State::Starting,
            pid: std::process::id(),
            pid_start_ticks,
            since_secs: 0,
            deadline_secs: None,
            by_pid: None,
            by_start_ticks: None,
        };
        let base = crate::names::run_base().unwrap();
        let boot = base.join("boot-00000000");
        std::fs::create_dir_all(&boot).unwrap();
        std::fs::write(boot.join(crate::names::MADE), b"").unwrap();
        let boot = crate::vms::canonical(&boot);
        let idx = crate::names::Index::open().unwrap();
        assert!(idx.provisional().claim_exact(&boot, "boot").unwrap());
        write_record(&boot, &stale(Some(1)));
        let lock = boot.join(".virtkit-state.lock");
        std::fs::create_dir(&lock).unwrap();
        let first = crate::dev::plan::dev_state_base().unwrap().join("app-1111");
        std::fs::create_dir_all(&first).unwrap();
        let first = crate::vms::canonical(&first);
        write_record(&first, &stale(Some(1)));

        let (out, settled) = thorough(|_| Decision::NoTerminal);
        assert!(!settled, "{out}");
        let said = format!("{}: state record not cleared: opening", boot.display());
        assert!(out.contains(&said), "{out}");
        assert!(out.starts_with("tidied: 0 name(s) forgotten, 0 registry entry(ies) and 1 state"));
        assert_eq!(idx.lookup("boot").as_ref(), Some(&boot));
        assert!(crate::vmstate::peek(&boot).is_some());
        assert_eq!(crate::vmstate::peek(&first), None);

        std::fs::remove_dir(&lock).unwrap();
        let (out, settled) = thorough(|_| Decision::NoTerminal);
        assert!(settled, "{out}");
        assert!(out.starts_with("tidied: 1 name(s) forgotten, 0 registry entry(ies) and 1 state"));
        assert_eq!(idx.lookup("boot"), None);
        assert_eq!(crate::vmstate::peek(&boot), None);
    }

    /// A malformed state record survives repair. Unreadable registry entries, the dev
    /// base and the registry itself must also appear in the failure report.
    #[test]
    fn tidy_fails_on_what_it_cannot_read() {
        let _homes = Homes::new("tidy-unread");
        let bad = crate::names::run_base().unwrap().join("bad");
        std::fs::create_dir_all(&bad).unwrap();
        let bad = crate::vms::canonical(&bad);
        crate::names::Index::open()
            .unwrap()
            .claim_exact(&bad, "bad")
            .unwrap();
        let record = bad.join(crate::vmstate::FILE);
        std::fs::write(&record, b"{").unwrap();
        let reg = crate::vms::registry_dir().unwrap();
        let odd = reg.join("odd.json");
        std::fs::create_dir_all(&odd).unwrap();
        let dev = crate::dev::plan::dev_state_base().unwrap();
        std::fs::create_dir_all(dev.parent().unwrap()).unwrap();
        std::fs::write(&dev, b"").unwrap();

        let (out, settled) = thorough(|_| Decision::NoTerminal);
        assert!(!settled, "{out}");
        for said in [
            format!(
                "{}: state record not cleared: reading {}",
                bad.display(),
                record.display()
            ),
            format!("registry entry {} not read", odd.display()),
            format!("dev environments not read: reading {}", dev.display()),
        ] {
            assert!(out.contains(&said), "{said}\n{out}");
        }
        assert_eq!(std::fs::read(&record).unwrap(), b"{");

        std::fs::remove_file(&record).unwrap();
        std::fs::remove_file(&dev).unwrap();
        std::fs::remove_dir_all(&reg).unwrap();
        std::fs::write(&reg, b"").unwrap();
        let (out, settled) = thorough(|_| Decision::NoTerminal);
        assert!(!settled, "{out}");
        let said = format!("registry not tidied: reading {}", reg.display());
        assert!(out.contains(&said), "{out}");
    }
}
