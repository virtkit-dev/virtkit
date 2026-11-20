//! Tidying what `vk` records about VMs: the one place records that no longer describe
//! anything are removed, and the names that are owed are handed out.
//!
//! Commands that only read — `vk list`, `vk dev list`, `vk exec NAME` — write nothing: they
//! work out what a stale record should have said and say that it was stale. The commands
//! that start or stop a VM call [`run`], which puts the records right:
//!
//! - a name whose state dir was removed is forgotten;
//! - a registry entry whose run is gone is dropped;
//! - a `starting`/`stopping` record whose process is gone is cleared;
//! - a dev environment from before names existed is given its name.
//!
//! [`run`] is bounded: [`BUDGET`] is checked between items, and what is left when it runs
//! out is the next command's. Each item costs a few system calls, so a thousand VMs fit.
//!
//! `vk stop --tidy` is [`thorough`]: the same pass with no budget, and then the one thing no
//! pass settles by itself — a run that outlived a stop's timeout — put to the user, who may
//! have it ended.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::vmstate::{Standing, Transient};

/// How long one pass may take before it leaves the rest to the next command.
pub const BUDGET: Duration = Duration::from_millis(10);

/// How long [`thorough`] waits for a run it killed to be gone.
const KILL_WAIT: Duration = Duration::from_secs(10);

/// What a pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Tidied {
    /// names forgotten: their state dir was removed
    pub names: usize,
    /// transient-state records cleared: their process was gone
    pub states: usize,
    /// the pass ran out of [`BUDGET`] before it had looked at everything
    pub cut_short: bool,
}

/// One pass over the user's records, within [`BUDGET`]. Best-effort and silent: a record
/// that cannot be put right now is left for the next pass, and no command fails over it.
pub fn run() -> Tidied {
    pass(Some(Instant::now() + BUDGET))
}

/// A pass that ends at `deadline`, or looks at everything when there is none.
fn pass(deadline: Option<Instant>) -> Tidied {
    let out_of_time = || deadline.is_some_and(|d| Instant::now() >= d);
    let mut done = Tidied::default();
    let Ok(idx) = crate::names::Index::open() else {
        return done;
    };
    let names = idx.all();
    (done.names, done.cut_short) = idx.forget_removed_until(&names, deadline);
    for (_, dir) in &names {
        if out_of_time() {
            done.cut_short = true;
            break;
        }
        done.states += usize::from(crate::vmstate::clear_if_stale(dir));
    }
    if done.cut_short {
        return done;
    }
    // Reading the running VMs drops the entries of runs that are gone.
    let _ = crate::vms::running();
    if out_of_time() {
        done.cut_short = true;
    } else {
        // Only environments from before names existed are left to name: a boot names its own.
        crate::dev::list::name_unnamed();
    }
    done
}

/// A VM whose recorded stop or start is overdue while its run is still there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overdue {
    /// how `vk list` names it
    pub name: String,
    pub dir: PathBuf,
    pub record: Transient,
}

/// Every VM, named or running, whose transient state is [`Standing::Overdue`].
pub fn overdue() -> Vec<Overdue> {
    let idx = crate::names::Index::open().ok();
    let named = idx.as_ref().map(|i| i.all()).unwrap_or_default();
    let (running, _) = crate::vms::registered();
    let mut dirs: Vec<(String, PathBuf)> = named;
    for e in running {
        if !dirs.iter().any(|(_, d)| *d == e.state_dir) {
            dirs.push((crate::vms::display_name(&e), e.state_dir));
        }
    }
    dirs.into_iter()
        .filter_map(|(name, dir)| match crate::vmstate::peek(&dir)? {
            (record, Standing::Overdue) => Some(Overdue { name, dir, record }),
            _ => None,
        })
        .collect()
}

/// What `vk stop --tidy` does about an overdue run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// asked, and told to end it
    End,
    /// asked, and told to leave it
    Leave,
    /// nobody to ask: left, and said so
    NoTerminal,
}

/// `vk stop --tidy`: a full pass, then each overdue run put to the user through `decide`.
/// One the user has ended is killed and its records cleared. Returns the report, and
/// whether nothing overdue is left.
pub fn thorough(decide: impl Fn(&Overdue) -> Decision) -> (String, bool) {
    let done = pass(None);
    let mut out = format!(
        "tidied: {} name(s) forgotten, {} state record(s) cleared\n",
        done.names, done.states
    );
    let mut settled = true;
    for o in overdue() {
        let pid = o.record.pid;
        let what = o.record.state.label();
        match decide(&o) {
            Decision::End => match end(&o) {
                true => out.push_str(&format!("ended {} (pid {pid})\n", o.name)),
                false => {
                    out.push_str(&format!("{} (pid {pid}) is still there\n", o.name));
                    settled = false;
                }
            },
            Decision::Leave => {
                out.push_str(&format!("left {} (pid {pid}), still {what}\n", o.name));
                settled = false;
            }
            Decision::NoTerminal => {
                out.push_str(&format!(
                    "{} (pid {pid}) is still {what} past its deadline: run `vk stop --tidy` \
                     on a terminal to be asked about it, or `vk stop --force {}`\n",
                    o.name, o.name
                ));
                settled = false;
            }
        }
    }
    (out, settled)
}

/// End the run `o` names — if it is still that very process — and clear what it left on
/// record. A registered VM is ended as `vk stop --kill` ends one: its VMM first, its run
/// only if that does not follow. A run with no VM registered has no VMM to name, and is
/// killed itself; its helpers are tied to it and go with it. Whether it went.
fn end(o: &Overdue) -> bool {
    // Looked at again: the user answered a question asked a moment ago.
    let still = matches!(
        crate::vmstate::peek(&o.dir),
        Some((now, Standing::Overdue)) if now.pid == o.record.pid
    );
    if !still {
        return crate::vmstate::peek(&o.dir).is_none();
    }
    let (running, _) = crate::vms::registered();
    if let Some(entry) = running
        .into_iter()
        .find(|e| e.state_dir == o.dir && e.pid == o.record.pid)
    {
        return crate::vms::stop_many(&[entry], None, crate::vms::StopHow::Kill)[0];
    }
    let Ok(pid) = i32::try_from(o.record.pid) else {
        return false;
    };
    // SAFETY: kill with a signal number is always safe; the process was just checked to be
    // the one on record, by pid and start time.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let until = Instant::now() + KILL_WAIT;
    let gone = || crate::usage::proc_starttime(pid) != o.record.pid_start_ticks;
    while !gone() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(100));
    }
    if !gone() {
        return false;
    }
    crate::vmstate::clear(&o.dir);
    // Its registry entry, if it left one, is a dead run's now.
    let _ = crate::vms::running();
    true
}
