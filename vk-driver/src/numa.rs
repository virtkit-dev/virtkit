//! NUMA placement for every VM vk boots.
//!
//! On a multi-socket host every page of guest RAM lives on one memory node, and a vCPU thread
//! reaching a page on another node pays the interconnect for it. Nothing arranges that by
//! default: the kernel hands every thread the whole machine, faults each page in wherever the
//! thread that first touched it happened to be running, and then moves the threads around. A
//! VM ends up with its memory smeared across the sockets and its vCPUs on the far side of
//! most of it — a penalty that grows with the socket count, so the big machine runs the work
//! slower than the laptop it was written on.
//!
//! So a VM that fits inside one node is placed on it — vCPUs pinned to the node's CPUs and its
//! memory preferring the node, which is where first touch then puts it — and one that does not
//! fit — too much RAM, or more vCPUs than the node has CPUs — is interleaved across every node
//! instead. Interleaving is still a choice worth making: it spreads the guest evenly rather
//! than letting first touch pile it onto whichever node booted it, which is what turns one
//! node into the host's bottleneck while another sits idle.
//!
//! Both are set on the VMM subprocess before it execs ([`Placement::apply`]), which is what
//! makes them cover the whole guest without the VMM knowing anything about it: guest RAM is
//! one large mapping — anonymous, or a memfd where the guest needs shared memory for
//! virtio-fs — faulted in lazily by the VMM's own threads, and the kernel places each page
//! under the faulting task's own memory policy either way. That policy is the one the child
//! carries through exec, and the affinity mask decides which CPUs the threads doing the
//! faulting run on. Both are inherited by every thread the VMM goes on to create, vCPU
//! threads included.
//!
//! [`crate::run::spawn_vmm`] calls [`auto_place`] at boot for `vk run`, build stages,
//! compose services and CI jobs under the host-wide `[numa] mode`. Placement uses live
//! per-node free memory plus this process's outstanding allocations, so parallel build
//! stages account for guests whose RAM has not yet been faulted in. For CI jobs with an
//! admission ledger, the supervisor uses the other runners' grants instead and passes
//! [`Numa::Placed`] to the boot path.
//!
//! A host the kernel reports as single-node has nothing to place, and [`Topology::detect`]
//! answers `None` for it — the whole feature is then a no-op, which is the common case.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};

use crate::config::NumaMode;

/// Where the kernel publishes the node topology.
const SYSFS: &str = "/sys/devices/system/node";

/// Upper bound on a parsed cpu or node list, and on the ids in it. A cpulist is a
/// kernel-written range that expands as it is read, so a bound keeps a `/sys` that is not one
/// — a stray mount, a fixture — from turning `0-99999999999`, or a bare `99999999`, into an
/// allocation. Comfortably above both what `cpu_set_t` can name (1024) and the `MAX_NUMNODES`
/// any distribution kernel is built with.
const MAX_LIST: usize = 4096;

/// Bits in the words a nodemask is passed to the kernel as.
const MASK_BITS: usize = usize::BITS as usize;

/// One memory node: the CPUs attached to it and the memory it has. A node with no CPUs
/// (memory-only, e.g. CXL) is kept and simply never wins a bind, since no VM's vCPUs fit it.
#[derive(Debug, Clone)]
pub struct Node {
    pub id: u32,
    pub cpus: Vec<usize>,
    pub mem_total_mib: u64,
}

/// The host's online nodes, in id order.
#[derive(Debug, Clone)]
pub struct Topology {
    pub nodes: Vec<Node>,
    /// The `/sys` directory this was read from, so the live per-node memory
    /// ([`Topology::free_mib`]) is read from the same place the topology was.
    root: PathBuf,
}

/// What one node is already carrying, from the admission ledger or from the host's own live
/// figures: the guest RAM committed on it and how many VMs that is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NodeLoad {
    pub granted_mib: u64,
    pub jobs: usize,
}

/// Where one VM's memory and vCPUs go. Self-contained — it is applied in a forked child that
/// may read nothing — and carried in the [`crate::vmm::VmSpec`] the libkrun boot child is
/// handed as JSON.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Placement {
    /// Threads on `node`'s CPUs, memory preferring `node`. `nodes_total` is the host's node
    /// count, carried only so the log line can say which of how many.
    Bind {
        node: u32,
        cpus: Vec<usize>,
        nodes_total: u32,
    },
    /// Memory spread round-robin over `nodes`, threads left free to roam: the VM did not fit
    /// one node. The node ids are carried rather than a count because the kernel refuses a
    /// nodemask naming a node that is not online, and node ids are not always dense — a host
    /// with nodes 0 and 2 would have a `0..2` mask refused, and with it the whole placement.
    Interleave { nodes: Vec<u32> },
}

/// What a [`crate::vmm::VmSpec`] says about where its VM goes.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Numa {
    /// Decide at the boot, under the host's `[numa] mode` and against what this process has
    /// already placed ([`auto_place`]). Every VM says this unless something knew better.
    #[default]
    Auto,
    /// Place nothing, whatever the host's mode says (`vk run --numa off`).
    Off,
    /// A placement its caller already chose, because it knows what the boot path cannot: a
    /// CI supervisor reading the admission ledger, or `vk run --numa <node>`.
    Placed(Placement),
}

/// `vk run --numa`: a mode for this one VM, or the node to put it on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NumaArg {
    Off,
    Auto,
    Interleave,
    Node(u32),
}

impl NumaArg {
    /// clap value parser for `vk run --numa`.
    pub(crate) fn parse(s: &str) -> Result<NumaArg, String> {
        match s {
            "off" => Ok(NumaArg::Off),
            "auto" => Ok(NumaArg::Auto),
            "interleave" => Ok(NumaArg::Interleave),
            _ => s
                .parse()
                .map(NumaArg::Node)
                .map_err(|_| format!("expected off, auto, interleave or a node id, got {s:?}")),
        }
    }

    /// Resolve a node id to its CPUs and reject nonexistent nodes on the command line,
    /// before boot.
    pub(crate) fn resolve(self) -> anyhow::Result<Numa> {
        match (self, topology()) {
            (NumaArg::Off, _) => Ok(Numa::Off),
            (NumaArg::Auto, _) => Ok(Numa::Auto),
            // One node holds every page either way, so there is nothing to spread.
            (NumaArg::Interleave, None) => Ok(Numa::Off),
            (NumaArg::Interleave, Some(topology)) => Ok(Numa::Placed(Placement::Interleave {
                nodes: topology.node_ids(),
            })),
            (NumaArg::Node(_), None) => {
                anyhow::bail!("host has one memory node; --numa N needs a NUMA host")
            }
            (NumaArg::Node(id), Some(topology)) => {
                let node = topology
                    .nodes
                    .iter()
                    .find(|node| node.id == id)
                    .ok_or_else(|| {
                        let ids: Vec<String> =
                            topology.nodes.iter().map(|n| n.id.to_string()).collect();
                        anyhow::anyhow!("host has no memory node {id} (it has {})", ids.join(", "))
                    })?;
                Ok(Numa::Placed(Placement::Bind {
                    node: id,
                    cpus: node.cpus.clone(),
                    nodes_total: topology.nodes_total(),
                }))
            }
        }
    }
}

impl Topology {
    /// The host's topology, or `None` when it has fewer than two nodes or `/sys` cannot be
    /// read — both mean there is nothing to place.
    pub fn detect() -> Option<Topology> {
        Self::from_sysfs(Path::new(SYSFS))
    }

    /// [`Topology::detect`] against an arbitrary `/sys/devices/system/node`, for tests.
    ///
    /// Require every read: a partial topology gives a wrong total and can place a VM on
    /// an already-full node.
    pub(crate) fn from_sysfs(root: &Path) -> Option<Topology> {
        let online = parse_list(&std::fs::read_to_string(root.join("online")).ok()?)?;
        if online.len() < 2 {
            return None;
        }
        let mut nodes = Vec::with_capacity(online.len());
        for id in online {
            let id = u32::try_from(id).ok()?;
            let dir = root.join(format!("node{id}"));
            let cpus = parse_list(&std::fs::read_to_string(dir.join("cpulist")).ok()?)?;
            let meminfo = std::fs::read_to_string(dir.join("meminfo")).ok()?;
            nodes.push(Node {
                id,
                cpus,
                mem_total_mib: meminfo_field(&meminfo, "MemTotal:")? / 1024,
            });
        }
        nodes.sort_by_key(|n| n.id);
        Some(Topology {
            nodes,
            root: root.to_path_buf(),
        })
    }

    /// Each node's free memory in MiB right now. Only for a host with no admission ledger to
    /// read: it measures what has been faulted in, so it lags a VM that was placed a moment
    /// ago and has not touched its RAM yet. A node whose `meminfo` cannot be read is left out
    /// rather than reported as empty.
    pub(crate) fn free_mib(&self) -> HashMap<u32, u64> {
        self.nodes
            .iter()
            .filter_map(|n| {
                let path = self.root.join(format!("node{}", n.id)).join("meminfo");
                let text = std::fs::read_to_string(path).ok()?;
                Some((n.id, meminfo_field(&text, "MemFree:")? / 1024))
            })
            .collect()
    }

    pub(crate) fn nodes_total(&self) -> u32 {
        u32::try_from(self.nodes.len()).unwrap_or(u32::MAX)
    }

    /// The online node ids, which is what a nodemask handed to the kernel may name — see
    /// [`Placement::Interleave`].
    pub(crate) fn node_ids(&self) -> Vec<u32> {
        self.nodes.iter().map(|n| n.id).collect()
    }

    /// A topology with no `/sys` behind it, for tests in this crate that need one to place
    /// against rather than one to parse.
    #[cfg(test)]
    pub(crate) fn of(nodes: Vec<Node>) -> Topology {
        Topology {
            nodes,
            root: PathBuf::from(SYSFS),
        }
    }
}

/// `[numa] mode` as [`MODE`] holds it.
const MODE_AUTO: u8 = 0;
const MODE_OFF: u8 = 1;
const MODE_INTERLEAVE: u8 = 2;

/// The host's `[numa] mode`, read by every boot. A plain store rather than a `OnceLock` so
/// the re-exec'd `gitlab supervise` and the tests can set it again, as `[build]`'s priority
/// policy is ([`crate::prio::set_policy`]).
static MODE: AtomicU8 = AtomicU8::new(MODE_AUTO);

/// The host's topology, read once: `/sys` does not change under a running process short of a
/// hotplug, and a build booting stage after stage would otherwise re-read a directory per
/// node for each of them.
static TOPOLOGY: OnceLock<Option<Topology>> = OnceLock::new();

/// Read the host's `[numa]` policy. Called once from `main`, before any VM boots.
pub(crate) fn set_policy(mode: NumaMode) {
    MODE.store(
        match mode {
            NumaMode::Auto => MODE_AUTO,
            NumaMode::Off => MODE_OFF,
            NumaMode::Interleave => MODE_INTERLEAVE,
        },
        Ordering::Relaxed,
    );
}

fn mode() -> NumaMode {
    match MODE.load(Ordering::Relaxed) {
        MODE_OFF => NumaMode::Off,
        MODE_INTERLEAVE => NumaMode::Interleave,
        _ => NumaMode::Auto,
    }
}

fn topology() -> Option<&'static Topology> {
    TOPOLOGY.get_or_init(Topology::detect).as_ref()
}

/// A placement this process has made that nothing else accounts for yet: a guest faults its
/// RAM in over the minutes after it boots, so its node's `MemFree` still reports the memory
/// as free for most of that time. One VM per process would not need this — a CI supervisor
/// boots exactly one — but a build's parallel stages and a compose fleet start several
/// within the same second, and each would otherwise read the same empty node and pile onto
/// it.
#[derive(Debug)]
struct Outstanding {
    id: u64,
    /// The node the VM took, or `None` for an interleaved one: a share of every node.
    node: Option<u32>,
    mem_mib: u64,
    /// The VMM, once it is spawned. An entry with none yet is a placement whose VM has not
    /// been forked, which is the one stretch no pid can be checked for. A pid the host has
    /// recycled since would keep a dead VM's entry alive and read its node as fuller than it
    /// is; accepted rather than pinned down with the process's start time, because it costs
    /// one placement nudged to a neighbour and ends when the recycled process does.
    pid: Option<u32>,
}

impl Outstanding {
    /// What this placement has yet to take from its node, in MiB — not its declared size.
    ///
    /// Subtract the VMM's resident size: those pages are already absent from `MemFree`.
    /// Adding the full declaration would count them twice, making nodes with long-lived
    /// guests look full and forcing later VMs to interleave. Before the VMM spawns, the
    /// whole declaration is outstanding.
    fn remaining_mib(&self) -> u64 {
        match self.pid {
            Some(pid) => self.mem_mib.saturating_sub(rss_mib(pid)),
            None => self.mem_mib,
        }
    }
}

/// A process's resident size in MiB: the second field of `/proc/<pid>/statm`, its resident
/// page count. One short read from a file the kernel answers out of memory, per outstanding
/// placement per boot. A process that is already gone reads as 0, which costs nothing — the
/// sweep drops its entry on the same pass.
fn rss_mib(pid: u32) -> u64 {
    let Ok(statm) = std::fs::read_to_string(format!("/proc/{pid}/statm")) else {
        return 0;
    };
    let Some(pages) = statm
        .split_whitespace()
        .nth(1)
        .and_then(|field| field.parse::<u64>().ok())
    else {
        return 0;
    };
    // SAFETY: sysconf takes no pointers and reads nothing of ours.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page = u64::try_from(page).ok().filter(|n| *n > 0).unwrap_or(4096);
    pages.saturating_mul(page) / 1024 / 1024
}

/// What this process is holding. One lock over the whole list, taken for the few microseconds
/// a placement takes to decide.
static PLACED: Mutex<Vec<Outstanding>> = Mutex::new(Vec::new());

/// Source of [`Outstanding::id`], which need only be unique within this process.
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

/// A placement's claim on its node, from the moment it is chosen until the VMM that takes it
/// is spawned. Dropping it instead releases the node, so a boot that fails between the two
/// does not hold a node against the VMs after it.
#[derive(Debug)]
pub(crate) struct Ticket<'a> {
    registry: &'a Mutex<Vec<Outstanding>>,
    /// `None` once the placement has a VMM holding it, so the drop releases nothing.
    id: Option<u64>,
}

impl Ticket<'_> {
    /// The VMM took the placement: the claim stays, now under `pid`, and is swept once that
    /// process is gone.
    pub(crate) fn spawned(mut self, pid: u32) {
        let Some(id) = self.id.take() else { return };
        let mut placed = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = placed.iter_mut().find(|entry| entry.id == id) {
            entry.pid = Some(pid);
        }
    }
}

impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        let Some(id) = self.id else { return };
        let mut placed = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
        placed.retain(|entry| entry.id != id);
    }
}

/// Where the VM about to be spawned goes under the host's `[numa] mode`, with a [`Ticket`]
/// holding its node until the VMM has it. `None` — place nothing — under `mode = "off"` and
/// on a host with one memory node, which between them are nearly every host.
pub(crate) fn auto_place(cpus: u32, mem_mib: u64) -> Option<(Placement, Ticket<'static>)> {
    let topology = topology()?;
    let free = topology.free_mib();
    place(
        topology,
        |id| free.get(&id).copied(),
        &PLACED,
        mode(),
        cpus,
        mem_mib,
    )
}

/// [`auto_place`] against an explicit topology, per-node free-memory reader and registry, so
/// the accounting can be exercised on a host that has one node and no `/sys` to read.
fn place<'a>(
    topology: &Topology,
    free: impl Fn(u32) -> Option<u64>,
    registry: &'a Mutex<Vec<Outstanding>>,
    mode: NumaMode,
    cpus: u32,
    mem_mib: u64,
) -> Option<(Placement, Ticket<'a>)> {
    if mode == NumaMode::Off {
        return None;
    }
    let mut placed = registry.lock().unwrap_or_else(PoisonError::into_inner);
    // A VM this process placed and no longer runs is off its node. Swept here rather than
    // when it exits because nothing reports that: a `vk run` keeps its VMM for the session,
    // a build's stage guests come and go under it, and either way the next placement is the
    // first thing that cares.
    placed.retain(|entry| entry.pid.is_none_or(crate::spawn::pid_alive));
    let placement = match mode {
        NumaMode::Interleave => Placement::Interleave {
            nodes: topology.node_ids(),
        },
        _ => pick(
            topology,
            &load(topology, free, &placed),
            |node| node.mem_total_mib,
            mem_mib,
            cpus,
        ),
    };
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    placed.push(Outstanding {
        id,
        node: match &placement {
            Placement::Bind { node, .. } => Some(*node),
            Placement::Interleave { .. } => None,
        },
        mem_mib,
        pid: None,
    });
    Some((
        placement,
        Ticket {
            registry,
            id: Some(id),
        },
    ))
}

/// Node load is live used memory plus this process's allocations still to be faulted in
/// ([`Outstanding::remaining_mib`]), so resident VM memory is counted once.
fn load(
    topology: &Topology,
    free: impl Fn(u32) -> Option<u64>,
    placed: &[Outstanding],
) -> HashMap<u32, NodeLoad> {
    let mut load: HashMap<u32, NodeLoad> = topology
        .nodes
        .iter()
        .map(|node| {
            // A node whose free memory cannot be read counts as full: placing against a
            // figure that is not there is guessing at the one thing that decides.
            let used = node
                .mem_total_mib
                .saturating_sub(free(node.id).unwrap_or(0));
            (
                node.id,
                NodeLoad {
                    granted_mib: used,
                    jobs: 0,
                },
            )
        })
        .collect();
    let nodes_total = u64::try_from(topology.nodes.len()).unwrap_or(1);
    for entry in placed {
        let remaining = entry.remaining_mib();
        match entry.node {
            Some(id) => {
                if let Some(node) = load.get_mut(&id) {
                    node.granted_mib = node.granted_mib.saturating_add(remaining);
                    node.jobs = node.jobs.saturating_add(1);
                }
            }
            // An interleaved VM holds an equal share of every node, and weighs on each of
            // them — the same way the admission ledger counts one
            // ([`crate::admit::Reservation::place`]).
            None => {
                let share = remaining.checked_div(nodes_total).unwrap_or(0);
                for node in load.values_mut() {
                    node.granted_mib = node.granted_mib.saturating_add(share);
                    node.jobs = node.jobs.saturating_add(1);
                }
            }
        }
    }
    load
}

/// Describe the placement, adding the fallback reason when auto mode interleaves a VM.
pub(crate) fn announce(placement: &Placement) -> String {
    match (placement, mode()) {
        (Placement::Interleave { .. }, NumaMode::Auto) => {
            format!("{} (the VM does not fit one node)", placement.describe())
        }
        _ => placement.describe(),
    }
}

/// Place a VM wanting `want_mib` of RAM and `cpus` vCPUs, given what each node is already
/// carrying (`load`) and how much of it each may carry (`cap_mib_for`).
///
/// The emptiest node that still fits wins: filling one node before moving to the next would
/// pack more VMs onto a host, but every VM on a shared node contends for its memory
/// controller, so spreading is what keeps the placement worth having. Ties go to the node
/// running fewer VMs and then to the lowest id, so the choice is stable rather than dependent
/// on directory order. A VM that fits nowhere is interleaved — never refused: admission is the
/// gate that says no, and this only decides where what it admitted goes.
pub(crate) fn pick(
    topology: &Topology,
    load: &HashMap<u32, NodeLoad>,
    cap_mib_for: impl Fn(&Node) -> u64,
    want_mib: u64,
    cpus: u32,
) -> Placement {
    let nodes_total = topology.nodes_total();
    let best = topology
        .nodes
        .iter()
        .filter_map(|node| {
            if usize::try_from(cpus).unwrap_or(usize::MAX) > node.cpus.len() {
                return None;
            }
            let carried = load.get(&node.id).copied().unwrap_or_default();
            // Saturating throughout: these are figures parsed out of a ledger other processes
            // write, and a wrapped total would read as room where there is none.
            let headroom = cap_mib_for(node).saturating_sub(carried.granted_mib);
            (want_mib <= headroom).then_some((headroom, carried.jobs, node))
        })
        .min_by_key(|(headroom, jobs, node)| (std::cmp::Reverse(*headroom), *jobs, node.id));
    match best {
        Some((_, _, node)) => Placement::Bind {
            node: node.id,
            cpus: node.cpus.clone(),
            nodes_total,
        },
        None => Placement::Interleave {
            nodes: topology.node_ids(),
        },
    }
}

impl Placement {
    /// Apply this placement to `cmd`'s child, through a `pre_exec` hook — so it lands on the
    /// VMM alone and not on the shared spawner thread every child is forked from
    /// ([`crate::spawn::spawn_tied`]), whose policy the next child would otherwise inherit.
    ///
    /// Everything the hook needs is computed here, before the fork: the hook itself only makes
    /// syscalls, which is all a forked child may do before exec.
    pub(crate) fn apply(&self, cmd: &mut Command) {
        let (mode, nodes, affinity) = match self {
            // Preferred, not `MPOL_BIND`: a hard bind turns an allocation the node cannot
            // satisfy into reclaim and then an OOM kill on that node while the rest of the
            // host is roomy, and the per-node cap that is supposed to keep the node from
            // filling is only as good as the ledger it is computed from — on a host with no
            // `mem_budget` it is a `MemFree` reading that lags every VM admitted since. With
            // the vCPU threads pinned to the node, first touch already lands the guest's pages
            // there; preferring the node keeps that locality and lets an allocation the node
            // cannot take spill to another one instead of failing.
            Placement::Bind { node, cpus, .. } => (
                libc::MPOL_PREFERRED,
                nodemask(std::iter::once(*node)),
                Some(cpu_set(cpus)),
            ),
            Placement::Interleave { nodes } => {
                (libc::MPOL_INTERLEAVE, nodemask(nodes.iter().copied()), None)
            }
        };
        // The kernel takes `maxnode` as one past the last bit it may read, and copies whole
        // words, so this is exactly the mask built above.
        let maxnode = nodes.len().saturating_mul(MASK_BITS).saturating_add(1);
        use std::os::unix::process::CommandExt;
        // SAFETY: the hook runs in the forked child between fork and exec, where only
        // async-signal-safe work is allowed — two syscalls on memory already allocated.
        unsafe {
            cmd.pre_exec(move || {
                // Best-effort, and deliberately not reported: a host can refuse either call
                // for reasons that are none of this job's business — a cpuset cgroup the
                // runner sits in that excludes the chosen node's CPUs, a kernel built without
                // NUMA — and a VM that boots unplaced is slower, while a VM that does not boot
                // is a failed job. The placement is checked once from the parent instead
                // ([`landed`]), where saying so costs nothing.
                if let Some(set) = &affinity {
                    libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), set);
                }
                libc::syscall(
                    libc::SYS_set_mempolicy,
                    libc::c_long::from(mode),
                    nodes.as_ptr(),
                    maxnode as libc::c_ulong,
                );
                Ok(())
            });
        }
    }

    /// How this placement reads in a job trace.
    pub(crate) fn describe(&self) -> String {
        match self {
            Placement::Bind {
                node,
                cpus,
                nodes_total,
            } => format!(
                "node {node} (cpus {}) of {nodes_total}",
                format_list(cpus.iter().copied())
            ),
            Placement::Interleave { nodes } => {
                format!("interleaved across {} nodes", nodes.len())
            }
        }
    }
}

/// Whether `pid`'s affinity is the one a [`Placement::Bind`] asked for, by the mask the kernel
/// reports for it. `None` when there is nothing to check (an interleaved VM is left free to
/// roam) or the process is already gone — neither is a failed bind.
pub(crate) fn landed(pid: u32, placement: &Placement) -> Option<bool> {
    let Placement::Bind { cpus, .. } = placement else {
        return None;
    };
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status
        .lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))?;
    Some(parse_list(line)? == *cpus)
}

/// A kernel cpu/node list: `0`, `0-3`, `0,2-3`, `0-3,8-11`. Empty (a node with no CPUs) reads
/// as an empty list; anything else unparsable, or absurdly long, as `None`.
fn parse_list(text: &str) -> Option<Vec<usize>> {
    let mut out = Vec::new();
    let text = text.trim();
    if text.is_empty() {
        return Some(out);
    }
    for part in text.split(',') {
        let (first, last): (usize, usize) = match part.split_once('-') {
            Some((first, last)) => (first.trim().parse().ok()?, last.trim().parse().ok()?),
            None => {
                let only = part.trim().parse().ok()?;
                (only, only)
            }
        };
        // The id ceiling as well as the length: `99999999` on its own is one short list and
        // one absurd id, and it is the id a mask is sized from.
        if last < first || last >= MAX_LIST || out.len().saturating_add(last - first) >= MAX_LIST {
            return None;
        }
        out.extend(first..=last);
    }
    Some(out)
}

/// The inverse, for a cpu list in a log line.
fn format_list(cpus: impl Iterator<Item = usize>) -> String {
    let mut out = String::new();
    let mut run: Option<(usize, usize)> = None;
    let flush = |out: &mut String, (first, last): (usize, usize)| {
        if !out.is_empty() {
            out.push(',');
        }
        match first == last {
            true => out.push_str(&first.to_string()),
            false => out.push_str(&format!("{first}-{last}")),
        }
    };
    for cpu in cpus {
        run = match run {
            Some((first, last)) if cpu == last + 1 => Some((first, cpu)),
            Some(range) => {
                flush(&mut out, range);
                Some((cpu, cpu))
            }
            None => Some((cpu, cpu)),
        };
    }
    if let Some(range) = run {
        flush(&mut out, range);
    }
    out
}

/// One `nodeN/meminfo` field in kB, by its `Name:` prefix — the lines read
/// `Node 0 MemTotal:  31990836 kB`.
fn meminfo_field(text: &str, name: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let (_, rest) = line.split_once(name)?;
        rest.split_whitespace().next()?.parse().ok()
    })
}

/// A `set_mempolicy` nodemask naming `nodes`, sized from the highest of them rather than from
/// how many there are: the kernel reads whole words of it, so a mask narrower than the policy
/// names would have it read past the allocation, and node ids are not always dense. An id past
/// [`MAX_LIST`] is dropped rather than widening the mask without bound — the ids come from
/// `/sys`, but a [`Placement`] also arrives as JSON in a [`crate::vmm::VmSpec`].
fn nodemask(nodes: impl Iterator<Item = u32>) -> Vec<libc::c_ulong> {
    let nodes: Vec<usize> = nodes
        .filter_map(|node| usize::try_from(node).ok())
        .filter(|node| *node < MAX_LIST)
        .collect();
    let words = nodes
        .iter()
        .map(|node| node / MASK_BITS + 1)
        .max()
        .unwrap_or(1);
    let mut mask = vec![0; words];
    for node in nodes {
        if let Some(word) = mask.get_mut(node / MASK_BITS) {
            *word |= 1 << (node % MASK_BITS);
        }
    }
    mask
}

/// An affinity mask holding `cpus`. A CPU past what the kernel's fixed-size mask can name is
/// dropped rather than refused: the rest of the node is still the right place to run.
fn cpu_set(cpus: &[usize]) -> libc::cpu_set_t {
    // SAFETY: cpu_set_t is a plain bitmask with no invalid representation; CPU_ZERO then
    // initialises it properly anyway.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe { libc::CPU_ZERO(&mut set) };
    for &cpu in cpus {
        if cpu < libc::CPU_SETSIZE as usize {
            // SAFETY: `set` is owned here and `cpu` is in range for it.
            unsafe { libc::CPU_SET(cpu, &mut set) };
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-numa-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A fixture `/sys/devices/system/node` with `nodes` of `(cpulist, MemTotal MiB)`.
    fn fixture(name: &str, nodes: &[(&str, u64)]) -> PathBuf {
        let root = tmpdir(name);
        let online = match nodes.len() {
            1 => "0".to_string(),
            n => format!("0-{}", n - 1),
        };
        std::fs::write(root.join("online"), format!("{online}\n")).unwrap();
        for (id, (cpus, mem_mib)) in nodes.iter().enumerate() {
            let dir = root.join(format!("node{id}"));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("cpulist"), format!("{cpus}\n")).unwrap();
            std::fs::write(
                dir.join("meminfo"),
                format!(
                    "Node {id} MemTotal:       {} kB\nNode {id} MemFree:        {} kB\n",
                    mem_mib * 1024,
                    mem_mib * 1024 / 4
                ),
            )
            .unwrap();
        }
        root
    }

    fn topology(nodes: &[(u32, &[usize], u64)]) -> Topology {
        Topology::of(
            nodes
                .iter()
                .map(|(id, cpus, mem_total_mib)| Node {
                    id: *id,
                    cpus: cpus.to_vec(),
                    mem_total_mib: *mem_total_mib,
                })
                .collect(),
        )
    }

    fn load(entries: &[(u32, u64, usize)]) -> HashMap<u32, NodeLoad> {
        entries
            .iter()
            .map(|(id, granted_mib, jobs)| {
                (
                    *id,
                    NodeLoad {
                        granted_mib: *granted_mib,
                        jobs: *jobs,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn cpu_lists_parse() {
        assert_eq!(parse_list("0\n"), Some(vec![0]));
        assert_eq!(parse_list("0-1"), Some(vec![0, 1]));
        assert_eq!(parse_list("0,2-3\n"), Some(vec![0, 2, 3]));
        assert_eq!(parse_list("0-3,8-11"), Some(vec![0, 1, 2, 3, 8, 9, 10, 11]));
        assert_eq!(parse_list(""), Some(vec![]));
        assert_eq!(parse_list("3-0"), None);
        assert_eq!(parse_list("0-99999999"), None);
        // One entry, but an id no mask would be sized from.
        assert_eq!(parse_list("99999999"), None);
        assert_eq!(parse_list("a-b"), None);
    }

    #[test]
    fn cpu_lists_format() {
        assert_eq!(format_list([0].into_iter()), "0");
        assert_eq!(format_list([0, 1, 2, 3].into_iter()), "0-3");
        assert_eq!(format_list([0, 2, 3].into_iter()), "0,2-3");
        assert_eq!(format_list(std::iter::empty()), "");
    }

    #[test]
    fn a_two_node_host_is_read_and_a_single_node_one_is_not() {
        let root = fixture("two", &[("0-3", 16384), ("4-7", 8192)]);
        let topo = Topology::from_sysfs(&root).unwrap();
        assert_eq!(topo.nodes.len(), 2);
        assert_eq!(topo.nodes[0].cpus, vec![0, 1, 2, 3]);
        assert_eq!(topo.nodes[1].id, 1);
        assert_eq!(topo.nodes[1].mem_total_mib, 8192);
        assert_eq!(topo.free_mib().get(&1).copied(), Some(2048));

        // A single-node host has nothing to place, and so reads as no topology at all.
        assert!(Topology::from_sysfs(&fixture("one", &[("0-11", 32768)])).is_none());
        // Neither does an unreadable one.
        assert!(Topology::from_sysfs(&tmpdir("empty")).is_none());
    }

    #[test]
    fn the_emptiest_fitting_node_wins() {
        let topo = topology(&[(0, &[0, 1, 2, 3], 16384), (1, &[4, 5, 6, 7], 16384)]);
        let cap = |n: &Node| n.mem_total_mib;

        // Node 0 already carries a job, so the next one goes to node 1.
        assert_eq!(
            pick(&topo, &load(&[(0, 8192, 1)]), cap, 4096, 2),
            Placement::Bind {
                node: 1,
                cpus: vec![4, 5, 6, 7],
                nodes_total: 2,
            }
        );
        // Equal headroom: the node running fewer jobs, then the lowest id.
        assert_eq!(
            pick(&topo, &load(&[(0, 2048, 2), (1, 2048, 1)]), cap, 4096, 2),
            Placement::Bind {
                node: 1,
                cpus: vec![4, 5, 6, 7],
                nodes_total: 2,
            }
        );
        assert_eq!(
            pick(&topo, &load(&[]), cap, 4096, 2),
            Placement::Bind {
                node: 0,
                cpus: vec![0, 1, 2, 3],
                nodes_total: 2,
            }
        );
        // Too big for either node's memory, and too wide for either node's CPUs: interleaved
        // rather than refused.
        assert_eq!(
            pick(&topo, &load(&[]), cap, 24576, 2),
            Placement::Interleave { nodes: vec![0, 1] }
        );
        assert_eq!(
            pick(&topo, &load(&[]), cap, 4096, 6),
            Placement::Interleave { nodes: vec![0, 1] }
        );
        // A memory-only node never takes a VM's vCPUs, but still counts in the total.
        let lopsided = topology(&[(0, &[0, 1], 4096), (1, &[], 65536)]);
        assert_eq!(
            pick(&lopsided, &load(&[]), cap, 2048, 2),
            Placement::Bind {
                node: 0,
                cpus: vec![0, 1],
                nodes_total: 2,
            }
        );
    }

    #[test]
    fn a_narrower_cap_than_the_node_holds_it_back() {
        let topo = topology(&[(0, &[0, 1], 16384), (1, &[2, 3], 16384)]);
        // Half the host's memory budgeted: a job wanting more than half a node fits nowhere.
        let cap = |n: &Node| n.mem_total_mib / 2;
        assert_eq!(
            pick(&topo, &load(&[]), cap, 8193, 1),
            Placement::Interleave { nodes: vec![0, 1] }
        );
        // Exactly the cap still fits — the cap is what a node may carry, not what it must
        // stay under.
        assert_eq!(
            pick(&topo, &load(&[]), cap, 8192, 1),
            Placement::Bind {
                node: 0,
                cpus: vec![0, 1],
                nodes_total: 2,
            }
        );
    }

    /// Node ids need not be dense — a socket can be depopulated, or a memory-only node can sit
    /// past the ones with CPUs — and the interleave mask must name the ids that exist rather
    /// than the first few, since the kernel refuses a mask naming a node that is not online.
    #[test]
    fn a_host_with_sparse_node_ids_is_interleaved_over_the_ids_it_has() {
        let topo = topology(&[(0, &[0, 1], 4096), (2, &[2, 3], 4096)]);
        let placement = pick(&topo, &load(&[]), |n| n.mem_total_mib, 65536, 2);
        assert_eq!(placement, Placement::Interleave { nodes: vec![0, 2] });
        let Placement::Interleave { nodes } = &placement else {
            unreachable!()
        };
        assert_eq!(nodemask(nodes.iter().copied()), vec![0b101]);
    }

    #[test]
    fn nodemasks_name_the_nodes_they_are_given() {
        assert_eq!(nodemask(std::iter::once(0)), vec![0b01]);
        assert_eq!(nodemask(std::iter::once(1)), vec![0b10]);
        assert_eq!(nodemask(0..4), vec![0b1111]);
        // Sparse ids: the bits are the ids themselves, so a host with nodes 0 and 2 does not
        // get the offline node 1 named — a mask the kernel would refuse outright.
        assert_eq!(nodemask([0, 2].into_iter()), vec![0b101]);
        // Past one word: the mask grows, and the high node lands in the second.
        let wide = nodemask(std::iter::once(70));
        assert_eq!(wide.len(), 2);
        assert_eq!(wide[1], 1 << (70 - MASK_BITS));
        // An id no mask should be sized from is dropped, not honoured.
        assert_eq!(nodemask(std::iter::once(u32::MAX)), vec![0]);
    }

    /// Everything a whole node has, so a fixture places against the registry alone.
    fn all_free(node: u32, topology: &Topology) -> Option<u64> {
        topology
            .nodes
            .iter()
            .find(|n| n.id == node)
            .map(|n| n.mem_total_mib)
    }

    /// Two nodes of 16 GiB, four CPUs each.
    fn pair() -> Topology {
        topology(&[(0, &[0, 1, 2, 3], 16384), (1, &[4, 5, 6, 7], 16384)])
    }

    /// A process booting VM after VM does not hand them all the same node: a placement holds
    /// its node from the moment it is chosen, because the host will not report the memory as
    /// used until the guest has faulted it in — minutes after the next VM is placed.
    #[test]
    fn a_placement_holds_its_node_against_the_next_one() {
        let topo = pair();
        let registry = Mutex::new(Vec::new());
        let place = |mem_mib| {
            super::place(
                &topo,
                |node| all_free(node, &topo),
                &registry,
                NumaMode::Auto,
                2,
                mem_mib,
            )
        };
        let (first, held) = place(12288).expect("a two-node host places");
        assert!(matches!(first, Placement::Bind { node: 0, .. }));
        // Node 0 has 4 GiB left, which this one does not fit in.
        let (second, _second) = place(12288).unwrap();
        assert!(matches!(second, Placement::Bind { node: 1, .. }));

        // A boot that never happened releases its node: the ticket is dropped unspawned.
        drop(held);
        let (third, _third) = place(12288).unwrap();
        assert!(matches!(third, Placement::Bind { node: 0, .. }));
    }

    /// A VM whose VMM is gone stops holding its node. Nothing reports that a VM exited, so
    /// the next placement is what notices.
    #[test]
    fn a_placement_whose_vmm_is_gone_is_swept() {
        let topo = pair();
        let registry = Mutex::new(Vec::new());
        let place = |mem_mib| {
            super::place(
                &topo,
                |node| all_free(node, &topo),
                &registry,
                NumaMode::Auto,
                2,
                mem_mib,
            )
        };
        let mut child = Command::new("true").spawn().unwrap();
        let pid = child.id();
        let (first, ticket) = place(12288).unwrap();
        assert!(matches!(first, Placement::Bind { node: 0, .. }));
        ticket.spawned(pid);
        child.wait().unwrap();

        let (second, _second) = place(12288).unwrap();
        assert!(
            matches!(second, Placement::Bind { node: 0, .. }),
            "a dead VMM still held node 0: {second:?}"
        );
        assert_eq!(
            registry
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .len(),
            1
        );
    }

    /// A VM that has already faulted its RAM in is counted once, not twice: the pages it
    /// holds are gone from its node's `MemFree` and only the rest is still to come. Read
    /// against this test process, which is certainly resident for something.
    #[test]
    fn a_running_vm_is_counted_only_for_the_memory_it_has_not_touched() {
        let topo = pair();
        // Both nodes wholly free, so the live half of the figure contributes nothing and
        // what each node carries is the registry alone.
        let whole = |node| all_free(node, &topo);
        let me = std::process::id();
        assert!(rss_mib(me) > 0, "this process is resident for something");
        let on_node_0 = |mem_mib, pid| {
            vec![Outstanding {
                id: 0,
                node: Some(0),
                mem_mib,
                pid,
            }]
        };

        // No VMM yet: nothing of it has been faulted in, so all of it is still to come.
        let pending = super::load(&topo, whole, &on_node_0(8192, None));
        assert_eq!(pending[&0].granted_mib, 8192);
        // Spawned: what the VMM is already resident for is what the host has seen.
        let running = super::load(&topo, whole, &on_node_0(8192, Some(me)));
        assert!(
            running[&0].granted_mib < 8192,
            "a running VM was counted for its whole declared size: {}",
            running[&0].granted_mib
        );

        // Declared less than the VMM already holds: nothing left to come, rather than a
        // wrap that would read as a node no VM could ever fit on again.
        let small = super::load(&topo, whole, &on_node_0(1, Some(me)));
        assert_eq!(small[&0].granted_mib, 0);

        // And a size no subtraction can dent is still the remainder of it.
        let huge = super::load(&topo, whole, &on_node_0(u64::MAX, Some(me)));
        let taken = u64::MAX - huge[&0].granted_mib;
        assert!(
            taken > 0 && taken < 1024 * 1024,
            "{taken} MiB is not this process's resident size"
        );
    }

    #[test]
    fn the_mode_decides_what_a_boot_is_placed_as() {
        let topo = topology(&[(0, &[0, 1], 16384), (2, &[2, 3], 16384)]);
        let registry = Mutex::new(Vec::new());
        let place = |mode, cpus, mem_mib, free: fn(u32) -> Option<u64>| {
            super::place(&topo, free, &registry, mode, cpus, mem_mib).map(|(p, _)| p)
        };
        // Both nodes wholly free, so only the mode and the fit decide.
        let whole: fn(u32) -> Option<u64> = |_| Some(16384);

        assert_eq!(place(NumaMode::Off, 2, 1024, whole), None);
        // Every online id, not a count: a mask naming the offline node 1 is refused outright.
        assert_eq!(
            place(NumaMode::Interleave, 2, 1024, whole),
            Some(Placement::Interleave { nodes: vec![0, 2] })
        );
        // Wider than either node, so no node can hold its vCPUs.
        assert_eq!(
            place(NumaMode::Auto, 4, 1024, whole),
            Some(Placement::Interleave { nodes: vec![0, 2] })
        );
        // A node whose free memory cannot be read counts as full rather than empty.
        assert_eq!(
            place(NumaMode::Auto, 2, 1024, |node| (node != 0).then_some(16384)),
            Some(Placement::Bind {
                node: 2,
                cpus: vec![2, 3],
                nodes_total: 2,
            })
        );
    }

    /// `--numa` reaches the host's nodes: a mode needs none, a node id must name one.
    #[test]
    fn the_run_flag_resolves_against_the_host() {
        assert_eq!(NumaArg::parse("off"), Ok(NumaArg::Off));
        assert_eq!(NumaArg::parse("auto"), Ok(NumaArg::Auto));
        assert_eq!(NumaArg::parse("interleave"), Ok(NumaArg::Interleave));
        assert_eq!(NumaArg::parse("1"), Ok(NumaArg::Node(1)));
        assert!(NumaArg::parse("node1").is_err());
        assert!(NumaArg::parse("-1").is_err());

        assert_eq!(NumaArg::Off.resolve().unwrap(), Numa::Off);
        assert_eq!(NumaArg::Auto.resolve().unwrap(), Numa::Auto);
        // The rest depend on the host this runs on, which is single-node as often as not.
        match super::topology() {
            None => {
                assert_eq!(NumaArg::Interleave.resolve().unwrap(), Numa::Off);
                let err = NumaArg::Node(0).resolve().unwrap_err();
                assert!(format!("{err:#}").contains("one memory node"), "{err:#}");
            }
            Some(topology) => {
                assert_eq!(
                    NumaArg::Interleave.resolve().unwrap(),
                    Numa::Placed(Placement::Interleave {
                        nodes: topology.node_ids(),
                    })
                );
                let err = NumaArg::Node(u32::MAX).resolve().unwrap_err();
                assert!(format!("{err:#}").contains("no memory node"), "{err:#}");
            }
        }
    }

    /// The placement really reaches the child: a process spawned through [`Placement::apply`]
    /// runs on the CPUs the placement names and nothing else, and every mapping it has prefers
    /// the node. Against the real kernel, since it is the kernel that checks an affinity mask
    /// and a memory policy and no fixture can stand in for either.
    ///
    /// The CPUs are half of what this process may itself run on rather than a node's cpulist:
    /// a strict subset is what makes the check mean something — a hook that did nothing would
    /// pass against the full set — and it needs no `/sys`, so the test runs on a guest whose
    /// kernel publishes no node topology as well as on a host whose does. Node 0 is the node
    /// every kernel with NUMA has; one built without it refuses the policy, which is the
    /// best-effort case [`Placement::apply`] exists to survive, and publishes no `numa_maps`
    /// to check it against.
    #[test]
    fn a_bound_child_lands_on_the_node() {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let allowed = parse_list(
            status
                .lines()
                .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
                .unwrap(),
        )
        .unwrap();
        assert!(!allowed.is_empty());
        let cpus: Vec<usize> = allowed
            .iter()
            .copied()
            .take(allowed.len().div_ceil(2))
            .collect();
        let placement = Placement::Bind {
            node: 0,
            cpus,
            nodes_total: 1,
        };
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        placement.apply(&mut cmd);
        let mut child = cmd.spawn().unwrap();
        let pid = child.id();

        // The hook runs after the fork, so the mask may not be set the instant spawn returns.
        let mut landed = None;
        for _ in 0..100 {
            landed = super::landed(pid, &placement);
            if landed == Some(true) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let numa_maps = std::fs::read_to_string(format!("/proc/{pid}/numa_maps"));
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(landed, Some(true), "child {pid} did not take the affinity");
        // The memory policy is best-effort: `apply` does not report a refused `set_mempolicy`,
        // and a sandbox can refuse it (a seccomp filter that omits the call, a cpuset with no
        // say over the node) while still letting the affinity call through — leaving every
        // mapping on the task's default policy, indistinguishable from an `apply` that never
        // set one. Ask the kernel whether it lets *this* process set the same policy at all,
        // by the same path `apply` takes; only where it does is the child required to show it.
        let policy_honoured = {
            let nodes = nodemask(std::iter::once(0));
            let maxnode = nodes.len().saturating_mul(MASK_BITS).saturating_add(1);
            // SAFETY: a `set_mempolicy` on this thread with a mask that outlives the call,
            // then a restore to the default so the rest of the test allocates as before.
            unsafe {
                let set = libc::syscall(
                    libc::SYS_set_mempolicy,
                    libc::c_long::from(libc::MPOL_PREFERRED),
                    nodes.as_ptr(),
                    maxnode as libc::c_ulong,
                ) == 0;
                libc::syscall(
                    libc::SYS_set_mempolicy,
                    libc::c_long::from(libc::MPOL_DEFAULT),
                    std::ptr::null::<libc::c_ulong>(),
                    0,
                );
                set
            }
        };
        // The task's default policy is what /proc reports for every mapping that has none of
        // its own — which is every mapping a guest's RAM lives in.
        if let Ok(maps) = numa_maps {
            assert!(!maps.is_empty(), "child {pid} published an empty numa_maps");
            assert!(
                !policy_honoured || maps.lines().all(|l| l.contains(" prefer:0")),
                "unplaced mappings in numa_maps:\n{maps}"
            );
        }
    }

    #[test]
    fn a_named_interleave_is_not_announced_as_a_fallback() {
        // Explicit `vk run --numa interleave` uses `describe`; only auto placement uses
        // `announce`'s size fallback reason. MODE is Auto in tests.
        let interleave = Placement::Interleave { nodes: vec![0, 1] };
        assert_eq!(interleave.describe(), "interleaved across 2 nodes");
        assert_eq!(
            announce(&interleave),
            "interleaved across 2 nodes (the VM does not fit one node)"
        );
        let bind = Placement::Bind {
            node: 1,
            cpus: vec![24, 25, 26],
            nodes_total: 2,
        };
        // A bound placement reads the same either way — there is no fallback to explain.
        assert_eq!(bind.describe(), "node 1 (cpus 24-26) of 2");
        assert_eq!(announce(&bind), bind.describe());
    }
}
