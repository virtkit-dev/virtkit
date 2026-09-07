//! Stable host addresses for a dev environment's endpoints.
//!
//! An endpoint with `address = "auto"` is published on a loopback address that is the
//! environment's own: `127.0.<block>.<octet>`, one block per environment and one octet per
//! service in it (the primary counts as one), so the URL a runner announces stays the same
//! across restarts and never collides with another worktree's. Linux routes all of 127/8
//! locally, so nothing is configured on an interface.
//!
//! The allocation lives in `<state>/endpoints.json`. Choosing a block takes the global lock
//! all environments share, starts at a block derived from the state directory so worktrees
//! usually miss each other without coordination, and confirms a candidate two ways: no other
//! environment has written that block down, and every auto endpoint of the service binds on
//! it. The second test alone is not enough — a bind proves the block is free only until the
//! probe's listener is dropped, and the publisher takes the address later — so the recorded
//! blocks are what keeps two environments choosing at once apart. A wildcard listener
//! (`0.0.0.0:<port>`, or `[::]:<port>` with `IPV6_V6ONLY=0`) takes the port on every block,
//! and shows up here as every block failing. A remembered block is kept while anything is
//! published from the environment, moved only when it is taken by something else and nothing
//! of ours is live: an address never moves under a running relay.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::dev::plan::{EndpointPlan, Plan};

/// The allocation band: `127.0.<FIRST..=LAST>.x`, above the low blocks Debian and local
/// configuration commonly use.
pub(crate) const BLOCK_FIRST: u8 = 20;
pub(crate) const BLOCK_LAST: u8 = 250;

/// `<state>/endpoints.json`
pub(crate) const FILE: &str = "endpoints.json";

/// What an environment remembers: its block, and the octet each service got.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct Allocation {
    pub(crate) block: u8,
    /// service name → last octet; the primary is the empty key
    #[serde(default)]
    pub(crate) octets: BTreeMap<String, u8>,
}

impl Allocation {
    /// The address `service` (the primary for `None`) was given, if it has one.
    pub(crate) fn address(&self, service: Option<&str>) -> Option<Ipv4Addr> {
        let octet = *self.octets.get(service.unwrap_or(""))?;
        Some(Ipv4Addr::new(127, 0, self.block, octet))
    }

    /// The next free octet, 1 upwards.
    fn next_octet(&self) -> Result<u8> {
        (1..=254u8)
            .find(|o| !self.octets.values().any(|v| v == o))
            .context("no loopback octet left in this environment's block")
    }
}

fn path(plan: &Plan) -> PathBuf {
    plan.state_dir.join(FILE)
}

/// Where every environment's state directory lives, which is where the shared lock goes and
/// what the scan for other environments' allocations reads.
fn state_base(plan: &Plan) -> Result<PathBuf> {
    plan.state_dir
        .parent()
        .map(Path::to_path_buf)
        .with_context(|| format!("{} has no parent directory", plan.state_dir.display()))
}

/// The remembered allocation, or `None` before the first publish.
///
/// A file that is there but unreadable is an error and not "never allocated": answering the
/// latter moves the environment to a new block and changes every URL it publishes, which is
/// the one thing this module exists to prevent.
pub(crate) fn load(plan: &Plan) -> Result<Option<Allocation>> {
    let path = path(plan);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    serde_json::from_str(&text)
        .map(Some)
        .with_context(|| format!("parsing {}", path.display()))
}

/// Write the allocation through a private staging file in the state directory and publish
/// it by rename: a reader sees the previous allocation or the whole new one, never a
/// truncated file that would read as "never allocated".
fn save(plan: &Plan, alloc: &Allocation) -> Result<()> {
    let body = serde_json::to_vec_pretty(alloc)?;
    vk_fs::write_atomic(&path(plan), &body, 0o600)
}

/// The endpoints of `service` (the primary's for `None`) that have a publisher up.
fn published_names(plan: &Plan, service: Option<&str>) -> Vec<String> {
    let live: Vec<String> = crate::publish::live(&plan.state_dir)
        .unwrap_or_default()
        .into_iter()
        .map(|(e, _)| e.name)
        .collect();
    plan.endpoints
        .iter()
        .filter(|e| e.service.as_deref() == service && live.contains(&e.name))
        .map(|e| e.name.clone())
        .collect()
}

/// How a service is named in a message.
fn named(service: Option<&str>) -> String {
    match service {
        Some(s) => format!("service {s}"),
        None => "the environment's own endpoints".into(),
    }
}

/// Drop `service`'s octet (the primary's for `None`), so its next publish picks another.
/// For when a publish finds its address taken after all.
///
/// The block and every other service's octet stay: their relays are up on addresses in it,
/// and moving those under them is what this module promises never happens. For the same
/// reason this is a no-op while `service` itself still has a publisher up — the octet is not
/// free to give away while something answers on it.
pub(crate) fn forget(plan: &Plan, service: Option<&str>) {
    let still_up = published_names(plan, service);
    if !still_up.is_empty() {
        eprintln!(
            "virtkit: {} keeps its address: {} still published",
            named(service),
            still_up.join(", ")
        );
        return;
    }
    let mut alloc = match load(plan) {
        Ok(Some(alloc)) => alloc,
        Ok(None) => return,
        Err(e) => {
            eprintln!("virtkit: the endpoint allocation was left alone: {e:#}");
            return;
        }
    };
    if alloc.octets.remove(service.unwrap_or("")).is_none() {
        return;
    }
    if let Err(e) = save(plan, &alloc) {
        eprintln!("virtkit: the endpoint allocation was left alone: {e:#}");
    }
}

/// The lock every allocation takes, so two environments choosing at once cannot both
/// confirm the same block between the test bind and the publish.
fn global_lock(plan: &Plan) -> Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    let base = state_base(plan)?;
    std::fs::create_dir_all(&base).with_context(|| format!("creating {}", base.display()))?;
    let path = base.join(".endpoints.lock");
    let f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    // SAFETY: flock on an fd this process owns; blocks until the lock is ours.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error()).context("locking the endpoint allocator");
    }
    Ok(f)
}

/// The blocks the other environments on this host have written down. Read under the global
/// lock: an environment that confirmed a block a moment ago and has not published on it yet
/// is invisible to a bind probe, and this is what keeps the next chooser off it.
fn blocks_taken_elsewhere(plan: &Plan) -> Result<BTreeSet<u8>> {
    let base = state_base(plan)?;
    let ours = std::fs::canonicalize(&plan.state_dir).unwrap_or_else(|_| plan.state_dir.clone());
    let Ok(entries) = std::fs::read_dir(&base) else {
        return Ok(BTreeSet::new());
    };
    Ok(entries
        .flatten()
        .map(|e| e.path())
        .filter(|dir| std::fs::canonicalize(dir).unwrap_or_else(|_| dir.clone()) != ours)
        .filter_map(|dir| std::fs::read_to_string(dir.join(FILE)).ok())
        .filter_map(|text| serde_json::from_str::<Allocation>(&text).ok())
        .map(|alloc| alloc.block)
        .collect())
}

/// Whether every `port` can be bound on `addr` right now.
fn bindable(addr: Ipv4Addr, ports: &[u16]) -> bool {
    ports
        .iter()
        .all(|&p| TcpListener::bind(SocketAddrV4::new(addr, p)).is_ok())
}

/// The block the scan starts at, derived from the state directory.
fn preferred_block(state_dir: &Path) -> u8 {
    use sha2::{Digest, Sha256};
    use std::os::unix::ffi::OsStrExt;
    let digest = Sha256::digest(state_dir.as_os_str().as_bytes());
    let span = u32::from(BLOCK_LAST - BLOCK_FIRST) + 1;
    let offset = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % span;
    BLOCK_FIRST + offset as u8
}

/// The `auto` endpoints of `service` (the primary for `None`).
fn auto_endpoints<'a>(plan: &'a Plan, service: Option<&str>) -> Vec<&'a EndpointPlan> {
    plan.endpoints
        .iter()
        .filter(|e| e.auto() && e.service.as_deref() == service)
        .collect()
}

/// The address `service`'s auto endpoints publish on, allocating it if need be. `live` says
/// whether anything is published from this environment right now, which pins the block.
///
/// Only the ports no relay of ours holds yet are probed: our own publisher answering on a
/// port is exactly what a bind cannot tell apart from a stranger holding it, and would
/// otherwise condemn every block.
pub(crate) fn allocate(plan: &Plan, service: Option<&str>, live: bool) -> Result<Ipv4Addr> {
    let published = published_names(plan, service);
    let ports: Vec<u16> = auto_endpoints(plan, service)
        .iter()
        .filter(|e| !published.contains(&e.name))
        .map(|e| e.host_port)
        .collect();
    let _lock = global_lock(plan)?;
    let mut alloc = load(plan)?;
    if let Some(a) = &alloc
        && let Some(addr) = a.address(service)
    {
        if bindable(addr, &ports) {
            return Ok(addr);
        }
        // Something else took a port on our own address. With relays of ours up on this
        // block, moving is not on the table — an address never moves under a running relay
        // — so this is the caller's to resolve.
        if live {
            bail!(
                "{addr} cannot bind {ports:?}, and the environment's block is pinned while its \
                 relays are up — free the port, or stop the environment so its endpoints can \
                 move to another block"
            );
        }
        eprintln!(
            "virtkit: 127.0.{}.0/24 is taken by something else now — moving the environment's \
             endpoints to a free block",
            a.block
        );
        alloc = None;
    }
    let mut alloc = match alloc {
        // A block this environment holds: the service just needs an octet in it.
        Some(a) if a.address(service).is_none() => a,
        _ => {
            let elsewhere = blocks_taken_elsewhere(plan)?;
            let span = u32::from(BLOCK_LAST - BLOCK_FIRST) + 1;
            let start = u32::from(preferred_block(&plan.state_dir) - BLOCK_FIRST);
            let block = (0..span)
                .map(|i| BLOCK_FIRST + ((start + i) % span) as u8)
                .find(|b| !elsewhere.contains(b) && bindable(Ipv4Addr::new(127, 0, *b, 1), &ports))
                .with_context(|| {
                    format!(
                        "every 127.0.<{BLOCK_FIRST}-{BLOCK_LAST}>.x block is another \
                         environment's or already has a listener on one of the ports {ports:?}; \
                         a wildcard listener (0.0.0.0:<port>, or [::]:<port> with \
                         IPV6_V6ONLY=0) takes every block at once, so look for one of those \
                         first — and `vk dev list` names the environments"
                    )
                })?;
            Allocation {
                block,
                octets: BTreeMap::new(),
            }
        }
    };
    let octet = alloc.next_octet()?;
    let addr = Ipv4Addr::new(127, 0, alloc.block, octet);
    if !bindable(addr, &ports) {
        bail!(
            "{addr} cannot bind {ports:?}, though the block was free a moment ago — retry, \
             or look for a listener that came up on it"
        );
    }
    alloc
        .octets
        .insert(service.unwrap_or("").to_string(), octet);
    // Recorded before the lock goes: the next environment to choose reads this file, and a
    // block confirmed only by a probe's listener is free again the moment that drops.
    save(plan, &alloc)?;
    Ok(addr)
}

/// One endpoint as it stands on this host.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct View {
    pub(crate) name: String,
    pub(crate) service: Option<String>,
    /// `tcp://<address>:<port>`, or `None` for an auto address not allocated yet
    pub(crate) listen: Option<String>,
    pub(crate) to: String,
    /// `<scheme>://<address>:<port><path>`, when the endpoint names a scheme and has an address
    pub(crate) url: Option<String>,
    pub(crate) required: bool,
    pub(crate) published: bool,
}

/// The host address of `ep` as configured or remembered — never allocating.
pub(crate) fn address_of(alloc: Option<&Allocation>, ep: &EndpointPlan) -> Option<String> {
    if ep.auto() {
        alloc?.address(ep.service.as_deref()).map(|a| a.to_string())
    } else {
        Some(ep.address.clone())
    }
}

/// `tcp://<address>:<port>` for `ep` on `address`.
pub(crate) fn listen_on(ep: &EndpointPlan, address: &str) -> String {
    format!("tcp://{address}:{}", ep.host_port)
}

/// The URL `ep` is reached at on `address`, if it names a scheme.
pub(crate) fn url_on(ep: &EndpointPlan, address: &str) -> Option<String> {
    let scheme = ep.scheme.as_deref()?;
    Some(format!(
        "{scheme}://{address}:{}{}",
        ep.host_port,
        ep.path.as_deref().unwrap_or("")
    ))
}

/// Which endpoints a caller is asking about.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Which<'a> {
    /// every endpoint the plan declares
    All,
    /// the primary's own — those no compose service claims
    Primary,
    /// one compose service's, whatever it is called
    Service(&'a str),
}

/// The endpoints `which` selects, with each one's address and whether a publisher is live
/// for it. Reads only.
pub(crate) fn views(plan: &Plan, which: Which<'_>) -> Vec<View> {
    // A listing answers with what it can rather than failing: an unreadable allocation costs
    // the address column, and the note says why it is empty.
    let alloc = load(plan).unwrap_or_else(|e| {
        eprintln!("virtkit: no endpoint address to report: {e:#}");
        None
    });
    let live: Vec<String> = crate::publish::live(&plan.state_dir)
        .unwrap_or_default()
        .into_iter()
        .map(|(e, _)| e.name)
        .collect();
    plan.endpoints
        .iter()
        .filter(|e| match which {
            Which::All => true,
            Which::Primary => e.service.is_none(),
            Which::Service(name) => e.service.as_deref() == Some(name),
        })
        .map(|e| {
            let address = address_of(alloc.as_ref(), e);
            View {
                name: e.name.clone(),
                service: e.service.clone(),
                listen: address.as_deref().map(|a| listen_on(e, a)),
                url: address.as_deref().and_then(|a| url_on(e, a)),
                to: e.to.clone(),
                required: e.required,
                published: live.contains(&e.name),
            }
        })
        .collect()
}

/// `vk dev endpoints` as text: one row per endpoint, in the same table the other dev
/// listings use.
pub(crate) fn render(views: &[View]) -> String {
    if views.is_empty() {
        return "no endpoints configured\n".into();
    }
    let rows: Vec<Vec<String>> = views
        .iter()
        .map(|v| {
            vec![
                v.name.clone(),
                v.service.clone().unwrap_or_default(),
                v.url
                    .clone()
                    .or_else(|| v.listen.clone())
                    .unwrap_or_else(|| "(address allocated when published)".into()),
                v.to.clone(),
                match v.published {
                    true => "published".into(),
                    false => "not published".to_string(),
                },
            ]
        })
        .collect();
    crate::dev::list::table(&["NAME", "SERVICE", "ADDRESS", "TO", "STATE"], &rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::plan::Source;

    fn plan_in(dir: &Path, endpoints: Vec<EndpointPlan>) -> Plan {
        Plan {
            workspace: dir.join("ws"),
            config: dir.join("ws/.virtkit/config.toml"),
            environment: "dev".into(),
            state_dir: dir.join("state"),
            source: Source::Image {
                reference: "debian:13".into(),
            },
            workspace_folder: Some("/w".into()),
            user: None,
            freshness: crate::dev::config::Freshness::Ask,
            cpus: None,
            mem: None,
            mounts: vec![],
            container_env: vec![],
            exec_env: vec![],
            endpoints,
            host_exec: None,
            ssh_agent: false,
            cache: Default::default(),
            requires: Default::default(),
            cached_only: false,
            fallback_target: None,
            tasks: Vec::new(),
            hooks: Default::default(),
            vscode: None,
            managed_dirs: vec![],
            unresolved: vec![],
            secrets: Default::default(),
        }
    }

    fn ep(name: &str, service: Option<&str>, port: u16, scheme: Option<&str>) -> EndpointPlan {
        EndpointPlan {
            name: name.into(),
            service: service.map(String::from),
            host_port: port,
            address: "auto".into(),
            listen: format!("tcp://auto:{port}"),
            to: format!("tcp://{}:{port}", service.unwrap_or("127.0.0.1")),
            scheme: scheme.map(String::from),
            path: scheme.map(|_| "/ui".to_string()),
            required: false,
        }
    }

    struct Tmp(PathBuf);
    impl Tmp {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A scratch tree whose `state` directory sits in a base of its own: the allocator takes
    /// its shared lock and reads its neighbours' allocations beside the state directory it is
    /// given, so nothing here touches the host's own environments.
    fn scratch(name: &str) -> Tmp {
        let dir = std::env::temp_dir().join(format!("vk-endpoints-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("state")).unwrap();
        Tmp(dir)
    }

    /// A port free on this host, held for as long as the returned listener lives — on
    /// `127.0.0.1` only, so the allocator can still bind it on a `127.0.<block>.x` address
    /// while no other test in this binary can be handed the same number. Two tests taking
    /// the same ephemeral port is otherwise a coin toss they both lose.
    ///
    /// Fixed ports would make these tests fail on a machine that happens to hold one, and
    /// the allocator's own probe binds on every block anyway.
    fn free_port() -> (TcpListener, u16) {
        let held = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = held.local_addr().unwrap().port();
        (held, port)
    }

    #[test]
    fn allocation_is_stable_per_service_and_remembered() {
        let t = scratch("stable");
        let ((_h1, https), (_h2, web)) = (free_port(), free_port());
        let plan = plan_in(
            t.path(),
            vec![
                ep("r.https", Some("runner"), https, Some("https")),
                ep("r2.https", Some("runner-2"), https, Some("https")),
                ep("web", None, web, None),
            ],
        );
        let a = allocate(&plan, Some("runner"), false).unwrap();
        let b = allocate(&plan, Some("runner-2"), false).unwrap();
        let c = allocate(&plan, None, false).unwrap();
        // One block, one octet each, in allocation order; re-asking answers the same.
        assert_eq!(a.octets()[..3], b.octets()[..3]);
        assert_eq!((a.octets()[3], b.octets()[3], c.octets()[3]), (1, 2, 3));
        assert_eq!(allocate(&plan, Some("runner"), false).unwrap(), a);
        let remembered = load(&plan).unwrap().unwrap();
        assert_eq!(remembered.address(Some("runner")), Some(a));
        assert_eq!(remembered.address(None), Some(c));
        assert_eq!(remembered.block, a.octets()[2]);
        assert!(
            (BLOCK_FIRST..=BLOCK_LAST).contains(&remembered.block),
            "{remembered:?}"
        );
        // The file is the environment's own and nobody else's to read.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path(&plan)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        // The views name the addresses without allocating anything more.
        let views = views(&plan, Which::Service("runner"));
        assert_eq!(views.len(), 1);
        assert_eq!(
            views[0].url.as_deref(),
            Some(&*format!("https://{a}:{https}/ui"))
        );
        assert_eq!(
            views[0].listen.as_deref(),
            Some(&*format!("tcp://{a}:{https}"))
        );
        assert!(!views[0].published);
    }

    #[test]
    fn a_block_another_environment_wrote_down_is_not_offered_again() {
        // Two environments in one base, with the same ports and nothing published: the
        // second must miss the first's block on the strength of its `endpoints.json` alone,
        // since the probe that confirmed it dropped its listener on the way out.
        let t = scratch("neighbours");
        let (_held, port) = free_port();
        let mut first = plan_in(t.path(), vec![ep("web", None, port, None)]);
        first.state_dir = t.path().join("one");
        std::fs::create_dir_all(&first.state_dir).unwrap();
        let mut second = first.clone();
        second.state_dir = t.path().join("two");
        std::fs::create_dir_all(&second.state_dir).unwrap();

        let a = allocate(&first, None, false).unwrap();
        let b = allocate(&second, None, false).unwrap();
        assert_ne!(a.octets()[2], b.octets()[2], "a block each: {a} and {b}");
        // Each still answers with its own, and neither took the other into account twice.
        assert_eq!(allocate(&first, None, false).unwrap(), a);
        assert_eq!(allocate(&second, None, false).unwrap(), b);
    }

    #[test]
    fn forget_drops_one_services_octet_and_leaves_the_block() {
        let t = scratch("forget-one");
        let ((_ha, a_port), (_hb, b_port)) = (free_port(), free_port());
        let plan = plan_in(
            t.path(),
            vec![
                ep("a.web", Some("a"), a_port, None),
                ep("b.web", Some("b"), b_port, None),
            ],
        );
        let a = allocate(&plan, Some("a"), false).unwrap();
        let b = allocate(&plan, Some("b"), false).unwrap();

        forget(&plan, Some("a"));
        let left = load(&plan).unwrap().unwrap();
        assert_eq!(left.address(Some("b")), Some(b), "b keeps its address");
        assert_eq!(left.address(Some("a")), None, "a lost only its own");
        assert_eq!(left.block, a.octets()[2], "and the block stayed");
        // The next allocation for `a` takes a free octet in the same block.
        let again = allocate(&plan, Some("a"), false).unwrap();
        assert_eq!(again.octets()[2], a.octets()[2]);
        assert_ne!(again, b);
    }

    #[test]
    fn an_unreadable_allocation_is_an_error_and_not_a_fresh_start() {
        let t = scratch("corrupt");
        let (_held, port) = free_port();
        let plan = plan_in(t.path(), vec![ep("web", None, port, None)]);
        assert!(load(&plan).unwrap().is_none(), "nothing written yet");
        let first = allocate(&plan, None, false).unwrap();
        // Half a file — what a crash mid-write would once have left.
        std::fs::write(path(&plan), "{\"block\": 2").unwrap();
        let e = load(&plan).unwrap_err();
        assert!(format!("{e:#}").contains("endpoints.json"), "{e:#}");
        // And the allocator refuses rather than moving every published URL.
        let e = allocate(&plan, None, false).unwrap_err();
        assert!(format!("{e:#}").contains("endpoints.json"), "{e:#}");
        // Nothing was rewritten behind the error, so the file is still there to repair.
        assert_eq!(
            std::fs::read_to_string(path(&plan)).unwrap(),
            "{\"block\": 2"
        );
        assert!(first.is_loopback());
    }

    #[test]
    fn a_taken_block_moves_unless_something_of_ours_is_live() {
        let t = scratch("taken");
        let (_held, port) = free_port();
        let plan = plan_in(t.path(), vec![ep("web", None, port, None)]);
        let first = allocate(&plan, None, false).unwrap();
        // Something else squats our address:port while nothing of ours is published.
        let squatter = TcpListener::bind(SocketAddrV4::new(first, port)).unwrap();
        let moved = allocate(&plan, None, false).unwrap();
        assert_ne!(moved, first);
        assert_ne!(moved.octets()[2], first.octets()[2], "a different block");
        // With relays of ours live the block is pinned, so a squatter on the port is the
        // caller's to clear rather than a reason to move an address under a running relay.
        let squatter2 = TcpListener::bind(SocketAddrV4::new(moved, port)).unwrap();
        let e = allocate(&plan, None, true).unwrap_err();
        assert!(
            format!("{e:#}").contains("pinned while its relays are up"),
            "{e:#}"
        );
        drop(squatter2);
        assert_eq!(allocate(&plan, None, true).unwrap(), moved);
        drop(squatter);
        // Forgetting drops the octet, not the block: the next allocation is in the block
        // this environment already holds.
        forget(&plan, None);
        assert_eq!(load(&plan).unwrap().unwrap().octets, BTreeMap::new());
        assert_eq!(allocate(&plan, None, false).unwrap(), moved);
    }

    #[test]
    fn preferred_blocks_stay_in_band_and_differ_by_state_dir() {
        let a = preferred_block(Path::new("/s/one"));
        let b = preferred_block(Path::new("/s/two"));
        assert!((BLOCK_FIRST..=BLOCK_LAST).contains(&a));
        assert!((BLOCK_FIRST..=BLOCK_LAST).contains(&b));
        assert_eq!(a, preferred_block(Path::new("/s/one")));
        // Not a proof, but two paths landing on one block would be a 1/231 coincidence.
        assert_ne!(a, b);
    }

    #[test]
    fn render_shows_urls_addresses_and_state() {
        let views = vec![
            View {
                name: "r.https".into(),
                service: Some("runner".into()),
                listen: Some("tcp://127.0.20.1:8443".into()),
                to: "tcp://runner:443".into(),
                url: Some("https://127.0.20.1:8443/ui".into()),
                required: true,
                published: true,
            },
            View {
                name: "web".into(),
                service: None,
                listen: None,
                to: "tcp://127.0.0.1:8080".into(),
                url: None,
                required: false,
                published: false,
            },
        ];
        let text = render(&views);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            "NAME     SERVICE  ADDRESS                             TO                    STATE"
        );
        assert_eq!(
            lines[1],
            "r.https  runner   https://127.0.20.1:8443/ui          tcp://runner:443      published"
        );
        assert_eq!(
            lines[2],
            "web               (address allocated when published)  tcp://127.0.0.1:8080  not published"
        );
        assert_eq!(render(&[]), "no endpoints configured\n");
    }
}
