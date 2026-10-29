//! Capacity arbitration for queued jobs and reservation tickets.

use super::*;

/// Bound the work under the dispatch lock; the next pass continues arbitration.
const MAX_PLACEMENTS_PER_STEP: usize = 64;

/// How long after a claim a heartbeat of the claiming session must be received to reclaim an
/// admission it leaves out: one taken before the relay listed the claim may arrive after it.
const UNLISTED_GRACE: Duration = Duration::from_secs(10);

/// Grace for a node to answer an abandoned probe offer. On expiry, end its session once
/// so it reports and releases what it holds on reconnect, and stop counting the probe
/// against the shared probe budget.
pub(super) const ABANDONED_PROBE_GRACE: Duration = Duration::from_secs(30);

/// Why [`admission_node`] found no node: none outside `skip` has room, or only nodes in `skip`
/// (not `excluded`) would admit it: asked again after the pause.
pub(super) const NO_FITTING_NODE: &str = "no fitting node";

/// Why a queued job waits: its tenant no longer lists its project ([`delisted`]).
const DELISTED: &str = "project no longer listed for its tenant";

/// Whether `row` is a relay job whose project its tenant no longer lists (it was checked at
/// submission). Such a job is held with its reservation, to start once the project is listed
/// again or end at its deadline. A job recorded without a scheduling identity predates project
/// lists and is not held.
pub(super) fn delisted(policy: &crate::policy::Policy, row: &JobRow) -> bool {
    row.scheduling.as_ref().is_some_and(|identity| {
        identity
            .gitlab
            .as_deref()
            .zip(row.project_id)
            .is_some_and(|(gitlab, project)| {
                policy.project(&identity.tenant, gitlab, project).is_none()
            })
    })
}

/// Why [`admission_node`] found no node: each with room would take the room a headroom entry
/// keeps for production.
pub(super) const PRODUCTION_HEADROOM: &str = "production headroom";

/// Fleet room reserved by the policy's headroom entries for [`admission_node`]. Read on the
/// first normal admission and cached until the next placement changes it ([`Kept::new`] again).
pub(super) struct Kept<'a> {
    hub: &'a Hub,
    nodes: &'a [(String, NodeRow)],
    policy: &'a crate::policy::Policy,
    read: std::cell::OnceCell<KeptRooms>,
}

/// Fleet room for each headroom placement, merging identical placements at their greatest
/// slot count.
struct KeptRooms {
    entries: Vec<KeptEntry>,
    /// Each node's placed work, as [`placed`] counts it.
    placed: HashMap<String, u64>,
    /// Whether an envelope, by node index in [`Kept::nodes`] and size, leaves each entry its
    /// slots: each node and envelope is judged once until the next placement.
    memo: std::cell::RefCell<HashMap<(usize, u64, u32, u64), bool>>,
}

struct KeptEntry {
    placement: Placement,
    slots: u32,
    /// The placement's room on each node with any, and their sum.
    on: HashMap<String, u64>,
    total: u64,
}

impl<'a> Kept<'a> {
    pub(super) fn new(
        hub: &'a Hub,
        nodes: &'a [(String, NodeRow)],
        policy: &'a crate::policy::Policy,
    ) -> Self {
        Kept {
            hub,
            nodes,
            policy,
            read: std::cell::OnceCell::new(),
        }
    }

    fn read(&self, state: &State) -> &KeptRooms {
        self.read.get_or_init(|| {
            // Share one tally pass over the dispatch state across all entries.
            let tallies = tallies(state);
            let mut entries: Vec<KeptEntry> = Vec::new();
            for headroom in &self.policy.headroom {
                if let Some(entry) = entries
                    .iter_mut()
                    .find(|e| e.placement == headroom.placement)
                {
                    entry.slots = entry.slots.max(headroom.slots);
                    continue;
                }
                let found = rooms_with(
                    self.hub,
                    state,
                    self.nodes,
                    &headroom.placement,
                    &HashSet::new(),
                    &tallies,
                );
                let on: HashMap<String, u64> = found
                    .into_iter()
                    .map(|(node, _, room, _)| (node.to_owned(), room))
                    .collect();
                let total = on.values().fold(0u64, |sum, n| sum.saturating_add(*n));
                entries.push(KeptEntry {
                    placement: headroom.placement.clone(),
                    slots: headroom.slots,
                    on,
                    total,
                });
            }
            let placed = tallies
                .into_iter()
                .map(|(node, t)| (node.to_owned(), t.placed))
                .collect();
            KeptRooms {
                entries,
                placed,
                memo: std::cell::RefCell::default(),
            }
        })
    }

    /// Whether `admission` may go to `node`: production work anywhere; normal work where it
    /// preserves each entry's slots, or all remaining room if already short. An entry with
    /// no room on `node` does not block it.
    pub(super) fn admits(
        &self,
        state: &State,
        admission: (&Placement, crate::policy::Class),
        node: &str,
    ) -> bool {
        let (placement, class) = admission;
        if class == crate::policy::Class::Production || self.policy.headroom.is_empty() {
            return true;
        }
        let Some(at) = self.nodes.iter().position(|(id, _)| id == node) else {
            return false;
        };
        let read = self.read(state);
        let e = placement.envelope;
        let key = (at, e.mem_mib, e.cpus, e.disk_bytes);
        if let Some(&kept) = read.memo.borrow().get(&key) {
            return kept;
        }
        let row = &self.nodes[at].1;
        let placed = read
            .placed
            .get(node)
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        let kept = read.entries.iter().all(|entry| {
            let before = entry.on.get(node).copied().unwrap_or(0);
            if before == 0 {
                return true;
            }
            let p = &entry.placement;
            let after = room(self.hub, state, node, row, p, placed, Some(e)).unwrap_or(0);
            let left = entry.total.saturating_sub(before).saturating_add(after);
            left >= u64::from(entry.slots).min(entry.total)
        });
        read.memo.borrow_mut().insert(key, kept);
        kept
    }
}

/// Choose a node for `admission`, a placement and its class. `found` contains nodes with room
/// in [`candidates`] order: the first outside `skip` that [`Kept::admits`] it. `Err` says why
/// there is none: [`NO_FITTING_NODE`] too when only nodes in `skip` but not in `excluded`
/// would admit it, so that the caller asks them again after a pause, as for nodes that all
/// refused it; [`PRODUCTION_HEADROOM`] when none would.
fn admission_node(
    state: &State,
    kept: &Kept<'_>,
    admission: (&Placement, crate::policy::Class),
    found: &[(String, u64)],
    skip: &HashSet<String>,
    excluded: &HashSet<String>,
) -> std::result::Result<String, &'static str> {
    let (open, skipped): (Vec<_>, Vec<_>) = found
        .iter()
        .map(|(node, _)| node)
        .filter(|node| !excluded.contains(*node))
        .partition(|node| !skip.contains(*node));
    if open.is_empty() {
        return Err(NO_FITTING_NODE);
    }
    if let Some(node) = open.iter().find(|node| kept.admits(state, admission, node)) {
        return Ok((*node).clone());
    }
    if skipped
        .iter()
        .any(|node| kept.admits(state, admission, node))
    {
        Err(NO_FITTING_NODE)
    } else {
        Err(PRODUCTION_HEADROOM)
    }
}

fn blocked(state: &mut State, id: &str, reason: &'static str) {
    if let Some(ticket) = state.tickets.get_mut(id) {
        ticket.blocked = Some(reason);
    }
}

/// Whether a ticket in `phase` holds capacity: offered, granted, claimed or taken by a job.
fn holds(phase: &TicketPhase) -> bool {
    matches!(
        phase,
        TicketPhase::Offering { .. }
            | TicketPhase::Granted { .. }
            | TicketPhase::Claimed { .. }
            | TicketPhase::Job
    )
}

/// The runner a probing ticket probes for: its GitLab instance and runner ID.
fn probe_of(ticket: &Ticket) -> Option<(String, u64)> {
    ticket
        .probe
        .then(|| {
            ticket
                .identity
                .gitlab
                .clone()
                .zip(ticket.identity.runner_id)
        })
        .flatten()
}

pub(super) type RelayStates = [(
    String,
    crate::store::RelayRow,
    Option<vk_hub_proto::gitlab::ServerStatus>,
)];

pub(super) struct ScheduleCtx<'a> {
    pub(super) place: PlaceCtx<'a>,
    pub(super) policy: &'a crate::policy::Policy,
    pub(super) relays: &'a RelayStates,
    /// [`Hub::heartbeat_receipts`], read before `relays`.
    pub(super) heartbeats: &'a HashMap<String, (u64, Instant)>,
}

/// What a pass reads of the relays, once.
struct Relays<'a> {
    by_id: HashMap<
        &'a str,
        (
            &'a crate::store::RelayRow,
            &'a Option<vk_hub_proto::gitlab::ServerStatus>,
        ),
    >,
    /// The request and job admissions each relay's last heartbeat lists, for those whose
    /// heartbeat accounts for every runner and every request it holds.
    listed: HashMap<&'a str, (HashSet<&'a str>, HashSet<&'a str>)>,
    /// Each relay runner's jobs without an admission, by its last heartbeat.
    unadmitted: HashMap<(&'a str, &'a str), u64>,
    /// Those jobs, summed by relay.
    unadmitted_by_relay: HashMap<&'a str, u64>,
    /// When each relay's session last stored a heartbeat received, as
    /// [`ScheduleCtx::heartbeats`].
    heartbeats: &'a HashMap<String, (u64, Instant)>,
}

impl<'a> Relays<'a> {
    fn new(relays: &'a RelayStates, heartbeats: &'a HashMap<String, (u64, Instant)>) -> Self {
        let by_id = relays
            .iter()
            .map(|(id, row, status)| (id.as_str(), (row, status)))
            .collect();
        // A relay's jobs may outnumber its job admissions: those taken before it upgraded have
        // none, and are charged as such.
        let listed: HashMap<&str, (HashSet<&str>, HashSet<&str>)> = relays
            .iter()
            .filter_map(|(id, row, _)| {
                let (inventory, heartbeat) = (row.inventory.as_ref()?, row.heartbeat.as_ref()?);
                if heartbeat.runners.len() != inventory.runners.len()
                    || heartbeat.runners.iter().any(|r| {
                        usize::try_from(r.requests).ok() != Some(r.request_admissions.len())
                            || usize::try_from(r.jobs).map_or(true, |n| n < r.job_admissions.len())
                    })
                {
                    return None;
                }
                let requests = heartbeat
                    .runners
                    .iter()
                    .flat_map(|r| r.request_admissions.iter().map(String::as_str))
                    .collect();
                let jobs = heartbeat
                    .runners
                    .iter()
                    .flat_map(|r| r.job_admissions.iter().map(String::as_str))
                    .collect();
                Some((id.as_str(), (requests, jobs)))
            })
            .collect();
        let unadmitted: HashMap<(&str, &str), u64> = relays
            .iter()
            .filter(|(id, _, _)| listed.contains_key(id.as_str()))
            .filter_map(|(id, row, _)| Some((id, row.heartbeat.as_ref()?)))
            .flat_map(|(id, heartbeat)| {
                heartbeat.runners.iter().filter_map(move |r| {
                    let admitted = u32::try_from(r.job_admissions.len()).unwrap_or(u32::MAX);
                    let n = r.jobs.saturating_sub(admitted);
                    (n > 0).then(|| ((id.as_str(), r.name.as_str()), u64::from(n)))
                })
            })
            .collect();
        let mut unadmitted_by_relay: HashMap<&str, u64> = HashMap::new();
        for (&(relay, _), &n) in &unadmitted {
            let sum = unadmitted_by_relay.entry(relay).or_default();
            *sum = sum.saturating_add(n);
        }
        Relays {
            by_id,
            listed,
            unadmitted,
            unadmitted_by_relay,
            heartbeats,
        }
    }

    /// Whether relay `key`'s last heartbeat is of `session` and was received at least
    /// [`UNLISTED_GRACE`] after `claimed`, so a claim it leaves out is no longer held.
    fn heard_well_after(&self, key: &str, session: u64, claimed: Instant) -> bool {
        self.row(key)
            .is_some_and(|relay| relay.heartbeat_session == Some(session))
            && self
                .heartbeats
                .get(key)
                .is_some_and(|&(s, at)| s == session && at >= claimed + UNLISTED_GRACE)
    }

    /// Relay `key`'s row, if it is a relay.
    fn row(&self, key: &str) -> Option<&'a crate::store::RelayRow> {
        self.by_id.get(key).map(|(row, _)| *row)
    }

    /// The name relay `key`'s inventory gives the runner of `identity`, if any. Matched by
    /// runner ID alone: a relay serves one GitLab.
    fn runner_name(
        &self,
        key: &str,
        identity: &crate::store::SchedulingIdentity,
    ) -> Option<&'a str> {
        self.row(key)?
            .inventory
            .as_ref()?
            .runners
            .iter()
            .find(|r| r.runner_id == identity.runner_id)
            .map(|r| r.name.as_str())
    }
}

/// What tenants, relays and relay runners hold as arbitration charges it, read once a pass and
/// kept up to date as it places work.
#[derive(Default)]
struct Loads {
    tenant: HashMap<String, u64>,
    relay: HashMap<String, u64>,
    runner: HashMap<(String, String), u64>,
    /// Of the jobs charged, those without an admission, by relay and by relay runner: the rest
    /// of those a relay's heartbeat counts are charged on top ([`Loads::relay_load`]).
    unadmitted_relay: HashMap<String, u64>,
    unadmitted_runner: HashMap<(String, String), u64>,
    /// Live jobs recorded without a scheduling identity or a GitLab project, by principal.
    legacy: HashMap<String, u64>,
    /// Runners with a probe out, abandoned or not.
    probing: HashSet<(String, u64)>,
    /// Probes out fleet-wide, abandoned or not.
    probes: usize,
}

/// Add one to `map`'s count of `key`, or take one off.
fn count<K: std::hash::Hash + Eq>(map: &mut HashMap<K, u64>, key: K, add: bool) {
    let n = map.entry(key).or_default();
    *n = if add {
        n.saturating_add(1)
    } else {
        n.saturating_sub(1)
    };
}

impl Loads {
    fn new(state: &State, policy: &crate::policy::Policy, relays: &Relays<'_>) -> Self {
        let mut loads = Loads {
            probing: state
                .abandoned_probes
                .values()
                .map(|(runner, _)| runner.clone())
                .collect(),
            probes: state.abandoned_probes.len(),
            ..Loads::default()
        };
        for ticket in state.tickets.values().filter(|t| holds(&t.phase)) {
            loads.charge_ticket(ticket);
        }
        for job in state.jobs.values() {
            if charged(state, &job.row) {
                loads.charge_job(policy, relays, &job.row, true);
            }
            if legacy(&job.row) {
                count(&mut loads.legacy, job.row.key.clone(), true);
            }
        }
        loads
    }

    /// Charge `ticket`, which holds capacity.
    fn charge_ticket(&mut self, ticket: &Ticket) {
        if ticket.probe && !matches!(ticket.phase, TicketPhase::Job) {
            self.probes = self.probes.saturating_add(1);
            if let Some(runner) = probe_of(ticket) {
                self.probing.insert(runner);
            }
        }
        count(&mut self.tenant, ticket.identity.tenant.clone(), true);
        count(&mut self.relay, ticket.key.clone(), true);
        if let Some(runner) = &ticket.identity.runner {
            count(&mut self.runner, (ticket.key.clone(), runner.clone()), true);
        }
    }

    /// Charge the job of `row`, or with `add` false take its charge back.
    fn charge_job(
        &mut self,
        policy: &crate::policy::Policy,
        relays: &Relays<'_>,
        row: &JobRow,
        add: bool,
    ) {
        count(&mut self.tenant, job_tenant(policy, row).to_owned(), add);
        count(&mut self.relay, row.key.clone(), add);
        if row.admission.is_none() {
            count(&mut self.unadmitted_relay, row.key.clone(), add);
        }
        if let Some(identity) = &row.scheduling
            && let Some(runner) = relays.runner_name(&row.key, identity)
        {
            let key = (row.key.clone(), runner.to_owned());
            if row.admission.is_none() {
                count(&mut self.unadmitted_runner, key.clone(), add);
            }
            count(&mut self.runner, key, add);
        }
    }

    fn tenant_load(&self, tenant: &str) -> u64 {
        self.tenant.get(tenant).copied().unwrap_or(0)
    }

    /// What relay `key` holds: what is charged to it, and the jobs its heartbeat counts
    /// without an admission that no job charged accounts for.
    fn relay_load(&self, relays: &Relays<'_>, key: &str) -> u64 {
        let held = relays.unadmitted_by_relay.get(key).copied().unwrap_or(0);
        let charged = self.unadmitted_relay.get(key).copied().unwrap_or(0);
        self.relay
            .get(key)
            .copied()
            .unwrap_or(0)
            .saturating_add(held.saturating_sub(charged))
    }

    /// What runner `runner` of relay `key` holds, as [`Loads::relay_load`] counts a relay.
    fn runner_load(&self, relays: &Relays<'_>, key: &str, runner: &str) -> u64 {
        let held = relays.unadmitted.get(&(key, runner)).copied().unwrap_or(0);
        let key = (key.to_owned(), runner.to_owned());
        let charged = self.unadmitted_runner.get(&key).copied().unwrap_or(0);
        self.runner
            .get(&key)
            .copied()
            .unwrap_or(0)
            .saturating_add(held.saturating_sub(charged))
    }
}

/// The tenant the job of `row` is charged to: its scheduling identity's; recorded without one,
/// the tenant listing its project, else the policy's fallback.
fn job_tenant<'a>(policy: &'a crate::policy::Policy, row: &'a JobRow) -> &'a str {
    match &row.scheduling {
        Some(identity) => identity.tenant.as_str(),
        None => legacy_tenant(policy, row).unwrap_or(policy.fallback.as_str()),
    }
}

/// Whether the job of `row` is charged as a job: placed, or queued on an admission, unless
/// its admission's ticket still holds the capacity.
fn charged(state: &State, row: &JobRow) -> bool {
    !(row.state == JobState::Queued && row.admission.is_none())
        && !row
            .admission
            .as_ref()
            .is_some_and(|id| state.tickets.get(id).is_some_and(|t| holds(&t.phase)))
}

/// Whether the job of `row` was recorded without a scheduling identity or a GitLab project
/// and placed: its relay's tickets wait for it to settle.
fn legacy(row: &JobRow) -> bool {
    row.scheduling.is_none()
        && row.node.is_some()
        && (row.gitlab.is_none() || row.project_id.is_none())
}

/// Each placement's nodes with room ([`candidates`], skipping none), until the next placement
/// changes them.
#[derive(Default)]
struct Found(Vec<(Placement, Vec<(String, u64)>)>);

impl Found {
    fn get(
        &mut self,
        hub: &Hub,
        state: &State,
        nodes: &[(String, NodeRow)],
        placement: &Placement,
    ) -> &[(String, u64)] {
        let at = match self.0.iter().position(|(p, _)| p == placement) {
            Some(at) => at,
            None => {
                let found = candidates(hub, state, nodes, placement, &HashSet::new());
                self.0.push((placement.clone(), found));
                self.0.len().saturating_sub(1)
            }
        };
        self.0.get(at).map_or(&[], |(_, found)| found.as_slice())
    }
}

#[derive(Clone)]
struct Candidate {
    id: String,
    node: String,
    class: crate::policy::Class,
    probe: bool,
    load: u64,
    weight: u32,
    tenant_probe: Option<Instant>,
    runner_probe: Option<Instant>,
    arrived: Instant,
    job: bool,
    reserved: bool,
    /// A job at its deadline: placed now or ended.
    due: bool,
}

/// Where `e` ranks among the candidates of a placement, lowest first: a job holding its
/// reservation, then production work other than probes, then production probes ahead of normal
/// work, except while normal work is `owed` a turn ([`Turns`]).
fn rank(e: &Candidate, owed: bool) -> u8 {
    use crate::policy::Class;
    match (e.reserved, e.class, e.probe) {
        (true, _, _) => 0,
        (false, Class::Production, false) => 1,
        (false, Class::Normal, _) if owed => 2,
        (false, Class::Production, true) => 3,
        (false, Class::Normal, _) => 4,
    }
}

/// `a` against `b` by their tenants' load per weight, the lower first.
fn share(a: &Candidate, b: &Candidate) -> std::cmp::Ordering {
    (u128::from(a.load) * u128::from(b.weight)).cmp(&(u128::from(b.load) * u128::from(a.weight)))
}

/// Whose turn it is between production probes and normal work.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Turns {
    /// Production probes offered since normal work was last granted room.
    production_probes: u32,
    /// Whether normal work goes ahead of production probes: after `production_probe_burst` of
    /// them, until normal work is granted room. A hub starts owing it, so a restart lets normal
    /// work in first: production probes never wait on more than one turn of it.
    normal_owed: bool,
}

impl Default for Turns {
    fn default() -> Self {
        Turns {
            production_probes: 0,
            normal_owed: true,
        }
    }
}

impl Turns {
    /// Whether eligible normal work without its own reservation is owed a turn.
    fn owed(&self, eligible: &[Candidate]) -> bool {
        self.normal_owed
            && eligible
                .iter()
                .any(|e| !e.reserved && e.class == crate::policy::Class::Normal)
    }

    /// Record a grant by class, probe status and reservation status.
    /// `burst` is the policy's `production_probe_burst`; work on its reservation takes no turn.
    fn granted(&mut self, class: crate::policy::Class, probe: bool, reserved: bool, burst: u32) {
        if reserved {
            return;
        }
        match class {
            crate::policy::Class::Normal => {
                *self = Turns {
                    production_probes: 0,
                    normal_owed: false,
                }
            }
            crate::policy::Class::Production if probe => {
                self.production_probes = self.production_probes.saturating_add(1);
                if self.production_probes >= burst {
                    self.normal_owed = true;
                }
            }
            crate::policy::Class::Production => {}
        }
    }
}

/// One arbitration pass over the tickets and the queued jobs: forget what lapsed, reconcile
/// claims with relays' heartbeats, then offer capacity. Whether a ticket changed phase.
pub(super) fn schedule_tickets(
    hub: &Hub,
    state: &mut State,
    schedule: &ScheduleCtx<'_>,
    writes: &mut Vec<(String, JobRow, Vec<Event>)>,
    now: Instant,
) -> Result<bool> {
    let relays = Relays::new(schedule.relays, schedule.heartbeats);
    let mut moved = sweep(hub, state, schedule.policy, &relays, now);
    moved |= reconcile(hub, state, &relays);
    moved |= expire(state, now);
    moved |= refresh(state, schedule.policy, &relays);
    moved |= arbitrate(hub, state, schedule, &relays, writes, now)?;
    Ok(moved)
}

/// Forget abandoned probes past [`ABANDONED_PROBE_GRACE`], ending their node's session, the
/// tickets of relays gone, and the arbitration history of runners and tenants the policy no
/// longer names. Whether a ticket went.
fn sweep(
    hub: &Hub,
    state: &mut State,
    policy: &crate::policy::Policy,
    relays: &Relays<'_>,
    now: Instant,
) -> bool {
    // A node which never answers an abandoned offer reconnects; on reconnect it reports and
    // releases what it holds.
    let lapsed: Vec<String> = state
        .abandoned_probes
        .iter()
        .filter(|(_, (_, since))| now.duration_since(*since) >= ABANDONED_PROBE_GRACE)
        .map(|(id, _)| id.clone())
        .collect();
    for id in lapsed {
        state.abandoned_probes.remove(&id);
        if let Some(reservation) = state.reservations.get(&id)
            && let Some(link) = state.links.get(&reservation.node)
        {
            hub.end_session(&reservation.node, link.session);
        }
    }
    state
        .demand
        .retain(|(gitlab, runner), _| policy.runner(gitlab, *runner).is_some());
    state
        .tenant_probe
        .retain(|tenant, _| policy.tenant(tenant).is_some());
    let removed: Vec<_> = state
        .tickets
        .iter()
        .filter(|(_, ticket)| {
            ticket.identity.gitlab.is_some() && !relays.by_id.contains_key(ticket.key.as_str())
        })
        .filter(|(id, _)| !state.pending_admissions.contains(*id))
        .map(|(id, _)| id.clone())
        .collect();
    let moved = !removed.is_empty();
    for id in removed {
        if let Some(ticket) = state.tickets.remove(&id)
            && let Some(reservation) = &ticket.reservation
        {
            discard_ticket_reservation(state, reservation, probe_of(&ticket));
        }
        state.admission_changes.push((id, None));
    }
    moved
}

/// Reconcile claimed admissions with the heartbeats of the relays holding them. Whether a
/// ticket changed.
fn reconcile(hub: &Hub, state: &mut State, relays: &Relays<'_>) -> bool {
    let mut moved = false;
    // A newly connected relay reports every held admission before it requests more work.
    let mut reconciled_away = Vec::new();
    for (id, ticket) in &mut state.tickets {
        if state.pending_admissions.contains(id) {
            continue;
        }
        if !matches!(ticket.phase, TicketPhase::Claimed { .. } | TicketPhase::Job) {
            continue;
        }
        let Some(session) = hub.current_session(&ticket.key) else {
            continue;
        };
        if ticket.session == Some(session) {
            continue;
        }
        let Some(relay) = relays.row(&ticket.key) else {
            continue;
        };
        if relay.heartbeat_session != Some(session) {
            continue;
        }
        // A heartbeat from before the relay could list a claim is no say on it.
        if ticket
            .claimed_at
            .is_some_and(|claimed| !relays.heard_well_after(&ticket.key, session, claimed))
        {
            continue;
        }
        let Some((requests, jobs)) = relays.listed.get(ticket.key.as_str()) else {
            continue;
        };
        let request = requests.contains(id.as_str());
        let job = jobs.contains(id.as_str());
        if !request && !job {
            reconciled_away.push(id.clone());
        } else {
            ticket.session = Some(session);
            if job && !matches!(ticket.phase, TicketPhase::Job) {
                ticket.phase = TicketPhase::Job;
                ticket.probe = false;
                moved = true;
                state
                    .admission_changes
                    .push((id.clone(), Some(AdmissionOutcome::Job)));
            }
        }
    }
    // A claimed admission whose outcome never arrived: once a heartbeat of the session that
    // claimed it, taken well after the claim, no longer lists it, the relay holds nothing
    // under it.
    for (id, ticket) in &state.tickets {
        if state.pending_admissions.contains(id)
            || !matches!(ticket.phase, TicketPhase::Claimed { .. } | TicketPhase::Job)
        {
            continue;
        }
        let (Some(claimed_at), Some(session)) = (ticket.claimed_at, ticket.session) else {
            continue;
        };
        if hub.current_session(&ticket.key) != Some(session) {
            continue;
        }
        if !relays.heard_well_after(&ticket.key, session, claimed_at) {
            continue;
        }
        let Some((requests, jobs)) = relays.listed.get(ticket.key.as_str()) else {
            continue;
        };
        if !requests.contains(id.as_str()) && !jobs.contains(id.as_str()) {
            reconciled_away.push(id.clone());
        }
    }
    // Either way, the relay holds nothing under it, and its node's reservation goes too.
    for id in reconciled_away {
        moved = true;
        if let Some(ticket) = state.tickets.remove(&id)
            && let TicketPhase::Claimed { reservation } = ticket.phase
        {
            discard_ticket_reservation(state, &reservation, None);
        }
        state.admission_changes.push((id, None));
    }
    moved
}

/// Drop idle waiters, retire offers whose node refused or did not answer, and end grants
/// whose lease ran out unclaimed. Whether a ticket changed.
fn expire(state: &mut State, now: Instant) -> bool {
    let mut moved = false;
    let mut release = Vec::new();
    let ids: Vec<String> = state.tickets.keys().cloned().collect();
    for id in ids {
        if state.pending_admissions.contains(&id) {
            continue;
        }
        let Some(ticket) = state.tickets.get(&id) else {
            continue;
        };
        let idle = now.duration_since(ticket.polled) >= TICKET_IDLE;
        let offering = match &ticket.phase {
            TicketPhase::Offering { reservation, since } => Some((reservation.clone(), *since)),
            _ => None,
        };
        let granted = match &ticket.phase {
            TicketPhase::Granted {
                reservation,
                accepted,
            } => Some((reservation.clone(), *accepted)),
            _ => None,
        };
        if idle
            && !matches!(ticket.phase, TicketPhase::Claimed { .. } | TicketPhase::Job)
            && (ticket.queued || !matches!(ticket.phase, TicketPhase::Granted { .. }))
        {
            if let Some((r, _)) = offering.clone().or(granted) {
                release.push((r, probe_of(ticket)));
            }
            if matches!(ticket.phase, TicketPhase::Finished(_)) {
                state.admission_changes.push((id.clone(), None));
            }
            state.tickets.remove(&id);
            moved = true;
            continue;
        }
        if let Some((r, since)) = offering {
            let node = state.reservations.get(&r).map(|r| r.node.clone());
            let refused = state
                .reservations
                .get(&r)
                .is_none_or(|r| matches!(r.phase, ResvPhase::Refused(_) | ResvPhase::Abandoned));
            if refused || now.duration_since(since) >= OFFER_TIMEOUT {
                let abandoned_probe = state
                    .tickets
                    .get(&id)
                    .filter(|_| !refused)
                    .and_then(probe_of);
                if let Some(probe) = abandoned_probe {
                    state.abandoned_probes.insert(r.clone(), (probe, now));
                }
                if let Some(resv) = state.reservations.get_mut(&r) {
                    if matches!(resv.phase, ResvPhase::Offered) {
                        resv.phase = ResvPhase::Abandoned;
                    } else {
                        state.reservations.remove(&r);
                    }
                }
                if !refused && let Some(node) = &node {
                    send(
                        state,
                        node,
                        HubJobMsg::Release {
                            reservation: r.clone(),
                        },
                    );
                }
                if let Some(ticket) = state.tickets.get_mut(&id) {
                    ticket.phase = TicketPhase::Waiting;
                    ticket.probe = false;
                    if let Some(node) = node {
                        ticket.tried.insert(node);
                    }
                    moved = true;
                }
            }
        }
        if let Some((r, accepted)) = granted {
            let expired = state
                .reservations
                .get(&r)
                .is_none_or(|resv| match resv.phase {
                    ResvPhase::Held { lease_secs } => {
                        now.duration_since(accepted).as_secs().saturating_add(1)
                            >= u64::from(lease_secs)
                    }
                    _ => true,
                });
            if expired {
                release.push((r, None));
                // Never claimed: given back, as the relay giving it back says.
                if let Some(ticket) = state.tickets.get_mut(&id) {
                    ticket.phase = TicketPhase::Finished(AdmissionOutcome::Released);
                    ticket.probe = false;
                    moved = true;
                }
            }
        }
    }
    for (id, probe) in release {
        discard_ticket_reservation(state, &id, probe);
    }
    moved
}

/// Refresh waiting tickets' identities and limits from the current policy and inventory,
/// ending those no longer valid. Whether a ticket ended.
fn refresh(state: &mut State, policy: &crate::policy::Policy, relays: &Relays<'_>) -> bool {
    let mut moved = false;
    for ticket in state
        .tickets
        .values_mut()
        .filter(|t| matches!(t.phase, TicketPhase::Waiting))
    {
        let valid = if let (Some(gitlab), Some(runner_id)) =
            (&ticket.identity.gitlab, ticket.identity.runner_id)
        {
            let current = relays
                .by_id
                .get(ticket.key.as_str())
                .and_then(|(row, status)| {
                    let approved = status
                        .as_ref()
                        .is_some_and(|s| s.state.approved() && s.name.as_deref() == Some(gitlab));
                    if !approved {
                        return None;
                    }
                    let inventory = row.inventory.as_ref()?;
                    let mut runners = inventory
                        .runners
                        .iter()
                        .filter(|r| Some(&r.name) == ticket.identity.runner.as_ref());
                    let runner = runners.next()?;
                    if runners.next().is_some()
                        || !runner.verified
                        || runner.runner_id != Some(runner_id)
                        || runner.placement != ticket.placement
                    {
                        return None;
                    }
                    Some((inventory, runner))
                });
            if let (Some((inventory, runner)), Some(mapping)) =
                (current, policy.runner(gitlab, runner_id))
            {
                ticket.identity.tenant.clone_from(&mapping.tenant);
                ticket.identity.class = mapping.class;
                ticket.identity.concurrent = inventory.concurrent;
                ticket.identity.limit = runner.limit;
                ticket.identity.request_concurrency = runner.request_concurrency;
                true
            } else {
                false
            }
        } else if let Some((name, _)) = policy.client(&ticket.key) {
            ticket.identity.tenant = name.to_owned();
            true
        } else {
            false
        };
        if !valid {
            ticket.phase = TicketPhase::Finished(AdmissionOutcome::Error);
            moved = true;
        }
    }
    moved
}

/// Offer capacity to waiting tickets and place queued jobs, one placement at a time, the
/// tenant holding the least for its weight first. Whether a ticket was offered capacity.
fn arbitrate(
    hub: &Hub,
    state: &mut State,
    schedule: &ScheduleCtx<'_>,
    relays: &Relays<'_>,
    writes: &mut Vec<(String, JobRow, Vec<Event>)>,
    now: Instant,
) -> Result<bool> {
    let (ctx, policy) = (&schedule.place, schedule.policy);
    let nodes = ctx.nodes;
    let probe_limit = usize::try_from(policy.probe_limit).unwrap_or(usize::MAX);
    let mut loads = Loads::new(state, policy, relays);
    let mut found = Found::default();
    let mut moved = false;
    let mut skipped_jobs = HashSet::new();
    let mut placed = 0;
    loop {
        if placed == MAX_PLACEMENTS_PER_STEP {
            break;
        }
        let mut kept = Kept::new(hub, nodes, policy);
        let mut eligible = Vec::new();
        let waiters: Vec<_> = state
            .tickets
            .iter()
            .filter(|(_, t)| matches!(t.phase, TicketPhase::Waiting))
            .map(|(id, t)| (id.clone(), t.clone()))
            .collect();
        for (id, ticket) in &waiters {
            if ticket.identity.runner.is_some()
                && loads.legacy.get(&ticket.key).is_some_and(|&n| n > 0)
            {
                blocked(state, id, "legacy relay jobs pending settlement");
                continue;
            }
            // Heard from in the relay's current session, its heartbeat lists what it holds.
            if ticket.identity.runner.is_some()
                && !(relays.listed.contains_key(ticket.key.as_str())
                    && relays.row(&ticket.key).is_some_and(|relay| {
                        relay.heartbeat_session.is_some()
                            && relay.heartbeat_session == hub.current_session(&ticket.key)
                    }))
            {
                blocked(state, id, "awaiting relay reconciliation");
                continue;
            }
            let Some(tenant) = policy.tenant(&ticket.identity.tenant) else {
                blocked(state, id, "tenant unavailable");
                continue;
            };
            let load = loads.tenant_load(&ticket.identity.tenant);
            if tenant.cap.is_some_and(|cap| load >= u64::from(cap)) {
                blocked(state, id, "tenant cap");
                continue;
            }
            if loads.relay_load(relays, &ticket.key) >= u64::from(ticket.identity.concurrent) {
                blocked(state, id, "relay concurrent limit");
                continue;
            }
            if let Some(runner) = &ticket.identity.runner
                && ticket.identity.limit.is_some_and(|limit| {
                    loads.runner_load(relays, &ticket.key, runner) >= u64::from(limit)
                })
            {
                blocked(state, id, "runner limit");
                continue;
            }
            let demand_key = ticket
                .identity
                .gitlab
                .as_ref()
                .zip(ticket.identity.runner_id)
                .map(|(g, r)| (g.clone(), r));
            let demand = demand_key.as_ref().and_then(|k| state.demand.get(k));
            if demand
                .and_then(|d| d.backoff_until)
                .is_some_and(|until| now < until)
            {
                blocked(state, id, "backoff");
                continue;
            }
            let probe = demand_key.is_some()
                && !demand
                    .and_then(|d| d.busy_until)
                    .is_some_and(|until| now < until);
            let last_probe = demand.and_then(|d| d.last_probe);
            if probe && loads.probes >= probe_limit {
                blocked(state, id, "shared probe budget");
                continue;
            }
            if probe
                && demand_key
                    .as_ref()
                    .is_some_and(|key| loads.probing.contains(key))
            {
                blocked(state, id, "runner already probing");
                continue;
            }
            let admission = (&ticket.placement, ticket.identity.class);
            let fits = found.get(hub, state, nodes, &ticket.placement);
            let none = HashSet::new();
            let mut node = admission_node(state, &kept, admission, fits, &ticket.tried, &none);
            if node == Err(NO_FITTING_NODE)
                && !ticket.tried.is_empty()
                && let Some(live) = state.tickets.get_mut(id)
            {
                let ended = *live.round_ended.get_or_insert(now);
                if now.duration_since(ended) >= RETRY_PAUSE {
                    live.tried.clear();
                    live.round_ended = None;
                    node = admission_node(state, &kept, admission, fits, &none, &none);
                }
            }
            let node = match node {
                Ok(node) => node,
                Err(why) => {
                    blocked(state, id, why);
                    continue;
                }
            };
            let tenant_probe = probe
                .then(|| state.tenant_probe.get(&ticket.identity.tenant).copied())
                .flatten();
            blocked(state, id, "waiting for tenant share");
            eligible.push(Candidate {
                id: id.clone(),
                node,
                class: ticket.identity.class,
                probe,
                load,
                weight: tenant.weight,
                tenant_probe,
                runner_probe: last_probe,
                arrived: ticket.created,
                job: false,
                reserved: false,
                due: false,
            });
        }
        let jobs: Vec<_> = state
            .jobs
            .iter()
            .filter(|(id, j)| {
                j.row.state == JobState::Queued
                    && j.row.cancel.is_none()
                    && !skipped_jobs.contains(*id)
            })
            .map(|(id, j)| {
                (
                    id.clone(),
                    j.row.clone(),
                    j.reservation.clone(),
                    j.deadline,
                    j.tried.clone(),
                    j.round_ended,
                )
            })
            .collect();
        for (id, row, mut reservation, deadline, mut tried, round_ended) in jobs {
            let Some(job) = state.jobs.get(&id) else {
                continue;
            };
            let excluded = placement_exclusions(policy, job, nodes);
            if reservation.as_ref().is_some_and(|r| {
                state.reservations.get(r).is_some_and(|r| {
                    excluded.contains(&r.node) || !nodes.iter().any(|(id, _)| id == &r.node)
                })
            }) {
                if let Some(r) = reservation.take()
                    && let Some(old) = state.reservations.remove(&r)
                {
                    send(state, &old.node, HubJobMsg::Release { reservation: r });
                }
                if let Some(job) = state.jobs.get_mut(&id) {
                    job.reservation = None;
                }
                found = Found::default();
                kept = Kept::new(hub, nodes, policy);
            }
            tried.extend(excluded.iter().cloned());
            let identity = row.scheduling.as_ref();
            let tenant_name = job_tenant(policy, &row);
            let class = identity.map_or(crate::policy::Class::Normal, |i| i.class);
            let tenant = policy.tenant(tenant_name);
            let weight = tenant.map_or(1, |t| t.weight);
            let load = loads.tenant_load(tenant_name);
            if delisted(policy, &row) {
                if let Some(job) = state.jobs.get_mut(&id) {
                    job.blocked = Some(DELISTED);
                }
                continue;
            }
            // A job on an admission was held to these when the admission was offered.
            if row.admission.is_none() {
                let relay = relays.row(&row.key);
                let gate = match relay.map(|relay| &relay.inventory) {
                    _ if tenant
                        .and_then(|t| t.cap)
                        .is_some_and(|cap| load >= u64::from(cap)) =>
                    {
                        Some("tenant cap")
                    }
                    None => None,
                    Some(None) => Some("its relay's inventory is unknown"),
                    Some(Some(inventory))
                        if loads.relay_load(relays, &row.key)
                            >= u64::from(inventory.concurrent) =>
                    {
                        Some("relay concurrent limit")
                    }
                    Some(Some(inventory)) => match identity.and_then(|i| i.runner_id) {
                        None => None,
                        Some(runner_id) => match inventory
                            .runners
                            .iter()
                            .find(|r| r.runner_id == Some(runner_id))
                        {
                            None => Some("its runner is not in its relay's inventory"),
                            Some(runner)
                                if runner.limit.is_some_and(|limit| {
                                    loads.runner_load(relays, &row.key, &runner.name)
                                        >= u64::from(limit)
                                }) =>
                            {
                                Some("runner limit")
                            }
                            Some(_) => None,
                        },
                    },
                };
                if gate.is_some() {
                    if let Some(job) = state.jobs.get_mut(&id) {
                        job.blocked = gate;
                    }
                    continue;
                }
            }
            if let Some(job) = state.jobs.get_mut(&id) {
                job.blocked = None;
            }
            let reserved = reservation
                .as_ref()
                .is_some_and(|r| usable_reservation(hub, state, nodes, &excluded, r).is_some());
            let node = if reserved {
                String::new()
            } else {
                let admission = (&row.placement, class);
                let fits = found.get(hub, state, nodes, &row.placement);
                let mut chosen = admission_node(state, &kept, admission, fits, &tried, &excluded);
                if chosen == Err(NO_FITTING_NODE) && !tried.is_empty() {
                    let job = state
                        .jobs
                        .get_mut(&id)
                        .ok_or_else(|| anyhow!("queued job disappeared"))?;
                    let ended = *job.round_ended.get_or_insert(now);
                    if round_ended.is_some_and(|at| now.duration_since(at) >= RETRY_PAUSE)
                        || now.duration_since(ended) >= RETRY_PAUSE
                    {
                        job.tried.clear();
                        job.round_ended = None;
                        tried.clone_from(&excluded);
                        chosen = admission_node(state, &kept, admission, fits, &tried, &excluded);
                    }
                }
                match chosen {
                    Ok(node) => node,
                    Err(why) => {
                        if let Some(job) = state.jobs.get_mut(&id) {
                            job.blocked = (why == PRODUCTION_HEADROOM).then_some(why);
                        }
                        continue;
                    }
                }
            };
            let age = crate::now_secs().saturating_sub(row.created_at);
            let arrived = now
                .checked_sub(Duration::from_secs(age))
                .unwrap_or(now)
                .min(deadline);
            eligible.push(Candidate {
                id,
                node,
                class,
                probe: false,
                load,
                weight,
                tenant_probe: None,
                runner_probe: None,
                arrived,
                job: true,
                reserved,
                due: now >= deadline,
            });
        }
        if eligible.is_empty() {
            break;
        }
        let owed = state.turns.owed(&eligible);
        let rank = |e: &Candidate| rank(e, owed);
        // A job at its deadline goes before all, or it ends unplaced this pass.
        eligible.sort_by(|a, b| {
            b.due
                .cmp(&a.due)
                .then_with(|| rank(a).cmp(&rank(b)))
                .then_with(|| share(a, b))
                .then_with(|| a.id.cmp(&b.id))
        });
        let Some(first) = eligible.first() else { break };
        let tied = eligible.iter().take_while(|e| {
            e.due == first.due && rank(e) == rank(first) && share(e, first).is_eq()
        });
        let probes = tied
            .clone()
            .filter(|e| e.probe)
            .min_by_key(|e| (e.tenant_probe, e.runner_probe, e.arrived, &e.id));
        let known = tied.filter(|e| !e.probe).min_by_key(|e| (e.arrived, &e.id));
        let chosen = match (probes, known) {
            (Some(probe), Some(known)) => {
                if (probe.arrived, &probe.id) < (known.arrived, &known.id) {
                    probe
                } else {
                    known
                }
            }
            (Some(probe), None) => probe,
            (None, Some(known)) => known,
            (None, None) => break,
        };
        let Candidate {
            id,
            node,
            class,
            probe,
            job,
            ..
        } = chosen.clone();
        if owed && class == crate::policy::Class::Normal {
            let passed: Vec<String> = eligible
                .iter()
                .filter(|e| !e.job && e.probe && e.class == crate::policy::Class::Production)
                .map(|e| e.id.clone())
                .collect();
            for id in passed {
                blocked(state, &id, "normal turn owed");
            }
        }
        placed += 1;
        if job {
            let before = state.jobs.get(&id).map(|j| j.row.clone());
            let write = place(
                hub,
                state,
                ctx,
                &id,
                now,
                (!node.is_empty()).then_some(node.as_str()),
            );
            if let Some(write) = write {
                writes.push(write);
            } else {
                skipped_jobs.insert(id.clone());
            }
            // Started, it takes its turn unless it started on its own reservation.
            if let Some(started) = state
                .jobs
                .get(&id)
                .filter(|j| j.row.state == JobState::Starting)
            {
                let on_reservation = started.reservation.is_some();
                let burst = policy.production_probe_burst;
                state.turns.granted(class, false, on_reservation, burst);
            }
            // Its charge as placed, or ended, in place of its charge as queued.
            let after = state.jobs.get(&id).map(|j| j.row.clone());
            for (row, add) in [(before, false), (after, true)] {
                if let Some(row) = row {
                    if charged(state, &row) {
                        loads.charge_job(policy, relays, &row, add);
                    }
                    if legacy(&row) {
                        count(&mut loads.legacy, row.key.clone(), add);
                    }
                }
            }
            found = Found::default();
            continue;
        }
        let reservation = crate::random_hex(vk_hub_proto::ID_BYTES)?;
        let Some(ticket) = state.tickets.get_mut(&id) else {
            continue;
        };
        ticket.blocked = None;
        let demand_key = ticket
            .identity
            .gitlab
            .as_ref()
            .zip(ticket.identity.runner_id)
            .map(|(g, r)| (g.clone(), r));
        let tenant_name = ticket.identity.tenant.clone();
        let (key, instance, envelope, lease_secs) = (
            ticket.key.clone(),
            ticket.instance.clone(),
            ticket.placement.envelope,
            ticket.lease_secs,
        );
        ticket.probe = probe;
        ticket.reservation = Some(reservation.clone());
        ticket.phase = TicketPhase::Offering {
            reservation: reservation.clone(),
            since: now,
        };
        state.reservations.insert(
            reservation.clone(),
            Resv {
                key,
                instance,
                node: node.clone(),
                envelope,
                phase: ResvPhase::Offered,
                accepted_at: 0,
                leases: 0,
                ticket: Some(id.clone()),
            },
        );
        if !send(
            state,
            &node,
            HubJobMsg::Offer {
                reservation: reservation.clone(),
                envelope,
                lease_secs,
            },
        ) {
            state.reservations.remove(&reservation);
            if let Some(ticket) = state.tickets.get_mut(&id) {
                ticket.phase = TicketPhase::Waiting;
                ticket.probe = false;
                ticket.tried.insert(node);
            }
            continue;
        }
        moved = true;
        if let Some(ticket) = state.tickets.get(&id) {
            loads.charge_ticket(ticket);
        }
        found = Found::default();
        if probe {
            state.tenant_probe.insert(tenant_name, now);
            if let Some(key) = demand_key {
                state.demand.entry(key).or_default().last_probe = Some(now);
            }
        }
        let burst = policy.production_probe_burst;
        state.turns.granted(class, probe, false, burst);
    }
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Class;

    fn candidate(class: Class, probe: bool, reserved: bool) -> Candidate {
        Candidate {
            id: String::new(),
            node: String::new(),
            class,
            probe,
            load: 0,
            weight: 1,
            tenant_probe: None,
            runner_probe: None,
            arrived: Instant::now(),
            job: reserved,
            reserved,
            due: false,
        }
    }

    #[test]
    fn production_ranks_ahead_of_normal_but_for_a_turn_owed() {
        let probe = candidate(Class::Production, true, false);
        let known = candidate(Class::Production, false, false);
        let normal = candidate(Class::Normal, true, false);
        let reserved = candidate(Class::Normal, false, true);
        // Not owed: production probes ahead of normal work.
        assert!(rank(&probe, false) < rank(&normal, false));
        // Owed: normal work ahead of production probes, not of other production work.
        assert!(rank(&normal, true) < rank(&probe, true));
        assert!(rank(&known, true) < rank(&normal, true));
        // A job on its reservation, ahead of all.
        for owed in [false, true] {
            assert!(rank(&reserved, owed) < rank(&known, owed));
        }
    }

    #[test]
    fn shares_compare_load_per_weight() {
        let tenant = |load, weight| Candidate {
            load,
            weight,
            ..candidate(Class::Normal, false, false)
        };
        assert!(share(&tenant(1, 2), &tenant(1, 1)).is_lt());
        assert!(share(&tenant(2, 2), &tenant(1, 1)).is_eq());
        assert!(share(&tenant(3, 2), &tenant(1, 1)).is_gt());
    }

    #[test]
    fn normal_work_is_owed_a_turn_after_a_burst_of_production_probes() {
        let mut turns = Turns::default();
        // A hub starts owing it.
        assert!(turns.normal_owed);
        turns.granted(Class::Normal, true, false, 3);
        assert!(!turns.normal_owed);
        for _ in 0..2 {
            turns.granted(Class::Production, true, false, 3);
            assert!(!turns.normal_owed);
        }
        // Production work other than probes does not count.
        turns.granted(Class::Production, false, false, 3);
        assert!(!turns.normal_owed);
        turns.granted(Class::Production, true, false, 3);
        assert!(turns.normal_owed);
        // A reserved normal job neither pays the debt nor counts as normal waiting.
        turns.granted(Class::Normal, false, true, 3);
        assert!(turns.normal_owed);
        assert!(!turns.owed(&[candidate(Class::Normal, false, true)]));
        assert!(turns.owed(&[candidate(Class::Normal, false, false)]));
        turns.granted(Class::Normal, false, false, 3);
        assert_eq!(
            turns,
            Turns {
                production_probes: 0,
                normal_owed: false,
            }
        );
    }
}
