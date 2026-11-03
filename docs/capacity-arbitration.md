# Capacity arbitration: setting it up

Status: experimental, like [GitLab dispatch](gitlab-dispatch.md), which defines the client API,
tickets, reservations, placement and [scheduling order](gitlab-dispatch.md#admission-and-reservations).
This guide covers policy configuration, upgrades and monitoring for operators.

## The policy

The hub keeps one capacity policy, `"version": 2`. Every input is a **lane**: each relay
runner, each API key given one, and the default lane of every other API key. Work is charged to
its lane and held to its settings.

- `lanes`: each names its source once — `runner: {gitlab, id}` (the instance's name on the hub
  and GitLab's runner ID, never the runner's name), `key: "<principal ID>"` (the *principal ID*
  column of the web UI's *API keys*), or `default: true` — with:
  - `class`: `normal` (default) or `production`, runner lanes only.
  - `weight` (positive, default 1) and `max_slots` (positive; absent is unbounded): the slots
    it holds at once — room offered, granted or claimed, its jobs, and finished admissions not
    yet settled. Checked when room is granted; a job already on its slot is not checked again.
  - `nodes`: node IDs and pool names its work may use — a node listed, or in a pool listed.
    Absent, any node. It is the only placement setting, applied when room is granted.
  - `projects` (runner lanes only): `{gitlab, id, branches?}`, on the runner's own GitLab.
    Absent, any project; `[]`, none. With `branches` (globs), a job of that project must be a
    branch pipeline of a matching branch. A production lane must list its projects, each with
    `branches`.
  An unmapped runner gets no work; an API key without a lane of its own uses the default lane,
  and gets none without one. An API key's work is always normal.
- `headroom`, `probe_limit`, `production_probe_burst`, `backoff_initial_secs`,
  `backoff_max_secs`, `busy_secs`: see [below](#scheduling).

A minimal policy, for project 7 of instance `gl`, its normal runner 42 and production runner 43:

```json
{
  "version": 2,
  "lanes": [
    { "runner": { "gitlab": "gl", "id": 42 }, "class": "normal", "weight": 3,
      "projects": [{ "gitlab": "gl", "id": 7 }] },
    { "runner": { "gitlab": "gl", "id": 43 }, "class": "production", "nodes": ["trusted"],
      "projects": [{ "gitlab": "gl", "id": 7, "branches": ["main", "release/**"] }] },
    { "key": "ci-bot", "max_slots": 2 },
    { "default": true }
  ]
}
```

The hub rejects unknown fields at any depth, invalid names or IDs, a source named twice, and
policies exceeding these bounds: 32769 lanes, 64 headroom entries; 16384 projects per lane,
1024 branches per project, 256 nodes and pools per lane.

## Setting it

In the hub's web UI, *Capacity* (`/capacity`) lists the lanes, headroom and scheduling settings,
and operators replace the whole policy as JSON there, asked first what changes. Each project's
page lists the lanes that may run it.

From the hub's host, through its admin socket:

```sh
vk-hub capacity-policy show > policy.json   # prints its digest on stderr
vk-hub capacity-policy set policy.json --expected <digest>
```

Edits are rejected if the policy has changed since it was read; reload the page or run `show`
again. The audit log records the lanes and settings changed and the before and after digests.
Resubmitting the same policy changes nothing and is not audited, except to activate a policy
held since its conversion (see [Upgrading](#upgrading)). If a later hub stored a policy this hub
cannot read, the error includes its digest. Replace it with `set --expected` and that digest.

A change applies from the next scheduling pass. Running jobs are never touched, and a request
already claimed keeps the lane and class it was granted under. A runner unmapped has its waiting
requests refused. A queued job its lane no longer allows — runner unmapped, project or branch no
longer listed — is held until allowed again or its deadline; one on a node its lane no longer
allows moves to an allowed one.

## Upgrading

### From tenants to lanes

On first start, a hub of this release converts a stored policy of the earlier format (tenants,
runner and client mappings, project placement rules) once, keeps the original beside it for a
rollback, rewrites the scheduling identity of claimed admissions and unfinished jobs to their
lane, and audits the conversion with both digests:

- Each mapped runner becomes a lane with its class and nodes and pools, its tenant's weight, cap
  (as `max_slots`) and projects on the runner's GitLab; an empty list stays empty. A production
  runner's lane keeps only projects with production branches, as their `branches`.
- Each mapped API key becomes a lane with its tenant's weight and cap; the fallback tenant's
  settings become the default lane. Tenants no runner or key used disappear.
- Lanes converted from one tenant each get its whole weight and cap, so together they get more
  than before. `show` and the page list those lanes until they are next changed.
- A placement rule applying to every job a runner lane can take narrows the lane's nodes. Any
  other rule cannot be expressed on a lane: the converted policy is then held — it grants no new
  capacity, running work continues — and `show` and the page list each rule with its lane.
  Set the lanes' nodes and set the policy, changed or not, to activate it.

A job recorded before capacity arbitration, without a scheduling identity, is charged to the
default lane until it finishes. `capacity-policy set` also accepts the earlier format for this
release: it converts it the same way, prints the result and what to review, and refuses a policy
whose placement rules do not convert exactly. `show` prints lanes only.

The earlier hub cannot read lanes. Before upgrading, keep the output of its
`capacity-policy show`; a rolled-back hub takes it back with `set --expected` and the digest of
the unreadable policy it reports. Work in flight when rolling back is charged to no tenant until
it finishes.

### Relay protocol 2

Capacity arbitration needs relay session protocol 2, which a `vk-gitlab` of this release speaks:

1. **Upgrade the hub.** It keeps taking a protocol 1 relay's session, which follows, cancels and
   settles the jobs it holds, but gets no capacity, reservation or new job: *GitLab adapters* marks
   the relay *upgrade vk-gitlab: no new jobs*. A job such a relay took from GitLab and had not
   yet submitted fails.
2. **Map the runners.** Approve the relays' GitLab server and give each runner a lane by its
   GitLab ID. The hub refuses a runner's requests unless it is verified with GitLab, listed once
   in its relay's inventory with its GitLab ID, of the placement it requests, and has a lane.
3. **Upgrade the relays.** A relay of protocol 2 is refused by a hub that does not speak it: it
   asks GitLab for no jobs, logs that the hub must be upgraded, and dials again about every
   minute. Once its session has sent a heartbeat listing what it holds, its requests are
   arbitrated.

## Production lanes

The hub learns which project's job a runner takes only once GitLab has handed it over, so
priority is per runner: register a production runner beside the normal one, give it a tag of
its own, and use that tag only on production branch pipelines, for example:

```yaml
deploy:
  tags: [web-production]
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

The hub refuses a runner's job unless its lane allows its project and, when the lane lists
`branches` for it, its pipeline is one of a matching branch, as the job's sources show it: the
branch's refspec alone, with at most its pipeline's ref at the job's commit. A tag or merge
request pipeline never matches. A production lane lists `branches` for every project. A refused
job fails in GitLab, and its request counts as having found none.

A group runner, or one several projects share, takes whichever of their jobs GitLab hands it
next: its lane must list them all. To place projects or branches differently, register separate
runners and let GitLab route jobs to them.

## Scheduling

How the hub orders waiting requests and queued jobs is in
[admission and reservations](gitlab-dispatch.md#admission-and-reservations); in short:

- A job at its placement deadline, then one holding its reservation, then production work, then
  production probes, then normal work — except that after `production_probe_burst` production
  probes (default 1) since normal work was last granted room, normal work goes before the next
  production probe. A hub starts owing normal work that turn, so after a restart it goes first.
  Production work that is not a probe always goes before normal work: under sustained
  production demand, normal work waits. Nothing preempts a running job.
- Within each, the lane holding the least for its weight first, the oldest first. Weights
  compare slots held at once, not their size, and an idle lane's share goes to the others: no
  lane banks unused share. A runner lane's load adds up across every relay serving the runner.
- A request waits while its lane holds its `max_slots`, its relay its `concurrent`, its runner its
  `limit`, or while its runner backs off after a request that found no job.
- A runner that took no job in the last `busy_secs` (default 60) probes GitLab: at most
  `probe_limit` (default 1) probes are out fleet-wide, one per runner. An empty answer or an
  error backs the runner off from `backoff_initial_secs` (default 1), doubling up to
  `backoff_max_secs` (default 60), each wait ±25%, never past the maximum.
- Each `headroom` entry keeps `slots` envelopes of its placement (pool, labels, envelope) for
  production work: normal work must leave the fleet that much room for it, or all the room left
  when already short.

A lane given `nodes` has its room granted only on a node listed or in a pool listed, the least
loaded of those first; other nodes are never used for it, even idle. Without `nodes`, it may
use any node. Confinement follows the runner ID its relay reports — no trust boundary beyond the
relay.

## Reading the runners

Each row of *Runners*, updated live as the hub's placement passes change it, shows the
runner's lane weight and class, or *unmapped* (`-` while its server is not approved), and what the
hub has of it: its requests waiting and the oldest one's wait, its requests offered to a node,
those held (granted or claimed) and its jobs, its demand — *unknown*, *recently busy*,
*recently empty* or *unhealthy* — with what is left of its backoff, and what its oldest
waiting request waits for, or else its oldest queued job passed over (or `-` while it has
none):

| Reason | Meaning |
|---|---|
| `waiting for scheduling` | not yet passed over since it was queued or its last offer ended |
| `waiting for lane share` | eligible; other work went first this pass |
| `lane at max slots` | its lane holds its `max_slots` |
| `lane unavailable` | the policy no longer has its lane |
| `capacity policy awaiting activation` | the policy converted to lanes is held until set again |
| `relay concurrent limit`, `runner limit` | its relay holds `concurrent`, its runner `limit` |
| `backoff` | its last request found no job, or failed |
| `shared probe budget`, `runner already probing` | `probe_limit` probes are out, or one of its own |
| `normal turn owed` | a production probe passed over for normal work's turn |
| `no fitting node` | no node of its placement has room |
| `production headroom` | the room left is headroom kept for production |
| `awaiting relay reconciliation` | its relay's session has not yet listed what it holds |
| `its lane's allowed nodes` | nodes have room, none its lane may use |
| `no longer allowed by its lane` | a queued job, held until allowed again or its deadline |
| `its relay's inventory is unknown`, `its runner is not in its relay's inventory` | a queued job submitted without an admission |

A queued job still unplaced at its deadline fails with `no_capacity`, giving the last reason.
