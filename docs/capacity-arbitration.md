# Capacity arbitration: setting it up

Status: experimental, like [GitLab dispatch](gitlab-dispatch.md), which defines the client API,
tickets, reservations, placement and [scheduling order](gitlab-dispatch.md#admission-and-reservations).
This guide covers policy configuration, upgrades and monitoring for operators.

## The policy

The hub keeps one capacity policy. Every relay runner's request, and every API key's
reservation, is charged to a **tenant** of it:

- `tenants`: by name, each with a `weight` (positive), an optional `cap` (positive; absent is
  unbounded) on the requests and jobs it holds at once, and the `projects` its runners may take
  jobs of: `{gitlab, id}`, the instance's name on the hub and GitLab's project ID, with the
  project's `production_branches` (globs) and `placement_rules`.
- `runners`: each relay runner, by `{gitlab, runner_id}` — the instance's name and GitLab's
  runner ID, never the runner's name — mapped to a `tenant` and a `class`, `normal` or
  `production`. An unmapped runner gets no work.
- `clients`: API keys, by principal ID (the *principal ID* column of Connections' *Other API
  clients* tab), mapped to a tenant. A key mapped to none is charged to the `fallback` tenant;
  an API key's work is always normal. Relay runners never fall back.
- `headroom`, `probe_limit`, `production_probe_burst`, `backoff_initial_secs`,
  `backoff_max_secs`, `busy_secs`: see [below](#scheduling).

A minimal policy, for project 7 of instance `gl`, its normal runner 42 and production runner 43:

```json
{
  "fallback": "fallback",
  "tenants": {
    "fallback": { "weight": 1 },
    "web": {
      "weight": 2,
      "cap": 8,
      "projects": [
        { "gitlab": "gl", "id": 7, "production_branches": ["main", "release/**"] }
      ]
    }
  },
  "runners": [
    { "gitlab": "gl", "runner_id": 42, "tenant": "web", "class": "normal" },
    { "gitlab": "gl", "runner_id": 43, "tenant": "web", "class": "production" }
  ]
}
```

The hub rejects unknown fields at any depth, invalid names or IDs, and policies exceeding
these bounds: 4096 tenants, 16384 runner mappings, 16384 clients, 64 headroom entries;
16384 projects per tenant; 1024 production branches and 64 placement rules per project;
1024 branches, 256 nodes and 256 pools per rule. A project listed by several tenants must
have identical production branches in the same order, and identical placement rules in any
order.

## Setting it

In the hub's web UI, Connections' *Capacity tenants* lists tenants and links to their pages
and the whole policy (`/clients/capacity`). Operators can add tenants there. Each tenant's
page edits its weight, cap, projects and runner mappings. Each project's page edits its
production branches and placement rules across all tenants listing it. The policy page edits
the whole policy as JSON. Viewers see the same pages without forms.

From the hub's host, through its admin socket:

```sh
vk-hub capacity-policy show > policy.json   # prints its digest on stderr
vk-hub capacity-policy set policy.json --expected <digest>
```

Except when adding a tenant, edits are rejected if the policy has changed since it was read;
reload the page or run `show` again. The UI asks for confirmation before each change except
adding a tenant, listing the affected tenants, runners, clients and settings. The audit log
records the same list and the before and after digests. Resubmitting the same policy changes
nothing and is not audited; the UI also ignores changes that only reorder runner mappings.
If a later hub stored a policy this hub cannot read, the error includes its digest. Replace
it with `set --expected` and that digest; the UI editors refuse changes until then.

A change applies from the next scheduling pass. Running jobs stay where they are, and a request
already claimed keeps the tenant and class it was granted under; a queued job is held to the
project lists and placement rules as they are now.

## Upgrading

Capacity arbitration needs relay session protocol 2, which a `vk-gitlab` of this release speaks:

1. **Upgrade the hub.** It keeps taking a protocol 1 relay's session, which follows, cancels and
   settles the jobs it holds, but gets no capacity, reservation or new job: Connections marks
   the relay *upgrade vk-gitlab: no new jobs*. A job such a relay took from GitLab and had not
   yet submitted fails.
2. **Map the runners.** Approve the relays' GitLab server, list each tenant's projects, and map
   each runner by its GitLab ID, shown in Connections' *Runners*. The hub refuses a runner's
   requests unless it is verified with GitLab, listed once in its relay's inventory with its
   GitLab ID, of the placement it requests, and mapped.
3. **Upgrade the relays.** A relay of protocol 2 is refused by a hub that does not speak it: it
   asks GitLab for no jobs, logs that the hub must be upgraded, and dials again about every
   minute. Once its session has sent a heartbeat listing what it holds, its requests are
   arbitrated.

A job recorded by a hub from before arbitration has no tenant: it is charged to the first
tenant, by name, listing its project, else to the fallback. Such a job placed without a known
project keeps its relay's new requests waiting until it settles (*legacy relay jobs pending
settlement*).

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

The hub refuses a production runner's job unless its project is one its tenant lists and its
pipeline is one of a branch matching the project's `production_branches`, as the job's sources
show it: the branch's refspec alone, with at most its pipeline's ref at the job's commit. A tag
or merge request pipeline is never production. A refused job fails in GitLab, and its request
counts as having found none. A normal runner's job needs its project listed too.

A group runner, or one several projects share, takes whichever of their jobs GitLab hands it
next: map it to a tenant listing them all.

## Scheduling

How the hub orders waiting requests and queued jobs is in
[admission and reservations](gitlab-dispatch.md#admission-and-reservations); in short:

- A job at its placement deadline, then one holding its reservation, then production work, then
  production probes, then normal work — except that after `production_probe_burst` production
  probes (default 1) since normal work was last granted room, normal work goes before the next
  production probe. A hub starts owing normal work that turn, so after a restart it goes first.
  Production work that is not a probe always goes before normal work: under sustained
  production demand, normal work waits. Nothing preempts a running job.
- Within each, the tenant holding the least for its weight first, the oldest first. Weights
  count envelopes, not their size, and an idle tenant's share goes to the others: no tenant
  banks unused share.
- A request waits while its tenant holds its `cap`, its relay its `concurrent`, its runner its
  `limit`, or while its runner backs off after a request that found no job.
- A runner that took no job in the last `busy_secs` (default 60) probes GitLab: at most
  `probe_limit` (default 1) probes are out fleet-wide, one per runner. An empty answer or an
  error backs the runner off from `backoff_initial_secs` (default 1), doubling up to
  `backoff_max_secs` (default 60), each wait ±25%, never past the maximum.
- Each `headroom` entry keeps `slots` envelopes of its placement (pool, labels, envelope) for
  production work: normal work must leave the fleet that much room for it, or all the room left
  when already short.

Placement rules restrict where a project's jobs go, by the ref the relay reports for each job —
no trust boundary; see [placement](gitlab-dispatch.md#placement). The project's page explains
them beside its editor.

## Reading Connections

Each row of *Runners*, updated live as the hub's placement passes change it, shows the
runner's tenant and class, or *unmapped* (`-` while its server is not approved), and what the
hub has of it: its requests waiting and the oldest one's wait, its requests offered to a node,
those held (granted or claimed) and its jobs, its demand — *unknown*, *recently busy*,
*recently empty* or *unhealthy* — with what is left of its backoff, and what its oldest
waiting request waits for, or else its oldest queued job passed over (or `-` while it has
none):

| Reason | Meaning |
|---|---|
| `waiting for scheduling` | not yet passed over since it was queued or its last offer ended |
| `waiting for tenant share` | eligible; other work went first this pass |
| `tenant cap` | its tenant holds its `cap` |
| `tenant unavailable` | the policy no longer has its tenant |
| `relay concurrent limit`, `runner limit` | its relay holds `concurrent`, its runner `limit` |
| `backoff` | its last request found no job, or failed |
| `shared probe budget`, `runner already probing` | `probe_limit` probes are out, or one of its own |
| `normal turn owed` | a production probe passed over for normal work's turn |
| `no fitting node` | no node of its placement has room |
| `production headroom` | the room left is headroom kept for production |
| `awaiting relay reconciliation` | its relay's session has not yet listed what it holds |
| `legacy relay jobs pending settlement` | its relay holds a job from before arbitration |
| `project placement rules` | a queued job: nodes have room, none its project's rules allow |
| `project no longer listed for its tenant` | a queued job, held until listed again or its deadline |
| `its relay's inventory is unknown`, `its runner is not in its relay's inventory` | a queued job submitted without an admission |

A queued job still unplaced at its deadline fails with `no_capacity`, giving the last reason.
