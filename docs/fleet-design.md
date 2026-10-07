# Fleet: a hub and its nodes

Status: experimental, implemented in part. This document describes the target; the
[prototype reference](fleet-prototype.md) and its [status](fleet-prototype.md#status) say what
is built, with its commands, defaults and limits. The [exit criteria](#prototype-exit-criteria)
define the evidence required before unattended maintenance or phase 2.

A fleet is a set of machines running `vk node`, managed by one `vk-hub`. The hub owns the
fleet's inventory, desired state and operations — capacity ceilings, drains, `vk` rollouts,
resets — and shows them in a web UI. In the target, GitLab jobs reach the fleet through
`vk-gitlab`, a daemon that takes them from GitLab as a runner and has the hub place each one on
a node ([GitLab jobs](#gitlab-jobs)); generic VM jobs are placed the same way. Until then, and
on any node still configured so, each node keeps its own gitlab-runner with the vk executor,
and the hub steers how much work each runner accepts.

The target is a fleet of tens of bare-metal hosts, not hundreds: one hub process, one
embedded database, no replication.

## Components

- **`vk node`** — a `vk` subcommand run as a long-lived supervisor on each node. It is to
  link the executor, admission, the concurrency controller and self-update in-process, dial
  the hub, apply what the hub asks within what local policy allows, and run the jobs the hub
  places on it; today it enrolls, reports inventory, heartbeats and workloads, sets its
  runner's concurrency, keeps the desired state and commands it is sent, runs a managed
  gitlab-runner, which it drains and quarantines, updates its own `vk` on trial, and resets.
- **`vk-hub`** — the hub binary: inventory, desired state, operations, audit log, web UI, and
  later reservations, job placement and the client API job producers use. Its database is
  `redb`, as `vk-registry`'s accounts store is.
- **`vk-gitlab`** — experimental, a crate of this workspace: gitlab-runner's GitLab-facing
  side, reimplemented. It holds runner tokens, takes jobs from GitLab and submits them to the hub,
  and writes their traces and states back to GitLab.
- **`vk-hub-proto`** — the hub↔node wire types, versioned, beside the VM list `vk workloads`
  prints for the programs on its host, the hub's client API and the job spec. A node and the
  hub negotiate the protocol version on connect; a rolling update runs mixed versions by
  definition.
- **`vk-registry`** — unchanged and operated separately. Nodes pull from it directly; the hub
  is one of its clients.

Where state lives:

| Owner | State |
|---|---|
| GitLab | the CI queue, job status, traces, artifacts, cancellation |
| `vk-gitlab` | runner tokens, the GitLab jobs it has taken and their trace offsets |
| hub | inventory, desired state per node, operations in progress, audit log, placed jobs and their output |
| node | processes, admission ledger, checkouts, caches, job history, drain state, command journal |
| registry | images and build content |

## Node requirements

A node is any host `vk` already runs on:

- an x86-64 Linux kernel with KVM enabled;
- a dedicated user with read/write access to `/dev/kvm`;
- network access to the hub, to GitLab, and to the registries its jobs pull from.

`vk check`'s KVM, VMM and guest-kernel probes are the gate: a node refuses to enroll while
one fails. No root is needed at runtime and no distribution is assumed. `vk node run` is a
foreground process; how it is kept running is the host's choice. `vk node service install`
installs a systemd unit for it (see [Running the node](fleet-prototype.md#running-the-node));
any other supervisor works. A unit running it with a managed runner wants
`KillMode=mixed`: gitlab-runner takes `SIGTERM` as abandoning its jobs, so the stop signal
must reach the node alone, which quits the runner and waits for the jobs; a second one sends
the runner `SIGTERM`. Its `TimeoutStopSec` bounds that wait: past it, systemd kills both.

A managed gitlab-runner runs as the node's user, with its configuration under
`~/.gitlab-runner/` unless `[node] runner_config` names another, so `vk node` edits its
`concurrent` directly. A root-managed runner is supported through `vk-runnerctl`, as `vk tune`
uses it, with its concurrency the only thing the hub steers.

Enrollment uses a single-use token and a node-generated ed25519 identity. The hub pins the
key, and the identity survives updates. See [enrollment](fleet-prototype.md#enrollment) for
the command and retry behavior.

## Hub ↔ node protocol

The node dials the hub over WebSocket on TLS; nodes need no inbound port. The connection
carries control, telemetry and placed jobs' output — images, caches and artifacts go directly
between nodes and the registry or GitLab.

Each connection opens with:

- the protocol version range each side speaks;
- the node's ID and a signature over a hub-issued challenge, made with the node's key and
  covering both version ranges, the version the hub chose — the highest both speak, which
  the node checks — and the TLS connection it arrives on, so it cannot be replayed on another
  connection or used to steer the session to an older version;
- the node's **incarnation ID**, new on every `vk node run` start, so the hub tells a reconnect
  from a restart;
- the node's full observed state and every command outcome the hub has not yet recorded,
  from protocol version 2; then its inventory, heartbeats and workloads.

Then:

- **node → hub**: inventory when it changes, a heartbeat with capacity and job counts every
  few seconds — at an interval the hub sets, since the hub decides when a quiet node counts
  as unreachable — and command progress and results.
- **hub → node**: desired state, as a document with a generation number; operations
  (`drain`, `quarantine` and their reverses, `update`, `reset`), each with an ID
  and an expiry.

Steering — desired state, commands and their outcomes — takes protocol version 2 on both
sides; a session with a version-1 node (0.83.0 or 0.84.0) carries monitoring only.

A node applies a desired-state generation at most once, and journals every command before
acting on it, so a command redelivered after a reconnect is recognized and not repeated. It
repeats each command's outcome until the hub says it has stored it. The hub resends desired
state to a node that reports an older generation, and every command without a final outcome;
a command the node never takes expires after a day. A lost connection means the node's
state is unknown, not that it stopped. The prototype's session, limits and timeouts are in [the
reference](fleet-prototype.md#hub-and-node).

**Losing the hub does not stop the fleet.** A disconnected node keeps running CI under its
local policy and the last desired state it applied, and a drain or quarantine it has
persisted stays in force.

## Configuration

A node's `vk` configuration (`config.toml`) is authoritative: paths, shares, resource
ceilings, and the executor tuning a host with a lot of RAM and a slow network disk depends on
(tmpfs `checkout_dir`, reused host-side checkouts, DAX shares, disk admission). The hub only
narrows it — a lower concurrency ceiling, stopped acquisition, drain, quarantine, a choice
among versions the node allows — and, apart from a forced update, never overrides a limit
local policy sets or pushes `[executor]` settings. Proposed: the node's configuration also
sets which operations the hub may run.

The node reports a hash of its effective configuration, and its node page shows it, so drift
between nodes that should match is visible.

## Inventory

Every node reports, keeping hard facts, measured load and operator policy apart:

- **hardware** — CPU model and count, memory nodes, RAM, `vk check` results;
- **storage** — for the job-dir and checkout filesystems: identity, size, free bytes and
  inodes, tmpfs or disk, and a speed class the operator declares (`fast`, `slow`);
- **pressure** — memory available, CPU, memory and I/O PSI, disk latency;
- **runner** — the gitlab-runner configuration, its `concurrent` and runner names, its
  version, and its jobs preparing, waiting on admission, running and cleaning up;
- **admission** — memory reserved and budget, disk claimed;
- **versions** — `vk`, the guest kernel, the effective configuration hash.

A transient reading never changes a node's declared capabilities. The facts — hardware,
filesystem identity and size, declared speed class, versions, runner configuration — are
the inventory, sent when they change; the readings — pressure, free bytes and inodes,
admission — ride on the heartbeat. The prototype reports memory available, admission, free
space and the runner's configuration; PSI, disk latency, disk admission, the runner's version
and its jobs by stage are not reported yet.

### Workloads

A node also reports the VMs running on it for its user, so the hub shows what a node is
doing rather than only how full it is; [local mode](#local-mode) shows the same list for the
machine it runs on. Each entry carries:

- the kind — CI job, dev environment, pinned run (`vk run --state-dir`);
- what it belongs to — project, job name and job ID for CI; workspace and environment for
  `vk dev`; the image and project directory for a run;
- the pid of the process managing it — the `vk run`, or the job's supervisor — its vCPUs,
  the memory reserved for it, when it started, and its state dir. The reservation is the
  admission ledger's for a CI job, and the memory the VM booted with otherwise.

Workload discovery reads existing host records rather than creating another source of truth.
It must avoid touching stopped environments or their workspaces. Reports are bounded, expose
omissions, and distinguish reserved memory from measured host memory. The hub keeps the latest
list, not a history. See [workload reporting](fleet-prototype.md#workloads) for discovery,
limits, measurement cadence and current UI support.

## Runner concurrency

This section is about a node's own gitlab-runner, which [GitLab jobs](#gitlab-jobs) replace;
a placed job is admitted through a reservation instead.

A node's gitlab-runner takes as many jobs as its `concurrent` allows, and a job admission
makes wait has already been assigned by GitLab: it cannot move to an idle node. So each node
keeps its runner from accepting work its host cannot start promptly, with one decision:

```
effective = min(local estimate, hub ceiling, local ceiling)
```

- **local estimate** — `vk tune`'s control law: the jobs running plus as many typical jobs as
  fit the memory budget and the host's available memory, falling at once and rising one step
  at a time.
- **hub ceiling** — set by the hub in the node's desired state, for a node that is unhealthy,
  saturated on a resource the estimate does not see, or whose capacity is kept for other work.
- **local ceiling** — `[executor.schedule] max_concurrency`, the node's own limit.

`vk tune` and `vk node run` use one controller, with a single writer while the node is up.

The node applies the hub's ceiling whether or not the hub is reachable. gitlab-runner has no
`concurrent = 0`, so **stopping acquisition** is a state rather than a number, and needs a
runner the node runs itself: the node sends gitlab-runner `SIGQUIT`, which stops it
requesting jobs and lets running ones finish, and does not start it again until the state is
lifted. Proposed: the hub also pauses the runner through the GitLab API, which keeps GitLab
from assigning it jobs even if a request is already in flight when the node stops it. See
[concurrency control](fleet-prototype.md#concurrency-control) for the cadence and how the
number reaches the runner.

An operator sets the hub's ceiling today. Proposed: the hub adjusts ceilings itself over tens
of seconds with hysteresis, cutting quickly under sustained pressure and raising slowly,
without aiming for equal utilization.

What this achieves is coarse: a node accepts about what it can start, a job beyond that waiting
at admission, and compatible work lands elsewhere. It cannot pick the best node for a given
job, and checkout or image locality is incidental — the next job of a project may not return to
the node holding its tree.

Tags should be stable workload classes (e.g. `vk`, `large-memory`), assigned per runner by the
operator. GitLab requires a runner to have every tag a job asks for, so tags decide which
runners are eligible; load is never encoded in them. Protected and untrusted work are
separated by runner registration and project scope, not by tags.

## Node states

```
ready ─▶ draining ─▶ drained ─▶ maintenance ─▶ validating ─▶ ready
                                                   │
quarantined (entered from any state; left only by an operator)
```

A drain:

1. is persisted on the node before anything else;
2. stops acquisition and, proposed, pauses the runner in GitLab;
3. waits for gitlab-runner to finish its jobs, the executor's cleanup, and the admission
   ledger to empty;
4. reports `drained` only once all three hold.

Drain state survives a node restart or loss of the hub. Stopping acquisition requires a
managed runner; the prototype refuses drain and quarantine with an external runner. See
[drain and runner lifecycle](fleet-prototype.md#drain-and-runner-lifecycle) for observations,
runner adoption and transitions.

The intended `validating` gate runs a boot/exec/network smoke test and, when configured, a
representative synthetic job before the node goes back to `ready`. The prototype's default is
weaker: the workload test depends on the operator configuring `[node] validate`.

All six states are built; an update or a reset is what takes a node through `maintenance`
and `validating`. The prototype's
[maintenance transitions](fleet-prototype.md#maintenance-transitions) define how concurrent
drain, quarantine, update and reset requests interact.

A node that stops heartbeating is shown as unreachable, not paused: pausing every
disconnected node would turn a hub outage into a fleet outage.

## Updates

The intended update sequence is: check the release metadata and signing policy → drain →
download and verify the approved release → run it on trial → validate and reconnect → install
and return to the previous node state. The installed binary stays untouched during the trial.
Downloading before draining could shorten maintenance later, but must not run the candidate
before its bytes and the configured signing policy have been checked. Rollback protects the
binary; future configuration migrations must separately preserve a form the previous binary
can read.

Rollouts go by hardware profile: one canary per profile, then small batches, each node
updated, validated and back in its state before the next batch starts. Rollout state lives
in the hub's database, so a rollout survives a hub restart. Built:
[Rollouts](fleet-prototype.md#rollouts).

`vk-selfupdate` provides the download, digest check, version smoke test and atomic rename.
Fleet updates add:

- a signature check against keys pinned on the node, before the new binary runs;
- proposed: the same pinning for the gitlab-runner binary;
- one `vk` binary per job for the job's whole life: executor stages running during a switch
  must not mix versions, which draining guarantees.

Built: a node drains, downloads and checks the release, and runs it on trial with the
installed binary untouched; the release must pass `vk check`'s gate and `[node] validate`, and
reach the hub again, before it installs itself, and a failure, repeated crashes at start or
the trial's deadline hand the node back to the previous binary. See
[update trial and rollback](fleet-prototype.md#update-trial-and-rollback) for the binary
switch, restart deadlines, installed-path checks and the external-runner exception.

Built release trust: a node with signing keys in its own configuration requires a signature
by one of them, checked when the update arrives and again before the release first runs; the
key signs offline, never on the hub ([Release signing](fleet-prototype.md#release-signing)).
Proposed: remote updates require at least one locally pinned signing key and a valid
signature by default, where a node with no keys takes unsigned releases today. A node may opt
out explicitly for development; the hub cannot grant that exception, and the node's report
and UI must show it. Official release signing is
a prerequisite for using that default with official binaries. Document key rotation with an
overlap period, removal of retired keys, and emergency revocation through a trusted path
independent of the hub. A compromised hub must not be able to add a trusted key or undo its
revocation. Proposed: forcing an update on a node without a managed runner needs the node's
own permission, not just the hub's, and the operator is shown that executor stages may then
cross versions; today the hub alone allows it, with `--force`.

Proposed validation and promotion: provide a standard workload using an image pinned by digest
that boots with the candidate, executes a command, checks required networking and proves its
cleanup completed. Require that test for unattended rollouts; a successful host check and hub
reconnection alone are insufficient. Sites may add representative CI jobs through local
validation policy. An unavailable test dependency blocks promotion and is reported distinctly
from a candidate failing its test; neither result is success.

Canaries must pass this validation and a configured observation window before the next wave.
Where representative job results are used, require an explicit minimum number of successes;
a quiet node does not satisfy the gate merely by waiting. Persist the evidence and the window
with the rollout so a hub restart does not bypass them. Allow operator-defined canary groups
for material configuration differences, such as VMM version, kernel and executor settings,
alongside the hardware profile. Show uncovered groups before starting a rollout. This gate is
not built: a canary is promoted as soon as its own update has passed.

Release downloads are authenticated and scoped to a pending update; their bytes do not ride on
the control session. The hub stores and serves releases this way
(see [Releases](fleet-prototype.md#releases)).

## Resets

| Operation | Effect |
|---|---|
| restart | restart `vk node` and its gitlab-runner |
| reset | drain, stop anything the node's user still owns from past jobs, clear chosen caches and scratch, validate |
| redeploy | reinstall the host (Redfish/IPMI and PXE) — only on [managed nodes](#managed-nodes) |

A node without a BMC integration reports redeploy as unavailable.

Only reset is built. Its [current implementation](fleet-prototype.md#resets) drains a managed
runner, stops and removes recognized leftovers and selected caches, then validates. Restart and
redeploy remain planned.

Proposed reset contract: track each job's host processes in an explicit ownership boundary,
preferably a delegated cgroup where the host supports it. A process that changes its executable
or arguments must remain attributable to that job. Stop the boundary and verify it is empty
before releasing its network lease or deleting its scratch. Failure to inspect ownership is
a maintenance failure, not evidence that nothing remains; leave the node drained and report
what could not be established. Protect the node supervisor and unrelated workloads from the
cleanup boundary.

The existing executable-and-argument scan remains a fallback for older jobs and hosts without
that boundary. It cleans recognized leftovers but cannot prove that every descendant is gone,
so it must never be described as a verified clean reset or satisfy unattended maintenance's
reset gate. Proposed: report that limited coverage with the result; today a reset's outcome is
only `done` or `failed`, and what it cleared goes to the node's log.

## Web UI

Served by the hub on its own listener, server-rendered HTML with no JavaScript build
toolchain in the release build:

- **htmx** with its SSE extension, both embedded in the `vk-hub` binary. Pages subscribe to
  server-sent events that carry HTML fragments (`event: nodes` / `data: <table …>`); actions
  are plain form POSTs. SSE rather than WebSocket: it is ordinary HTTP, reconnects on its
  own, and is one streamed response body on the hub's hyper server.
- **A strict Content Security Policy** on every page: `script-src 'self'`, no inline script,
  no `unsafe-eval`, and htmx configured with `allowEval: false`. The pages show strings nodes
  send — hostnames, versions, error text — so the policy is what keeps an escaping mistake
  from becoming script in an operator's session that will be able to drain or redeploy
  machines.
- **Not Datastar:** it compiles every `data-*` expression with `Function(...)`, which needs
  `'unsafe-eval'`.

Pages, in order of priority:

1. **nodes** — state, capacity (local estimate, hub ceiling, effective), pressure, admission
   waits, versions, configuration drift; desired, observed and unknown shown distinctly;
2. **node detail** — inventory, effective configuration, recent jobs linked to GitLab, atop
   timelines and egress reports;
3. **operations** — drains, resets, rollouts and their progress; built so far, releases and
   rollouts, with a node's drain and reset steered from its page;
4. **audit** — every operator action and every command's outcome.

Built: the nodes table, node detail and audit pages, and the operations page's releases and
rollouts. Proposed: pressure and admission waits in the nodes table, and recent jobs linked to
GitLab, atop timelines and egress reports on node detail.

Proposed: metrics for capacity, admission waits and node states, exported for Prometheus.

See the prototype reference for [UI configuration and live pages](fleet-prototype.md#web-ui)
and their rendering and connection limits.

### Signing in

People sign in through the OIDC provider `[oidc]` names, with the relying party `vk-registry`
uses, and are given the viewer or operator role by their email (unless the provider marks it
unverified), from a grant `vk-hub accounts` keeps in the hub's database; anyone else is
refused. Sign-in links issued through the admin socket also establish viewer or operator
sessions, for whom the provider cannot sign in. See the prototype reference for [sign-in,
sessions and request checks](fleet-prototype.md#signing-in).

## Local mode

`vk-hub local` runs the hub for the one machine it is started on, for a person
watching and controlling their own VMs — the role virt-manager plays for libvirt:

- no enrollment and no node session: it runs as the user who owns the VMs and reads their
  [list](#workloads) from a `vk workloads --watch` child;
- the same UI and request checks, over plain http on loopback under a per-start name,
  opened in the browser with a sign-in link the way Jupyter does;
- a state dir of its own under the user's XDG state home, so it never shares a database with
  a fleet hub.

Actions reuse existing CLI commands as subprocesses. The UI must preserve their ownership
checks, confirm destructive actions against the observed workload identity, and audit actions
before running them. CI jobs are left to the executor. A browser shell is planned.

Local mode draws a random `.localhost` name, and a port unless `--port` names one, on every
start, binds both loopback address families and ends the previous run's sessions. This
separates its cookies from other local services and prevents reuse of the previous origin's
authority. The [local mode reference](fleet-prototype.md#local-mode) records the threat
model, commands and process handling.

## Security

- Nodes accept typed operations only, never a shell command. Proposed: each checked against
  the operations local policy allows.
- Node identities are pinned keys, revoked from the hub (`vk-hub nodes remove`); rotation is
  not built. Enrollment tokens are short-lived and single-use.
- A hub chooses which release a node updates to, never whether it may go back: a node refuses
  an older `vk` than it runs unless its own configuration allows it (`[node] allow_downgrade`),
  since an override the hub carried would be worth nothing against a compromised hub — which
  could otherwise take the fleet back to a release with a known flaw, signed or not.
- A release's signature is checked by the node against keys in its own configuration
  (`[node] release_keys`), made by a key kept off the hub: a compromised hub can hand a node
  any bytes, but not a signature it has no key for.
- Proposed: runner authentication tokens stay on their nodes, and the hub's GitLab
  credential is a separate one, scoped to managing runners (pause, resume, list). With
  [GitLab jobs](#gitlab-jobs), runner tokens are `vk-gitlab`'s alone and leave no node.
- Hub roles: viewer; operator (ceilings, stopping acquisition, drain and quarantine,
  pausing, resuming and aborting rollouts, resets); admin (enrollment, releases,
  starting a rollout, and the proposed redeploy). Proposed: BMC
  credentials are held apart and used only by redeploys. Admin is the admin socket's:
  whoever runs as the hub's user or root, who also issues the web UI's sign-in links; a web
  UI session is a viewer or an operator: an operator steers a node from its page and a
  rollout from the operations page, and a viewer only looks.
- The web UI and the node endpoint are separate listeners with separate authentication.
  Every UI response carries `Content-Security-Policy: default-src 'self'; script-src 'self';
  style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none';
  form-action 'self'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: same-origin`, `Cross-Origin-Resource-Policy` and
  `Cross-Origin-Opener-Policy` `same-origin`, and, over https, `Strict-Transport-Security`;
  pages are `no-store`, and refused to a request whose `Sec-Fetch-Site` is `same-site` or
  `cross-site`. A request whose `Host` is not `ui_url`'s — local mode's own name — is refused
  with 421, so a page on another name that resolves to the UI's address reaches nothing (DNS
  rebinding); a reverse proxy in front of the UI must pass the `Host` it was asked for.
- Run the hub on its own host and back up its database and secrets. In the prototype, the
  hub sends desired state only after a node reports the generation it applied. If that
  generation is newer, the hub reissues its stored state as the generation after it. This
  orders messages but does not reconcile intent: restoring a backup from before an
  acquisition stop or a ceiling cut can reissue an older permission to run. A hub with no
  desired state for the node adopts its reported applied state, preserving its restrictions.
  This covers backups predating steering and downgrades to 0.84.0 or earlier followed by an
  upgrade, since those versions drop desired state. Operator changes made before the node's
  report replace only the fields they set. A node forgets its applied
  generation when enrolled anew or with another hub, since generations count for one hub and
  one enrollment.

### Proposed recovery after a hub restore

A node ahead of the hub is a recovery conflict. Preserve the node's applied restrictions,
mark the conflict in the CLI and UI, and suspend automatic desired-state changes and new
maintenance commands to it, including rollout advancement, until an operator resolves it.
Ordinary work continues under the node's existing policy; an in-progress maintenance
operation follows its persisted local recovery rules. A higher generation alone is never
evidence of newer operator intent.

The node reports the applied policy as well as its generation, and the prototype adopts it
when the hub holds no policy of its own for the node. Reconciliation presents that policy
beside the hub's restored policy and lets the operator explicitly adopt the node's
restrictions or replace them with a reviewed policy. Record the decision and both
states in the audit log before sending anything. Keep persisted drain and quarantine intact;
recovering the hub does not authorize lifting either.

The restore procedure must also reconcile pending commands against node journals and their
acknowledged outcomes before replay or rollout advancement. Old commands that would relax
restrictions require review. Test recovery from a backup taken before a stop, a ceiling cut,
a quarantine, a completed maintenance command and a rollout transition. These rules replace
the prototype's automatic generation bump; they are not implemented yet.

## Phase 2: placed jobs

Placed jobs — [GitLab jobs](#gitlab-jobs) first, generic jobs after — require
**reservations**, which phase 1 lacks. The hub asks a node to set a resource envelope aside;
the node accepts or refuses immediately through its admission ledger. When the workload
starts, its ledger entry takes over the envelope. Leases run on the node's clock and expire
unless renewed. All workload types — CI job VMs, their services, image builds and placed
jobs — must use that ledger before sharing a node.

Both kinds of job reach the hub through one client API and run on the node through one job
API: a durable job identity, ordered output resumable from an offset, cancellation, and
results that keep a job's own failures apart from the fleet's. The contract is
[GitLab dispatch](gitlab-dispatch.md).

### Generic jobs

The hub owns their queue, so it can place each one exactly:

```
Job {
  kind: vm | compose,
  image: registry digest,
  resources: { mem, cpus, disk, numa? },
  inputs: registry blobs,
  egress: policy,
  command | compose file,
  timeout, retry policy,
  outputs: log stream, exit status, artifacts to the registry, atop timeline
}
```

Placement filters on labels and capabilities, scores on headroom and locality, then takes a
reservation on the chosen node. A compose group runs whole on one node. Inputs are packaged
explicitly; nothing refers to a submitter's local paths. A job whose node disconnects is not
rerun until its first run is known to be over, and only under a retry policy that says its
side effects can repeat.

### Authentication for submitted jobs

Two kinds of principal submit jobs; nodes never do — a node's key authenticates its session
and nothing else.

| Principal | Credential | Client side |
|---|---|---|
| a person | OIDC login on the hub, exchanged for a short-lived hub session token | `vk hub login https://hub` — the OAuth device flow, so it works over SSH; the token is kept `0600` under `~/.config/virtkit/` |
| other automation — `vk-gitlab` first | a scoped API key: hashed at rest, expiring, revocable | `token_file` in the config, as the registry client does |

The hub and `vk-registry` are to share one identity layer — the registry's accounts
machinery, used by both — so a person has one login and an API key is issued in one place.
They share the OIDC relying party today; the web UI's sessions are the hub's own, and its
roles come from its own grants rather than from the registry's accounts.

Policy on the hub maps a principal (a user, a group or an API key) to:

- **pools** — the execution classes and nodes it may use; a job cannot name one its
  principal is not allowed;
- **limits** — the largest job, and how many may run at once;
- **egress** — the widest policy its jobs may have; a job can narrow it, never widen it;
- **secrets** — a job carries references only; the hub resolves them from a store scoped to
  the principal and hands them to that job's node alone.

A node pulls a job's image with a short-lived registry token the hub mints for that job:
read-only, scoped to the image's repository, and issued only if the submitter may read it.
A node's own registry credential is never used for a submitted image, so no one runs an image
through the fleet that they could not pull themselves. That check is as strict as the
registry's read rules, under which every authenticated session reads every repository; they
need per-user read scopes before it means more.

A job's owner can see and cancel it; operators can see and cancel every job. Each job records
its principal — user or key — in the audit log.

## GitLab jobs

Experimental; the wire contract is [GitLab dispatch](gitlab-dispatch.md), and
[GitLab end to end](gitlab-e2e.md) runs it against a real GitLab.

`vk-gitlab` is gitlab-runner's GitLab-facing side, reimplemented: it registers as one or more
runners, asks GitLab for jobs, and has the hub run each on a node. The node runs the job's
stages itself — no gitlab-runner binary on the node or in the guest — reusing the executor's
VM, exec, checkout and cleanup code. The local gitlab-runner with the vk executor is the
transition state: it keeps working on the nodes still configured for it, and a node moves
over by draining its runner and taking placed jobs instead.

```
GitLab ◀──runner API──▶ vk-gitlab ──client API──▶ vk-hub ◀──session──▶ vk node ──▶ microVMs
  ▲                                                                       │
  └──────────── clone, dependency artifacts, artifact uploads ────────────┘
```

| Party | Does | Holds |
|---|---|---|
| `vk-gitlab` | job requests, the commit, trace patches, state updates, keep-alives, the final update, cancellation from `Job-Status`, failure mapping | runner tokens, its hub API key, the jobs it has taken |
| hub | capacity, reservations, placement, output storage, cancellation and loss of jobs | job records and output; specs in memory until a node accepts |
| node | admission, the stages, masking, the clone, caches, dependency downloads, artifact uploads | the job's spec, its tokens and secrets, while it runs |

**Admission.** GitLab cannot take a job back from a runner, so `vk-gitlab` holds capacity
before it asks for a job, never after. It polls GitLab for a runner only while the hub reports
room for the runner's placement; before each job request it holds a reservation on a node, its
lease covering the request; and it submits the job it gets on that reservation, where the node
sizes it by its own rules. Idle capacity is one reservation per outstanding job request. A job
arriving after its reservation ended — the node lost, or its lease out — is placed afresh,
within a bound, and otherwise fails as `runner_system_failure`.

**Placement.** GitLab's job response does not carry the job's tags, and tags already decide
which runners may take a job, so a runner maps to one placement: a hub pool, node labels and
an envelope, in `vk-gitlab`'s configuration. The API key's policy on the hub bounds the pools
and envelopes the daemon may use. Services run with the job as a compose group on its node.

**Trust.** Runner tokens and the API key stay with `vk-gitlab`. The node gets the job token,
the dependency tokens and the job's variables: everything the job itself is given, and what
it needs to clone and transfer artifacts. The hub sees a job's secrets in transit and does not
store them.

**Output and artifacts.** The node masks the output and streams it at byte offsets to the hub,
which stores it before acking; `vk-gitlab` patches GitLab's trace from GitLab's own offset, so
either side can restart and resume. Artifacts go from the node to GitLab with the job token,
as gitlab-runner's uploader does from the build environment, rather than through the hub,
whose session carries no bulk data. Caches go to the registry, kept apart by project and by
the protection of the job's ref, as gitlab-runner keeps them.

**Cancellation and failures.** GitLab's `Job-Status` on a trace or update answer — `canceling`
or `canceled` — becomes a graceful or immediate cancel, from `vk-gitlab` to the hub to the
node. The node classes how a job failed; `vk-gitlab` maps the class to the `failure_reason`s
the job's GitLab accepts. A node unreachable past a grace period loses its jobs, which fail as
`runner_system_failure`, and GitLab's `retry:` rules decide what happens next: the hub places
a job a second time only while no node can have started it.

**Reimplemented, dropped.** Reimplemented, as gitlab-runner 19.5 does them: the runner API
client — verify, job requests with long polling, trace patching, updates, keep-alives — the
stage order, bash script generation, trace masking and sections, cache key handling, and the
artifact archive formats and uploads. Ports of gitlab-runner code and fixtures keep its MIT
notice. Dropped: every executor but this one, the helper image (the node and `vk-agent` do its
work), interactive web terminals and session proxies, external secret providers, native
steps, job inputs, artifact provenance metadata, and `gitlab-runner register`. A job that
needs one of these fails as `runner_configuration_error` rather than running differently.

**Compatibility.** `vk-gitlab` advertises in its job requests only the features it
implements, so GitLab does not hand it a job that relies on another. gitlab-runner's own tests
— its job response samples, trace and update expectations, failure-reason mapping — are
ported as compatibility tests, and each release of `vk-gitlab` names the gitlab-runner
version it matches.

## Managed nodes

Proposed, not built: for hosts the hub owns end to end, a node OS image, offered but never
required:

- built with `vk build --disk`: a minimal system with a kernel, KVM, a `vk` user and
  `vk node`;
- installed by PXE — the hub is to serve iPXE, the installer kernel and initramfs, and the
  disk image, the payload `vk export iso` packages for USB installs. The image carries no
  token: the hub issues a single-use enrollment token per machine at install time;
- redeployed over Redfish or IPMI: drain, one-time PXE boot, power-cycle, install, re-enroll.

## Prototype first

1. **Acquisition and drain races** — burst submissions against long polls, concurrency cuts,
   API pause, `SIGQUIT`, runner restarts, hub partitions. Measure jobs accepted but waiting on
   admission, and show that `drained` is only reported when nothing is left.
2. **The slow-disk, large-RAM host under real mixed load** — checkout RAM, image builds, disk
   latency, inode pressure, DAX. Admission does not count image-build guests today, and disk
   admission predicts bytes without tracking inodes.
3. **Update recovery** — a crash during download or switch, a failed validation, rollback, a
   reconnect carrying stale commands.
4. **Accounting completeness** before phase 2: every workload type in the one ledger.

### Prototype exit criteria

Before phase 2 or unattended fleet maintenance, demonstrate the following on a small fleet.
Record the versions, configuration, injected failure, observed transitions and audit evidence
for each run. Unit tests of transitions complement these exercises; they do not replace a
runner, node and hub being interrupted together.

| Exercise | Required result |
|---|---|
| Restore a backup older than a stop, a ceiling cut or a quarantine | Recovery conflict is visible; acquisition does not resume, the ceiling does not rise and the quarantine is not lifted without an explicit reconciliation decision |
| Partition the hub during ordinary CI and during drain | Ordinary CI follows persisted policy; drain remains in force; an unreachable node is never presented as confirmed idle |
| Burst jobs during concurrency cuts, a drain, runner shutdown and restart | Accepted work is accounted for; `drained` is reported only after runner exit, cleanup and admission completion |
| Drop command acknowledgements and reconnect with duplicates | The journal preserves one operation identity and its outcome; replay does not repeat a completed destructive effect |
| Crash before and after each durable update transition, including install | Restart resumes or rolls back deterministically; it neither accepts jobs prematurely nor loses the known-good binary |
| Let host checks pass but fail candidate boot, networking or cleanup | Validation fails and the rollout cannot promote the canary |
| Complete a canary update, then fail representative jobs or interrupt its observation window | The next wave stays blocked; hub restart preserves the gate and its evidence |
| Lose the hub during a trial or make a test dependency unavailable | The trial reaches a bounded recovery outcome; missing evidence never becomes successful validation |
| Move wall clocks forward and backward during command expiry and trials | Documented deadline semantics hold; a clock change cannot leave maintenance unbounded or revive completed commands |
| Update with no trusted key, an invalid signature or a revoked key | Remote update is refused before candidate execution; only unsigned development updates have an explicit local opt-out, which never bypasses a failed signature check |
| Reset with an orphan that changes executable or arguments, or with process inspection denied | Ownership catches the orphan or reset reports that it cannot prove cleanup; scratch is not removed under a known live owner |
| Run reset beside unrelated local workloads | Only the job ownership boundaries selected for cleanup are affected |

The immediate milestone is a small fleet surviving these failures with no unexpected resume,
false drain, unvalidated promotion or ambiguous cleanup reported as verified. Complete resource
accounting remains an additional prerequisite before different workload types share phase 2
reservations. Restart, redeploy and broader scheduling do not take priority over these gates.

## Integration path

Each step ships in a release of its own and leaves the fleet working. Throughout, workloads
carry IDs of their own, node-local policy stays authoritative and the protocol is versioned.

1. **Local mode.** `vk workloads` and `vk-hub local`: one host's VMs, a page each, and
   lifecycle actions, with no hub↔node session. Its web UI is the core the fleet's is built
   on.
2. **Phase 1.** Enrollment, sessions, inventory, hub ceilings and stopping acquisition,
   drain and quarantine, signed releases and rollouts, resets, the workloads each node runs.
   Nodes keep their local gitlab-runners. Before unattended maintenance, the gaps in the
   [capability table](fleet-prototype.md#status) close — the GitLab API pause, gitlab-runner
   pinning, resets by process ownership, a representative validation workload, recovery after
   a hub restore, pinned release keys — and the [exit criteria](#prototype-exit-criteria) are
   met.
3. **Complete accounting.** Every workload type in the node's admission ledger, image builds
   included, with disk admission tracking inodes.
4. **Reservations**, as phase 2 describes them, each with a lease the node expires on its
   own: protocol version 3. A job's processes run inside an ownership boundary that resets
   reuse.
5. **A node job API** that runs a placed workload for the hub: durable job and stage
   identity, ordered output resumable from an offset, cancellation, exit codes that keep
   build failures apart from system failures, and cleanup when the lease lapses.
6. **GitLab jobs.** The hub's client API with API keys, pools and labels, and `vk-gitlab`;
   nodes run GitLab jobs' stages themselves. Nodes move over one at a time, each draining its
   local gitlab-runner; a fleet runs both kinds of node meanwhile.
7. **Generic jobs.** `vk submit`, people as principals and their policy, scoring on locality,
   and per-job registry tokens, on the client API GitLab jobs already use.
8. **Managed nodes** — the OS image, PXE, Redfish — whenever a host is to be managed end to
   end, independent of steps 3 to 7.

Steps 3 to 6 are the critical path; 7 builds on them.

The end state is one placement engine on the hub over every node's ledger, fed by jobs
submitted to the hub — GitLab's through `vk-gitlab`; nodes keep admission and local policy,
and run no gitlab-runner; local mode remains the form for a single host.
