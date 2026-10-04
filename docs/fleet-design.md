# Fleet: a hub and its nodes

Status: experimental, implemented in part. This document describes the architecture,
intended guarantees and proposed improvements. The [prototype reference](fleet-prototype.md)
records what is built, its commands, defaults and limitations. “Proposed” sections below are
work still to do, not guarantees of the current prototype.

Start with the [capability table](fleet-prototype.md#status) to compare current behavior with
the intended gates. The [prototype exit criteria](#prototype-exit-criteria) define the evidence
required before unattended maintenance or phase 2.

A fleet is a set of machines running `vk node`, managed by one `vk-hub`. The hub owns the
fleet's inventory, desired state and operations — capacity ceilings, drains, `vk` rollouts,
resets — and shows them in a web UI. It does not take GitLab jobs itself: each node keeps
its own gitlab-runner with the vk executor, and the hub steers how much work each runner
accepts. Central placement comes first for generic VM jobs, whose queue the hub owns, and
reaches GitLab jobs only if measurements show that local acquisition is not good enough.

The target is a fleet of tens of bare-metal hosts, not hundreds: one hub process, one
embedded database, no replication.

## Components

- **`vk node`** — a `vk` subcommand run as a long-lived supervisor on each node. It links
  the executor, admission, the concurrency controller and self-update in-process, dials the
  hub, and applies what the hub asks within what local policy allows.
- **`vk-hub`** — a new binary: inventory, desired state, operations, audit log, web UI, and
  later the generic job queue. Its database is `redb`, as `vk-registry`'s accounts store is.
- **`vk-hub-proto`** — the hub↔node wire types, versioned, beside the VM list `vk workloads`
  prints for the programs on its host. A node and the hub negotiate the protocol version on
  connect; a rolling update runs mixed versions by definition.
- **`vk-registry`** — unchanged and operated separately. Nodes pull from it directly; the hub
  is one of its clients.

Where state lives:

| Owner | State |
|---|---|
| GitLab | the CI queue, job status, traces, artifacts, cancellation |
| hub | inventory, desired state per node, operations in progress, audit log |
| node | processes, admission ledger, checkouts, caches, job history, drain state, command journal |
| registry | images and build content |

## Node requirements

A node is any host `vk` already runs on:

- an x86-64 Linux kernel with KVM enabled;
- a dedicated user with read/write access to `/dev/kvm`;
- network access to the hub, to GitLab, and to the registries its jobs pull from.

`vk check` is the gate: a node refuses to enroll while it fails. No root is needed at
runtime and no distribution is assumed. `vk node run` is a foreground process; how it is
kept running is the host's choice (`vk node install` writes a `systemd --user` unit where
there is one). A unit running it with a managed runner wants `KillMode=mixed`: gitlab-runner
takes `SIGTERM` as abandoning its jobs, so the stop signal must reach the node alone, which
quits the runner and waits for the jobs; a second one sends the runner `SIGTERM`.

The node's gitlab-runner runs as the same user, with its configuration under
`~/.gitlab-runner/`, so `vk node` edits its `concurrent` directly. A root-managed runner is
supported through `vk-runnerctl`, as today.

Enrollment uses a single-use token and a node-generated ed25519 identity. The hub pins the
key, and the identity survives updates. See [enrollment](fleet-prototype.md#enrollment) for
the command and retry behavior.

## Hub ↔ node protocol

The node dials the hub over WebSocket on TLS; nodes need no inbound port. The connection
carries control and telemetry only — images and artifacts go directly between nodes and the
registry or GitLab.

Each connection opens with:

- the protocol version range each side speaks;
- the node's ID and a signature over a hub-issued challenge, made with the node's key and
  covering both version ranges, the version the hub chose — the highest both speak, which
  the node checks — and the TLS connection it arrives on, so it cannot be replayed on another
  connection or used to steer the session to an older version;
- the node's **incarnation ID**, new on every `vk node` start, so the hub tells a reconnect
  from a restart;
- the node's full observed state and the commands it has journaled but not yet reported
  done.

Then:

- **node → hub**: inventory when it changes, a heartbeat with capacity and job counts every
  few seconds — at an interval the hub sets, since the hub decides when a quiet node counts
  as unreachable — command progress and results.
- **hub → node**: desired state, as a document with a generation number; operations
  (`drain`, `update`, `reset`), each with an ID and an expiry.

A node applies a desired-state generation at most once, and journals every command before
acting on it, so a command redelivered after a reconnect is recognized and not repeated. It
repeats each command's outcome until the hub says it has stored it, and the hub resends
desired state to a node that reports an older generation, and every command without a final
outcome. A command the node never takes expires after a day. A lost connection means the
node's state is unknown, not that it stopped.

**Losing the hub does not stop the fleet.** A disconnected node keeps running CI under its
local policy and the last desired state it applied. A drain or quarantine it has persisted
stays in force.

## Configuration

A node's `virtkit.toml` is authoritative. It sets what the node permits — paths, shares,
resource ceilings, which operations the hub may run — and all of the executor tuning a host
like one with a lot of RAM and a slow network disk depends on (tmpfs `checkout_dir`, reused
host-side checkouts, DAX shares, disk admission).

The hub only ever narrows it: it can lower the node's concurrency ceiling, stop acquisition,
drain, and choose among versions the node is allowed to run. It never raises a limit local
policy sets and never pushes `[executor]` settings.

The node reports its effective configuration with a hash, and the UI shows it per node, so
drift between nodes that should match is visible.

## Inventory

Every node reports, keeping hard facts, measured load and operator policy apart:

- **hardware** — CPU model and count, memory nodes, RAM, `vk check` results;
- **storage** — for the job-dir and checkout filesystems: identity, size, free bytes and
  inodes, tmpfs or disk, and a speed class the operator declares (`fast`, `slow`);
- **pressure** — memory available, CPU, memory and I/O PSI, disk latency;
- **runner** — gitlab-runner version, runner IDs and tags, `concurrent`, jobs preparing,
  waiting on admission, running, cleaning up. Tags are held by GitLab, not the runner's
  `config.toml`, so they reach the hub through its GitLab credential;
- **admission** — memory reserved and budget, disk claimed;
- **versions** — `vk`, the guest kernel, the effective configuration hash.

A transient reading never changes a node's declared capabilities. The facts — hardware,
filesystem identity and size, declared speed class, versions, runner configuration — are the
inventory, sent when they change; the readings — pressure, free bytes and inodes, admission
— ride on the heartbeat.

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
wire limits, measurement cadence and current UI support.

## Load balancing without central acquisition

GitLab gives a job to whichever eligible runner asks first. The lever the fleet has is how
much work each runner asks for: its `concurrent`. Admission stays the final gate on each
node — but a job admission makes wait has already been assigned by GitLab, and cannot move
to an idle node. So the goal is to keep runners from accepting work their host cannot start
promptly.

Each node computes its own concurrency:

```
effective = min(local estimate, hub ceiling, local ceiling)
```

- **local estimate** — the control law `vk tune` applies today: running jobs plus as
  many typical jobs as fit the memory budget and the host's available memory, keeping 15% of
  the host back, falling at once and rising one step at a time. Extended with free disk
  bytes and inodes on the job-dir filesystem, I/O pressure, and jobs accepted but not yet
  admitted.
- **hub ceiling** — set by the hub, for a node that is unhealthy, saturated on a resource the
  local estimate does not see, or whose capacity is being kept for a specialist class.
- **local ceiling** — the administrator's limit in `virtkit.toml`, `[executor.schedule]
  max_concurrency`.

The standalone tuner and node use one controller, with a single writer while the node is up.
See [concurrency control](fleet-prototype.md#concurrency-control) for its cadence and runner
configuration paths.

gitlab-runner has no `concurrent = 0`. **Stop acquisition** is therefore a state, not a
number: the node sends gitlab-runner `SIGQUIT`, which stops it requesting jobs and lets
running ones finish, and does not restart it until the state is lifted. The hub can also
pause the runner through the GitLab API, which keeps GitLab from assigning it jobs even if a
request is already in flight when the node stops it.

The hub adjusts ceilings over tens of seconds with hysteresis: it cuts quickly under
sustained pressure and raises slowly. It does not aim for equal utilization.

What this achieves is coarse: a node takes no more than it can start, and compatible work
lands elsewhere. It cannot pick the best node for a given job, and checkout or image
locality is incidental — the next job of a project may not return to the node holding its
tree.

Tags are stable workload classes (`vk`, `large-memory`, `docker-vm`, `fast-scratch`),
assigned per runner by the operator. GitLab requires a runner to have every tag a job asks
for, so tags decide which runners are eligible; load is never encoded in them. Protected
and untrusted work are separated by runner registration and project scope, not by tags.

## Node states

```
ready ─▶ draining ─▶ drained ─▶ maintenance ─▶ validating ─▶ ready
                                                   │
quarantined (entered from any state; left only by an operator)
```

A drain:

1. is persisted on the node before anything else;
2. stops acquisition, and pauses the runner in GitLab;
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

The prototype's [maintenance transitions](fleet-prototype.md#maintenance-transitions) define
how concurrent drain, quarantine and update requests interact.

A node that stops heartbeating is shown as unreachable, not paused: pausing every
disconnected node would turn a hub outage into a fleet outage.

## Updates

The prototype's update sequence is: check the release metadata and signing policy → drain →
download and verify the approved release → run it on trial → validate and reconnect → install
and return to the previous node state. The installed binary stays untouched during the trial.
Downloading before draining could shorten maintenance later, but must not run the candidate
before its bytes and the configured signing policy have been checked. Rollback protects the
binary; future configuration migrations must separately preserve a form the previous binary
can read.

Rollouts go by hardware profile: one canary per profile, then small batches, each node
validated before the next batch starts. Rollout state is in the hub's database, so a
rollout survives a hub restart.

`vk-selfupdate` provides the download, digest check, version smoke test and atomic rename.
Fleet updates add:

- a signature check against keys pinned on the node, before the new binary runs;
- the same pinning for the gitlab-runner binary;
- one `vk` binary per job for the job's whole life: executor stages running during a switch
  must not mix versions, which draining guarantees.

See [update trial and rollback](fleet-prototype.md#update-trial-and-rollback) for the current
binary switch, restart deadlines, installed-path checks and external-runner exception.

Proposed release trust: remote updates require at least one locally pinned signing key and a
valid signature by default. A node may opt out explicitly for development; the hub cannot
grant that exception, and the node's report and UI must show it. Official release signing is
a prerequisite for using that default with official binaries. Document key rotation with an
overlap period, removal of retired keys, and emergency revocation through a trusted path
independent of the hub. A compromised hub must not be able to add a trusted key or undo its
revocation. Permission to force an update without a managed runner is a separate local policy
decision, not implied by permission to update; the operator must see that executor stages can
cross versions.

The prototype reference covers [release storage and rollout commands](fleet-prototype.md#releases-and-rollouts),
including waves, success checks, timeouts, pause/resume and persistence.

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
for material configuration differences, such as VMM backend, kernel and executor settings,
alongside the hardware profile. Show uncovered groups before starting a rollout. This gate is
not built: the [current completion checks](fleet-prototype.md#releases-and-rollouts) do not
observe subsequent workload health.

Release downloads are authenticated and scoped to a pending update; their bytes do not ride on
the control session. See [release downloads](fleet-prototype.md#release-downloads).

## Resets

| Operation | Effect |
|---|---|
| restart | restart `vk node` and gitlab-runner |
| reset | drain, stop anything the node's user still owns from past jobs, clear chosen caches and scratch, validate |
| redeploy | reinstall the host (Redfish/IPMI and PXE) — only on [managed nodes](#managed-nodes) |

A node without a BMC integration reports redeploy as unavailable.

Only reset is built. Its [current implementation](fleet-prototype.md#resets) drains a managed
runner, removes recognized leftovers and selected caches, then validates. Restart and redeploy
remain planned.

Proposed reset contract: track each job's host processes in an explicit ownership boundary,
preferably a delegated cgroup where the host supports it. A process that changes its executable
or arguments must remain attributable to that job. Stop the boundary and verify it is empty
before releasing its network lease or deleting its scratch. Failure to inspect ownership is
a maintenance failure, not evidence that nothing remains; leave the node drained and report
what could not be established. Protect the node supervisor and unrelated workloads from the
cleanup boundary.

The existing executable-and-argument scan remains a fallback for older jobs and hosts without
that boundary. Report its limited coverage explicitly: it cleans recognized leftovers but
cannot prove that every descendant is gone. Do not describe that result as a verified clean
reset or use it to satisfy unattended maintenance's reset gate.

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
  from becoming script in an operator's session that can drain or redeploy machines.
- **Not Datastar.** It compiles every `data-*` expression with `Function(...)`, so it runs
  only under `'unsafe-eval'`; a spike under the policy above rendered nothing.

In order of priority:

1. **nodes** — state, capacity (local estimate, hub ceiling, effective), pressure, admission
   waits, versions, configuration drift; desired, observed and unknown shown distinctly;
2. **node detail** — inventory, effective configuration, recent jobs linked to GitLab,
   atop timelines and egress reports;
3. **operations** — drain, reset, rollouts and their progress;
4. **audit** — every operator action and every command's outcome.

Metrics for capacity, admission waits and node states are exported for Prometheus.

See the prototype reference for [UI configuration and live pages](fleet-prototype.md#web-ui)
and their rendering and connection limits.

### Signing in

Sign-in links issued through the admin socket establish viewer or operator sessions. They
stand in for OIDC login until the shared identity layer is ready. See the prototype reference
for [sign-in links, sessions and request checks](fleet-prototype.md#signing-in).

## Local mode

`vk-hub local` runs the hub for the one machine it is started on, for a person
watching and controlling their own VMs — the role virt-manager plays for libvirt:

- no enrollment and no node session: it runs as the user who owns the VMs and reads the
  [workloads](#workloads) sources directly;
- the same UI and the same security properties, on loopback, opened in the browser with a
  sign-in link the way Jupyter does;
- a state dir of its own under the user's XDG state home, so it never shares a database with
  a fleet hub.

Actions reuse existing CLI commands as subprocesses. The UI must preserve their ownership
checks, confirm destructive actions against the observed workload identity, and audit actions
before running them. CI jobs remain their runner's responsibility. A browser shell is planned.

Local mode uses a fresh random `.localhost` name and port per start, binds both loopback
address families and expires previous sessions. This separates its cookies from other local
services and prevents reuse of the previous origin's authority. The [local mode reference](fleet-prototype.md#local-mode)
records the threat model, browser observations, commands and process handling.

## Security

- Nodes accept typed operations only, never a shell command, each checked against the
  operations local policy allows.
- Node identities are pinned keys, rotated and revoked from the hub; enrollment tokens are
  short-lived and single-use.
- A hub chooses which release a node updates to, never whether it may go back: a node refuses
  an older `vk` than it runs unless its own configuration allows it (`[node] allow_downgrade`),
  since an override the hub carried would be worth nothing against a compromised hub — which
  could otherwise take the fleet back to a release with a known flaw, signed or not.
- Runner authentication tokens stay on their nodes. The hub's GitLab credential is a separate
  one, scoped to managing runners (pause, resume, list).
- Hub roles: viewer; operator (ceilings, drain, reset, rollouts); admin (enrollment,
  redeploy). BMC credentials are held apart and used only by redeploys. Admin is the admin
  socket's: whoever runs as the hub's user or root, who also issues the web UI's sign-in
  links; a web UI session is a viewer or an operator.
- The web UI and the node endpoint are separate listeners with separate authentication.
  Every UI response carries `Content-Security-Policy: default-src 'self'; script-src 'self';
  style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none';
  form-action 'self'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: same-origin`, `Cross-Origin-Resource-Policy` and
  `Cross-Origin-Opener-Policy` `same-origin`, and, over https, `Strict-Transport-Security`;
  pages are `no-store`, and served only to a request from the UI's own pages or from none
  (`Sec-Fetch-Site`). A request whose `Host` is not `ui_url`'s — local mode's own name — is refused
  with 421, so a page on another name that resolves to the UI's address reaches nothing (DNS
  rebinding); a reverse proxy in front of the UI must pass the `Host` it was asked for.
- The hub runs on its own host; its database and secrets are backed up. In the prototype,
  it sends desired state only after a node reports the generation it applied. If that
  generation is newer, the hub reissues its stored state as the generation after it. This
  orders messages but does not reconcile intent: restoring a backup from before an
  acquisition stop can reissue an older permission to run. A node forgets its applied
  generation when enrolled anew or with another hub, since generations count for one hub
  and one enrollment.

### Proposed recovery after a hub restore

A node ahead of the hub is a recovery conflict. Preserve the node's applied restrictions,
mark the conflict in the CLI and UI, and suspend automatic desired-state changes and new
maintenance commands to it, including rollout advancement, until an operator resolves it.
Ordinary work continues under the node's existing policy; an in-progress maintenance
operation follows its persisted local recovery rules. A higher generation alone is never
evidence of newer operator intent.

Have the node report the applied policy as well as its generation. Reconciliation presents
that policy beside the hub's restored policy and lets the operator explicitly adopt the
node's restrictions or replace them with a reviewed policy. Record the decision and both
states in the audit log before sending anything. Keep persisted drain and quarantine intact;
recovering the hub does not authorize lifting either.

The restore procedure must also reconcile pending commands against node journals and their
acknowledged outcomes before replay or rollout advancement. Old commands that would relax
restrictions require review. Test recovery from a backup taken before a stop, a ceiling cut,
a completed maintenance command and a rollout transition. These rules replace the prototype's
automatic generation bump; they are not implemented yet.

## Phase 2: generic jobs and docker-executor VMs

Both need one thing phase 1 does not: **reservations** — the hub asking a node to set a
resource envelope aside, the node deciding through its admission ledger and answering yes or
no, and the envelope handed over to the workload's own ledger entry when it starts. All
workload types on a node — CI job VMs, their services, image builds, generic jobs, docker
VMs — must be in that one ledger before they share a node.

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

Three kinds of principal submit jobs; nodes never do — a node's key authenticates its session
and nothing else.

| Principal | Credential | Client side |
|---|---|---|
| a person | OIDC login on the hub, exchanged for a short-lived hub session token | `vk hub login https://hub` — the OAuth device flow, so it works over SSH; the token is kept `0600` under `~/.config/virtkit/` |
| a GitLab CI job | the job's `id_tokens:` JWT with the hub as `aud`, verified against GitLab's JWKS | declared in `.gitlab-ci.yml`, read by `vk submit` from the job's environment; nothing is stored |
| other automation | a scoped API key: hashed at rest, expiring, revocable | `token_file` in the config, as the registry client does |

CI jobs are the main case: the ID token gives the hub the job's project, ref, whether the ref
is protected, and the pipeline source, with no secret for anyone to create or rotate.

The hub and `vk-registry` share one identity layer — the registry's accounts machinery, used
by both — so a person has one login and an API key is issued in one place.

Policy on the hub maps a principal (a user, a group, an API key, or a GitLab project and ref)
to:

- **pools** — the execution classes and nodes it may use; work from a protected ref gets
  protected pools, and a job cannot name one its principal is not allowed;
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
its principal — user, key, or GitLab project, ref and pipeline — in the audit log.

### Docker-executor VMs

For jobs written for GitLab's docker executor — `image:`, `services:`, docker-in-docker —
a node boots a disposable microVM carrying dockerd and gitlab-runner, which runs
`run-single --max-builds 1`, takes one job, and is destroyed after it. The VM's envelope is
reserved before its runner starts asking for work. The microVM is the isolation boundary, so
privileged containers are acceptable. A dind job needs no nested KVM; the existing `nested`
option is only for jobs that boot VMs themselves.

The runner token is the problem: a privileged job inside the VM can read it from the
runner's memory and use it to take further jobs. A runner registered per VM through the
GitLab API and deleted afterwards narrows that window without closing it. Closing it takes
the hub as a proxy for the runner API:

- the VM's runner points at the hub and authenticates with a hub-issued credential valid for
  one job request;
- on `POST /api/v4/jobs/request` the hub substitutes the real runner token, carried in the
  JSON `token` field and the `RUNNER-TOKEN` header;
- job updates, traces and artifacts carry the per-job token and are forwarded as streams;
  Git, cache and object-storage traffic goes direct.

That proxy is the only piece of central job handling phase 2 needs, and it is scoped to
docker VMs.

Before building either, prototype the VM itself end to end: guest startup, cgroup
delegation, docker storage, DNS and MTU, services, dind, cancellation, artifact upload.
dockerd's `registry-mirrors` covers Docker Hub only; other registries need their own
pull-through endpoints.

## Phase 3: central GitLab acquisition, if needed

Phase 1 is measured for what local acquisition leaves on the table: admission-wait
percentiles, eligible capacity idle while jobs wait, checkout and image cache misses, storage
saturation, pipeline duration. Central acquisition is built only if those show coarse
capacity control is materially inadequate.

Proposed measurement gate: replay the same mixed workload on the same hosts with fixed runner
concurrency and with adaptive concurrency plus hub ceilings. Include a slow-storage,
large-memory host, cold and warm caches, and record workload mix and configuration with each
run. Measure queue-to-start latency separately from execution time, admission-wait p50/p95/p99,
eligible idle capacity while jobs wait, cache misses and storage pressure. Missing telemetry
is unknown, not zero; instrument these observations before using them to choose a scheduler.

Before the experiment, agree a queue-to-start objective and how much eligible idle capacity
while jobs wait is unacceptable. Repeat under burst submissions, hub partitions, runner
restarts and concurrency cuts. Central acquisition needs a reproducible miss attributable to
local placement or acquisition, rather than insufficient resources or an accounting gap, and
a small experiment showing that reservations and central placement address it. Do not set the
threshold after seeing the results.

Two shapes remain candidates:

- **a central stock gitlab-runner with a remote custom executor** — the hub runs
  gitlab-runner, and each stage runs on a node chosen at `prepare`. The executor already
  reads each stage's script and streams it into the guest, which is the seam; the remote
  version needs durable stage identity, resumable ordered output, cancellation, exit-code
  fidelity and cleanup.
- **the runner-API proxy of phase 2, extended to every job** — slots on the nodes run
  `run-single` against the hub.

Either way, GitLab assigns a job when it is requested, not when it starts, so central
acquisition must request jobs only against capacity already reserved on nodes, and bound the
jobs acquired but not yet placed. Parallel `run-single` processes all get
`CI_CONCURRENT_ID=0`, and host checkouts are keyed by it, so each slot needs its own
identity passed to the executor.

Phase 1 keeps both open by giving workloads IDs of their own rather than GitLab's, keeping
node-local policy authoritative, versioning the protocol, and keeping GitLab specifics in an
adapter apart from the fleet core.

## Managed nodes

For hosts the hub owns end to end, a node OS image is available, never required:

- built with `vk build --disk`: a minimal system with a kernel, KVM, a `vk` user and
  `vk node`;
- installed by PXE — the hub serves iPXE, the installer kernel and initramfs, and the disk
  image, the payload `vk export iso` packages for USB installs. The image carries no token:
  the hub issues a single-use enrollment token per machine at install time;
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
| Restore a backup older than a stop or ceiling cut | Recovery conflict is visible; acquisition does not resume and the ceiling does not rise without an explicit reconciliation decision |
| Partition the hub during ordinary CI and during drain | Ordinary CI follows persisted policy; drain remains in force; an unreachable node is never presented as confirmed idle |
| Burst jobs during concurrency cuts, runner shutdown and restart | Accepted work is accounted for; `drained` is reported only after runner exit, cleanup and admission completion |
| Drop command acknowledgements and reconnect with duplicates | The journal preserves one operation identity and its outcome; replay does not repeat a completed destructive effect |
| Crash before and after each durable update transition, including install | Restart resumes or rolls back deterministically; it neither accepts jobs prematurely nor loses the known-good binary |
| Let host checks pass but fail candidate boot, networking or cleanup | Validation fails and the rollout cannot promote the canary |
| Complete a canary update, then fail representative jobs or interrupt its observation window | The next wave stays blocked; hub restart preserves the gate and its evidence |
| Lose the hub during a trial or make a test dependency unavailable | The trial reaches a bounded recovery outcome; missing evidence never becomes successful validation |
| Move wall clocks forward and backward during command expiry and trials | Documented deadline semantics hold; a clock change cannot leave maintenance unbounded or revive completed commands |
| Update with no trusted key, an invalid signature or a revoked key | Remote update is refused before candidate execution; only unsigned development updates have an explicit local opt-out, which never bypasses a failed signature check |
| Reset with an orphan that changes executable or arguments, or with process inspection denied | Ownership catches the orphan or reset reports that it cannot prove cleanup; scratch is not removed under a known live owner |
| Run reset beside unrelated local workloads | Only the job ownership boundaries selected for cleanup are affected |
| Compare fixed and adaptive concurrency under the same mixed load | Results meet the predeclared objective or identify a reproducible reason to investigate central acquisition |

The immediate milestone is a small fleet surviving these failures with no unexpected resume,
false drain, unvalidated promotion or ambiguous cleanup reported as verified. Complete resource
accounting remains an additional prerequisite before different workload types share phase 2
reservations. Restart, redeploy and broader scheduling do not take priority over these gates.

## Integration path

Each step ships in a release of its own and leaves the fleet working. Throughout, workloads
carry IDs of their own, node-local policy stays authoritative, the protocol is versioned, and
GitLab specifics stay in an adapter, so central GitLab acquisition changes how jobs reach the
hub, not how nodes run them.

1. **Local mode.** `vk workloads` and `vk-hub local`: one host's VMs, a page each, and
   lifecycle actions, with no hub↔node session. Its web UI is the core the fleet's is built
   on.
2. **Phase 1.** Enrollment, sessions, inventory, hub ceilings and stop-acquisition, drain and
   quarantine, signed releases and rollouts, resets, the workloads each node runs. Nodes keep
   their local gitlab-runners. Before unattended maintenance, the gaps in the
   [capability table](fleet-prototype.md#status) close — the GitLab API pause, gitlab-runner
   pinning, resets by process ownership, a representative validation workload, recovery
   after a hub restore, pinned release keys — and the [exit criteria](#prototype-exit-criteria)
   are met. The phase 3 measurements are instrumented here: admission-wait percentiles,
   eligible capacity idle while jobs wait, cache misses, storage pressure.
3. **Complete accounting.** Every workload type in the node's admission ledger, image builds
   included, with disk admission tracking inodes.
4. **Reservations**, as phase 2 describes them, each with a lease the node expires on its
   own. A job's processes run inside an ownership boundary that resets reuse.
5. **A node job API** that runs a placed workload for the hub: durable job and stage
   identity, ordered output resumable from an offset, cancellation, exit codes that keep
   build failures apart from system failures, and cleanup when the lease lapses. Generic jobs
   use it first; phase 3's remote custom executor uses the same API.
6. **Generic jobs.** The hub's queue, `vk submit`, principals and their policy, placement —
   filter, score, reserve — and per-job registry tokens.
7. **Docker-executor VMs.** The phase 2 microVM. Two ways keep the runner token out of it:
   the runner-API proxy, or a stock gitlab-runner beside the hub using the docker-autoscaler
   executor, with a fleeting plugin that provisions each VM through a reservation and
   `max_use_count = 1`. The second relies on a published plugin interface rather than
   GitLab's internal runner API; check that it fits before building the proxy.
8. **Central GitLab acquisition**, only if the [measurement gate](#phase-3-central-gitlab-acquisition-if-needed)
   calls for it. One gitlab-runner registration per pool and workload class, run beside the
   hub rather than in its process, so a hub restart abandons no job. Its custom executor
   drives the node job API, each runner's `limit` is the capacity reserved for it plus a
   bounded backlog, and placement is step 6's. Pools move over one at a time: a node takes
   jobs from its local runner or from the hub, never both. Once all have moved, nodes hold
   no runner tokens.
9. **Managed nodes** — the OS image, PXE, Redfish — whenever a host is to be managed end to
   end, independent of steps 3 to 8.

Steps 3, 4 and 5 are the critical path; 6 and 8 build on them in either order, and the
measurements running since step 2 decide whether 8 is built.

The end state is one placement engine on the hub over every node's ledger, fed by two
intakes: GitLab jobs through central runners, and jobs submitted to the hub. GitLab keeps the
CI queue, traces, artifacts and cancellation; nodes keep admission and local policy; local
mode remains the form for a single host.
