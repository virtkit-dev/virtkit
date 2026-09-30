# Fleet: a hub and its nodes

Status: proposal, implemented in part and experimental: the list of the VMs a host runs
(`vk workloads`) and local mode's web UI showing it and acting on it (`vk-hub local`),
signed into with links it prints; enrollment, the node session, inventory and heartbeats;
desired state (hub ceiling, stopping acquisition), drain and quarantine, with the node
applying them and the hub auditing them (`vk-hub nodes ceiling`, `stop`, `resume`, `drain`,
`undrain`, `quarantine`, `release`, `vk-hub audit`). Updates, resets, the GitLab API pause and
the fleet's web UI are not built yet.

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
- **`vk-fleet-proto`** — the hub↔node wire types, versioned. A node and the hub negotiate
  the protocol version on connect; a rolling update runs mixed versions by definition.
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

Enrollment:

```sh
vk-hub token create | ssh ci-7 vk node join https://hub.example.com --token -
```

generates the node's ed25519 identity, which the hub pins on first contact. The node signs
the token with that key, so the hub pins only a key the caller holds. Enrollment tokens are
single-use and expire, and are issued by `vk-hub token create` through a unix socket on the
hub's host rather than over the network. A node whose enrollment answer was lost enrolls
again with a new token and the same key, and gets its node ID back. The identity survives
`vk` updates; `vk-hub nodes remove` revokes it and ends its session.

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

The sources exist already and are read, not duplicated: the host's VM registry under
`<data>/vms/`, whose entries are checked against the state dir's lock so a stale entry is not
reported (and is pruned, as `vk list` prunes it); the identities of the running dev
environments, read as `vk dev list` reads them, whose JSON fields are only ever added to; the
executor's job dirs whose supervisor is alive, and the `job.json` `prepare` writes into each —
the job's ID, project, name, image and size; the admission ledger for reservations. A job
prepared by an older `vk` has no record and is reported by its job ID alone.

Only what runs is read. A stopped dev environment's state dir and any environment's workspace
are left alone, so a share nobody is using is not mounted, or kept mounted, by whoever lists
the VMs. A state dir's lock is asked of `/proc/locks` rather than taken: taking it, even for
an instant, fails a `vk run` starting on that dir at that moment. A registry entry whose pid
now names a process started after the entry was written — its lock outlived the run in a
child — is reported without the pid.

Compose services are not listed on their own: whether a declared service is up takes a
question to its run's control socket, and what a running one holds is counted in its
primary's figure.

Built so far: `vk workloads`, plumbing, which prints the list as one line of JSON and, with
`--watch`, a new line each time it changes. It holds at most 256 entries and 256 KiB — CI jobs
first, then the newest of the rest — with every string cut to 256 characters, and counts the
VMs it leaves out. Beside the list, by each entry's ID, derived from its state dir, is what
each holds on the host: the managing process's whole process tree — the guest, its compose
services, the switch, virtiofsd — counted proportionally (`Pss` from `smaps_rollup`), the
figure `vk list` and `vk dev list` show, so the UI and a shell agree. Reading it walks every
page table of every process, so it is measured every `--mem-secs` (30 by default) and as a VM
appears, and the lines between repeat the last figures — as does a measurement within a
sixteenth of the last one; a VM's pages move more slowly than that matters to anyone
watching. A dev environment's entry also names its SSH alias, when it has an SSH setup, and
the guest directory its workspace is at.

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

`vk tune` and `vk node run` compute it the same way, in one place, and on a node only `vk node
run` does: every half minute, and whenever its desired state changes, only the half-minute
pass raising it, by the estimate's one step. `vk tune` stands aside while `vk node run` is up,
and otherwise applies the ceiling the node last persisted. A runner config the node's user
owns (`[node] runner_config`) has its `concurrent` set directly, and a root-managed one still
goes through `vk-runnerctl`.

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

The node tells these from what it can observe. gitlab-runner, sent `SIGQUIT`, exits only
once its jobs are over, cleanup stage included; the admission ledger holds and awaits
nothing; and no job supervisor is still alive — a job dir alone proves nothing, since a
failed cleanup leaves one behind, but its supervisor's pid, checked against the job dir, says
whether its VM is still up. These are the node's own state dir's ledger and job dirs, so the
executor its runner runs must use the same vk configuration; the node warns when the
runner's config names another. Stopping acquisition needs a runner the node runs itself,
`[node] runner = "managed"`; with an external runner the node refuses a drain and a
quarantine, and reports a stop of acquisition as something it cannot carry out while it
still steers the runner's concurrency. gitlab-runner has no way back from `SIGQUIT`: a runner
told to stop is reported `quitting`, and acquisition as still running, until it has exited,
and a resume that comes meanwhile starts a new runner once the old one has gone. A runner
outlives a node killed outright; the next `vk node run` finds it by its recorded pid and start
time and follows it rather than start a second. `undrain` returns a drained or draining node
to `ready`; a quarantine stops acquisition from any state and only `release` lifts it,
returning the node to `drained` if that is where it was quarantined and to `ready` otherwise.
All of it is persisted on the node, and a restart or a lost hub leaves it where it was.

`validating` runs a boot/exec/network smoke test and, when configured, a synthetic job
before the node goes back to `ready`.

A node that stops heartbeating is shown as unreachable, not paused: pausing every
disconnected node would turn a hub outage into a fleet outage.

## Updates

An update is: download the approved release → verify it → drain → switch the binary →
validate → ready. The previous binary and configuration are kept, and restored if
validation fails or the node does not reconnect within a deadline.

Rollouts go by hardware profile: one canary per profile, then small batches, each node
validated before the next batch starts. Rollout state is in the hub's database, so a
rollout survives a hub restart.

`vk-selfupdate` provides the download, digest check, version smoke test and atomic rename.
Fleet updates add:

- a signature check against keys pinned in the installed `vk`, before the new binary runs;
- the same pinning for the gitlab-runner binary;
- one `vk` binary per job for the job's whole life: executor stages running during a switch
  must not mix versions, which draining guarantees.

## Resets

| Operation | Effect |
|---|---|
| restart | restart `vk node` and gitlab-runner |
| reset | drain, stop anything the node's user still owns from past jobs, clear chosen caches and scratch, validate |
| redeploy | reinstall the host (Redfish/IPMI and PXE) — only on [managed nodes](#managed-nodes) |

A node without a BMC integration reports redeploy as unavailable.

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

Built so far, in [local mode](#local-mode): the server-rendered pages, their sign-in and the
policy above, with the listener's timeouts on everything before a request is authenticated.

Pages stay live over server-sent events. A fragment the same for everyone — the VMs table —
is rendered by one task on a change and every page showing it is sent that one rendering; a
page of one thing renders its own, woken by the changes it follows. A fragment is rendered at
most once a second, and every five seconds regardless, and sent only when it differs, so a
page with nothing new to show is sent nothing but a keep-alive comment every 15 seconds. When
its session ends, a stream sends a fragment saying so and a `close` event, on which htmx's SSE
extension (`sse-close`) stops reconnecting.

Streams hold connections — the listener speaks HTTP/1.1 only, HTTP/2 not being in the build —
so at most 96 of its 128 are streams and at most 6 belong to one session; past either a
stream is refused with 429 or 503, which the SSE extension retries with its backoff, doubling
from half a second to a minute. There is no per-address cap: the people using the UI are few
and often share one proxy or NAT address.

htmx 2.0.7 and htmx-ext-sse 2.2.3 are vendored in `vk-hub/assets/` (`VENDOR.md` gives their
sources and digests), embedded, and served under a hash of their content with a year's
caching. htmx runs with `allowEval`, `allowScriptTags` and `includeIndicatorStyles` off and
`selfRequestsOnly` on; the pages have no inline script or style for the policy to refuse.
IDs the hub checks as hex are the only values in an attribute htmx reads; what the host
reports goes only into text and plain attributes, escaped.

### Signing in

A person signs in with a single-use link — `<origin>/login?t=<token>` — that the hub prints,
or issues over its admin socket: `vk-hub local login [--role viewer|operator] [--ttl 10m]`.
The token is short-lived and stored hashed. Opening the link shows a "Sign in" button, and
only the `POST` it makes — from the sign-in page itself, by `Sec-Fetch-Site` — spends the
token, so a mail scanner or a chat's link preview fetching the link leaves it unused. The
post opens a session: a random secret set as a cookie (`HttpOnly`, `SameSite=Strict`,
`Path=/`, and `Secure` with the `__Host-` prefix over https), kept hashed in the database
with its role, and valid for 12 hours. The page it answers moves on to `/` itself, so the
token never stays in the address bar. `vk-hub local sessions` lists the sessions, `vk-hub
local logout <id>|--all` ends them.

Browsers keep cookies apart by host, not by port. On plain http — which the UI serves only
on loopback — the session cookie therefore goes to every other http service on that host,
and any of them can set a cookie of the same name. The hub treats a request carrying two
session cookies as signed in with neither, but cannot stop the first from being read: a UI
on plain http is served under a name of its own (see [Local mode](#local-mode)).

Every state-changing request is a `POST` from the UI's own origin — its `Origin`, or
`Sec-Fetch-Site: same-origin` — carrying a CSRF token derived from the session's secret, and
is done as the session's principal, `ui session <id> (<role>)`, which is what the audit log
records.

Links stand in for a login until people sign in through OIDC, with the identity layer the
hub shares with `vk-registry` ([Authentication for submitted jobs](#authentication-for-submitted-jobs)),
which then replaces them; the session and its role stay as they are.

## Local mode

`vk-hub local` runs the hub for the one machine it is started on, for a person
watching and controlling their own VMs — the role virt-manager plays for libvirt:

- no enrollment and no node session: it runs as the user who owns the VMs and reads the
  [workloads](#workloads) sources directly;
- the same UI and the same security properties, on loopback, opened in the browser with a
  sign-in link the way Jupyter does;
- a state dir of its own under the user's XDG state home, so it never shares a database with
  a fleet hub.

Its actions run the existing commands as subprocesses rather than reimplementing them:

- dev environments: stop, start again (`vk dev up` in the workspace), clean up stale ones
  (`vk dev gc`);
- pinned runs: stop, reboot;
- every VM: the console log tail, the atop timeline, the egress report;
- dev environments: an "open in VS Code" link through the SSH alias `vk dev` already
  configures (`vscode://vscode-remote/ssh-remote+<alias>/<path>`).

A shell in the browser needs a terminal emulator (xterm.js, vendored like htmx) over a
WebSocket to the VM's exec socket; it fits the CSP and is left for later.

The cookie problem is sharper here than on a fleet hub: a developer's machine serves many
things on loopback, including the ports `vk dev` itself forwards, and cookies are not
isolated by port. The local UI is therefore served under a name of its own,
`vk-<random>.localhost`, so its session cookie is host-scoped to that name and is not sent to
`localhost` or `127.0.0.1` on any other port. Chromium 153 and Firefox 156 both resolve
`*.localhost` to loopback and keep a cookie set by `vk-<random>.localhost` (SameSite Lax or
Strict) off `localhost`, `127.0.0.1` and other `*.localhost` names on every port. It still
reaches the same name on other ports, which is why the name is random.

Built so far: `vk-hub local [--port N] [--no-browser] [--vk PATH]` keeps its database, admin
socket and name — `vk-<16 hex digits>.localhost`, drawn once — in
`$XDG_STATE_HOME/virtkit/hub-local` (or `--state-dir`), serves on `127.0.0.1` (a port the
system picks unless `--port`), and prints an operator's sign-in link valid for an hour;
unless `--no-browser` it opens the link with `xdg-open` through a page in that private
directory, so the token never sits in a command line another local user can read. It runs
`vk workloads --watch` — the `vk` beside it, else the one on `PATH` — for as long as it
serves, starting it again with a backoff when it ends, and shows the list it prints, each VM
with a page of its own, both kept live. A child rather than a command run again every few
seconds, so the memory figures keep their own cadence; a list of a version the hub cannot
read is refused rather than misread. A VM's page also shows its console's last hundred lines
(`vk logs`), atop's account of a VM that records itself (`vk atop --summary`; one that does
not is not attached to), and what a CI job's switch recorded of its egress (`vk
egress-report`, plumbing), each read as the page loads.

An operator's session acts on them by running `vk` as a shell would: a pinned run is stopped
(`vk stop`) or rebooted (`vk reboot`), named by the pid of its `vk run` — `vk stop <dir>`
would take the VMs of every directory below too — and a dev environment stopped (`vk dev
stop`). `/dev` lists every environment `vk dev list` knows, stopped ones included, read as the
page loads: a stopped one is started again in its recorded workspace (`vk dev up --workspace
… --environment …`), and one that is stale — its workspace gone, or no boot recorded —
removed (`vk dev gc --yes`). A CI job is its runner's and has no action. A stop, a reboot and a
removal are asked again on a form of their own before they run. Each runs in the background,
one at a time on each thing acted on, with a time limit; the pages show it under way and how
it ended, with the last line it printed, and the audit log records it, as the session's
principal, as it starts and as it ends. A dev environment with an SSH setup has an "open in
VS Code" link through its alias, which the user's own SSH config must reach (`vk dev
ssh-config` prints the stanza); `vk dev code` in the workspace needs none. A shell in the
browser is not built.

## Security

- Nodes accept typed operations only, never a shell command, each checked against the
  operations local policy allows.
- Node identities are pinned keys, rotated and revoked from the hub; enrollment tokens are
  short-lived and single-use.
- Runner authentication tokens stay on their nodes. The hub's GitLab credential is a separate
  one, scoped to managing runners (pause, resume, list).
- Hub roles: viewer; operator (ceilings, drain, reset, rollouts); admin (enrollment,
  redeploy). BMC credentials are held apart and used only by redeploys.
- The web UI and the node endpoint are separate listeners with separate authentication.
  Every UI response carries `Content-Security-Policy: default-src 'self'; script-src 'self';
  style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none';
  form-action 'self'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: same-origin` and, over https, `Strict-Transport-Security`; pages are
  `no-store`. A request whose `Host` is not the UI's own is refused with 421, so a page on
  another name that resolves to the UI's address reaches nothing (DNS rebinding); a reverse
  proxy in front of the UI must pass the `Host` it was asked for.
- The hub runs on its own host; its database and secrets are backed up, and a restored hub
  reconciles against the nodes before it sends anything: it sends desired state only in
  answer to a node's report of the generation it applied, and a node that reports one newer
  than the hub's own gets the hub's desired state re-issued as the generation after it. A
  node, for its part, forgets the generation it applied when it is enrolled anew or with
  another hub, since generations count for one hub and one enrollment.

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

## Phasing

1. `vk node` and the hub: enrollment, inventory, the capacity controller with hub ceilings
   and stop-acquisition, node states and drain, signed rollouts, resets, the web UI, the
   workloads each node reports. Nodes keep their local gitlab-runners. Local mode comes first,
   its web UI the core the fleet's is built on.
2. Reservations; generic jobs with central placement; docker-executor VMs behind the runner-API
   proxy.
3. Central GitLab acquisition, only if phase 1's measurements call for it.
4. Managed nodes: the OS image, PXE, Redfish — whenever a host is to be managed end to end.
