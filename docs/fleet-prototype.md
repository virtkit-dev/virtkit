# Fleet prototype: operation and implementation

This reference records the experimental implementation: available commands, configuration,
limits and recovery behavior. Read [the design](fleet-design.md) for ownership rules, intended
guarantees and proposed changes. The [exit criteria](fleet-design.md#prototype-exit-criteria)
are requirements to demonstrate, not a claim that the prototype has passed them.

## Status

The prototype provides, all experimentally:

- `vk workloads`: the host's running VMs;
- `vk-hub local`: a web UI to view and act on those VMs, with printed sign-in links;
- enrollment, node sessions, inventory and heartbeats;
- `vk-hub workloads`: each node's VMs;
- live nodes and node detail pages, and an audit log, with sign-in links from
  `vk-hub ui login`.

The hub observes nodes but does not control them. Desired state, drain and quarantine,
releases, updates, rollouts, resets, restart and redeploy are not built.

| Capability | Current prototype | Proposed gate |
|---|---|---|
| Hub recovery | Not built: the hub keeps no desired state | [Preserve node restrictions and resolve the recovery conflict explicitly](fleet-design.md#proposed-recovery-after-a-hub-restore) |
| Update validation | Not built | [A pinned boot/exec/network/cleanup workload required for unattended rollouts](fleet-design.md#updates) |
| Canary promotion | Not built | [Representative workload success and an observation window](fleet-design.md#updates) |
| Release trust | Not built | [Pinned keys required for remote updates; explicit development opt-out](fleet-design.md#updates) |
| Reset | Not built | [Explicit job process ownership, verified empty before scratch removal](fleet-design.md#resets) |

## Enrollment

Enroll a node with a token issued on the hub host:

```sh
vk-hub token create | ssh ci-7 vk node join https://hub.example.com --token -
```

`vk-hub token create [--ttl 1h]` issues a single-use token, valid for at most 30 days, through
the hub's admin socket rather than over the network, and prints it alone on stdout. `vk node
join <hub> --token TOKEN|-|--token-file FILE [--ca FILE]` generates the node's ed25519
identity and signs the token with it, so the hub pins only a key the caller holds. The hub URL
is `https`, or `http` only to a loopback hub. `--ca` verifies the hub against that bundle
alone, not the system's roots. Enrollment speaks TLS 1.3 only, ignores `HTTP(S)_PROXY` and
follows no redirect. `join` refuses while `vk check` fails on KVM, the VMM or the guest
kernel, and on a host already enrolled.

A node whose enrollment answer was lost enrolls again with a new token and the same key, and
gets its node ID back. The identity survives `vk` updates. `vk-hub nodes remove <id>` revokes
it and ends its session. The host can then join again only as a new node: remove
`<state_dir>/node/` and use a new token. Issuing a token, enrolling, re-enrolling and removing
a node are recorded in the audit log.

## Hub and node

`vk-hub serve [--config hub.toml]` serves nodes. `hub.toml` sets `addr` (default
`127.0.0.1:8443`), `tls_cert` and `tls_key`, `data_dir` (default `$XDG_DATA_HOME/virtkit/hub`,
else `~/.local/share/virtkit/hub`), and the web UI's keys (see [Web UI](#web-ui)). Every key
is optional and an unknown one is an error. Without TLS the hub serves only on loopback. TLS is
1.3 only, on both the hub and the node. `vk-hub token`, `vk-hub nodes`, `vk-hub workloads` and
`vk-hub ui` reach the running hub through `<data_dir>/admin.sock`, open to the hub's user and
root.

`vk node run` holds a WebSocket session at `/v1/node` in the foreground. The node signs the
hub's challenge, its node ID and incarnation (new on every `vk node run`), both version ranges,
the version the hub picked, which the node checks against both ranges before signing, and,
over TLS, 32 bytes of exporter output under the label `EXPERIMENTAL-vk-fleet-node-auth` (a
plaintext loopback session signs a `plaintext` marker instead). A signed payload starts with a
label of its own, and every variable-length part carries a big-endian `u64` length prefix.
Keys, signatures, nonces and IDs are strict lowercase hex. A proxy in front of the hub must
pass TLS through: terminating it breaks the binding, and the hub refuses the signature.

The hub admits at most 256 connections that have not authenticated, each step of which (TLS,
request headers, an enrollment body, a handshake message) has 10 seconds. One past that is
closed at once. At most 256 handshakes run at once; past that the upgrade is answered HTTP
503, and the node redials. A message is at most 1 MiB either way.

The hub asks for a heartbeat every 5 seconds; the node clamps what it is asked to 1–300
seconds. A node silent for 3 heartbeats has its session dropped and is listed unreachable; the
node gives up on a hub silent for 3 of the intervals it asked for. The node re-reads its
inventory every 60 seconds and sends it when it changed, and sends a report of its VMs at the
start of every session and with the next heartbeat after the list changes.

The inventory carries the hostname; CPUs, CPU model, RAM, memory nodes and the `vk check`
results that gate enrollment; the job-dir and checkout filesystems, each with its device, size,
whether it is tmpfs and the speed `[node] jobs_speed` or `checkouts_speed` declares; the `vk`
and guest kernel versions and a hash of the effective configuration; and the gitlab-runner
configuration read, its `concurrent` and its runner names. The heartbeat carries admission
(memory committed and budget, jobs running and waiting), the runner concurrency last asked
for, memory available, free bytes and inodes per filesystem, and each VM's memory.

The hub stores heartbeats and reports at most once per half heartbeat, holding back the latest
and storing it at the next ping. Heartbeats are written without an fsync, one a minute made
durable; an inventory is made durable at most once a heartbeat. Each of an inventory's lists
(filesystems, memory nodes, checks, runner names) is cut to 64 entries. `vk-hub nodes` lists
ID, NAME, REACH, LAST SEEN, VK, CPUS, RAM, ADMITTED and VMS.

The node redials a lost session with a backoff doubling from 1 to 60 seconds, plus up to a
quarter of jitter, reset by a session that lasted a minute. Superseded three times in a row, it
warns that another host may hold a copy of its state dir and redials every minute. A hub
refusal of `not_enrolled`, `bad_signature` or `revoked` ends `vk node run`. A first SIGTERM or
SIGINT closes the session, waiting at most 5 seconds for the hub; a second exits at once.
`vk node run` exits 75 while another `vk node` holds `<state_dir>/node/lock`, and refuses to
start unless `<state_dir>/node/` belongs to its user and is closed to everyone else.

## Workloads

For the fields reported and their ownership, see the [workload design](fleet-design.md#workloads).

Workload discovery reads existing records:

- the host's VM registry under `<data>/vms/`, checking each state dir's lock and pruning
  stale entries as `vk list` does;
- running dev environments' identities, as read by `vk dev list`;
- executor job dirs with a live supervisor, and the `job.json` that `prepare` writes with
  the job's ID, project, name, image and size;
- the admission ledger's reservations.

A job prepared by an older `vk` has no record and is reported by its job ID alone.

Only what runs is read. A stopped dev environment's state dir and any environment's workspace
are left alone, so a share nobody is using is not mounted, or kept mounted, by whoever lists
the VMs. A registry entry is told live by its state dir's lock, as `vk list` tells it: taken
for an instant, which a `vk run` starting on that dir at that moment waits out. A registry
entry whose pid now names a process started after the entry was written — its lock outlived
the run in a child — is reported without the pid.

Compose services are not listed on their own: whether a declared service is up takes a
question to its run's control socket, and what a running one holds is counted in its
primary's figure.

`vk workloads`, plumbing, prints the list as one line of JSON and, with `--watch`, a new line
each time it changes, looking again every `--interval-secs` (2 by default) until stdin closes.
A node's list rides on the report.

One bound, `bound_workloads` in `vk-hub-proto`, applies on the node and again on the hub: at
most 256 entries and 256 KiB, CI jobs first, then the newest of the rest, stopping at the
first that does not fit. Every string is stripped of control and invisible characters and cut
to 256 characters; an SSH alias or guest workspace that is not display-safe is dropped rather
than altered, and an entry whose ID is not 16 lowercase hex digits is dropped. Every entry left
out is counted, and the hub shows the count.

Each VM's host memory travels beside the list — on a node, on the heartbeat — keyed by the
entry's ID, which derives from its state dir. It is the managing process's whole tree — guest,
compose services, switch, virtiofsd — counted proportionally (`Pss` from `smaps_rollup`, else
`VmRSS`), the figure `vk list` and `vk dev list` show. Reading it walks every page table of
every process, so it is measured as a VM appears and every `[node] workload_mem_secs`
(`--mem-secs` for `vk workloads`; 30 by default). Between measurements, and while a new
reading stays within a sixteenth of the last, the last figures repeat.

The hub keeps each node's latest list, not its history, in a table apart from the node's row,
written without an fsync since the node resends it every session; the row keeps the count. It
shows the list on the node's page, with when each VM started rather than an uptime, and the
count in the nodes table. `vk-hub workloads [--node ID|HOSTNAME]` lists them; `--node` takes
an ID or a hostname only one node has. A node not connected is marked "not connected; as last
seen at" its last time. When every node's lists together would pass the admin socket's 16 MiB
reply, each is replaced by its count and a pointer to `vk-hub workloads --node <id>`.

A dev environment's entry also names its SSH alias, when it has an SSH setup, and the guest
directory its workspace is at. Nothing acts on a node's workloads; local mode acts on its own
(see [Local mode](#local-mode)).

## Web UI

`ui_addr` in `hub.toml` turns the listener on, with its own `ui_tls_cert` and `ui_tls_key` or
the node listener's pair, plain HTTP only on loopback, and TLS 1.3 only. The TLS handshake, a
request's headers and a form's body each have 10 seconds. `ui_url` is the address browsers
reach it at: sign-in links start with it, and a state-changing request's `Origin` must be it.
It defaults to `http(s)://<ui_addr>`, and is required when `ui_addr` binds an unspecified
address. It is `https` whenever the listener has TLS, and `http` only for `localhost`,
`127.0.0.0/8` or `[::1]`. It is normalized as a browser writes an origin: lowercase, no path,
no default port, IPv6 in canonical form; an IPv4-mapped IPv6 address and a numeric host that
is not a dotted quad are refused. `ui_url`, `ui_tls_cert` or `ui_tls_key` without `ui_addr` is
an error.

The UI serves the nodes table with the columns of `vk-hub nodes`; each node's inventory,
heartbeat and workloads; and the audit log (`/audit`, filterable by node, 100 lines a page; the
hub keeps the newest 100,000 rows). The fleet's pages only show the fleet: removing a node
stays on the admin socket. A page is refused to a request whose `Sec-Fetch-Site` is
`same-site` or `cross-site`.

The nodes table and a node's page stay live over server-sent events. The hub notes every
heartbeat, report and session, by node. The nodes table is the same for everyone, so one task
renders it on a change and every nodes page is sent that one rendering; a node's page is woken
by changes to that node alone. A fragment is rendered at most once a second, and every
heartbeat interval regardless — a node going quiet sends nothing — and sent only when it
differs. Ages on the pages move in steps of a heartbeat, so a fleet with nothing new to report
sends nothing but a keep-alive comment every 15 seconds, and a node reporting faster than that
changes nothing about the rate. When its session ends, a stream sends a fragment saying so and
a `close` event, on which htmx's SSE extension (`sse-close`) stops reconnecting; a page asking
for a stream with the cookie of a session that has ended is answered the same, rather than
refused into retrying. A stream whose browser stops reading is given up on, and its connection
dropped.

Streams hold connections — the listener speaks HTTP/1.1 only, HTTP/2 not being in the build —
so at most 96 of its 128 are streams and at most 4 belong to one session — below the six a
browser opens to one host, which every tab shares; past either a stream is refused with 429 or
503, which the SSE extension retries with its backoff, doubling from half a second to 64
seconds. There is no per-address cap: the people using the UI are few and often share one
proxy or NAT address.

htmx 2.0.7 and htmx-ext-sse 2.2.3 are vendored in `vk-hub/assets/` (`VENDOR.md` gives their
sources and digests), embedded, and served under a hash of their content with a year's
caching. htmx runs with `allowEval`, `allowScriptTags` and `includeIndicatorStyles` off and
`selfRequestsOnly` on; the pages have no inline script or style for the policy to refuse.
Node IDs, issued by the hub and checked as fixed-length lowercase hex — and in local mode the
VM IDs `vk workloads` derives, checked the same way, and dev environment names, checked to be
`[A-Za-z0-9._-]` not starting with `.` or `-` — are the only values in an attribute htmx reads
or a link the hub builds; what nodes or the host send goes only into text and plain
attributes, escaped.

### Signing in

A person signs in with a link `vk-hub ui login [--role viewer|operator] [--ttl 10m]` prints
over the admin socket — `<ui_url>/login?t=<token>`, for a viewer by default; `vk-hub local`
prints one as it starts, and `vk-hub local login` more, for an operator by default. The token
is single-use, valid 10 minutes by default and at most a day, and stored hashed, like an
enrollment token. Opening the link shows a "Sign in" button, and only the `POST` it makes —
`Sec-Fetch-Site` `same-origin` (the sign-in page itself) or `none` — spends the token, so a
mail scanner or a chat's link preview fetching the link leaves it unused. The post opens a
session: a random secret set as a cookie (`HttpOnly`, `SameSite=Strict`, `Path=/`, and
`Secure` with the `__Host-` prefix over https), kept hashed in the database with its role,
and valid for 12 hours. The page it answers moves on to `/` itself, so the token never stays
in the address bar. `vk-hub ui sessions|logout <id>|--all` (`vk-hub local sessions|logout`)
list and end sessions; an ID, 12 hex digits, ends every session that shares it, and one naming
none is an error.

Browsers keep cookies apart by host, not by port. On plain http — which the UI serves only
on loopback — the session cookie therefore reaches every other http service on that host,
and any of them can set a cookie of the same name. The hub treats a request carrying two
session cookies as signed in with neither, but cannot stop the cookie being read: when
anything else is served on the machine the UI is used from, give a fleet hub's UI TLS even on
loopback (the hub's own certificate will do). Local mode serves under a name of its own
instead (see [Local mode](#local-mode)).

Every state-changing request is a `POST` from the UI's own origin — its `Origin`, or
`Sec-Fetch-Site: same-origin` — carrying a CSRF token derived from the session's secret, and
is done as the session's principal, `ui session <id> (<role>)`, which is what the audit log
records. On a fleet hub the only one is signing out. Issuing a link, signing in and out, and
ending sessions are audited too.

## Local mode

`vk-hub local [--port N] [--no-browser] [--vk PATH]` keeps its database and admin socket in
`$XDG_STATE_HOME/virtkit/hub-local`, else `~/.local/state/virtkit/hub-local` (or
`--state-dir`); a second `vk-hub local` on the same directory stops at the database lock. It
serves under a name drawn as it starts — `vk-<16 hex digits>.localhost` — on `127.0.0.1` and
`::1`, on `--port` or one the system picks, and issues an operator's sign-in link valid for an
hour, printed with `--no-browser` or when stderr is a terminal. Unless `--no-browser` it opens
the link with `xdg-open` through a page in that private directory, removed a minute later, so
the token never sits in a command line another local user can read. A browser that cannot read
the page — a snap's, kept out of hidden directories — shows an error, and the printed link is
opened by hand. `vk-hub local login --role viewer` prints a link for a session that can only
look.

A developer's machine serves many things on loopback, including the ports `vk dev` forwards,
so the session cookie is scoped to the hub's own name and is not sent to `localhost` or
`127.0.0.1` on any other port; Chromium and Firefox resolve `*.localhost` to loopback. The
cookie still reaches the same name on other ports, and loopback ports are anyone's: a name
kept across starts would be learnt by whatever took the hub's port while it was down, from the
`Host` of the next request a browser sent there, which could then catch the cookie on another
port under that name — or, `.localhost` being a secure context, leave a service worker on the
hub's origin to answer in its place. The name, and the port unless `--port` names one, are
therefore drawn anew each time the hub starts, and every session and unspent sign-in link of
the last run ends, so what was caught under an old name opens nothing. The port is bound on
both `127.0.0.1` and `::1` (on `127.0.0.1` alone where the host has no `::1`), since a browser
may try `::1` first for a `.localhost` name, and a hub asked for a port taken on either
refuses to start. `SameSite=Strict` still sends the cookie with requests from another port of
the same name, which is the same site; the `Sec-Fetch-Site` check on pages is what refuses
those.

Local mode's actions run the existing commands as subprocesses rather than reimplementing
them:

- dev environments: stop, start again (`vk dev up` in the workspace), clean up stale ones
  (`vk dev gc`);
- pinned runs: stop, reboot;
- every VM: the console log tail, the atop timeline, the egress report.

`vk-hub local` runs `vk workloads --watch` while serving, restarting it with backoff when
it exits. It uses `--vk`, then the `vk` beside it, then the one on `PATH`. Each list updates
the VM list and individual VM pages through the same live mechanism as the fleet pages.
Keeping the child alive preserves the memory measurement cadence; unsupported list versions
are refused.

A VM's page also shows its console's last hundred lines (`vk logs
--exact`, which reads that state dir's console alone, back from its end in bounded pieces),
atop's account of a VM that records itself (`vk atop --summary`; a CI job's is in the archive
its job dir names, and one that does not record is not attached to), and the egress its switch
recorded — what a CI job's refuses and contacts, or what a `vk run --audit-egress` contacts
(`vk egress-report`, plumbing) — each read as the page loads: reloaded within five seconds it
shows what was read, and at most two pages read at once. What the commands print is shown with
their terminal escape sequences dropped whole. A VM whose state dir the list cannot show as it
is — a byte that is not UTF-8, a control character — is neither read nor acted on by its path:
`vk workloads` derives the ID from the path's bytes, and the path shown no longer hashes to it.

An operator's session acts by running `vk` as a shell would. A pinned run is stopped (`vk
stop`) or rebooted (`vk reboot`), named by the pid of its `vk run` — `vk stop <dir>` would take
the VMs of every directory below too — or by its state dir when the list has no pid; a dev
environment is stopped with `vk dev stop`. `/dev` lists every environment `vk dev list` knows,
stopped ones included, read as the page loads and reused for five seconds: a stopped one is
started again in its recorded workspace (`vk dev up --workspace … --environment …`), and a
stale one — its workspace gone, or no identity recorded — removed (`vk dev gc --yes --
<name>`). A CI job is the executor's and has no action.

Stops, reboots and removals require confirmation from the same session, once and within ten
minutes. The target must still match: the run's pid and start, or the environment's last boot.

Actions run in the background, one at a time per target, with a 5-minute limit (one hour for
`vk dev up`). On timeout, the process group receives SIGTERM, then SIGKILL 2 minutes later.
Pages show progress and the outcome, including the last output line. The audit log records
the start and end under the session's principal; an action cannot run unless its start is
recorded. A browser shell is not built.

## Testing

`tests/fleet-*.sh` test the hub and its nodes end to end: in CI on GitHub's hosted runners
(`ci.yml`'s `fleet-e2e`, for pushes outside `release`, pull requests and manual runs), and with
the rest of `tests/` before a release. CI's build embeds the guest kernel of the release the
commit descends from (`build.sh --kernel-from`), or builds one when the kernel inputs changed
since or the run is manual.
They cover enrollment (single-use and expired tokens, re-enrollment with the same key,
removal), the session, inventory, heartbeats, workloads, and reconnecting after a hub restart,
a node restart and a partition. The web UI and local mode have unit tests only.

Without a writable `/dev/kvm` or nested virtualization a script skips; CI and
`release-e2e.sh` set `E2E_REQUIRE_KVM=1`, which makes that a failure. The scripts also need
openssl and a registry to pull alpine.

### Topology

A fleet is one `vk` compose group, set up by `tests/fleet/lib.sh`:

- **primary** — `vk-hub serve`, over TLS with a certificate from a CA made for the run,
  driven through its CLI with `vk exec`. Only the primary boots with the group; it starts
  and stops its sibling services through `/run/vk/services`, as
  `fullvm-compose-ctl-e2e.sh` does, so a test starts, stops and restarts nodes from inside
  the fleet.
- **node services** — nesting guests of 1 GiB (alpine with nftables,
  `tests/fleet/node/Dockerfile`), with the `vk` under test shared in, as `vk-hub` is into
  the primary, so a code change rebuilds no image. A test enrolls each node from inside its
  guest with `vk node join`; the service then runs `vk node run`, started again while it
  exits 75 on a state dir `join` still holds. Their roots persist, so a node keeps its
  identity across a restart.

One more node runs on the test host itself, beside the compose group, enrolled through the
hub's port published on loopback (`vk publish`): the VMs it runs are the workloads
`fleet-monitoring-e2e.sh` watches come and go.

### Fault injection

| Fault | How |
|---|---|
| node stop, restart | stop or start the node's service from the primary |
| hub crash | kill `vk-hub` in the primary and start it again on the same database |
| partition | drop the node's traffic to the hub with nftables in its guest |

### Evidence

A script that fails prints the end of the hub's log, each node service's state and the end of
its log, and the end of the host node's log.
