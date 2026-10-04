# Fleet prototype: operation and implementation

This reference records the experimental implementation: available commands, configuration,
limits and recovery behavior. Read [the design](fleet-design.md) for ownership rules, intended
guarantees and proposed changes. The [exit criteria](fleet-design.md#prototype-exit-criteria)
are requirements to demonstrate, not a claim that the prototype has passed them.

## Status

Implemented so far, all experimental: the list of the VMs a host runs (`vk
workloads`) and local mode's web UI showing it and acting on it (`vk-hub local`), signed
into with links it prints; enrollment, the node session, inventory and heartbeats; the VMs
each node runs (`vk-hub workloads`); the web UI's live nodes and node pages, signed into with
links from `vk-hub ui login`. The hub observes its nodes and steers none of them: desired
state, drain and quarantine, releases, updates, rollouts, resets, restart, redeploy, the
GitLab API pause and gitlab-runner pinning are not built yet.

“Built so far” describes current behavior. The proposed gates are work still to do, specified
in the linked design sections. They are not guarantees of the prototype.

| Capability | Current prototype | Proposed gate |
|---|---|---|
| Hub recovery | Not built: the hub keeps no desired state | [Preserve node restrictions and resolve the recovery conflict explicitly](fleet-design.md#proposed-recovery-after-a-hub-restore) |
| Update validation | Not built | [A pinned boot/exec/network/cleanup workload required for unattended rollouts](fleet-design.md#updates) |
| Canary promotion | Not built | [Representative workload success and an observation window](fleet-design.md#updates) |
| Release trust | Not built | [Pinned keys required for remote updates; explicit development opt-out](fleet-design.md#updates) |
| Reset | Not built | [Explicit job process ownership, verified empty before scratch removal](fleet-design.md#resets) |
| Capacity control | `vk tune` on each node, with no hub ceiling | [Measured against fixed concurrency before considering central acquisition](fleet-design.md#phase-3-central-gitlab-acquisition-if-needed) |

## Enrollment

Enroll a node with a token issued on the hub host:

```sh
vk-hub token create | ssh ci-7 vk node join https://hub.example.com --token -
```

This generates the node's ed25519 identity, which the hub pins on first contact. The node signs
the token with that key, so the hub pins only a key the caller holds. Enrollment tokens are
single-use and expire, and are issued by `vk-hub token create` through a unix socket on the
hub's host rather than over the network. A node whose enrollment answer was lost enrolls
again with a new token and the same key, and gets its node ID back. The identity survives
`vk` updates; `vk-hub nodes remove` revokes it and ends its session.

## Workloads

For the fields reported and their ownership, see the [workload design](fleet-design.md#workloads).

The sources exist already and are read, not duplicated: the host's VM registry under
`<data>/vms/`, whose entries are checked against the state dir's lock so a stale entry is not
reported (and is pruned, as `vk list` prunes it); the identities of the running dev
environments, read as `vk dev list` reads them, whose JSON fields are only ever added to; the
executor's job dirs whose supervisor is alive, and the `job.json` `prepare` writes into each —
the job's ID, project, name, image and size; the admission ledger for reservations. A job
prepared by an older `vk` has no record and is reported by its job ID alone.

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
each time it changes; a node's list rides on the report and is sent again when a VM starts or
stops. It holds at most 256 entries and 256 KiB — CI jobs first, then the newest of the rest —
with every string cut to 256 characters; it counts the VMs it leaves out, and the hub shows
the count. What each holds on the host goes beside it — on a node, on the heartbeat — by the
entry's ID, derived from its state dir: the managing process's whole process tree — the
guest, its compose services, the switch, virtiofsd — counted proportionally (`Pss` from
`smaps_rollup`), the figure `vk list` and `vk dev list` show, so the hub and a shell on the
host agree. Reading it walks every page table of every process, so it is measured every
`[node] workload_mem_secs` (`--mem-secs` for `vk workloads`; 30 by default) and as a VM
appears, and the heartbeats or lines between repeat the last figures — as does a measurement
within a sixteenth of the last one; a VM's pages move more slowly than that matters to anyone
watching. The hub keeps the latest list per node, not its history, apart from the node's row
and written without an fsync — the node sends it again on every session — with a count on the
row. It shows the list on the node's page, with when each VM started rather than an uptime
that would move the page on every minute, the count in the nodes table, and both in `vk-hub
workloads [--node ID|HOSTNAME]`. A dev environment's entry also names its SSH alias, when it
has an SSH setup, and the guest directory its workspace is at. Nothing acts on a node's
workloads yet; local mode acts on its own (see [Local mode](#local-mode)).

## Concurrency control

Not built yet: the hub sets no ceiling, and a node's runner concurrency is `vk tune`'s alone,
as on a host outside a fleet.

## Drain and runner lifecycle

Not built yet: a node takes no drain, stop or quarantine, and does not run gitlab-runner
itself.

## Maintenance transitions

Not built yet: nothing takes a node out of service.

## Update trial and rollback

Not built yet: a node's `vk` is updated as any host's is.

## Release signing

Not built yet.

## Releases and rollouts

Not built yet: the hub holds no releases.

## Release downloads

Not built yet.

## Resets

Not built yet.

## Web UI

Built so far: `ui_addr` in `hub.toml` turns the listener on — with its own `ui_tls_cert` and
`ui_tls_key` or the node listener's pair, plain HTTP only on loopback, and the node
listener's timeouts on everything before a request is authenticated. It serves the nodes
table with the columns of `vk-hub nodes`, and each node's inventory, heartbeat and workloads.
`ui_url` is
the address browsers reach it at: sign-in links start with it, and a state-changing request's
`Origin` must be it.

The nodes table and a node's page stay live over server-sent events. The hub notes every
heartbeat, report and session, by node. The
nodes table is the same for everyone, so one task renders it on a change and every nodes page
is sent that one rendering; a node's page is woken by changes to that node alone. A fragment
is rendered at most once a second, and every heartbeat interval regardless — a node going
quiet sends nothing — and sent only when it differs. Ages on the pages move in steps of a
heartbeat, so a fleet with nothing new to report sends nothing but a keep-alive comment every
15 seconds, and a node reporting faster than that changes nothing about the rate. When its
session ends, a stream sends a fragment saying so and a `close` event, on which htmx's SSE
extension (`sse-close`) stops reconnecting; a page asking for a stream with the cookie of a
session that has ended is answered the same, rather than refused into retrying. A stream whose
browser stops reading is given up on, and its connection dropped.

Streams hold connections — the listener speaks HTTP/1.1 only, HTTP/2 not being in the build —
so at most 96 of its 128 are streams and at most 4 belong to one session — below the six a
browser opens to one host, which every tab shares; past either a
stream is refused with 429 or 503, which the SSE extension retries with its backoff, doubling
from half a second to a minute. There is no per-address cap: the people using the UI are few
and often share one proxy or NAT address. The pages only show the fleet: removing a node stays
on the admin socket.

htmx 2.0.7 and htmx-ext-sse 2.2.3 are vendored in `vk-hub/assets/` (`VENDOR.md` gives their
sources and digests), embedded, and served under a hash of their content with a year's
caching. htmx runs with `allowEval`, `allowScriptTags` and `includeIndicatorStyles` off and
`selfRequestsOnly` on; the pages have no inline script or style for the policy to refuse.
Node IDs, issued by the hub and checked as hex — and in local mode the VM IDs `vk workloads`
derives, checked the same way, and dev environment names, checked to be `[A-Za-z0-9._-]` not
starting with `.` or `-` — are the only values in an attribute htmx reads or a link the hub
builds; what nodes or the host send goes only into text and plain attributes, escaped.

### Signing in

A person signs in with a link `vk-hub ui login [--role viewer|operator] [--ttl 10m]` prints
over the admin socket — `<ui_url>/login?t=<token>`; `vk-hub local` prints one as it starts,
and `vk-hub local login` more. The token is single-use, short-lived and stored hashed, like
an enrollment token. Opening the link shows a "Sign in" button, and only the `POST` it makes
— from the sign-in page itself, by `Sec-Fetch-Site` — spends the token, so a mail scanner or
a chat's link preview fetching the link leaves it unused. The post opens a session: a random
secret set as a cookie (`HttpOnly`, `SameSite=Strict`, `Path=/`, and `Secure` with the
`__Host-` prefix over https), kept hashed in the database with its role, and valid for 12
hours. The page it answers moves on to `/` itself, so the token never stays in the address
bar. `vk-hub ui sessions` (`vk-hub local sessions`) lists the sessions, `vk-hub ui logout
<id>|--all` ends them.

Browsers keep cookies apart by host, not by port. On plain http — which the UI serves only
on loopback — the session cookie therefore goes to every other http service on that host,
and any of them can set a cookie of the same name. The hub treats a request carrying two
session cookies as signed in with neither, but cannot stop the first from being read: when
anything else is served on the machine the UI is used from, give the UI TLS even on
loopback (the hub's own certificate will do). Local mode serves under a name of its own
instead (see [Local mode](#local-mode)).

Every state-changing request is a `POST` from the UI's own origin — its `Origin`, or
`Sec-Fetch-Site: same-origin` — carrying a CSRF token derived from the session's secret, and
is done as the session's principal, `ui session <id> (<role>)`, which is what the audit log
records.

Links stand in for a login until people sign in through OIDC, with the identity layer the
hub shares with `vk-registry` ([Authentication for submitted jobs](fleet-design.md#authentication-for-submitted-jobs)),
which then replaces them; the session and its role stay as they are.

## Local mode

Its actions run the existing commands as subprocesses rather than reimplementing them:

- dev environments: stop, start again (`vk dev up` in the workspace), clean up stale ones
  (`vk dev gc`);
- pinned runs: stop, reboot;
- every VM: the console log tail, the atop timeline, the egress report.

A shell in the browser needs a terminal emulator (xterm.js, vendored like htmx) over a
WebSocket to the VM's exec socket; it fits the CSP and is left for later.

The cookie problem is sharper here than on a fleet hub: a developer's machine serves many
things on loopback, including the ports `vk dev` itself forwards, and cookies are not
isolated by port. The local UI is therefore served under a name of its own,
`vk-<random>.localhost`, so its session cookie is host-scoped to that name and is not sent to
`localhost` or `127.0.0.1` on any other port. Chromium 153 and Firefox 156 both resolve
`*.localhost` to loopback and keep a cookie set by `vk-<random>.localhost` (SameSite Lax or
Strict) off `localhost`, `127.0.0.1` and other `*.localhost` names on every port. It still
reaches the same name on other ports, and loopback ports are anyone's: a name kept across
starts would be learnt by whatever took the hub's port while it was down, from the `Host` of
the next request a browser sent there, which could then catch the cookie on another port under
that name — or, `.localhost` being a secure context, leave a service worker on the hub's
origin to answer in its place. The name and the port are therefore drawn anew each time the
hub starts, and every session and unspent sign-in link of the last run ends, so what was
caught under an old name opens nothing. The port is bound on both `127.0.0.1` and `::1`:
Chromium 153 tries `::1` first for a `.localhost` name and Firefox falls back to it, so a hub
on `127.0.0.1` alone would leave `::1` to whoever takes it, and a hub asked for a port taken on
either refuses to start. A page (`GET`) is served only to a request the UI's own pages made or
no page made (`Sec-Fetch-Site` `same-origin` or `none`): `SameSite=Strict` still sends the
cookie with requests from another port of the same name, which is the same site.

Built so far: `vk-hub local [--port N] [--no-browser] [--vk PATH]` keeps its database and
admin socket in `$XDG_STATE_HOME/virtkit/hub-local` (or `--state-dir`), serves under a name
drawn as it starts — `vk-<16 hex digits>.localhost` — on `127.0.0.1` and `::1`, on `--port`
or one the system picks, and issues an operator's sign-in link valid for an hour, printed with
`--no-browser` or when stderr is a terminal. Unless `--no-browser` it opens the link with
`xdg-open` through a page in that private directory, removed a minute later, so the token
never sits in a command line another local user can read. A browser that cannot read the page
— a snap's, kept out of hidden directories — shows an error, and the printed link is opened by
hand. `vk-hub local login --role viewer` prints a link for a session that can only look.

It runs `vk workloads --watch` — the `vk` beside it, else the one on `PATH` — for as long as it
serves, starting it again with a backoff when it ends, and shows the list it prints, each VM
with a page of its own, both kept live the way the fleet's pages are, woken by each list. A
child rather than a command run again every few seconds, so the memory figures keep their
own cadence; a list of a version the hub cannot read is refused rather than misread. A VM's
page also shows its console's last hundred lines (`vk logs --exact`, which reads that state
dir's console alone, back from its end in bounded pieces), atop's account of a VM that records
itself (`vk atop --summary`; a CI job's is in the archive its job dir names, and one that does
not record is not attached to), and the egress its switch recorded — what a CI job's refuses
and contacts, or what a `vk run --audit-egress` contacts (`vk egress-report`, plumbing) —
each read as the page loads: reloaded within five seconds it shows what was read, and at most
two pages read at once. What the commands print is shown with their terminal escape sequences
dropped whole. A VM whose state dir the list cannot
show as it is — a byte that is not UTF-8, a control character — is neither read nor acted on
by its path: `vk workloads` derives the ID from the path's bytes, and the path shown no
longer hashes to it.

An operator's session acts on them by running `vk` as a shell would: a pinned run is stopped
(`vk stop`) or rebooted (`vk reboot`), named by the pid of its `vk run` — `vk stop <dir>`
would take the VMs of every directory below too — and a dev environment stopped (`vk dev
stop`). `/dev` lists every environment `vk dev list` knows, stopped ones included, read as the
page loads and reused for five seconds: a stopped one is started again in its recorded
workspace (`vk dev up --workspace … --environment …`), and one that is stale — its workspace
gone, or no boot recorded — removed (`vk dev gc --yes`). A CI job is its runner's and has no
action. A stop, a reboot and a removal are asked again before they run, with a question the
session answers once, within ten minutes, and only while what it was asked about — the run's
pid and start, the environment's last boot — is still as it was. Each runs in the background,
one at a time on each thing acted on, with a time limit past which its process group is
killed; the pages show it under way and how it ended, with the last line it printed, and the
audit log records it, as the session's principal, as it starts and as it ends; an action whose
start the audit log cannot record is not run. A shell in the browser is not built.

## Testing

`tests/fleet-*.sh` test the hub and its nodes end to end, on GitHub's hosted runners for every
push (`ci.yml`'s `fleet-e2e`) and with the rest of `tests/` before a release. They cover what
is built: enrollment, the session, inventory, heartbeats and workloads, and reconnecting after
a fault. The [exit criteria](fleet-design.md#prototype-exit-criteria) concern what is not built
yet, and each becomes a script of its own as what it exercises is built.

### Topology

A fleet is one `vk` compose group, set up by `tests/fleet/lib.sh`:

- **primary** — `vk-hub serve`, over TLS with a certificate from a CA made for the run,
  driven through its CLI with `vk exec`. The primary starts and stops its sibling services
  through `/run/vk/services`, as `fullvm-compose-ctl-e2e.sh` does, so a test crashes and
  restarts nodes from inside the fleet.
- **node services** — nesting guests of 1 GiB, each running `vk node join` and `vk node run`
  from the `dist/` under test, shared in rather than baked into an image, so a code change
  rebuilds nothing but `vk`. Their roots persist, so a node keeps its identity across a
  restart.

One more node runs on the test host itself, beside the compose group, enrolled through the
hub's port published on loopback (`vk publish`): the VMs it runs are the workloads a test
watches come and go.

### Fault injection

| Fault | How |
|---|---|
| node crash, restart | stop or start the node's service from the primary |
| hub crash | kill `vk-hub` in the primary and start it again on the same database |
| partition | drop the node's traffic to the hub with nftables in its guest |

### Evidence

A script that fails prints the hub's log, and each node service's state and the end of its
log.

### What it does not cover

No gitlab-runner runs: a node reports its runner's configuration, which the tests do not
check, and how GitLab spreads jobs over runners is measured on real CI hosts under real load.
