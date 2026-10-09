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
- on the node, desired state and a command journal kept across restarts, the runner's
  concurrency set within the hub's ceiling, and drain and quarantine of a gitlab-runner the
  node runs itself (`[node] runner = "managed"`);
- on the hub, that desired state (a ceiling, stopping acquisition) and those commands, sent
  to each node and shown beside what it reports (`vk-hub nodes ceiling`, `stop`, `resume`,
  `drain`, `undrain`, `quarantine`, `release`), and the audit log (`vk-hub audit`);
- on the hub, the `vk` releases it holds (`vk-hub release`) and updates naming one (`vk-hub
  nodes update`), each release served only to a node updating to it;
- on the node, those updates, run on trial and rolled back to the previous binary when the
  release does not pass, and releases checked against signing keys of the node's own (`vk
  release-key`);
- on the hub, rollouts of a release by wave, with a canary per hardware profile (`vk-hub
  rollout`);
- resets, which clear what a node's past jobs left (`vk-hub nodes reset`);
- `vk-hub workloads`: each node's VMs;
- live nodes, node detail and operations pages, steering and resetting from a node's page,
  pausing, resuming and aborting rollouts from the operations page, and an audit log, with
  sign-in links from `vk-hub ui login`.

Restart and redeploy are not built.

| Capability | Current prototype | Proposed gate |
|---|---|---|
| Hub recovery | Reissues its stored desired state above a newer node generation; adopts the node's applied state when it holds none | [Preserve node restrictions and resolve the recovery conflict explicitly](fleet-design.md#proposed-recovery-after-a-hub-restore) |
| Update validation | `vk check`, an optional local validation command, then hub reconnection | [A pinned boot/exec/network/cleanup workload required for unattended rollouts](fleet-design.md#updates) |
| Canary promotion | One canary per hardware profile, promoted once its update is done, the release reported running and the node back ready or drained | [Representative workload success and an observation window](fleet-design.md#updates) |
| Release trust | Signatures required by default only when keys are configured | [Pinned keys required for remote updates; explicit development opt-out](fleet-design.md#updates) |
| Reset | Matches known executables and job paths in process arguments | [Explicit job process ownership, verified empty before scratch removal](fleet-design.md#resets) |
| Stopping acquisition | `SIGQUIT` to a managed runner | [The runner also paused through the GitLab API](fleet-design.md#runner-concurrency) |
| Runner binary | Whatever `[node] gitlab_runner` names, or `gitlab-runner` on `PATH` | [Pinned on the node, as `vk` releases are](fleet-design.md#updates) |

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
kernel, and on a host already enrolled unless given `--replace`, which enrolls it again as a new
node: once the token is read and the checks pass, the old `<state_dir>/node/` is moved aside to
`node.replaced-<time>` beside it, not deleted, and `join` prints the old node ID to remove from
its hub. If the enrollment then fails, the error names where the old identity is, to move back.
A running node holds the state dir, and `join` says so: stop it, or pass `--service`, which
stops it first and starts it again if the join fails with its old enrollment still in place.

Run as root, `join --user NAME` sets the host up for the user the node will run as, then
enrolls as that user. Once the token is read, the checks pass and no node holds the state dir,
it creates the user when `/etc/passwd` has none (`useradd --system --create-home`, shell
`nologin`), adds it to the group `/dev/kvm` belongs to, creates the state dir and hands it and
what is in it to the user (`chown`, groups left as they are, never following a symlink,
crossing a mount point or changing a file also linked from outside the tree: those are named
and left as they are, and `join` refuses if one is not the user's), and checks that the user
can reach the state dir, run `vk` and read the config. The enrollment itself runs as the user
— its uid, groups and home — with the token passed on stdin. `--service` stops a running
`vk-node.service` before any of this, and once enrolled installs and starts it as `vk node
service install [--user NAME]` does. If the join fails, the unit is started again only while
its enrollment is still in place and it runs as `NAME`. So one command moves a runner host to
a hub, and a new one onto it:

```sh
sudo vk node join https://hub.example.com:8443 --token - --user gitlab-runner --service [--replace]
```

A node whose enrollment answer was lost enrolls again with a new token and the same key, and
gets its node ID back. The identity survives `vk` updates. `vk-hub nodes remove <id>` revokes
it and ends its session. The host can then join again only as a new node, with `vk node join
--replace` and a new token. Issuing a token, enrolling, re-enrolling and removing a node are
recorded in the audit log.

### Running the node

`vk node service install [--no-start] [--stop-timeout DURATION] [--user NAME]` runs `vk node
run` under systemd as `vk-node.service`, enabled and started. Run as root, it writes a system
unit to `/etc/systemd/system/` (`WantedBy=multi-user.target`, pulling in
`network-online.target`) that runs the node as root, or as `--user NAME`: the unit always names
its `User=`, so systemd sets `HOME` for a managed runner's default config. The user must be in
`/etc/passwd`: `vk` reads no other user database, so a user only LDAP or SSSD knows installs a
user unit instead, running the command as that user. Run as any other user, it writes a user
unit to `$XDG_CONFIG_HOME/systemd/user/` when the user owns that directory (else
`.config/systemd/user/` under the home directory `/etc/passwd` gives, not `HOME`: `su` and
`sudo -u` may carry either over from the invoking user;
`WantedBy=default.target`), and enables lingering for that user so the node runs without a
login session, or prints the `sudo loginctl enable-linger <user>` an administrator must run
when the user may not; `--user` is refused there. It refuses on a host not enrolled, and on one
whose `<state_dir>/node/` belongs to another user than the node would run as — that user
enrolled the host, and running the node as another means removing it from the hub, deleting
`node/` and joining again as that user. It also refuses while another `vk node` holds the state
dir (a foreground `vk node run`, or a unit of the administrator's own) and the unit is to be
started, while `vk-node.service` is starting or stopping, when a
`vk-node.service` it did not write is in the way, and when the other systemd manager already
runs a node as the same user: a system unit naming that `User=`, or the user's own unit.

On a CI host where the node runs as `gitlab-runner` with `/etc/virtkit/config.toml`, root
enrolls it as that user and installs the unit:

```sh
sudo -u gitlab-runner vk node join https://hub.example.com --token -
sudo vk node service install --user gitlab-runner
```

`sudo vk node join … --user gitlab-runner --service` does both, and sets the user up first.

With `--user`, the account must be able to reach the state dir, read the config and execute
`vk`. If the command read no config, it refuses a user config under `~/.config/virtkit/`,
which the node would read instead. Installation warns if the user cannot write the binary's
directory: the node refuses updates there. Permissions are checked using mode bits, not
ACLs. With `[node] runner = "managed"` and no `[node] gitlab_runner`, `gitlab-runner` must be
on systemd's own `PATH` (`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`), which
lacks `~/.local/bin`; otherwise set `gitlab_runner` to its absolute path.

The unit runs the `vk` the command was run from, resolved through symlinks — the installed
binary an update replaces, so a release from `<state_dir>/node/releases/` is refused — with
`--config` naming the config file the command read, if any, so the service uses the state dir
`join` enrolled. It sets `KillMode=mixed` and `TimeoutStopSec` from `--stop-timeout` (`90s`,
`10m`, `1h` or seconds; `1h` by default, GitLab's default job timeout; `0` for no limit). A
shutdown or reboot waits for the same: up to `--stop-timeout` with a managed runner. To stop
sooner, `systemctl kill --kill-whom=main vk-node` sends the node the second signal, which
abandons the jobs; a plain `systemctl kill` signals the runner too. `OOMPolicy=continue` keeps
the node up when the kernel kills one job's VM for memory. The unit is not sandboxed: its
processes are the runner, its executors and their VMs, which need `/dev/kvm`, taps, the state
dir and the installed `vk`'s directory; the VM is the isolation boundary. `Restart=on-failure`
with `RestartSec=10s` starts the node again after a crash, a release on trial killed by its
`SIGALRM`, an exit 75 or any other failure; a refusal for good exits 1 like a local failure, so
the start limit — ten starts in ten minutes — is what ends a node that fails on every start,
after leaving room for a trial's attempts and its rollback. Under the unit, a node that exits
takes its runner and the jobs running with it: systemd ends the unit's processes before
starting it again. Runner adoption covers a node run without such a supervisor. Reinstalling
rewrites the unit, clears a start-limit failure, and restarts a running node, waiting for a
managed runner's jobs. If the systemd manager is unreachable, installation fails and names
the unit it wrote. `vk node service uninstall` stops, disables and removes the unit (the
system unit when run as root), preserving enrollment.

## Hub and node

`vk-hub serve [--config hub.toml]` serves nodes. `hub.toml` sets `addr` (default
`127.0.0.1:8443`), `tls_cert` and `tls_key`, `data_dir` (default `$XDG_DATA_HOME/virtkit/hub`,
else `~/.local/share/virtkit/hub`), `release_repository` (see [Releases](#releases)), and the
web UI's keys (see [Web UI](#web-ui)). Every key is optional and an unknown one is an error.
Without TLS the hub serves only on loopback. TLS is 1.3 only, on both the hub and the node.
`vk-hub token`, `vk-hub nodes`, `vk-hub release`, `vk-hub workloads`, `vk-hub audit` and
`vk-hub ui` reach the running hub through `<data_dir>/admin.sock`, open to the hub's user and
root.

`vk node run` holds a WebSocket session at `/v1/node` in the foreground. The node signs the
hub's challenge, its node ID and incarnation (new on every `vk node run`), both version ranges,
the version the hub picked, which the node checks against both ranges before signing, and,
over TLS, 32 bytes of exporter output under the label `EXPERIMENTAL-vk-fleet-node-auth` (a
plaintext loopback session signs a `plaintext` marker instead). A signed payload starts with a
label of its own, and every variable-length part carries a big-endian `u64` length prefix.
Keys, signatures, nonces and IDs are strict lowercase hex, except a release key's signature,
which is base64. A proxy in front of the hub must pass TLS through: terminating it breaks the
binding, and the hub refuses the signature.

From 0.83.0, hubs and nodes of different releases interoperate: protocol version 1 and
enrollment at `/v1/` are frozen, though the fleet remains experimental. Version 2 adds
steering — desired state, commands, their acks, and the node's state on its report. A hub
serves a version-1 node for monitoring only (see [Steering](#steering)); a node whose hub
speaks only version 1 runs on its local policy alone. Version 2 also defines updates: the
`update` operation, which names a release by sha256 and size and may carry a release key's
base64 signature; the `maintenance` and `validating` states; the update's progress on the
report; and a release download, `GET /v1/releases/<sha256>`, signed by the node under the
label `vk-fleet release-download v1` over its ID, the release's 32-byte sha256, the time (`u64`)
and the channel, sent in the `vk-node`, `vk-time` and `vk-signature` headers. The hub issues
updates and serves releases (see [Releases](#releases)), and a node applies them (see
[Update trial and rollback](#update-trial-and-rollback)).

The hub admits at most 256 connections that have not authenticated, each step of which (TLS,
request headers, an enrollment body, a handshake message) has 10 seconds. One past that is
closed at once. At most 256 handshakes run at once; past that the upgrade is answered HTTP
503, and the node redials. A message is at most 1 MiB either way.

The hub asks for a heartbeat every 5 seconds; the node clamps what it is asked to 1–300
seconds. A node silent for 3 heartbeats has its session dropped and is listed unreachable; the
node gives up on a hub silent for 3 of the intervals it asked for. The node re-reads its
inventory every 60 seconds and sends it when it changed. Its report carries its VMs and, from
version 2, its state (see [Node state and commands](#node-state-and-commands)); it goes out at
the start of every session from version 2, with the next heartbeat after the VMs change, and
whenever the node's state changes.

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
ID, NAME, REACH, STATE, ACQUIRE, CEILING, CONC, SYNC, LAST SEEN, VK, CPUS, RAM, ADMITTED and
VMS.

The node redials a lost session with a backoff doubling from 1 to 60 seconds, plus up to a
quarter of jitter, reset by a session that lasted a minute. Superseded three times in a row, it
warns that another host may hold a copy of its state dir and redials every minute. A hub
refusal of `not_enrolled`, `bad_signature` or `revoked` ends `vk node run`, once a managed
runner has finished its jobs. A first SIGTERM or SIGINT closes the session, waiting at most 5
seconds for the hub, and quits a managed runner, waiting for its jobs; a second exits at once,
or with a managed runner sends it SIGTERM, abandoning the jobs, and exits once it has gone; a
third exits at once. `vk node run` exits 75 while another `vk node` holds
`<state_dir>/node/lock`, and refuses to start unless `<state_dir>/node/` belongs to its user and
is closed to everyone else.

## Steering

`vk-hub nodes ceiling <id> <n|none>` caps a node's runner concurrency, and `vk-hub nodes stop`
and `resume` stop and resume its acquisition: the node's desired state, kept on the hub with a
generation that moves on every change, to one past both the hub's last and the one the node
last reported applying. A ceiling of 0 is refused: gitlab-runner has none, and stopping
acquisition is what it would mean. `vk-hub nodes drain`, `undrain`, `quarantine`, `release` and
`reset` issue a command, valid for a day. On the admin socket they are audited as `uid <n>`,
the caller's; an operator's node page in the web UI runs the same operations, audited as its
session's principal (see [Web UI](#web-ui)).

A session sends desired state once the node's report shows an older generation, once per
generation, and each command without a final outcome once per session; nothing goes before the
node's first report. A change made while the node is connected goes out at once, and one made
while it is not on its next session. Each ack is answered `recorded`, even for a command the
hub does not know, which the node would otherwise repeat for ever; a new outcome is recorded
and audited. A final outcome is never replaced, so a late `accepted` cannot reopen a finished
command. A command the node never took is not sent past its expiry. Settled commands are kept
30 days, and go with their node when it is removed.

A node reports the desired state it applied, not only its generation. When the hub's desired
state is older than the node's, or was built on the defaults before the node reported, one of
these happens, audited either way:

- The hub holds desired state of its own for the node, older — restored from a backup taken
  after the node was first steered, say. It is re-issued as the generation after the node's.
  This orders messages; it does not reconcile intent (see
  [recovery after a hub restore](fleet-design.md#proposed-recovery-after-a-hub-restore)).
- The hub holds none — restored from a backup taken before the node was steered, or taken
  back to 0.84.0 or earlier and forward again, since such a hub rewrites the node's row
  without it. The hub adopts what the node applied as its own desired state, at the node's
  generation, and sends nothing: the node keeps its ceiling and its stopped acquisition. An
  operator change made before the node reports what it applied is applied onto the node's
  state: the fields the operator set, even to a default, replace the node's, the others stay as
  the node has them, and the result is issued past the node's generation unless the node
  already applied it.

Steering takes protocol version 2. A node whose latest session ran version 1 — a `vk` of
0.83.0 or 0.84.0 — is monitored only: the hub refuses to change its desired state or issue it
a command, saying to update its `vk`, and `vk-hub nodes` shows it as `monitor only (v1)`. A
node that has not connected yet is steered on trust; if it then connects at version 1, it is
sent nothing, and its commands expire unanswered.

`vk-hub nodes` shows what the hub asked beside what the node reports. STATE is the node's own,
with how many commands are pending. ACQUIRE and CEILING are the hub's, with the node's in
brackets where they differ, and `quitting` while a stopped runner finishes its jobs. CONC is
the concurrency the node set. SYNC compares the state the node applied with the hub's: `ok`,
`behind (2<3)` or `ahead (4>3)`, `differs` when the node applied another state under the same
generation, `unknown` before the node's report, and `-` while the hub has asked nothing. Under
the table, a line says each thing a node cannot carry out (`cannot comply: …`) and why it
cannot set its concurrency.

`vk-hub audit [--node ID] [--limit 50]` prints the latest audit lines, oldest first — time,
node, actor, event: operator actions, with the generation or command each made, and what nodes
report of them — a new state, a newly applied generation, each command's outcome, each phase of
an update as the node reaches it, what a node cannot carry out. Each line is written in the
transaction of the change it records. The log keeps the latest 100,000 lines.

## Node state and commands

`vk node run` keeps what its hub asks in `<state_dir>/node/state.json`, `0600`, rewritten whole
and renamed into place: the desired-state generation it last applied, its own state (`ready`,
`draining`, `drained`, `maintenance`, `validating` or `quarantined`), a journal of the commands
it received, and the update or reset under way. A
generation no newer than the applied one is ignored, so each is applied at most once. A
command is journaled by its ID, together with the change it makes, before anything acts on it;
one delivered again is answered from its entry rather than run again, and one received past its
expiry is answered `expired`. An entry is kept until the hub has recorded its outcome and its
command has expired, and past 4096 recorded entries the oldest go first.

The node answers every delivery of a command with its ack, and at the start of every session
repeats each ack whose outcome the hub has not recorded. The state names the hub and node ID it
was kept for: a node enrolled anew, or with another hub, forgets the applied generation and the
journal but keeps its own state. In a session at version 1 the node sends no ack and its report
carries its VMs alone; what it persisted still applies.

A drain is `accepted`, and its ack moves to `done` once the node is drained, or to `failed` if
an `undrain` or a `quarantine` ends it first; a drain of a drained node is `done` at once. An
update and a reset are `accepted` too, and end `done` or `failed` ([Update trial and
rollback](#update-trial-and-rollback), [Resets](#resets)). Any other command the node can carry
out is `done` when received. Drain, quarantine and reset need a runner the node runs itself:
with an external runner the node refuses them, and reports a stop of acquisition in the desired
state as something it cannot carry out (`unsupported`), while still setting the runner's
concurrency. Each change is written, and its directory fsynced, before the ack goes out: the
hub does not send a command again once it has its ack.

## Concurrency control

`vk node run` sets the runner's concurrency itself, with `vk tune`'s decision and the hub's
ceiling from the applied desired state as a third term: every half minute, and whenever its
desired state or anything else it reports changes, only the half-minute pass raising it, by
the estimate's one step when there is a memory budget. As with `vk tune`, the number goes to
`<state_dir>/schedule/desired-concurrency` for `vk-runnerctl`, and a runner config the node's
user owns (`[node] runner_config`, by default `~/.gitlab-runner/config.toml` for a managed
runner) has its `concurrent` set directly. The report carries the
estimate, both ceilings and the effective number; a concurrency that cannot be set is
reported with the reason (`concurrency_error`), and logged when it starts.

On a node, `vk node run` is the one writer: `vk tune` does nothing while `vk node run` holds
`<state_dir>/node/lock`, and otherwise applies the ceiling the node last persisted, so a timer
left running from before the host joined gives the same answer. A `vk tune` pass holds that
lock shared, and a starting `vk node run` waits up to ten seconds for it.

## Drain and runner lifecycle

With `[node] runner = "managed"`, `vk node run` runs `gitlab-runner run --config
<runner_config>` itself (`[node] gitlab_runner` names the binary, `gitlab-runner` on `PATH` by
default), in a process group of its own and with every signal at its default disposition, so
one the node inherited as ignored cannot keep the runner from stopping. It restarts a runner
that dies with a backoff doubling from 1 to 60 seconds, reset by a run that lasted a minute.
It stops acquisition with `SIGQUIT` while the hub has asked for that and while the node is
draining, drained or quarantined, and starts no runner until it may take jobs again.
gitlab-runner has no way back from `SIGQUIT`: a runner told to stop is reported `quitting`,
and acquisition as still running, until it has exited, and a resume that comes meanwhile
starts a new runner once the old one has gone. A runner outlives a node killed outright; its
pid and start time are kept in `<state_dir>/node/runner.pid`, and the next `vk node run`
follows the runner it finds there rather than start a second.

A drain completes on what the node can observe. gitlab-runner, sent `SIGQUIT`, exits only
once its jobs are over, cleanup stage included; the admission ledger holds and awaits
nothing; and no job supervisor is still alive — a job dir alone proves nothing, since a
failed cleanup leaves one behind, but its supervisor's pid, checked against the job dir, says
whether its VM is still up. The report carries which of the three hold (`drain`) while the
node drains. These are the node's own state dir's ledger and job dirs, so the executor its
runner runs must use the same vk configuration; the node warns at start when the runner's
config names another. `undrain` returns a drained or draining node to `ready`; a quarantine
stops acquisition from any state and only `release` lifts it, returning the node to `drained`
if that is where it was quarantined and to `ready` otherwise. A quarantined node refuses
`drain` and `undrain`. All of it is persisted on the node, and a restart or a lost hub leaves
it where it was.

## Releases

`vk-hub release add <file> --version <v>` copies a `vk` binary into `<data_dir>/releases/`,
named by its sha256, and prints the sha256; `release list` and `release remove` show and delete
them, unless a node is still updating to the release. Adding the same bytes and version again
returns the existing release and restores its binary if missing or the wrong size, so a retry
after a lost response succeeds. The hub never runs a binary it is handed: it holds the
database, its TLS key and every node's pinned key, so it only reads the file, checking that it
is an x86-64 ELF of at most 1 GiB that holds the stated version as a string of its own. The
version is the operator's to state; running the binary is left to the node. `vk-hub nodes
update <id> --release <sha256>` issues the update, which names the release by digest and size;
a prefix of at least 8 hex digits names a release too. `--force` asks a node whose runner is
external, which cannot be drained, to update without draining. Like any command, it is refused
for a node monitored only.
`release add --signature <file>` stores a release key's signature with the release, and the
update carries it (see [Release signing](#release-signing)); the hub checks only that it is an
ed25519 signature in base64, and `release list` shows which releases are signed. Adding the same
bytes again requires the same signature, including its absence: remove the release to change
its signature.

`vk-hub release fetch [<version>|latest]` downloads a published release instead, from
`release_repository` in `hub.toml`: `https://github.com/virtkit-dev/virtkit` by default, another
`https://<host>/<owner>/<repo>` — a repository on a GitHub Enterprise Server, whose API is
`/api/v3` on that host — or `"none"`, which turns fetching off. The hub resolves the release
through GitHub's REST API, downloads its `vk` asset (the static linux x86-64 binary) over https,
refusing any redirect off it, and holds it only once it hashes to the sha256 the release
publishes beside it in `vk.sha256`, the tag is the version asked for, and the binary passes the
checks above; it is held unsigned, as `vk-hub release add` without `--signature` holds one. This
is the code `vk update` replaces a binary with (`vk-selfupdate`), short of running the binary,
which the hub never does. The asset may be at most 512 MiB, each read must arrive within 30
seconds, the fetch's requests within 30 minutes in all, and one fetch runs at a time. The
`HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY` environment of `vk-hub serve` applies. `--check`
prints which version the latest release is, and downloads nothing; asked again within 30
seconds, it gives the last answer, or the last failure, as GitHub allows an unauthenticated
caller 60 requests an hour. The fetch, and a failure with its reason, are audited, and the
release added is audited as a `release add` is.

What a fetch proves is that the hub holds the bytes the repository published as that version,
intact: not who built them. A repository or account compromised to publish another binary
with a matching `vk.sha256` passes, as `vk update` does. Releases are attested by a
reproducible rebuild in CI, which the hub does not check, and official releases carry no
release key signature yet, so a node with `require_signed` refuses a fetched release, as it
refuses any unsigned one (see [Release signing](#release-signing)).

An update's release is downloaded from the node listener, `GET /v1/releases/<sha256>`, with the
node's ID, the time and its signature over both, the release and the connection's TLS exporter
— the session auth's binding — in the request's headers. The hub serves it only to an enrolled
node whose pinned key verifies, within five minutes of the hub's clock, and which has an update
to that release still to finish: the hub is not a download site, and no grant sits in a command
or the node's journal to be replayed. The body is streamed from the file, one download per
connection; once authenticated, a download no longer counts against the connections the
listener allows before authentication, and may hold its connection for 30 minutes past the 30
seconds any connection gets. At most 64 downloads run at once; past that the request is
answered HTTP 503, to be retried.

## Maintenance transitions

An update or a reset ([Resets](#resets)) is taken from `ready`, `draining` or `drained` and
drains the node first (a drain already under way is joined, and the node returns to `drained`
after); `maintenance` covers the download and the switch, `validating` the release's trial, and
the node then returns to the state it came from — or enters a quarantine that arrived
meanwhile, which is in force from the moment it is received since maintenance takes no jobs.
While the node still drains, `undrain` or `quarantine` call the update or reset off; once
maintenance has begun, the job runs to its end: a `drain` makes it end `drained`, a `release`
withdraws a quarantine received meanwhile, and an `undrain`, another update or a reset is
refused. A quarantined node refuses an update and a reset. What `validating` runs is
`vk check`'s gate and `[node] validate`, an argv of the operator's that must exit 0 within
`validate_timeout_secs` (600 by default) — booting a small image with `$VK_BINARY`, the
release on trial, is the intended use. The report carries the update's phase (`draining`,
`downloading`, `validating`, then `done`, `rolled_back` or `failed`, with the reason), and the
inventory the sha256 of the `vk` the node runs.

## Update trial and rollback

An update names its release by sha256 and size, and may give a time limit, `within_secs`,
counted from the end of the drain; a drain still under way when the command expires calls the
update off. After the drain, the node downloads the release into
`<state_dir>/node/releases/<sha256>` — a private file renamed into place once it hashes to the
sha256 and is no longer than the size — runs its `--version` (`vk-selfupdate`'s smoke test,
killed past 30 seconds), keeps the running binary beside it under its own sha256, and executes
the release in its own place with a trial recorded in its state, flushed to disk: the
installed binary's path and its device and inode, the attempts, and a deadline —
`validate_timeout_secs` plus ten minutes on, or the command's limit if that comes first.

The installed binary is the file the last `vk node run` not started from a release executed,
as the kernel names it — a symlink is followed, and its target is what an update replaces, so
a `vk` reached through a link into a versioned directory has that directory's file replaced.
The path is recorded in the node's state, never read off a release running from the releases
directory, and an update is refused while it is unknown, gone, inside the node's own
directory, or in a directory the node's user cannot write.

The installed binary is not touched during the trial, so whatever starts `vk node run` next —
a supervisor restarting a release that crashed or was ended, or a person — starts the previous
binary, which counts the attempt and hands over to the release again while it still hashes to
what was downloaded, and past three attempts, past the deadline, or when it no longer hashes
ends the update as rolled back and runs on itself. A release that dies before it can count
anything is counted all the same. The binary that executes a release on trial arms `alarm(2)`
for a minute past the deadline across the exec, and the release arms it again before anything
else runs, so the kernel ends a release that hangs — even one that is no `vk` at all — and the
previous binary, restarted, finds the deadline past; a release that does not hang rolls back
at the deadline itself. The alarm is disarmed once the trial is confirmed. Without a
supervisor that restarts `vk node run`, such as the unit `vk node service install` writes, a
release that crashed or was ended leaves the node down until someone starts it.

On trial the release validates, waits for a session with the hub, and only then copies itself
beside the installed binary — checking what it copied against the sha256 — and renames it into
place, ending the update done; it then executes the installed binary, so the node never goes
on running from its releases directory. A failure or the deadline ends it as rolled back: the
release executes the installed binary, or failing that the copy kept of it, whichever still
hashes to what the release replaced; with neither, it quarantines the node, for an operator,
rather than run on as ready. An installed binary that is no longer the file the trial started
from — replaced by hand or a package manager meanwhile — is not overwritten: the update fails,
and the node runs what is installed. A crash during the download leaves the node in
`maintenance`, which the next start takes up again; one between recording the trial and
executing the release is the first attempt counted; one during the install is finished by
the next start. The update's ack is `done`, or `failed` with the reason — `rolled back: …`
when the release ran. After an update the release and the binary before it are kept in
`releases/`, and after a rollback the binary running; everything else there is removed.

A release that validates but cannot reach the hub by the deadline is rolled back. The
previous binary downloaded the release from the hub just before the switch, so the trial
treats lost connectivity as a release failure: keeping it could leave the node unreachable
by its hub. If the hub went down meanwhile, the update must be retried.

An update is refused on a node whose runner is external unless issued with `--force`: such a
runner cannot be drained, so jobs running across the switch run their later stages with the
new `vk` — the one thing draining exists to prevent. It is refused, too, for an older version
than the node runs unless the node's own `[node] allow_downgrade = true` allows it, and even
then for one older than 0.85.0, the first release that takes part in a trial; versions are
compared as `MAJOR.MINOR.PATCH`, and an older one that is not of that form is refused.

## Release signing

Signatures are made offline: `vk release-key generate --key <file>` writes an ed25519 key
(`0600`, published whole and never over an existing file) and prints its public half in
base64, and `vk release-key sign --key <file> --version <v> <binary>` prints the signature of
the binary's sha256 and version under the label `vk-fleet release v1`. The tool is in `vk`,
which every node and workstation has and which already links ring, rather than in `vk-hub`:
keep the key off the hub so a compromised hub cannot sign releases.

A node's `[node] release_keys` lists its trusted keys. `require_signed` defaults to true when
any key is set, requiring a signature by one of them. The node checks it on receipt, before
any drain, and again before the release first runs, using its current keys. With keys
configured, the node rejects invalid signatures even when signatures are optional. The keys
are pinned in the node's configuration, not in the `vk` binary. Official releases are not
signed this way yet: that is a step for the release workflow, with the key in CI's secrets.

## Rollouts

`vk-hub rollout create --release <sha256> [--nodes all|<id>,…] [--batch N]
[--canary-per-profile] [--max-failures N] [--node-timeout 30m] [--drain-timeout 4h]
[--force]` puts the chosen nodes into waves — with canaries, wave 0 is one node of each
hardware profile, and then batches of N in profile and hostname order — and a hub task issues
each wave's updates once the wave before has finished. It prints the rollout's ID alone on
stdout. A hardware profile is the CPU model, the RAM rounded to the nearest power of two in
GiB, and the speed classes declared for the job and checkout filesystems: what makes hosts
behave differently under one `vk`, and nothing a heartbeat moves.

A node's update succeeds when its command is `done`, it reports the release's sha256 (its
version, for a node that reports none), and it is back to work: `ready`, or `drained` — the
state it was in when the update was issued, unless an operator drained or undrained it
meanwhile. It has two windows. The drain has `--drain-timeout`, from the issue: it is the
command's expiry, so a node that never takes the command refuses it as expired, and one still
draining then calls the update off. The update proper has `--node-timeout`, from the node's
report that its drain is over: the command carries it, and the node makes it its trial's
deadline, rolling back past it. The hub counts the node failed two minutes after either
window ends — it learns of the node's progress from reports, and its clock may lead the
node's — so an update the rollout has given up on is never kept. A hub that has just started
judges no window for two minutes, while its nodes reconnect: its database predates its
downtime. A node also fails when its command fails or is refused, when it is removed, or when
it ends its update quarantined.

A failure pauses the rollout; `rollout resume` carries on past the failed node, and a failure
past `--max-failures` aborts it instead; a node whose update ends after an abort is recorded
but not counted. A node is skipped from the start, so canaries are picked among the others,
when it is monitored only (its latest session at protocol version 1), already runs the
release, is quarantined, has not reported its state yet, or — unless `--force` — has an
external runner, which cannot be drained. When its wave comes, a node is skipped for any of
these, when it has been removed, when it is draining or in maintenance of its own, or when an
update an operator issued it before the rollout reached it is still under way.
`rollout status [<id>]`, `pause`, `resume` and `abort` steer it; pausing or aborting issues
nothing more, and updates under way finish and are still recorded. One rollout runs at a time,
a release is kept while a rollout of it is not over, and `vk-hub nodes update` refuses a node a
running or paused rollout has still to update. The rollout and its nodes' states are one row in
the hub's database, written in one transaction with the commands it issues and the audit lines
that describe each step; a pass that changes nothing writes nothing; the hub task advances
every rollout from the database at start, whenever a node reports, and every five seconds, so a
restarted hub carries on where it stopped. A rollout that cannot advance holds none of the
others back.

## Resets

`vk-hub nodes reset <id> [--images]`, or the reset button on an operator's node page — which
asks again, on a form of its own, before the reset is issued — drains the node like an update
does, from `ready`, `draining` or `drained` and only with a managed runner, except that the
drain is over once the runner has exited and no job is waiting for admission or being admitted:
a job supervisor a failed cleanup left running, and the admission it holds, are what a reset is
for, not something it waits on. A job admitted with no supervisor yet is a `prepare` under way,
which the reset does not stop; it waits for that one to exit or hand its job to a supervisor,
and fails, the node left `drained`, if it has done neither within ten minutes. In `maintenance`
the node stops the processes past jobs left: those of its user whose binary is a `vk` (the
running one, the installed one, a release under the node dir, or any file so named), a
`cloud-hypervisor` or a `virtiofsd`, and whose arguments name a path inside one of its job dirs,
whole or as a `--flag=` value — a shell or a `tail` of a job's log is not one of them. Each is
held by a pidfd opened before its `/proc` entry is read and kept only if still alive after, sent
`SIGTERM` through it, and `SIGKILL` if it has not exited ten seconds later; one still alive five
seconds after that, or a `/proc` the node cannot list, fails the reset before anything is
removed. The node then gives back each job dir's network lease, removes the job dirs under
`<state_dir>/jobs` and anything else there but its dot-entries, a symlink removed as itself and
never followed, sweeps the host checkouts no job uses, and with `--images` evicts the
materialized images under `<state_dir>/{registry,docker,build}` as `vk gc --idle-secs 0` does.
The build cache's registry store is never touched. `validating` then runs what an update's trial
does — `vk check`'s gate, `[node] validate`, and a session with the hub within ten minutes — and
the node returns to the state it was in; a node that fails stays `drained`, with the reset
`failed` and the reason, rather than take jobs on a host that does not pass. A reset clears the
last update's progress from the node's report, and a reset and an update exclude each other; a
`vk node run` stopped during either takes it up again at its next start. The command's audit
lines name it `reset`, or `reset, images included`.

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
compose services, switch, forwards — counted proportionally (`Pss` from `smaps_rollup`, else
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
request's headers and a form's body each have 10 seconds; a release's upload has limits of its
own (see below). `ui_url` is the address browsers reach it at: sign-in links start with it, and
a state-changing request's `Origin` must be it. It defaults to `http(s)://<ui_addr>`, and is
required when `ui_addr` binds an unspecified address. It is `https` whenever the listener has
TLS, and `http` only for `localhost`, `127.0.0.0/8` or `[::1]`. It is normalized as a browser
writes an origin: lowercase, no path, no default port, IPv6 in canonical form; an IPv4-mapped
IPv6 address and a numeric host that is not a dotted quad are refused. `ui_url`, `ui_tls_cert`
or `ui_tls_key` without `ui_addr` is an error. An `[oidc]` table adds sign-in through an OIDC
provider (see [Signing in](#signing-in)).

The UI serves the nodes table with the columns of `vk-hub nodes`; each node's inventory,
heartbeat and workloads; and the audit log (`/audit`, filterable by node, 100 lines a page; the
hub keeps the newest 100,000 rows). A node's page shows what the hub asks of it beside what it
reports — its state, acquisition, runner, concurrency, drain progress and what it cannot
carry out — and its 20 latest commands with their outcomes. An operator's node page offers
the steering actions: a ceiling set or lifted, acquisition stopped or resumed, drain,
undrain, quarantine, release, and reset, which requires confirmation from the same session,
once and within ten minutes, as local mode's stops do. Each action returns a status line
through htmx while the node's fragment updates live, and also works as a plain form.
Monitoring-only nodes are marked, offer no actions and reject steering posts. Viewers have no
actions. Removing a node stays on the admin socket. A page is refused to a request whose
`Sec-Fetch-Site` is `same-site` or `cross-site`.

The nodes table and `vk-hub nodes` show an update under way beside the node's state —
`maintenance, updating to 0.85.0: downloading` — and a rolled-back one until the next; a
node's page shows the update's release, phase and what the node said of it, and the sha256 of
the `vk` it runs. `/operations` lists the releases the hub holds, signed or not, and its ten
latest rollouts with their state, counts, current wave, and each node's status and profile
by wave. Operators can pause, resume and abort active rollouts. These actions post to
`/rollout/<id>/action` with the node actions' origin, CSRF and role checks, and run the admin
socket's operation as the session's principal. Invalid state transitions return 409. The
shared fragment carries no session token: the surrounding page supplies its session's CSRF
token through `hx-headers`, as JSON that htmx parses without evaluating. The buttons require
htmx; `vk-hub rollout pause|resume|abort` works without it.

Above the fragment, an operator's `/operations` carries three forms, each with the same
origin, CSRF and role checks, run as the session's principal; a viewer's carries none.

- **Upload** posts a `vk` binary, its version and optionally a release key's signature (the
  base64 `vk release-key sign` prints) to `/releases/upload` as `multipart/form-data`, a plain
  form. The body is read as it arrives: the CSRF token (field or `X-CSRF-Token` header), the
  version and the signature are checked before a byte of the file is written, and the file is
  streamed to a private file in `<data_dir>/releases/`, then held through `release add`'s
  checks. Any failure, the browser leaving included, removes the file; so does `vk-hub serve`
  starting, for what a stopped hub left. The binary may be 1 GiB, the body must state its length
  and arrive within a minute plus its length at 256 KiB/s — a little over an hour for 1 GiB,
  about seven and a half minutes for 100 MB — and never pause for 30 seconds. One upload runs at
  a time, counted from when its fields pass their checks, and the session must still be an
  operator's once the file is in.
- **Fetch from GitHub** posts a version, `latest` by default, to `/releases/fetch` and starts
  `release fetch` in the background; the fragment shows its progress and how it ended. "Check
  the latest" asks which version that is and shows it, giving the last answer, or the last
  failure, again within 30 seconds. The form is absent with `release_repository = "none"`.
- **Start a rollout** takes a held release, all nodes or a chosen few, and `rollout create`'s
  options, and posts to `/rollouts`. It is asked again first, as a reset is, showing the
  release, whether it is signed, and the nodes wave by wave with those skipped and why; the
  answer counts once, from the same session, within ten minutes, and only while the plan is
  still what was shown — a node enrolled, removed or updated meanwhile refuses it.

The nodes table, a node's page and `/operations` stay live over server-sent events. The hub
notes every heartbeat, report, session, command outcome and desired-state change, by node, and
every release added or removed and rollout step. The nodes table is the same for everyone, so
one task renders it on a change and every nodes page is sent that one rendering; `/operations`
likewise, once for every viewer's page and once for every operator's. A node's page is woken
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

With an `[oidc]` table, a person signs in through an OIDC provider:

```toml
ui_addr = "0.0.0.0:8444"
ui_url = "https://hub.example.com:8444"

[oidc]
issuer = "https://login.example.com/app/1"
client_id = "vk-hub"
client_secret_file = "/etc/vk-hub/oidc-secret"
```

`issuer`, `client_id` and `client_secret_file` are checked as `vk-registry`'s `[oidc]` is: the
issuer is `https` (or loopback `http`) with no query or fragment, and the provider's discovery
document must name that issuer and only `https` (or loopback `http`) endpoints; the secret
file is read when `vk-hub serve` starts, not through a symlink, at most 4 KiB, trimmed and not
empty, with a warning if others can read it. `[oidc]` needs `ui_addr` and a `ui_url` that is
`https`. Register `<ui_url>/auth/callback` with the provider as the client's redirect URI;
`vk-hub serve` prints it as it starts.

An unknown key in the table is an error. Manage sign-in grants and roles over the admin
socket; the hub stores them in its database:

```
vk-hub accounts grant alice@example.com --role operator
vk-hub accounts grant '*' --role viewer
vk-hub accounts revoke alice@example.com
vk-hub accounts [list]
```

A grant gives an email address a role, taking effect at once; addresses are compared ignoring
ASCII case, and granting one again replaces its role. `*` admits anyone the provider signs in
whom no grant of their own names, with a verified email or not, and only as a viewer. A sign-in
gets its address's grant, else `*`'s; anyone else is refused. Grant `*` only on a provider that
signs in a known population, as anyone it signs in can then sign in at will: a sign-in only `*`
admits is audited within the same bounds as a refusal (below), and one identity holds at most 8
sessions, a sign-in past that ending its oldest. Lowering or revoking a grant ends the open
sessions it covered — for `*`, every session opened through OIDC — that hold more than a
sign-in would now get. `vk-hub accounts` lists every grant with its role, who made it and when.
Grants are audited as the admin socket's peer, `uid <n>`; a hub without `[oidc]` keeps them for
when it has one. `vk-hub serve` warns as it starts when `[oidc]` is set and nothing is granted,
as nobody can sign in yet. Grants name addresses, not a provider: after changing `issuer`,
review `vk-hub accounts` and end the old sessions with `vk-hub ui logout --all`.

The address is the provider's `email` claim from UserInfo, if it is an address and not marked
unverified (`email_verified` false); a provider that says nothing of verification is taken at
its word, as `vk-registry` takes it, so grant by email only with a provider whose `email` claim
users cannot set themselves. Whoever is refused gets a page saying whom they signed in as, and
why when their email is marked unverified. The refusal is audited under that name, at most once
per identity every 10 minutes and 60 times an hour in all, so scripted refusals cannot flood
the audit log; past that, it is logged to stderr only. A signed-out page carries a "Sign in
with <issuer host>" button, as `/login` does without a token. It leads to `/auth/login`, which
sends the browser to the provider with the authorization code flow — `state` in a `__Host-`,
`SameSite=Lax` cookie bound to the browser, PKCE (S256), valid 5 minutes and single-use.
Another site's page may open `/auth/login` only through top-level navigation
(`Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`), so a provider's application portal
can use it as the application's login URL. The callback exchanges the code with the client
secret and reads who signed in from UserInfo; it does not verify an ID token or send a nonce,
as the state cookie and PKCE already bind the code to the browser and this client. It opens
a session as a link does, with the identity — the email, or `sub <subject>` without one —
beside the role. Signing out ends the hub's session alone, not the provider's.

Sign-in links remain available for people the provider cannot sign in.
`vk-hub ui login [--role viewer|operator] [--ttl 10m]` prints a link over the admin socket —
`<ui_url>/login?t=<token>`, for a viewer by default; `vk-hub local` prints one as it starts,
and `vk-hub local login` more, for an operator by default. The token
is single-use, valid 10 minutes by default and at most a day, and stored hashed, like an
enrollment token. Opening the link shows a "Sign in" button, and only the `POST` it makes —
`Sec-Fetch-Site` `same-origin` (the sign-in page itself) or `none` — spends the token, so a
mail scanner or a chat's link preview fetching the link leaves it unused. The post opens a
session: a random secret set as a cookie (`HttpOnly`, `SameSite=Strict`, `Path=/`, and
`Secure` with the `__Host-` prefix over https), kept hashed in the database with its role,
and valid for 12 hours. The page it answers moves on to `/` itself, so the token never stays
in the address bar. `vk-hub ui sessions|logout <id>|--all` (`vk-hub local sessions|logout`)
list and end sessions, each with who issued its link or whom the provider signed in; an ID,
12 hex digits, ends every session that shares it, and one naming none is an error.

Browsers keep cookies apart by host, not by port. On plain http — which the UI serves only
on loopback — the session cookie therefore reaches every other http service on that host,
and any of them can set a cookie of the same name. The hub treats a request carrying two
session cookies as signed in with neither, but cannot stop the cookie being read: when
anything else is served on the machine the UI is used from, give a fleet hub's UI TLS even on
loopback (the hub's own certificate will do). Local mode serves under a name of its own
instead (see [Local mode](#local-mode)).

Every state-changing request is a `POST` from the UI's own origin — its `Origin`, or
`Sec-Fetch-Site: same-origin` — carrying a CSRF token derived from the session's secret, and
is done as the session's principal, `ui session <id> (<role>)`, or `ui session <id> (<role>,
<identity>)` for one opened through OIDC, which is what the audit log records. On a fleet hub
they are signing out, a node's steering actions, a rollout's pause, resume and abort,
uploading and fetching a release, and starting a rollout. Issuing a link, signing in and out,
a refused OIDC sign-in, granting and revoking roles, and ending sessions are audited too.

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
a node restart and a partition (`fleet-enrollment`, `fleet-monitoring`, `fleet-resilience`);
a ceiling, stopping acquisition, drain, quarantine across a node restart, an external
runner's refusals, and a reset that stops a leftover job process and removes its job dir
(`fleet-steering`); hubs and nodes of protocol version 1 beside version 2
(`fleet-mixed-versions`); and updates — a rollback on failed validation, a signature
required, an update surviving a restart, a rollout a node per wave (`fleet-update`). The web
UI and local mode have unit tests only.

`fleet-mixed-versions` needs a `vk` and a `vk-hub` of 0.83.0 or 0.84.0 (`VK_V1`,
`VK_HUB_V1`), and `fleet-update` a `vk` of a higher version, 0.85.0 or later, to update to
(`VK_NEXT`); each skips without them, as both do in CI.

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
  the primary, so a code change rebuilds no image; a guest copies it to `/opt/vk/bin/vk` on
  its first boot and runs that copy, for an update to replace. A test enrolls each node from
  inside its guest with `vk node join`; the service then runs `vk node run`, started again
  on any exit, as a supervisor would, until the hub refuses the node for good. Their roots
  persist, so a node keeps its identity and its installed `vk` across a restart. A test sets
  a node's vk configuration before it boots; a managed runner is a gitlab-runner stand-in
  (`tests/fleet/node/gitlab-runner`), a process that quits on `SIGQUIT` as a runner with no
  jobs left does.

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

### What it does not cover

The suite runs no real gitlab-runner or CI jobs. The stand-in takes no jobs, so drain tests
wait for a runner that is slow to quit, and reset tests use a planted leftover process.
How GitLab spreads jobs over runners is measured on real CI hosts under real load.
