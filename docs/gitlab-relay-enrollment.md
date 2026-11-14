# A GitLab relay that enrolls with the hub (design)

Status: **implemented** (steps 1 to 5 below), in the release after 0.95. Builds on [the fleet
design](fleet-design.md), [GitLab dispatch](gitlab-dispatch.md) and [a registry the hub
manages](registry-hub.md), whose enrollment and session this reuses.

`vk-gitlab` becomes a **relay**: a peer that enrolls with the hub as a node or a registry does,
then says what it is and what it sees. Its identity replaces the hub API key. The hub trusts an
enrolled relay as it trusts a node, and asks an operator only about what is new: a GitLab server
it does not know, a project it has not approved.

## Why the current setup is complex

Essential:

- **GitLab owns the runner.** Tokens, tags and project assignment live in GitLab, and a job it
  handed over cannot be given back, so capacity is held before asking.
- **A job's identity comes through the relay.** Only the relay sees GitLab's job response; the
  project, ref and protection that registry namespaces and egress rules key on are its word.
- **A project ID means nothing without its instance**, so the hub names instances (`{gitlab}`
  in namespaces, `gitlab:<name>:<project>` in egress records).

Accidental: `vk-gitlab` was built as a client of the client API before peers enrolled, and every
later need was hung on its API key:

| Need | Where it went | Why that hurts |
|---|---|---|
| who the daemon is | a `vkk_` key, shared by any number of daemons, told apart by a self-chosen `vk-client-instance` header | a key is a secret, not an identity; rotating it makes a new principal, so the API keys page shows each daemon twice |
| which GitLab, which projects | `vk-hub gitlabs add`, then `keys create --gitlab --projects id:path,…` | three objects the operator keeps consistent by hand with the daemon's `[[runners]] url`; nothing says which projects actually run |
| what the hub may place | the key's pools and largest envelope | a second policy beside the daemon's own placement |
| presence | a hello every minute over HTTP | a poll pretending to be a session |
| registry tokens, project egress rules | jobs of a *bound* key only | an unbound key's jobs silently get no token and only the default egress rule |

Nodes and registries have none of this: one token, one pinned identity, one session.

## Model

- **The enrollment token is the operator's approval of the relay.** `vk-hub token create --kind
  gitlab` issues it (CLI or GitLab › Overview); spending it pins the relay's ed25519 key. From
  then on the relay is trusted like a node: it already holds the runner tokens and sees every
  job's secrets, so a hub-side ceiling on what it claims would protect little. Removing it from
  the page or with `vk-hub relays remove` revokes it; there is no pausing one short of that.
- **What is new is approved on the hub.** A GitLab server not yet known, and a project not yet
  approved for its server, are **pending** until an operator approves them. Approval is per
  server, so it covers every relay of that server. Nothing else needs the operator.
- **One GitLab server per relay**, any number of relays per server. A daemon serving two
  GitLabs today becomes two relays (two services, two state directories).

## Setup

```toml
# /etc/vk-gitlab/config.toml
concurrent = 16
state_dir = "/var/lib/vk-gitlab"

[gitlab]
url = "https://gitlab.example.com"

[[runners]]
name = "ci"
token_file = "/etc/vk-gitlab/runner-ci.token"   # glrt-…
envelope = { mem = "16G", cpus = 8, disk = "16G" }
limit = 8
```

```sh
vk-hub token create --kind gitlab | ssh ci-relay-1 vk-gitlab join https://hub.example.com --token - [--ca FILE]
```

`join` creates `<state_dir>/hub/` (`0700`) with the relay's key, the hub's URL, its CA and the
relay ID, as `vk-registry join` does. `vk-gitlab leave` deletes it. A runner with a `url` of its
own is refused, as is a `[hub]` table naming the hub: the enrollment does. `[hub]` only says
what the hub may do to the relay ([Updates](#updates)).

- **The GitLab credential is the runner tokens (`glrt-`), as today.** They take jobs and nothing
  else; `verify` gives each runner's ID. A token that lists a runner's projects or creates
  runners (`manage_runner`, `create_runner`) can also edit runners or take other runners' jobs,
  which a host reading untrusted traces should not hold.
- **A runner's envelope stays with its token and is reported to the hub.** It corresponds to
  the runner's GitLab tags. Keeping the envelope beside the token gives one place to change
  a runner: the relay's config, or its runner files for a runner
  [added on the hub](#runners-added-on-the-hub). The hub displays the envelope.
  The runner's lane on the hub selects the pools and nodes, giving the operator one place
  to set placement ([capacity arbitration](capacity-arbitration.md)). Relays from before
  0.111 also report a runner pool; those before 0.112 report labels. The hub ignores both.

## What the relay reports

The relay opens `/v1/gitlab/session` as a WebSocket on its HTTP/2 connection to the hub
([One connection to the hub](#one-connection-to-the-hub)), with the handshake every peer
shares (`vk-peer`: hello, challenge, auth bound to the TLS connection), then sends
`vk_hub_proto::gitlab`'s messages:

- **inventory**, on connect and when it changes: version, hostname, `system_id`, `concurrent`;
  the GitLab server: its URL, the SHA-256 of its TLS certificate's public key (what the operator
  checks when approving it), and its version when known (a runner token cannot ask GitLab for
  it, so usually absent); per runner its name, GitLab runner ID, placement, `limit`,
  `request_concurrency` (version 2), whether `verify` passed; the placement is the envelope,
  with a `pool` from a relay below version 6 and `labels` from one before 0.112. Never a token;
- **heartbeat**: per runner, job requests outstanding, jobs held, the admission of each
  (`request_admissions`, `job_admissions`; version 2), last GitLab answer;
- **report**: each runner's state (`polling`, `waiting_capacity`, `server_pending`,
  `unhealthy`, `token_refused`), and the update under way or the last one's end.

The hub binds the relay to the normalized URL of its first inventory, and answers with that
server's **status** (`approved` with its name, `pending`, `rejected`), again whenever it
changes. A relay whose server is not approved does not poll GitLab, so it takes no job the hub
would refuse for its server; the hub refuses its submissions anyway. A relay that later reports
another URL is told `rebound` and refused jobs until re-enrolled (`join --replace`).

**Projects are learned from jobs.** A runner token cannot list the projects a runner serves, so
the relay knows a project only once GitLab gives it one of its jobs, and the hub learns it from
that job's submission. **The first job of a project not yet approved fails** (below). An
operator can approve a project beforehand, by ID and path.

## Runners added on the hub

Status: **design**.

An operator who created a runner in GitLab hands its token to a relay from the hub, rather than
editing the relay's config over SSH. GitLab still creates the runner: the hub keeps no GitLab
credential and calls no GitLab API. The token passes through the hub in memory only; the relay's
runner file is its one stored copy.

**Opt-in.** A relay takes runners from the hub only if its config allows it, as for updates:

```toml
[hub]
allow = ["update", "runners"]
```

Such a relay needs `[gitlab] url` and runs with no runner at all, waiting for one.

**Add.** *Add runner* on a relay's row (GitLab › Overview), or `vk-hub relays runners add <relay>
<name> --token-file FILE [--envelope mem=16G,cpus=8,disk=16G] [--limit N]
[--request-concurrency N]`. The form takes the `glrt-` token, a name, and the settings a
`[[runners]]` table has, with the same defaults. The hub refuses, before sending anything, a
relay that does not allow `runners` or speaks a protocol below 6 (one below it wants a pool
with the runner), and a name it reports.

1. The hub issues an `add_runner` command, as it issues an update. Its record holds the name and
   settings; the token is not part of what is stored, logged or shown, and stays in memory, with
   the command, until the relay answers.
2. The relay checks, under one lock for all runner changes, what the hub's view cannot: `allow`,
   the command's expiry, a name that is safe as a file name and not taken (by the config, a
   runner file, or a runner being removed), and `MAX_RUNNERS`. Then it verifies the token with
   GitLab (`POST /runners/verify`, with its own system ID, as at startup). Verification records
   the relay as a manager of that runner in GitLab, as its first job request would. A runner ID
   this relay already runs is refused: one GitLab runner under two names would share one lane.
3. Verified, it writes `<state_dir>/runners/<name>.toml` (`0600`, written whole and renamed into
   place): the settings, the token, the GitLab runner ID and the command's ID. It starts the
   runner's worker, sends a new inventory, then acks the command done.
4. The hub records the ack, takes the runner's GitLab ID from the inventory entry naming the
   command, audits both, and drops the token.

A relay failing a command answers with a code, never GitLab's text: `token_refused` (GitLab
answered 401 or 403), `gitlab_unreachable` (a transport error or a 5xx; adding again retries),
`name_taken` (also for a name that is not safe as a file name), `runner_taken`,
`too_many_runners`, `not_allowed`, `expired`, and for a removal `runner_gone`. A verify answer
without a positive runner ID is `gitlab_unreachable`. Settings the relay's config would refuse
(the hub checks them first), or a runner file it cannot write, fail `other`.

The relay journals runner commands as it journals updates, without the token: it acks a command
accepted before acting on it, repeats its last ack until the hub records it, and answers a
command sent again from the journal, without verifying again. So a hub restarted mid-add learns
the outcome when the relay reconnects. A relay restarted mid-command ends it from its runner
files: an add done if one names its command, else `gitlab_unreachable`; a removal done if the
file is marked removed or gone, else `other`. Only a command the relay never accepted is lost with the
hub's memory: if the relay's first report after the restart does not show it, it ends failed
`token_lost`, for the operator to add again. Unrecorded relay acks follow that report;
an ack for the command replaces `token_lost`.

**Capacity.** A new runner has no [lane](capacity-arbitration.md), so its jobs are refused until
one maps its GitLab ID. Once the add is done, the page says so and links to adding the lane.

**Remove.** *Remove* on a runner added on the hub, or `vk-hub relays runners remove <relay>
<name>`; a `[[runners]]` table stays the config's. `remove_runner` must match the runner file's
name, GitLab ID and adding command; otherwise it is refused `runner_gone`. This prevents late
or replayed removals from reaching a runner added again under the same name.

Removal marks the runner file removed and stops new job requests. Outstanding requests finish
through submission, as before an update; jobs finish on their job tokens. Once the state file
holds no jobs, the relay deletes both files. Until then the name stays taken, and a restarted
relay loads the file to resume jobs without polling. The runner stays in GitLab, to delete there.

**On the relay.** `vk-gitlab run` loads the config's runners, then `<state_dir>/runners/`. A
runner file that does not parse stops the relay at start, as a config that does not parse does:
its jobs are resumed only with its settings. Runner files written before 0.111 contain a pool,
which is ignored. New files and job records omit it and cannot be read by `vk-gitlab` before
0.111; downgrading a relay holding either stops it at startup. Each runner's inventory
`source` is `config` or `hub` (default `config` for older relays). Hub runners also report the
command that added them, and the hub offers *Remove* for them only. Dropping `runners` from
`allow` keeps existing runners running but refuses further runner commands.

**Hub commands.** Runner commands share updates' table, delivery and `Recorded`.
They do not use updates' recovery for commands absent from the relay's first report.
Release retention and the Updates page's latest command consider `update` commands only.
A session at protocol 3 receives update commands only.

**Audit.** Each add and removal, with the actor, the relay, the runner's name and GitLab ID, and
the outcome; never the token.

**Protocol.** Version 4 raises both ranges' maximum: the `Operation` variants `add_runner` and
`remove_runner`, and the inventory runner's optional `source` and `command`. `Operation` has no
fallback variant, so neither is sent below 4. A failure code rides in the ack's outcome:
`expired` as `expired`, `not_allowed` as `refused`, the others as `failed`, the code its reason
or message. `add_runner`'s token is absent from the JSON of the command as the hub stores it.

**Later.** Editing a runner's settings: requests already taken keep the placement of their
admission, so an edit waits for them to drain as a removal does. Replacing a token after a reset
in GitLab, refused if its runner ID differs. Renewing an expiring token with `POST
/runners/reset_authentication_token`, rewriting the runner file. Until then, a runner is changed
by removing it and adding it again.

**Implementation order.** (1) Proto: the two operations, `source` and `command`, version 4.
(2) vk-gitlab: runner files, loading them beside the config's, a relay with no runner, the
workers started and stopped at run time, the two commands. (3) Hub: the commands with the token
in memory only, reconciliation from the inventory, the CLI, the audit. (4) UI: *Add runner*,
*Remove*, the outcome on the relay's row, the missing lane.

## Updates

A relay whose `[hub] allow` lists `update` is updated to a `vk-gitlab` release the hub holds,
from the hub's Updates page or `vk-hub relays update <id> --release <sha256 prefix>`:

```toml
[hub]
allow = ["update"]
release_keys = ["…"]      # optional: an update must then be signed by one of them
# require_signed = true   # the default once release_keys names a key
# allow_downgrade = false
```

The relay's inventory says whether it allows updates and needs them signed, and the hub refuses
an update the relay would refuse before issuing it. One issued before the relay dropped
`update` from its `allow` is still sent, and refused. A relay or hub from before updates
(relay protocol version 3) is never sent one. Releases reach the hub as a node's do: `vk-hub
release add <file> --program vk-gitlab --version V [--signature FILE]`, signed with `vk
release-key sign --program vk-gitlab`, or `vk-hub release fetch --program vk-gitlab`, or the
Updates page's upload and fetch. `vk-hub relays show <id>` lists the commands issued to a relay
and how each ended.

An update runs on trial, as a registry's does:

1. the relay downloads the release from `/v1/gitlab/releases/<sha256>` under its own
   signature, and checks its digest, size, signature (against its `[hub] release_keys`) and
   `--version`;
2. it keeps its running binary beside the release under `<state_dir>/hub/releases/`;
3. it stops asking GitLab for jobs and waits for the job requests out to end and the jobs they
   brought to be in the state files. Past ten minutes it goes on all the same, as a restart
   would: a job GitLab hands to a request cut short then waits for GitLab's stuck-job timeout;
4. it executes the release in its place. Running jobs are not stopped: the release resumes them
   from the state files, as after any restart, their logs picking up where GitLab has them;
5. the release, once in session with the hub, installs itself over the installed binary by
   rename and reports the update done.

A release has two minutes to reach the hub. One that crashes is started again by the
supervisor, through the previous binary, at most three starts in all; one that hangs is ended
by its alarm a minute past that deadline. Past three starts or the deadline, the previous
binary takes the relay back and reports the update rolled back. A release that reached the hub
records so before it installs itself, and a relay stopped in between finishes the install on
its next start. So `vk-gitlab run` needs a supervisor that restarts it (`Restart=always` under
systemd), from a binary in a directory its user can write. A relay stopping on SIGTERM or
SIGINT takes no update, and one stopping during an update does not execute the release.

A vk-gitlab from before updates cannot confirm a trial, so with `allow_downgrade` an update to
one is always rolled back.

## Jobs

Jobs keep the [client API](gitlab-dispatch.md#daemon--hub-the-client-api): its endpoints,
idempotency and retries. Only authentication and transport change: instead of a bearer key,
the relay's requests ride its [one connection to the hub](#one-connection-to-the-hub), which
its session authenticates with the relay's key. There is no bearer to steal or rotate. A relay
at protocol 2 to 4, released before that connection, **signs** each request instead, on
HTTP/1.1: headers `vk-relay` (its ID), `vk-time` and `vk-signature` carry an ed25519 signature
over `client_request_message` (the relay ID, method, path and query, the body's SHA-256, the
time, and the TLS connection's exporter), which the hub checks against the enrolled relay, the
time within `DOWNLOAD_SKEW_SECS`. Moving jobs onto the session would replace a working
contract without another benefit.

The relay is the job's principal: jobs, reservations and request IDs belong to its ID. The job's
`{gitlab}` is its server's name, which is what egress rules, Blocked rows, registry namespaces
and job tokens key on. The relay submits `egress: None` as today and receives no egress setting.

**The approval gate.** It applies to every GitLab job submitted. Only a relay submits GitLab
jobs: an API key's are refused. A submission whose request ID the hub has seen is answered with
its first answer before the gate, body digest compared as today, so a relay recovering an
accepted job after a restart is not refused by a later rejection, for as long as the hub keeps
request answers (a day). The gate applies to new submissions only: rejecting or forgetting a
server or project leaves its queued and running jobs alone; an operator cancels them if needed.
A job whose `server_url` is not its relay's server, or of a relay told `rebound`, is 403
`forbidden`; one of a pending server is refused `approval_pending`, of a rejected one
`project_rejected`, as a project's are.

**A job of a project not approved.** The hub records the project as pending (server, ID, path,
first job, relay) and refuses the submission with 403 `approval_pending`; the relay releases its
reservation and fails the job in GitLab as `runner_configuration_error` (through the existing
failure mapper, which falls back to `script_failure` where GitLab does not accept it), its trace
ending with:

```text
ERROR: project acme/web (ID 12) is waiting for approval on the fleet hub: https://hub.example.com:8444/gitlab/main/projects/12
Retry this job once an operator has approved it there.
```

The refusal's `approval_url` links to the project's page on the hub's web UI. Older hubs and
hubs without a UI omit it; the trace uses the enrolled hub URL with "(GitLab > Pending)"
([gitlab-dispatch.md](gitlab-dispatch.md)).

The job is not held: approval is a human step, and GitLab's `retry: when:
runner_system_failure` does not retry this reason, so a pending project does not loop. A
rejected project's jobs fail the same way, with `project_rejected` and a message saying so.
A refused submission retried under the same request ID counts once.

## One connection to the hub

Status: **implemented**, relay protocol version 5.

A relay holds **one HTTP/2 connection** to the hub. Its session is a stream of it, and its
client API requests are the others. The hub **pushes** small notices over the session when a
ticket or a job of the relay changes, and the relay **fetches** what changed with plain requests
on the same connection. Nothing long-polls. Nodes and registries keep their HTTP/1.1 WebSocket
sessions.

**HTTP/2 for relays only.** The hub's listener offers ALPN `vk-relay/1` and `http/1.1`,
never `h2`. `vk-relay/1` is a private protocol ID that means HTTP/2, and the hub serves it
as HTTP/2. Only vk-gitlab offers it, so curl and other API-key clients stay on HTTP/1.1.

**The session.** The relay dials the hub's listener over TLS 1.3, offering ALPN `vk-relay/1` and
`http/1.1`, and opens `/v1/gitlab/session` as a WebSocket over HTTP/2 (RFC 8441): `CONNECT` with
`:protocol` `websocket` and `sec-websocket-version: 13`, answered 200. The hub's HTTP/2 server
enables the extended CONNECT (hyper's `enable_connect_protocol`); the stream is then the
`Upgraded` an HTTP/1.1 upgrade gives, so `vk-peer`'s handshake (hello, challenge, auth signed
over the connection's TLS exporter, welcome) and `relays::run` are those of an HTTP/1.1 session.
On a plain-HTTP loopback listener, which has no ALPN, the hub tells HTTP/2 from HTTP/1.1 by the
client's connection preface (h2c with prior knowledge). There the auth is `Channel::Plaintext`,
as on HTTP/1.1.

**The session authenticates the connection.** Before the welcome, the hub marks the
connection as the relay's, under the relay's ID and the session's number. From then on it
serves the client API on that connection as that relay, while the session is current
(`Hub::is_current`). A request **carries no signature**: no `vk-relay`, `vk-time` or
`vk-signature`, no body digest. The per-request signature bound a request to the relay key and
the TLS connection; the session's auth binds the same key to the same exporter once, and TLS
1.3 lets only the holder of that connection's traffic keys send on it. A TLS-terminating
proxy breaks the auth exactly as it broke the signatures, and a hub with a stolen certificate
key gets neither: the exporters on its two sides differ. Signing each request again adds
nothing against the [trust model](trust-model.md)'s attackers, and costs a body hash, a
signature, and a dependency on the relay's clock (`DOWNLOAD_SKEW_SECS`). The connection lives
as long as its session. When the session ends (lost, superseded, removed or handed over),
the hub stops new requests on the connection with 503 `unavailable` and sends GOAWAY. Requests
already accepted still finish. The relay dials a new connection and session, then sends
any unanswered request again. Every client API request is idempotent.

**What the hub pushes.** Version 5 adds two `HubRelayMsg`s. Each names an object and
carries no data:

- `ticket {ticket}`: a ticket of the relay was granted or ended (refused, cancelled, its grant
  unclaimed past the lease). It replaces the ticket's long poll
  (`GET /v1/reservations/tickets/<id>?wait=`).
- `job {job, revision, output_len}`: an unsettled job of the relay has a new `revision`
  (state, node, stage, cancel, result) or more output. It replaces the job view's and output's
  long polls, and covers what the relay waits for on a job: its placement, a cancel
  issued on the hub, its end, which a settle refused 409 waits for, and its output up to
  `output_len`.

The other long polls have no notice. Capacity (`POST /v1/capacity`) is not asked by vk-gitlab; a
claimed reservation that is lost is still found by its renewal's 410, within `lease_secs / 3`.
The relay fetches over the connection with the client API's requests, without `wait`: a ticket's
`GET` (201 grant, 202 queued, 410 gone), the job's `GET` and its output from an offset. On a
session connection the hub refuses a request carrying `wait` (or a capacity request's
`wait_secs`) with 400 `invalid`, the client API's code for a bad request. So each stream is
short, and a relay bug shows at once instead of holding streams. A grant is fetched rather than
pushed so that the relay still counts its lease from when it sent the request that brought it
([Admission and reservations](gitlab-dispatch.md#admission-and-reservations)). Counting from
before the wait would charge the wait for the notice against the lease, so the `Reservation` a
fetch returns carries the instant that fetch was sent, and the poll loop counts from that.

The hub builds notices by diffing, not by queueing events. Its source is the dispatch state the
long polls follow, which already signals each change: the principal's tickets with their phase,
and its unsettled jobs with their `(revision, output_len)`, from the live jobs, the finished ones
not yet written, and a **record** of the finished ones whose final row is written and which
memory no longer holds. The write that drops a finished job from memory adds it to the record;
its settlement, expiry (`JOB_KEEP`) or trim from the history removes it. Tickets leave it when
collected (below). A job finished and written before the hub started needs no entry: nothing changes it
until its relay, which fetches it on its new session, settles it. Each session keeps what it
last told per object. On a change of the dispatch state, coalesced over 50 ms, it sends one
notice per object that moved: a ticket granted or ended (one gone from the state ended too; one
the relay claimed is not told), a job at a new revision or output length. It forgets any entry
whose object left the state. Several changes made while a send is pending collapse into one
notice, so the notices outstanding never exceed the relay's tickets (at most 256 live, and those
ended still retained) and its unsettled jobs. A send is bounded by the heartbeat, as the ping
is. A relay that does not read ends its session.

**Ordering, duplicates, misses.** The hub reads a notice's values from the dispatch state before
sending it. A fetch issued after the relay receives the notice is served from that state or a
later one, so it sees at least the revision and output length the notice named. A notice can
come before the answer that tells the relay about its object: a grant before `POST
/v1/reservations` has answered with the ticket, or a revision before `POST /v1/jobs` has
answered. So the relay keeps the latest notice per ID in a table, as a `watch` keeps its value,
and a waiter compares against the table rather than waiting for the next notice. A waiter
fetches once when it starts following an object, which a notice may not cover (a job finished
before the hub started), and keeps the output length each answer reports, so it reads on at once
while more is there. An entry goes when its ticket ends or its job is settled. An entry for an
ID nothing claims within two minutes goes too. A duplicate notice costs at most one fetch: the
relay fetches only past the revision and offset it holds. Notices are lost only with the
session. The relay therefore takes a new session as one notice about everything it follows. Each
waiter fetches once on the new connection: a job's view and its output from its offset, and a
ticket, which answers 410 because its session ended (below). The new session's first diff starts
from nothing, so it tells every object anew, harmlessly. As a backstop against a bug in the
notices, a waiter that hears nothing for `MAX_WAIT_SECS` (60 s) fetches anyway, the long poll's
timeout without its held stream.

**Tickets end with their session.** A ticket belongs to the session of the connection that
queued it, not to whichever session is current when the request runs: a request accepted just
before a reconnect would otherwise bind its ticket to the new session. The queue and the claim
take the connection's session number. Under the dispatch lock, which `relay_disconnected` also
takes, they refuse with 503 `unavailable` a session that is no longer current. So a ticket
either exists before `relay_disconnected` ends its session's tickets or is never created. A
waiting, offered or granted ticket of a version-5 session is not polled, so `TICKET_IDLE` does
not expire it: it ends with its session or by its own lease. Ended tickets are still collected:
idle expiry and eviction past `MAX_RETAINED_TICKETS` apply to them. Claimed admissions outlive
the session, and the next session's first heartbeat reconciles them.

**Restarts.** *Hub handover*: when the gate closes, the hub closes every relay session with
a WebSocket close, so that the connections drain: an HTTP/2 connection lives as long as its
streams, and the session's stream would otherwise hold it for the whole `GRACE`. Fetches are
short, so the connections end well within it. The relay redials into the listener's backlog,
and the release accepts it. Its first heartbeat reconciles claims. Tickets granted but not
claimed were in memory only and are lost. The relay queues again on its
fetch's 410. *Hub restart*: the same, after the relay's session backoff. *Relay restart*:
the state files list the relay's jobs, and each resumes with a fetch once the
session is up. The new incarnation's session gets the notices for every unsettled job of the
relay ID, including those the old incarnation submitted.

**Flow control.** The session must not starve behind bulk bodies, in either direction. The relay
bounds both directions: at most 4 output reads in flight, and at most 4 submissions, the only
large request bodies (a spec of up to 512 KiB). Small requests are not bounded. From hub to
relay, only output reads are large: at most `MAX_OUTPUT_READ` (1 MiB). The relay reads every
answer whole as it arrives, already bounded by `MAX_ANSWER`, before writing anything to GitLab.
So a slow trace patch never holds the window, and 4 MiB in flight stays within hyper's client
connection window (5 MiB). From relay to hub, the hub reads each request body whole before
handling it, and its connection window is raised from hyper's 1 MiB to 4 MiB, enough for the 4
submissions. Both windows therefore keep room for the session's stream whatever the bulk traffic
does. The stream still shares the link's bandwidth: on a slow link a notice or heartbeat may
wait behind up to 4 MiB in flight. The heartbeat's silence limit (`MISSED_HEARTBEATS`) must
absorb that, which a test saturating a throttled link checks. `MAX_CLIENT_STREAMS` (512) stays
per connection. Without long polls, a relay keeps far fewer requests in flight than that.

**Before the session: limits.** An HTTP/2 connection whose session is not up yet is
unauthenticated. It holds one of `MAX_PRE_AUTH` connection permits, and it must be
authenticated within `3 * PRE_AUTH_TIMEOUT`, as an HTTP/1.1 one must be, or it is closed. It
serves the session's `CONNECT`, which takes a handshake permit with each step bounded by
`HANDSHAKE_STEP` as on HTTP/1.1, and nothing else: any other request is refused 403 `forbidden`.
A second `CONNECT` on a connection that has had one is refused too: one session per
connection. Once its session is up, a connection serves that relay's requests alone.
Anything else, such as a bearer key or a signature, is refused 403 `forbidden`. hyper's
bounds on header lists (`MAX_H2_HEADER_LIST`) and on reset streams (rapid reset) stay.

**Off the connection.** Enrollment and release downloads stay on HTTP/1.1 connections of their
own: `join` is one call, and a release would compete with the session for the window. `vk-peer`
dials them with HTTP/1.1-only TLS.

**Compatibility.** The hub speaks `PROTOCOL` 1 to 5, and the transport decides which of these a
relay's session gets. On HTTP/1.1 the hub's challenge offers 1 to 4. The relay's signed client
API on HTTP/1.1, with its long polls and `TICKET_IDLE`, is unchanged for relays at 2 to 4. On
HTTP/2 the challenge offers 5 only, so the hub never pushes notices to a relay that cannot read
them and never serves unsigned requests to one that did not authenticate the connection. The
relay speaks `RELAY_PROTOCOL` 5 only and **refuses an older hub** instead of falling back.
Falling back would keep the signed client, its HTTP/1.1 connections and every long poll alive in
the relay for a configuration the upgrade order already excludes: hub first, then relays. A hub
that negotiates `http/1.1` (every hub before this one), or whose SETTINGS do not enable the
extended CONNECT, is refused as outdated, as a hub refusing version 5 is. The relay logs that
the hub must be upgraded, asks GitLab for no jobs, and redials at the longest backoff. Its held
jobs wait. An update that an older hub pushes to such a release never reaches the session, so
its trial rolls back to the previous binary. The relay dials once per session, not per
request.

## Approval on the hub

| Item | Becomes pending when | Approve | Effect |
|---|---|---|---|
| GitLab server | a relay reports a URL no server has | give it a name (`{gitlab}`) | its relays start polling |
| project | a job of a project not approved for its server is submitted | by ID; the path is recorded and kept current from jobs | its jobs are accepted from every relay of that server |

- **Where.** A *Pending* section on top of the GitLab pages, and its count on
  the GitLab link, as the Egress link counts *New* items. Each row says which relay
  reported it and when, and for a project its path, first job and how many jobs failed waiting.
  Rows of one group can be selected together for a bulk approve; no rule such as `acme/**`
  approves projects no one has looked at, at the cost of each new project's first job.
  Approved projects are listed below the servers, and each project has a page of its own.
- **CLI.** `vk-hub gitlabs pending`, `gitlabs approve <url> --name <name>`, `gitlabs projects
  approve <gitlab> <id>[:<path>] …`, `reject`, `forget`. `gitlabs add <name> <url>` and
  `projects approve` also work before anything is pending.
- **Reject** keeps the item and refuses its jobs, without listing it as pending again; it can be
  approved later. **Forget** deletes it: a project's next job makes it pending again, and a
  forgotten server is pending again at once if a relay still reports it. Removing a server,
  refused while relays are bound to it, forgets its projects. An approved server is not
  rejected: its relays are removed, then the server.
- **Audit.** Every approval, rejection and forget, with the actor.

## Migration from 0.95

A breaking release: no coexistence. vk-gitlab runs only as an enrolled relay, and GitLab-bound
API keys go — `keys create --gitlab`/`--projects`, the key's binding and project ceiling, the
Runner keys on the GitLab page, and the hub's resolution of a job's server from its key. An API
key's GitLab jobs are refused.

The hub converts once, at its first start, so no operator state is lost: every server it knows
stays, approved under its name, so namespaces, egress records, mutes, Observed traffic, Blocked
rows and token `pipeline` claims are unchanged; per server, every project a bound key lists and
every project its retained job history names is approved; the bound keys are revoked and
removed, with their client instances. All of it is audited as the hub's; a hub with no bound key
left converts nothing. Projects older than the history, or run only through unbound keys, go
pending at their next job, or are approved beforehand with `gitlabs projects approve`.

vk-gitlab's state file records the relay its jobs were submitted as, `run` refuses records of
another, and `join`, `join --replace` and `leave` refuse while records remain; a 0.95 state
file is refused the same way. Upgrading is **drain, upgrade, enroll, start**:

1. stop each vk-gitlab with SIGTERM and let it drain, until its state files are empty;
2. upgrade the hub and vk-gitlab;
3. per daemon: move the runners' URL to `[gitlab] url` and drop the `[hub]` table's URL and
   keys, which the new vk-gitlab refuses, then `vk-hub token create --kind gitlab | vk-gitlab join <hub-url>
   --token -`, and start it.

`/v1/clients` and `vk-client-instance` stay for the API keys of other clients.

## What survives of `gitlab-keys-ui`

| Commit | Fate |
|---|---|
| `c5d7f33b` add and remove GitLab servers | survives: adding pre-approves a server; the removal guard moves from bound keys to bound relays. Land it |
| `8abfff87` create runner keys | dropped: an *Add relay* button issuing an enrollment token replaces the key form and its policy fields |
| `00d56a06` Replace link | dropped: re-keying is `join --replace` with a new token, then removing the old relay |

## Protocol

`vk_hub_proto::gitlab`: enrollment at `/v1/gitlab/enroll` (its own table of pinned keys and a
token of kind `gitlab`, so no other peer's token enrolls a relay), the session at
`/v1/gitlab/session`, `RelayMsg` and `HubRelayMsg`. The hub speaks `PROTOCOL` 1 to 5, a relay
`RELAY_PROTOCOL` 5 only. Version 2 adds each runner's `request_concurrency` to the inventory
and `request_admissions` and `job_admissions` to its heartbeat load; the hub takes new work only
from a relay at version 2 or later, and serves a version-1 relay only to settle the jobs it
holds: replayed submissions, output, cancel and settle. A hub at version 1 refuses a version-2
relay, which takes no jobs and redials until the hub is upgraded, so the hub is upgraded first.
The crate's rules hold: a released version is frozen; within it only optional fields are added;
a new message or variant takes a new version; enums read from the wire (runner states, server
status) carry an `#[serde(other)]` fallback. The client API keeps `/v1/` and gains the signature
headers and the `approval_pending` and `project_rejected` codes, which an older client reads as
`other`. Version 3 adds updates: `command`, `ack` and `recorded`, sent only in a session at
version 3, and the inventory's `allow` and `requires_signed` and the report's `update`, optional
fields a version-2 peer ignores, so either side meets an older other at version 2, without
updates. Version 4 adds [runners added on the hub](#runners-added-on-the-hub). Version 5 is
[one connection to the hub](#one-connection-to-the-hub), with the `ticket` and `job` notices:
the hub offers it on a relay's HTTP/2 connection alone, and 1 to 4 on HTTP/1.1, where
released relays sign their requests. A relay at 5 refuses an older hub, so the hub is upgraded
first.

## Implementation order

1. Proto: the `gitlab` module, `client_request_message`, the two error codes; JSON and signed
   bytes pinned by tests.
2. Hub: `TokenKind::Gitlab`, the relays table, enroll and session, inventory stored, server
   status; `vk-hub relays list|show|remove`, servers pending and approved.
3. Hub: signed requests as a principal on the client API; the approval gate for every GitLab
   job, after the request-ID lookup; projects pending, approved and rejected; the migration;
   registry token minting and egress resolution taking the server from the relay; removal of
   GitLab-bound keys.
4. vk-gitlab: `join`, `leave`, the session, the signed hub client, the relay as the principal
   in state files, failing a job refused for approval; removal of its API key.
5. UI: relays and runners on the GitLab pages, *Add relay*, the Pending section and its count,
   the Runner keys gone; land `c5d7f33b`.
