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
| who the daemon is | a `vkk_` key, shared by any number of daemons, told apart by a self-chosen `vk-client-instance` header | a key is a secret, not an identity; rotating it makes a new principal, so the Connections page shows each daemon twice |
| which GitLab, which projects | `vk-hub gitlabs add`, then `keys create --gitlab --projects id:path,…` | three objects the operator keeps consistent by hand with the daemon's `[[runners]] url`; nothing says which projects actually run |
| what the hub may place | the key's pools and largest envelope | a second policy beside the daemon's own placement |
| presence | a hello every minute over HTTP | a poll pretending to be a session |
| registry tokens, project egress rules | jobs of a *bound* key only | an unbound key's jobs silently get no token and only the default egress rule |

Nodes and registries have none of this: one token, one pinned identity, one session.

## Model

- **The enrollment token is the operator's approval of the relay.** `vk-hub token create --kind
  gitlab` issues it (CLI or the Connections page); spending it pins the relay's ed25519 key. From
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
pool = "ci"
labels = ["large-memory"]
envelope = { mem = "16G", cpus = 8, disk = "16G" }
limit = 8
```

```sh
vk-hub token create --kind gitlab | ssh ci-relay-1 vk-gitlab join https://hub.example.com --token - [--ca FILE]
```

`join` creates `<state_dir>/hub/` (`0700`) with the relay's key, the hub's URL, its CA and the
relay ID, as `vk-registry join` does. `vk-gitlab leave` deletes it. A config with a `[hub]`
table, or a runner with a `url` of its own, is refused.

- **The GitLab credential is the runner tokens (`glrt-`), as today.** They take jobs and nothing
  else; `verify` gives each runner's ID. A token that lists a runner's projects or creates
  runners (`manage_runner`, `create_runner`) can also edit runners or take other runners' jobs,
  which a host reading untrusted traces should not hold.
- **Placement stays in the relay's config, and is reported.** A runner's pool, labels and
  envelope go with the tags it was registered with in GitLab, which the relay's operator chose;
  keeping them beside the token keeps one place to change a runner, and the hub needs no
  placement store, import or sync. The hub shows them.

## What the relay reports

The relay dials `GET /v1/gitlab/session` over WebSocket on TLS, with the handshake every peer
shares (`vk-peer`: hello, challenge, auth bound to the TLS connection), then sends
`vk_hub_proto::gitlab`'s messages:

- **inventory**, on connect and when it changes: version, hostname, `system_id`, `concurrent`;
  the GitLab server: its URL, the SHA-256 of its TLS certificate's public key (what the operator
  checks when approving it), and its version when known (a runner token cannot ask GitLab for
  it, so usually absent); per runner its name, GitLab runner ID, placement, `limit`, whether
  `verify` passed. Never a token;
- **heartbeat**: per runner, job requests outstanding, jobs held, last GitLab answer;
- **report**: each runner's state (`polling`, `waiting_capacity`, `server_pending`,
  `unhealthy`, `token_refused`).

The hub binds the relay to the normalized URL of its first inventory, and answers with that
server's **status** (`approved` with its name, `pending`, `rejected`), again whenever it changes.
A relay whose server is not approved does not poll GitLab, so it takes no job the hub would
refuse for its server; the hub refuses its submissions anyway. A relay that later reports
another URL is told `rebound` and refused jobs until re-enrolled (`join --replace`).

**Projects are learned from jobs.** A runner token cannot list the projects a runner serves, so
the relay knows a project only once GitLab gives it one of its jobs, and the hub learns it from
that job's submission. **The first job of a project not yet approved fails** (below). An
operator can approve a project beforehand, by ID and path.

## Jobs

Jobs keep the [client API](gitlab-dispatch.md#daemon--hub-the-client-api): its endpoints, long
polls, idempotency and retries are unchanged. Only authentication changes: instead of a bearer
key, each request is **signed by the relay's key**, as a node signs a release download. Headers
`vk-relay` (its ID), `vk-time` and `vk-signature` carry an ed25519 signature over a new
`client_request_message`: the relay ID, method, path and query, the body's SHA-256, the time, and
the TLS connection's exporter. The hub checks the relay is enrolled and not revoked, the time
within `DOWNLOAD_SKEW_SECS`, and the signature. A signature is good on its own connection only,
so there is no bearer to steal or rotate. vk-gitlab's hub client moves from `reqwest` to
`vk-peer`'s TLS dialing, which exposes the exporter: one connection per request at first, as a
release download does, so a long poll never holds up a renewal; it signs the exact body it
sends, and a retry signs again. Pooling comes later if connection setup shows up. Moving jobs
onto the session instead would rewrite a contract that works, for nothing more.

The relay is the job's principal: jobs, reservations and request IDs belong to its ID. The job's
`{gitlab}` is its server's name, which is what egress rules, Blocked rows, registry namespaces
and job tokens key on. The relay submits `egress: None` as today and receives no egress setting.

**The approval gate.** It applies to every GitLab job submitted. Only a relay submits GitLab
jobs: an API key's are refused. A submission whose request ID the hub has seen is answered
with its first answer before the gate, body digest compared as today, so a relay recovering an accepted job after a restart is not refused
by a later rejection, for as long as the hub keeps request answers (a day). The gate
applies to new submissions only: rejecting or forgetting a server or project leaves its queued
and running jobs alone; an operator cancels them if needed. A job whose `server_url` is not its relay's server, or of a
relay told `rebound`, is 403 `forbidden`; one of a pending server is refused `approval_pending`,
of a rejected one `project_rejected`, as a project's are.

**A job of a project not approved.** The hub records the project as pending (server, ID, path,
first job, relay) and refuses the submission with 403 `approval_pending`; the relay releases its
reservation and fails the job in GitLab as `runner_configuration_error` (through the existing
failure mapper, which falls back to `script_failure` where GitLab does not accept it), its trace
ending with:

```text
ERROR: project acme/web (ID 12) is waiting for approval on the fleet hub https://hub.example.com.
Retry this job once an operator has approved it (Connections > GitLab > Pending).
```

The job is not held: approval is a human step, and GitLab's `retry: when:
runner_system_failure` does not retry this reason, so a pending project does not loop. A
rejected project's jobs fail the same way, with `project_rejected` and a message saying so.
A refused submission retried under the same request ID counts once.

## Approval on the hub

| Item | Becomes pending when | Approve | Effect |
|---|---|---|---|
| GitLab server | a relay reports a URL no server has | give it a name (`{gitlab}`) | its relays start polling |
| project | a job of a project not approved for its server is submitted | by ID; the path is recorded and kept current from jobs | its jobs are accepted from every relay of that server |

- **Where.** A *Pending* section on top of the Connections page's GitLab tab, and its count on
  the Connections link, as the Egress link counts *New* items. Each row says which relay
  reported it and when, and for a project its path, first job and how many jobs failed waiting.
  Rows of one group can be selected together for a bulk approve; no rule such as `acme/**`
  approves projects no one has looked at, at the cost of each new project's first job.
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
Runner keys on the GitLab tab, and the hub's resolution of a job's server from its key. An API
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
3. per daemon: move the runners' URL to `[gitlab] url` and drop the `[hub]` table, which the
   new vk-gitlab refuses, then `vk-hub token create --kind gitlab | vk-gitlab join <hub-url>
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
`/v1/gitlab/session`, `RelayMsg` and `HubRelayMsg`, `PROTOCOL` 1. The crate's rules hold: a
released version is frozen; within it only optional fields are added; a new message or variant
takes a new version; enums read from the wire (runner states, server status) carry an
`#[serde(other)]` fallback. The client API keeps `/v1/` and gains the signature headers and the
`approval_pending` and `project_rejected` codes, which an older client reads as `other`.

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
5. UI: relays and runners on the GitLab tab, *Add relay*, the Pending section and its count,
   the Runner keys gone; land `c5d7f33b`.
