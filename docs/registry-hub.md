# A registry the hub manages (design)

Status: **in progress**. Implemented: migration steps 1 (registration and monitoring), 2 in
part (gc schedule and windows, read-only, the `gc` command; not WebDAV steering, nor the
`delete-tag` and `delete-repo` commands) and 3 in part (an update on trial to a release the hub
holds, one registry at a time; rollouts do not cover registries yet) and 4 in part (namespaces
and job tokens, 4a and 4b; see [its own section](#step-4-namespaces-and-job-tokens)). The rest
is proposed. Builds on [the fleet design](fleet-design.md).

A `vk-registry` enrolls with the hub as a node does and keeps a session open for monitoring
and control. In **managed** mode it keeps no database: besides content it stores only its enrollment and a
cache of what the hub sent, and every identity, key, scope, caption and policy comes from the
hub.

## Goals

- **One place to operate the fleet.** A registry's health, usage, gc and version show on the
  hub beside its nodes, and are changed there, with the same audit log and roles.
- **One identity layer.** People sign in once, on the hub; an API key is issued once, on the
  hub; a job's registry access is the hub's decision. `fleet-design.md` already wants the hub
  and the registry to share identities; this makes the hub the owner.
- **A registry is content and nothing else.** Losing its disk loses blobs, which a rebuild
  or a re-push restores. Nothing on it is the only copy of a decision.
- **Jobs are isolated by the hub.** The registry is one deduplicated store holding
  compartmented references. Which projects and refs may read, write or lock under which
  namespace is the hub's policy; the registry enforces the result and knows nothing of
  projects.
- **No trust in the hub beyond what the registry's config grants.** With hub tokens off,
  every registry request a job causes, the guest's through the credential proxy included,
  carries the node's own `[registry]` credential, and a job's `registry_credentials` from
  GitLab only mask its output. With hub tokens on, the hub mints each placed job a scoped
  token beside the registry's own credentials; in managed mode it issues every one. The
  registry's operator opts into either in its config; every other operation is typed and
  bounded by the registry's own config.

Out of scope: replicas, or a registry serving several hubs. Which content is trusted, and who
may sign it, belongs to [the trust model](trust-model.md): a namespace's write grant never
makes an image trusted.

## Modes

`mode` keeps its two values and gains a third. Configuration still rejects settings of another
mode, so a registry cannot end up half-managed.

| Mode | Who authenticates | State besides content |
|---|---|---|
| `shared-secret` | one token or one Basic pair | none |
| `accounts` | OIDC sessions, `vkr_` API keys, admins on the socket | `accounts/accounts.db` |
| `managed` | the hub: its tokens, and keys and sessions it vouches for | the enrollment, and a cache of what the hub sent |

`managed` replaces `accounts` for a registry in a fleet; `accounts` stays for one operated
on its own. `shared-secret` stays for local use.

## Enrollment

Same shape as a node's, so the hub's token issuance, pinning and audit are reused:

```sh
vk-hub token create --kind registry | ssh reg-1 vk-registry join https://hub.example.com --token -
```

- `join` generates an ed25519 identity under `<root>/hub/`, signs the token with it, and
  sends its hostname, for display only.
- Its public URL, which tokens and sign-in need, is not the registry's to claim: the operator
  binds it to the token (`vk-hub token create --kind registry --url
  https://reg-1.example.com`), and the hub refuses a URL another registry holds. Both come
  with hub tokens (migration step 4).
- The hub pins the key and answers with the registry's ID, which tokens name as `aud`. The
  registry gets the hub's **token-signing public keys** (several, for rotation) over the
  authenticated session, not at enrollment: they are what it checks tokens against, and a
  later change arrives the same way, signed by a key it already trusts.
- A token is issued for one kind. A node token cannot enroll a registry, nor the reverse, so
  the hub never mistakes one for the other.
- `vk-hub registries remove <id>` revokes the key and ends the session. `join --replace`
  re-enrolls, keeping the old identity aside as `vk node join --replace` does.

## Session

The registry dials the hub over WebSocket on TLS, as nodes do: it needs no inbound port
for control, and the hub never reaches into it. The handshake is the node's: version ranges,
a signature over the hub's challenge bound to the TLS connection, an incarnation ID. The
messages are their own (`RegistryMsg`, `HubRegistryMsg` in `vk-hub-proto`), since a registry
has no jobs, runner or admission.

**Registry → hub**

- inventory, when it changes: version, listen address and TLS, mode, WebDAV, upstreams, store
  filesystem and size, a hash of its effective config, what `[hub] allow` lists and whether
  updates must be signed; later, as an optional field, TLS certificate expiry;
- a report, when it changes: the desired state it applied and what it refused, its gc
  schedule and last gc, the update under way;
- a heartbeat every few seconds: connections against `max_connections`, uploads in flight,
  locks held, the store's free space; later, as optional fields, requests and bytes in and
  out and relay traffic to upstreams;
- usage, every few minutes: `vk-registry status`'s figures (stored and referenced bytes, per
  repository tags and size; stage data later, as an optional field);
- outcomes: each command's result, until the hub acknowledges it; the last gc's rides in the
  report.

**Hub → registry**

- desired state, with a generation: the registry applies the newest one, and again after a
  restart, as nodes do:
  - retention and grace windows, and when gc runs (a schedule, or never); later (step 4),
    a retention per namespace prefix, within what the registry's config allows, sent only
    to a registry whose `[hub] allow` lists `gc`, which takes it only then;
  - whether writes are accepted (read-only for maintenance: a client's pushes, uploads and
    deletions are refused, but the pull-through relay still caches what a read fetches);
    later, whether WebDAV is on;
  - the token-signing keys, the revocation list, and the key table (see below);
  - each repository's caption;
- commands, journaled before they run so each runs at most once, with an ID and an expiry:
  - `gc [--dry-run]`; later (step 2), `delete-tag` and `delete-repo`;
  - `update` to a release, run on trial and rolled back as a node's is. As for a node, that
    needs `vk-registry serve` under a supervisor that restarts it (systemd, say): a release
    that cannot reach the hub in time is ended by its alarm, and only a restart brings the
    previous binary back to roll it back.

The registry's config controls the listener, TLS, store root, upstreams and connection
limits. The hub only narrows what the config allows. The config lists what the hub may set
or send (`[hub] allow = ["read-only", "gc", "update"]`;
`delete-tag` and `delete-repo`, not implemented yet, are to be listed the same way); anything
else is refused. gc deletes
too, since retention decides when an idle tag stops being a root: the hub refuses a retention
or grace of 0 days, and the registry keeps floors of its own (`[hub] min_retention_days`,
default 7, and `min_grace_days`, default 1) that the hub's windows may lengthen, never
shorten. These floors bound the store-wide window only: a manifest annotated with its own
retention or expiry is outside them, since any account with push rights sets those.

**Losing the hub does not stop the registry.** It keeps serving content, checking tokens
against the keys it pinned and the key table and revocation list it last received, and runs gc
on the schedule it last applied. What stops is new sign-ins and new tokens, which come from the
hub (see *Availability*).

## Authentication without a database

### Machines and jobs: hub-issued tokens

The registry becomes an OCI resource server: an unauthenticated request gets the standard
challenge

```text
WWW-Authenticate: Bearer realm="https://hub.example.com/v1/registry/token",service="9c2f4e1a7b3d5e60f1a2b3c4d5e6f708",scope="repository:d/wab-master/build-cache:pull,push"
```

and the client asks the hub's token endpoint for a short-lived token, presenting what it
holds and sending `service` back, which becomes the token's `aud`. This is the Docker/OCI
token flow: `oci-client`, `docker`, `podman`, `skopeo` and `crane` follow it as they are.
vk's own clients do not: the raw-HTTP requests in `vk-driver/src/registry.rs` (among them
`push_blob_zstd`, `detect_transparent_zstd`'s `/v2/` probe, `exists_batch`), the lock client
(`vk-registry/src/client.rs`) and the guest credential proxy (`vk-driver/src/regproxy.rs`)
send a static Basic or bearer credential and must learn to fetch and renew a token, and a
node signing its token request is new code on both sides.

| Client | Presents to the hub | Gets |
|---|---|---|
| a placed job | nothing: its node gets the job's token with the job; the guest reaches the registry through the credential proxy, which injects that token, never the node's own | the job's namespaces, until the job's timeout plus a margin (see [step 4](#step-4-namespaces-and-job-tokens)) |
| a node outside a job (`vk build` warm-up, image pulls) | its node identity, signing the request | the node's scopes, 1 hour |
| automation (task-rs outside the fleet, release scripts) | a hub API key, as Basic | the key's scopes, 15 minutes |
| a person's CLI (`docker login`, `vk registry push`) | a hub session token (`vk hub login`, proposed in `fleet-design.md`) | the person's scopes, 15 minutes |

The registry checks each token locally: signature against the pinned keys, `aud` is its own
registry ID, `exp` with a small skew, `jti` not in the revocation list, and the requested
action against the scopes. No request waits on the hub.

### Keys presented directly

Some clients cannot follow the token flow: an `sccache` on `/dav/files/`, `curl`. For them the
hub sends a **key table** in desired state: per hub API key allowed to talk to this registry,
`sha256(secret)`, owner, name, scopes and expiry, no secret. The registry checks a bearer or Basic key
against it in memory, as `accounts.db`'s `api_keys` does today. It is a cache of the hub's
state, written atomically as one file, read at start, and replaced wholesale by the next
generation: nothing the registry writes, nothing to back up.

### People in the browser

The registry keeps its UI — `/browse`, `/upload`, `/settings/keys` — and serves it itself.
In `accounts` mode nothing changes. In `managed` mode only signing in moves to the hub:

1. an unauthenticated browser request redirects to the hub's
   `/registry/login?registry=9c2f4e1a7b3d5e60f1a2b3c4d5e6f708`;
2. the hub signs the person in with its own OIDC session, and redirects back with a one-time,
   one-minute token for this registry naming the user and their scopes;
3. the registry turns it into a session cookie it signs itself: an HMAC over user, scopes and
   expiry, under a key held in memory and regenerated at each start.

Sessions need no table: a restart signs everyone out, logout clears the cookie, and the
revocation list carries users to cut off before their cookie expires. `/settings/keys` lists
the person's hub keys for this registry, which the key table's entries name by owner, and
links to the hub to create or revoke one.

### Scopes

One rule set, on the hub: a person's grants, an API key's scopes, a job's namespaces. The
registry enforces them, now for every credential; it never decides who gets which.

Credentials that exist today keep their semantics: an API key's scope is still an exact
repository or an explicit `prefix/*` subtree, and `write` implies `read`. A hub token
carries prefix grants instead, cut at a path component as `prefix/*` is: `images` covers
`images/app` but not `images2`. A prefix grant covers every kind of reference under its
prefix alike: repositories, plain files under `/dav/files/` (as `files/<dir>`, as today),
and locks and failure memos, whose names take the form `<prefix>:<key>` (see
[step 4](#step-4-namespaces-and-job-tokens)). Converting existing keys to prefix grants, if
ever, belongs to the import into managed mode.

Today any authenticated principal may use the lock API on any name; a token principal may
lock only under a prefix it holds `lock` on. The registry challenges a lock request with
`scope="registry:lock:<prefix>"`, and a client asks for that scope. The hub grants it in job
tokens from their namespaces, in node tokens, in tokens minted for an API key given `lock`
(automation takes locks), and in the key table for such keys.

A browser session lasts eight hours from sign-in, as today's do, and keeps the scopes it was
signed in with: a grant changed on the hub applies at the next sign-in, and only the
revocation list ends a session sooner.

That closes the gap `fleet-design.md` names: today every authenticated session reads every
repository. Under the hub, a person's scopes are their grants, so a submitted job's image check
means something.

## What moves where

| Today (`accounts`) | Managed |
|---|---|
| `users` | the hub's users, from its OIDC sign-in |
| `sessions` | stateless signed cookies |
| `api_keys` | hub API keys, sent as the key table; `vkr_` keys imported once (see below) |
| admins, on the Unix socket | hub roles: operator for gc, read-only, captions and enrollment tokens (the Registries page issues one), admin for deletions and updates |
| `repo_captions` | the hub's, sent in desired state |
| `vk-registry gc` by cron | gc scheduled in desired state, its reports on the hub |
| failure memos and locks | unchanged for now: in memory on the registry, under the `lock` grant. They move to the hub later, as a step of their own after managed mode |

Hub keys must support `vkr_` keys. `vk-hub/src/store/keys.rs` knows only the `jobs` and
`capacity` scopes, with no repository globs. A key records its creator but has no owning
user, which a person's key needs. Its lifetime is capped at a year (`MAX_KEY_TTL`), while
a `vkr_` key may never expire: import must cap their lifetime or lift the cap for imported
keys. The hub keeps at most 256 keys, revoked ones included (`MAX_KEYS`).
`Db::api_key` accepts only keys starting `vkk_`, so a `vkr_` key would never match.

The admin socket goes: it serves accounts only, beside `accounts.db`. On the host,
`vk-registry status` and `vk-registry gc` keep working, since they open the store directly.
Leaving managed mode, when the hub is gone for good, is a config change back to
`mode = "accounts"` on the archived `accounts.db`; `vk-registry leave` forgets the hub. That
db is as of the import: users, keys and captions created on the hub since are not in it.

## On the hub

- A **Registries** page beside Nodes: state, version, disk, traffic, usage per repository,
  last gc and its report, steering (schedule, windows, read-only), commands.
- `vk-hub registries` (the list), `vk-hub registries show|remove`, `vk-hub registries
  read-only|gc-schedule|gc|update`.
- Rollouts cover registries: `vk-hub release` holds `vk-registry` binaries as it holds `vk`,
  signed by the same off-hub key (`vk release-key sign --program vk-registry`). A registry
  whose `[hub] release_keys` names any key requires a signature by one of them (unless
  `require_signed = false`); one that names none takes unsigned releases. It
  refuses a downgrade unless its config allows it.
- Nodes' `[build] cache_registry` can name a registry by ID; the hub turns it into the URL
  bound at enrollment, and the node's tokens name that ID as `aud`.
- The audit log records enrollment, every command and every desired-state change, as for
  nodes, and every token issued to a person or an API key, never the token.

## Availability

The hub becomes a dependency of registry *authentication*, not of registry *serving*:

- tokens already issued work until they expire: a placed job's until its timeout plus a
  margin, at most `max_job_token_secs`, so a running job survives a partition as it does
  today; a node's own after an hour; others after 15 minutes;
- API keys presented directly keep working from the cached key table;
- browser sessions already open keep working until they expire or the registry restarts;
- new tokens and new sign-ins wait for the hub.

A node renews its own token at half-life, so a hub outage under 30 minutes costs `vk build`
nothing; a longer one stops builds that use tokens for the build cache until the hub is back.

## Security

- With hub tokens on (and in managed mode, for every credential), whoever holds the hub's
  token-signing key reads and writes every repository. That is the trust the mode asks for,
  and nothing more follows from it: deletion (gc today; `delete-tag` and `delete-repo` once
  they exist) and updates are off unless `[hub] allow` lists them, gc's windows never go
  below the registry's floors, and, when `[hub] release_keys` names any key, updates install
  only releases signed by a key the hub does not hold. The hub's own refusal of 0-day windows
  does not count here: a compromised hub skips it.
- The registry takes the hub's token-signing keys, first ones and rotated ones, only from the
  authenticated session; a stolen enrollment token is useless after first use.
- The key table carries hashes only. A registry's disk holds no secret but its own identity
  key and its TLS key.
- A registry never runs anything but typed commands; there is no shell, as for nodes.
- One signing key serves all registries, so a token names its registry's ID as `aud`, and
  another registry refuses it.
- A registry that allows `update` with no `[hub] release_keys` trusts the hub with its binary:
  the hub can then install any release it holds, signed or not.

## Migration

Each release is opt-in on the registry and reversible by its operator on the registry host
alone. Client changes are listed below.

| Step | What the operator does | What changes for clients | Undo |
|---|---|---|---|
| 1. Registration and monitoring | `vk-hub token create --kind registry`, then `vk-registry join` on the registry host | nothing: same URL, same mode, same keys, same UI | `vk-registry leave`, then restart `serve`; the registry runs as before. `vk-hub registries remove <id>` drops it from the hub |
| 2. Steering | list `read-only` and `gc` in `[hub] allow`; set a gc schedule on the hub, and drop `vk-registry gc` from cron | nothing, unless the hub makes the registry read-only | drop them from `[hub] allow`, restart `serve`, and put the cron entry back; what the hub asked is no longer applied |
| 3. Updates | list `update` in `[hub] allow` and keys in `[hub] release_keys`; run `serve` under a supervisor that restarts it, from a binary in a directory the service user can write (either of `install-service`'s units: the `--system` one lets its account write the binary's directory when it owns it); sign `vk-registry` releases (`vk release-key sign --program vk-registry`) and add them to the hub | the registry restarts on the new version, dropping open connections, as after a manual upgrade | drop `update` from `[hub] allow` and restart `serve`. A release that fails its trial is rolled back on its own; to go back after one succeeded, reinstall the previous binary, kept as `<root>/hub/releases/<sha256>` until the next update or `leave` |
| 4. Hub tokens | define namespaces on the hub; `[hub] tokens = true` on the registry, `gc` in its `[hub] allow` for the hub's per-prefix windows, and `[[gc.prefix]] path = "ci-pipeline", retention_days = 2`, a window below `min_retention_days` the hub cannot set; `[registry] guest_credential = "job"` on nodes | jobs reach the registry with tokens scoped to their namespaces, guests through `registry.vk` including locks and files; other clients and their credentials keep working | `tokens = false`; nodes back to `guest_credential = "node"` |
| 5. Managed mode | `vk-hub registries import`, then `mode = "managed"` | people sign in through the hub; imported `vkr_` keys keep working, and new keys come from the hub | restore `mode = "accounts"`: `accounts.db` is archived, not deleted, but holds nothing created on the hub since the import |
| 6. Locks on the hub | to be designed | — | — |

Steps 1 to 3 are partly implemented; the reference below covers them. WebDAV steering,
`delete-tag` and `delete-repo` (step 2), and rollouts across registries (step 3) remain
proposed. Step 4 is partly implemented ([its own
section](#step-4-namespaces-and-job-tokens)), steps 5 and 6 are proposed; steps 1 to 3 do not
depend on them, so a registry may stay at step 3.

Step 4 runs in `accounts` or `shared-secret` mode, next to that mode's credentials. The
registry keeps its `Basic` challenge, so `docker login` goes on with a `vkr_` key; a job's
token, and one an admin mints, is presented unprompted, as a bearer or as a Basic password.
The challenge naming the hub comes with step 5.

In step 5, `vk-hub registries import 9c2f4e1a7b3d5e60f1a2b3c4d5e6f708 accounts.db` turns users
into hub users (matched on OIDC issuer and subject), keeps API keys working by importing their
hashes and scopes as hub keys (once hub keys can hold them; see *What moves where*), and moves
captions to the hub; then the registry restarts in `managed` and `accounts.db` is archived.

## Steps 1 to 3: reference

Enrollment works in both `shared-secret` and `accounts` modes without changing the
registry's database, keys, UI or serving when the hub is unreachable. The hub lists it on
its **Registries** page and through `vk-hub registries`.

**Enrolling.**

```sh
vk-hub token create --kind registry | ssh reg-1 vk-registry join https://hub.example.com --token - [--ca FILE] [--config FILE]
```

A token is issued for a node or for a registry (`--kind`, a node by default), and enrolls
nothing else: the registry has `POST /v1/registry/enroll`, a table of pinned keys of its own,
and its session at `GET /v1/registry/session`, so neither kind of peer is ever taken for the
other. `join` resolves the store root as `status` does (`--root`, `VK_REGISTRY_ROOT`, the
`root` in `--config`, the shared store) and creates `<root>/hub/` (mode `0700`) with the
registry's ed25519 key, the hub's URL, its CA bundle when given, and the registry ID the hub
assigns; it prints the ID. `--replace` enrolls an enrolled registry again, as a new one, the
old enrollment moved aside and put back if the new one fails. A `serve` running unenrolled
picks up a first enrollment within a minute, and one started later connects at start; after
`--replace`, restart `serve`.
`vk-registry leave` deletes `<root>/hub/`; a running `serve` reports until it restarts, and
the hub keeps the registry, disconnected, until `vk-hub registries remove <id>`. An operator
can also issue a registry token from the web UI's Registries page.

The session opens with the handshake every peer shares (hello, challenge, auth bound to the
TLS connection), then speaks `vk_hub_proto::registry`'s messages, version 1. `vk node` and
`vk-registry` share the client side in the `vk-peer` crate. The hub ends a session with a
`Refused` message when the registry was removed or a newer session took over; a registry the
hub no longer knows stops dialing and says to `leave` and `join` again.

**Monitoring.** The registry sends its inventory (version and binary sha256, listen address
and TLS, mode, WebDAV, upstream prefixes, store filesystem size, a hash of its config, what
`[hub] allow` lists and whether updates must be signed) on connect and when it changes, a
heartbeat at the interval the hub asks (connections open and the limit, uploads in flight,
build-once locks held, free space), its store usage after each gc and every 10 minutes
(`status`'s figures, and its 256 largest repositories), and a report of what it applied and
is doing. The hub keeps the latest of each: `vk-hub registries`, `vk-hub registries show
<id>`, `/registries`, `/registry/<id>`.

**Steering.** Desired state carries, each optional, with a generation; the registry applies
the newest one, and again after a restart:

- `read_only` (`vk-hub registries read-only <id> on|off|default`): refuse writes — pushes,
  uploads, WebDAV writes, deletions — after authentication, with 503 and `Retry-After`, while
  reads, sign-ins, key and caption management, the lock service and the pull-through relay's
  caching go on;
- `gc` (`vk-hub registries gc-schedule <id> --every 1d [--retention-days 30] [--grace-days 1]
  | --off`, at most every 10 minutes): the registry runs gc itself on that schedule, as
  `vk-registry gc` does. It refuses windows below its floors (`[hub] min_retention_days`, 7
  by default, and `min_grace_days`, 1).

Commands are `gc` (`vk-hub registries gc <id> [--retention-days N] [--grace-days N]
[--dry-run]`, under the same floors) and `update`, each journaled by the registry so one
redelivered after a reconnect is answered with its outcome rather than run again, and one a
restart interrupted is reported failed. The registry applies a desired-state field or runs a
command only when `[hub] allow` lists it (`read-only`, `gc`, `update`); anything else is
refused, and reported as refused. An enrolled registry with no `[hub]` table is watched and
nothing more.

**Updates.** `vk-hub release add <file> --version V --program vk-registry [--signature FILE]`
holds a `vk-registry` binary as `vk-hub` holds `vk` ones; nodes never update to it, nor
registries to a `vk`. `vk release-key sign --program vk-registry` signs one: its message
differs from a `vk` release's, so neither signature verifies as the other.
`vk-hub registries update <id> --release <sha256 prefix>` sends it. The registry:

1. refuses it if another update is under way, if its version is older than its own (unless
   `[hub] allow_downgrade`), if its signature does not verify against `[hub] release_keys`
   when signatures are required (by default, once keys are listed), or if the installed
   binary — the one `serve` last started from outside `<root>/hub/` — is not in a directory
   its user can write;
2. downloads it from `/v1/registry/releases/<sha256>` under its own signature, checks its
   digest and size, and its `--version`;
3. keeps the running binary under `<root>/hub/releases/`, waits for a gc under way, records a
   trial, and executes the release in its place, `alarm(2)` armed past a two-minute deadline.
   Open connections are dropped, as by a restart;
4. the release, once in session with the hub, installs itself over the installed binary's
   path by rename and reports the update done.

Until then the installed binary is left as it is. Run `serve` under a supervisor that restarts
it (`vk-registry install-service`), from a binary in a directory its user can write: the
user unit as is, or the `--system` unit, which lets its account write the binary's directory
(an account owning it, such as `/opt/vk-registry/`, rather than a shared `/usr/local/bin`). A
release that crashes or hangs is restarted as the
previous binary, which hands over again up to three starts, then takes the registry back and
reports the update rolled back.

## Step 4: namespaces and job tokens

Status: 4a and 4b are implemented (see *Step 4: reference*); 4c is proposed. This step covers
GitLab jobs, and tokens an admin mints for automation and tests. Node tokens, tokens for API keys and people's tokens come later on
the same keys, format and checks.

### Namespaces

The registry is one deduplicated store of blobs with compartmented references on top. A
**namespace** is a path prefix on one registry together with who may read, write or lock
under it. The hub holds namespaces per registry, in its database, and manages them with
`vk-hub namespaces` and on the Registries page. Every change goes in the audit log.

```text
namespace images       path = "images"                                    retention = default
  read        *
  write       gitlab gl, projects "infra/images", protected
namespace project      path = "p/{gitlab}/{project_id}"
  read write lock      own project, protected
  read                 own project, unprotected
namespace project-dev  path = "p/{gitlab}/{project_id}/dev"
  read write lock      own project
namespace wab          path = "wab"
  read write lock      gitlab gl, projects "wab/**", protected
  read                 gitlab gl, projects "wab/**"
namespace ci-cache     path = "ci-cache/{gitlab}/{project_id}/{protection}"
  read write           own project
namespace ci-pipeline  path = "ci-pipeline/{gitlab}/{project_id}/{pipeline_id}"  retention = 2d
  read write lock      own project, own pipeline
```

- **What a prefix covers.** A namespace's path covers every kind of reference beneath it,
  cut at a path component (`images` does not cover `images2`):
  - repositories `<path>` and `<path>/…`;
  - plain files `/dav/files/<path>/…`, which the registry already treats as the
    repositories `files/<path>/…`;
  - lock and failure-memo names `<path>:<key>`.
- **Subjects** select a job by project (`*`, `projects <path glob>`, or `project-id <n>`),
  by ref (a glob), or by protection (`protected`, `unprotected`). Project paths and IDs
  repeat across GitLab instances, so `projects` and `project-id` need `gitlab <name>` too.
  `own project` and `own pipeline` match any job: the path's template does the scoping, so
  a namespace granting either must have `{gitlab}` and `{project_id}` or `{pipeline_id}` in
  its path, which the hub checks when it stores the namespace. Granting `write` or `lock` by
  ref name requires `protected` as well: anyone who can push to a project can create a
  branch with any name.
- **Templates** are filled from the job's claims when its token is minted, from identifiers
  only, so two namespaces never collide:
  - `{gitlab}`, the name the hub gave the job's GitLab instance (see *Trust*);
  - `{project_id}` and `{pipeline_id}`, GitLab's numeric IDs;
  - `{protection}`, which is `protected` or `unprotected`.

  Project paths select jobs but never name a namespace: they are not unique across GitLab
  instances, and a project's path changes when it is renamed or moved.
- **Grants add up.** A namespace nested in another adds grants on its subtree and never
  removes any. A job's grants are the union of every namespace that selects it.
- **There is no catch-all.** A token reaches only declared namespaces. A path outside every
  namespace is reachable only by the registry's own credentials and the hub's admins.
- **Deduplication stays global.** The same content pushed into two namespaces is stored once.
  A blob is served only through a repository the caller may read (`readable_through`).
  vk-registry has no `?mount=` blob mount. The manifest-reference mount requires read on
  another repository holding the blob; `shared-secret` mode records no membership, so it
  mounts nothing. That mount looks for the blob in the whole store before it walks the
  repositories the caller may read (`lib.rs`, `authorize_and_mount_manifest_blobs`). Both
  refusals look the same but take different times, which tells a caller whether the store
  holds a digest. For a token principal the registry skips the whole-store
  lookup, so the answer and its timing depend only on what the token may read; a token
  guessing digests then pays a walk per guess, bounded by `MAX_MANIFEST_REFERENCES` per
  manifest.
- **Sharing is explicit.** Build-once works between the jobs that share a namespace: a lock
  and the image it guards live in the same namespace. Two projects share builds only through
  a namespace both may write and lock in. The same content built in two namespaces is built
  twice and stored once.
- **Retention.** A namespace with a `retention` has its tags dropped once they sit idle that
  long; a pull or a re-push counts as use, as it does for every tag. The window is a gc
  window on the static part of the namespace's path, before its first placeholder, which
  the registry also knows on its own (see *Retention by prefix* below), and the hub sends it
  in desired state. The hub refuses a retention on a path with a fixed component after a
  placeholder, or whose static part reaches another namespace asking for a different window.
  Under a window the registry's own config sets, a manifest's `org.virtkit.retention=keep` is
  ignored and an `org.virtkit.expires` later than the window is cut to it, since any job with
  write access chooses those annotations. Under a window the hub sets, both hold, so a hub
  cannot drop pinned tags.
- **The default set.** The hub starts with `ci-cache` and `ci-pipeline` as above; the
  operator may change both paths and grants, and declares the rest. These two names are
  roles: the node stores a job's caches in the repositories they resolve to (see 4a).

**Trust.** A job's claims (project ID and path, ref, protection, pipeline) are vk-gitlab's,
sent with the `vkk_` jobs key that submits it, and the hub does not check them with GitLab.
Each of them is a separate field of the job, so the hub bounds the key, not the fields one
by one:

- The hub knows each GitLab instance it takes jobs from, by URL, under a short name it gives
  it (`vk-hub gitlabs add|list|remove`). A jobs key may be bound to one instance
  (`vk-hub keys create --gitlab <name> [--projects id:path,…]`), and the hub refuses a job of
  that key whose `server_url` is not that instance's.
- A bound key's ceiling is either the whole instance, or a list of projects, each by ID with
  its path. The hub refuses a job whose project ID is not on the list, or whose path is not
  the one listed for that ID; a rename on GitLab means updating the list.
- A key bound to no instance behaves as today, and its jobs never get a token.
- Protection and pipeline ID are trusted as vk-gitlab asserts them. A key whose ceiling is
  the whole instance is trusted for the whole instance.

A leaked or compromised bound key thus reaches only the namespaces its ceiling selects,
though within them it can claim protection.

### Tokens

- **Format.** A token is `vkt_<claims>.<signature>`: both parts base64url, the claims JSON,
  the signature ed25519 over the claims. There is no JWT library and no algorithm choice, and
  clients treat the token as opaque. The claims:
  - `kid`, the signing key;
  - `aud`, the registry ID;
  - `sub`, `job:<hub job id>`, or the admin who minted it;
  - `jti`;
  - `pipeline`, optional, as `<gitlab>/<pipeline id>`, with the instance's hub-given name;
  - `iat` and `exp`;
  - `grants`, a list of prefixes, each with its subset of `read`, `write` and `lock`.
- **Signing keys.** The hub keeps them under `<data_dir>/token-keys/`, each with a `kid`.
  `vk-hub token-keys rotate` adds a new key and publishes it; with a fleet root pinned, a
  registry accepts the new key only once it has a root certificate
  ([the trust model](trust-model.md)). The hub signs a registry's tokens with the new key
  only once that registry reports a generation that includes it, and with the old key until
  then. The old key stays published until the longest token it signed has expired, then goes.
- **Distribution.** The public keys reach registries as an optional `token_keys` field of
  desired state, which the hub fills in when it sends. A rotation bumps every registry's
  generation. The registry keeps the keys with the rest of its applied state in
  `<root>/hub/state.json` and restores them before it serves, so a restart does not wait for
  the hub.
- **Checks.** The registry checks a token against those keys in memory, with no request to
  the hub:
  - its `kid` is known and its signature verifies;
  - `aud` is the registry's own ID;
  - `exp` has not passed, allowing 60 seconds of skew;
  - the request falls under a grant.

  A revocation list comes later; until then a token is valid until it expires.
- **Opting in.** The registry turns tokens on with `[hub] tokens = true` and announces it in
  its inventory; the hub mints tokens only for registries that do. The registry takes a
  `vkt_` token as a bearer or as a Basic password. In `accounts` mode it is checked as a
  token, before `vkr_` keys; in `shared-secret` mode, beside the shared secret.
- **Which registry.** A node reports its `[registry]` URL in its inventory. The hub matches it
  against the URL bound to each registry at enrollment
  (`vk-hub token create --kind registry --url …`; `vk-hub registries set-url` for registries
  already enrolled). A node whose registry is unknown, or does not take tokens, gets jobs
  without a token.
- **Minted by an admin.** `vk-hub registries token <id> --grant <prefix>=<rwl> [--pipeline
  <p>] [--ttl <d>]` mints a token for automation and tests. Its `sub` names the admin, not a
  job, and it carries a `pipeline` claim only when given one.
- **Audit.** The hub logs every token it issues, by `jti`, job or admin, registry and grants,
  never the token itself. The token is not stored with the job: the spec on the hub stays
  redacted.

### 4a: tokens for placed jobs

- **Minting.** `place()` mints the token when it places a job and sends it in `JobStart` as
  an optional field. The token is opaque to the node, so the field also carries what the node
  needs to route:
  - the registry ID, the token and its expiry;
  - the grants, as in the token, for discovery (4b);
  - the repositories the `ci-cache` and `ci-pipeline` namespaces resolve to for this job,
    when they select it.

  Namespace paths are absolute paths on the registry: the repository prefix of the node's
  `[registry] repo` does not apply to them.
- **Lifetime.** It lasts the job's timeout plus 15 minutes, for the caches and artifacts
  stored after the last step, up to the hub config's `max_job_token_secs` (86400, 24 hours,
  by default). A job allowed to run longer loses registry access once the cap passes.
  - There is no renewal, so a running job survives a hub partition as it does today.
  - The guest never sees the token, and the node drops it when the job ends. A copy taken
    from the node stays valid until it expires.
- **On the node.**
  - `[registry] guest_credential = "job" | "node"` chooses what the guest's credential
    proxy injects. The default is `"node"`, which is today's behaviour.
  - With `"job"`, the guest proxy runs for every job, whatever `proxy_guests` says. A job
    that arrives without a token gets a proxy that answers every request with 403. It never
    falls back to the node's credential.
- **The CI cache.** It moves to the repository `JobStart` names for `ci-cache` and is stored
  with the job's token, under `"node"` too. Protection becomes part of the repository path,
  so an unprotected job cannot overwrite a protected cache. The tag is the sha256 of the key
  alone. Existing caches miss once. A start without a token names no cache repository. A
  job whose start names none keeps today's caches (`ci-cache/<host>/<project>`, with the
  node's credential); only under `"job"` does it run without caches, with a warning in its
  trace.
- **Unchanged in this step.** These keep the node's credential: image pulls and relays,
  `vk build`'s build cache, and the build-once locks and failure memos `vk` takes around a
  build. Pulling a job's image with a read token for its namespace (`images` for most) is
  the next step, as `fleet-design.md` intends.

### 4b: registry access from inside a job

- **The proxy.** When it injects a job token, the credential proxy forwards `/lock/` and
  `/dav/files/` as well as `/v2/`. With the node's credential it keeps refusing anything
  outside `/v2/`, since that credential is not scoped. The proxy filters no namespace
  itself: the registry enforces the token.
  - It sets no response timeout of its own: `/lock/acquire` long-polls for up to an hour by
    default, and a blob or file transfer takes as long as it takes.
- **Locks for a token principal.**
  - Every name in a request to any `/lock/` endpoint must be `<prefix>:<key>` under a
    prefix the token holds `lock` on.
  - `x-vk-lock-pipeline` must be absent or equal the token's `pipeline` claim; when absent,
    the registry takes the claim. A token without the claim may take locks, but
    `/lock/fail` and `/lock/fail-status` answer it 403.
  - In-job tools leave `x-vk-lock-pipeline` out. The claim is `<gitlab>/<pipeline id>`,
    while today's clients send a bare `CI_PIPELINE_ID` (`jobctx::pipeline_identity`), so a
    header they set would be refused.
  - Failure memos are keyed by name and pipeline, for every caller: a record under pipeline
    B leaves pipeline A's. With both checks a job neither records nor clears another
    pipeline's memos.
  - The tokens of one subject (a job) hold at most 256 live locks together. An acquire that
    would take more is answered 429 at once rather than waiting, so a job cannot grow the
    lock table every acquire scans.
  - Nothing a token starts outlives it: the registry cuts an acquire's wait, a lease and a
    memo's TTL to the token's remaining lifetime, and checks the token's expiry again before
    it grants a lock someone waited for. Without a token, a wait or a lease can run up to 24
    hours.
  - Releasing and renewing still need the owner token the registry minted, as today.
- **Discovery.** The node gives every job using `"job"` two variables:
  - `VK_REGISTRY=http://registry.vk`;
  - `VK_REGISTRY_NAMESPACES`, the job's prefixes with their rights, e.g.
    `p/gl/42=rwl images=r ci-pipeline/gl/42/1234=rwl`.
- **In-job tools.** task-rs points its lock backend at `$VK_REGISTRY/lock/` and prefixes its
  lock names with a namespace it may lock in. sccache uses
  `$VK_REGISTRY/dav/files/<prefix>/…` under a namespace it may write. Neither holds a
  credential.

### 4c: pipeline caches and captures

- **The namespace.** `ci-pipeline` gives every job of a pipeline read, write and lock on its
  own prefix. Jobs of the pipeline pass content to one another through it, and the first job
  to need something builds it once while the others wait for it. Inside it, the layout is
  fixed, so the node finds its way without asking the hub:
  - `<prefix>/cache`, the pipeline's caches, one tag per key;
  - `<prefix>/services/<name>`, the service captures of
    [the disk images design](disk-images-design.md) (§3), each tagged `job-<job id>` by the
    job that captured it and `current` for the last one published.
- **Caches from `.gitlab-ci.yml`.** A cache whose key starts with `vk-pipeline/` goes to
  `<prefix>/cache` instead of `ci-cache`, tagged with the sha256 of the rest of the key.
  `policy`, `when` and `fallback_keys` behave as for other caches, and a job may mix both
  kinds. Under gitlab-runner, off the fleet, the same entry is an ordinary cache, so a
  pipeline keeps working there.
- **Captures.** `vk-agent service commit <service> --as <name>` pushes to
  `<prefix>/services/<name>` with the job's token, and `pipeline/<name>` names the `current`
  capture in a later job's images. The disk images design covers capture and publication;
  this step gives them a namespace and a credential.
- **From inside the guest.** The same namespace is reachable through `$VK_REGISTRY`, as OCI
  content, files or locks, for tools that want more than one archive per key.
- **Compared with GitLab artifacts.**
  - Content is deduplicated against everything in the registry.
  - It travels between the fleet and its registry, not through GitLab.
  - GitLab's artifact size limit does not apply.
  - Locks come with it.
  - Its use does not follow `needs:` or `dependencies:`.

  Artifacts stay for what GitLab must hold: reports, downloads, `expire_in`.
- **Lifetime.** The hub does not see when a pipeline ends, so expiry is by time: the
  namespace's retention, 2 days idle by default. A job that uses a capture or a cache keeps
  it alive. The hub cannot set that window: `[hub] min_retention_days` (7 by default) bounds
  what it sets, and it may only lengthen a window. The registry sets it, with
  `[[gc.prefix]] path = "ci-pipeline", retention_days = 2`, and that prefix must follow the
  namespace's path if the operator changes it.
- **Without the hub.** A node run by gitlab-runner, with no hub, keeps the same layout for
  captures under its own `[registry] repo`: `ci-pipeline/<gitlab>/<project id>/<pipeline
  id>`. It pushes with its own credential: there is no job token, so the registry enforces
  no namespace and the isolation is the node's alone. Where the node takes the job's
  identity, and the resolver rules that keep a job inside its pipeline, are in
  [the disk images design](disk-images-design.md) (§3).

### Retention by prefix

A gc window on a prefix is the registry's own setting first, so it works with or without a
hub:

```toml
[[gc.prefix]]
path = "ci-pipeline"
retention_days = 2
```

- A prefix's window applies to every tag under it. A window the config sets on a prefix may
  be below `[hub] min_retention_days`, which bounds only what the hub sets.
- The hub may set a window on a prefix from a namespace's `retention`, and sends it only to
  a registry whose `[hub] allow` lists `gc`; the registry takes hub windows only then. The
  hub may lengthen a window the config sets, never shorten it, and on any other prefix it
  stays within the store-wide floors and above the config's window covering that prefix. A compromised hub thus cannot expire the `images`
  namespace in a day.
- Without a window of its own, a prefix takes the store-wide one.

### Implementation order

1. Failure memos keyed by name and pipeline. It stands alone and fixes today's API too.
2. The token codec in a crate shared by the hub and the registry: claims, grants, minting
   and checking. It reuses the ed25519 verification vk-registry already links through
   vk-peer.
3. The hub:
   - GitLab instances, and jobs keys bound to one with their ceilings, refusing a bound
     key's jobs outside them;
   - signing keys, with rotation that waits for registries;
   - namespaces: store, templates, CLI and page;
   - the admin mint, and the audit of issued tokens.
4. The protocol:
   - `token_keys` and per-prefix retention in `DesiredState`;
   - `tokens` in the registry's inventory;
   - the `[registry]` URL in the node's inventory;
   - the URL bound at registry enrollment, and `set-url`.
5. The registry's checks:
   - `[hub] tokens` and the token principal;
   - grants on `/v2/`, `/dav/files/` and `/lock/`;
   - the pipeline check, and locks and memos bounded by the token's lifetime;
   - no whole-store lookup when mounting for a token;
   - retention by prefix in gc, from `[[gc.prefix]]`, and from the hub when `[hub] allow`
     lists `gc`, within the floors.
6. Minting in `place()`, and `JobStart`'s field: token, grants and cache repositories.
7. The node: `guest_credential`, and the CI cache in the repository `JobStart` names, with
   the job's token.
8. The proxy forwarding `/lock/` and `/dav/files/` under a job token, and the two variables
   (4b).
9. `vk-pipeline/` cache keys, and captures under `services/` with the job's token (4c).
10. End-to-end tests in `tests/gitlab/fleet.sh`:
    - a guest push outside its grants is refused;
    - a lock outside its prefixes is refused;
    - a failure memo for another pipeline is refused, and does not clear that pipeline's;
    - a proxy holding the node's credential still refuses `/lock/`;
    - a pipeline cache is shared between two jobs of one pipeline and not with another
      pipeline;
    - a job whose project ID and path disagree with its key's ceiling is refused.

## Step 4: reference

The hub's side of step 4; the registry's is in
[vk-registry's design](../vk-registry/DESIGN.md).

**GitLab instances and bound keys.** `vk-hub gitlabs add <name> <url>`, `gitlabs list` and
`gitlabs remove <name>` keep the instances the hub takes jobs from, by a name of lowercase
letters, digits and `-`, which namespaces call `{gitlab}`. A URL is normalized (lowercase
scheme and host, no default port, no trailing `/`) and names one instance; an instance a
working key is bound to is not removed. `vk-hub keys create … --gitlab <name> [--projects
<id>:<path>,…]` binds a jobs key. A bound key submits only jobs whose `server_url` is its
instance's, naming a project (ID not 0), and with `--projects` only those projects, by ID and
path both; anything else is 403. Keys bound to none submit as before, and their jobs get no
token.

**Namespaces.** `vk-hub namespaces list|show <registry> [<name>]`, `namespaces add <registry>
<name> --path <template> [--retention-days <n>] --grant <rights>:<subject> [--grant …]` (adding
an existing name replaces it) and `namespaces remove <registry> <name>`, audited under the
registry. A registry holds at most 64 namespaces, a token's grants. A path is a repository name
whose components may be `{gitlab}`, `{project_id}`, `{pipeline_id}` or `{protection}` whole; it
starts with a fixed component. Rights are some of `r`, `w`, `l`. A subject is comma-separated
terms that must all hold:

| Term | Selects |
|---|---|
| `*` | any job |
| `own project`, `own pipeline` | any job, the path naming its own through `{gitlab}` and `{project_id}` or `{pipeline_id}`, which the hub checks |
| `gitlab <name>` | jobs from that instance |
| `projects <glob>`, `project-id <n>` | that project, beside `gitlab <name>`: `*` stays within a path component, `**` crosses them |
| `ref <glob>` | that ref; with `w` or `l`, only beside `protected` |
| `protected`, `unprotected` | that protection |

A retention (1 to 3650 days) covers the path's leading fixed components, so the path has no
fixed component after a placeholder, and it is refused where it would reach into another
namespace asking for another window. A registry that first takes tokens gets `ci-cache`
(`ci-cache/{gitlab}/{project_id}/{protection}`, `rw:own project`) and `ci-pipeline`
(`ci-pipeline/{gitlab}/{project_id}/{pipeline_id}`, `rwl:own project, own pipeline`, 2 days),
once; their names are the roles that name a job's cache repository and pipeline prefix. The
2-day window takes effect only on a registry whose `[[gc.prefix]]` allows it: the hub may only
lengthen a registry's own window, and stays within `min_retention_days` elsewhere.

**Registry URLs.** `vk-hub token create --kind registry --url <url>` binds the enrolling
registry to the URL its clients reach it at; `vk-hub registries set-url <id> <url>|--none`
changes it, and `registries show` prints it with whether the registry takes tokens. A URL is
`http(s)://host[:port]`, and one host and port belong to one registry whatever the scheme. A
URL another registry took before the token was spent is not bound, and the audit log says so.

**Signing keys.** The hub keeps them in `<data_dir>/token-keys/` (`0700`, each key `0600`),
creating the first when a registry first takes tokens. `vk-hub token-keys list` and
`token-keys rotate`. A registry with `[hub] tokens = true` gets every key in its desired
state, and its namespaces' retention windows when gc is in its `[hub] allow`. A new key signs
a registry's tokens once the registry reports applying the generation that first carried it;
a key superseded for longer than any token lives (7 days and the skew) is retired, its file
removed, at the next sync or the hourly sweep. `max_job_token_secs` in `hub.toml` (60 to
604800, 86400 by default) caps a token's lifetime.

**Minting.** A job of a working bound key, placed on a node whose inventory names a registry
URL the hub binds and says it uses job tokens, on a registry that takes tokens and applied a
key, gets a token: its grants from that registry's namespaces, `sub` `job:<id>`, `pipeline`
`<gitlab>/<pipeline id>` when the job names a pipeline, living its timeout plus 15 minutes up
to `max_job_token_secs`. Anything missing, the job goes without. Each issue is audited under
the registry by jti, job and node, never the token, which the hub stores nowhere. `vk-hub
registries token <id> --grant <prefix>=<rights> [--grant …] [--pipeline <gitlab>/<id>] [--ttl
1h]` mints one for automation and tests, audited the same way.

**Web UI.** `/registries` lists each registry's name, bound address, connection status, free
storage and job access: *off* (no `[hub] tokens`), *Setup needed* (no bound address or applied
signing key), *Updating signing keys* (a newer key exists; the applied key still signs), or
*Configured* with a storage-area count. The UI calls namespaces storage areas. Version, mode
and ID are on the registry's page.

A registry's page has three tabs. *Overview* (`/registry/<id>`) is what it reports and what
the hub asks of it. *Job access* (`?tab=access`) lists its storage areas, each with who may
read and who may publish there in plain words ("Projects under wab/ on gl, protected
branches and tags only · can coordinate builds"); the two the hub keeps for CI, `ci-cache`
and `ci-pipeline`, are folded under *Managed by CI*. It says when cleanup after inactivity
does not apply, because the registry's `[hub] allow` lacks `gc` or the registry refused a
window, and links to the registry's audit log. *Settings* (`?tab=settings`) shows the bound
address and, per signing key the registry was sent, whether it signs the registry's tokens,
awaits being applied, or was replaced and is kept while its tokens may be live.

## Open questions

- **Key table size.** Bounded by the hub's 256 keys today; a fleet with per-project keys in the
  thousands would rather have the registry ask the hub per unknown key and cache the answer.
- **Several registries.** A pull-through cache per site would want the same management; does
  one hub token name several registries (`aud` a list), or one per registry as proposed?
- **Child pipelines.** A child pipeline has its own pipeline ID, and a job's payload does not
  name the parent, so a child cannot reach its parent's `ci-pipeline` namespace. Granting it
  needs a parent claim; what GitLab sends a child pipeline's jobs is unchecked.
- **Locks on the hub.** Decided in principle, not designed: the build-once lock service moves to
  the hub after managed mode, which would let a lock span registries. The open part is how a
  lock outlives a hub restart.
