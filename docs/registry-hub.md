# A registry the hub manages (design)

Status: **in progress**. Implemented: migration steps 1 (registration and monitoring), 2 in
part (gc schedule and windows, read-only, the `gc` command; not WebDAV steering, nor the
`delete-tag` and `delete-repo` commands) and 3 in part (an update on trial to a release the
hub holds, one registry at a time; rollouts do not cover registries yet). The rest is
proposed. Builds on [the fleet design](fleet-design.md).

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
- **No trust in the hub beyond what the registry's config grants.** The hub mints no registry
  credential today: a job's `registry_credentials` are GitLab's, passed through, and
  `fleet-design.md` only intends per-job tokens. In managed mode the hub issues every registry
  credential, which the registry's operator opts into by choosing the mode; every other
  operation is typed and bounded by the registry's own config.

Out of scope: replicas, or a registry serving several hubs.

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
  with hub tokens (migration step 4); enrollment today takes no URL.
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
  - retention and grace windows, and when gc runs (a schedule, or never);
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
| a placed job | nothing: its node gets the job's token with the job; the guest reaches the registry through the credential proxy, which injects that token, never the node's own | the job's scopes, until the job's timeout |
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

One rule set, on the hub: a person's grants, an API key's scopes, a job's scopes. The
registry enforces `read`/`write` on repository globs, as it does for API keys today, now for
every credential; it never decides who gets which.

`/lock/*` needs a grant of its own, `lock`: OCI scopes name repositories only, and today any
authenticated principal may use the lock API. The registry challenges a lock request with
`scope="registry:lock:*"`, and a client asks for that scope. The hub grants it in node and
job tokens, in tokens minted for an API key given `lock` (automation takes locks), and in the
key table for such keys.

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

- tokens already issued work until they expire: a placed job's at its timeout, so a running
  job survives a partition as it does today; a node's own after an hour; others after 15
  minutes;
- API keys presented directly keep working from the cached key table;
- browser sessions already open keep working until they expire or the registry restarts;
- new tokens and new sign-ins wait for the hub.

A node renews its own token at half-life, so a hub outage under 30 minutes costs `vk build`
nothing; a longer one stops builds that use tokens for the build cache until the hub is back.

## Security

- In managed mode the hub mints every registry credential: whoever holds its token-signing
  key reads and writes every repository. That is the trust the mode asks for, and nothing
  more follows from it: deletion (gc today; `delete-tag` and `delete-repo` once they exist)
  and updates are off unless `[hub] allow` lists them, gc's windows never go below the
  registry's floors, and, when `[hub] release_keys` names any key, updates install only
  releases signed by a key the hub does not hold. The hub's own refusal of 0-day windows
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
| 4. Hub tokens | `[hub] tokens = true` | clients may also get tokens from the hub; `vkr_` keys and sessions keep working | `tokens = false` |
| 5. Managed mode | `vk-hub registries import`, then `mode = "managed"` | people sign in through the hub; imported `vkr_` keys keep working, and new keys come from the hub | restore `mode = "accounts"`: `accounts.db` is archived, not deleted, but holds nothing created on the hub since the import |
| 6. Locks on the hub | to be designed | — | — |

Steps 1 to 3 are partly implemented; the reference below covers them. WebDAV steering,
`delete-tag` and `delete-repo` (step 2), and rollouts across registries (step 3) remain
proposed. Steps 4 to 6 are also proposed; steps 1 to 3 do not depend on them, so a registry
may stay at step 3.

Step 4 runs in `accounts` mode next to `vkr_` keys. The registry keeps its `Basic` challenge,
so `docker login` goes on with a `vkr_` key; nodes and jobs present their hub token as a
bearer unprompted. The challenge naming the hub comes with step 5.

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

## Open questions

- **Key table size.** Bounded by the hub's 256 keys today; a fleet with per-project keys in the
  thousands would rather have the registry ask the hub per unknown key and cache the answer.
- **Several registries.** A pull-through cache per site would want the same management; does
  one hub token name several registries (`aud` a list), or one per registry as proposed?
- **Locks on the hub.** Decided in principle, not designed: the build-once lock service moves to
  the hub after managed mode, which would let a lock span registries. The open part is how a
  lock outlives a hub restart.
