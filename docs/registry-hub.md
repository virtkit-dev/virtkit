# A registry the hub manages (design)

Status: **in progress**. Implemented: migration steps 1 (monitoring), 2 in part (gc schedule
and windows, read-only, the `gc` command) and 5 in part (an update on trial to a release the
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
  https://reg-1.example.com`), and the hub refuses a URL another registry holds.
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
  - `gc [--dry-run]`, `delete-tag`, `delete-repo`;
  - `update` to a release, run on trial and rolled back as a node's is. As for a node, that
    needs `vk-registry serve` under a supervisor that restarts it (systemd, say): a release
    that cannot reach the hub in time is ended by its alarm, and only a restart brings the
    previous binary back to roll it back.

The registry's config controls the listener, TLS, store root, upstreams and connection
limits. The hub only narrows what the config allows. The config lists what the hub may set
or send (`[hub] allow = ["read-only", "gc", "update"]`;
`delete-tag` and `delete-repo` are listed the same way); anything else is refused. gc deletes
too, since retention decides when an idle tag stops being a root: the hub refuses a retention
or grace of 0 days, and the registry keeps floors of its own (`[hub] min_retention_days`,
default 7, and `min_grace_days`, default 1) that the hub's windows may lengthen, never
shorten.

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
`sha256(secret)`, scopes and expiry, no secret. The registry checks a bearer or Basic key
against it in memory, as `accounts.db`'s `api_keys` does today. It is a cache of the hub's
state, written atomically as one file, read at start, and replaced wholesale by the next
generation: nothing the registry writes, nothing to back up.

### People in the browser

`/browse`, `/upload` and `/settings/keys` stay on the registry, which serves the bytes;
signing in moves to the hub:

1. an unauthenticated browser request redirects to the hub's
   `/registry/login?registry=9c2f4e1a7b3d5e60f1a2b3c4d5e6f708`;
2. the hub signs the person in with its own OIDC session, and redirects back with a one-time,
   one-minute token for this registry naming the user and their scopes;
3. the registry turns it into a session cookie it signs itself: an HMAC over user, scopes and
   expiry, under a key held in memory and regenerated at each start.

Sessions need no table: a restart signs everyone out, logout clears the cookie, and the
revocation list carries users to cut off before their cookie expires. `/settings/keys` becomes
a link to the hub's key page.

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
| failure memos and locks | unchanged: in memory, under the `lock` grant |

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
  more follows from it: deletion and updates are off unless `[hub] allow` lists them, gc's
  windows never go below the registry's floors, and, when `[hub] release_keys` names any
  key, updates install only releases signed by a key the hub does not hold. The hub's own
  refusal of 0-day windows does not count here: a compromised hub skips it.
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

1. **Monitoring.** Enrollment and the session with inventory, heartbeat, usage and gc
   reports, in any mode. Nothing about authentication changes; useful on its own.
2. **Steering.** Desired state (gc schedule and windows, WebDAV, read-only) and commands, still
   in any mode.
3. **Hub tokens.** The hub's token endpoint and the registry's checks, in `accounts` mode next
   to `vkr_` keys. The registry keeps its `Basic` challenge, so `docker login` goes on with a
   `vkr_` key; nodes and jobs present their hub token as a bearer unprompted. The challenge
   naming the hub comes with managed mode.
4. **Managed mode.** `vk-hub registries import 9c2f4e1a7b3d5e60f1a2b3c4d5e6f708 accounts.db`
   turns users into hub users (matched on OIDC issuer and subject), keeps API keys working by
   importing their hashes and scopes as hub keys, and moves captions to the hub; then the
   registry restarts in `managed` and `accounts.db` is archived.
5. **Updates** of `vk-registry` through rollouts.

Each step ships on its own and leaves the registry working without the next.

## Open questions

- **Browse on the hub instead?** The hub could serve the catalog and manifests over the
  session and leave only blob downloads to the registry, ending browser sessions on the
  registry altogether. Costs a proxy of every page through the session.
- **Key table size.** Bounded by the hub's 256 keys today; a fleet with per-project keys in the
  thousands would rather have the registry ask the hub per unknown key and cache the answer.
- **Several registries.** A pull-through cache per site would want the same management; does
  one hub token name several registries (`aud` a list), or one per registry as proposed?
- **Locks on the hub?** The build-once lock service lives in the registry today; with a hub in
  every fleet it could move there, which would let a lock span registries.
