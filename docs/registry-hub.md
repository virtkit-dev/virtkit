# A registry the hub manages (design)

Status: **proposed**. Builds on [the fleet design](fleet-design.md) and on
[registry domains and on-demand secrets](registry-domains-and-secrets.md), whose hub-signed job
tokens it generalizes.

A `vk-registry` enrolls with the hub as a node does, keeps a session open to it, and is
watched and steered from it. In the new **managed** mode it keeps no database: content is all
it stores, and every identity, key, scope and policy comes from the hub.

## Goals

- **One place to operate the fleet.** A registry's health, usage, gc and version show on the
  hub beside its nodes, and are changed there, with the same audit log and roles.
- **One identity layer.** People sign in once, on the hub; an API key is issued once, on the
  hub; a job's registry access is the hub's decision. `fleet-design.md` already wants the hub
  and the registry to share identities; this makes the hub the owner.
- **A registry is content and nothing else.** Losing its disk loses blobs, which a rebuild
  or a re-push restores. Nothing on it is the only copy of a decision.
- **No new trust in the hub beyond what nodes already give it.** The hub could already mint
  registry tokens under the domains design; managing the registry adds operations, typed and
  bounded by the registry's own config.

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
  sends the registry's public URL (`public_url`, what clients and job tokens' `aud` name).
- The hub pins the key and answers with its own **token-signing public keys** (several, for
  rotation) and the registry's ID. The registry pins those keys: they are what it checks
  tokens against, and a later change arrives only over the authenticated session, signed by a
  key it already trusts.
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

- inventory, when it changes: version, `public_url`, store filesystem, size and free space,
  TLS certificate expiry, a hash of its effective config, the policy it applied;
- a heartbeat every few seconds: connections against `max_connections`, requests and bytes in
  and out, uploads in flight, relay traffic to upstreams, locks held;
- usage, every few minutes: `vk-registry status`'s figures (stored and referenced bytes, per
  repository tags and size, stage data);
- outcomes: each gc pass's report, each command's result, until the hub acknowledges them.

**Hub → registry**

- desired state, with a generation, applied at most once, as for nodes:
  - retention and grace windows, and when gc runs (a schedule, or never);
  - whether WebDAV is on, whether writes are accepted (read-only for maintenance);
  - the token-signing keys, the revocation list, and the key table (see below);
- commands, journaled before they run, with an ID and an expiry:
  - `gc [--dry-run]`, `delete-tag`, `delete-repo`, `caption`;
  - `update` to a release, run on trial and rolled back as a node's is.

The registry's config stays authoritative for what concerns the host: listener, TLS, store
root, upstreams, connection limits. The hub only narrows what the config allows, and the
config lists which commands the hub may send (`[hub] allow = ["gc", "update", ...]`); a
deletion is off unless listed.

**Losing the hub does not stop the registry.** It keeps serving content, checking tokens
against the keys it pinned and the key table and revocation list it last received, and runs gc
on the schedule it last applied. What stops is new sign-ins and new tokens, which come from the
hub (see *Availability*).

## Authentication without a database

### Machines and jobs: hub-issued tokens

The registry becomes an OCI resource server: an unauthenticated request gets the standard
challenge

```text
WWW-Authenticate: Bearer realm="https://hub.example.com/v1/registry/token",service="reg-1",scope="repository:d/wab-master/build-cache:pull,push"
```

and the client asks the hub's token endpoint for a short-lived token, presenting what it
holds. This is the Docker/OCI token flow: `oci-client`, `docker`, `podman`, `skopeo` and
`crane` all follow it with no code of ours.

| Client | Presents to the hub | Gets |
|---|---|---|
| a placed job | nothing: its node and the guest get tokens with the job, renewed over the session | the domain's scopes, 15 minutes |
| a node outside a job (`vk build` warm-up, image pulls) | its node identity, signing the request | the node's scopes, 15 minutes |
| automation (task-rs outside the fleet, release scripts) | a hub API key, as Basic | the key's scopes, 15 minutes |
| a person's CLI (`docker login`, `vk registry put`) | a hub session token (`vk hub login`) | the person's scopes, 15 minutes |

The registry checks each token locally: signature against the pinned keys, `aud` is its own
`public_url`, `exp` with a small skew, `jti` not in the revocation list, and the requested
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

1. an unauthenticated browser request redirects to the hub's `/registry/login?registry=reg-1`;
2. the hub signs the person in with its own OIDC session, and redirects back with a one-time,
   one-minute token for this registry naming the user and their scopes;
3. the registry turns it into a session cookie it signs itself: an HMAC over user, scopes and
   expiry, under a key held in memory and regenerated at each start.

Sessions need no table: a restart signs everyone out, logout clears the cookie, and the
revocation list carries users to cut off before their cookie expires. `/settings/keys` becomes
a link to the hub's key page.

### Scopes

One rule set, on the hub: a person's grants, an API key's scopes, a job's domain. The
registry enforces `read`/`write` on repository globs as it does today, whatever the
credential; it never decides who gets which.

That closes the gap `fleet-design.md` names: today every authenticated session reads every
repository. Under the hub, a person's scopes are their grants, so a submitted job's image check
means something.

## What moves where

| Today (`accounts`) | Managed |
|---|---|
| `users` | the hub's users, from its OIDC sign-in |
| `sessions` | stateless signed cookies |
| `api_keys` | hub API keys, sent as the key table; `vkr_` keys imported once |
| admins, on the Unix socket | hub roles: operator for gc and captions, admin for deletions, updates and enrollment |
| `repo_captions` | a file per repository in the store (`repos/<name>/caption`), set by command |
| `vk-registry gc` by cron | gc scheduled in desired state, its reports on the hub |
| failure memos and locks | unchanged: in memory, domain-scoped per the domains design |

The admin socket stays, for an operator on the host: `status`, `gc`, and, when the hub is
gone for good, leaving managed mode.

## On the hub

- A **Registries** page beside Nodes: state, version, disk, traffic, usage per repository,
  last gc and its report, steering (schedule, windows, read-only), commands.
- `vk-hub registries list|show|remove`, `vk-hub registries gc|read-only|update`.
- Rollouts cover registries: `vk-hub release` holds `vk-registry` binaries as it holds `vk`,
  signed by the same off-hub key, checked against the registry's own `release_keys`, and a
  registry refuses a downgrade unless its config allows it.
- Nodes' `[build] cache_registry` can name a registry by ID; the hub turns it into its URL and
  the `aud` of the node's tokens.
- The audit log records enrollment, every command and every desired-state change, as for
  nodes, and every token issued to a person or an API key, never the token.

## Availability

The hub becomes a dependency of registry *authentication*, not of registry *serving*:

- tokens already issued work until they expire (15 minutes), and a running placed job's
  tokens are renewed by its node only while the hub is up, which placed jobs need anyway;
- API keys presented directly keep working from the cached key table;
- browser sessions already open keep working until they expire;
- new tokens and new sign-ins wait for the hub.

A hub outage longer than a token lifetime stops `vk build` on nodes that use tokens for the
build cache. Proposed: node tokens outside jobs last an hour, and a node renews at half-life,
so an hour's outage costs nothing.

## Security

- The hub can already mint any registry token under the domains design; managing the registry
  adds deletion and updates, both off unless the registry's config allows them, and updates
  only to releases signed by a key the hub does not hold.
- The registry pins the hub's token-signing keys at enrollment and accepts rotated ones only
  from the session; a stolen enrollment token is useless after first use.
- The key table carries hashes only. A registry's disk holds no secret but its own identity
  key and its TLS key.
- A registry never runs anything but typed commands; there is no shell, as for nodes.
- One signing key for all registries means a token for `reg-1` names `aud = reg-1` and is
  refused by `reg-2`.

## Migration

1. **Monitoring.** Enrollment and the session with inventory, heartbeat, usage and gc
   reports, in any mode. Nothing about authentication changes; useful on its own.
2. **Steering.** Desired state (gc schedule and windows, WebDAV, read-only) and commands, still
   in any mode.
3. **Hub tokens.** The hub's token endpoint and the registry's checks, in `accounts` mode next
   to `vkr_` keys: this is step 1 of the domains design's migration.
4. **Managed mode.** `vk-hub registries import reg-1 accounts.db` turns users into hub users
   (matched on OIDC issuer and subject), keeps API keys working by importing their hashes and
   scopes as hub keys, and moves captions into the store; then the registry restarts in
   `managed` and `accounts.db` is archived.
5. **Updates** of `vk-registry` through rollouts.

Each step ships on its own and leaves the registry working without the next.

## Open questions

- **Browse on the hub instead?** The hub could serve the catalog and manifests over the
  session and leave only blob downloads to the registry, ending browser sessions on the
  registry altogether. Costs a proxy of every page through the session.
- **Key table size.** Fine for hundreds of keys; a fleet with per-project keys in the
  thousands would rather have the registry ask the hub per unknown key and cache the answer.
- **Several registries.** A pull-through cache per site would want the same management; does
  one hub token name several registries (`aud` a list), or one per registry as proposed?
- **Locks on the hub?** The build-once lock service lives in the registry today; with a hub in
  every fleet it could move there, which would let a lock span registries.
