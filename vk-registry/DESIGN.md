# vk-registry — design

A central OCI-distribution server that all CI runners share, so an image/bundle is
**built once** and everyone else pulls it. It also fronts upstream registries as a
pull-through cache and backs the `task` build cache. It is deployed on its own host
(TLS + auth, many remote clients) — not a per-runner sidecar.

## Why it exists

Today each runner's `vk` can push/pull built bundles to a configured `[registry]`
(`vk-driver/src/registry.rs`: CDC-chunked, zstd, content-addressed dedup), and the
`wab` `task` fork caches task outputs the same way over its `oci://` transport
(`internal/ocicas`, oras-go v2). Both already speak **plain OCI distribution v2**, which
`vk-driver/src/regserve.rs` already implements. What is missing is a single, central,
concurrency-coordinated place to point them at:

- **build-once dedup** across all runners (one build, everyone reuses);
- a **distributed lock** so N runners needing the same artifact don't all build it;
- a **credential boundary** so a guest job can pull/push without holding the secret;
- a **backend for the `task` server** (its `oci://` cache + a lock scheme).

## Role summary

One server, three client families, one store:

1. **virtkit runners** — `registry.rs` (oci-client) bundle push/pull + build-once.
2. **`task`'s `oci://` cache** — oras-go `ocicas`; standard OCI + tags + annotations,
   so it works against this server with no vk-registry-specific client code.
3. **pull-through relay** — fronts upstream registries, caches digest-addressed content.

## Crate layout

New workspace member `vk-registry/` = **lib + bin**.

- **lib** owns the content-addressed `Store` and its helpers (`default_root`,
  `zstd_with_size`, `ZSTD_LEVEL`, `TRANSPARENT_ZSTD_HEADER`), moved out of
  `vk-driver/src/regserve.rs`, plus the hyper server, the OCI v2 route table, the
  pull-through relay, and the lock/auth modules.
- **bin** is a thin CLI (`serve`/`gc`/`status`/`install-service`) over the lib, plus
  `update` (over `vk-selfupdate`) so an operator can move it to a published release.
  `install-service` covers both shapes it is deployed in: a `systemd --user` unit it
  installs itself, and — with `--system` — a machine-wide one it prints for an admin to
  install, running as an unprivileged account with only the store writable.

`vk-driver` gains a path dep on the lib and deletes `regserve.rs`; its in-process
build-cache backend (`registry.rs` `mod local`) uses only `vk_registry::Store`. One
`Store` implementation, no drift. Because the server lives in the lib, `vk` links its
server/relay/TLS dep tree transitively even though it uses only `Store`.

### What changes in `vk`

- **Removed:** `vk registry serve` and `install-service` — the HTTP-serving role moves
  to `vk-registry`. The in-process filesystem store already gives worktree-local
  sharing without a daemon (advisory flock + atomic writes), so nothing is lost; a
  loopback OCI-over-HTTP endpoint is now `vk-registry serve` with no upstreams.
- **Kept:** the in-process local filesystem store as the **no-config default** cache
  backend, plus client-side `registry push`/`pull`/`inspect` and the local-store admin
  `registry status`/`gc`. A configured `[registry]` points at `vk-registry`.

Migration: anyone with `[registry] repo = 127.0.0.1:5000` against the old embedded
server switches to `repo = file:///…` (no daemon) or runs `vk-registry serve`.
User-visible → CHANGELOG.

## Pull-through relay

Every request tries the local `Store` first (today's fast path). On a miss, route to an
upstream by **longest-prefix match on the repo name** and act by addressing mode:

| Request                         | Miss action                              | Persist? |
|---------------------------------|------------------------------------------|----------|
| GET/HEAD blob `sha256:…`        | fetch upstream, verify, stream back      | **yes**  |
| GET/HEAD manifest `@sha256:…`   | fetch upstream, verify, stream back      | **yes**  |
| GET/HEAD manifest `:tag`        | resolve + relay upstream live            | **no**   |

Content is cached iff addressed by an explicit `sha256:` digest (blobs always are;
digest-pinned manifests are immutable). A `:tag` is mutable, so it is relayed every time
and never persisted — a client warms the cache by pinning the digest.

Routing convention: the first path segment(s) of the repo name select the upstream, e.g.
`mirror/docker.io/library/alpine@sha256:…` → prefix `docker.io` →
`https://registry-1.docker.io`, upstream repo `library/alpine`. Config:

```toml
[[upstream]]
prefix = "docker.io"                 # longest-prefix match; "" = catch-all
url    = "https://registry-1.docker.io"
# anonymous by default (bearer-token / WWW-Authenticate handled by oci-client);
# optional username + password_file, ca_file, insecure
[[upstream]]
prefix = "ghcr.io"
url    = "https://ghcr.io"
```

How persistence works:

- **Blobs stream to disk** — a pulled blob is streamed into a store temp file (bounded
  memory, never a multi-GB layer in RAM), hashed as it arrives, verified against the
  requested digest, then promoted to `blobs/sha256/<hex>` and served from the store. A
  relayed layer is already compressed, so it is stored identity (the adaptive-zstd path
  wouldn't shrink it). `Store::uploads_dir`/`identity_blob_path` expose the staging seam.
- **Manifests** — a digest-referenced manifest is persisted with the existing
  `put_manifest` (a digest reference writes no tag), so relayed manifests are cached
  without ever creating a mutable tag.

## Locking — the server is the authority

One registry process ⇒ an **authoritative in-process leased lock**; no Redis and no
cross-host flock on the hot path. Semantics mirror `task`'s `internal/redis/locker.go`
so `vk-registry` is a drop-in replacement for `cache.lock: redis://`:

- keyed by name (the content-key / cache tag); **leased ~30 s, client-renewed ~10 s**;
  the server auto-releases on lease expiry — same "holder dies ⇒ lock frees" guarantee
  as the abstract-socket lock (`internal/lock/lock_linux.go`) and the Redis TTL;
- **release-if-owner** via a server-minted opaque owner token;
- **contention** = block/long-poll until free or timeout (Redis default: 1 h max);
- **holder identity** returned for observability (like the Redis/socket holder info).

Explicit action endpoints under `/lock/`, **all POST**, outside the `/v2/` OCI namespace.
Names are repeated `?name=` params (one name = the single-lock case). Acquire returns an
opaque **owner token**; renew/release present it in `X-Vk-Lock-Owner`. Multi-name acquire
is **atomic all-or-nothing** (for a step that builds several images together — the
`ci-lock-mgr.sh` model), so it never wastes CPU re-spinning per image; done under one
mutex, so no lock-ordering/deadlock concern. The batch shares one owner token.

| Endpoint (POST)   | Query / headers                                | Result                                        |
|-------------------|------------------------------------------------|-----------------------------------------------|
| `/lock/acquire`   | `?name=a&name=b&ttl=30&wait=3600`, `X-Vk-Lock-Holder` | 200 `{owner, names, ttl}` \| 409 `{blockers:[{name,holder}]}` |
| `/lock/renew`     | `?name=a&name=b&ttl=30`, `X-Vk-Lock-Owner`     | `{renewed, of}` (fewer than `of` ⇒ lost part of the batch) |
| `/lock/release`   | `?name=a&name=b`, `X-Vk-Lock-Owner`            | `{released}` (count, `ci-lock-mgr.sh`-style)  |
| `/lock/status`    | `?name=a&name=b`                               | `{holders:[{name, holder}]}`                  |

`acquire` long-polls up to `wait`; the client retries until it wins or times out.
`ci-lock-mgr.sh` can retire its lock-only Redis by pointing `lock`/`release` at these
endpoints over `curl` (or a future `vk-registry lock` CLI mirroring its handle interface).

## Build-once flow (unifies virtkit + task)

Content-key `K` = the fingerprint each side already computes (virtkit `dockerhash`;
`task` `generates`/`sources` checksum):

1. HEAD `K` → hit ⇒ pull, done.
2. miss ⇒ `acquire-lock(K)` (lease + heartbeat).
3. re-check (someone may have pushed while we waited) ⇒ hit ⇒ pull.
4. else build → push (CDC chunks, dedup) → tag `K` → release.

Waiters block in step 2 and resume at step 3.

## `task` integration

`task`'s `oci://` cache transport works against `vk-registry` unchanged. Add **one** new
`lock.Locker` implementation with a `vk://` scheme in `task`, selected in
`evalCacheLocker` **alongside the existing `redis://`** (Redis stays as a fallback):

```yaml
cache:
  url:  oci://vk-registry.internal/task/mytask:<key>
  lock: vk://vk-registry.internal/task/mytask   # was redis://…
```

The `vk://` locker speaks the HTTP lock API above (acquire long-poll + heartbeat
goroutine + release-if-owner), matching the shape of `redis.Locker`.

## vk-optimized storage (client-side zstd chunk upload)

When the target is a `vk-registry` — it advertises `x-virtkit-transparent-zstd` on
`GET /v2/` — the `task` `ocicas` client uploads each chunk **already zstd-compressed**
client-side, instead of shipping raw bytes for the server to compress:

- the chunk's blob **digest is over the uncompressed bytes**, so dedup is
  compression-independent (the same content dedups regardless of who compressed it);
- the body is a zstd frame sent with `Content-Encoding: zstd`, the decompressed size
  recorded in the frame header, so the server reports a canonical `Content-Length` on
  HEAD without decompressing;
- the server stores the frame verbatim in `blobs/zstd/` and serves canonical bytes to
  plain clients, zstd frames to aware ones.

This is the Go twin of virtkit's `transparent_zstd` path (`registry.rs`), reusing the
same capability header, fixed `ZSTD_LEVEL`, and frame-content-size convention
(`zstd_with_size`) — so `vk-registry` handles `task` and virtkit uploads with one code
path. It cuts upload bandwidth and server CPU. "When doable" = capability-gated, and
adaptive: a chunk that does not shrink is uploaded identity (mirroring the server's
adaptive storage). Against a dumb OCI registry (no capability header) the client falls
back to plain raw upload. Cache-*pool* sharing with virtkit still depends on chunk
boundary alignment (see the note below); client-side compression is independent of that.

## Credential injection (opt-in, per VM)

Off by default; opt-in per VM via `vk run --registry-proxy <upstream-url>` (needs `--net`).
When set, `vk` runs a host-local reverse proxy (`regproxy.rs`) on loopback that forwards to
the upstream registry, injecting the runner's `--username`/`--password`/`--ca` credential
(`reqwest` Basic auth). The guest reaches it **credential-free** at `registry.vk` (a hint
also exported as `VIRTKIT_REGISTRY`). Delivery: the switch's resolver maps `registry.vk` to
an unroutable sentinel (`240.0.0.1`), and its TCP egress (`proxy_tcp`) special-cases that
sentinel — splicing the flow to the loopback proxy instead of egressing. So the proxy is
never bound to a network interface; it is reachable only through that per-VM redirect, and
the job never holds the secret. A guest that doesn't opt in has no such path.

The GitLab executor opts in runner-wide with `[registry] proxy_guests = true`: each job's
switch (`vm.rs`) starts the same `regproxy` forwarding to the host `[registry]` with its
credentials, exposed to the job at `registry.vk`. Proxy bodies stream both ways, so a job
pushing/pulling multi-GB layers through it never buffers a whole blob.

## Auth / TLS

Network-exposed: HTTPS with a server cert; clients authenticate with a bearer token or
Basic (per-runner or shared), same `[registry]` credential shape `registry.rs` already
builds (`ca_file`, `username`, `password_file`, `insecure`). The lock API and relay
share the listener and auth.

## GC / retention

Relay-cached and build-once objects are digest-pinned and (for cache tags) tagged, so
the existing `Store::gc` retention model applies: idle tags drop past a retention window;
digest-pinned manifests survive a grace window; unreferenced blobs are swept. A
**size-capped LRU** for the relay cache is the likely follow-up — the mtime bookkeeping
(`touch` on hit) is already in place.

## Store / dedup note

`task`'s `ocicas` chunker and virtkit's FastCDC (1/4/16 MiB) cut different boundaries, so
the two share the **server and blob store** but not necessarily the same *dedup pool per
artifact*. Correct as-is (artifacts self-describe); aligning chunkers for a shared pool
is a later optimization, not required.

## Implementation order

Each step is one concern, independently buildable.

1. **Extract the store.** New `vk-registry` lib with `Store` + helpers moved from
   `regserve.rs`; rewire `vk-driver` (`mod local`, `build.rs`/`run.rs` defaults) onto
   `vk_registry::Store`. Behaviour-neutral.
2. **Drop serving from `vk`.** Remove `registry serve` + `install-service` from the `vk`
   CLI; keep `push`/`pull`/`inspect`/`status`/`gc`. CHANGELOG.
3. **`vk-registry` bin, local-only.** `serve` (no upstreams) + `gc`/`status`/
   `install-service` — regserve serving as a standalone daemon.
4. **TLS + auth** for network exposure.
5. **Pull-through relay.** Multi-upstream namespace routing, digest-only caching,
   blobs streamed to disk (bounded memory), digest-referenced manifest persistence.
6. **Lock API.** In-process leased lock manager + the four endpoints.
7. **Build-once in runners.** `Executor::build_lock` (a `registry.rs` `BuildLock` guard,
   `LockClient` + heartbeat over `block_on`); `build_stage` takes it on the stage's final
   key, re-checks the cache, and restores instead of rebuilding when a peer won.
8. **`task` `vk://` locker.** New `lock.Locker`, wired in `evalCacheLocker` beside
   `redis://`.
9. **`task` vk-optimized upload.** Capability-detect `x-virtkit-transparent-zstd` in
   `ocicas`; compress chunks client-side (uncompressed-digest, `Content-Encoding: zstd`,
   frame content size), adaptive + fallback to raw for dumb registries.
10. **Credential injection.** `regproxy.rs` loopback proxy + the switch sentinel/DNS
    redirect, opt-in per VM (`vk run --registry-proxy`) or runner-wide for executor jobs
    (`[registry] proxy_guests`). Streams both ways.
11. **Ship.** `build.sh`/`release.yml`/`.gitlab-ci.yml` build + sign the third
    reproducible binary; README + AGENTS.md architecture section.

## Accounts, OIDC, and scoped API keys

Today's auth (`auth.rs`) is one shared secret for the whole server, checked before any
route dispatch — fine for a handful of trusted CI runners, not enough once humans need to
browse/upload through a UI and CI needs per-pipeline, revocable, scoped credentials. This
section adds accounts on top **without changing the content store or the existing
OCI/`lock` wire protocol** — `push`/`pull`/`inspect` against a shared-secret or
account-issued token behave identically, and the CAS layout is untouched (the root gains
one sibling directory for the accounts db); only *who is authorized for what* becomes
richer.

### New state: an embedded identity store alongside the CAS store

The store stays 100% filesystem (§ above). Everything identity-related — users, sessions,
API keys — goes in a new **`redb`** file, `<root>/accounts/accounts.db`. It gets a
directory of its own because `Db::open` creates that one `0700` itself, whereas the store
root's mode is whatever the ambient umask left (`002` is common), and a directory a group
member can write to lets them rename the db aside and plant one naming themselves admin —
`0600` on the file does not help.

**Not sqlite**: a bundled sqlite (`rusqlite`, `features = ["bundled"]`) does not *link*
under this project's musl cross-toolchain — `libsqlite3-sys`'s vendored `sqlite3.c` calls
the LFS64 symbols (`open64`, `stat64`, `fstat64`, `ftruncate64`, `fcntl64`, `pread64`,
`pwrite64`, `mmap64`, `lstat64`) directly, and this repo's `gcc`-as-musl-cc setup
(`.cargo/config.toml`) doesn't expose them the way a real musl cross-compiler's headers
would. `redb` is pure Rust (no C, no cc-rs build script), so it needs none of that and
links clean. This is the one new piece of infrastructure; content, GC, and locking are
untouched.

Three tables of JSON-blob rows (`vk-registry/src/accounts.rs`), keyed by stable strings
instead of an autoincrement id — `redb` has no natural `last_insert_rowid`, and stable
keys turn out to be available for free:

```
users     : "{oidc_issuer}\x1f{oidc_subject}" -> {email, display_name, is_admin, created_at, last_login_at}
sessions  : sha256(session_id) hex            -> {user_key, csrf_secret, created_at, expires_at}
api_keys  : sha256(bearer_token) hex          -> {owner_user_key, name, token_prefix, scopes,
                                                   created_at, expires_at, last_used_at, revoked_at}
```

Neither credential is stored in a replayable form: a session row is keyed by the *hash*
of its cookie value and an API key row by the hash of its bearer token, so a reader of the
db file holds nothing it can present to the server. A user's id *is* its OIDC identity
(issuer+subject need no separate index, and `\x1f` is what makes the pair unambiguous, so
an issuer or subject containing a control character is rejected on the way in); an API
key's id *is* its token hash (already irreversible, so it doubles as a safe-to-display
identifier for revoke calls — no separate id needed either, though a revoke is still
checked against the key's owner, since an id shown in a listing is not authority over it).
`scopes` = `[{"action":"read"|"write","repo_pattern":"team-a/*"}]`; `repo_pattern` matches
the same `<name>` used in `/v2/<name>/...` and `repos/<name>` on disk — no new naming
concept, and a pattern that could match no such name is refused when the key is made. A
key's secret is never stored: only its hash (the row's key) and `token_prefix` (the first
8 chars of the token's *random half* — not of the token, whose first 4 are the constant
`vkr_` — for identifying a key in a listing without showing enough of it to be usable).
`list_api_keys(owner)` is a linear scan over `api_keys` filtering by
`owner_user_key` — fine at this data's expected scale (one team/org's users and keys, not
a hot path), and it avoids needing a secondary owner→keys index.

### Principal + authz

A request resolves to at most one principal, cookie and bearer header being mutually
exclusive (bearer present ⇒ ignore any cookie):

```rust
enum Principal { Session(User), ApiKey(ApiKey) }
fn authorize(principal: &Principal, action: Read | Write, repo: &str) -> bool
```

Every `/v2/*` handler gains this check in place of today's global gate. `/lock/*` does
**not**: a scope is `(action, repo_pattern)` and a lock name is an arbitrary build-once key,
not a repository, so there is nothing for a pattern to match. The lock API stays gated on
being an authenticated principal at all — which means any key, however narrowly scoped, can
take and hold locks.
Session principals: any authenticated user gets **read-all**; **write** requires
`is_admin` or an explicit key (a human uploading through the browser still goes through an
API-key-shaped grant, just session-authenticated — see manual upload below). API-key
principals: hash the presented token, look up `api_keys`, reject if `revoked_at` is set or
`expires_at` has passed, then match `action`/`repo` against `scopes`; on success bump
`last_used_at`.

Credential lookup is on the request path, so it runs in a read transaction. An API key
lookup's only write is a `last_used_at` bump, coarse enough (a minute) that a push does not
pay an fsync per chunk and committed with `Durability::Eventual` — still a real commit,
just without the final barrier, because losing the last-seen time to a crash costs nothing.
A session found expired is deleted by the lookup that found it, which is one durable write
per dead cookie; a session someone comes back to is therefore reclaimed, one simply
abandoned is not, and a periodic sweep is deferred.

`authorize()`'s scope enforcement lands with the routes that need it (step 3 below); until
then an accounts-mode server accepts any resolved principal for anything, the same coarse
shape as the shared-secret mode it replaces.

`mode` is a top-level config key, like the credentials it chooses between, and an
unrecognized key in the file is an error — a mistyped or misplaced `mode` must not start
the server in the auth model the operator meant to replace. The existing shared-secret
`Auth` stays as `mode = "shared-secret"` (the default), mutually exclusive with
`mode = "accounts"` — cheap to keep, and useful for solo/dev use and for
bootstrapping the first admin before OIDC is reachable.

### OIDC login

`openidconnect` (pure Rust, pluggable HTTP client — reuses the existing `reqwest`+`rustls`
stack already linked for TLS and the relay). Routes, config shape, and the
state-nonce/target-passthrough flow mirror idaas's `assetserver` (`auth.go`), with three
deliberate fixes over that implementation:

- session cookie is `Secure` + `HttpOnly` + `SameSite=Lax` (assetserver sets none of the
  last two);
- a real per-session CSRF token guards state-changing forms — upload, key create/revoke
  (assetserver wires a CSRF key through config but never uses it);
- session expiry is decided once, at creation, and is not extended by use — assetserver's
  `LastUpdate` is set once and never renewed either, but there it is a bug rather than a
  choice; here a bounded absolute lifetime is the point, and it costs no per-request write.

```toml
[oidc]
issuer        = "https://login.example.com/app/…"
client_id     = "vk-registry"
client_secret_file = "/etc/vk-registry/oidc-secret"
public_url    = "https://registry.internal"
```

Routes: `/login`, `/auth/callback`, `/logout` (RP-initiated, same `end_session_endpoint`
discovery trick as assetserver). Identity is claims-based (`sub`, `email`) — a `users` row
is upserted on first login, not pre-provisioned.

### HTTP surface: browse, download, manual upload

New routes alongside the existing `/v2/` and `/lock/` prefixes in `route()`:

| Route                                | Auth    | Behavior                                                               |
|--------------------------------------|---------|------------------------------------------------------------------------|
| `/browse`                            | session | list repos — walks `repos/` (mirrors `Store::repo_dirs`)               |
| `/browse/<repo>`                     | session | list tags/manifests for one repo, filtered to what the caller can read |
| `/browse/<repo>/<ref>`               | session | manifest detail: layers, digests, sizes, download links                |
| `/upload` (GET form, POST multipart) | session | manual upload (see below)                                              |
| `/settings/keys`                     | session | list/create/revoke the caller's API keys                               |

Actual bytes are **not** re-served by new code: browse/download links point at the
existing `/v2/<name>/blobs/<digest>` and `/v2/<name>/manifests/<ref>` GETs, now gated by
`authorize()` instead of the global secret. `/browse` listings filter out repos the caller
can't read rather than 403ing the whole page (the one assetserver pattern worth copying
directly — `RegisterDirEndpoints` in `assetserver.go`).

**Manual upload shares the dedup store natively**: a file dropped through `/upload` is
turned into one blob (`Store::put_blob`, digest = sha256 of the file) plus a small
single-layer manifest (`Store::put_manifest`, a generic media type such as
`application/vnd.virtkit.raw-file`) tagged with the given `name:tag` — exactly the shape a
CI `push` produces. A human-uploaded artifact is therefore pullable by `vk registry pull`
with no special-casing, and a duplicate upload of already-known bytes costs no new disk —
this is the point of routing it through `Store` instead of a parallel raw-file tree like
assetserver's (which stores every upload as its own file, no dedup, reject-on-name-clash
instead of content-addressing).

### Implementation order

1. `redb`-backed `users`/`sessions`/`api_keys` + `Principal` resolution, behaviour-neutral
   until `mode = "accounts"` is set. `vk-registry/src/accounts.rs`, wired in
   `config.rs`/`lib.rs`.
2. OIDC login/callback/logout + read-only `/browse`, gated by session-read-all.
3. API key CRUD (`/settings/keys`) + `authorize()` enforcement on `/v2/*` write paths.
4. `/upload` (session-authed, writes through `Store` as a synthetic manifest+blob).
5. Optional: a `request_log` table (who pushed/pulled what, when) for audit.

## Deferred

- Size-capped LRU eviction for the relay cache.
- Aligning `task`/virtkit chunk boundaries for a shared dedup pool.
- Multi-replica `vk-registry` (would reintroduce an external lock backend — Redis/etcd —
  behind the same lock API). The accounts `redb` file is single-writer for the same
  reason; a multi-replica accounts story needs this resolved together with locking.
- A periodic sweep of expired sessions. A session presented again is dropped by the lookup
  that finds it stale; one abandoned without a further request is not, so the table grows
  with logins that are never returned to.
- Per-user custom scopes beyond `is_admin` (e.g. a non-admin user with a *scoped* session,
  not just all-or-nothing read-all) — start simple, revisit if a real need shows up.
- Audit log (`request_log`) — noted above as optional, not required for v1.
