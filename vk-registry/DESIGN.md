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

Every `/v2/*` write/read branch calls `authorize()` in place of today's global gate
(`/lock/*` still stops at authentication — see the module doc for why). Session
principals: any authenticated user gets **read-all**; **write** requires `is_admin`
(a human uploading through the browser is still session-authenticated with no
separate key — see manual upload below; there is no per-user "repos I own" model yet,
so admin-only is the deliberately simple starting point). API-key principals: hash the
presented token, look up `api_keys`, reject if `revoked_at` is set or `expires_at` has
passed, then match `action`/`repo` against `scopes` (bumping `last_used_at` on success);
`authorize()` itself just checks `scopes.iter().any(|s| s.allows(action, repo))` once a
key has resolved.

Credential lookup is on the request path, so it runs in a read transaction. An API key
lookup's only write is a `last_used_at` bump, coarse enough (a minute) that a push does not
pay an fsync per chunk and committed with `Durability::Eventual` — still a real commit,
just without the final barrier, because losing the last-seen time to a crash costs nothing.
A session found expired is deleted by the lookup that found it, which is one durable write
per dead cookie; a session someone comes back to is therefore reclaimed, one simply
abandoned is not, and a periodic sweep is deferred.

`authorize()` (`accounts.rs`) gates every `/v2/*` branch (`blobs/uploads`,
`blobs/<digest>`, `manifests/<reference>`, `tags/list`) through `authorize_or_forbidden`
in `route()`, and filters `/browse`: a principal is shown only the repositories it may
read, and one it may not read answers 404 rather than 403, so a listing does not confirm
what it excludes. `/settings/keys` (`keys.rs`) is a session-only, CSRF-protected API-key
UI; minting a **write**-scoped key needs an admin session, since a plain session cannot
write and must not be able to mint itself a key that can. Granting admin has no HTTP route
at all: it is `set_admin`, and the `vk-registry accounts` CLI (step 5 below) is how an
operator reaches it.

`/lock/*` stays authentication-only: a lock name is a build key, not a repository name,
so there is nothing per-repo to check against. The consequence is that any principal,
including a read-only key, can take a build-once lock and see other holders' names in a
`blockers` list — acceptable while every principal on a registry is a colleague, and the
thing to revisit if that stops being true.

Two limits worth stating plainly, both about the content-addressed store being shared by
every repository:

- **Blob reads are not repo-scoped.** `GET /v2/<name>/blobs/<digest>` checks `Read` on
  `<name>`, then looks the digest up in the global CAS: a caller who learns a digest can
  fetch it through any repository it may read. Manifests and tags are what scoping
  protects, and they are where digests come from — so this matters only against a caller
  who obtains a digest another way. Per-repo blob membership is deferred.
- **A key's scopes are bounded at the route, not in the store.** `create_api_key` takes
  the scopes it is given, so it is `/settings/keys` that refuses a plain session a
  `Write` key — without that check a session which may only read could mint itself one
  that writes. Any later caller of `create_api_key` owes the same check. The bound is at
  creation time only: revoking someone's admin with `set_admin` leaves the write-scoped
  keys they already minted live, so demoting an admin means revoking their keys too.
- **Writes cannot claim a digest they did not produce.** `finish_upload` hashes the bytes
  and refuses a mismatch, and an upload session records the repository it was opened for,
  so a caller cannot start an upload where it may write and finish it where it may not.
  Session ids carry a random tail for the same reason.

`mode` is a top-level config key, like the credentials it chooses between. An
unrecognized key anywhere in the file, `[oidc]` included, is an error: a mistyped or
misplaced `mode` must not start the server in the auth model the operator meant to
replace. The existing shared-secret `Auth` stays as `mode = "shared-secret"` (the
default), mutually exclusive with `mode = "accounts"` — cheap to keep, and useful for
solo/dev use and for bootstrapping the first admin before OIDC is reachable.

### OIDC login

Hand-rolled against the Authorization Code flow (`vk-registry/src/oidc.rs`) — no OIDC
crate, deliberately: it keeps this on the crate's existing `reqwest`+rustls TLS backend
instead of risking a second TLS stack (openssl/aws-lc-rs) pulled in by an OIDC crate's own
HTTP-client feature flags (see `Cargo.toml`'s comments on why that dependency shape is
worth protecting), and the flow itself is short enough not to need one: discover, redirect,
exchange a code for a token, then call UserInfo for claims — the same shape idaas's
`assetserver` uses (`auth.go`), and enough for a confidential client (this server holds a
`client_secret`) without also parsing/verifying the id_token's JWT locally — that
verification is what a full OIDC crate would buy back, and it is not needed for
correctness here because the code→token exchange is itself an authenticated,
server-to-server, TLS request.

What the flow relies on, and what it deliberately does not:

- the login `state` is **bound to the browser that started the login**: `/login` puts it
  in an `HttpOnly` cookie as well as in a server-side map, and the callback requires the
  two to agree. Single-use and a 5-minute TTL are replay protection; the cookie is what
  makes `state` CSRF protection. Without it, an attacker who completes a login at the
  provider can hand a victim the callback URL and log the victim in **as the attacker** —
  which, once `/upload` and `/settings/keys` land, means the victim pushing into the
  attacker's account. `assetserver` has this same gap;
- **PKCE (S256)** is sent even though this is a confidential client. The secret protects
  the exchange but not against code *injection* — a code that leaks through a
  provider-side open redirect, a `Referer`, or a proxy log is otherwise redeemable
  against a victim's callback. RFC 9700 asks for PKCE here for exactly that;
- the **id_token's JWT is not parsed or verified**, and does not need to be: claims come
  from UserInfo over a bearer token this server obtained itself in a TLS request it
  authenticated, and the identity namespace is the *configured* issuer, never one the
  provider asserts. What verification would add — binding the token to this client and
  this exchange — PKCE and the cookie-bound state already cover;
- the **discovery document is checked against the configured issuer**, and both `issuer`
  and `public_url` must be `https` unless loopback: every endpoint the flow uses comes out
  of that document, so whoever can substitute it chooses who logs in;
- the session and login cookies are `HttpOnly` + `SameSite=Lax` + `Secure` whenever the
  browser's connection is HTTPS — TLS terminated here *or* at a proxy, which is what
  `public_url` says (`accounts::set_cookie_header`). Unconditional `Secure` would silently
  break the loopback-plaintext deployment `ServerConfig` allows; `assetserver` sets neither
  of the first two attributes;
- wherever `Secure` is possible, both cookies are **`__Host-` prefixed**
  (`__Host-vk_session`, `__Host-vk_login`). Without the prefix, any host that can set a
  cookie for a parent or sibling domain — a neighbouring app under the same registrable
  domain, a plaintext sibling with a network attacker in front of it — can *toss* a cookie
  in, which is session fixation on one and, on the other, the very thing the browser
  binding above exists to stop. The prefix costs the login cookie its `/auth/callback`
  path scoping (it mandates `Path=/`), which is the lesser property. On the
  loopback-plaintext deployment the prefix is impossible, so the bare names are used and
  that protection is simply absent — one more reason that deployment is loopback-only.
  Reading is **strict**, which is where the protection actually lives: a request is
  searched for only the name this deployment would have *written*, never both. A bare
  cookie on a TLS deployment can only be one another host tossed in, so accepting it as a
  fallback would hand the prefix straight back. The price is that turning TLS on or off
  invalidates every live session and in-flight login, since the names change with it;
- **only the discovery document's origin is authenticated by the issuer comparison, not
  the URLs inside it**, so every endpoint it names is separately required to be `https`
  (or loopback `http`) and free of anything a header would refuse. A `Location` this
  server hands a browser, and a request carrying the client secret, both come from there;
  an `end_session_endpoint` that fails the check is dropped, leaving logout local-only,
  rather than failing discovery and with it every login;
- in-flight logins are **capped, and at the cap the oldest are evicted** rather than the
  new login refused: `/login` needs no credential, so refusing would let one flood close
  sign-in for everybody until the TTL ran out;
- `email_verified` is **not consulted**, and identity is `(issuer, sub)` — never the
  email, which is display-only. Anything that later authorizes on an email address has to
  revisit that;
- `?target=` (where to land back after login) is an **allowlist**: a `/browse` path made
  of `[A-Za-z0-9._:/-]`, nothing else. A denylist would have to anticipate every form a
  browser reads as off-origin (`//host`, `/\host`, a tab or newline before either);
- **`/logout` is a POST carrying the session's CSRF secret**, which `/browse` renders as
  a form once it lands. A link would let any page on the internet end a visitor's session
  with an `<img src>` — and, chained with a forced login, swap it for someone else's. A
  request with no session cookie — which is every cross-site POST, the cookie being
  `SameSite=Lax` — is answered with a bare redirect and no `Set-Cookie`, so it cannot
  force a re-login either;
- login **supersedes the browser's previous session** (the old row is deleted), so a
  re-login does not leave a second live credential behind for up to `SESSION_TTL`;
- the provider is **discovered lazily, at the first login**, and cached. Discovery at
  startup would mean a briefly unreachable IdP stopping a server whose `/v2/` clients
  never touch OIDC from starting at all.

Tested against an in-process fake IdP (`oidc.rs`'s tests — the same "spin up a real server
on an ephemeral port" pattern `tests/relay_e2e.rs` uses for its fake upstream), covering
discovery (including a document that states somebody else's issuer, and one naming a
cleartext endpoint), the authorization-URL shape, both client-authentication methods, the
cookie-binding refusals, the state TTL and the eviction at the cap, and the
code→token→claims exchange — without a live external IdP. The cookie naming, the
`/logout` CSRF comparison and the redirect-target allowlist are unit-tested directly,
and `tests/relay_e2e.rs` covers the session cookie end to end through a real server.

The claims kept from a login (`email`, `name`) are bounded and stripped of control
characters where they enter the store (`accounts::upsert_user`), not at the login handler,
so the `accounts` CLI and any later caller get the same treatment. An identity's two
halves are refused rather than truncated: they are a key.

Three limits worth knowing before this faces a real IdP:

- **any identity the provider authenticates gets a session**, with the coarse read/write
  every resolved principal has until the per-scope commits land. There is no
  email-domain, group, or audience restriction in `[oidc]`, so pointing it at a
  multi-tenant issuer (`login.microsoftonline.com/common`, say) means every account at
  that issuer, not every account in the org. Point it at a tenant-specific issuer.
- **the OIDC client trusts the platform roots only.** Unlike a relay `[[upstream]]`, which
  takes a `ca_file`, an IdP behind a private CA is not configurable here — and it fails at
  the first login, not at startup, because discovery is lazy.
- **the discovery document is fetched once and cached for the process's life**, so a
  provider that moves an endpoint needs a restart.

A login's two db writes (upsert the user, mint the session) run inline on the hyper
worker, as `resolve_principal` does — human-scale volume, so not worth a `spawn_blocking`
yet. Revisit together, if the accounts store ever moves off the request thread.

One deliberate divergence from the original plan: **session lifetime is a fixed 8-hour
absolute TTL (`accounts::SESSION_TTL`), not sliding.** A sliding expiry needs a write on
every authenticated request just to bump a timestamp; a bounded absolute lifetime gets
"a stolen cookie has a bounded shelf life" for free and is what actually shipped.
Revisit if 8 hours of forced daily re-login turns out to be the wrong trade.

```toml
[oidc]
issuer              = "https://login.example.com/app/…"
client_id           = "vk-registry"
client_secret_file  = "/etc/vk-registry/oidc-secret"
public_url          = "https://registry.internal"
```

Routes: `GET /login` (redirects to the provider, `?target=` says where to land back),
`GET /auth/callback`, `POST /logout` (RP-initiated if the provider advertises
`end_session_endpoint`, local-only otherwise — either way the session is deleted).
Identity is claims-based (`sub`, `email`, `name`, each bounded on the way in) — a `users`
row is upserted on first login, not pre-provisioned. All three routes are exempt from the
accounts-mode auth gate in `route()` (a login page gated on already being logged in would
be unreachable) and 404 if accounts mode/`[oidc]` isn't configured. They answer a browser
with HTML, not the OCI JSON error envelope, and never reflect the internal error chain:
what went wrong goes to the log.

### HTTP surface: browse, download, manual upload

New routes alongside the existing `/v2/` and `/lock/` prefixes in `route()`:

| Route                                          | Auth                                | Behavior                                        |
|------------------------------------------------|-------------------------------------|-------------------------------------------------|
| `/browse`                                      | any principal, scope-filtered       | list repos, via `Store::repo_names`/`list_tags` |
| `/browse/<name>`                               | any principal, `Read` on `<name>`   | list tags for one repo                          |
| `/browse/<name>/manifests/<reference>`         | any principal, `Read` on `<name>`   | manifest detail: layers, digests, sizes, links  |
| `/upload` (GET form, POST multipart)           | session, `Write` — i.e. admin | manual upload (see below), CSRF-protected       |
| `/settings/keys`, `/settings/keys/<id>/revoke` | session                             | the caller's own API keys, CSRF-protected       |

`/browse` exists **only in accounts mode**: it is the one surface that *enumerates*
repository names (there is no `/v2/_catalog` here), so a shared-secret server — where an
open `Auth::None` is an ordinary local configuration — 404s it rather than handing out the
store's inventory. An unauthenticated browser in accounts mode is redirected to
`/login?target=<path>` (not the bare 401 an OCI/CI client gets on `/v2/*`); scope
filtering of *what* a session may see lands with `authorize()`.

Reference disambiguation reuses the OCI API's own marker instead of inventing one:
`<name>/manifests/<reference>` is the exact split `route()`'s `/v2/` handling already does
(`rest.rfind("/manifests/")`), so a name containing slashes (`bundles/appbuilder`) reads
the same on both surfaces — a repository whose own name ends in `manifests` is the one
case that stays ambiguous, on `/v2/` equally. Actual bytes are **not** re-served by
`browse.rs`: its download links point at the existing `/v2/<name>/blobs/<digest>` GET,
authenticated by the same session cookie, and a descriptor digest that is not a digest is
rendered as inert text rather than linked — manifest JSON is pushed content, so a
`../../../v2/other/blobs/…` in it must not become a link. Every page is
`Cache-Control: no-store` with `nosniff`, `no-referrer`, and a `default-src 'none'` CSP:
it renders one person's identity over the store's inventory, and nothing on it loads a
remote resource.

**Manual upload shares the dedup store natively**: a file dropped through `/upload`
(`upload.rs`) is turned into one blob (`Store::put_blob`, digest = sha256 of the file)
plus a small single-layer manifest (`Store::put_manifest`; the *layer's* media type is
`application/vnd.virtkit.raw-file`, with the original filename — bounded, since it is
client-supplied — as an `org.opencontainers.image.title` annotation) tagged with the
given `name`/`tag`. The bytes come straight back over the ordinary OCI API:
`GET /v2/<name>/manifests/<reference>` then `GET /v2/<name>/blobs/<digest>`.

It is **not** a `vk` bundle: `vk registry pull` wants a `BundleConfig` and
`CHUNK_MEDIA_TYPE` layers and refuses this shape. A raw file here is for fetching, not
for booting — the point of routing it through `Store` is dedup and one storage path, not
`vk` compatibility. A duplicate upload of already-known bytes costs no new disk (config,
layer, *and* manifest all dedup when the file, filename and manifest shape are identical
— a manifest carries no repo/tag of its own), where assetserver's parallel raw-file tree
stores every upload as its own file, with no dedup and a reject-on-name-clash rule
instead of content-addressing. Uploading to an existing tag repoints it, exactly as a
`/v2/` push does.

The file is held in memory to hash it, so the form caps an upload at just under 64 MiB
(the cap covers the part's framing too); anything
larger belongs in `vk registry push`, which streams. The multipart body is parsed as it
arrives by a small hand-rolled scanner (`upload.rs`'s `Scanner`) rather than a crate:
what is needed is "the next complete part", and the crates on offer carry a
charset-transcoding dependency for a feature this never uses — the same reasoning behind
the hand-rolled cookie and query parsing elsewhere in this crate. Parts are acted on in
arrival order, and the form emits `csrf`, `name`, `tag` before `file`, so a caller who
fails CSRF or the write check is refused after a few hundred bytes instead of after the
whole upload; a body that puts `file` first is refused for that reason.

Like `/settings/keys`, `/upload` is session-only — an API key already has a purpose-built
path (`vk registry push`) — and CSRF-protected the same way (the session's `csrf_secret`
as a hidden form field). Write still means `is_admin` (via the same `authorize()` every
`/v2/*` branch uses), so today only an admin session can upload. Proven with real
multipart POSTs over HTTP in `tests/upload_e2e.rs`, including the dedup claim, the
readback over `/v2/*`, and each refusal.

### `vk-registry accounts` — the operator CLI

Grants and API-key management that intentionally have no HTTP route (`set_admin`) live in
`accounts_cli.rs`, under `vk-registry accounts <subcommand>`:

```
vk-registry accounts list-users
vk-registry accounts grant-admin  <EMAIL> [--issuer URL]
vk-registry accounts revoke-admin <EMAIL> [--issuer URL]
vk-registry accounts list-keys  [--owner-email EMAIL] [--issuer URL]
vk-registry accounts revoke-key <ID>
vk-registry accounts create-key --name NAME --scope ACTION:PATTERN [--owner-email EMAIL] [--expires-days DAYS]
```

Each takes the `--root`/`--config` store-selection flags `status`/`gc` already do, plus
an `--accounts-db` that replaces them and may not be combined with them
(`ServerConfig::accounts_db_of`, mirroring
`root_of`). It opens the same db a server would, which means **the server has to be
stopped**: redb holds an exclusive `flock` for the life of the process, so a running
`serve` locks out even `list-users`. The CLI also never *creates* a db — a mistyped
`--root` is an error naming the path, not an empty db and a truthful-looking "no users
yet".

Users are selected by their OIDC `email` claim, matched case-insensitively over ASCII. An
email is
an unverified, provider-controlled claim, and two providers can assert the same one, so
when it matches more than one account the CLI refuses and prints the `--issuer` that
would narrow it — it never guesses. A key is selected by the id `list-keys` prints in
full (its token hash — see `accounts.rs`'s `ApiKey::id`); `revoke-key` cannot tell an
unknown id from an already-revoked one and reports both the same way.

This is deliberately **not** gated by `authorize()`: an operator who can run this CLI
already has filesystem access to the accounts db, the same trust level `set_admin`
(called with no HTTP route at all) already assumed. Two consequences to know. A key's
scopes are its own, so `create-key` can give a non-admin user a write-scoped key and
`revoke-admin` does not revoke it — which is why `list-keys` prints each key's owner. And
revoking the last admin is allowed; this CLI is the way back.

`create-key --owner-email` is optional: omit it for a **system key**, `owner_user_id:
None` at the `Db::create_api_key` layer, which supported this from the start with nothing
above it exposing it. This is the CI case: a key tied to a person keeps working with
rights that person has since lost — `authorize()` for an `ApiKey` principal reads the
key's own `scopes` and never the owner's `is_admin` — so tying a pipeline's credential to
an individual buys nothing and misleads an audit. `list-keys` labels such a key's owner
`(system)`.

The trade is that an ownerless key has no owner to check a revoke against, so
`/settings/keys` cannot reach it and `revoke_api_key_unchecked` — this CLI — is the only
path. Revoking a leaked system key therefore means stopping the registry. A `write:*`
system key is an unattended credential that may push to every repository; nothing stops
an operator minting one, and nothing but this CLI takes it away again.

### Implementation order

1. `redb`-backed `users`/`sessions`/`api_keys` + `Principal` resolution, behaviour-neutral
   until `mode = "accounts"` is set. `vk-registry/src/accounts.rs`, wired in
   `config.rs`/`lib.rs`.
2. OIDC login/callback/logout (`oidc.rs`) + read-only `/browse`, gated by
   session-read-all.
3. API key CRUD (`keys.rs`, CSRF-protected) + `authorize()` enforcement on every
   `/v2/*` branch (`lib.rs`'s `authorize_or_forbidden`) and scope-filtering on `/browse`.
   That enforcement presumes two things the write path establishes first: a blob is
   stored only under a digest the server itself hashed the bytes to, and an upload
   session can only be finished into the repository it was opened in — otherwise a
   per-repo scope check on `POST .../uploads/` says nothing about where the blob lands.
4. `/upload` (`upload.rs`, session-authed + CSRF-protected, admin-only write, writes
   through `Store` as a synthetic manifest+blob).
5. `vk-registry accounts`, the CLI that grants admin and manages accounts and keys with
   no HTTP route to do it through.
6. Optional: a `request_log` table (who pushed/pulled what, when) for audit.

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
