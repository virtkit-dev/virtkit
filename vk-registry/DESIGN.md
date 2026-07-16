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
- **bin** is a thin CLI (`serve`/`gc`/`status`/`install-service`) over the lib.

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

Two net-new `Store` methods:

- **streaming tee** — relay upstream→client while writing to a store temp file, promote
  to `blobs/sha256/<hex>` on digest match; never buffer a multi-GB layer in memory.
- **`put_manifest_by_digest(digest, ctype, body)`** — cache a relayed manifest keyed by
  digest with no tag (tags are never persisted).

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

Not yet wired into the GitLab executor path (`vm.rs`/`JobCtx`), which would take its
upstream + credentials from the host `[registry]` config rather than CLI flags — a
follow-up reusing the same `regproxy` + switch redirect.

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
   streaming tee, `put_manifest_by_digest`.
6. **Lock API.** In-process leased lock manager + the four endpoints.
7. **Build-once in runners.** `Executor::build_lock` (a `registry.rs` `BuildLock` guard,
   `LockClient` + heartbeat over `block_on`); `build_stage` takes it on the stage's final
   key, re-checks the cache, and restores instead of rebuilding when a peer won.
8. **`task` `vk://` locker.** New `lock.Locker`, wired in `evalCacheLocker` beside
   `redis://`.
9. **`task` vk-optimized upload.** Capability-detect `x-virtkit-transparent-zstd` in
   `ocicas`; compress chunks client-side (uncompressed-digest, `Content-Encoding: zstd`,
   frame content size), adaptive + fallback to raw for dumb registries.
10. **Credential injection.** `vk run --registry-proxy` opt-in: `regproxy.rs` loopback
    proxy + the switch sentinel/DNS redirect. (Executor path is a follow-up.)
11. **Ship.** `build.sh`/`release.yml`/`.gitlab-ci.yml` build + sign the third
    reproducible binary; README + AGENTS.md architecture section.

## Deferred

- Size-capped LRU eviction for the relay cache.
- Aligning `task`/virtkit chunk boundaries for a shared dedup pool.
- Multi-replica `vk-registry` (would reintroduce an external lock backend — Redis/etcd —
  behind the same lock API).
