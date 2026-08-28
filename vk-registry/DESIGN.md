# vk-registry design

`vk-registry` is a central OCI Distribution server for virtkit runners. It provides three
services behind one listener:

- a content-addressed OCI store shared by all runners;
- a pull-through cache for upstream registries; and
- a leased lock service that coordinates build-once work across runners.

The server is intended to run on a dedicated host or as a user service. Local virtkit use
does not require it: `vk` uses the same `Store` implementation directly for its default
on-disk build cache.

The design favors a single authoritative process and a local filesystem over external
coordination services. Writes and garbage collection are coordinated on that host, and
individual file publications are atomic. Multi-replica operation is explicitly out of
scope.

## Architecture

The `vk-registry` crate contains both the reusable store library and the server binary.
The library provides the store, OCI routes, pull-through relay, build lock service, and
authentication. In accounts mode it also provides OIDC login, browser, upload, and local
administration surfaces.

The binary provides `serve`, `status`, `gc`, `install-service`, `accounts`, and `update`.
`vk-driver` depends on the library only for `Store`; it does not run the HTTP server in
process.

One `ServerState` owns the store, upstream configuration, lock manager, authenticator,
and optional TLS acceptor. Request handlers share it through `Arc`.

## Content store

The store is content-addressed by the SHA-256 digest of the canonical, uncompressed bytes.
Repository names and tags are metadata over that shared blob pool.

```text
<root>/
  blobs/sha256/<hex>            canonical bytes
  blobs/zstd/<hex>              zstd frame of the canonical bytes
  repos/<name>/tags/<tag>       manifest digest referenced by the tag
  repos/<name>/manifests/<hex>  manifest media type and repository membership
  repos/<name>/blobs/<hex>      blob membership marker
  uploads/<id>                  in-progress upload
  uploads/owners/<id>           repository that opened the upload
  accounts/accounts.db          account data, when accounts mode is enabled
```

The `sha256` and `zstd` directories are two physical encodings of the same logical
namespace. A digest always identifies the uncompressed bytes. Deduplication is therefore
independent of whether a client or the server performed compression.

Writes are staged under the store root, verified, and renamed into place. Staging and
destination paths are on the same filesystem, so the rename is atomic. Store operations
also use an advisory lock so the in-process `vk` cache, `vk-registry`, `status`, and `gc`
can safely share a root.

Repository path components named `tags`, `manifests`, or `blobs` are rejected. Those names
are structural delimiters in the layout; accepting them would make repository discovery
and garbage collection ambiguous.

## OCI Distribution API

The server implements the subset of OCI Distribution v2 required by virtkit and ordinary
OCI clients:

- registry capability probing through `GET /v2/`;
- blob `GET` and `HEAD`;
- monolithic and chunked blob uploads;
- manifest `GET`, `HEAD`, and `PUT`; and
- tag listing.

An upload is bound to the repository that opened it. Finishing an upload recomputes the
digest and rejects a mismatch, so a caller cannot claim content it did not send or finish
an authorized upload in a different repository.

Manifest uploads are limited to 4 MiB and 4,096 distinct digest references. These limits
bound both memory use and the authorization work performed while the store lock is held.

Only recognized OCI and Docker manifest media types are served as such. Parameters are
removed and matching is case-insensitive. Unrecognized types are served as
`application/vnd.oci.image.manifest.v1+json`. Manifest, blob, and error responses include
`X-Content-Type-Options: nosniff`; a writer cannot use a manifest media type to serve active
content from the browser application's origin.

### Transparent zstd uploads

`GET /v2/` advertises `x-virtkit-transparent-zstd`. A client that recognizes the header may
send a zstd frame with `Content-Encoding: zstd` while retaining the digest of the
uncompressed bytes.

The frame must include its decompressed size. This lets the server answer `HEAD` with the
canonical content length without decompressing the blob. The server stores the frame
verbatim and either serves it to an aware client or decompresses it for an ordinary OCI
client. Compression is adaptive: content that does not shrink is stored and uploaded in
canonical form. Clients that do not see the capability header use standard identity
uploads.

Serving is symmetric. A blob `GET` reads the stored file a chunk at a time at the client's
pace, decoding a stored frame on the way out for a client that cannot take zstd, so no
response holds a whole layer in memory.

## Pull-through relay

Each request checks the local store first. On a miss, the server selects an upstream by
longest-prefix match against the repository name. The selected prefix is removed before the
request is sent upstream.

For example, `docker.io/library/alpine` matches the `docker.io` upstream and requests
`library/alpine` from Docker Hub.

```toml
[[upstream]]
prefix = "docker.io"
url = "https://registry-1.docker.io"

[[upstream]]
prefix = "ghcr.io"
url = "https://ghcr.io"
```

An omitted prefix is a catch-all. Upstreams may specify Basic credentials and an additional
CA certificate. Bearer challenges from upstream registries are handled by the OCI client.

| Request | Behavior on a local miss | Persisted locally |
|---|---|---|
| `GET` blob by digest | fetch, hash, and stream | yes |
| `HEAD` blob by digest | return the local result | no relay |
| `GET`/`HEAD` manifest by digest | fetch and verify | yes |
| `GET`/`HEAD` manifest by tag | resolve and relay | no |

Only explicitly digest-addressed content is persistent. Tags are mutable and are resolved
upstream on every request.

Relayed blobs stream into a temporary file with bounded memory. The server hashes the bytes
as they arrive, verifies the requested digest, and promotes the file only after successful
verification. Promotion applies the same adaptive choice as an upload — compressed when that
shrinks the bytes, identity otherwise — decided before the store lock is taken.
Digest-addressed manifests follow the normal manifest write path without creating a tag.

Blob `HEAD` deliberately describes local storage rather than upstream availability. This
supports the push deduplication protocol: `vk push` skips an upload after a successful
`HEAD`, so relaying an upstream hit would cause the client to omit content this store does
not own. On a cold pull-through repository, `HEAD` may therefore return 404 while the
corresponding `GET` succeeds and warms the cache.

## Repository-scoped content

The blob pool is global, but knowledge of a digest is not authorization to read its bytes.
Accounts mode records repository membership explicitly:

```text
repos/<name>/blobs/<hex>
repos/<name>/manifests/<hex>
```

Membership is created only when the registry has verified possession for that repository:

- a completed upload whose bytes match the requested digest;
- a relayed blob fetched and verified for the repository;
- a stored manifest; or
- a cross-repository mount validated during manifest upload.

A manifest reference alone does not establish membership. A caller can submit a manifest
without possessing the blobs it names, so inferring membership from references would turn
write access into a digest-enumeration read primitive.

A blob or digest-addressed manifest is readable through a repository when that repository
has a membership record, or when the principal may read another repository that has one.
The second rule preserves cross-repository deduplication without disclosing bytes the
principal could not already fetch. The common pull path is one membership lookup; only a
miss searches the repositories the principal may read.

A manifest `PUT` succeeds only if every referenced digest is already readable by the
caller. Accepted references receive membership in the target repository. Validation and
write run under the same store lock, preventing `gc` from removing a referenced blob
between them. Image indexes are traversed when establishing membership, including their
child manifest digests.

The explicit OCI cross-repository blob mount endpoint is not implemented. A client that
requests it receives a normal upload session and may fall back to uploading. `vk push`
already obtains the useful deduplication behavior through blob `HEAD` followed by membership
creation at manifest `PUT`.

Stores created before membership records were introduced are not migrated automatically.
They must be repopulated by pushing the content again. Reconstructing membership from old
manifests would violate the authorization rule above.

Shared-secret mode treats every repository as readable and bypasses membership checks, so
existing unscoped deployments retain their behavior.

## Authentication and authorization

The server has two mutually exclusive authentication modes. Configuration parsing rejects
unknown keys and rejects account settings in shared-secret mode, preventing a misspelled or
misplaced setting from silently selecting a weaker model.

Credentials on a non-loopback listener require TLS. Plain HTTP remains available on
loopback.

### Shared-secret mode

Shared-secret mode is the default. It supports one bearer token, one Basic username and
password, or no authentication. It is suitable for a trusted CI environment and local use,
but does not provide per-user identity or repository scopes.

### Accounts mode

Accounts mode separates human and machine credentials:

- humans authenticate through OIDC and receive a session cookie;
- machines authenticate with scoped API keys; and
- operators manage administrators and system keys through a local Unix socket, or directly
  through the accounts database while the server is stopped.

The account database is a `redb` file at `<root>/accounts/accounts.db` by default. `redb` is
pure Rust and fits the project's static-musl build. The containing directory is created with
mode `0700`; protecting only the file would not prevent replacement by a user who can write
its parent directory.

```text
users         (issuer, subject) -> profile, admin flag, timestamps
sessions      sha256(cookie)    -> user, CSRF secret, timestamps
api_keys      sha256(token)     -> owner, name, prefix, scopes, timestamps
repo_captions repository name   -> one-line caption
```

Session IDs and API-key secrets are never stored directly. User identity is the OIDC
`(issuer, subject)` pair; email is display and operator-selection metadata, not identity.
Claims and captions are bounded, stripped of control characters where appropriate, and
escaped when rendered.

An API-key scope contains an action (`read` or `write`) and a repository glob such as
`team-a/*`. Invalid repository patterns are rejected when the key is created. An
Authorization header takes precedence over a session cookie, so each request resolves to at
most one principal.

Authorization rules are intentionally small:

- every authenticated session may read every repository;
- only an administrator session may write;
- an API key may perform an action only when one of its scopes matches the repository; and
- any authenticated principal may use the lock API.

OCI and browser routes authorize before accessing repository content. A browser request for
a repository the principal cannot read returns 404 rather than revealing its existence with
403.

API-key lookup rejects expired and revoked keys. `last_used_at` is updated at most once per
minute with eventual durability so blob traffic does not force an fsync. Expired sessions
are removed when presented; abandoned expired sessions are not swept periodically.

API-key permissions are self-contained. Demoting an administrator does not revoke keys the
administrator previously created, and changing a user's privileges does not alter an owned
key. Operators must revoke those keys separately. System keys have no owner and can only be
revoked through the operator CLI.

## OIDC and browser sessions

OIDC uses the Authorization Code flow with discovery, PKCE S256, and UserInfo. The server is
a confidential client and holds a client secret. Provider discovery is lazy and cached for
the process lifetime, allowing OCI traffic to continue when the identity provider is
temporarily unavailable at startup.

```toml
mode = "accounts"

[oidc]
issuer = "https://login.example.com"
client_id = "vk-registry"
client_secret_file = "/etc/vk-registry/oidc-secret"
public_url = "https://registry.example.com"
```

The login routes are `GET /login`, `GET /auth/callback`, and `POST /logout`. They exist only
in accounts mode. Human-facing unauthenticated requests redirect to login; OCI, lock, and
unknown API requests receive an authentication challenge.

The login flow enforces the following properties:

- `state` is single-use, expires after five minutes, and is bound to the initiating browser
  with an HTTP-only cookie;
- PKCE binds the authorization code to the initiating login;
- discovery must report the configured issuer;
- every discovered endpoint must use HTTPS, except loopback HTTP;
- redirect targets are restricted to safe local `/browse` paths;
- sessions have a fixed eight-hour lifetime rather than sliding expiration; and
- logout is a CSRF-protected POST that deletes the server-side session.

Session and login cookies use `HttpOnly`, `SameSite=Lax`, and `Secure` when the public
connection uses HTTPS. Secure deployments use `__Host-` cookie names. Cookie lookup accepts
only the name appropriate to the deployment, so switching between HTTP and HTTPS invalidates
existing sessions and in-flight logins.

Identity claims come from UserInfo over the access token obtained by the authenticated token
exchange. The ID token is not used as an identity source. Any identity accepted by the
configured provider can sign in; deployments that require tenant isolation must configure a
tenant-specific issuer.

## Browser and manual upload surfaces

Accounts mode exposes a small HTML interface:

| Route | Access | Purpose |
|---|---|---|
| `/browse` | authenticated, scope-filtered | list readable repositories |
| `/browse/<name>` | repository read | list tags |
| `/browse/<name>/manifests/<reference>` | repository read | inspect a manifest |
| `/upload` | administrator session | upload one raw file |
| `/settings/keys` | session | manage the caller's API keys |

Shared-secret mode returns 404 for `/browse`; an unauthenticated local registry must not
accidentally expose a repository catalog. Browser pages use `Cache-Control: no-store`, a
`default-src 'none'` content security policy, `nosniff`, and a no-referrer policy.

Downloads use the normal `/v2/` blob routes and therefore pass through the same
authorization checks. Digest-like values from manifest JSON are validated before becoming
links.

Manual upload stores a file as one blob plus a single-layer OCI manifest tagged with the
requested repository and tag. The layer uses `application/vnd.virtkit.raw-file`; the
original filename is stored as a bounded OCI title annotation. Identical content
deduplicates through the normal store.

A manually uploaded file is not a bootable virtkit bundle. `vk registry pull` expects a
`BundleConfig` and virtkit chunk layers and rejects the raw-file manifest shape.

The browser upload request is capped at 64 MiB and buffers the file in memory. Larger
content must use an OCI client such as `vk registry push`, which streams uploads. The
multipart parser requires the CSRF token, repository, and tag before the file part so
unauthorized requests are rejected before a large body is accepted.

Repository captions are administrator-editable, one-line plain text stored in the accounts
database. They are not garbage-collected with repository content; deleting and later
recreating a repository restores its previous caption unless an administrator cleared it.

## Build-once lock service

The registry process is the authority for leased locks. No Redis or shared filesystem lock
is involved in the request path. Locks are process-local: restarting the server releases all
leases.

Locks are keyed by content fingerprint. A lease defaults to 30 seconds and clients renew it
periodically. An expired lease is reclaimed automatically. Only the opaque owner token
returned by the server can renew or release a lease.

All lock operations use `POST` and repeat names as `?name=` parameters:

| Endpoint | Required input | Result |
|---|---|---|
| `/lock/acquire` | `ttl`, `wait`, `X-Vk-Lock-Holder` | owner token or blockers |
| `/lock/renew` | `ttl`, `X-Vk-Lock-Owner` | renewed count |
| `/lock/release` | `X-Vk-Lock-Owner` | released count |
| `/lock/status` | names | current holders |
| `/lock/fail` | `ttl`, `X-Vk-Lock-Pipeline`, reason body | records a failed build |
| `/lock/fail-status` | `X-Vk-Lock-Pipeline` | recent matching failure |

Acquiring multiple names is atomic and all-or-nothing under one mutex. A batch cannot
deadlock through inconsistent client lock ordering, and all names share one owner token.
Contended acquisition long-polls until the names become available or the wait expires.

Failure records are separate from mutual exclusion. They let jobs in the same pipeline avoid
repeating an expensive build that a peer has already shown to fail. Records are scoped by
pipeline ID, default to six hours, are capped at 24 hours, and hold at most 4 KiB of reason
text. A new pipeline ID always gets a fresh build attempt.

The normal build-once sequence for content key `K` is:

1. Check the cache and return on a hit.
2. Check for a recent failure in the same pipeline.
3. Acquire the lease for `K` and start a heartbeat.
4. Check the cache again; another runner may have populated it while this runner waited.
5. Build and push on a miss, or record the failure.
6. Release the lease.

## Accounts administration

`vk-registry accounts` manages users, sessions, administrators, and API keys. The command
prefers the running server's Unix admin socket and falls back to opening the database
directly when no server is listening. `redb` holds the database exclusively, so direct
access is available only while the server is stopped.

The CLI never creates a missing database. A bad selector fails instead of producing an
empty database and a misleading result. Every operation prints the socket or database it
actually reached.

Each selector can come from its command-line flag or the corresponding
`VK_REGISTRY_ROOT`, `VK_REGISTRY_CONFIG`, or `VK_REGISTRY_ADMIN_SOCKET` variable; an
explicit flag wins over its own variable. Root and socket selectors then override values
read from the selected config file. This means, for example, that an inherited
`VK_REGISTRY_ROOT` still overrides the root in an explicitly named `--config` file.

`--accounts-db` overrides every other database selector and intentionally has no
environment variable. An explicitly selected admin socket identifies the server to
administer; in that case the local database path is only the fallback. With no selector,
the CLI uses the default shared store.

Users are selected by email using ASCII case-insensitive comparison. If more than one issuer
has asserted the same email, the command requires `--issuer`. API keys are selected by the
full hash identifier printed by `list-keys`.

The administration channel is not HTTP and is never part of the public route table. By
default, the socket is `admin.sock` beside the accounts database. It is published with mode
`0600` by binding it inside a private staging directory and atomically renaming it into
place. Each connection must also pass `SO_PEERCRED`: only the server's UID or root is
accepted.

The protocol is one versioned JSON request and response per connection, framed by
half-close. Request and response sizes are bounded. Separate wire types prevent database
row changes from implicitly changing the administration protocol. Mutations are logged with
the peer UID and PID; key creation logs the key ID and scopes but never the token.

A live socket is never replaced. A stale socket may be replaced, but a non-socket path is
left untouched. Failure to bind the admin socket logs a warning without taking down the OCI
service; an operator can still stop the server and use direct database access.

## Garbage collection and reporting

`status` reports physical storage, compression and deduplication savings, in-progress
uploads, and per-repository counts for tags, manifests, and membership records.

`gc` applies two windows:

- retention controls when idle tags stop being roots; and
- grace protects recent unreferenced blobs, digest-pinned manifests, and uploads.

Membership markers are not roots. After sweeping blobs, `gc` removes markers and manifest
sidecars whose content no longer exists. Repository traversal does not follow symlinks and
is bounded by the same repository-depth limit enforced on writes.

Garbage collection currently refuses to process a rooted OCI image index because its mark
phase does not traverse child manifests. The pass aborts before deleting anything. Image
indexes can be stored and mounted, but a store containing a live tagged index cannot be
collected until the mark phase supports that graph.

## Guest credential proxy

With `vk run --registry-proxy` or `[registry] proxy_guests = true`, the host starts a
loopback reverse proxy that injects the runner's registry credential — a bearer token when
`token_file` names one, else the Basic pair, the precedence every other `[registry]` client
applies. The guest accesses it without credentials at `registry.vk` through a sentinel
address handled by the userspace network switch.

The proxy never binds a network interface, and request and response bodies stream in both
directions. This keeps registry credentials out of guest jobs without buffering large
layers. The feature is opt-in and requires guest networking.

## Operational constraints and deferred work

- The lock manager and accounts database assume one server process. Multi-replica operation
  requires a distributed lock implementation and a replicated account store.
- Pull-through cache eviction is retention-based; there is no size-capped LRU policy.
- Chunk boundaries are client-defined. Clients using different chunkers share the blob pool
  but may not deduplicate the same artifact effectively.
- Expired sessions are removed when presented, not by a periodic sweep.
- Sessions are read-all with administrator-only write. Per-user session scopes are not
  implemented.
- The server has no durable request audit log. Administration mutations are logged, but OCI
  reads and writes are not persisted as audit records.
- OIDC trusts platform roots only and caches discovery until restart.
