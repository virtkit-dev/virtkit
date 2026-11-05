# vk-registry design

`vk-registry` is a central OCI Distribution server for virtkit runners. It provides four
services behind one listener:

- a content-addressed OCI store shared by all runners;
- a pull-through cache for upstream registries;
- a leased lock service that coordinates build-once work across runners; and
- a WebDAV view of the store, with a plain-file area for build caches such as
  `sccache`, backed by the same blob pool.

The server is intended to run on a dedicated host or as a user service. Local virtkit use
does not require it: `vk` uses the same `Store` implementation directly for its default
on-disk build cache.

The design favors a single authoritative process and a local filesystem over external
coordination services. Writes and garbage collection are coordinated on that host, and
individual file publications are atomic. Multi-replica operation is explicitly out of
scope.

## Architecture

The `vk-registry` crate contains both the reusable store library and the server binary.
The library provides the store, OCI routes, pull-through relay, build lock service, WebDAV
view, and authentication. In accounts mode it also provides OIDC login, browser, upload, and local
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
  uploads/<id>                  in-progress upload, or a WebDAV PUT being staged
  uploads/owners/<id>           repository that opened the upload
  accounts/accounts.db          account data, when accounts mode is enabled
```

The plain-file area `/dav/files/` uses the same pool: each object is a tag on a raw-file
manifest in a `files/` repository, with its bytes stored as a blob. See "WebDAV view".

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
- manifest `GET`, `HEAD`, `PUT` and `DELETE`; and
- tag listing.

A manifest `DELETE` takes write access, as a `PUT` does, and answers 202, or 404 when there
is nothing to drop. By tag it drops that tag; by digest, every tag of the repository on that
digest and the manifest's membership there, including the marker a mount left for an index
child that declares its media type. Tags and membership in other repositories are
untouched, and the bytes wait for the gc, as for a tag deleted from `/browse`. Until then a
read by digest is answered as for any digest the repository does not hold: in accounts mode
only to a caller who may read another repository holding it, and in shared-secret or open
mode, where repositories are not scoped, to anyone. Deleting a child of an index still tagged
in the repository can leave that index unpullable through it in accounts mode.

A `DELETE` is never relayed upstream: an upstream's copy is not this registry's to delete. A
reference this registry holds no copy of answers 404 to a `DELETE` though a `GET` relays it,
and a deleted digest a read can no longer reach here is fetched and cached again on that
read.

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

An omitted prefix is a catch-all. Upstreams may specify Basic credentials, sent only over
`https://` (or loopback), and an additional CA certificate. Bearer challenges from upstream
registries are handled by the OCI client.

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
| `/lock/renew` | `ttl`, `X-Vk-Lock-Owner` | renewed count and granted ttl |
| `/lock/release` | `X-Vk-Lock-Owner` | released count |
| `/lock/status` | names | current holders |
| `/lock/fail` | `ttl`, `X-Vk-Lock-Pipeline`, reason body | records a failed build |
| `/lock/fail-status` | `X-Vk-Lock-Pipeline` | recent matching failure |

Lease `ttl` and `acquire` long-poll `wait` are capped at 24 hours.

Acquiring multiple names is atomic and all-or-nothing under one mutex. A batch cannot
deadlock through inconsistent client lock ordering, and all names share one owner token.
Contended acquisition long-polls until the names become available or the wait expires.

Failure records are separate from mutual exclusion. They let jobs in the same pipeline avoid
repeating an expensive build that a peer has already shown to fail. Records are keyed by
name and pipeline ID, so one pipeline's record never replaces another's. They default to six
hours, are capped at 24 hours, and hold at most 4 KiB of reason text. Beyond 10,000 records,
the oldest is evicted first. A new pipeline ID always gets a fresh build attempt.

A [hub token](#hub-tokens) may name only locks its grants cover with `lock`, as
`<prefix>:<key>`; one name outside them refuses the request. It acts as the token's own
pipeline: an `X-Vk-Lock-Pipeline` naming another is refused, an absent one is the token's,
and a token naming no pipeline records and reads no failure. Nothing it starts outlives it:
the wait and a record's ttl are cut to the token's remaining lifetime, and a lease, granted
after a wait or renewed, ends by the token's expiry. The tokens of one subject (a job) hold
at most 256 live locks together: an acquire that would take more is answered 429 at once,
without waiting. A token past its expiry, though within the skew it is otherwise taken with,
is refused here with the mode's challenge.

## Batched manifest probe

`POST /vk/manifests/exists?name=<repo>` with body `{"tags": [...]}` answers
`{"present": [...]}`, one boolean per tag in the order asked. It is the batched form of
`HEAD /v2/<repo>/manifests/<tag>`: `vk build` asks about every step of a stage at once to
find the newest snapshot it can resume from, instead of a request per step.

Read access to the repository is authorized once for the batch, as a tag `HEAD` is. Only
tags are accepted — a digest is not scoped to a repository, and is refused as absent. A tag
that resolves has its last-used time bumped, as a `HEAD` hit does. The answer comes from
this server's store alone; a pull-through mirror reports what it holds and does not relay.
At most 4096 tags per request. A client that receives 404 or 405 is talking to a registry
without the endpoint and falls back to one `HEAD` per tag.

The normal build-once sequence for content key `K` is:

1. Check the cache and return on a hit.
2. Check for a recent failure in the same pipeline.
3. Acquire the lease for `K` and start a heartbeat.
4. Check the cache again; another runner may have populated it while this runner waited.
5. Build and push on a miss, or record the failure.
6. Release the lease.

## WebDAV view (`/dav/`)

The whole store is reachable over WebDAV under one root, through the registry's existing
listener, TLS and client auth, with the permission model the OCI API enforces. WebDAV is
enabled by default. Set `webdav = false` to disable it: `/dav/` requests return 404 after
authentication, and the server logs this setting at startup.

The verb set is what opendal's `webdav` service issues — the client behind `sccache`, `oli`
and other opendal-based tools: `PROPFIND` at `Depth` 0 and 1, `GET`, `HEAD`, `PUT`, `MKCOL`, `DELETE`
and `OPTIONS`. `Depth: infinity` is refused with 403, as RFC 4918 allows, and a missing
`Depth` is served as 0, what opendal means by omitting it, where RFC 4918 reads it as
infinity. `COPY`, `MOVE`, `LOCK` and `PROPPATCH` are 405. No client XML is parsed: a `PROPFIND`
body of up to 64 KiB is drained and ignored, `allprop` being both what the client sends and
what an empty body means; a larger one is 413.

```text
/dav/                                 repos/  files/
/dav/repos/<name>/                    tags/  manifests/  blobs/  (+ nested repositories)
/dav/repos/<name>/tags/<tag>          the manifest the tag resolves to, with its media type
/dav/repos/<name>/manifests/<hex>     that manifest
/dav/repos/<name>/blobs/<hex>         the blob's canonical bytes; a stored zstd frame is decoded
/dav/files/<dir>/<path…>              plain files: repositories and tags under files/, read-write
```

**`repos/` is a read-only view, not an export.** The disk tree is not what a client wants:
a stored blob may be a zstd frame, a tag file holds a digest rather than a manifest, and the
blob pool is readable per repository, not as one directory. So tags and manifests download
as the manifest bytes with their media type and blobs as their canonical bytes, through the
same handlers `/v2/` uses and under the same authorization — `Read` on the repository, and
membership for anything addressed by digest. The tree is derived from the list of
repositories the principal may read, never from a `read_dir` of `repos/`: a repository the
principal cannot read is a 404, as `/browse` answers, and a scope such as `read:team-a/*`
lists `team-a/` and nothing beside it. A `files/` directory appears there as the repository
it is, under the same grant. Blobs download with `Content-Disposition: attachment`, as
`files/` objects do. Every write verb there is 405: an OCI write verifies
a digest, records membership and holds the store lock, and a DAV client cannot supply a
manifest's media type. Those go through `/v2/`. A listing of `blobs/` carries each member's
canonical length, which for a zstd-stored blob is one `open` and a frame-header read; a
repository of chunked bundles lists thousands of members, so that listing is an
interactive operation and never on a CI path.

**`files/` is a directory tree over the pool.** A path's directories are a repository under
`files/` and its leaf a tag on a single-layer raw-file manifest, the shape `/upload` writes:
`/dav/files/sccache/a/b/abcdef` is the tag `abcdef` of the repository `files/sccache/a/b`,
and its bytes are the layer blob. An object therefore dedups, compresses and is collected
like any other content, and is reachable over `/v2/` and `/browse` under that name.

Each resource authorizes as the repository it is or is a tag of, the name `/v2/` checks for
the same content: `GET`, `HEAD` and `PROPFIND` are reads, `PUT`, `MKCOL` and `DELETE`
writes. A `PUT` needs `Write` on its parent repository, a `MKCOL` on the one it creates, and
the other verbs on whichever the path resolves to; a caller holding the action on neither the
path's own name nor its parent's is 403 before anything is looked up. To reads and to
`DELETE`, a directory or object the caller may not read is otherwise absent, from listings
and when named. A write refused over a clash — a `PUT` onto a directory or a tag that is not
a raw file, a `MKCOL` onto anything, either below a tag — answers 405 or 409 whether or not
the caller may read the name it clashed with, and so reveals that the name exists. The key
above
authorizes as `files/sccache/a/b`, so a cache directory takes `write:files/sccache/*` or
`read:files/sccache/*`, both covering `files/sccache` itself; an exact `files/sccache` covers
only the objects directly in it. `OPTIONS` needs no grant. Nothing in the server knows what
`sccache` is; it is a directory that a compiler cache happens to write to.

Every component obeys the OCI name rules — `[A-Za-z0-9._-]`, at most 16 components counting
`files`, `<dir>` and the leaf, none named `tags`, `manifests` or `blobs` — and anything else
is 400. A tag whose manifest is not a raw file, an image pushed over `/v2/` into a `files/`
repository, is absent to reads and a 409 to `PUT` and `DELETE`, so this view neither replaces
nor removes it.

| Verb on `files/` | Answer |
|---|---|
| `GET`, `HEAD` | 200 with the layer blob (`application/octet-stream`, `nosniff`, `Content-Disposition: attachment`, `Last-Modified` from the tag); a directory, a missing path, or an object's path with a trailing `/` is 404. A `GET` that serves the object refreshes the tag's mtime once it is an hour old — the use the gc's retention keys on — so `Last-Modified` and `getlastmodified` move forward on reads too; a `HEAD` refreshes nothing, neither the tag nor the layer blob |
| `PUT` | streamed to `uploads/` and hashed on the way, then promoted into the pool and tied to the tag by a manifest under the shared store lock — 201 when the tag is new, 204 when it is replaced, the previous content left for the gc. Missing parent directories are created with it, where RFC 4918 answers 409. 413 past 4 GiB; 405 for directories, top-level names and paths ending in `/`; 409 below an object or onto a tag that is not a raw file |
| `PROPFIND` | 207 for an object or a directory; at `Depth: 1` the nested directories and the objects follow it, each object with `getcontentlength` (the layer's canonical size) and `getlastmodified` (the tag's), which opendal requires; an object is listed, and answers, only when a `GET` would serve it; 404 when absent |
| `MKCOL` | 201, creating an empty repository (a `tags/` with nothing in it) and its missing ancestors, a top-level directory included; 405 when the path is already a directory or a tag; 409 when a tag is above it; 415 with a request body, as RFC 4918 allows |
| `DELETE` | 204 for an object (the tag goes; the bytes wait for the gc) or an empty directory; 403 for a directory with members — a tag, a nested directory, or any entry that is not the repository's layout; 409 for one holding fresh records other than its deleted objects' (see below) or for a tag that is not a raw file; 404 when absent or unreadable to the caller; 503 when the store lock stays taken (see below) |
| `OPTIONS` | `DAV: 1` and the verbs that resource serves: the `files/` list below `/dav/files/`, the read-only one at `/dav/`, `/dav/files/` and throughout `/dav/repos/`; every other verb is 405 with the same list |

Every refusal reads the request body through first, and so does every `DELETE`, up to the
4 GiB object cap (past it, 413); only a declared `Content-Length` over the cap is refused at
once. A status sent with
request bytes still unread closes the socket with a reset, and `sccache` takes a reset on its startup probe as
an unwritable store and runs the whole build read-only. A read-only key makes that probe
fail with 403, which the client reports as read-only mode: an untrusted pipeline consumes
the cache without writing to it. Since a writer with `Write` on a directory owns its
content, give write access only to trusted pipelines (protected branches), hand everything
else a read-only key, and use one directory per trust level when that is not enough.

A directory's `DELETE` removes only leftovers: what a deleted object leaves behind — its
raw-file manifest's sidecar and the membership markers of its layer and of the shared empty
config — and any other record older than the default gc grace window of one day. A fresh
sidecar of any other manifest may be pulled by digest, and the gc roots it while its blob is
that fresh; a fresh marker no raw-file sidecar there accounts for may be a `/v2/` push that
has uploaded its blobs and not yet its manifest. Either keeps the directory, with a 409, until
it ages past the window, so a marker whose layer lives on in another repository after the gc
swept the manifest does not keep it forever. The removal holds the store lock exclusive,
lists every directory strictly, and unlinks only the entries it saw before a `remove_dir` of
each directory. The lock is tried rather than waited for, with backoff, releasing the
namespace lock below between attempts so the other `files/` writes proceed; after 30 s of
shared holders or a running gc, the answer is 503.

`PUT`, `MKCOL` and `DELETE` under `files/` hold one process-local lock across their checks
and namespace changes. `PUT` rechecks its path after staging, so `MKCOL` and `PUT` of one
path cannot both succeed. `/v2/` pushes into `files/` do not take this lock. Listings,
`MKCOL` and `DELETE` run on the blocking pool. A `Depth: 1` listing uses memory proportional
to the collection's members.

Paths are split on raw `/` before each component is percent-decoded on its own — `%XX`
escapes only, `+` being itself, and the result UTF-8 — so `%2F` cannot smuggle a separator;
`.`, `..`, empty, over-long (255 bytes) and control-byte components, malformed escapes,
invalid UTF-8, and more than 18 components below the area — a 16-component repository name
and `blobs/<hex>` — are refused; under `files/` the 16-component name bound, `files`
included, refuses a path first.
Hrefs in a 207 are rebuilt from the decoded
components, percent-encoded, with a trailing slash on a collection. `/dav/` is not a human
path, so an unauthenticated client gets the 401 challenge rather than a login redirect.

**Enumeration** is the one disclosure a listing makes beyond what the caller named. A
`Depth: 1` on `/dav/`, `/dav/repos/`, `/dav/files/` or a path component above repositories
shows only what the principal may read, and on a server with no credential configured at
all it is refused with 403, for the reason `/browse` does not exist in shared-secret mode:
a catalog is not something anyone who can reach the port gets for free. `Depth: 0` there,
which is what opendal's parent walk asks, always answers.

### Lifecycle

An object is a tag, so `gc` expires it as it expires every tag: dropped once idle past the
retention window, its blobs swept once unreferenced and past the grace window, both windows
store-wide, unless its manifest keeps or expires it ("Garbage collection and reporting"). A
WebDAV `PUT` writes none of those annotations; `vk registry put --keep|--ttl` does. Like an
`/upload` or a `/v2/` push, `vk registry put` takes no WebDAV namespace lock, so it can tag
an object under a name a collection already holds. Idleness is the tag's mtime, which a
`PUT` sets and a `GET` refreshes once it is an hour old, so a read-only pipeline's hits keep
an entry alive as a writer's do. There is no per-directory policy and no size cap; a
replaced or deleted object frees no disk until the next `gc`. A staging file a crashed `PUT`
left in `uploads/` goes with the idle uploads, and so does an S3 multipart upload nothing has
been written into for the grace window: its directory under `uploads/s3/` is idle by the
newest mtime among its files (the directory's own does not move when a part is replaced),
and goes whole, parts and all. Completing an upload marks it used, so the sweep does not
take it while its parts are read.

## S3 view (`/s3/`)

The `files/` area is also served as S3, path-style, under `/s3/`, through the same listener,
TLS and credentials: a bucket is a top-level `files/` directory and an object key the path
below it, so `PUT /s3/sccache/a/b/abcdef` writes the same tag `/dav/files/sccache/a/b/abcdef`
names. Nothing new is stored, and the WebDAV view, `/v2/`, `/browse`, `vk registry get` and
the gc see the same entries. S3 is enabled by default. Set `s3 = false` to disable it: `/s3/`
requests then return the 404 any unknown path returns, after the usual authentication, and
the server logs this setting at startup.

```text
/s3/                          the buckets: top-level directories of files/
/s3/<bucket>                  files/<bucket>
/s3/<bucket>/<key…>           the object files/<bucket>/<key…> names, as in /dav/files/
```

Clients take `endpoint = https://<registry>/s3` and any region: `sccache` with
`SCCACHE_BUCKET=<bucket> SCCACHE_ENDPOINT=https://<registry>/s3 SCCACHE_REGION=auto`
(`SCCACHE_S3_KEY_PREFIX` names a directory inside the bucket).

**Virtual-hosted style** is opt-in, for clients that cannot be made to use paths: with
`s3_host = "s3.example.com"`, a request sent to `<bucket>.s3.example.com` names its bucket by
its host and its key by its whole path, and is served as `/s3/<bucket>/<path>`, so `/` there
is the bucket and `/a/b` its object `a/b`, even where the path is one another route would
take. The `Host` port is ignored. The signature is checked over the request as sent, host and
path included, so nothing about credentials changes. It needs a wildcard DNS record
`*.s3.example.com` pointing at the registry and, with TLS, a certificate covering that
wildcard (one label deep: a bucket name with a dot is not covered). A host whose label cannot
be a bucket, `s3_host` itself, and every other host are served as before, and path-style
`/s3/` keeps working on any of them. The setting is a lowercase host name with no port; the
server refuses anything else at startup. The registry's own host name must not be below
`s3_host`, since every `<label>.<s3_host>` is taken for a bucket, `/v2/`, `/login` and
`/browse` included: `s3_host = "example.com"` would serve `reg.example.com` as bucket `reg`.
The server refuses at startup an `[oidc] public_url` whose host is below `s3_host`, and
`s3_host` with `s3 = false`; `s3_host` may be the registry's own name, which is not a
bucket's.

**Credentials.** SigV4 needs the server to hold the signing secret, and this registry stores
API keys only as hashes and never mints hub tokens, so no new secret is introduced: the
access key id is a credential the registry already takes, and the secret access key is the
same string. In accounts mode `AWS_ACCESS_KEY_ID=vkr_…` and `AWS_SECRET_ACCESS_KEY=vkr_…`,
the same value; a hub token likewise, in either mode, when the registry takes them; the
shared bearer likewise. With a shared Basic user, the access key id is the user name and the
secret its password, which then never crosses the wire; a user name holding `/` cannot be an
access key id, since the credential scope is split from the right. The access key id is
authenticated first, exactly as the bearer it would be, so revocation, expiry and scopes
apply unchanged, and only then is its secret used to check the signature; an unknown id is
403 `InvalidAccessKeyId`, a wrong signature 403 `SignatureDoesNotMatch` (with the string to
sign and canonical request, as AWS answers). The signature must cover `host`, `x-amz-content-sha256`
and, as S3 requires, every `x-amz-*` header the request carries: one left out is 403
`AccessDenied` naming it in `HeadersNotSigned`, since anything on the way could have added
it. The request's time must be on the scope's day
and within 15 minutes of the server's (403 `RequestTimeTooSkewed`, naming the server's
time). The usual `Authorization: Bearer|Basic` and the session cookie keep working on `/s3/`;
an `Authorization` of any other scheme (SigV2, say), or with no scheme at all, is 400
`InvalidArgument`, as S3 answers a signature version it does not take; a request with no
credential on a server that requires one is S3's 403 `AccessDenied`, not the 401 challenge. On a server with no credential configured, signatures are not checked, as
nothing else is. Presigned (query-string) URLs are refused with 400
`AuthorizationQueryParametersError`, since they put a credential in a URL and so in logs, and
temporary credentials (`x-amz-security-token`) with 400 `InvalidToken`.

The exposure is today's: a bearer travels in clear under TLS and so does an access key id,
while the signature also binds the method, path, query, signed headers and a timestamp. With
`UNSIGNED-PAYLOAD`, which OpenDAL and most SDKs send, a captured `Authorization` header can be
replayed with another body to the same key for those 15 minutes, as a captured bearer can be
for as long as it is good.

**Keys** follow the store's name rules as they are; there is no escaping scheme. A bucket is
one component; a key is 1 to 14 components (16 counting `files` and the bucket), each a run of
`[A-Za-z0-9._-]` of at most 255 bytes, not `.`, `..`, `tags`, `manifests` or `blobs`, the whole
key at most 1024 bytes, no empty component and no trailing slash, so there are no "directory
marker" objects. Paths are split before they are percent-decoded, as WebDAV's are, so `%2F`
cannot smuggle a separator. Anything else is 400 `InvalidArgument`, `KeyTooLongError` or
`InvalidBucketName`, with a message naming the rule. `sccache`'s keys (`a/b/c/<hex>`,
`.sccache_check`) pass. A query's parameters, names and values alike, are percent-decoded
once, as the signature decodes them, before the request is dispatched on them; a malformed
escape is 400 `InvalidArgument`.

**Authorization** is the WebDAV view's: a `PUT` needs `Write` on the key's parent repository,
a read `Read` on the repository the key resolves to, and a `DELETE` `Write` there; a caller
holding the action on neither the key's own name nor its parent's is 403 `AccessDenied` before
anything is looked up, and what it may not read is otherwise absent (`NoSuchKey`). A write
refused over a clash answers 409 and so reveals that the name exists, as WebDAV's does. A
bucket authorizes as `files/<bucket>`, except that HeadBucket and GetBucketLocation also
admit a caller that may read only a directory inside it, which clients probe before listing
the prefix they were given. Listing the buckets needs a configured credential, as `/dav/`'s
root listing does, and shows only those HeadBucket admits the caller to: a bucket it may read,
or read a directory inside. Listing a bucket's objects is
admitted when the caller may read the bucket or the directory the prefix's whole components
name (`prefix=proj/` for a `read:files/team/proj/*` key over bucket `team`; `prefix=proj`
names no directory and is refused), and shows only what a read would serve: a directory the
caller may not read is passed over with everything below it, as `PROPFIND` passes it over,
and neither a foreign tag nor an object whose bytes the caller may not read through it is
listed.

**A write makes its bucket.** PutObject, CopyObject and CompleteMultipartUpload into a bucket
that does not exist create it, with every directory above the key, as WebDAV's `PUT` creates
missing directories, rather than answering S3's `NoSuchBucket`; the write is authorized as
any other, on the key's parent. This is deliberate: a job behind the guest proxy may not
create the bucket its area lies in (see below), and can write there all the same.

**Objects are bytes.** Every object is served `application/octet-stream`,
`Content-Disposition: attachment` and `nosniff`, whatever its writer sent: a `Content-Type`
is not stored, for the reason manifest media types are restricted (this origin also serves
`/browse` and holds the session cookie). An object's ETag is the MD5 of its bytes, quoted,
which a `PutObject` computes in the same pass as the SHA-256 and records on the manifest as
`org.virtkit.md5`; an object written otherwise (WebDAV, `vk registry put`, `/upload`) has no
MD5 and its ETag is its SHA-256, quoted — 64 hex digits, which a client checking an ETag as
an MD5 sees is not one. An object a multipart upload made has S3's multipart ETag,
`"<MD5 of its parts' MD5s>-<parts>"`, recorded in the same annotation, so GetObject, HeadObject,
the listings and a copy's source all answer it. The `x-amz-checksum-*` a write carried, once it held, is kept as `org.virtkit.s3-checksum` and is the object's checksum from then on, in listings and on reads. User metadata (`x-amz-meta-<name>`, names `[a-z0-9-]`, at most 2 KiB
of names and values) is kept on the manifest as `org.virtkit.s3-meta.<name>` and sent back on
reads; a replaced object keeps only what its own write sent.

| Request | Answer |
|---|---|
| `PUT /s3/<b>/<k>` PutObject | 200 with `ETag`; streamed to `uploads/` while hashed (SHA-256, MD5, and the SHA-1 or CRC32 when asked), then tagged under the namespace lock as a WebDAV `PUT` is. `x-amz-content-sha256` is `UNSIGNED-PAYLOAD`, the body's SHA-256 (else 400 `XAmzContentSHA256Mismatch` and nothing is tagged), or a streaming mode whose `aws-chunked` body is decoded on the way in (below). `Content-MD5` and one `x-amz-checksum-{crc32,crc32c,sha1,sha256,crc64nvme,sha512,md5}`, as a header or in a chunked body's trailer, are checked (400 `BadDigest`; 400 `InvalidDigest`/`InvalidRequest` when malformed, or when two are sent, or when `x-amz-sdk-checksum-algorithm` names another algorithm than the header or the trailer; 501 `NotImplemented` for S3's XXHASH family, or any other algorithm, rather than taken unchecked) and the checksum echoed with `x-amz-checksum-type: FULL_OBJECT` and kept on the manifest as `org.virtkit.s3-checksum` (`<ALGORITHM>:<base64>`), the object's from then on. `If-None-Match: *` (create only) and `If-Match: <etag>` (replace only that object; an absent one fails too) are checked under the lock the tag is written under: 412 `PreconditionFailed`. 409 `OperationAborted` onto a directory, below an object, or over a foreign tag; 413 `EntityTooLarge` past 4 GiB, declared or streamed; 400 `MetadataTooLarge` |
| `GET`, `HEAD /s3/<b>/<k>` GetObject, HeadObject | 200 with the bytes, `ETag`, `Last-Modified` from the tag, `Content-Length` and the metadata; with `x-amz-checksum-mode: ENABLED`, the checksum the write kept (`x-amz-checksum-<algorithm>` and `x-amz-checksum-type: FULL_OBJECT`), or `x-amz-checksum-sha256` (the store's digest, base64) for an object that kept none. `If-Match`, `If-Unmodified-Since`, `If-None-Match` and `If-Modified-Since` in RFC 9110's order: 412 `PreconditionFailed`, or 304 with the `ETag`. Then one byte range of `Range` (`bytes=a-b`, `bytes=a-`, `bytes=-n`): 206 with `Content-Range: bytes a-b/<size>`, the part's `Content-Length` and the same headers but no checksum, which S3 sends with the whole object only (the AWS CLI checks one it is sent against each part it reads); a last byte past the end, or a suffix longer than the object, is cut to it, and a suffix of an empty object is all of it (200); a first byte past the end, an empty object's first byte included, or `bytes=-0` is 416 `InvalidRange` with `Content-Range: bytes */<size>`; several ranges, another unit or a header that does not parse (whitespace in the range, `bytes= -1`, or a last byte before the first, `bytes=5-2`, as S3 takes them) are ignored (200), as RFC 9110 allows, as is a `Range` whose `If-Range` (an ETag compared strongly, or a date equal to `Last-Modified`) no longer holds. `?partNumber=<n>` instead of a `Range` (both is 400 `InvalidRequest`) serves part `n` of the object as it was uploaded: 206 with its `Content-Range` and `x-amz-mp-parts-count` for an object a multipart upload made (its parts' sizes are kept on the manifest as `org.virtkit.s3-parts`), an object written whole being its one part (206, no count), a part of no bytes the whole object (200); a part there is not is 416 `InvalidPartNumber`, a number outside 1 to 10000 400 `InvalidArgument`. A HEAD answers what the GET would. Every answer with the object says `Accept-Ranges: bytes`. A directory, a foreign tag or a missing key is 404 `NoSuchKey`. `?versionId=null`, the one version ListObjectVersions gives every object, names the object itself, here and on a delete or a copy source; any other version id is 501 `NotImplemented`. A `GET` refreshes an idle tag as WebDAV's does, a ranged one included; a `HEAD` touches nothing |
| `GET /s3/<b>/<k>?attributes` GetObjectAttributes | 200 `GetObjectAttributesResponse` with what `x-amz-object-attributes` names of `ETag`, `Checksum` (the kept checksum, named by its algorithm, with its `ChecksumType`; else the SHA-256), `ObjectParts` (for an object a multipart upload made: each part's number and size, `x-amz-max-parts` of them from after `x-amz-part-number-marker`, with `PartsCount`; absent for an object written whole), `StorageClass` (`STANDARD`) and `ObjectSize`, and `Last-Modified`; 400 `InvalidArgument` without the header; touches nothing |
| `DELETE /s3/<b>/<k>` DeleteObject | 204 whether or not the key held an object, as S3 answers, and for a key that is a directory, which holds no object to delete, with or without `?versionId=null`; 409 `OperationAborted` for a foreign tag; 403 when the caller may read the object but not write it. Writing the key's repository is what deletes: a grant to write and not read deletes too |
| `PUT /s3/<b>/<k>` with `x-amz-copy-source` CopyObject | 200 `CopyObjectResult` (`LastModified`, `ETag`): the source tagged again at the key on the same layer, so no byte moves and the pool holds it once; the destination's repository records the layer as a member, so a caller that may read only the copy reads its bytes. The source is `<bucket>/<key>`, with or without a leading `/`, escaped as a whole or not, `?versionId=null` naming the same; another `?versionId=` is 501 `NotImplemented`. It is read as GetObject reads it (403 when the caller may read neither its path nor its parent, 404 `NoSuchKey` when absent, a directory, foreign or unreadable, `NoSuchBucket` when its bucket is not there), and the destination written as PutObject writes (`Write` on its parent, 409 `OperationAborted`, `If-None-Match: *`/`If-Match` checked where the tag is written), under the namespace and shared store lock across both. `x-amz-copy-source-if-match`, `-if-none-match`, `-if-modified-since` and `-if-unmodified-since` decide on the source in GetObject's order, what a read would answer 304 failing too: 412 `PreconditionFailed`. The source's MD5 (so its ETag), the checksum it kept and its parts come along; its user metadata too with `x-amz-metadata-directive: COPY` (the default), the request's `x-amz-meta-*` instead with `REPLACE`; a retention annotation is not copied. A copy onto itself is 400 `InvalidRequest` unless it is a `REPLACE` |
| `POST /s3/<b>?delete` DeleteObjects | 200 `DeleteResult`: each key of the `Delete` document deleted as DeleteObject deletes it (a key with no object counts as deleted, in a bucket that is not there too), in the order asked, as `<Deleted>` (left out with `<Quiet>true</Quiet>`) or as an `<Error>` with its `Key`, `Code` and `Message`: `AccessDenied` for a key the caller may not delete, `InvalidArgument`/`KeyTooLongError` for one the store cannot name, `OperationAborted` for a foreign tag, `NotImplemented` for one naming a `VersionId` other than `null`, `InternalError` for one the store failed to delete (logged with the request id), the batch going on past it. The namespace lock is taken once for the batch. The document is at most 1 MiB and 1000 keys, and holds no character XML 1.0 does not allow, literal or as a reference, else 400 `MalformedXML`, and is checked as a PutObject's body is against `x-amz-content-sha256`, `Content-MD5` and `x-amz-checksum-{sha256,sha1,crc32}` before a key is touched (400 `XAmzContentSHA256Mismatch`, `BadDigest`); an `aws-chunked` document is 501 |
| `PUT /s3/<b>` CreateBucket | 200 with `Location: /s3/<b>`: the directory `files/<b>`, made as WebDAV's `MKCOL` makes it, under the namespace lock; needs `Write` on `files/<b>`. 409 `BucketAlreadyOwnedByYou` when it is a directory already, 409 `OperationAborted` when something else has its name in the store. A `CreateBucketConfiguration` body of at most 1 KiB is taken and ignored (a larger or malformed body is 400 `MalformedXML`); `x-amz-bucket-object-lock-enabled: true` is 501 `NotImplemented`, and so is an `x-amz-acl` other than the owner's (below) |
| `DELETE /s3/<b>` DeleteBucket | 204 when the bucket holds no key: its directory tree is removed deepest first, each directory as WebDAV's `DELETE` removes an empty one, since the directories of deleted keys are left behind and S3 calls such a bucket empty; needs `Write` on `files/<b>`. 409 `BucketNotEmpty` while a key, a foreign tag or a record too fresh to be a deleted object's (an image's manifest pushed over `/v2/` lately, its message says) is there; 404 `NoSuchBucket`; the removal needs the store lock exclusive, retried for up to 30 s, then 503 `ServiceUnavailable` with `Retry-After` |
| `GET /s3/<b>?versioning` and the other configurations | what S3 answers for a bucket with none configured, after HeadBucket's checks: an empty `VersioningConfiguration`, `BucketLoggingStatus`, `NotificationConfiguration` and `AccelerateConfiguration`; `RequestPaymentConfiguration` naming `BucketOwner`; `?tagging` (bucket or object) an empty `TagSet`; `?acl` (bucket or object) an `AccessControlPolicy` granting `FULL_CONTROL` to the owner `vk-registry`; 404 `NoSuchLifecycleConfiguration` (`?lifecycle`), `NoSuchBucketPolicy` (`?policy`, `?policyStatus`), `NoSuchCORSConfiguration` (`?cors`), `ServerSideEncryptionConfigurationNotFoundError` (`?encryption`), `ObjectLockConfigurationNotFoundError` (`?object-lock`), `ReplicationConfigurationNotFoundError` (`?replication`), `NoSuchWebsiteConfiguration` (`?website`), `NoSuchPublicAccessBlockConfiguration` (`?publicAccessBlock`), `OwnershipControlsNotFoundError` (`?ownershipControls`). An object's after GetObject's checks. Tools probe these before they use a bucket. A `PUT` or `DELETE` of any of them is 501 `NotImplemented`, its body read through. So is any request whose headers ask for one of them on the object or bucket it names, rather than the header being taken and dropped: `x-amz-server-side-encryption*` (SSE-S3, SSE-KMS and SSE-C, on a read and a copy's source too: a client that asked for its own key is never told its bytes are stored under it), `x-amz-tagging` naming a tag, `x-amz-acl` other than `private` or `bucket-owner-full-control` (the one ACL there is), `x-amz-grant-*`, `x-amz-storage-class` other than `STANDARD` (400 `InvalidStorageClass` for a class S3 does not have), `x-amz-website-redirect-location` and `x-amz-object-lock-*` |
| `GET /s3/<b>?list-type=2` ListObjectsV2 | `ListBucketResult` with `KeyCount`, the keys starting with `prefix` (any text, which may end inside a component), each with `Key`, `LastModified`, `ETag` (as HeadObject's), `ChecksumAlgorithm` and `ChecksumType` when its write kept a checksum, `Size` and `StorageClass` `STANDARD`, and `Owner` `vk-registry` with `fetch-owner=true`. Keys come in byte order of the whole key, the order S3 lists in: a directory's keys all start with `<name>/`, so tag `a-b` and `a.b` come before the keys below directory `a`, and those before tag `a_b`. `delimiter` (any text) folds every key past the prefix holding it into a `CommonPrefixes` entry ending at its first occurrence; a directory folded so is not walked, and an empty one is listed as a prefix, as WebDAV shows it. `max-keys` defaults to 1000 and is clamped to it; `0` is an empty, complete page. `NextContinuationToken` names the page's last entry; a `continuation-token` or `start-after` resumes after it, a common prefix included (a start key inside a folded prefix passes over it). `encoding-type=url` percent-encodes keys, prefixes, the delimiter and `StartAfter`. 400 `InvalidArgument` for a token this registry did not give or a malformed parameter; 404 `NoSuchBucket`; 403 `AccessDenied` past the admission rule above. Touches nothing |
| `GET /s3/<b>` ListObjects | the first version of the same listing: `marker` for `start-after`, `Marker` and, on a truncated page, `NextMarker` in the answer, no `KeyCount`, and every object's `Owner` |
| `GET /s3/<b>?versions` ListObjectVersions | the same listing as a store that keeps no versions answers it, a `ListVersionsResult` in which each object is a `<Version>` with ListObjects' fields and its `Owner`, `VersionId` `null` and `IsLatest` `true`, with no `<DeleteMarker>`. `key-marker` resumes after a key; `version-id-marker` is taken and echoed as `VersionIdMarker`, a key having one version; `KeyMarker` and, on a truncated page, `NextKeyMarker` with `NextVersionIdMarker` `null` are in the answer, so a paginator sends back what it is given. `list-type` with it, or a `version-id-marker` without a `key-marker`, is 400 `InvalidArgument`. Ceph's s3-tests empty every bucket through it, deleting each key with the `null` version it lists |
| `HEAD /s3/<b>` HeadBucket | 200 when `files/<b>` is a directory, 404 `NoSuchBucket` when not; 403 when the caller may read neither `files/<b>` nor anything below it |
| `GET /s3/<b>?location` GetBucketLocation | the region the request was signed for, which is any the client chose, or an empty `LocationConstraint` for an unsigned request; after HeadBucket's checks |
| `GET /s3/` ListBuckets | `ListAllMyBucketsResult`: the readable top-level directories, each dated by its directory's mtime, and the owner `vk-registry`; 403 `AccessDenied` on a server with no credential |
| `POST /s3/<b>/<k>?uploads` CreateMultipartUpload | 200 `InitiateMultipartUploadResult` (`Bucket`, `Key`, `UploadId`): a new upload of the key, its user metadata recorded for the object; needs `Write` on the key's parent, and the key is checked as PutObject's is (409 `OperationAborted`), and again at completion. `x-amz-checksum-algorithm` is taken and echoed (501 for an algorithm not computed here); `x-amz-copy-source` is 400 `InvalidArgument` |
| `PUT /s3/<b>/<k>?partNumber=<n>&uploadId=<id>` UploadPart | 200 with the part's `ETag` (its MD5): its body received as a PutObject's is — the same payload modes, `aws-chunked` decoding, `Content-MD5` and `x-amz-checksum-*` checks and echoes, 413 `EntityTooLarge` past 4 GiB — into the upload's directory, replacing any earlier part `n` whole. Part numbers are 1 to 10000 (else 400 `InvalidArgument`); no minimum part size is enforced. An upload id that is not one of the key's own uploads, completed or aborted is 404 `NoSuchUpload`, whatever key it was made for |
| UploadPart with `x-amz-copy-source` UploadPartCopy | 200 `CopyPartResult` (`LastModified`, `ETag`): the source object, or the bytes `x-amz-copy-source-range: bytes=<first>-<last>` names, copied into the part off the runtime (a part is the upload's own until it completes), the source read and its `x-amz-copy-source-if-*` conditions checked as CopyObject's are. A range past the source's end is 416 `InvalidRange`, a malformed one 400 `InvalidArgument` |
| `POST /s3/<b>/<k>?uploadId=<id>` CompleteMultipartUpload | 200 `CompleteMultipartUploadResult` (`Location`, the object's absolute URL as S3 gives it, from the listener's scheme, the `Host` and the path as sent; `Bucket`, `Key`, `ETag`): the parts the `CompleteMultipartUpload` document names, concatenated in that order into one staging file in a single pass off the runtime, then tagged as a PutObject's body is (the key checked again, `If-None-Match: *`/`If-Match` where the tag is written, stored plain from 8 MiB), with the metadata recorded at creation; the upload then goes. The numbers must ascend (400 `InvalidPartOrder`), each part must be there with the ETag given (400 `InvalidPart`; each part's MD5 is checked again as it is read), at least one part (400 `MalformedXML`), and the total at most 4 GiB (413 `EntityTooLarge`). A whole-object `x-amz-checksum-*` of any of the algorithms computed here is checked against the object (400 `BadDigest`) and kept as a PutObject's is, named in the result with its `ChecksumType`; a composite one (`…-<parts>`) is passed over, anything else is 400 `InvalidRequest`, and an algorithm not computed here 501. The parts' sizes are kept with the object, for a read of one part and `ObjectParts`. Every refusal is a real status, never S3's late `200` carrying an `Error`, and leaves the upload to be completed again |
| `DELETE /s3/<b>/<k>?uploadId=<id>` AbortMultipartUpload | 204: the upload and its parts removed; 404 `NoSuchUpload` |
| `GET /s3/<b>/<k>?uploadId=<id>` ListParts | 200 `ListPartsResult`: the parts in ascending order after `part-number-marker`, `max-parts` of them (at most and by default 1000), each with `PartNumber`, `LastModified`, `ETag` and `Size`, `IsTruncated` and `NextPartNumberMarker`; needs `Read` on the key's parent; 404 `NoSuchUpload` |
| `GET /s3/<b>?uploads` ListMultipartUploads | 200 `ListMultipartUploadsResult`: the bucket's uploads in progress whose key starts with `prefix`, by key then upload id, after `key-marker` (and `upload-id-marker` for that key), `max-uploads` of them (at most and by default 1000), each with `Key`, `UploadId`, `Initiator`, `Owner`, `StorageClass` and `Initiated`; admitted as a listing of the bucket with that prefix is, showing only the uploads whose key the caller may read; `encoding-type=url` honoured, `delimiter` 501 `NotImplemented`; a `prefix` or marker holding a control character, or past 1024 bytes, is 400 `InvalidArgument`, as a bucket listing's; 404 `NoSuchBucket` |
| anything else | 501 `NotImplemented`: writes of tagging, ACLs, versioning and the other configurations, `partNumber` on a read, every other subresource, and a parameter an operation does not take; an SDK's `x-id` operation hint is ignored |

**XML in** (`Delete`, `CreateBucketConfiguration`, `CompleteMultipartUpload`) is read by an
element scanner of this registry's own, not a parser: UTF-8 only; the XML declaration,
processing instructions and comments are passed over and CDATA is text;
`&lt; &gt; &amp; &quot; &apos;` and character references are decoded, and any other entity, or
a document type declaration (which could define one), is 400 `MalformedXML`, so nothing is
fetched or expanded. Elements are known by their local name, so namespaces and attributes say
nothing, and an element a request does not define is passed over. Nesting is at most 16 deep and a document holds a bounded number of
elements (6 per key or part and a few more for a `Delete` or a `CompleteMultipartUpload`, of
at most 1 MiB), so it costs at most its length in memory; a field given twice, a missing `Key`,
`PartNumber` or `ETag`, or anything that is not well formed is `MalformedXML`.

**`aws-chunked` bodies**, which AWS's SDKs and CLI send by default, are decoded as they
stream, in one pass: a run of `<hex size>[;chunk-signature=<sig>]\r\n<data>\r\n` chunks ended
by an empty one, then, in the `-TRAILER` modes, the checksum `x-amz-trailer` announced and,
when signed, `x-amz-trailer-signature`. `x-amz-content-sha256` names the mode:
`STREAMING-AWS4-HMAC-SHA256-PAYLOAD` signs every chunk, its `-TRAILER` form the trailer too,
`STREAMING-UNSIGNED-PAYLOAD-TRAILER` signs nothing and carries the checksum, and
`Content-Encoding: aws-chunked` beside `UNSIGNED-PAYLOAD` or a SHA-256 is framing alone (the
SHA-256 then being the decoded bytes'). Chunk signatures chain from the request's own as AWS
defines them, the trailer's signing its `name:value\n` lines after the last chunk's; they are
checked with the signing key the request's signature was, which is kept while the body
streams and wiped after. **A request authenticated by a bearer, Basic or session credential
rather than SigV4** — the way a proxy that authenticates a guest's requests itself forwards
them — and any request to a server with no credential has no secret to check them with: its
framing is decoded and its signatures are read, not checked. `x-amz-decoded-content-length`
is required (400 `InvalidRequest`), past 4 GiB is 413 before the body is read, and the chunks
must hold exactly that many bytes. The trailer's `x-amz-checksum-{crc32,sha1,sha256}` is
checked against the decoded bytes and echoed, as a header's is; `crc32c` and `crc64nvme` are
taken unchecked; a checksum sent both as a header and in the trailer is 400. Reading is
bounded as it goes: a chunk header of at most 256 bytes, a chunk no longer than what is left
of the declared length, a trailer of at most 8 KiB, nothing after its end, and memory of one
frame and a line. A body that breaks any of this is refused where it goes wrong — 400
`InvalidChunkSizeError`, `IncompleteBody` or `MalformedTrailerError`, 403
`SignatureDoesNotMatch` — and its staging file is dropped, so nothing it held is tagged. No
other content encoding is decoded: one named beside `aws-chunked` is 501 `NotImplemented`, as
is another streaming mode (`STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD`); another encoding
alone is stored as sent, its name not kept.

**Ranges** are read from the stored blob without buffering the part. A blob stored plain is
read after a seek. One stored as a zstd frame is decoded from its start and what precedes the
range discarded, so a range costs a decode of everything before it: nothing to notice on a
small object, but a client reading a large one in consecutive ranges would decode about
N²/(2·range) bytes in all. The AWS CLI and the SDKs' transfer managers download an object past
8 MiB as parallel 8 MiB ranges, so a `PutObject` of 8 MiB or more is stored plain, with no
compression pass, and each of its ranges is a seek; smaller ones are compressed when that
pays, and their ranges cost at most an 8 MiB decode. An object written otherwise (WebDAV,
`vk registry put`, `/upload`) is stored as those writes store it, compressed when that pays
whatever its size, and content already held keeps the form it was stored in first, so a large
object of either kind can still be a zstd frame and pay that cost.

**A listing's cost** is bounded by its page. The walk runs on the blocking pool, starts at the
directory the prefix's whole components name, lists each directory it enters once (its
subdirectories and tags), and stops one entry past `max-keys`, to know whether the page is
truncated; memory is the page and a directory listing per level. A resumed page passes over
every subtree that sorts before its resume point unread, so it costs the directories on the
way down to that point plus the page, however deep into the bucket it is. Each key listed
costs a manifest read and a membership `stat`, as a `PROPFIND` entry does: about a thousand
small reads for a full page. A listing with `delimiter=/` never walks below the level it
lists; one without a delimiter over a sharded `sccache` directory walks its thousands of
repositories across its pages (see "Operational constraints and deferred work").

**Multipart uploads** are staged in the store, each in a private directory
`uploads/s3/<id>/` the gc sweeps once idle ("Lifecycle" above), not in the pool: `meta.json`
(the bucket, the key, when it was created and the user metadata the object will carry), and
for each part `part-<n>` (its bytes) and `part-<n>.json` (their size and MD5). Each file is
written under a private temporary name and renamed over its own, so a part sent again replaces
the earlier one whole; since a part's bytes and its record are two renames, completing an
upload checks each part's MD5 again as it reads it. An upload id is minted as an OCI upload id
is, `<pid>-<n>-<random hex>`, and held to hex digits and dashes, so it never names a path, and
every call checks that the id's recorded bucket and key are the request's. A part's bytes
stay out of the pool until the upload completes, so parts of the same content are stored once
per upload until then; completing an upload costs a sequential read and write of the whole
object, and listing uploads reads the record of every upload in progress in the store.
`vk-registry status` counts the multipart uploads in progress beside the OCI ones.

**`LastModified` moves on reads**, as `getlastmodified` does over WebDAV: a `GET` refreshes
the tag's mtime once it is an hour old, which is what keeps a hot cache entry from the gc's
retention. Sync tools that compare modification times (`aws s3 sync`, rclone `--update`) see
it; they keep the source file's own time in user metadata.

**Errors** are S3's XML `Error` documents (`Code`, `Message`, `Resource`, `RequestId`, and
the extra elements AWS sends, such as `ServerTime` or `Condition`), so a client shows a code
rather than a bare status. Every `/s3/` response carries an `x-amz-request-id` of 16 hex
digits, the same id again as `x-amz-id-2` (S3's second id, which SDK test suites expect on
every answer) and `nosniff`; an internal error logs its request id, so a client's report can
be matched to the server's line. A refusal decided before the caller is authenticated reads at
most 64 KiB of the body first, enough for `sccache`'s 13-byte probe to see its answer rather
than a reset; every refusal after it reads the body through, up to the 4 GiB cap, as
WebDAV's do. A refusal of a request with a body then closes the connection. A registry its
hub made read-only answers writes 503 `ServiceUnavailable` with `Retry-After`.

S3 writes into `files/` take the WebDAV view's namespace lock, run their store work on the
blocking pool and stream their bodies on the runtime. Objects expire under the gc's tag
retention like every `files/` entry ("Lifecycle" above): a PutObject writes no retention
annotation.

**Tests.** Besides the in-process suite (`tests/s3_e2e.rs`), `tests/s3-e2e.sh` at the
repository root drives real clients in a microVM (`tests/s3/Dockerfile`) against a
`vk-registry serve` in accounts mode, with TLS on the host's LAN address: `sccache` (a miss
then a hit, read-only with a `read:files/*` key, a wrong secret failing its startup check),
the AWS CLI (`cp` up to 100 MiB each way through multipart uploads and ranged downloads, its
default CRC64NVME and CRC32/SHA-1/SHA-256 checksums, paged `list-objects-v2`, `sync`,
`head-object`, ranged `get-object`, `copy-object`, `delete-objects`, a multipart upload by
hand, a presigned URL refused, `rb --force`) and rclone (`copy` with a multipart upload,
`ls`, `check`, `sync` twice with modification times from metadata, `delete`, `cleanup`); then
`vk registry get` reads an object the CLI wrote and `vk-registry gc` keeps it.

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

Users are selected by email using ASCII case-insensitive comparison. Only an email the
provider has not marked unverified (`email_verified: false`) is stored, and one marked so at
a later sign-in clears the stored value; a provider that sends no `email_verified` at all is
taken at its word, so selecting by email is only as sound as the provider's own checks. A
user promoted while their email stood keeps `is_admin` once it is cleared. The commands
print the issuer and subject of the user they act on. If more than one issuer has asserted
the same email, the command requires `--issuer`. API keys are selected by the full hash
identifier printed by `list-keys`.

`create-key` prints the new token alone on stdout, so a redirect captures it and nothing else;
what to do with it goes to stderr, including the token as S3 clients take it
(`AWS_ACCESS_KEY_ID=vkr_… AWS_SECRET_ACCESS_KEY=vkr_…`, the same value twice). That pair
spells the token out only when stdout is a terminal, so a redirected run leaves it out of a
log stderr may be going to. `/settings/keys` shows a key it mints both ways, on the one page
that ever shows its token.

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

`status` reports stored blob bytes split by whether tags reference them, with in-progress
uploads, and the S3 multipart uploads in progress, counted separately. A blob counts as
referenced when the `gc` mark would reach it from a tag, image indexes included. The
repository table lists tag counts. Bytes without tag references are not a prediction of what
`gc` will reclaim: its retention and grace windows still apply.

`Stage data` is the uncompressed data in recorded completed build stages, including builder
stages but excluding intermediate instruction checkpoints. It sums the chunk placement
lengths per stage tag: shared chunks count again for each stage and each placement, while
sparse holes, config metadata, and unused disk capacity are excluded. This is not a sum of
guest file lengths; filesystem metadata and padding within stored chunks count as data.
Missing size metadata makes the total unavailable rather than silently partial.

On successful stage completion or restore, `vk build` adds a `stage-<hash>` tag in
`build-cache` pointing to the stage's immutable snapshot manifest. A pending upload records
the tag only after it succeeds. These aliases add no image data and follow ordinary tag
retention; the tag counts include them. Existing snapshots do not record stage boundaries,
so the total covers stages built or restored with this tracking in place. With no stage
tags in an existing cache, status reports the stage data size as unknown.

`gc` holds the store lock exclusive only in short spells, so pushes and pulls wait for one spell
at most, not for a whole pass over a large store. One gc runs at a time, serialized by
`.gc.lock` in the store root. It reads every tag and manifest, decides what to drop and marks
what stays under the shared lock, alongside pushes and pulls. It then works in exclusive
spells: the tag drops, the blob sweep, and last the sidecars, membership markers and uploads.
Each spell first brings the mark up to date with whatever was tagged or pushed since, then
re-checks every item it works: a tag is dropped only if its bytes and mtime are as read, a
blob only if still unmarked, unleased and idle. That refresh is the primary safeguard; a
push's touch of the blobs it references, which puts them inside the grace window, is the
backup. A spell works at least 64 items, then more until half a second is spent, so how long
it holds the lock depends on the store's disk and on what was written since the last spell.
Unless the gc waits for good, a spell that cannot have the lock within its wait (about a second
and a half under `Wait::Try`) ends the pass partway: what it had not reached, stale sidecars
and markers included, waits for the next complete pass.

`gc` applies two windows:

- retention controls when idle tags stop being roots; and
- grace protects recent unreferenced blobs, digest-pinned manifests, and uploads, S3
  multipart uploads among them (idle by the newest file in the upload's directory).

A manifest can set its own tags' retention through annotations, which the pusher chooses:
`org.virtkit.retention=keep` keeps a tag however long it sits idle, and
`org.virtkit.expires=<seconds since the epoch>` drops it once that time passes, used or not.
A manifest without either, with one that does not parse, or one that is missing or
oversized, takes the window. One that is there but cannot be read aborts the pass, since it
might be the one keeping the tag: remove the tag or its blob to unwedge gc. The policy
follows the manifest, so every tag on it shares it, and re-tagging a manifest whose
annotations differ is how a pusher changes it (`vk registry put --keep|--ttl` does). An
expired tag's blobs go as any unreferenced blob does, after the grace window.

A reader that goes on reading blobs by path after it lets the store lock go — the lazy disk
views `vk build` boots its cached stages from — leases them: a file under `leases/` naming one
blob per line, written under the shared lock it found them under and locked for as long as the
reader lives. `gc` reads the leases under its exclusive lock and keeps every blob a live one
names, however long it has sat unreferenced; a lease nobody holds is its dead reader's, and
`gc` removes it. A `vk` older than leases takes none, so its builds are protected by the grace
window alone. Leases are as open as the umask allows, so on a store a group shares each member's
`gc` reads the others'. Like the store lock, they rest on `flock`: a store on a filesystem whose
locks do not reach every reader and collector (NFS, some FUSE and virtiofs setups) is not
protected by them.

Membership markers are not roots. After sweeping blobs, `gc` removes markers and manifest
sidecars whose content no longer exists. Repository traversal does not follow symlinks and
is bounded by the same repository-depth limit enforced on writes.

The mark phase follows a rooted OCI image index into its child manifests, through any
nesting, and keeps everything they reference. Each child manifest is visited once, so an
index that lists itself or forms a cycle still terminates. A root manifest it cannot parse
aborts the pass before deleting anything. A child that does not read as a manifest — a layer
an index names, or anything larger than a manifest may be — is kept and references nothing,
so no push can stop collection.

The `/dav/files/` objects are tags and blobs under `files/` and need no pass of their own:
`gc` and `status` treat them as the repositories they are.

## Management by a hub

A registry may enroll with a `vk-hub` (`vk-registry join`), which then sees its inventory,
load and usage and, within what `[hub] allow` lists, makes it read-only, schedules and runs
its gc, and updates it on trial. The registry's authentication and its accounts database are
not involved: the session is an outbound WebSocket to the hub, authenticated with the
registry's own ed25519 key, and everything kept for it is under `<root>/hub/`. Read-only is
enforced after authentication: every write a client asks for — pushes, uploads, deletions,
including a tag deleted from the settings pages — is answered 503, while keys and captions,
which live in the accounts database, and the lock service go on. The pull-through relay is
the exception: a read it relays still caches the digest-addressed blob or manifest it
fetched, so a read-only store still grows by what clients pull through it. See
[`docs/registry-hub.md`](../docs/registry-hub.md).

### Hub tokens

With `[hub] tokens = true`, an enrolled registry also takes the tokens its hub signs for
placed jobs, in either mode, beside the mode's own credentials. A token comes as a bearer,
or as the password of a Basic pair, and is told apart by its `vkt_` prefix. The registry
checks it in memory against the keys the hub last sent in its desired state, kept in
`<root>/hub/state.json` and taken again at start before the first connection: signed by a
known key, for this registry's ID, not expired beyond a minute of skew. A desired state that
sends no keys keeps the previous ones. A bad token is a 401 with the mode's challenge, and
its refusal is logged, a line a minute at most. With tokens on, a shared secret starting with
`vkt_` is refused at start, since it would be taken for a token.

Once the hub answers that it no longer knows the registry (revoked, or not enrolled), the
registry drops the keys, in memory and in `state.json`, and refuses every token. A `vk-registry
leave` under a running `serve` does the same, noticed at the next heartbeat or redial: within
five minutes.

A token is answered by its grants alone: path prefixes with read, write and lock rights. A
prefix covers the repositories at and under it and the plain files under
`/dav/files/<prefix>/`; the pages, uploads and settings are refused to a token. Mounting a
manifest's references for a token skips the store-wide existence check, so neither the
answer nor its timing says whether the store holds a digest outside the token's grants.

Tokens confine only on a registry that refuses requests without credentials. On an open one
(shared-secret mode with no secret), a token's grants limit nothing more than sending no
credential does.

### Retention by prefix

`[[gc.prefix]]` gives the tags under a prefix (`path`, `path/…` and `files/path/…`) an idle
window of their own, `retention_days`, below the hub's floors if need be, since the operator
set it; the most specific prefix wins. Under such a window `org.virtkit.retention=keep` is
ignored and `org.virtkit.expires` holds only within it, since whoever may push there chose
them. `vk-registry gc --config` applies the configured windows to the store that config
names. A window replaces the store-wide retention while a pass removes tags by age at all,
and a tag it governs is one the size limit may drop, as any tag only age keeps. With gc in
`[hub] allow`, the hub may lengthen a configured window, and set windows on other prefixes no
shorter than `[hub] min_retention_days` nor than a configured window covering them; anything
else it asks is refused and reported as `prefix-retention`. Under a window the hub set, `keep`
and `expires` hold as they do store-wide, against the size limit too: a hub cannot drop a tag
pinned there, nor one before its date.

## Guest credential proxy

With `vk run --registry-proxy` or `[registry] proxy_guests = true`, the host starts a
loopback reverse proxy that injects the runner's registry credential — a bearer token when
`token_file` names one, else the Basic pair, the precedence every other `[registry]` client
applies. The guest accesses it without credentials at `registry.vk` through a sentinel
address handled by the userspace network switch.

The proxy never binds a network interface, and request and response bodies stream in both
directions. This keeps registry credentials out of guest jobs without buffering large
layers. The feature is opt-in and requires guest networking.

The runner's credential is not scoped, so the proxy lends it for `/v2/` only. Under
`[registry] guest_credential = "job"` it lends a hub-placed job's own token instead, whose
grants this registry enforces ([Hub tokens](#hub-tokens)), and forwards `/lock/` and
`/dav/files/` and the S3 view (`/s3`) too; under `/dav/files/` only GET, HEAD, PROPFIND, PUT,
MKCOL, DELETE and OPTIONS pass, MOVE and COPY naming the proxy in their `Destination`, and
under `/s3` GET, HEAD, PUT, POST, DELETE and OPTIONS. A job without a token, a gitlab-runner
job included, gets a proxy that refuses everything.

On `/s3/`, the proxy replaces the guest's `Authorization` — SigV4 with dummy keys, or none —
with the job's token, so the guest holds no key, and drops `x-amz-security-token`. An
`aws-chunked` body passes as sent: authenticated by a bearer, its framing is decoded and its
chunk signatures are not checked (see `aws-chunked` bodies above). The job's areas map as on
`/dav/files/`: `/s3/job/<alias>/<key…>` is the key below the area's prefix, so for the prefix
`a/b/c`, bucket `a` and key `b/c/<key…>`, and a copy's `x-amz-copy-source: /job/<alias>/<key>`
likewise. `/s3/job/<alias>` alone is the area as a bucket: the real bucket `a`, whose listings
(`ListObjects`, `ListObjectsV2`, `ListMultipartUploads`) are given the key prefix `b/c/`
before their `prefix`, `start-after`, `marker` and `key-marker` and inside their
`continuation-token`, a `prefix` when they name none; an area below its bucket takes only
reads there, since creating, deleting or batch-deleting its bucket would act on all of `a`.
The documents answering a request through an area name it back: the bucket as `<alias>`, keys,
prefixes, markers and continuation tokens without `b/c/` (a key outside the area as it is),
and the paths in `Location` and `Resource` as `/s3/job/<alias>/…`.

## Connection limits

Every limit below applies before authentication, so a client that connects and sends
nothing cannot hold a task and a descriptor indefinitely: 10 s to finish a TLS handshake,
30 s for a request's headers to arrive (on connect, and again whenever a kept-alive
connection goes idle).

- **`max_connections`** (default 4096) is how many connections are served at once. Past it,
  the server stops accepting until one closes, and new clients wait in the listen backlog
  (4096).
- **`max_connections_per_client`** (default 1024) is how many of those one client address
  may hold: an IPv4 address, or an IPv6 /64, the block one host is commonly given. Without
  it, one busy host — a CI runner whose jobs all start pulling at once — could take every
  slot and leave the other runners waiting in the backlog. A connection past it is
  answered `503` with `Retry-After: 2`, the server's `WWW-Authenticate` challenge (a client
  probing `/v2/` learns from it how to authenticate) and an OCI `TOOMANYREQUESTS` error,
  then closed once up to 64 KiB of an unread request body is drained. At most 64 such
  answers are pending at once, each bounded by the handshake timeout and 12 s; past that, a
  turned-away connection is closed unanswered. The cap is logged at most once a minute per
  address, with the count turned away since the last line. Behind a TLS-terminating
  reverse proxy every client is the proxy's address: set it equal to `max_connections`
  there.

The server speaks HTTP/1.1 only, so every request in flight is a connection. `vk` fetches
or uploads up to 16 blobs at once per pull or push, so a host running N of them at once
holds up to 16·N connections; size `max_connections_per_client` to the busiest host and
`max_connections` to the fleet. `vk` waits out a `503`, a `429`, or a connection closed
before any answer for up to three minutes, with jittered exponential backoff; clients
before that change retried a closed connection three times over 14 s and fail on a `503`
at once. Build-lock requests (`/lock/`) are turned away like any other; the lock client
waits out a `503` too, an acquire for its own wait or at least 30 s, a renewal for up to
half the lease. Its release, holder and failure-memo calls do not: they are best effort, and
a refused release leaves the lock held until its lease runs out.

Each connection holds a file descriptor, beside the store files being read and written.
`serve` raises its soft open-file limit to the hard limit (at most `fs.nr_open`) and warns
when that is still below `max_connections` plus 256. The unit `install-service` writes sets
`LimitNOFILE=1048576`; a server started by hand gets the shell's limits.

## Operational constraints and deferred work

- The lock manager and accounts database assume one server process. Multi-replica operation
  requires a distributed lock implementation and a replicated account store.
- Pull-through cache eviction is retention-based; there is no size-capped LRU policy.
- `files/` entries expire through `gc`'s store-wide retention unless their manifest keeps or
  expires them; there is no per-directory policy and no size cap (see "Lifecycle").
- Retention annotations are trusted from any account with push rights: a pusher can keep its
  tags past the operator's window, and there is no quota.
- Every `files/` directory is a repository. `sccache` shards keys as `a/b/c/<key>`, so one
  cache directory grows to up to 4096 repositories and the path components above them, and
  each entry costs about five files — the tag, the manifest sidecar, the layer's membership
  marker and the pool's manifest and layer blobs, the last two shared with identical
  entries. Everything that walks every repository name pays for those directories: a
  membership miss on `/v2/` (`readable_through`), a `/dav/repos/` prefix lookup or listing,
  an S3 listing of such a directory without a delimiter, `/browse`, `status` and `gc`.
- The `files/` area trusts its writers: a stored compiler-cache entry is linked into every
  project computing the same key, so write access belongs to trusted pipelines only (see
  "WebDAV view"). A key reaches exactly the same content over `/v2/`, `/dav/` and `/s3/`.
- SigV4 needs the server's clock within 15 minutes of its clients'. A reverse proxy in front
  of `/s3/` must pass `Host` and the path unchanged, since the signature covers both.
- The store directory must be writable only by trusted local users. Requests can follow
  symlinks in parent directories under `repos/files/`; checks reject only a symlink at the
  final path component. Preventing this requires descriptor-relative path resolution.
- Chunk boundaries are client-defined. Clients using different chunkers share the blob pool
  but may not deduplicate the same artifact effectively.
- Expired sessions are removed when presented, not by a periodic sweep.
- Sessions are read-all with administrator-only write. Per-user session scopes are not
  implemented.
- The server has no durable request audit log. Administrative changes are logged to stderr:
  `accounts admin: <peer>:` identifies the admin socket peer; `accounts web: <identity>:`
  identifies the session for browse and settings changes (tag deletion, API key minting and
  revocation, captions, uploads). Writes through `/v2/`, WebDAV and S3, including tag removal
  and replacement, are not audited.
- OIDC trusts platform roots only and caches discovery until restart.
