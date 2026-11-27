# vk-registry design

`vk-registry` is a central OCI Distribution server for virtkit runners. It provides four
services behind one listener:

- a content-addressed OCI store shared by all runners;
- a pull-through cache for upstream registries;
- a leased lock service that coordinates build-once work across runners; and
- plain files for build caches such as `sccache` (over S3) and for install media and other
  artifacts (`/files/`), backed by the same blob pool.

The server is intended to run on a dedicated host or as a user service. Local virtkit use
does not require it: `vk` uses the same `Store` implementation directly for its default
on-disk build cache.

The design favors a single authoritative process and a local filesystem over external
coordination services. Writes and garbage collection are coordinated on that host, and
individual file publications are atomic. Multi-replica operation is explicitly out of
scope.

## Architecture

The `vk-registry` crate contains both the reusable store library and the server binary.
The library provides the store, OCI routes, pull-through relay, build lock service, plain
files, and authentication. In accounts mode it also provides OIDC login, browser, upload, and local
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
  uploads/<id>                  in-progress upload, or a request body being staged
  uploads/owners/<id>           repository that opened the upload
  flat/<prefix, / as +>/        a flat store bound with [[flat]] (see "Flat stores")
  accounts/accounts.db          account data when accounts mode is enabled
                                (for the default store, see "The default store")
```

Plain files use the same pool: each object is a tag on a raw-file manifest in a `files/`
repository, with its bytes stored as a blob. See "Plain files". The objects under a prefix
bound with `[[flat]]` are the exception: they are files in a flat store of their own.

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

Nonempty PATCH and PUT bodies stream to separate files under `uploads/`. An interrupted
request leaves the session intact, so the client can resend the chunk. A nonempty PUT to
an empty session uses the staged file directly and can reuse the digest computed during
receipt for a raw body.

The blocking pool handles appends, compression and any remaining hashing in bounded
memory under the session lock. Garbage collection can sweep an idle session during this
work. Before publishing, the handler takes the shared store lock, rechecks the repository
binding, installs the blob if absent, records membership and cleans up the session.
Hashing, compression and store-lock errors roll back the final chunk for retry. A failed
rollback invalidates the session. A failed installation attempts to remove the staged files.

The blocking pool handles blob and manifest reads with their membership checks, manifest
pushes and deletes, batched manifest probes, storage of relayed manifests, `/browse` pages,
manual upload storage, admin tag deletion and plain-file downloads. A slow repository lookup
or a store lock wait leaves the runtime worker free to read other connections.

Each store limits work that may wait on its lock to 64 blocking tasks. The limit covers
manifest pushes, deletes and probes, relayed manifest storage, manual upload storage,
admin tag deletion, upload finalization, relayed blob promotion, plain-file promotion and
deletion, and file puts. Other lock waiters await a slot without occupying a thread,
leaving blocking threads available for upload chunks and plain-file reads during `gc`. Each
task keeps its slot until it finishes, even if the request is dropped. Upload-session
bookkeeping and OCI tag listings run on the runtime and take no store lock. A tag listing
reads and sorts the entries in one repository's tags directory.

A request for a session the repository does not have is refused before its body is read.

Manifest uploads are limited to 16 MiB and 65,536 distinct digest references. At task-rs's
1 MiB average chunk size, this allows cache snapshots of about 64 GiB uncompressed. The
limits bound memory use and authorization work under the store lock.

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
canonical form. The server skips compression for raw uploads with gzip, zstd, xz or bzip2
headers or a ZIP local file header. Clients that do not see the capability header use
standard identity uploads.

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
Digest-addressed manifests follow the normal manifest write path without creating a tag,
except that they are kept as the upstream wrote them even when a descriptor names a digest
that is not `sha256:<64 lowercase hex>` (OCI allows other algorithms). Nothing in the store
reads through such a digest, and `vk` refuses it before using it.

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
miss searches the repositories the principal may read, the `files/` tree last, so a digest
an image repository holds is found without listing the plain files' directories. A manifest
`PUT` lists readable repositories only if a reference needs a cross-repository check. For a
hub token, the search is limited to `<prefix>` and `files/<prefix>` for each read grant.
For users and API keys, one blob-pool lookup skips the search if the digest is absent.
A read-scoped API key can use `HEAD` timing to distinguish this miss from a digest held
only in unreadable repositories. Hub tokens search their granted trees in either case.

A manifest `PUT` naming a digest that is not `sha256:<64 lowercase hex>` — config, layer,
index child or subject — is refused with `DIGEST_INVALID`, in every mode, rather than having
that digest skipped by the check. Otherwise it succeeds only if every referenced digest is
already readable by the caller. Accepted references receive membership in the target repository. Validation and
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

The account database is a `redb` file at `<root>/accounts/accounts.db` by default (for the
default store, see "The default store"). `redb` is
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

### Streamed file puts

`PUT /files/<dir>/<name>` stores one file streamed whole, as `vk registry put --dir <dir>`
stores it: one blob, tagged `files/sha256:<sha256>` and `files/<dir>:<name>` on a raw-file
manifest whose layer is titled `<name>`. With `?under=<path>`, both repositories are under
`<path>/`, where a client whose registry repository is `<path>` (`vk registry put` with
`--cache-registry <host>/<path>`) finds them. The writer needs write on both repositories;
`<dir>` may not be `sha256`, repository names are at most 255 characters and the tag at most
128. A chunked body is refused with 411; a request with neither `Content-Length` nor a
chunked body is an empty file. Optional headers: `vk-sha256`, the digest the bytes must hash
to; `vk-retention: keep`, which marks both tags `keep` (see "Retention by prefix" for where
that is ignored); `vk-annotations`, a base64url JSON object of strings (at most 16 KiB
decoded) for the manifest, retention annotations excepted. The answer, `201` with `{sha256,
size, manifest}`, comes once both tags are written.

The route is checked like any other write: authentication first, then write on both
repositories, once, when the request arrives. A registry with no authentication takes file
puts from anyone who reaches it. Everything but the body's length and digest is checked
before the body is read, so a request refused for it stages nothing.

The body streams to a staging file under `uploads/`, hashed on the way, and is installed
uncompressed, by choice: compressing would cost a second pass over gigabytes. Nothing is
tagged unless every declared byte arrived and, when `vk-sha256` is given, the bytes hash to
it; a body cut short, refused or silent for five minutes (408) leaves no staging file. A
failure while the tags are written can leave the blob and the digest tag; putting the file
again completes it.

Each registry process streams two puts into a store at once and answers a third 503 with
`Retry-After`. A slow client keeps its slot as long as no gap between frames reaches five
minutes. A put that would leave less than 1 GiB free on the store's filesystem is refused
with 507 before its body is read. Its staging file is then given the whole declared size
on disk (`fallocate`), so other writes cannot take the space it was admitted for, and the
put is refused if the claim leaves less than 1 GiB. Where the filesystem cannot preallocate, the put's size counts
against the free space of the process's next puts until it ends; another process serving
the store, during a handover, does not see it. The 1 GiB is checked, not reserved: other
writes can still fill the store, causing a put to fail while streaming or writing its tags.
Registries advertise the route to their hub in their inventory.

### Plain-file reads and deletions

`GET`, `HEAD` and `DELETE` on `/files/<dir>/<name>` act on the object `files/<dir>:<name>` as
`/s3/` serves it (see "Plain files" for the rules both follow, except that `<name>` may be any
tag a file put writes, `tags` included, and a leaf as long as a component may be): a file put
there, `/files/sha256/<sha256>` for one by digest, which serves only a file whose bytes hash to
that digest, or an object written over S3. A read needs `Read` on the repository the path
resolves to, a deletion `Write` there; a caller holding the action on neither the path's own
name nor its parent's is 403 before anything is looked up, and an object it may not read is
otherwise 404. A read answers as "Plain files" describes, with `Accept-Ranges: bytes`; a `GET`'s
single byte range (`bytes=<first>-[<last>]`, `bytes=-<n>`) is served as a 206, one starting past
the end is 416, and several ranges, an `If-Range` or a malformed one get the whole object; a
`HEAD` always describes the whole object. A stored zstd frame is decoded from its start up to
the range. Every request's body is read through before the answer. `DELETE` drops only that tag
(204, 404 when absent): the file stays reachable by digest and under any other name until gc
expires them; a directory or a tag that is not a raw file is 409. Preconditions are not
evaluated: a read ignores `If-None-Match` and `If-Modified-Since`, and is 501 with `If-Match` or
`If-Unmodified-Since`; a `DELETE` with any of the four is 501. Queries are ignored, git's dumb HTTP probe `info/refs?service=…` among them,
except `under=`, which is a put's and refused with 400.

## Build-once lock service

The registry process is the authority for leased locks. No Redis or shared filesystem lock
is involved in the request path. Locks are process-local: restarting the server releases all
leases, unless it hands its table to the release that updates it.

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

### The default store

Without an explicit root, `vk-registry` shares `vk`'s default build store at
`$XDG_CACHE_HOME/virtkit/registry` (normally `~/.cache/virtkit/registry`). `--root` and the
config's `root` override it; `status`, `gc` and the commands that read the accounts database
also take `VK_REGISTRY_ROOT`. Releases through 0.116 kept the store at
`$XDG_DATA_HOME/virtkit/registry`.

`serve` and `install-service` migrate the legacy store when they resolve the default.
Resolving `vk`'s image-cache root also migrates `docker/` and `build/`. On the same
filesystem, `renameat2(RENAME_EXCHANGE)` swaps the directory with a symlink to its new
path. Without exchange support, migration renames the directory before creating the
link, and a migration interrupted in between creates it next time. Older binaries can use
the old path once the link exists. A migration that fails leaves the store where it is,
and it is used there.

Across filesystems, nothing is copied: the old directory stays, and the new path links to
it. If the old path is a user symlink, the new path links to its target. If both paths hold
separate directories, migration keeps both, uses the new one and warns. Selecting an
explicit root, reporting status and collecting garbage do not migrate the store.

Set an explicit root for content that must survive cache cleanup. A server using the
default store, including through an alias, keeps its accounts database and hub enrollment
under `$XDG_DATA_HOME/virtkit/registry-server/{accounts,hub}`. `serve` moves there, by one
rename, either one an older release kept inside the store, when its user owns the store
and no other process holds the accounts database; otherwise the server uses it where it
is, and a note says where to move it while no server runs.

### Locks of a local store

A local store has no daemon. A process that serves one in-process would be a lock authority
of its own, next to every other process of the host doing the same. A lock manager made
host-shared for a store root instead acts as one authority with the others made so. For each
name it leases, it also holds a host lock: an abstract Unix socket, shared by the processes
of one network namespace, named after the resolved store root and the lock name. It stays
bound while the lease lives and is closed when the lease is released or lapses, or when the
process dies, once no child holds a copy of it. A `vk build` caching into a local store
takes the same host lock directly around a stage, with no lease, so it and such a manager
exclude each other on a name. The `vk-registry` server keeps its process-local table, even
over the same store.

- A batch is still all-or-nothing: a name another process holds unbinds what the batch had
  bound, and the acquire tries again within 250 ms until its wait is over.
- `/lock/status` and the blockers of a refused acquire name another process's holder by
  asking it over the socket. The holders asked share what is left of the acquire's wait, or
  250 ms when less is, and one second for a status request. A holder that says nothing by
  then is named `another process`.
- A lapsed lease is removed when it lapses, not at the next request, since other processes
  wait on its socket.
- A lease lasts at most 5 minutes, and a manager holds at most 256 at once, answering 429
  past them: no token bounds the clients of an in-process server.
- The socket namespace has no permissions. A name bound by another user's process, or that
  three queries in a row cannot connect to, is not waited for: the lease is granted and
  excludes that manager's own clients only, as when the name cannot be bound at all. A
  holder that connects and names no one is waited for. Sharing is an optimisation, never a
  reason to hang or fail.
- The store root is created when missing, so that every process resolves it to one name.
- Failure records are not shared between processes, and a host-shared manager refuses to
  hand its table over: the sockets would not follow.

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

## Plain files (`/files/`, `/s3/`)

A plain file is a named object over the pool. A path's directories are a repository under
`files/` and its leaf a tag on a single-layer raw-file manifest, the shape `/upload` and a
file put write: `sccache/a/b/abcdef` is the tag `abcdef` of the repository
`files/sccache/a/b`, and its bytes are the layer blob. An object therefore dedups,
compresses and is collected like any other content, and is reachable over `/v2/` and
`/browse` under that name. `/files/<path>` reads and deletes it ("Plain-file reads and
deletions"), `PUT /files/<dir>/<name>` stores a file under two tags ("Streamed file puts"),
and `/s3/<bucket>/<key>` reads and writes it as one S3 object (below). Directories are
implicit: there is no listing and no way to create or remove one.

File grants use the same repository names as `/v2/`. An S3 `PUT` needs `Write` on the
parent repository. `PUT /files/` also needs `Write` on the digest repository,
`files/sha256` by default. A writer scoped to one directory can therefore store a single
name over S3.

Before lookup, `GET` and `HEAD` check `Read`, and `DELETE` checks `Write`, on the path's
repository name or its parent. If neither grants the action, the registry returns 403.
After lookup, an unreadable object appears absent even to `DELETE`, which also needs
`Write` on the resolved repository. An S3 `PUT` onto a directory or a non-file tag, or
below a tag, reveals the conflict even when the writer cannot read that name.

The example key belongs to `files/sccache/a/b`. Both `write:files/sccache/*` and
`read:files/sccache/*` cover `files/sccache` and its descendants. An exact `files/sccache`
grant covers only objects directly in that repository. The registry treats `sccache` as
an ordinary directory.

Every component obeys the OCI name rules — `[A-Za-z0-9._-]`, at most 16 components counting
`files`, the directories and the leaf, with `tags`, `manifests` and `blobs` reserved — for
S3 keys. For `/files/` reads and deletions, only the directories count toward the repository
depth limit. The leaf is a tag and may use any of those three names.

S3 requests and `/files/` reads and deletions split on raw `/` before decoding `%XX` in
each component as UTF-8. `+` stays literal. Invalid names return 400, including decoded
separators, `.`, `..`, empty components, components over 255 bytes, control characters,
malformed escapes and invalid UTF-8. `PUT /files/` validates the literal path and limits
the repository name to 255 bytes and the tag to 128.

A non-file tag, such as an image pushed into `files/` over `/v2/`, is absent to file reads.
An S3 `PUT` or a `/files/` `DELETE` returns 409 there. `PUT /files/` can replace it.
When credentials are required, an unauthenticated client gets a 401 challenge at `/files/`
and 403 `AccessDenied` at an enabled S3 object route. Neither redirects to login.

A read serves the layer as `application/octet-stream` with `nosniff` and
`Content-Disposition: attachment`. A directory, a missing path or an object with a trailing
`/` returns 404 on file lookup. `Last-Modified` reports the tag's mtime before the read.
A successful `GET` refreshes that time for gc if the tag is more than an hour old.
`HEAD` leaves both the tag and the layer blob untouched.

An S3 `PUT` hashes the body as it streams to `uploads/`. Under the shared store lock, it
promotes the blob and tags its manifest, creating missing parents and leaving replaced
content for gc. A bucket alone, a directory, a trailing `/`, a path below a tag or a
non-file tag cannot be an upload target.

The object handler drains refused requests and `DELETE` bodies up to 4 GiB. A declared
`Content-Length` over that cap returns 413 immediately. A streamed body returns 413 when
it crosses the cap. Earlier checks, including authentication, can refuse a request
without draining it. Unread request bytes can cause a reset that hides the status from
the client. A read-only key can fetch cache entries and gets 403 on the sccache probe
write. Give write access only to trusted pipelines, such as protected branches. Give
other pipelines read-only keys and use separate directories for separate trust levels.

S3 promotion and `/files/` deletion run their final path checks and namespace changes
under both a process-local lock and the store's cross-process namespace lock. An S3
`PUT` rechecks after staging, so competing S3 writes cannot make one path both a
directory and an object. `/v2/` pushes and `PUT /files/` take no namespace lock.
Reads, S3 promotion and deletion run on the blocking pool.

### Lifecycle

An object is a tag, so `gc` expires it as it expires every tag: dropped once idle past the
applicable retention window, subject to manifest keep and expiry annotations and
`[[gc.prefix]]` rules. See "Retention by prefix" and "Garbage collection and reporting".
GC sweeps unreferenced blobs after the grace window. S3 writes no retention annotations.
`vk registry put --keep|--ttl` does.

Like `/upload` and `/v2/` pushes, file puts take no namespace lock. A file put can create
a tag with the same name as a directory. File lookup finds the directory first. A `PUT`
sets the tag's mtime. A successful `GET` refreshes it after more than an hour, so hits
from read-only pipelines also keep an entry alive. There is no write-time quota per cache
directory. Replacement and deletion reclaim blob space only when gc sweeps the bytes.
GC removes staging files left by crashed uploads with other idle files in `uploads/`.

### Flat stores (`[[flat]]`)

Tags suit small collections of long-lived files. Compiler caches write many small entries
once and often look up missing keys. As tags, each entry costs about five files. Misses
leave negative dentries, writes take the namespace lock, and `gc` walks the entries without
enforcing a size cap. A `[[flat]]` table gives a directory below `files/` its own flat store.

```toml
[[flat]]
prefix = "sccache"   # files/sccache/…, the S3 bucket sccache
cap = "200G"         # required; evict least recently used objects above this cap
evict_to = 0.9       # evict down to this share of cap [default: 0.9]
durable = false      # sync each object before acknowledging it [default: false]
```

A prefix has at most 14 lowercase repository components. Prefixes cannot overlap or start
with `sha256` or `files` as a component. Each object occupies one file under
`<root>/flat/<prefix with / as +>/`, named by the SHA-256 of its key. The store preserves
the uploaded bytes, including sccache's compression.

Each serving process has one in-memory index per store. It loads the 256 shards on demand
and tracks changes with inotify. An indexed miss needs no lookup of the absent name.
Reads, writes and deletes take no cross-process lock.

When usage exceeds the cap, the process holding `evict.lock` evicts the least recently used
objects in the background, aiming for `evict_to` times the cap. A hit attempts to refresh
the object's mtime when it is at least an hour old. Without `durable`, power loss can leave
a partial object. sccache can detect a corrupt entry and treat it as a miss. The registry
opens every bound store at startup and fails if any cannot be opened. A hub with `flat` in
the registry's `[hub] allow` may bind more prefixes while it serves, resize them and unbind
them (see "Management by a hub"): a store whose prefix stays bound keeps its instance and
index, and a store that fails to open leaves the bindings as they were.

The key is the decoded path below `files/`. These routes use the flat store for keys
strictly below its prefix (`<prefix>/<anything>`):

- S3 supports `GET`, `HEAD` and `PUT`. `/files/` supports `GET`, `HEAD` and `DELETE`.
  Each route keeps its path and request checks. S3 uploads have the same body limit and
  `x-amz-content-sha256` check as tagged uploads. A `PUT` replaces the whole object.
  The last upload published wins.
- Reads and deletes return 403 before lookup if neither the key nor its parent grants the
  requested action. After admission, a read or delete returns 404 without `Read` on the
  parent. Deletion also requires `Write` there and returns 403 to a reader without it.
  S3 `PUT` requires `Write` on the parent.
- Reads retain the tagged routes' download headers and single-range handling. Flat
  responses omit `Last-Modified`, `ETag` and `Docker-Content-Digest`. The file's mtime
  records use. A `HEAD` hit can refresh it too.
- Flat keys have no directories. `a/b` and `a/b/c` can both be objects. A trailing slash
  returns 404 on a read, 409 `InvalidRequest` on S3 `PUT`, and 400 `NAME_INVALID` on a
  direct `/files/` upload.
- Direct `PUT /files/` returns 405 with `Allow: GET, HEAD, DELETE` for valid flat object
  paths, including file names over 128 characters. A successful upload writes a digest
  tag and returns the manifest digest. Uploads with `?under=` still use tags.
- `/files/sha256/<hex>`, `/v2/`, `/browse` and tag GC do not see flat objects. Below a
  bound prefix, S3 and `/files/` look only in the flat store. Existing tags retain their
  GC policy. Unbinding leaves the flat store on disk for the operator to remove.

## S3 view for sccache (`/s3/`)

sccache's S3 backend (OpenDAL's path-style `s3` service) can read, stat and write cache
objects at `/s3/<bucket>/<key>` with `GET`, `HEAD` and single-request `PUT`. Each object is
a tag in the plain-file store, visible to `/browse` and gc. Read it at
`/files/<bucket>/<key>`, or with `vk registry get` when its name is a valid CLI reference.
A read by digest also checks that the layer matches the digest tag. S3 `GET` and `HEAD`
both support a single byte range. `/files/` supports ranges on `GET`. An unsatisfiable
S3 range returns 416 `InvalidRange`. S3 defaults on. Set `s3 = false` to disable it.

The service root, bucket operations, other methods and nonempty queries (listings, presigned
URLs, multipart and sub-resources) return 501 `NotImplemented`. So do `Content-MD5`,
streaming payloads (`STREAMING-…`), a `Content-Encoding` other than `identity` (`aws-chunked`
included), `If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`,
`Content-Range`, and `x-amz-*` headers other than `x-amz-date` and `x-amz-content-sha256`.
The store ignores preconditions, writes whole objects verbatim and keeps no content coding
to return on a read. After verifying the signature, S3 admission drains a refused
upload's body as the plain-file handler
does, with the same 413 past the object cap.

Only SigV4 requires `x-amz-content-sha256`. Other than a `STREAMING-…` marker, a value must
be one `UNSIGNED-PAYLOAD` or lowercase SHA-256 digest, or the request returns 400. Signature
checks run first, so an unsigned `x-amz-*` header on a signed request returns 403
`AccessDenied`. A `PUT` creates missing parent directories, including the bucket. A missing
key returns 404 `NoSuchKey`, a cache miss for sccache.

**Credentials.** Set both `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` to the registry
credential (an API key, hub token or shared bearer). The registry uses the access key as the
secret to verify the SigV4 header signature (`AWS4-HMAC-SHA256`). It stores no separate S3
secret and keeps API keys hashed.

Sign `host`, `x-amz-date` and every `x-amz-*` header, including the required
`x-amz-content-sha256`. The scope must name the `s3` service. The region can be any nonempty
sequence of ASCII letters, digits and hyphens. The date must be within 15 minutes of the
server clock. A `PUT` that supplies a SHA-256 in place of `UNSIGNED-PAYLOAD` must match it
before publication. A mismatch returns 400 `XAmzContentSHA256Mismatch`.

The registry strips cookies and serves a signed request as one carrying
`Authorization: Bearer <access key>`: the credential is checked as on any route, then the
object's grants as "Plain files" describes them, including
`write:files/<bucket>/*` and hub grants. Requests without `Authorization` get the anonymous
permissions. Bearer or Basic credentials on unsigned requests are checked the same way.
For example, sccache can use `SCCACHE_S3_NO_CREDENTIALS=true` with a proxy that injects the
job's bearer token. Shared Basic credentials cannot serve as access keys. A shared bearer
containing a comma cannot sign because commas separate the SigV4 authorization fields.

Use TLS to protect the `Authorization` header. It contains the access key in clear text,
so anyone who obtains it can sign another request. S3 tooling treats access key IDs as
public. Client debug logs (`SCCACHE_LOG=debug`) and proxies may record the credential.
The registry returns S3 XML errors. When authentication is enabled, a rejected credential or
a failed grant check before lookup returns 403 `AccessDenied`, which sccache reports at
startup or as a read-only cache. A read allowed to look up a path returns 404 `NoSuchKey`
if the resolved object is inaccessible.

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
uploads counted separately. A blob counts as referenced when the `gc` mark would reach it
from a tag, image indexes included. The repository table lists tag counts. Bytes without
tag references are not a prediction of what `gc` will reclaim: its retention and grace
windows still apply.

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
- grace protects recent unreferenced blobs, digest-pinned manifests, and uploads.

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

Plain files are tags and blobs under `files/` and need no pass of their own:
`gc` and `status` treat them as the repositories they are.

Flat stores (`[[flat]]`) have separate usage totals and eviction. For an existing registry,
`status --config` lists each configured prefix's object count, size and cap. It opens only
existing areas and counts a missing area as empty. Opening an area for inspection reaps
abandoned uploads without evicting objects.

After collecting repositories, `gc --config` attempts an eviction pass on each existing flat
store. A pass evicts objects when the store is over cap and reaps abandoned uploads even
below cap. The command reports stores left to another process and fails on eviction errors.
A running `serve` normally holds `evict.lock` and checks the cap at one-second intervals.
A dry run reports flat usage or counting errors and skips flat eviction. A root supplied by
`--root` or `VK_REGISTRY_ROOT` disables the config's `[[flat]]` bindings and `[[gc.prefix]]`
windows.

Hub-requested and scheduled gc also attempt flat eviction. When repository gc succeeds,
the hub's report includes the bytes freed by flat eviction and any flat eviction errors.
The registry sends up to 64 flat stores in `Usage.flat`. Older hubs ignore the field.

## Management by a hub

A registry may enroll with a `vk-hub` (`vk-registry join`), which then sees its inventory,
load and usage and, within what `[hub] allow` lists, makes it read-only, schedules and runs
its gc, binds prefixes to flat stores beside `[[flat]]`, which wins for any prefix it binds,
above or below, and updates it on trial. The registry's authentication and its accounts database are
not involved: the session is an outbound WebSocket to the hub, authenticated with the
registry's own ed25519 key, and everything kept for it is under `<root>/hub/` (for the default
store, see "The default store"). Read-only is
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
sends no keys keeps the previous ones. The desired state also lists revoked subjects, as
`node:<id>` for a node the hub removed: a token whose `sub` is one is refused whatever it
says, now and after a restart, until the hub drops it from the list once none of its tokens
can be live; a desired state with no list keeps the previous one, as does one listing more than
4096. The registry announces this in its inventory, and the hub sends such lists only to a
registry that does. A bad token is a 401 with the mode's challenge, and
its refusal is logged, a line a minute at most. With tokens on, a shared secret starting with
`vkt_` is refused at start, since it would be taken for a token.

Once the hub answers that it no longer knows the registry (revoked, or not enrolled), the
registry drops the keys, in memory and in `state.json`, and refuses every token. A `vk-registry
leave` under a running `serve` does the same, noticed at the next heartbeat or redial: within
five minutes.

A token is answered by its grants alone: path prefixes with read, write and lock rights. A
prefix covers the repositories at and under it and the plain files under `/files/<prefix>/`
and `/s3/<prefix>/`; the pages, uploads and settings are refused to a token. Mounting a
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
reverse proxy that injects a registry credential: the one `vk run` was given, or the
runner's — a bearer token when `token_file` names one, else the Basic pair, the precedence
every other `[registry]` client applies. The guest accesses it without credentials at
`registry.vk` through a sentinel address handled by the userspace network switch.

The proxy listens on a Unix socket rather than a port, and serves only processes of the user
running `vk`: the host's other users cannot borrow the credential through it. The proxy and
the switch each require the uid at the other end of a connection to be their own. Neither
accepts the kernel's overflow uid (`/proc/sys/kernel/overflowuid`, 65534 by default), which
stands for every user a user namespace cannot name: a `vk` running as that uid starts no
proxy. Large layers stream in both directions without being buffered; a request the proxy
can send again is held for that up to 16 MiB. The feature is opt-in and requires guest
networking.

The runner's credential is not scoped, so the proxy lends it for `/v2/` only. Under
`[registry] guest_credential = "job"` it lends a hub-placed job's own token instead, whose
grants this registry enforces ([Hub tokens](#hub-tokens)), and forwards `/lock/`, `/files/`
and `/s3/` too; under `/files/` only GET, HEAD, PUT and DELETE pass, so no MOVE or COPY names
the proxy in its `Destination`. A job without a token,
a gitlab-runner job included, gets a proxy that refuses everything.

A `vk dev` environment with `[dev.cache] shared` gets a proxy over its shared caches instead:
a local store of their own (`$XDG_CACHE_HOME/virtkit/shared-cache`), private to its user and
marked as the shared cache store, which each run serves in-process on a loopback port, behind
a bearer token made for that run and with [host-shared locks](#locks-of-a-local-store). Each
shared cache is an area: its name `<alias>` is the prefix `dev/<alias>`, the same for every
environment using the store. The token is not scoped, so the proxy does the confining: it
forwards the ping, the manifests and blobs of repositories under an area's prefix, S3 object
`GET`, `HEAD` and single-request `PUT` under one,
with the headers the [S3 view](#s3-view-for-sccache-s3) admits, and `/lock/acquire`, `renew`
and `release` whose every name is under one — by alias (`job/<alias>`) or by real name — and
refuses the rest. That confines names only: a shared-secret credential reads any blob or
manifest of a store by digest, whichever area it was pushed to, which is why the shared cache
store is never the build cache's store nor a registry server, but a store holding nothing
else.

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
  expires them, or `[[gc.prefix]]` sets a window; only a `[[flat]]` store has a size cap (see
  "Lifecycle" and "Flat stores").
- Retention annotations are trusted from any account with push rights: a pusher can keep its
  tags past the operator's window, and there is no quota.
- Outside `[[flat]]` prefixes, every `files/` directory is a repository. `sccache` shards
  keys as `a/b/c/<key>`, so one
  cache directory grows to up to 4096 repositories and the path components above them, and
  each entry costs about five files — the tag, the manifest sidecar, the layer's membership
  marker and the pool's manifest and layer blobs, the last two shared with identical
  entries. An account's `/v2/` membership lookup (`readable_through`) can reach those
  directories on a miss for a digest the store holds. `/browse`, `status` and `gc` also
  visit them. A hub token
  searches only its granted trees, including `files/<prefix>`.
- The `files/` area trusts its writers: a stored compiler-cache entry is linked into every
  project computing the same key, so write access belongs to trusted pipelines only (see
  "Plain files").
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
  revocation, captions, uploads). Writes through `/v2/`, `/files/` and `/s3/`, including tag removal
  and replacement, are not audited.
- OIDC trusts platform roots only and caches discovery until restart.
