# vk-registry design

`vk-registry` is a central OCI Distribution server for virtkit runners. It provides four
services behind one listener:

- a content-addressed OCI store shared by all runners;
- a pull-through cache for upstream registries;
- a leased lock service that coordinates build-once work across runners; and
- a WebDAV view of the store, with a plain-file area that build caches such as
  `sccache`'s write to.

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

The binary provides `serve`, `status`, `gc`, `files`, `install-service`, `accounts`, and
`update`.
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
  files/<dir>/<path…>           plain file, served read-write at /dav/files/
  files/.staging/<pid>-<n>      in-flight WebDAV PUT
  files/.policy/<dir>.toml      eviction policy for files/<dir>
  accounts/accounts.db          account data, when accounts mode is enabled
```

The plain-file area under `files/` is a store of its own beside the pool: its objects are
neither content-addressed nor compressed, and garbage collection's mark phase never sees
them. It has its own eviction, per directory and only where a policy says so. See "WebDAV
view".

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
authentication, and the server logs this setting at startup. File eviction continues.

The verb set is what opendal's `webdav` service issues — the client behind `sccache`, `oli`
and other opendal-based tools: `PROPFIND` at `Depth` 0 and 1, `GET`, `HEAD`, `PUT`, `MKCOL`, `DELETE`
and `OPTIONS`. `Depth: infinity` is refused with 403, as RFC 4918 allows; `COPY`, `MOVE`,
`LOCK` and `PROPPATCH` are 405. No client XML is parsed: a `PROPFIND` body is drained and
ignored, `allprop` being both what the client sends and what an empty body means.

```text
/dav/                                 repos/  files/
/dav/repos/<name>/                    tags/  manifests/  blobs/  (+ nested repositories)
/dav/repos/<name>/tags/<tag>          the manifest the tag resolves to, with its media type
/dav/repos/<name>/manifests/<hex>     that manifest
/dav/repos/<name>/blobs/<hex>         the blob's canonical bytes; a stored zstd frame is decoded
/dav/files/<dir>/<path…>              plain files under <root>/files/, read-write
```

**`repos/` is a read-only view, not an export.** The disk tree is not what a client wants:
a stored blob may be a zstd frame, a tag file holds a digest rather than a manifest, and the
blob pool is readable per repository, not as one directory. So tags and manifests download
as the manifest bytes with their media type and blobs as their canonical bytes, through the
same handlers `/v2/` uses and under the same authorization — `Read` on the repository, and
membership for anything addressed by digest. The tree is derived from the list of
repositories the principal may read, never from a `read_dir` of `repos/`: a repository the
principal cannot read is a 404, as `/browse` answers, and a scope such as `read:team-a/*`
lists `team-a/` and nothing beside it. Every write verb there is 405: an OCI write verifies
a digest, records membership and holds the store lock, and a DAV client cannot supply a
manifest's media type. Those go through `/v2/`. A listing of `blobs/` carries each member's
canonical length, which for a zstd-stored blob is one `open` and a frame-header read; a
repository of chunked bundles lists thousands of members, so that listing is an
interactive operation and never on a CI path.

**`files/` is an ordinary directory tree.** A top-level directory authorizes as the
repository `files/<dir>`: `GET`, `HEAD`, `PROPFIND` and `OPTIONS` are reads, `PUT`, `MKCOL`
and `DELETE` writes, so scopes such as `write:files/*` or `read:files/sccache` apply
unchanged. Nothing in the server knows what `sccache` is; it is a directory that a compiler
cache happens to write to. Objects are plain files kept out of the content-addressed pool —
a cache value embeds its unit's metadata hash, so distinct keys share no bytes, and entries
arrive already compressed. Dot-prefixed names at the top of `files/` are reserved for the
store's own directories (`.staging/` holds in-flight writes): refused as directory names and
absent from listings.

| Verb on `files/` | Answer |
|---|---|
| `GET`, `HEAD` | 200 with the object (`application/octet-stream`, `nosniff`, `Content-Disposition: attachment`); a directory or a missing path is 404 |
| `PUT` | streamed to `.staging/` and renamed into place — 201 when created, 204 when replaced, so a replace is atomic; 413 past 4 GiB; 405 for directories and top-level names, after draining the body |
| `PROPFIND` | 207 for a file or a directory; at `Depth: 1` the directory's members follow it, each with `getcontentlength` (files) and `getlastmodified`, which opendal requires; 404 when absent |
| `MKCOL` | 201, creating missing ancestors — a top-level directory included, which is how one comes to exist; 405 when anything is at the name; 409 when a file is in the way |
| `DELETE` | 204 for an object or an empty directory; 403 for a directory with members; 404 when absent |
| `OPTIONS` | `DAV: 1` and the `Allow` list; every other verb is 405 with the list the resource serves |

A `PUT` answered early still reads its body through: a status sent with request bytes still
unread closes the socket with a reset, and `sccache` takes a reset on its startup probe as
an unwritable store and runs the whole build read-only. A read-only key makes that probe
fail with 403, which the client reports as read-only mode: an untrusted pipeline consumes
the cache without writing to it. Since a writer with `Write` on a directory owns its
content, give write access only to trusted pipelines (protected branches), hand everything
else a read-only key, and use one directory per trust level when that is not enough.

Paths are split on raw `/` before each component is percent-decoded on its own, so `%2F`
cannot smuggle a separator; `.`, `..`, empty, over-long (255 bytes) and control-byte
components, and depth past 32, are refused. Hrefs in a 207 are rebuilt from the decoded
components, percent-encoded, with a trailing slash on a collection. `/dav/` is not a human
path, so an unauthenticated client gets the 401 challenge rather than a login redirect.

**Enumeration** is the one disclosure a listing makes beyond what the caller named. A
`Depth: 1` on `/dav/`, `/dav/repos/`, `/dav/files/` or a path component above repositories
shows only what the principal may read, and on a server with no credential configured at
all it is refused with 403, for the reason `/browse` does not exist in shared-secret mode:
a catalog is not something anyone who can reach the port gets for free. `Depth: 0` there,
which is what opendal's parent walk asks, always answers.

### Eviction policy

A directory under `files/` is swept only once an operator attaches a policy to it: an idle
TTL, a size cap, or both. A directory without one is never swept and grows until somebody
deletes from it; the server names such directories, with their sizes, in its log at startup
and whenever the set changes, and `status` lists every directory with its policy or `none`.
There is deliberately no default: an artifact directory silently expiring after thirty days
is the surprise an explicit per-directory policy avoids.

```text
files/.policy/<dir>.toml      ttl_days = 30            # optional; 0 drops on the next pass
                              max_bytes = "200G"       # optional; binary units, or an integer
```

The policy is a file in the store, not a key in the server's config: it is set by exactly who
may already write the store root — the operator, as the server's user, with `vk-registry
files policy <dir> --ttl-days N --max-bytes SIZE`, or `--clear` — and by nothing else. There is
no HTTP route for it, because `Write` on `files/<dir>` must not be enough to lift that
directory's own cap, or a CI key turns its cache into unbounded storage; a remote operator
reaches the host first. Written atomically, so a pass never reads half a policy; read with a
size cap and without following symlinks. A file at a policy's name that is not a policy fails
closed: the pass logs it, leaves that directory alone, and `status` shows `invalid`, so a typo
makes noise rather than lifting a cap.

The running server re-reads the policy files on every pass and needs no restart or signal. It
looks at `.policy/` every five minutes and runs a pass when the directory's mtime changed — a
policy renamed into or out of it — or an hour has elapsed since the last pass, and once at
startup, so a server restarted onto a full disk starts recovering at once. `vk-registry gc`
runs the same pass, honouring `--dry-run`, after its OCI pass, and prints one line per
directory that lost something.

Idleness is the object's mtime. A `PUT` sets it, and a `GET` refreshes it once it has drifted
more than an hour — a `HEAD` or `PROPFIND` is opendal checking that something exists, not
using it — so a read-only pipeline's hits keep an entry alive as a writer's do, and a cache
read is a disk write at most once an hour per object. A pass over one directory is two walks
in constant memory: a read walk sums object lengths into a histogram of idle ages (to the
minute under a day, to the hour past it), from which one cutoff falls out — the TTL's bucket,
lowered bucket by bucket from the idlest kept until what is fresher than it fits the cap — and
a write walk drops everything past the cutoff, from the cutoff's own bucket only as many bytes
as the cap still needs (its objects are equally idle, so which of them go is not a choice
worth a sort), then the subdirectories that leaves empty, never the top-level directory the
policy is attached to. The walk is by `lstat`, symlinks skipped, bounded
to the depth the DAV parser admits, and takes no store lock: `files/` is outside the pool. Size
is the sum of object lengths, as `status` measures blobs.

The write walk decides on a stat and unlinks by path. A `PUT` that lands on the same name
between the two loses one fresh object — a recompute for a cache — and `PUT` recreates any
parent directory the sweep removed under it. That is the accepted alternative to holding the
store's exclusive lock over a directory walk, which every `/v2/` push would pay for. An unlink
that finds nothing is not an error: the server's pass and an offline `gc` may run at once.

Every pass, policies or none, also removes files under `files/.staging/` older than a day: an
in-flight `PUT` refreshes its staging file's mtime with every chunk, so one that old was
abandoned by a server that died mid-write.

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

`status` reports stored blob bytes split by whether tags reference them, with in-progress
uploads counted separately. The repository table lists tag counts. Bytes without tag
references are not a prediction of what `gc` will reclaim: its retention and grace windows
still apply.

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

After the OCI pass, `gc` runs the `files/` pass under the per-directory policies (see
"Eviction policy" under the WebDAV view) and reports it separately: a different store with a
different model gets its own lines rather than one summary conflating the two. `status` ends
with a table of the `files/` directories, their object counts and sizes, and their policies.

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
- A `files/` directory has no eviction until an operator attaches a policy to it; there is
  no default, by design (see "Eviction policy"). Setting a policy needs access to the host
  holding the store; an admin-gated HTTP route for it is a natural addition in accounts mode
  and does not exist yet.
- The `files/` area trusts its writers: a stored compiler-cache entry is linked into every
  project computing the same key, so write access belongs to trusted pipelines only (see
  "WebDAV view").
- The store directory must be writable only by trusted local users. Requests and eviction
  can follow symlinks in parent directories under `files/`; checks reject only a symlink at
  the final path component. Preventing this requires descriptor-relative path resolution.
- Chunk boundaries are client-defined. Clients using different chunkers share the blob pool
  but may not deduplicate the same artifact effectively.
- Expired sessions are removed when presented, not by a periodic sweep.
- Sessions are read-all with administrator-only write. Per-user session scopes are not
  implemented.
- The server has no durable request audit log. Administration mutations are logged, but OCI
  reads and writes are not persisted as audit records.
- OIDC trusts platform roots only and caches discovery until restart.
