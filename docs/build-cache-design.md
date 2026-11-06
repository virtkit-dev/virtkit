# Per-project build caches

Status: **implemented**, steps 1–6; step 7 in part (`build_cache` in
`tests/gitlab/scenarios.sh`). Not to be released before the
[node-wide content store](#node-wide-content-store), steps 8–12.

On a fleet, a job's builds cache their layers in a registry repository of the job's project
and protection, reached with the job's registry token, as `task-cache` scopes task-rs's
cache. An operator may name refs (branch or tag globs) that get a cache of their own. On a
node that announces `job_build_cache`, a job never reads or reuses what a job of another
project, protection or scope built or cached, in the registry or on the node.

A node currently caches every build's layers in `[build] cache_registry` with its own
credential ([registry hub](registry-hub.md#4a-tokens-for-placed-jobs)), and keeps built
content in a local tier keyed by content alone.

## Scopes: `{scope}` and isolated refs

A namespace may list **isolated refs**, ref globs with the `ref <glob>` subject's syntax
(`vk-hub namespaces add … --isolate 'release/*' --isolate main`), and hold `{scope}` in its
path, one repository name component:

- `all` for a job whose ref matches none of the namespace's isolated refs;
- for one whose ref matches, `ref-` + the ref lowercased, each run of characters outside
  `[a-z0-9]` turned into `-`, cut to 32 characters, trimmed of `-` (`x` if nothing is left),
  then `-` and the first 32 hex digits (128 bits) of the SHA-256 of `<kind>:<ref>`, `kind`
  being `branch` or `tag`.

`Release/1.2` fills as `ref-release-1-2-<hash>`. Shared and isolated components never
coincide (`all` has no `ref-`), and the 128-bit digest is collision-resistant, so two refs,
or a branch and a tag of one name, do not share one in practice. The components are siblings, never prefixes
of one another, so a grant on the shared scope does not cover an isolated one.

- The hub refuses `--isolate` on a namespace whose path lacks `{scope}`. Without isolated
  refs every job fills `all`: the cache is per project and protection, like `task-cache`.
- **Ref kind.** In a namespace that isolates refs, a job without a ref fills no `{scope}`
  path, even where no glob would match it, and neither does a job whose ref matches an
  isolated glob but whose kind is unknown: the hub cannot hash its ref's kind. The namespace
  gives such a job nothing; for `ci-build`, it gets no `build_prefix` and builds with the
  cache off. A ref no glob matches fills `all` whatever its kind. `vk-gitlab` sends any
  `ref_type` but `tag` as `Branch`; it also sets `Sources.ref_type_unknown` beside it for
  anything but `branch` and `tag` (a flag, not a new `RefType` value an older hub or node
  would refuse to read), and `JobClaims` gains `ref_type`, `None` for such a job and in an
  older egress record.
- Isolation works both ways: an isolated ref's jobs cannot read the shared scope, and other
  refs cannot read its scope.
- Protection stays in the path. A ref matching an isolated glob in an unprotected pipeline
  fills the same `{scope}` as in a protected one, under the other `{protection}`.
- Changing a namespace's isolated refs moves the affected refs' caches: a newly isolated ref
  takes a scope no other ref's token ever covered, cold unless the ref was isolated before and
  its repositories have not expired; a released one rejoins `all`. Old repositories expire by
  retention.

`{scope}` takes a whole component like the other placeholders; a retention still needs no
fixed component after one, so a deleted branch's repositories expire by last use.

### Path checks

When it stores a namespace, the hub checks its path at its longest filling, not at a sample,
against the grant prefix grammar (`vk_hub_proto::token::valid_prefix`): OCI's lowercase
components, plus what the registry's own `valid_name` adds:

- at most 16 components, with `/build-cache` added for `ci-build`;
- no component named `tags`, `manifests` or `blobs`;
- each placeholder at its longest filling: `{gitlab}` 32 characters (an instance name is
  lowercase letters, digits and `-`, and the hub refuses one that is a reserved name),
  `{project_id}` and `{pipeline_id}` 20 digits, `{protection}` 11 (`unprotected`) and
  `{scope}` 69; the whole at most 255 characters.

`valid_prefix` already applies the component grammar at minting and gains only the component
count and the reserved names, so a bad filling never reaches the registry.

### Reserved roots

Grants add up across namespaces, and a prefix covers everything beneath it: another
namespace granting `task-cache/{gitlab}/{project_id}` would hand a job every protection and
scope of `task-cache`. A namespace with `{scope}` therefore **reserves** its path up to its
first placeholder (`ci-build`, `task-cache`): the hub refuses to store any namespace whose
path, at any filling, is an ancestor of, a descendant of or overlaps a reserved root, and
refuses to give a namespace `{scope}` while another one's path reaches its root. A path
starting with a placeholder, which would overlap every root, is refused for any namespace
already.

Tokens are not revoked: one minted before a change keeps its grants until it expires, at most
`max_job_token_secs` (as it stood at minting) after it was issued, plus the 60 s of clock
skew the registry accepts. A reserved root is checked free when the namespace is stored, but a
path removed just before (a broad namespace replaced by a scoped one) stays reachable through
such tokens. `vk-hub namespaces add` says so whenever it stores a namespace with `{scope}`,
and the isolation holds once those tokens have expired.

## The registry cache: `ci-build`

A namespace named `ci-build` gives a job's builds their cache, as `ci-cache` gives its GitLab
caches:

```text
namespace ci-build  path = "ci-build/{gitlab}/{project_id}/{protection}/{scope}"  retention = 14d
  read write lock  own project
```

- **Default.** A registry first taking tokens gets `ci-build` beside `ci-cache` and
  `ci-pipeline`, with no isolated refs: per project and protection out of the box. A
  registry seeded before gets it once on upgrade (a `build_cache_seeded` flag beside
  `namespaces_seeded`), unless a namespace already has that name or a path reaching the
  `ci-build` root, in which case the hub logs why and leaves it to the operator. To isolate
  refs, replace it with `vk-hub namespaces add <registry> ci-build … --isolate …`.
- **Its path is checked.** The hub refuses a `ci-build` path without `{gitlab}`,
  `{project_id}`, `{protection}` and `{scope}`, or a grant other than `own project`.
- **Hub.** The prefix `ci-build` fills for the job goes in `JobRegistry.build_prefix`, sent
  only to a node announcing `job_build_cache`, as `areas` is gated on `registry_areas`.
- **Node.** A job build — a `dockerfile:` image, `vk-agent build`, a compose `build:` service,
  a Windows build — gets an explicit cache setting, carried through every build entry point
  instead of rebuilding a cache `Registry` from `[build] cache_registry`: *scoped* (the node's
  `[registry]` at `build_prefix`, the job's token kept redacted), *off*, or *shared*
  (`[build] cache_registry`, for local gitlab-runner jobs and builds outside jobs). The
  builder reaches the cache only through it, base-image snapshots included.
  - layers at `<prefix>/build-cache:<key>`, Windows layers at `<prefix>/build-cache:win-<key>`;
  - build-once locks and failure memos under the same names. One function builds a lock name
    `<repository path>:<tag>` for both Linux and Windows; the memo client makes the pipeline
    header optional and leaves it out with a token, so the registry takes the token's claim.
- **Every hub-placed job is scoped or off.** On a node announcing `job_build_cache`, a job
  the hub placed builds *scoped* when its `JobStart` carries a token and `build_prefix`, and
  *off* otherwise, whatever the reason (no registry on the hub, minting failed, no
  `ci-build`); its trace says which once. The node never infers from a missing token that
  the shared cache is allowed. `[build] cache_registry` serves only jobs from a local
  gitlab-runner and builds outside jobs.
- **Outside jobs.** `vk build`, image warm-up and the node's own builds keep `[build]
  cache_registry` and the node's credential.

Blobs are content-addressed registry-wide, so two scopes pushing one layer store it once.
A push skips the upload when the registry links the blob to the destination repository or to
another repository the token can read; a job can therefore mount only what its own grants
already let it read.

### The guest's registry access

A guest can bypass build-cache scoping with the node's credential:
`guest_credential = "node"` and `proxy_guests` make `registry.vk` inject it
(`vm.rs` `guest_proxy`).

- A node announces `job_build_cache` only when its guest proxy never lends the node's
  credential: `guest_credential = "job"`, or no proxy at all. A node lending it keeps the old
  behaviour and gets no `build_prefix`.
- `[jobs] require_job_build_cache = true` in `hub.toml` makes the hub place jobs only on
  nodes announcing `job_build_cache`. It is off by default, so a mixed-version fleet keeps
  running jobs during an upgrade; turned on, no job lands on a node where the isolation does
  not hold. It is hub-wide, as `[jobs] egress_rules` is: placement checks it per node without
  looking up the node's registry.

## Windows

`winiso::base` uses one registry argument both to fetch installation media by digest and to
cache layers. It takes two:

- **Media**: ISOs and drivers, fetched by digest (`files/sha256:<hex>`) from the registry's
  file store with the node's credential, read-only, into the node's shared media directory,
  as today. That store holds whatever anyone uploaded, not only media, and a job's
  `winiso:` stage names the digest: with the node's credential, a hub-placed job could fetch
  any file whose digest it knows. A node setting, `[executor] windows_media`, lists the
  digests the operator approved; for a hub-placed job on a node caching by scope, the node
  takes only those, from its media cache or the registry, and a stage naming another fails
  unless the file is in its build context. Other builds fetch as today. Media are not
  project content: the media cache (`<data>/windows/winiso/{iso,media,verified}`) is shared
  by every scope, its entries keyed by the pinned digests.
- **Layers**: the job's cache setting, as for Linux — scoped at `<prefix>/build-cache:win-<key>`
  or off — and on the node its local scope's Windows cache ([the local tier](#the-local-tier)).

A cold node with the cache off still fetches its media: step 7 tests it.

## The local tier

A node keeps built images and layers locally, keyed by content. A job build stores and looks
them up under its **local scope**: the SHA-256 of a tag and the length-prefixed registry ID
and `build_prefix`, the prefix naming the GitLab instance, project, protection and `{scope}`.
The node takes both from the hub-authorized `JobStart`. The local scope selects an entry's
location and grants nothing. It changes the entry's name, not its content key: stage keys,
their fingerprints and the builder's stamps stay unchanged, and builds of the same content
reuse entries within their scope.

- Linux: a build-tier entry is `<state_dir>/build/<fingerprint of scope and stage key>`,
  beside the unscoped entries, so the idle GC, the use locks and the staging sweep treat
  both alike. The builder keeps no other stage output on the node: what it caches goes to
  the job's cache destination.
- Windows: settled bases, installs and instruction layers (`layers/<key>`), with the backing
  chains they reference, in `<data>/windows/scopes/<local scope>` (its hex digest), laid out
  as the unscoped cache. The sweep after each Windows build walks the unscoped cache and every
  local scope's, and keeps what a kept layer stands on. Media stay in the shared media cache.
- A hub-placed job building *off* builds in a scope of its own, whose entries its cleanup
  removes, never in the unscoped tier.
- Builds outside jobs and local gitlab-runner jobs keep the unscoped tier.

Isolated refs and the branches sharing `all` each build the stages they share once per node;
shared toolchains belong in an image pulled read-only, not in a build cache.

## In-job areas

`{scope}` and isolated refs work for any namespace; an aliased one such as `task-cache` gains
them by adding `{scope}` to its path, which also reserves its root:

```text
namespace task-cache  path = "task-cache/{gitlab}/{project_id}/{protection}/{scope}"  alias = task-cache
  isolate main, release/*
  read write lock  own project
```

The guest still reaches it as `$VK_REGISTRY/dav/files/job/task-cache` or
`vk: http://registry.vk/job/task-cache`; the alias hides the scope, so nothing in the guest
changes. The proxy serves it with the job's token; on a node lending its own credential the
isolation does not hold, as for builds. sccache takes an area the same way.

## Compatibility

- An upgraded hub seeds `ci-build` (above). Where it cannot, job builds on an upgraded node
  run with the cache off until the operator adds it; the release notes say so.
- An older node, or one lending its credential to guests, does not announce
  `job_build_cache`, gets no `build_prefix`, and keeps the shared cache and the unscoped
  local tier: the isolation holds only on nodes announcing it, everywhere once
  `require_job_build_cache` is on.
- An older relay sends a ref of unknown kind as `Branch`, without the flag.
- An older hub rejects a namespace path holding `{scope}` and the `--isolate` option.
- Adding `{scope}` to an existing `task-cache` path moves its caches under `all`: one cold
  run per project.
- The reserved-root check may refuse a namespace an operator stored before; the hub keeps
  stored namespaces as they are and refuses only new or changed ones, naming the conflict.

## Steps

1. **Relay.** `vk-gitlab` sets `ref_type_unknown` for a kind other than `branch` or `tag`,
   so the hub never takes an unknown kind for a branch.
2. **Hub.** `{scope}` and isolated refs (store, CLI, filling, the namespace doc); the path
   checks against the repository grammar at every filling; reserved roots; `ref_type` in
   `JobClaims` with its serde default; the `ci-build` checks, the default
   and its one-time seeding on upgrade; `JobRegistry.build_prefix`; the `job_build_cache`
   capability and `[jobs] require_job_build_cache` placement.
3. **Node, cache setting.** The explicit scoped/off/shared setting through every build entry
   point, the token kept through `make_microvm`, base-image snapshots included; every
   hub-placed job scoped or off; the trace line. The node does not announce `job_build_cache`
   yet, so its placed jobs keep the shared cache until step 6.
4. **Node, locks and memos.** The lock name function; the optional memo pipeline header.
5. **Node, local scope.** The local scope of the build tier's entries; a job's own scope when
   its cache is off.
6. **Node, Windows.** Media and layers split in `winiso::base`, `[executor] windows_media` for
   hub-placed jobs; wincache at the job prefix; scoped local layers, bases and installs with their GC.
   Then the node announces `job_build_cache`, when its guest proxy never lends the node's
   credential.
7. **End to end** (`tests/gitlab/scenarios.sh`): two branches of a project share a cache, in
   the registry and warm on the node; an isolated branch, a tag of its name and another
   project miss and cannot read, mount, lock or memo the others' (nor they its); an
   unprotected job cannot write the protected cache; a job with no token or no prefix builds
   with the cache off in a scope of its own; a Windows build with the cache off fetches its
   media cold; a namespace overlapping a reserved root is refused; `task-cache` with an
   isolated branch. So far `build_cache` covers two pipelines of a branch sharing a build
   (possibly from the node's local tier) with their scope's layers in the registry, and an
   isolated branch building its own, each token reading and locking its own scope's
   build-cache and refused the other's; the rest of this list is still to do.

## Node-wide content store

Status: **design**, reviewed once by codex. It ships with steps 1–7: without it, scoping the local tier multiplies a
node's disk use by its number of scopes.

### What a node stores twice today

- A pulled bundle (`<state>/registry/<name>/<digest>`) keeps its chunks compressed in a
  chunk directory two levels up (`<state>/registry/chunks` for a one-component name, another
  for a longer one) and its whole filesystem again, decompressed, in `runner.ext4`. Two
  bundles sharing chunks download them once but store their bytes once each.
- A build-tier entry (`<state>/build/<fp>`) is a standalone qcow2, flattened. The same stage
  key in two local scopes is two entries, two full copies.
- A restore from a remote build cache caches its chunks beside its output: inside the tier
  entry it builds (`<fp>/chunks`), kept with it, once per entry.
- Windows keeps installs, settled bases and layers per scope root, each root with its own
  chunk cache (`<root>/registry/chunks`). Two scopes building or pulling the same key store it
  twice; an install is tens of GB.
- Only the media cache (by sha256, an identical ISO under another name hardlinked) and a
  local `vk-registry` store (lazy views read its blobs in place) store a hash once.

### Content once, an index per scope

Scoping decides what a job can *find*; it need not decide where bytes live. A node keeps
content once, by digest, and each scope an index of keys to digests:

- **Chunk store.** `<state>/cas/chunks/<hex>`, the stored blob as the registry served it
  (zstd, or raw for a `transparent_zstd` chunk), its name its verified digest, written by
  tmp sibling and rename. Every pull from a remote registry goes through it: `pull_into`,
  `try_pull_ext4` and its lazy form, and `wincache::pull`. The per-entry and per-root chunk
  directories go. A view names the store by path, so the roots need not share a filesystem
  with it; temporary files are siblings of where they are published.
- **Canonical digests only.** Every digest from a manifest is parsed once, as
  `sha256:<64 lowercase hex>`, before any lookup, path, lease or view uses it; anything else
  fails the pull, and vk-registry refuses a pushed manifest naming one (0.106.1, step 8).
- **A canonical digest is not an entitlement.** A chunk found locally is used only for a
  manifest whose blobs the registry checked against the reader's access. Two paths skip
  that check today:
  - a manifest the pull-through relay stored from an upstream (`put_relayed_manifest`)
    records no membership for its blobs, and a digest GET serves it to anyone who can read
    some repository holding it; an upstream a job controls could name another scope's
    chunk by its real digest;
  - a JSON body uploaded as a blob can be read back through `/manifests/<digest>` without
    the manifest checks.

  Before step 9, the registry serves as a manifest only what was admitted as one (relayed
  manifests included, their children checked against the upstream repository's members),
  and the relay's manifests never satisfy a digest lookup in another repository.
- **The local store.** With `[build] cache_registry` unset the builder uses the node's local
  vk-registry store, whose lazy views already read its blobs in place
  (`VK_RO_IMG_LAYOUT_STORE_ROOT`): that store is the content store for those builds, nothing
  is imported, and a persistent view over it holds a reference the store's own gc honours,
  not only a process lease. `none` keeps caching off.
- **Views, not copies.** An entry holds a `.vk_ro_img` view over store chunks, not a
  reassembled image:
  - A pulled bundle is `runner.vk_ro_img`. The job's disk is already a throwaway qcow2 overlay
    over the base (`vm.rs` `create_overlay`), and libkrun opens a view as a backing file, as
    for Windows layers.
  - A build-tier entry the build pushed to its cache destination becomes a view of the
    pushed manifest, pinned by digest, once **every** chunk it names is in the store and
    referenced, including chunks a diff push inherited from its parent and chunks the
    registry already had, which a push does not upload and so never reads today. The
    export's own changes (the normalized superblock, the freshness UUID, the journal) stay
    in a small immutable qcow2 overlay above the view. Until all of that holds, and when the
    push or the conversion fails, the entry stays the qcow2 it is now. An entry that was not
    pushed (the cache off) stays a qcow2; a private scope's goes when the job ends.
  - Windows: pulled layers and bases are views already; built layers are overlays, deltas
    only. Installs: below.
  - Where a full file is unavoidable (the eager fallback when chunks cannot be leased, a
    raw export), it is written as today.
- **Resolve before use.** A scope's entry is written only after its digest was resolved
  through that scope's registry access: a tag read, or a manifest asked for by digest, with
  the job's token for a scoped job. The guest never names store paths; only the node writes
  views. Knowing a digest therefore grants nothing: a pull by digest whose bundle is already
  present asks the registry for the manifest first (one request), and a pulled bundle's
  entry is keyed by the registry and the full repository path, not the bare name. This
  closes the [pulled-images-by-digest](#open-points) gap.
- **Collection.** A chunk is live while a registered reference names it. One protocol,
  under the store's lock, covers every writer and collector, starting from Windows'
  `hold_chunks`:
  - a pull, push, conversion or restore registers the chunks it will use before fetching or
    linking any, and keeps them registered until its view is published or abandoned;
  - a published view's chunk list is a registered reference while the view exists; the
    roots holding views (pulled tier, build tier, every Windows root) are registered with
    the store, and a collection that cannot read one stops without removing anything;
  - a chunk is published before any view names it: a failed rename fails the pull, unlike
    `pull_chunk`'s best-effort publish today;
  - the collector takes the lock, computes the live set, and removes the rest.

  Entries go by idle time as now; chunks then go when nothing names them. `vk gc --dry-run`
  counts each chunk once.

### Windows installs

An install is built from its medium alone (`install_key`: the media key and disk size; the
media key covers the ISO and driver digests, the edition and product key, the answer file
and setup scripts the node generates). It holds no project content when the medium came
from the operator, so:

- An install whose ISO and drivers were both taken from the media cache under
  `[executor] windows_media`, not from a build context, goes in a node-wide tier,
  `<data>/windows/installs/<install_key>`, shared by every scope and the unscoped cache.
  Approving a medium is the operator's statement that whatever it installs may be shared by
  every scope of the node; equal digests alone would not be.
- Shared installs are immutable generations: a failed settle never deletes or replaces an
  install some root's chain stands on (today `make_base` discards the install after a failed
  settle, checking only live references); a retry builds a new generation. The build-once
  lock and the reinstall count move to the shared install key, out of the scope's cache.
- Anything else (media from a job's build context) stays in its scope, as now.
- Settled bases and layers stay per scope, overlays on the install: a scope costs its deltas.
- The product key is part of the key; a scope reaches a shared install only with the same
  key, which it supplied itself.
- The sweep keeps a shared install while any root's chain stands on it.

Two separate installs of one key are not byte-identical (Setup is not reproducible), so
sharing comes from building once into the shared tier under its build lock, not from
deduplicating afterwards.

### Migration

The store starts empty. Old per-entry and per-root chunk directories and reassembled
`runner.ext4` bundles stay usable until the idle GC takes them; nothing is moved.

### Performance

A view is decompressed as the guest reads it; each reader caches 128 decoded chunks and holds
its cache lock while it decodes a miss. Before pulled bundles and build-tier entries become
views, cold and warm Linux boots and concurrent jobs are measured against reassembled images.
If views cost too much, the fallback keeps full images but shares them by their own digest,
with the same per-scope index and resolve-before-use rule: less saving (no chunk sharing
between images), no change to boot or export.

### Steps

8. **Digests.** Canonical digests in the driver and vk-registry: done, 0.106.1.
9. **Store.** `<state>/cas/chunks` used by every remote pull; per-entry chunk directories
   gone; the reference protocol and collection over every root; durable references into a
   local vk-registry store; the boot benchmarks; manifests served only as admitted (above).
10. **Pulled bundles as views**, keyed by registry and repository, resolved before use.
11. **Build tier as views** once pushed.
12. **Windows**: one chunk store, the shared install tier in generations.

## Open points

- **Merge-request pipelines.** What `git_info.ref` holds there (the source branch, or
  `refs/merge-requests/<iid>/head`) decides whether an MR pipeline of an isolated branch
  shares its cache. To check against GitLab in step 7.
- **Pulled images through the relay.** A job's `docker:` image pulls still relay through
  `[build] cache_registry` with `[build]`'s credentials (`dockerimg.rs` `relay_target`). The
  relay caches upstream images by their reference, with the registry's own upstream
  credentials where it has any, so a job can pull through it what those reach. That is not a
  project's builds and is left out of the scope here; it needs its own change.
- **Pulled images by digest.** A pulled bundle is cached at `<state>/registry/<name>/<digest>`,
  `<name>` relative to the registry prefix it came from, and one found there by digest is
  used without asking the registry. A `pipeline/build/runner` pulled from one pipeline's
  namespace therefore satisfies another project's `virtkit/runner@sha256:<that digest>` on
  the same node. This predates build caches; [the content store](#content-once-an-index-per-scope)
  fixes it.
- **Chunk presence across scopes.** With one store, a scope's pull of a chunk another scope
  stored is served locally. To name such a chunk a job must get a manifest naming it into its
  own scope: a scoped manifest push referencing a blob not in its repository is accepted
  only when the pusher can read that blob elsewhere, and refused (`MANIFEST_BLOB_UNKNOWN`)
  otherwise; non-canonical descriptors are refused (0.106.1). What remains is the relay and
  blob paths above, and timing: a local hit is faster than a fetch.
