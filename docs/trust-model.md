# Fleet trust model (design)

Status: proposal. Nothing below is implemented. The defaults it names are recommendations
still open to change; each is marked *(default)*. Builds on
[the fleet design](fleet-design.md), [the registry hub design](registry-hub.md) and
[the disk images design](disk-images-design.md).

The long-term goal is a fleet administered from the hub alone. The hub holds every node's and
every registry's configuration, and a host needs almost no administration of its own. Today
the opposite holds: a node's own config is authoritative and the hub only narrows it
(`fleet-design.md`, *Configuration*), and trust anchors such as release keys are pinned on
each host. This design keeps what that buys, a hub compromise that cannot take over the
fleet, and drops the per-host administration. The hub holds and distributes everything, but
an offline **fleet root** signs the few powers the hub may not grant itself.

## Goals

- **The hub holds the configuration.** A host keeps only what lets it reach the hub and check
  what the hub sends.
- **A compromised hub is bounded.** It can disrupt the fleet and misuse its routine powers.
  It cannot install unsigned releases, add trust anchors, loosen sensitive settings, roll
  configuration back, or make an image trusted.
- **Nodes are trusted, jobs are not.** A job runs in a VM with what the hub grants it, and
  its output is never trusted by default.
- **Trust is a property of a digest.** An image is trusted because a chain of signatures says
  so, never because of where it is stored or who could write there.

## Principals

| Principal | Trusted with | Not trusted with |
|---|---|---|
| **Fleet root** (offline) | the fleet's trust anchors | nothing online; it is used rarely and by hand |
| **Hub** | routine configuration, placement, registry tokens, distribution of everything | sensitive settings, releases, builders, recipe grants, image trust |
| **Node** | running jobs in VMs, its own identity key | building trusted images, unless it is a builder |
| **Builder node** | building recipes, signing what it built | running untrusted jobs |
| **Registry** | storing content, enforcing tokens and trusted namespaces | deciding policy |
| **Maintainer** | signing recipes, for the names a grant gives them | anything else |
| **Job** | what its token's namespaces allow | anything else |

## Keys

| Key | Held | Signs |
|---|---|---|
| Fleet root | offline; a threshold of several holders later | certificates (hub, token, builder keys), the delegation, sensitive bundles, release keys, `min_enforcing`, recipe grants, countersignatures, checkpoints with their revocations, root rotation |
| Hub online key | the hub, `<data_dir>` | routine bundles, within its delegation |
| Hub token key | the hub | registry tokens ([step 4](registry-hub.md#step-4-namespaces-and-job-tokens)), certified by the root for that use only |
| Release key | offline (exists today) | `vk` and `vk-registry` releases |
| Builder key | each builder node, generated there | provenance, and entries of the trusted build cache |
| Maintainer key | each maintainer; SSH keys *(default)* | recipes |

Every key is ed25519; maintainer keys are SSH ed25519 keys. A host identity key (node or
registry, as today) only authenticates its session with the hub; it signs nothing anyone else
checks. A registry with a root pinned accepts only token keys the root certifies.

## Enrollment

A host learns the root at enrollment, as the one trust setting it keeps locally:

```sh
vk-hub token create | ssh node-1 vk node join https://hub.example.com --token - \
    --root <fingerprint> [--checkpoint <file>]
```

- The fingerprint comes on the command line, from the operator, never from the hub. A managed
  node OS image ([Managed nodes](fleet-design.md#managed-nodes)) carries it built in, so a
  host installed by PXE needs no administration at all.
- `--checkpoint` gives the host a first checkpoint (see *Freshness*) from outside the hub, so
  it starts with a floor the hub cannot lower. The managed OS image carries a recent one.
  Without it the host takes its first checkpoint from the hub, which could hand it an old,
  still unexpired one: the host is then as fresh as the hub chooses, until the next checkpoint.
- The root rotates by a statement the old root signs, naming the new one. A host that loses
  its root (a lost key, a compromise of the root itself) is enrolled again by hand.
- A host with no root pinned behaves as today: its own config is authoritative.

## Configuration held by the hub

A host's local config shrinks to:
- the hub's URL;
- its identity;
- the root's fingerprint;
- facts only the host knows: paths, disks, devices, its store root.

Everything else arrives from the hub as **bundles**: signed documents the host applies whole.

### Routine and sensitive

- **The routine fields are an explicit list, in the code.** Any field not on it is
  sensitive. Routine means capacity and performance:
  - concurrency, ceilings, and the resources a VM gets by default;
  - checkout and cache sizes and idle times (`checkout_tmpfs`, `checkout_cache_idle_secs`,
    `windows_cache_idle_secs`);
  - disk admission and image eviction;
  - gc schedules and windows within the floors;
  - namespaces;
  - egress rules by project and ref
    ([Job egress from the hub](fleet-design.md#job-egress-from-the-hub)), which only narrow
    the node's caps;
  - which trusted CI tools version a node uses (see *CI tools*).
- **Sensitive fields need the root's signature.** They include everything that changes what
  a job VM can reach, or what a host trusts:
  - credential forwarding (`[executor.auth] ssh_agent`), host shares (`[executor.share]`),
    the host checkout and its overlay (`host_checkout`, `checkout_overlay`), `[egress]`, and
    the registry's guest proxy (`proxy_guests`, `guest_credential`);
  - release keys, unsigned releases, `allow_downgrade`, and the minimum release that enforces
    this model (`min_enforcing`);
  - a registry's `[hub] allow` list and gc floors;
  - which namespaces are trusted, and their admission policy;
  - builder certificates and recipe grants.
- **The delegation** is a statement the root signs: the hub's online key, the routine fields
  it may set, and an expiry (1 year *(default)*). When it lapses the host keeps applying its
  last bundle and refuses new routine bundles until the root renews it.
- **Local settings still win where present.** Each field says how. A numeric field set locally
  is a ceiling; a boolean that opens access (`ssh_agent`, `host_checkout`) set off locally
  cannot be turned on by a bundle; a path is the host's alone. This is how a host is made an
  exception, and how a fleet moves over: an existing host keeps its config, and settings move
  into bundles one by one.

### What a bundle signs

A bundle is addressed to exactly one host. Groups are how the hub authors bundles; it expands
them per host before signing, so a host never merges bundles and no precedence between
groups exists. A bundle signs:

- `fleet`, the root's fingerprint;
- `host`, the host's ID;
- `kind`, `routine` or `sensitive`;
- `epoch`, which the root raises when it rotates or renews the delegation;
- `version`, counted per host, kind and epoch;
- the fields.

A host applies one routine and one sensitive bundle. It refuses a bundle for another fleet or
host, of another kind than its signer may sign, or with an `(epoch, version)` not above the
one it applied. It keeps those counters in `<state_dir>/trust/`, written atomically, apart
from every cache and from what a reset clears. Enrolling again starts them over, which the
checkpoint bounds.

**Replay, not rollback.** The counters refuse an old document replayed. They do not stop the
holder of the online key from signing new routine bundles with old values: a compromised or
badly restored hub can loosen routine fields, within the delegation and the local ceilings.
Sensitive fields need the root, so it cannot loosen those. A hub restored from backup signs
its state again at a higher version only after the reconciliation
[the fleet design](fleet-design.md#proposed-recovery-after-a-hub-restore) proposes.

### Freshness

The root signs a **checkpoint** every 90 days *(default)*:

- the current sensitive bundle version for each host, and the current grant set;
- the revocation list: keys, certificates, recipe archives and outputs;
- an expiry: 90 days after it is signed, with a margin for the next one.

A host refuses a checkpoint older than the one it holds, and a sensitive bundle or grant set
older than its checkpoint names. When its newest checkpoint expires, the host stops admitting
images its policy requires to be trusted; jobs already running carry on, and nothing else
changes. A hub that withholds a checkpoint, or a revocation in it, thus stops trusted work
within 90 days instead of keeping revoked trust forever.

## Releases

A host takes a release the release key signed, as today. Two exceptions are sensitive
settings: unsigned releases for development, and `allow_downgrade`. Neither may take a host
below `min_enforcing`, the oldest release that enforces this model: an older binary would
read none of it, so a downgrade past it would remove every protection at once. The root
raises `min_enforcing` when a release adds a check worth keeping.

## Trusted images

### Recipes

A shared image is built from a **recipe**: an archive holding a Dockerfile, a `recipe.toml`
and the build context, signed by a maintainer.

- **Format.** The archive is an uncompressed POSIX tar, the format of OCI layers. The
  signature covers the archive's bytes as uploaded; the archive is never re-encoded, and its
  digest is the recipe's identity. Compression is the registry's business, not the recipe's.
  - Not zip: its two indexes, the central directory and the local headers, can disagree, so
    two tools can read different files out of one signed archive.
  - Not ar: no directories, and file names limited to 16 bytes without extensions.
- **`recipe.toml`** sits at the archive's root, beside the Dockerfile, and is covered by the
  signature:
  - `name` and `version`;
  - the target tags, the only tags its output may take;
  - the platforms;
  - `network`, whether the build's VMs get network (`false` *(default)*).
- **Inputs are pinned.** The builder checks the build graph once fully expanded, every stage
  and instruction, and every source of content in it is one of:
  - a public OCI image by digest, wherever the Dockerfile names an image: `FROM`,
    `COPY --from`, `RUN --mount=…,from=…`. An index digest pins every platform under it, and
    the provenance records the platform manifest each stage resolved to. The builder pulls
    through the registry's relay and checks every digest. The digest stops substitution, not
    a bad upstream: the maintainer vouches for the upstream by pinning it;
  - another recipe by archive digest, `FROM recipe@sha256:<archive>` (or in `COPY --from` and
    `--mount`). It resolves to the one output whose provenance names that archive, in the
    namespace its grant gives it; if there are several, the build fails, so whoever schedules
    builds can break one, never choose its bytes. The referenced recipe verifies under its
    own grant, not the referencing one's. Cycles are refused, and the depth is bounded
    (8 *(default)*);
  - another recipe by name, `FROM recipe:<name>`, which follows that name's highest trusted
    version. It is explicit in the Dockerfile, and the provenance records the archive and
    output it took;
  - a file by sha256: an ISO (`FROM debiso:…@sha256:…`), `ADD --checksum=sha256:…`,
    fetched from the registry's `files/` or from a URL and checked after download. Files
    stay out of the recipe archive;
  - another stage of the same Dockerfile, or the recipe's own context.
- **Refused** in a recipe: any image or file not pinned as above; named build contexts
  (`--build-context`, compose `additional_contexts`); build secrets; build arguments
  `recipe.toml` does not fix; and any instruction or flag the builder does not know.
- **Unpacking** is strict, so what a reviewer inspects is what the builder builds:
  - only regular files and directories, in ustar headers, with PAX records for `path` and
    `size` only, each at most once per entry;
  - each path is made canonical after applying its PAX record: no leading `./`, no empty or
    `.` components, no trailing `/` but on directories, UTF-8. A path not already canonical
    is refused, not rewritten;
  - refused: duplicate canonical paths, a file and a directory at one path, absolute paths,
    `..` components, links, devices, FIFOs, GNU headers, a size the entry's data does not
    match, and any byte after the end-of-archive marker but its zero padding.

  Owners, groups and timestamps are ignored, and a mode keeps only its executable bit. The
  same parsed listing serves the signature check's review, reading `recipe.toml`, and
  extraction.
- **Storage.** A recipe is an OCI artifact with one layer, the archive
  (`application/vnd.oci.image.layer.v1.tar`), in the registry's `recipes/` namespace. Its
  maintainer signature is an SSH signature (`ssh-keygen -Y sign -n vk-recipe`) attached as a
  referrer.
- **Versions.** `recipes/` is the ledger of versions, and is never collected: gc skips it, and
  a deletion there needs a statement the root signs. The registry refuses a recipe whose name
  and version another archive already has. A builder that still finds two (pushed to two
  registries, say) trusts neither.

### Grants

A **grant** is a statement the root signs, the only per-recipe administration:

- the maintainer keys it covers;
- the recipe names they may publish, as globs;
- the namespace and tags the outputs may take;
- `kind`: `image` or `tools` (see *CI tools*);
- whether a recipe with `network = true` is accepted;
- `promote = "auto"` or `"countersign"`: whether the output is trusted once built, or only
  once a root holder countersigns its digest.

Maintainers publish new versions without the root. A grant may list a key that CI holds (a
protected GitLab variable, say), which makes a pipeline a maintainer: its trust is then
GitLab's branch protection, a weaker anchor the grant states openly.

### Builds

- **Builders are dedicated nodes** *(default)*, each with a builder key the root certifies.
  They never run untrusted jobs: the hub never places one there, and the builder refuses one
  on its own, since being a builder is in its sensitive bundle. A VM escape in a job thus
  cannot reach a builder key.
- **The hub schedules builds** as typed operations to builders, not as GitLab jobs: when a
  recipe version is pushed, when an operator asks, and, for a recipe that follows a base by
  name, when that base gains a new trusted version.
- **The builder runs the build on its host**, with `vk build`, not a script in a guest, so
  what it signs is what it built. It:
  1. fetches the recipe by digest and checks its signature against a grant;
  2. resolves every input, recursively, and checks each digest;
  3. unpacks the archive strictly;
  4. builds. The network policy applies to every VM the build boots: `RUN` steps, helper
     images, an installer and its settle boots;
  5. pushes the output by digest, then attaches the provenance.
- **The build cache.** Builders share a cache of their own, `trusted-cache/`. Write access to
  it proves nothing, since the hub mints registry tokens: each entry carries a statement a
  builder key signed, naming the entry's digest and its cache key, and a builder reuses only
  an entry whose statement verifies. The cache key includes the network policy, and an entry
  made with network is never reused by a build without it.
- **Hermetic** means the network was off for the whole build, and every base recipe and
  every cache entry the build used was hermetic too.
- **Installs from ISOs.** `FROM debiso:` and `FROM winiso:` are recipes like any other.
  Their helper images (the Windows medium's is `FROM debian:trixie` with packages from apt
  today, `vk-driver/src/winiso/Dockerfile`) become recipes themselves, pinned by archive
  digest. The provenance lists every material the install injects: the medium's hooks and
  scripts, drivers, and the firmware, which comes with the `vk` version.

### Attestations

Every signed statement is a DSSE envelope over an in-toto Statement v1
(`payloadType: application/vnd.in-toto+json`), attached as a referrer to its subject.

| Statement | Signed by | `subject` | Predicate |
|---|---|---|---|
| provenance | a builder key | the output: the index and each platform manifest, one statement each | SLSA provenance v1: the recipe's archive digest and grant, every resolved input by digest, the builder's ID and `vk` version, `hermetic`, start and end |
| countersignature | the root | an output digest | `vk.countersign/v1`: the namespace and tags it is promoted to |
| cache entry | a builder key | the entry | `vk.cache/v1`: its cache key, `hermetic` |

A certificate is a statement the root signs, naming a key, its purpose (`builder`, `token`,
`hub`) and an expiry. A key used outside its certified purpose is refused.

The format aims at `cosign verify-attestation --key` with no Fulcio and no Rekor, pinned to a
tested cosign version, so the chain can be checked outside vk. A valid signature alone never
makes a digest trusted: the checks below do.

### What makes a digest trusted

A digest is trusted when all of these hold:

1. a provenance statement has it as `subject`, signed by a key the root certifies for
   `builder`. For a platform manifest under an index, its own statement is the one checked;
2. the recipe that provenance names is signed by a maintainer key, under a grant of the
   right `kind` that covers its name and the output's namespace;
3. that recipe is the only archive with its name and version;
4. if the provenance is not hermetic, the grant accepts that;
5. if the grant says `countersign`, the root countersigned the digest;
6. nothing involved is revoked, checked recursively: the keys, certificates, recipe archives
   and outputs of the digest and of every recipe input it was built from.

A trusted digest stays bootable, an old one included, until it is revoked.

**Moving a tag** needs more: the tag must be among the recipe's target tags and allowed by its
grant, and the new version must be strictly above the one the tag points at. A maintainer
signs the target tags, so the hub cannot move a trusted tag anywhere a recipe did not ask for,
nor back to an older version.

## Enforcement

Two places check trust. Neither relies on the other.

- **The registry, on push.** A trusted namespace, from a sensitive bundle, accepts a tag only
  as *Moving a tag* allows. Pushes by digest and referrers are accepted from builders, so the
  output and its provenance arrive before the tag. No credential bypasses that, the
  registry's own and admins' included; a sensitive bundle may lift it for a namespace.
- **The node, before boot.** Admission policy is per namespace *(default)*: a namespace may
  require trusted images, and `images` does from the start. The node:
  - resolves a tag once and checks the exact digest it will boot, a platform manifest under
    an index included;
  - checks every compose service and every disk image derived from one;
  - checks an image again when it enters the node's local cache, so a cached image is no
    shortcut;
  - stops admitting such images when its checkpoint expires (see *Freshness*).

## CI tools

CI tools definitions (`fleet-design.md`, *CI tools*) are a build context identified by its
sha256, built today by every node on its own (`vk-driver/src/node/tools.rs`). Under this model
they are recipes under a grant of kind `tools`:

- builders build them, and a node installs only a tools output that is trusted;
- the hub chooses which trusted version a node runs, a routine field;
- a node with no root pinned keeps building them itself, as today.

The hub packs definitions with GNU tar headers today (`vk-hub/src/tools.rs`), which recipes
refuse. The packer moves to ustar first, which gives every definition a new digest and needs
it signed anew.

## Jobs

- A job reaches the registry only through its namespaces
  ([step 4](registry-hub.md#step-4-namespaces-and-job-tokens)). Write access to a trusted
  namespace does not let it publish there: the registry refuses a tag *Moving a tag* does not
  allow.
- A job may push a recipe to `recipes/`. Unsigned, it does nothing. A pipeline that holds a
  maintainer key (see *Grants*) publishes as that maintainer.
- A job's output, captures and caches included, is never trusted, whatever namespace holds it.

## A compromised hub

| It can | It cannot |
|---|---|
| stop work, misplace jobs, drain nodes | install a release the release key did not sign, unless a host's sensitive bundle allows unsigned releases; nor take a host below `min_enforcing` |
| change routine settings within its delegation and the local ceilings, old values included | change a sensitive setting, or replay any old bundle |
| mint registry tokens: read and write untrusted content, and break builds | make a digest trusted, poison the trusted cache, or move a trusted tag where its recipe did not ask |
| withhold checkpoints and revocations, for up to 90 days | keep revoked trust past the checkpoint's expiry, or certify a builder, grant a maintainer, or pin another root |

## Migration

Each step is opt-in, and a host without a root pinned keeps today's behaviour.

| Step | Content |
|---|---|
| 1. Root | the root key and its tooling; `--root` and `--checkpoint` at enrollment and on enrolled hosts; root rotation; checkpoints |
| 2. Routine bundles | the routine field list, the hub's delegation and online key, bundle addressing and counters; local settings as ceilings |
| 3. Sensitive bundles | everything off the routine list, root-signed; `min_enforcing` |
| 4. Recipes | the recipe format, strict unpacking, `recipes/` as a ledger, maintainer signatures, grants |
| 5. Builders | builder certificates, builds as typed operations, `trusted-cache/` with signed entries, provenance; helper images as recipes |
| 6. Registry enforcement | trusted namespaces, tag moves, the referrers API, gc keeping referrers |
| 7. Node admission | per-namespace policy, checks before boot and on caching; CI tools from builders |

The registry needs two things it lacks today:
- **The referrers API.** vk-registry treats a manifest's `subject` as a reference, but
  serves no `GET /v2/<name>/referrers/<digest>`.
- **A gc rule for referrers.** gc must keep a referrer, which no tag names, as long as its
  subject is kept.

## Open questions

- **Trusted time.** Expiries are checked against the host's clock. A host whose clock the
  network can move (NTP without authentication) can be made to accept expired statements.
- **Attestation retention.** How long provenance outlives its image. Recipes stay, as the
  ledger of versions.
- **An audit trail outside the hub.** Without Rekor, the record of what was signed is the
  hub's audit log and the attestations in the registry. A log the hub cannot rewrite, a copy
  kept elsewhere, say, is not designed.
- **Threshold root.** Several holders, any k of which sign, instead of one key: the format
  should allow it from the start even if the first deployments use one key.
