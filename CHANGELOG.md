# Changelog

All notable changes to virtkit will be documented in this file.

## [Unreleased]

## [0.21.0] - 2026-07-21

### Added

- `[registry]` and `[build]` gained `token_file`/`cache_token_file`: a static bearer token
  to authenticate to a registry gated by `Auth::Bearer` (takes precedence over Basic when
  set). The driver's registry client (oci_client, raw-HTTP push/probe, and the `/lock/`
  client) previously spoke only Basic, so it could not authenticate to a bearer-gated
  vk-registry at all.
- libkrun's built-in virtio-fs now supports UID/GID mapping (`krun_add_virtiofs4` with
  `uid_map`/`gid_map`, virtiofsd `--uid-map`/`--gid-map`-compatible spec strings;
  `krun_add_virtiofs3` delegates with none). The soft-idmap engine that the bundled
  `vk virtiofsd` used moved into the shared fs device crate so both backends use it.

### Fixed

- The build-once `/lock/` client authenticates with the cache registry's credentials now,
  not just a bearer token — and the driver builds it with those credentials instead of
  tokenless. Against an auth-gated registry the lock API previously `401`'d, so runners
  never serialized fleet-wide and each rebuilt the same image independently. `LockClient`
  takes a `ClientAuth` (None / Basic / Bearer).
- `[gitlab] host_checkout` jobs whose image runs as a non-root user no longer fail with
  `Permission denied` under `/builds`. The checked-out sources are shared into the guest
  with a virtio-fs map that squashes every guest id onto the host user vk runs as (the
  `0700` checkout's owner), so the job reads and writes the tree as its owner whatever the
  image's user — without the host having to resolve that user's id before boot.
- Authenticated `vk-registry` now challenges the `GET /v2/` version probe (401 +
  `WWW-Authenticate`) instead of answering it 200. An OCI client (oci_client's
  `store_auth_if_needed`) probes `/v2/` to discover whether it must authenticate; a 200
  made it assume anonymous access and then 401 on the actual blob requests — so build-cache
  pushes to an auth-gated registry silently failed ("not cached"). vk-driver's
  transparent-zstd capability probe now authenticates its own `/v2/` request to match.
- `vk build`'s live dashboard no longer garbles (a stranded progress line, a duplicated
  header/rule, a large blank gap) when a `RUN` step prints a carriage-return progress bar
  (a `foo\rbar…` line with no newline): the current frame now updates one pinned line in
  place. Most visible on a terminal that is not tall or wide enough.

## [0.20.0] - 2026-07-21

### Added

- `[docker.mirror]`: a Docker Hub pull-through mirror, the equivalent of Docker's
  `registry-mirrors`. Bare docker-hub names and explicit `docker.io/…` refs in a job's
  `image:` are fetched through the configured mirror (with the `library/` prefix added for
  official images) and, unlike Docker, with NO direct-to-Hub fallback — so an `image:` job
  needs no direct Docker Hub egress. Only Docker Hub is routed; other registries are
  untouched. The mirror carries its own optional auth
  (`ca_file`/`username`/`password_file`/`insecure`), independent of `[docker]`.
- `vk run -t`/`--tty`: allocate a pty for the trailing command and wire it to the local
  terminal, so it runs interactively (`docker run -t`).
- Concurrent-pull diagnostics: when a prepare waits on the local pull/build lock, the
  "waiting for a concurrent pull" message now names the holding job (its `CI_JOB_URL`, else
  job id/pid), served by the holder over the lock's own abstract socket — so a stuck build is
  traceable to the job that owns it.
- The cross-runner `vk-registry` build-once lock records the same job identity as its holder,
  and a runner waiting on a contended stage now shows "waiting for a concurrent build (held by
  …)" — so a build blocked behind a peer names the job that holds it.

### Changed

- `[docker].repo` is now optional: `[docker]` may be empty or carry only a `[docker.mirror]`.
  The `docker/<name>` MICROVM_IMAGE form and bare `image:` names route through `repo` when
  set; with no repo, `docker/<name>` is pulled directly, while a bare `image:` Hub ref goes
  through `[docker.mirror]` if configured (else direct).

### Fixed

- `vk run <image> <command>` now runs the command under the image's `ENTRYPOINT` and in its
  `WORKDIR`, as `docker run` does — previously the entrypoint was dropped and the command ran
  from `/`.

## [0.19.0] - 2026-07-20

### Added

- `[build]` gained `cache_ca_file`, `cache_username` and `cache_password_file`: the shared
  instruction-cache registry (`cache_registry`) can now be a remote vk-registry gated by TLS
  (a private/self-signed CA) and HTTP Basic auth. This is also what the build-once `/lock/`
  uses, so a central authenticated vk-registry gives cross-runner build-cache sharing and a
  fleet-wide build lock. Previously the cache client was anonymous over the system roots.

### Changed

- A `dockerfile:` image's build context now defaults to the Dockerfile's own directory (like
  `docker build <dir>`) instead of the repo root, so a Dockerfile outside the repo root finds
  its `COPY` sources and `.dockerignore`. Add `?context=<dir>` to the image ref to override it
  (e.g. `?context=.` for the previous repo-root context).
- The GitLab executor's `dockerfile:` image ref takes an `?arg=<NAME>=<VALUE>` parameter
  (repeatable) supplying a `--build-arg` — e.g. `dockerfile:<path>?context=.&arg=UID=1000#<stage>`.
  It replaces the `MICROVM_BUILD_ARG_<NAME>` job variables, which are no longer read.

## [0.18.0] - 2026-07-20

### Added

- `[gitlab] checkout_dir` overrides where the `host_checkout` mode clones a job's sources on
  the host (default `<state_dir>/checkouts`), so a runner can keep the checkout and the job's
  writes on a RAM-backed tmpfs instead of the state disk.

## [0.17.0] - 2026-07-20

### Added

- `vk cache gc [--idle-secs N]` reclaims the host image cache on demand: evicts materialized
  bases (`<state_dir>/{registry,docker}`) idle past the threshold (`0` = every base no VM is
  using) and drops registry chunks no cached bundle still references. Reclaim otherwise runs
  after each pull, so this is for a cron or manual sweep on an idle runner.
- `vk build --tag <name>:<tag>` builds the target and publishes it as a bootable bundle
  to the `[registry]` repo, pulled by the executor with `MICROVM_IMAGE: virtkit/<name>:<tag>`.
  The rootfs is byte-clean — the image's Env/User ride the bundle config and are applied at
  boot (the embedded agent rides a preinit initramfs, the model `vk run -f` uses) — so its
  chunks dedup against `--cache-registry`: co-located, publishing writes only the manifest.
  The native-bundle prefix is `virtkit/` (was `registry/`), distinct from the `docker/` OCI path.
- The GitLab executor can boot the job's image built from the project's own git sources:
  `MICROVM_IMAGE: dockerfile:<path>[#<stage>]` builds that Dockerfile stage and boots it,
  taking `--build-arg`s from `MICROVM_BUILD_ARG_<NAME>` job variables. Built images are cached
  and shared across jobs and runners. It requires the new `[gitlab] host_checkout` mode (off by
  default), which checks the sources out on the host and shares them into the job over a
  filesystem mount, keeping the git credential out of the guest.
- The GitLab executor can also boot a whole fleet from a compose file in the git sources:
  `MICROVM_IMAGE: compose:<file>#<primary>` builds/pulls every service the file describes,
  boots `<primary>` as the job VM and the rest as siblings on the job network, resolvable by
  alias — so a job's image, its services, and their wiring live in one file. `MICROVM_PROFILE`
  selects optional services. Same `host_checkout` requirement as `dockerfile:`.
- CI `services:` accept the `virtkit/<name>[:tag]` prefix: a service sourced from a
  `[registry]` bundle is pulled (CDC+zstd dedup) and booted on the same clean-image unit
  path as an OCI service (agent initramfs + embedded kernel applying the bundle config).
  Generic-disk bundles only; a `virtkit/` service without a `[registry]` config is a clear error.
- New `vk-registry` binary: a standalone OCI-distribution server backed by the same
  content-addressed store `vk` uses, meant to run centrally and be shared by every
  runner. `vk-registry serve` (plus `gc`/`status`/`install-service`) replaces the old
  `vk registry serve`.
- `vk-registry` is a **pull-through mirror**: configure `[[upstream]]` entries (routed
  by repo-name prefix) and it relays images from upstream registries, caching only
  digest-addressed content (`@sha256:…` manifests and all blobs); tags are relayed live.
  Upstream credentials stay in `vk-registry`, so its clients never see them.
- `vk-registry` serves a **build-once lock** at `/lock/{acquire,renew,release,status}`
  (all POST; names as `?name=` params): a leased, heartbeat-renewed, release-if-owner lock
  so many runners building the same content-key build it once and the rest wait then pull.
  Acquiring several names at once is **atomic all-or-nothing** (with blocker reporting),
  for a step that builds several images together — the `ci-lock-mgr.sh` model, without Redis.
- `vk-registry` supports **TLS** (`tls_cert`/`tls_key`) and **client auth** (a bearer
  token file, or HTTP Basic), so it can be exposed on a shared network.
- `vk` image builds now take that **build-once lock** per stage when the instruction
  cache is a remote `vk-registry`: peers building the same stage wait and pull the result
  instead of rebuilding it. A no-op for the default local (on-disk) cache.
- Credential-injecting registry proxy: the guest reaches a registry credential-free at
  `registry.vk` and `vk` adds the credential on the way to the upstream, so the job never
  holds the secret. Opt in per VM with `vk run --registry-proxy <url>` (needs `--net`), or
  runner-wide for executor jobs with `[registry] proxy_guests = true` (uses the runner's
  `[registry]` credentials). Bodies stream, so large layers pass through without buffering.

### Removed

- `vk registry serve` and `vk registry install-service` — serving a store over HTTP now
  lives in the `vk-registry` binary. `vk` still uses its local filesystem store
  in-process by default (no daemon), and keeps `registry push`/`pull`/`inspect`/`status`/`gc`.

### Changed

- `vk run --compose` now reuses the same host image cache as CI: `image:` services are
  downloaded once and `build:` services are built once, then shared across runs (and runners)
  instead of copied per run. The cache lives in your user data dir, so a rootless dev needs no
  system-wide state directory. `vk cache gc` reclaims it alongside the other cached images.
- The deduped registry chunk store (`<state_dir>/registry/chunks/`) is now bounded: a pull
  records the chunk digests it used in the bundle's `chunks.list`, and the GC drops any chunk
  no remaining cached bundle references. Its lifetime tracks the (idle-evicted) bundles, so
  the compressed tier no longer grows without limit.
- Materialized image bases (`<state_dir>/{registry,docker}/…/runner.ext4`) are now kept by
  **reference count + idle timeout** rather than `keep = N` versions: a base is pinned by a
  shared advisory lock while any VM overlays it (the kernel drops it if the job crashes), and
  evicted once idle longer than `image_cache_idle_secs` (default 1800 / 30 min). This bounds
  disk to the active working set — the compressed chunk store is the durable tier, the full
  ext4 is transient and re-materialized on demand. The `[registry]`/`[docker]` `keep` field
  is **removed**; a config that sets it must drop it.
- CI `services:` now resolve their `image:` through the same digest-keyed cache the job's
  own image uses and boot a CoW overlay over the shared read-only rootfs, instead of a
  second per-service image store (with its own copy, UUID stamp and lock). A job image and
  a service naming the same ref share one cache entry. A service image ref resolves exactly
  like a job image (direct pull by default, `[docker]` proxy routing when configured).
  `[services] store_dir` is retained for config compatibility but no longer consulted.
- The GitLab executor now honours the job's standard `image:` (CI_JOB_IMAGE) — no
  `MICROVM_IMAGE` needed (`services:` was already supported). `image:` is booted directly.
  `MICROVM_IMAGE` stays as the explicit override for the `local/`/`virtkit/` sources; a job
  with no image boots `local/default`.
- Image references are now pulled **directly** from whatever registry they name, by default
  and with no allowlist — the microVM boundary is the security model, so the image source is
  not gated. The `[docker]` section becomes an OPTIONAL registry proxy: it *routes* bare
  docker-hub-style names through a shared pull-through cache (with its credentials) while a
  ref that names its own registry is still pulled directly; it never refuses an image. This
  applies uniformly to a job's `image:`, `MICROVM_IMAGE: docker/<ref>`, and `services:`.
- The GitLab executor's `MICROVM_IMAGE: docker/<name>` now boots the image **directly**:
  the native OCI client pulls it, the embedded vk-agent is injected as PID 1 and the
  embedded kernel boots it — the same path `vk run --source oci` uses. Registry auth is a
  slim `[docker]` section (repo/ca_file/username/password_file/insecure), replacing
  `[convert]`. Job `.gitlab-ci.yml` files are unchanged (`docker/<ref>` is repurposed).
- A kernel-less bundle (generic-disk `local`/`virtkit`/`docker` image) now boots vk's
  **embedded** kernel instead of a configured `generic_kernel` file, so the host needs no
  separate `vmlinux`. `generic_kernel` is dropped from `[local]`/`[registry]`, and a bundle
  that ships its own kernel still boots it.
- The `docker/` OCI-direct path now flattens a **byte-clean** rootfs and carries the image's
  Config (Env/User/WorkingDir/Entrypoint/Cmd) in a `runner.ext4.json` sidecar the boot
  applies — the same model bundles and OCI `services:` use — instead of baking
  `/etc/virtkit/{env,user}` into the ext4 (which also dropped WorkingDir/Entrypoint/Cmd). The
  cache key is the image digest alone (no agent fingerprint), since the agent rides the boot
  initramfs rather than the rootfs.
- The pinned guest kernel is bumped to 6.18.39.

## [0.16.0] - 2026-07-15

### Added

- `vk registry status [--root DIR]` reports a store's usage and content: on-disk size
  (zstd + identity blobs), a per-repository breakdown (tags, latest tag, logical size),
  the combined dedup+zstd packing factor (logical content ÷ bytes on disk), and the bytes
  held in blobs no tag references. Read-only.

### Fixed

- A static-addressed guest (the default build/RUN net) no longer hands off to the job
  before its vsock bridge is forwarding: the agent waits for the gateway to answer ARP
  after setting the address. Previously the job's first DNS query could hit a not-yet-live
  bridge and fail name resolution outright (getaddrinfo exhausting its retries).

## [0.15.0] - 2026-07-15

### Added

- `vk build --disk <path>` attaches a caller-owned raw disk read-write to the target
  stage's RUN guests as `/dev/vdb` (sources shift to `vdc`+); its writes are the artifact,
  so a RUN can partition it, mkfs and install a bootloader. Pairs with `FROM --kernel=image`
  (a kernel that can drive block devices). `--out` is optional when `--disk` is given — the
  disk is then the sole output, no rootfs ext4 is exported.
- `vk build`: `FROM --kernel=image <base>` runs that stage's RUN steps on the base image's
  own kernel (the preinit boot `vk run --kernel image` uses) instead of vk's minimal
  embedded build kernel — so a RUN can partition disks, `mkfs.btrfs`, use device-mapper,
  etc. The base must already carry a kernel (install it in a prior stage and `FROM` it);
  toggling the flag busts the stage's cache.
- `vk run --disk HOST[:ro]` (repeatable) attaches a raw host disk image to the guest as
  a block device, ordered after any rootfs disk. The guest reads/writes it directly — no
  virtiofs — so it can partition, mkfs and install into a disk image, e.g. assemble a
  bootable VM image. `:ro` marks the disk read-only.

## [0.14.0] - 2026-07-14

### Added

- `vk exec <addr> [--user U] [--dir D] [-t] -- <cmd>` runs a command in a live guest
  over its agent exec channel — an interactive shell or a one-shot command, with stdio (or a
  pty under `-t`) streamed and the command's exit status reproduced as `vk`'s own. It reuses
  the same client the in-guest agent embeds, so a host reaches a running VM with `vk` alone,
  no separate `vk-agent` binary.

### Changed

- `vk build --compose` now builds the services `vk run --compose` would boot — the
  profile-enabled set (profiled-down services excluded) plus every `image:` service — instead
  of every declared service. So a cache-warming prebuild matches what the boot needs, and a
  profiled-down service is left for its first on-demand `vk service up`. New `--primary <name>`
  / `--profile <name>` scope the build to the same set the matching `vk run --compose` boots.
- `vk connect` and `vk status` now take the address as a positional argument instead of the
  `--to <addr>` flag (`vk connect <addr>`, `vk status <addr>`), matching `vk exec`. The
  `run --ssh` ProxyCommand hint is emitted in the new form.

## [0.13.0] - 2026-07-13

### Added

- `vk status --to <addr>` probes a running guest's agent: it round-trips the status
  request over the exec channel and prints the reply, or exits non-zero if the agent does
  not answer. A liveness check that exercises the agent protocol — stronger than a socket
  stat — so external tooling can ask "is this VM up?" with `vk` alone, no separate agent
  binary.
- `vk build` mirrors build progress into the terminal title so the tab tracks the running
  counts and current step at a glance, restoring the terminal's original title when it
  exits. Set `VIRTKIT_NO_TITLE` (to any value) to suppress it.
- `vk service up|down|status <name>` controls the run's compose services from inside the
  guest, over the vsock control plane. `up` builds a service's image on first use — build
  progress streams live to the terminal — then boots it, so a profiled-down service can be
  brought up on demand instead of built up front with the rest.

### Changed

- `vk run --compose --primary` now builds the primary VM's image in the same pass as its
  sibling services. Stages they share (a common base Dockerfile) build or restore once
  for the whole set instead of once for the primary and again for the siblings, so a warm
  boot no longer pays the shared work twice.
- `vk run --compose` now builds only the services it starts — the profile-enabled set (or a
  `--primary`'s dependency closure) plus the primary — instead of every declared service. A
  profiled-down `build:` service is still provisioned (addressable, reservable) but its image
  builds on demand at its first `vk service up`; `image:` services are still pulled up front,
  as they cannot be built on demand. Declare `depends_on` for any service a `--primary` needs
  booted at start-up, so it lands in the eager set.

### Fixed

- `vk run --kernel image` now boots modular distro kernels that ship **compressed**
  modules: fullvm decompresses `.ko.xz` / `.ko.zst` / `.ko.gz` when assembling the preinit
  initramfs, instead of skipping them and coming up with no virtio-blk / vsock. Previously
  only uncompressed `.ko` (older Debian) worked; a stock Debian 13 kernel loaded 0 modules
  and never reached the agent.

## [0.12.0] - 2026-07-13

### Added

- `vk run` can boot a container image on its own kernel and hand PID 1 to the image's
  own init/systemd instead of virtkit's pinned kernel and agent: `--kernel image` boots
  the image's `/boot/vmlinuz` (with its modules), `--kernel <path>` boots a supplied
  kernel, and `--init image` runs the image's `/sbin/init`. The `image` axes read the
  image's disk, so they need a disk-backed boot and are incompatible with `--ram`.
- A compose service can choose these per service with an `x-virtkit: { init:, kernel: }`
  marker, honored the same whether the service runs as the `--primary` VM or as a
  background sibling.

## [0.11.0] - 2026-07-12

### Added

- `vk build` now builds several targets in one pass: repeat `--target`, or pass
  `--compose <file>` to build every service a compose file declares. Targets that share a
  Dockerfile build their common stages once and run the rest concurrently over a single
  job pool (bounded by host RAM). With `--out` each image exports to `<out>/<name>.ext4`;
  with none, the build only warms the instruction cache — handy for pre-warming before a
  `vk run`.
- `vk run --compose` now builds its services concurrently instead of one after another,
  in a single build over one job pool. Services sharing a Dockerfile build their common
  stages once; the live dashboard shows every service's stages together.
- Each `vk run` VM now shows a readable process name in `ps`/`top` — `vk:<stage>` for
  a Dockerfile boot, `vk:<image>` for an image, and `vk:<service>` for each compose
  service — instead of the generic `libkrun VM`. `--vm-name` overrides it with a template
  where `{name}` expands to the stage, image, or service name.
- `vk build` and `vk run` now print a timing breakdown when they finish, showing where
  the time went — planning, base pulls, cache pull/push, running instructions, image
  export, and (for `run`) source pull, boot-media assembly, boot, and command exec.
  Build phases are broken down per stage, and the header reports both wall-clock and
  summed busy time so a parallel build reads differently from one bottlenecked on a
  single stage.
- Guests can now bring up WireGuard tunnels in-guest — the pinned kernel every guest
  boots ships with `CONFIG_WIREGUARD` enabled.

### Fixed

- `vk build` no longer appears frozen after a stage's last step. A stage's final cache
  snapshot now uploads to the registry in the background like every other layer, so the
  build moves straight on to the next stage instead of stalling on that upload, and a
  spinner covers the brief guest shutdown that remains.
- `vk build` on the libkrun backend no longer re-chunks the whole stage image at every
  instruction, which made a long stage's cache checkpoints slow down quadratically. Each
  checkpoint again pushes only the instruction's delta, as the cloud-hypervisor backend
  already did.
- `vk build` on the libkrun backend no longer risks a corrupt stage image. The guest's
  disk cache is now flushed to the host image before the image is read back, so a stage
  is no longer left with unflushed writes that failed a later export or cache reuse with
  "failed to fill whole buffer".

## [0.10.0] - 2026-07-10

### Added

- `vk run --compose` now interpolates `$VAR`, `${VAR}` and `${VAR:-default}` in the
  compose file, docker-compose style, from the process environment layered over a
  sibling `.env` (process env wins; `$$` is a literal `$`). Interpolation runs on the
  parsed YAML values (never keys), so it covers every field uniformly. An unset
  variable with no default is a hard error rather than a silent empty value, so a
  mistyped path or image tag fails the boot loudly. This keeps machine-specific values
  (a repo path, a uid) out of the committed compose file.
- A `volumes:` entry is split on newlines into multiple bind specs, so a single
  `${VAR}` entry can inject a variable-length list of mounts — including conditional
  ones — from one host-built variable; an empty value (e.g. `${VAR:-}` unset)
  contributes no mounts.
- `vk run -v HOST:GUEST` now supports **single-file bind mounts**: when `HOST` is a
  regular file, that file is bound live read-write at `GUEST` instead of requiring a
  wrapper directory. The share exposes only that one file — a guest cannot reach its
  host siblings — and works on both the libkrun and cloud-hypervisor backends.

### Changed

- `vk run`'s flag selecting a compose service as the primary VM is renamed from
  `--service` to `--primary`, naming the role it fills: the foreground VM whose
  lifecycle the run follows, as opposed to the background sibling services.

- `vk build` now discards a stage's freed blocks (`fstrim`) just before each cache
  checkpoint, so a file created *and* deleted within one instruction interval is
  released back to holes and never enters the cached delta or the exported image —
  only live data is chunked and pushed. Built into the agent (FITRIM), so it works
  on any guest image.

### Fixed

- `vk build` / `vk run -f` no longer expands `$VAR`/`${VAR}` inside a `RUN`'s command
  itself. As Docker does, the command is left to the guest shell, with the in-scope
  `ARG` and `ENV` supplied through its environment — so a shell variable such as a
  `${opt}` loop index is no longer silently blanked. A `RUN`'s `--mount` fields still
  interpolate. This unblocks Dockerfiles whose `RUN` steps use shell variables.
- `vk build` no longer caches a corrupt ext4 for stages with large writes. The
  O(delta) checkpoint trusted libkrun's block dirty-tracking to list the changed
  clusters, but that side-channel drops writes (gigabytes, in `COPY`-heavy stages),
  so a checkpoint reused stale parent chunks for the dropped clusters and cached an
  image that failed with EUCLEAN on a later boot. The delta now comes from the qcow2
  overlay's allocation map (authoritative — a cluster can't be written without being
  allocated), which captures dropped writes and in-place rewrites alike; chunk dedup
  still avoids re-uploading unchanged data. A `--debug` check verifies the pulled-back
  reassembly (not just the frozen source, which is always consistent and so could
  never expose an incomplete delta). The unreliable block dirty-tracking this replaced
  — a large patch to vendored libkrun — has been removed; the guest freeze already
  flushes the overlay to its backing file, which is all the allocation-map read needs.

## [0.9.0] - 2026-07-09

### Added

- `vk run --host-exec` now makes the in-guest `vk-agent` client available at
  `/run/vk/bin/vk-agent`, so guest tooling can invoke the host-exec channel
  without relying on the image to ship the binary.
- `vk build` now supports `RUN --mount=type=bind,from=scratch,rw,target=…`, giving a
  step an empty, writable, disk-backed scratch directory at the target — handy for a
  step that writes more transient data than the RAM-backed `/tmp` holds. The scratch
  is discarded after the step and never enters the image, matching BuildKit, so the
  same Dockerfile builds under both. One such mount per step. As a virtkit extension
  (BuildKit rejects these on bind mounts), `uid=`/`gid=`/`mode=` set the scratch root's
  owner and mode so a non-root `RUN` can write to it.
- `vk build --build-tmp-tmpfs` uses a RAM tmpfs for each stage guest's `/tmp`
  instead of the default disk-backed scratch. `/tmp` is disk-backed by default so a
  step that writes a lot of transient data there (e.g. unpacking a big toolchain) is
  bounded by disk rather than half the guest's RAM; this flag reverts to the smaller,
  RAM-bound tmpfs. Also settable as `tmp_tmpfs` in the `[build]` config table.
- `vk build --build-cache <mode>` selects how aggressively the instruction cache
  is populated: `layers` caches only each stage's final snapshot, `instructions`
  caches every RUN/COPY, and `auto` (the default) caches stage boundaries plus
  intermediate snapshots only past a work threshold. `layers`/`auto` speed up
  builds of long stages by committing far fewer snapshots. Also settable as
  `build_cache` in the `[build]` config table.

### Changed

- `vk push` now compresses image chunks at a faster zstd level, speeding up
  pushes at the cost of slightly larger uploads and registry storage.
- `vk build` now sizes each parallel build guest to the host CPU count (capped
  at 16) and 4G of RAM by default, giving heavy stages more compile/link
  parallelism; override per guest with `VIRTKIT_BUILD_CPUS` / `VIRTKIT_BUILD_MEM`.

### Fixed

- `vk run` now boots the primary as its built image's `USER` (or a `--primary`
  service's compose `user:`); both primary paths were dropping it, so the guest
  agent gets a default run user again — without it the host-exec socket was left
  root-owned and unreachable by a non-root login.
- When a host directory is shared into the guest, parent directories created for
  the mount point are now owned by the same user as the shared directory (not
  root), so git and similar tools no longer reject the path.
- `vk build` no longer leaves stale separator lines in the TTY dashboard when
  build commands print long, wrapped output.

## [0.8.0] - 2026-07-07

### Added

- `vk run --detach` runs the build and boot in the foreground — so Ctrl-C aborts
  them cleanly instead of orphaning a half-started VM — then detaches once the
  guest is ready, freeing the terminal while the microVM keeps running.
  `--detach-log PATH` captures the backgrounded VM's output (default: discard).

### Changed

- `vk build` now always builds in a microVM (the embedded libkrun by default):
  the `--microvm` flag is gone, and `--cloud-hypervisor` is required only when
  `VIRTKIT_VMM=cloud-hypervisor` selects that backend.
- `vk build` on the microVM backend now builds independent stages in parallel
  over the Dockerfile's dependency graph, so multi-stage builds finish faster.
  Concurrency defaults to a job count bounded by available host RAM;
  `--build-jobs N` (or `VIRTKIT_BUILD_JOBS`) overrides it, and `--build-jobs 1`
  forces a sequential build.
- `vk build` now shows a live progress overview in a terminal — a pinned
  dashboard with a line per build step and each command's output attributed to
  its stage — falling back to plain log lines off a terminal or with
  `VIRTKIT_PROGRESS=plain`.
- `vk build` writes its temporary build scratch next to the output file instead
  of a RAM-backed temp dir, so large builds no longer risk running out of
  memory-backed space; scratch left behind by a crashed or killed build is
  cleaned up automatically on the next build.
- `vk run -f` writes its temporary launch scratch under the cache directory
  (`~/.cache/virtkit`) instead of a RAM-backed temp dir, so large builds no
  longer risk running out of memory-backed space; `--state-dir` still picks a
  caller-chosen location.

### Fixed

- `vk build` steps that write large amounts of transient data to `/tmp` (for
  example unpacking a big toolchain) no longer fail with "no space left on
  device" when the guest has ample disk free.
- `vk build` now rejects a multi-stage `COPY --from` (or `RUN --mount=…,from`)
  that reads from a `/tmp` path up front, with a message pointing at a
  persistent source path, instead of failing deep in the build with a cryptic
  "No such file".
- `vk build` now busts the layer cache when a file bind-mounted into a step
  (`RUN --mount=type=bind`) from the build context changes; previously editing
  such a file left the cached layer in place and the step was not rerun.

## [0.7.0] - 2026-07-04

### Added

- `vsock-auto://<vsock.sock>:<port>` addresses: one host→guest connect address
  that works on both VMM backends — the client picks the best path at connect
  time. `run --ssh` prints its ProxyCommand in this form, so attaching to a VM
  no longer depends on which backend booted it.
- `vk run --state-dir DIR` pins the run's sockets and console log to a stable
  directory (created/reused, never removed, forced to mode 0700 — it exposes the
  VM's control sockets) instead of a fresh temp dir, so external tooling can
  attach to the running VM: `vk-agent -s vsock-auto://DIR/vsock.sock:4444 exec`.
- `vk run -v/--volume HOST:GUEST[:ro]` bind-mounts extra host dirs into the
  primary (beyond `--workdir`), with the same semantics as a `--service`
  primary's compose volumes — persistent state (a dev VM's `~/.vscode-server`,
  credentials dirs) lives on the host while the VM stays throwaway.
- `vk run --symlink SRC:DST` creates in-guest symlinks after the mounts — the
  single-file share escape hatch (virtiofs shares directories only); a dangling
  `SRC` is skipped.
- `vk run --env KEY=VALUE` / `--env-file FILE` add environment to the guest:
  applied to the run command and to everything spawned in the VM. The effective
  env is also materialized to `/etc/virtkit/env` in the guest on every boot, so
  an image's profile.d snippet can restore it in login shells.
- `vk run --host-exec` serves host commands to the guest at `/run/vk/host.sock`
  (over vsock): guest tooling runs `vk-agent -s /run/vk/host.sock exec -- CMD`
  on the host with no transport knowledge. Without `--host-exec-wrapper` the
  guest can run any host command as the host user; `--host-exec-wrapper` forces
  every command through an allowlist program (`--host-exec-env` passes chosen
  client env globs through to it).
- `--require-cached` on `vk build` and `vk run`: the build may restore stages
  from the instruction cache but must not execute anything — a cache miss
  aborts with exit code 3, so scripts can branch cached-vs-cold without paying
  for a build.
- `vk run --ssh-user NAME` picks the `--ssh` login user (default stays root —
  the only user every image is guaranteed to have); a dev image's unprivileged
  user keeps shared-tree ownership coherent.

### Changed

- Under libkrun, the host→guest sockets (the exec channel, `--ssh`) now live at
  `<vsock.sock>_<port>` instead of the base `vsock.sock` path; tooling that
  dialed the base path directly should switch to a `vsock-auto://` address.
- The in-guest compose control filesystem moved its mountpoint one level down,
  from `/run/vk` to `/run/vk/services` — every visible path
  (`/run/vk/services/<name>/{state,ctl,log,error}`) is unchanged, and `/run/vk`
  is now a plain directory with room for the run's other endpoints.

## [0.6.0] - 2026-07-04

### Added

- `vk run --compose <file>` boots the file's services (a docker-compose subset;
  built from their `build:` stage or pulled from their `image:` ref into clean
  images, config supplied at boot) as sibling microVMs on the run's LAN,
  reachable by name — no readiness wait, retry the first connect. `--profile`
  gates profiled services. Three shapes: alongside an image/`-f` run; as the
  primary itself with `--service NAME` (like `docker compose run`, entrypoint
  and volumes applied); or alone — compose up, services only, held until
  ctrl-c.
- The primary VM controls its compose services through `/run/vk`:
  `services/<name>/{state,ctl,log,error}` — `echo restart > ctl` blocks until
  done, plain reads report state and console tails. No client binary needed.
- `vk run --ssh` serves SSH into the guest with no sshd in the image, and
  prints a ready-to-paste ssh command (keys from `--ssh-key` or your standard
  `~/.ssh` identities); VS Code Remote-SSH works out of the box.

### Changed

- The GitLab executor boots a job's `services:` as sibling microVMs on the
  per-job network instead of docker containers inside the job VM: job images no
  longer need docker, and registry credentials never enter a guest. The
  `[services]` config replaces `registry_proxy`/`port`/`ready_timeout_secs` with
  an optional `store_dir`.

### Removed

- The `vk fleet` command and the in-guest `virtctl` client. `vk run --compose`
  covers the workload with run's lifecycle: images materialize per run (warm
  through the instruction cache) instead of a named on-disk store, everything
  dies with the run, and the `/run/vk` control filesystem replaces virtctl.

### Fixed

- `vk run IMG -- cmd arg ...` preserves each argument as typed (docker-run
  semantics) instead of joining them with spaces, so quoting and shell
  metacharacters in an argument no longer leak; use `-- sh -c '...'` for shell
  features.

## [0.5.0] - 2026-07-03

### Added

- `vk check` verifies the host is usable by the current user — `/dev/kvm`
  access, the VMM backend, the guest kernel/agent, and each configured
  feature's host prerequisites; `--feature` checks specific features.
- **Built-in libkrun VMM, on by default** — no external hypervisor binary is
  needed. Cloud Hypervisor remains available (`VIRTKIT_VMM=cloud-hypervisor`).
- **Self-contained `vk`**: the guest kernel and `vk-agent` are embedded into the
  binary — a single file boots OCI images.
- **Build caching works out of the box**: microVM builds cache to a builtin local
  store by default, so a repeat build restores instead of rebuilding.
  `--cache-registry` selects a registry, a store directory, or `none`.
- Registry destinations can be a local store directory, accessed in-process and
  interchangeable with a `vk registry serve` on the same root.
- `vk registry gc` prunes idle tags and unreferenced blobs from a store.
- `run --cpus host` matches the host CPU count.
- Build-time network policy on `build` and `run -f`: `--build-net none` cuts the
  `RUN` steps off the network, and `--build-allow-ip CIDR[:PORT]` /
  `--build-allow-name SUFFIX` restrict their egress to an allowlist. The booted
  guest's `--net` is unaffected.
- `-f` is repeatable on `build`, `run` and `docker-hash`: the Dockerfiles merge
  into one stage namespace, so a `FROM` or `COPY --from` in one file can name a
  stage declared in another. `--context` is repeatable too, pairing with each
  `-f` in order.

### Changed

- Images boot from a native ext4 disk by default; the in-RAM cpio boot moves
  behind `--ram` (replacing `--disk`) and the cpio bundle format is retired.
- `vk virtiofsd` is reimplemented on the vendored libkrun fs engine; nothing in
  the tree links C libraries anymore.
- `run` streams its boot media instead of materialising launch temp files; an
  aborted boot no longer leaves a rootfs behind.
- The pinned guest kernel is bumped to 6.18.37.
- The guest kernel source falls back to the PGP-signed upstream git tag, verified
  against a vendored signing key, when the kernel.org CDN is unavailable.

### Fixed

- the run-stage shell is picked by probing the booted guest for bash, so
  bash-less images (alpine, distroless) run correctly.
- a `--ram` boot refuses an initramfs that cannot unpack in `--mem`, naming the
  required size.
- a stage consuming another via `COPY --from` or `RUN --mount=from` rebuilds
  when the source stage changes, instead of restoring a stale cached snapshot.
- `COPY --from=<stage>` with an absolute source copies the stage's path, not
  the host's.
- the fleet boots its units and the dev VM with the selected VMM backend
  (libkrun by default) instead of always Cloud Hypervisor.

## [0.4.0] - 2026-07-02

### Changed

- **Breaking:** the binaries are renamed — the host driver ships as `vk` (crate
  `vk-driver`) and the guest agent as `vk-agent`; the default install tree moves
  from `/usr/local/lib/virtkit/` to `/usr/local/lib/vk/`. The `VIRTKIT_*`
  host↔guest env-var protocol and the `/etc/virtkit`, `/var/lib/virtkit` and
  `$XDG_DATA_HOME/virtkit` runtime/state paths are a wire contract and are
  unchanged.
- Shared host↔guest code (the wire protocol, the exec/pty/forward helpers and
  the `.dockerignore` matcher) moved into a new `vk-core` crate; `vk` no longer
  depends on the agent crate, so guest-only code (the SSH stack, …) can never
  reach the host binary.
- Single `ring` crypto backend (aws-lc-rs dropped) plus thin LTO and one codegen
  unit on the release profile shrink the stripped binaries: `vk` 16.20 →
  11.85 MiB (-26.9%), `vk-agent` 6.58 → 5.62 MiB (-14.7%).
- The shipped guest `vmlinux` is stripped of its unloaded ELF symbol tables
  (~4.5 MB smaller; kallsyms keeps panic/oops backtraces symbolized).
- Rust toolchain upgraded to 1.96.1.

### Removed

- **Breaking:** the agent no longer creates the in-guest `/usr/local/bin/virtctl`
  convenience symlink at boot; expose the fleet control client explicitly with
  `fleet --vm-symlink /usr/local/bin/vk-agent:/usr/local/bin/virtctl`.

## [0.3.0] - 2026-06-30

### Added

- **microVM Dockerfile builder** (`virtkit build`): builds a bootable ext4 from a
  Dockerfile with no buildkit and no docker — each `RUN` runs in a Cloud Hypervisor guest,
  with a content-addressed instruction cache.
- **`virtkit run` boots a Dockerfile target or an image**: `-f <Dockerfile>` builds and
  boots a target; `--source oci|docker|auto` picks an image's rootfs. The command inherits
  the image environment, with `--workdir` for a shared cwd and `--net` for egress.
- **SSH-agent forwarding into guests**: host keys are relayed over vsock and never enter
  the guest — jobs via `[auth] ssh_agent`, `run` via `--ssh-agent` / `--ssh-host`.
- **Port-scoped egress** allowlist rules (`CIDR:port`).
- **`build.sh --use-virtkit`** builds virtkit with itself, and **`--bootstrap-check`**
  asserts the result is byte-for-byte identical to the Docker build.

### Changed

- **Breaking:** the `launch` subcommand is renamed to `run`.
- CoW overlays are created with an in-tree qcow2 writer instead of `qemu-img` (dropping
  that dependency).
- `virtkit docker-hash` now prints each stage's instruction-cache key.

### Removed

- **Breaking:** the buildkit-based `virtkit build` and its flags, superseded by the
  microVM builder above.

## [0.2.1] - 2026-06-28

### Added

- **`virtkit registry inspect <name>[:tag|@digest]`**: check a bundle exists in the
  `[registry]` repo without pulling it — prints the manifest digest and exits 0, or
  exits non-zero if absent. The CI build's already-built check, replacing
  `docker manifest inspect`.
- **Per-job egress narrowing** (`MICROVM_EGRESS_ALLOW_NAME` job variable): a gitlab
  job may restrict its switch egress to a subset of the host `[egress] allow_name`
  cap. The cap stays host-only, so a job can drop down to least privilege but never
  widen its egress; a requested name outside the cap fails the job.
- **`virtkit build --push-bundle <name>:<tag>`**: build a Dockerfile target and push
  the resulting ext4 straight to the `[registry]` as a bundle, in one process — no
  kept ext4 and no separate `registry push`. The fused buildkit → bundle path: the
  ext4 is materialized only transiently (point `TMPDIR` at tmpfs to keep it in RAM)
  and removed after the upload. A push failure fails the build.
- **`virtkit build --conf <virtkit.conf>`**: build a target declared in a project
  manifest with no external driver. The TOML manifest holds `dockerfiles`, a
  `[build_args]` table, and `[targets.<name>]` entries (`stage` + a `version`
  template); virtkit computes the stage hash (byte-for-byte matching the existing
  pipeline) and renders the tag from `{name}`/`{hash}`/`{ARG[<name>]}` tokens
  (`{ARG[debversion]}` → the effective `debversion` build-arg value), with optional
  bash-style strip transforms on `{ARG[...]}` — `%%<sep>*`/`%<sep>*` (before the
  first/last `sep`) and `##*<sep>`/`#*<sep>` (after the last/first `sep`), e.g.
  `{ARG[debversion]%%-*}` → the distro codename. It then
  push-bundles it to the `[registry]` (default), pushes an OCI image with
  `--push <ref>` (service images), loads it into the local container daemon with
  `--load` (the local-dev / docker-mode path), or writes a local ext4 with `--out`.
  `--conf --versions` lists every target's `<name> <version>` (the build's
  already-built / out.env source).
- **`virtkit build --load`**: build a Dockerfile target and load it straight into the
  local container daemon (buildkit `type=docker` streamed to `<cli> load`, no kept
  ext4/registry) — a normal local image, tagged by the `--conf` version (else
  `--name`). The loader is `docker`, overridable via `VIRTKIT_CONTAINER_CLI`.

## [0.2.0] - 2026-06-27

### Added

- **Per-job `switch` networking for the gitlab executor** (`net.mode = "switch"`):
  each job runs on its own userspace switch over vsock instead of a host tap — no
  host privileges and no virtio-net device. The in-guest agent bridges eth0 over
  vsock and takes a static address; the switch is spawned on `prepare` and torn
  down on `cleanup`.
- **DNS-pinned egress allowlist** for the switch (`virtkit switch --allow-ip
  <CIDR>` / `--allow-name <suffix>`, and the executor `[egress]` section): names
  outside the allowlist are refused (NXDOMAIN) and the A-records of allowed names
  are pinned for their TTL, so a guest can only reach a static allowed CIDR or a
  freshly resolved allowed name. Transparent; the default is unrestricted.
- **`virtkit build --push <registry>/<name>:<tag>`**: build a Dockerfile target and
  push it to a registry as an OCI image (no docker).
- **Embedded local OCI registry** (`virtkit registry serve` / `install-service`):
  a minimal v2 server over a content-addressed store, so dev worktrees share one
  bundle pool with no docker. Single musl-static binary.
- **Fleet bundle sharing** (`virtkit fleet --registry <repo>` / `--registry-serve
  <dir>`): build each unit's ext4 once and pull/push it across worktrees keyed by
  its content fingerprint; `--registry-serve` starts an inline ephemeral server
  over a shared store with no daemon. Best-effort — a registry failure never fails
  the build.
- **Transparent-zstd chunks** (`[registry] transparent_zstd`): chunks addressed by
  the *uncompressed* digest with the registry storing them zstd and negotiating
  `Content-Encoding` on the wire — compression-level-independent dedup, still
  OCI-interoperable. Auto-negotiated: used against a cooperating registry
  (virtkit's `regserve`, which advertises support on `/v2/`), with the
  compressed-digest layers as the fallback any dumb OCI registry stores compactly.

### Changed

- The bundle push compresses and uploads chunks concurrently (streaming, bounded),
  and caches each raw chunk's blob digest (`$XDG_CACHE_HOME/virtkit/chunkmap`) so a
  re-push skips recompressing unchanged chunks.

### Fixed

- File-capability xattrs (e.g. `/usr/bin/ping`'s `security.capability`) are
  preserved through the OCI layer flatten — they were dropped when the merger
  re-emitted the rootfs tar, leaving `ping` without `cap_net_raw`.

## [0.1.10] - 2026-06-27

### Fixed

- `read_boot_kind` trims the `boot.kind` marker before matching, so a marker
  written with a trailing newline (e.g. via `echo`) is read as the intended boot
  flavour instead of falling back to the systemd default.
- The guest agent writes `/etc/resolv.conf` from `VIRTKIT_VM_DNS` for every net
  mode, not only the vsock-bridge path. A guest on the kernel `ip=` (tap/pool) net
  previously got no resolver; it now gets one `nameserver` line per comma-separated
  entry.

## [0.1.9] - 2026-06-26

### Added

- Generic (`docker/`) converted guests now capture the image's `Config.User` and
  `Config.Env` into `/etc/virtkit/{user,env}` (which `docker export` drops), like
  the systemd path. The serve-mode agent restores the env and drops each stage to
  the image USER, so a plain image booted via `docker/<image>` runs exactly like
  `docker run` — as its USER, with its env — with no bespoke bootable variant.

### Changed

- Renamed the guest run-user env var `CMDRUNNER_DEFAULT_RUN_USER` →
  `VIRTKIT_DEFAULT_RUN_USER` (a leftover from the cmdrunner era).

## [0.1.8] - 2026-06-26

### Added

- New `[gitlab]` config section with a `dir` of static CI tool binaries (e.g.
  `git`, `git-lfs`, `gitlab-runner`) that the GitLab executor shares **read-only
  over virtio-fs** into every job VM. The in-guest agent links each tool onto the
  guest PATH (`/usr/local/bin`), skipping any the job image already provides
  (per-image opt-out, checked in-guest). Dynamic: the binaries stay on the host
  and are baked into no bundle, so updating them needs no re-conversion
  (`VIRTKIT_TOOLS=tag:mountpoint` drives the in-guest mount + link).
- `virtkit build --local-out <dir>` exports the target stage's rootfs to a host
  directory (buildctl `type=local`) instead of building an ext4 — e.g. to extract
  a built static binary from a scratch-final stage. `--out` and `--local-out` are
  mutually exclusive.

## [0.1.7] - 2026-06-25

### Added

- Native OCI bundle registry: `virtkit registry push <dir> <name>:<tag>` and `virtkit
  registry pull <name>[:tag|@sha256:…]` push/pull guest bundles (`runner.ext4` +
  `boot.kind` [+ `vmlinuz` + `initrd.img`]) straight to/from an OCI registry — no
  `oras`, no docker. `runner.ext4` is split with content-defined chunking (FastCDC) and
  each chunk is zstd-compressed and stored as its own blob keyed by the sha256 of the
  compressed bytes, so bundles that share data share blobs: pushes skip blobs the
  registry already has, and pulls skip chunks already in a local content-addressed
  cache. A new `[registry]` config section (registry repo allowlist + auth/TLS) gates it.
- New `local/` source for guest bundles baked on the host filesystem, configured by a
  new `[local]` section (`dir`, defaulting to `<state_dir>/images`, + `generic_kernel`).
  Each `<dir>/<name>/` is a bundle resolved straight from disk (no fetch).
- `MICROVM_IMAGE` is now fully prefix-based (the prefix names the source, split on the
  first `/`): `local/<name>` (a `[local]` bundle), `registry/<name>[:tag|@sha256:…]` (a
  `[registry]` bundle, pulled+cached like `[convert]` caches conversions), or
  `docker/<name>[:tag|@sha256:…]` (an on-demand `[convert]` conversion). Unset =
  `local/default`.

### Changed

- The default guest bundle now boots as a generic, agent-served disk guest
  (virtkit-agent is PID 1 on the ext4 root and serves the exec channel over vsock)
  instead of a self-booting systemd image. The run stage falls back to POSIX `sh`
  only for cpio/OCI guests; disk guests keep the configured `run_command` (bash).
- **Breaking:** the `MICROVM_IMAGE: default` keyword AND the single `[image]` config
  section are both removed. The builtin bundle is replaced by the `[local]` source: a
  default guest is now the `local/default` bundle (selected by leaving `MICROVM_IMAGE`
  unset, or explicitly). A bare `<name>` is no longer a registry image — registry
  bundles now require the explicit `registry/` prefix.

## [0.1.6] - 2026-06-24

### Changed

- `virtkit build`/`mkext-oci`: the flattened rootfs is now streamed straight into the
  ext4 builder over an OS pipe instead of being written to an intermediate rootfs tar
  and read back. For a large image (the dev VM is ~8 GB / 200k+ entries) this drops a
  multi-GB write+read pass.
- The rootless buildkit daemon root now lives under `XDG_CACHE_HOME` (`~/.cache/virtkit-buildkit`)
  instead of `XDG_DATA_HOME` (`~/.local/share`). It holds a purely regenerable, GC-bounded
  build cache, so it belongs under the cache hierarchy and can be reclaimed by cache-clearing
  tools.

## [0.1.5] - 2026-06-24

### Added

- `virtkit build`: build a bootable ext4 straight from a Dockerfile target with no
  docker or podman in the image path. It drives a rootless `buildkitd` (launched
  automatically — a native user-namespace unshare, falling back to `podman unshare`
  on AppArmor-restricted hosts) to an OCI archive, then flattens it to ext4. The
  output's UUID is a content fingerprint of the resolved stage tag plus injected
  files, so an unchanged rebuild is a fast no-op. Supports `--build-arg`, `--add-host`,
  `--label`, `--inject`, `--env-file`, `--free-gib` and `--force`.
- `virtkit mkext-oci`: flatten a local OCI image archive (the tar `buildctl --output
  type=oci` produces) into a bootable ext4, extracting the image config
  (Env/User/Entrypoint/Cmd) into `/etc/virtkit/{env,user,cmd}`. Replaces the
  `podman load → create → export → mkext-tar` chain.
- `fleet` can build each unit's ext4 in-process via the `virtkit build` machinery
  instead of shelling out to the `build-{service,vm}-image.sh` scripts: `--build-dockerfile`,
  `--build-context`, `--build-arg`, `--build-add-host`, `--build-free-gib`, per-unit
  `--unit-target NAME=STAGE`, `--unit-inject NAME=H:G:M`, `--unit-env-file NAME=PATH`,
  `--unit-free-gib NAME=N` and `--agent`. Units without a recipe keep the build-script path.
- `fleet --service NAME:EXT4:IP/CIDR:CID:autostart`: the `autostart` unit flag boots the
  service at fleet start.
- `virtkit-agent serve --exec-wrapper`: gate which commands the agent may execute, with
  the inherited environment filtered to an allowlist.

### Fixed

- OCI layer flattening now preserves hard/symlink targets longer than 100 bytes (the tar
  header field limit), which previously truncated long targets (e.g. uv's deep tool
  hardlinks) and made flattening fail.

## [0.1.4] - 2026-06-23

### Added

- `fleet --vm-ssh-key PUBKEY`: authorise an SSH public key for the dev VM (repeatable).
  Keys are passed inline on the kernel cmdline (`VIRTKIT_SSH_KEYS`), not via a file on
  disk; `fleet` rejects keys that are not in OpenSSH `type base64 [comment]` format.

### Changed

- **Breaking:** renamed the dev VM from "builder" to "vm" throughout — every `fleet
  --builder*` flag is now `--vm*` (`--builder` → `--vm`, `--builder-share` →
  `--vm-share`, `--builder-symlink`, `--builder-uid-map`, `--builder-gid-map`). Update
  invocations accordingly.
- `fleet --vm-name` is now optional; when omitted the VM hostname is derived from the
  ext4 filename stem (was a fixed `builder` default). The name is validated as a
  hostname (`[A-Za-z0-9-]`).
- `virtkit-agent ssh-serve`: replaced `--authorized-keys <file>` with a repeatable
  `--authorized-key <key>` taking inline OpenSSH keys; `init` decodes them from the
  `VIRTKIT_SSH_KEYS` cmdline parameter, so no `authorized_keys` file is read from disk.

## [0.1.3] - 2026-06-23

### Added

- `virtkit fingerprint <ext4> <parts>...`: new subcommand for build scripts to check
  freshness and compute the content UUID without reimplementing the algorithm.

### Changed

- Staleness check and fingerprint recipe moved from `ensure`/`fleet` into the build
  scripts; build scripts call `virtkit fingerprint` and own the UUID comparison.
- `fleet --agent` flag removed — build scripts no longer need to be told the agent
  binary path; they hash their own inputs directly.

## [0.1.2] - 2026-06-22

### Added

- `fleet --builder-share HOST:GUEST[:ro]`: share arbitrary host directories into the
  builder VM via virtiofs (repeatable).
- `fleet --builder-symlink SRC:DEST`: create guest symlinks after virtiofs mounts,
  driven by `VIRTKIT_SYMLINKS` on the kernel cmdline (repeatable).
- `fleet --builder-uid-map` / `--builder-gid-map`: per-share UID/GID translation for
  extra builder shares using virtiofsd's `soft_idmap` (PassthroughFs) mechanism.

### Changed

- ext4 images built from a tar archive now embed a 4 MiB JBD2 journal (inode 8),
  enabling crash recovery when the image is mounted read-write via a CoW overlay.
- `virtkit-agent` service mode (`VIRTKIT_MODE=service`) now forks the entrypoint
  instead of exec-ing it, keeping the agent as PID 1 to reap orphaned processes.
  `VIRTKIT_SERVE=1` optionally starts the vsock exec server alongside the service.

## [0.1.1] - 2026-06-22

### Changed

- Switch to jemalloc as the default allocator on musl targets (same approach as ripgrep).
- Bump `oci-client` 0.15 → 0.17, `sha2` 0.10 → 0.11, `toml` 0 → 1.
- `virtiofsd`: raise `RLIMIT_NOFILE` to 1 000 000 at startup to avoid exhaustion under large file trees.

## [0.1.0] - 2026-06-19

### Added

- Initial codebase: `virtkit` (host driver) and `virtkit-agent` (guest PID 1 / exec server).
- Rootless microVM fleet over Cloud Hypervisor — no tap devices, bridges, or `CAP_NET_ADMIN`.
- Userspace L2 network switch with ARP, DHCP, DNS gateway, and transparent TCP/UDP egress via `ipstack` over `vsock`.
- OCI/Docker image pull and conversion to bootable ext4 + initramfs bundles (`convert`, `oci-pull`, `mkext-tar`, `mkext`).
- Content-addressed ext4 images: filesystem UUID fingerprints build inputs for cheap staleness checks.
- GitLab custom executor lifecycle (`gitlab config / prepare / run / cleanup`) with per-job throwaway VMs and a tap pool.
- Dev fleet orchestrator (`fleet`) — builder + service VMs on a shared `*.lan` network; `virtctl` control client.
- In-VM agent: systemd-less guest init (`init`), vsock exec server (`serve`), and SSH `ProxyCommand` bridge (`connect`).
- Bundled vhost-user virtio-fs daemon (`virtiofsd`).
- Guest kernel build pipeline (`build-kernel.sh`, `update-kernel.sh`; vanilla Linux with vendored config fragment).
- Reproducible static-musl binaries from a digest-pinned Alpine devcontainer (`build.sh`, `update.sh`).

[Unreleased]: https://github.com/wallix/virtkit/compare/v0.21.0...HEAD
[0.21.0]: https://github.com/wallix/virtkit/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/wallix/virtkit/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/wallix/virtkit/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/wallix/virtkit/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/wallix/virtkit/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/wallix/virtkit/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/wallix/virtkit/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/wallix/virtkit/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/wallix/virtkit/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/wallix/virtkit/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/wallix/virtkit/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/wallix/virtkit/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/wallix/virtkit/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/wallix/virtkit/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/wallix/virtkit/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/wallix/virtkit/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/wallix/virtkit/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/wallix/virtkit/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/wallix/virtkit/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/wallix/virtkit/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/wallix/virtkit/compare/v0.1.10...v0.2.0
[0.1.10]: https://github.com/wallix/virtkit/compare/v0.1.9...v0.1.10
[0.1.9]: https://github.com/wallix/virtkit/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/wallix/virtkit/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/wallix/virtkit/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/wallix/virtkit/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/wallix/virtkit/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/wallix/virtkit/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/wallix/virtkit/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/wallix/virtkit/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/wallix/virtkit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/wallix/virtkit/releases/tag/v0.1.0
