# Changelog

All notable changes to virtkit will be documented in this file.

## [Unreleased]

### Changed

- `vk-registry accounts` no longer hides where its store comes from.
  `--config`, `--root`, `--accounts-db` and `--admin-socket` are listed by
  `vk-registry accounts --help` instead of only inside each subcommand's own
  help, and they work on either side of the subcommand name, so
  `accounts --config FILE list-users` and `accounts list-users --config FILE`
  both do the same thing.

## [0.43.0] - 2026-08-27

### Added

- `vk-registry` can be configured with `mode = "accounts"` to authenticate each
  request as a particular person, or as a named, scoped, revocable API key,
  instead of as whoever holds the one shared secret. Accounts live in an
  owner-only directory under the store (`accounts_db` to put the file
  elsewhere); the file holds no password and no usable copy of any key or
  session.

- People sign in to a registry in accounts mode through the same identity
  provider they use everywhere else: point `[oidc]` at it and `vk-registry` runs
  the sign-in itself, so nobody is handed a shared token to keep. There is no
  separate account to create — the first sign-in makes one.

- A registry in accounts mode has pages to look at: what it holds, each
  repository's tags, and what one image is made of, with links to download the
  parts. A tag that is a content key rather than a name someone chose says what
  kind of entry it is, and the build cache's own repository says so once — so
  its listing reads as something other than a wall of hashes. Read-only, and only for a signed-in person or a machine holding an API
  key — a registry left on the older shared-secret setting does not serve them
  at all.

- An API key now reaches only the repositories it was given. Each key names what
  it may do and where — read or write, one repository, or everything under a
  prefix — and a request outside that is refused, over the registry API and on
  the pages alike; the pages simply do not show what a key cannot reach. People
  create and revoke their own keys from a page in the registry. What a person may
  do stays deliberately coarse for now: anyone the identity provider will sign in
  can read every repository, and pushing needs an administrator — who is also the
  only one who can hand out a key that writes.

- A file can be put into a registry from a browser: sign in, name a
  repository and a tag, choose a file. It goes into the same store
  everything else does, so it can be fetched back through the registry's
  normal interface, and a file the registry already holds costs no extra
  space however many names it is given. Up to just under 64 MiB, and uploading needs
  an administrator, as pushing does.

- A registry in accounts mode can be administered from the command line, on
  the machine that holds it: see who has signed in, make someone an
  administrator or stop them being one, sign somebody out of every session
  they have open, and list, create or revoke API keys. Signing out is what
  taking an administrator's rights away needs beside it — a browser already
  signed in otherwise keeps working until its session runs out on its own.
  This is how the first administrator is appointed, since there is
  deliberately no way to do it over the network. It works with the registry
  running — it asks the server, over a private socket on that machine that
  nothing off the machine can reach — and with it stopped, so appointing an
  administrator or pulling a key costs no downtime. A key created this way
  can be left attached to nobody, which is what CI wants: a key tied to a
  person keeps working with whatever it was given even after that person's
  own access is taken away, so naming an owner buys nothing and misleads
  anyone auditing later. Such a key can only be revoked from this same
  command line, which is why that command line no longer needs the registry
  down.

- The private channel that command line uses is named when the registry
  starts, and nothing on the machine can reach it but the account the registry
  runs as and root. `admin_socket` puts it somewhere else, and
  `admin_socket = false` binds none — the command line then needs the registry
  stopped, as it once always did.

### Changed

- `vk-registry serve --help` now documents the `--config` file: every key it
  accepts and what each one does, plus two complete examples to copy — one with
  a shared secret, one with accounts and sign-in through an identity provider.

- The build cache is legible from the outside now. Its repository is called
  `build-cache` rather than `dfcache`, and its tags say what they are: an
  instruction snapshot is `snap-<hash>` and a base image's filesystem is
  `base-<hash>`, where before a snapshot was a bare hash and only base entries
  were prefixed. `vk docker-hash` prints the new form, and so does
  `$DOCKER_STAGE_HASH` inside a build. This is a cache-format change, so the
  first build after upgrading is a cold one; nothing looks at the old `dfcache`
  repository again and `gc` frees everything it held, though the emptied entry
  stays in the listings until you delete it from the store.

- `vk-registry` now refuses to start on a config file it does not fully
  understand — a setting it does not recognise, at the top level or inside an
  `[[upstream]]`, and an authentication setting the chosen mode would ignore.
  Any of them used to be dropped in silence, which for a misspelt `mode` meant
  serving with the authentication the file was written to replace. `serve`,
  `status`, `gc` and `install-service` all read the file, so all four report
  the bad setting.

### Fixed

- `vk-registry` no longer drops a connection when a request's query string or form
  body has a `%` in front of a non-ASCII character. Signing out from a page with
  such a body was enough to trigger it.

- **Breaking.** In a registry with accounts, an API key limited to certain
  repositories can no longer read the others' content — before, it could, once it
  learned the right identifier. A key is now served only what its own
  repositories hold, or what it could have fetched from another repository it may
  read anyway, so sharing identical content between repositories still costs
  nothing. Registries on the older shared-secret setting keep serving every
  repository to every client, as they did.

  Two things to do. An existing store's layers are not reachable under the new
  rules — a tag still resolves, but pulling what it points at fails — so start
  from an empty store, or push into it again. And a push that names content the
  registry does not hold is now refused, so it has to send its pieces first.

- A repository name may no longer have `blobs`, `tags` or `manifests` as one of
  its path components; such a name is indistinguishable from how the store lays
  itself out on disk, and content pushed under one could be collected as
  unreferenced. Rename before upgrading if you have one.

- `vk-registry` now refuses a manifest larger than 4 MiB, or one referencing more
  than 4096 distinct pieces of content. Both are far above any real image, and
  both apply however the registry authenticates.

- `vk registry status` and `vk-registry status` report how many pieces of content
  each repository holds, and `gc` says how many of those records it dropped.

- `vk-registry` now checks that a pushed layer or manifest really is the content
  its digest names, and refuses the push when it is not. A client can no longer
  claim a piece of content it did not send.

- An upload to `vk-registry` now stays in the repository it was started in, so it
  cannot be finished somewhere the client was not allowed to start one.

- `vk-registry` no longer echoes back an arbitrary content type for a stored
  manifest. It serves one of the four standard manifest types, whatever a client
  or an upstream labelled it, so nobody who can push to a registry can get the
  browser to treat stored bytes as a page from it.

- `vk push` no longer fails when the registry turns out not to hold a piece of
  content the push skipped uploading — it re-sends the image rather than giving
  up. This could happen when housekeeping ran on the registry mid-push.

- `vk registry gc` and `vk-registry gc` no longer delete images that are still in
  use when part of the store is not readable, or holds something they did not
  write. They now name the offending path and stop, having deleted nothing; the
  fix is to remove that path from the store and run the gc again. Repository
  names are capped at 16 `/`-separated parts, far past any real name.

## [0.42.0] - 2026-08-25

### Fixed

- `vk build --debug` now checks the filesystem of the cached stages a build
  actually loads. It used to check a separate copy unpacked just for the
  check, so a fault in the form a normal build loads went unnoticed.

- A `vk build` could have the files it was working on deleted by another `vk`
  starting up beside it, or refuse to start because it picked the same working
  directory as one already running — most often when the build runs inside a
  container writing to a shared output directory. Concurrent builds now keep
  out of each other's way there whether or not they can see each other.

- **A `vk build` stage could lose bytes the guest had already written.** Two
  writes landing close together in the same region of a stage's disk could
  race, and one of them was dropped — a file the guest wrote whole came back
  with a hole in the middle of it. The same could happen between a write and the
  zeroing of a neighbouring range of the disk. It surfaced later and at random:
  an unreadable file in the built image, a stage that would not boot, a kernel or
  module the next stage could not load. Stages cached by an affected `vk` may
  hold what it lost, so they are no longer used: the first build after upgrading
  rebuilds them once.

- **A `vk build` stage built on top of a cached one could come out corrupted.** A
  stage restored from the build cache was read back correctly, but a stage built on
  top of that restored stage saw the parts it had not rewritten itself as garbage or
  zeroes — filesystem errors and unreadable files in the built image, or a stage with
  no filesystem at all. Stages cached by an affected `vk` may hold corrupted content,
  so they are no longer used: the first build after upgrading rebuilds them once, no
  manual cache wipe needed.

- A CI job step that failed part-way through could leave the command it was
  running alive inside the guest, still holding the connection open. A step
  now always closes off the guest's input on its way out, however it ends.

- A cached build stage could be removed by `vk gc` while a job that had
  already resolved it — a later service build, or a service already running
  from it — was still using it, failing the job. It now stays in place for as
  long as the job is using it.

## [0.41.0] - 2026-08-22

### Added

- A build stage that fails once now stays failed for the rest of the CI
  pipeline: other jobs/retries needing the same content-key fail fast instead
  of repeating the same build.

### Changed

- `vk build` output now gets an ext4 journal by default, since it often
  outlives the build (e.g. reattached via `vk run --disk`) and a journal-less
  image can't recover from an unclean shutdown. The opt-out flag is renamed
  from `--journal` to `--no-journal` (`[build] journal` to `[build] no_journal`).

- **`vk build` restores cached stage images lazily instead of decompressing them
  upfront.** A cached base or instruction snapshot now decompresses only the
  parts a stage's steps actually read, so builds with many cached intermediate
  stages spend far less time on "restoring cached image."

- The instruction cache is now versioned: upgrading to a `vk` whose cache format
  or semantics changed treats every entry from an older version as a miss
  instead of restoring it, so a cache-affecting fix takes effect immediately.
  No manual cache wipe needed — the next build on each cache-key just rebuilds
  once, and the orphaned old entries are reclaimed by the existing idle GC.

### Fixed

- A `build:` unit's or docker-tier pull's `.tmp` scratch dir could leak
  forever when it failed — nothing removed it, and idle GC never reclaimed
  it either. A failed build/pull now cleans up its own scratch; `vk gc`
  (and every later build/pull) also sweeps any `.tmp` orphan left over from
  an older, hard-killed one.

- **A build stage's cache could be corrupted by a concurrent build of the
  same instruction.** A cache push could resolve its unchanged parent bytes
  through a shared, mutable reference that a racing build had since
  overwritten, silently splicing that other build's content in. A push now
  only ever reuses bytes from the exact parent it started from.

## [0.40.0] - 2026-08-21

### Changed

- **Guest disk reads and writes to the same image now run concurrently instead of
  queuing one at a time.** A batch of up to 8 in-flight virtio-blk requests dispatches
  across threads rather than serializing each one's full device latency, so a
  disk-backed image no longer pays every request's latency back-to-back.

### Fixed

- **A restarted compose sibling became unreachable by its peers.** Its own reboot
  deleted the network switch's routing socket to it along with its own stale
  control sockets, and the switch never redials a path a sibling's restart erased.

- **A guest disk write that failed partway through could silently corrupt later,
  unrelated reads.** A qcow2 write that allocated a new cluster but then failed to
  write into it left that cluster looking like valid, allocated storage holding
  whatever bytes happened to already be there — invisible to the guest until a
  later read or checkpoint exposed it as unrelated corruption. Suspected root
  cause of a corruption incident on a `vk build` guest.

## [0.39.0] - 2026-08-20

### Added

- **`vk publish` exposes a port on a guest's network to the host.** Accepts connections
  and relays each one, over the same control channel `vk exec`/`vk status` already
  use, to an address the target guest can reach — a compose sibling's own hostname
  included, resolved by that guest's own DNS. Works against whatever the VM is
  already running.

- **`vk check --feature publish` asks a `vk` whether it can run `vk publish`.**

### Fixed

- **A compose sibling started again after `vk service down`.** Its previous boot's
  vsock control-socket files were left behind, so the next `vk service up` failed to
  bind them — the guest itself booted fine, but `vk` never saw it come up, reporting
  the service stopped indefinitely.

- **Cached build stages restore concurrently instead of one at a time.** Build concurrency
  is sized from host memory to bound concurrent guest builds, but that same cap also
  throttled already-cached stages — serializing cheap cache restores to it and delaying the
  real, memory-heavy builds queued up behind them.

## [0.38.0] - 2026-08-20

### Added

- **Persistent volumes with full POSIX ownership.** A `host:guest:disk` volume (compose or
  `vk run -v`) is a whole ext4 filesystem in a host file, attached as a real block device
  instead of shared over virtiofs — so the guest gets full POSIX semantics (arbitrary `chown`,
  device nodes, sockets) that virtiofs's host-side ownership mapping does not allow, and the
  content survives across boots. The backing file is created and formatted the first time it
  is used (sparse; `size=` sets its capacity, default 64 GiB) and reused as-is afterwards.

### Fixed

- **An env-file value's quotes are stripped like docker compose's, not kept like docker's.**
  `--env-file` (`vk run`) and the compose `.env` both took a value fully raw, so a `.env`
  written for both paths — e.g. `TASK_TEMP_DIR='/workdir/.task/builder_$BUILDER_TAG'`, deferring
  `$VAR` expansion to a guest-side consumer — landed quote-wrapped and no longer absolute under
  `vk`, though compose's own `env_file:` already strips a matching pair. Both now strip one
  matching leading/trailing `'`/`"` pair the same way; a bare `--env` flag is untouched since the
  shell already de-quoted it.
- **A compose service's overlay volume now overlays.** Declaring `:overlay` on a
  compose sibling service's volume silently mounted it as a plain virtiofs
  share instead — only the primary's own volumes got the tmpfs-backed overlay.
- **A compose sibling's single-file volume bind now lands as a file.** A
  `host:guest` bind whose host side is a regular file mounted the share
  directly at `guest` for a sibling unit, turning it into a directory instead
  of the bound file — only the primary's own single-file binds got the hidden
  mount + symlink that makes the guest path a real file.

## [0.37.0] - 2026-08-19

### Added

- **A compose group whose primary is a full VM.** A primary that hands PID 1 to the image
  itself — `--init image` / `--init entrypoint`, or the matching `x-virtkit: { init: … }`
  marker — came up with no `/run/vk/services`, so nothing inside a systemd guest could read
  a sibling service's state or start and stop one, and asking for the pair on the command
  line was refused outright. Both now work: the control files are there, they outlive the
  handoff to the image's own init, and a full-VM primary drives its siblings with the same
  plain shell writes as any other primary.

### Changed

- **An image's entrypoint booted as PID 1 runs as the image's `USER`.** `--init entrypoint` ran
  it as root while the same image booted as a compose service ran it as its declared user; one
  image now comes up as the same user either way. An entrypoint that goes on to exec an init
  still needs root — declare `user: root` to keep it — and an image whose passwd has no entry for
  the USER, or no `setpriv` that can make the drop (busybox's takes neither `--reuid` nor
  `--regid`), says so and stays root rather than failing from PID 1. Note that a dropped
  entrypoint spends the fallback to the image's init: PID 1 is `setpriv` by then, so an
  entrypoint it cannot start is terminal.

- **A command run against a guest booted from the image itself runs as the image's `USER`.**
  Reading the USER for the entrypoint axis also gives a pulled image's `-- <command>` and its
  ssh sessions the same user a converted image's already had, so a guest that boots the image's
  own kernel or init (`--kernel image`, `--init image`, `--init entrypoint`) no longer runs it
  as root where the default path would not.

- **A guest's `/run` looks like a real system's.** It is root-owned and no longer
  world-writable, and can no longer grow to half the VM's memory. A process running as a
  non-root user that wrote a socket or pid file straight into `/run` — rather than into its
  own directory there, which still works — now needs that directory, as it would on any
  distribution.

### Fixed

- **A service built from a Dockerfile waits for its ports.** `EXPOSE` was recorded nowhere, so a
  compose or CI service built from a Dockerfile counted as ready the moment its guest booted, and
  a job could connect before it was listening — while the same image pulled from a registry
  waited for the ports its config declares. A built image now carries the ports its Dockerfile
  exposes, inherited from its base image and added to by each stage's own `EXPOSE`. A Dockerfile
  exposing a port its service never listens on therefore never reports ready: a CI job fails to
  prepare after `[vm] boot_timeout_secs`, and locally the service stays unreachable to `vk exec
  --service` — exactly as a pulled image declaring the same already did. A service image already
  built keeps the old behaviour until something makes it rebuild.

- **A compose primary that is not root can drive its siblings.** `/run/vk/services/<svc>/ctl`
  was root's, so a primary running as the image's `USER` — which is now what `--init entrypoint`
  boots as, and what a served command runs as — got `permission denied` writing `start`/`stop`
  and could not control the group it was brought up with. The control nodes belong to the run's
  own user now; `ctl` stays write-only to it, and the states and logs stay readable by everyone
  in the guest.

- **A VM that hands PID 1 to the image comes up on the network.** With `--net`, such a guest
  reached its own init or entrypoint with `eth0` unaddressed, so an appliance that configures
  itself from the running interface had nothing to read and failed outright. The address the
  run assigned is now in place before the image takes over; an image that runs its own DHCP
  client later still lands on it.

- **A VM that hands PID 1 to the image comes up with a name.** Such a guest booted nameless:
  an entrypoint that prepares the machine read the kernel's `(none)` where it expected the
  guest's name, and a declared `hostname:` never reached it at all. The name — and the
  matching self-entry in `/etc/hosts` — is now in place before the image takes over; an
  image that ships its own `/etc/hostname` still wins.

- **A build's base image is resolved once per invocation.** Every calculation of where a build
  lands — addressing a service, building it, answering `vk list --stale` — asked the registry
  again for the base image's digest: several anonymous requests, against the registries that
  rate-limit exactly those. And because a lookup that failed was not treated like one that
  answered, a single timeout could leave two calculations disagreeing about where a build
  belonged — after which that service was rebuilt from scratch on every start and reported
  stale for good, however untouched its sources. One lookup per base now, and every
  calculation agrees on it.

- **A CI service built from the repo boots that build's image, with its own settings.** A
  compose service the job builds came up with none of the environment, user or working
  directory its image declares: one declaring no `command:` ran a shell instead of its image's
  command, and one asking for `init: entrypoint` was refused for declaring no entrypoint when
  it had one. It could also boot a different build of the service than the one the job had just
  made, or fail to find any, when a registry was slow to answer. Both the image and its
  settings now come from the build the job ran.

- **A service built on its first `vk service up` boots the image that build produced.** A
  service a profile excludes is built only when it is first brought up; if anything in its
  build context had changed since the run started, the boot still went looking for the image
  the older sources would have produced — so it failed to find one, or came up on a stale
  image while the fresh build sat unused.

- **A guest's network interface survives being taken down and back up.** Bringing the link
  down from inside the guest — `ifdown`/`ifup`, NetworkManager, a DHCP client restart —
  used to cost it the interface for the rest of the run; it now comes back on its own once
  the link is back up.

## [0.36.0] - 2026-08-18

### Added

- **`[vm] nested`: CI jobs that boot microVMs of their own.** A GitLab job could not nest —
  the job VM masked VMX/SVM and a compose file asking to nest was refused, with nothing a
  runner admin could turn on instead. The runner config now carries the switch, so a fleet
  that builds or tests virtkit itself can run `vk` inside its job. Off by default, and it
  is the grant that also unlocks a `compose:` fleet's `x-virtkit: { nested: true }`, so the
  nesting guest can be a sibling rather than the primary; ungranted, that marker stays
  refused and no job variable can ask for it. A runner that sets the grant on a host
  without `kvm_intel.nested` / `kvm_amd.nested` is told so by `vk check --feature gitlab`
  and again when a job prepares, rather than handing the job a guest that cannot nest. On
  the cloud-hypervisor backend a job nests whenever the host allows it, setting or no
  setting.

- **`vk run --init entrypoint`: the image's own entrypoint as PID 1.** An image whose
  entrypoint prepares the machine and only then starts the real init now gets that step
  run: `--init image` hands PID 1 straight to `/sbin/init`, so the preparation was skipped
  in silence and the guest came up with none of the services the entrypoint would have
  assembled. The new axis execs the image's ENTRYPOINT+CMD as PID 1 instead, so the
  entrypoint hands PID 1 on when it execs the real init. It runs as root, being PID 1, and a
  trailing `-- <command>` runs on its own rather than wrapped in that entrypoint. A compose
  service picks the axis per service with `x-virtkit: { init: entrypoint }`, and
  `--init image` is unchanged.

- **`vk check --feature entrypoint`: ask a `vk` whether it can boot an image's entrypoint as
  PID 1.** Reading `--init`'s help answered this only by eye; the probe answers with an exit
  code, so a script can gate on it, and a `vk` too old to have the axis rejects the feature
  name outright. It names every `--init` axis the build supports and reports the agent that
  execs the entrypoint. Named-only — it says something about the build rather than the host,
  so `vk check` on its own does not print it.

### Changed

- **The help reads as a summary.** Every command and flag now leads with a one-line
  summary, so `vk --help` fits on a screen and `vk run -h` is a scannable list grouped
  under headings (guest, network, compose, SSH, build, …) instead of a wall of paragraphs.
  The detail moved to `--help`, so nothing is lost — and help now wraps at the terminal
  width instead of breaking mid-word. A few flags that shipped with no help text at all
  now have some. `vk-registry` and `vk-agent` read the same way.

- **A refused `--state-dir` names the run holding it.** Starting a second `vk run` on a
  state directory a live run already owns reported only the path — and since that run
  prints its build and boot progress to the terminal that started it, there was no way to
  tell a VM about to come up from one wedged mid-build, nor to find it and stop it. The
  refusal now carries the owning process and how long it has been running.

### Fixed

- **A `vk-registry serve --addr` you pass is the address it listens on.** With a `--config`
  file that set `addr`, the file won and the flag was ignored without a word — while
  `--root` worked the other way round, so the same command line honoured one flag and
  dropped the other. An address passed on the command line now wins, and the file supplies
  it for the runs that pass none.

## [0.35.0] - 2026-08-14

### Added

- **`vk run --nested`: microVMs inside a microVM.** The guest gets VMX/SVM and its own
  `/dev/kvm`, so `vk` runs inside a `vk` guest — build and boot images from a VM instead of
  only compiling them there. Needs nested virtualization enabled on the host
  (`kvm_intel.nested` / `kvm_amd.nested`), which the flag checks before pulling or building
  rather than leaving a guest whose `/dev/kvm` never appears. The guest kernel also carries
  what KVM needs to give those VMs an in-kernel interrupt controller, so qemu and friends
  boot in there too, not just `vk` inside `vk`. Off by default (nesting is for trusted
  guests); on the cloud-hypervisor backend a guest nests whenever the host allows it, flag
  or no flag.

- **A compose service can nest on its own.** `x-virtkit: { nested: true }` gives one service
  its own `/dev/kvm`, so a fleet can hold a builder that nests beside ordinary services that
  do not — honored the same whether the service runs as the `--primary` VM or as a
  background sibling. A host that disallows nesting refuses the boot. CI fleets cannot ask
  for it: a job-authored compose file reaching host KVM is the runner's decision, not a
  job's.

- **`vk-registry update`.** Upgrade the registry server in place from its GitHub releases —
  the latest by default, or the version you name — with the same checks `vk update` makes:
  it shows what it will install and asks first (`--yes` for unattended use). A server
  already running keeps serving the build it started as, so the command names the restart
  that puts the new one in service. `--check` reports whether a newer release is available
  without installing it, exiting 1 when there is one.
- **`vk-registry install-service --config`.** The unit it writes can now read the same
  config file `serve` does, instead of carrying an address and store baked in at install
  time — so editing that file is enough to move the server, and what the command reports
  about the one it started follows the TLS the file turns on.
- **`vk-registry install-service --system` prints a machine-wide unit.** The unit it
  installs is a `systemd --user` one, which runs as whoever installed it and cannot bind a
  port below 1024. The printed unit is for a server shared by every runner: an unprivileged
  account of its own, the store as its only writable path, and permission to bind a
  privileged port only when the port it was given is one. Install it with your own `sudo`;
  `vk-registry` itself still asks for no privilege anywhere.

### Changed

- **`vk registry status`/`gc` follow the store you configured.** They report on and sweep
  the store your configuration puts the build cache in (`[build] cache_registry`) instead
  of always the built-in default, so `gc` reclaims the store this host actually fills —
  including one you moved to another disk. When the cache is kept on a `vk-registry`
  server they refuse and ask for a `--root` in this filesystem, since the store is on that
  host. `vk paths` names the same store and says which setting placed it there.
  `vk-registry status`/`gc` take the same `--config` as the server, so they act on the
  store it was configured with.

### Fixed

- **A `vk-registry` serving TLS says `https` when it starts.** It announced its own URL as
  `http://` whichever scheme it was serving, so the line that confirms TLS came up reported
  the opposite.
- **Asking about a registry store no longer creates one.** `vk registry status` and
  `vk registry gc` (and `vk-registry status` / `vk-registry gc`) left a store directory tree
  behind at whatever path they were pointed at — including the default one, on hosts that
  had never used a registry. They now report an absent store as absent and write nothing,
  so a mistyped `--root` is visible instead of silently materialized.

## [0.34.0] - 2026-08-14

### Added

- **A build says how wide it is allowed to run.** Before the first stage starts it reports
  how many stages it may build at once, whether that came from your configuration or from
  the host's free memory, and the size of one stage's guest — so a build squeezed onto a
  loaded runner is told apart from one that simply had nothing to run in parallel.

### Changed

- **`--build-jobs 0` is refused instead of quietly meaning one.** It and `[build] jobs = 0`
  now fail, naming the offending value, rather than building one stage at a time and
  reporting that as the concurrency you configured.

### Fixed

- **A build caching to a registry (`--cache-registry`) restores its cached stages all at
  once.** They came back one at a time however many were ready, so a job that was entirely
  cache hits took as long as its restores added up to.
- **A base image can no longer be cached under another base image's name.** Two stages
  fetching their base images at the same time could store one image's filesystem under the
  other's cache key, so every later build starting from that image restored the wrong
  filesystem. Only builds caching to a registry were affected.
- **Two pulls fetching the same chunk at once no longer poison the image cache.** They could
  leave a partial chunk cached under its digest, and every later pull trusted it — so the
  image failed to unpack, or unpacked with corrupt bytes in it, on every run until that entry
  aged out. A cached chunk is now always the whole chunk, and one left behind by a killed pull
  is reclaimed instead of occupying the cache for good.

## [0.33.0] - 2026-08-13

### Added

- **A detached VM can shut itself down when left unused.**
  `vk run --detach --inactivity-timeout SECS` keeps accepting `vk exec` commands after its
  startup command finishes, then powers off once none has run for the chosen interval (`0`
  keeps it alive until stopped), so a VM left behind stops holding memory.
- **Every CI job now records what happened inside its VM.** The job's guest samples its own
  CPUs, memory, paging, pressure, disks, network and processes every 10 seconds and leaves the
  samples in `<state_dir>/atop/<date>/<job>/atop.log`. It is the text format `atop -P` prints,
  so existing atop parsers — or plain `grep`/`awk` — read it, and the account of a job survives
  the microVM that is destroyed when the job ends. On by default; `[gitlab] atop = false` turns
  it off and `atop_interval_secs` changes the resolution. See the
  [GitLab CI guide](docs/gitlab-ci.md#resource-usage).
- **A job's recorded statistics are kept for two weeks.** Each day of recordings older than
  `[gitlab] atop_retention_days` is dropped whole, so the archive stays bounded on a runner
  nobody visits. Anything else left in it by hand is never touched.
- **`vk atop` finds a recorded job's log.** Give it a job id, or any part of a job's name, and
  get the newest run of it — or hand it the path a job's trace printed, which reads on any
  machine, runner or not. It prints the path alone, so it composes with whatever reads logs
  (`less $(vk atop 42137)`).
- **`vk atop --summary` accounts a recorded job.** Instead of a few hundred lines per
  interval it prints the job: how long its guest ran, what it did with its processors and
  memory, what it moved over its disks and network, where it was held up waiting for a
  resource, the shape of it over time, and which of its processes the time went to. A figure
  the guest's kernel could not measure reads as `-` rather than as zero, and a log torn off by
  a VM that died is reported as far as it goes.
- **`vk atop --json` writes a recorded job's samples as JSON lines.** One object per
  sample, in the log's own units, for anything that would rather compute over a job than read
  it (`… --json | jq`). A figure the guest's kernel could not measure is `null`, never a zero.
- **`vk atop --view` walks a recorded job, and `--follow` watches one as it runs.** A
  full-screen panel of one sample at a time, walked with the arrow keys, sorted by cpu, memory
  or disk, filtered to the commands you are looking for, and switchable between a sample's
  activity and each process's whole-job totals. `--follow` picks up samples as the running job's
  guest commits them and holds still whenever you step back to read one.
- **`vk atop` watches a running VM.** Run it beside a `vk run` VM (or name the VM's
  directory) and its guest starts being sampled on the spot — nothing had to be asked for at
  boot, and the VM carries on running. On a terminal the panel opens on the recording as it
  grows; `--summary` records until Ctrl-C and then accounts what happened, and with no
  terminal to draw a panel on it records the same way and says where the recording is. That
  recording stays on the host afterwards, for `vk atop <path>` to read back with any of the
  flags above, and each new watch of a VM replaces the last one's. `--interval` sets the
  cadence (5 seconds by default).
- **`vk run --atop` records a dev VM from boot.** The very recording a CI job's guest makes,
  for a VM booted by hand: one sample every 5 seconds (`--atop=SECS` to change), covering the
  boot itself and landing in the run's `--state-dir`, at a path printed as it boots. `vk atop`
  beside that VM reads its own recording rather than starting a second one, and `--summary`,
  `--json` and `--view` all work on it while the VM runs — or long after it stopped, handed
  the path printed at boot.
- **A job's short-lived processes are now recorded too.** The guest asks its kernel to report
  every task as it exits, so the commands a job forks in their thousands — a compiler per file, a
  process per test — appear in the log with the whole of what each one used, where before they
  came and went between two samples and were never seen at all. `--summary` folds them into one
  row per command with the number of runs and how many failed (`cc1plus ×1184 (2 failed)`), and
  the panel marks them `E`. A dead process has only the name its kernel kept, not the arguments
  it was given, and a guest churning faster than the records can be read says so on its console.
- **Every job's trace now ends with what its guest did.** The account that `vk atop
  --summary` prints — the processor time and where it went, the memory held, the disks and
  network, the pressure that held the guest up, and the processes the time went to — is written
  into the trace itself, inside a section the GitLab UI shows folded. Reading a slow or failed
  job no longer starts with finding the runner it ran on. Nothing to report means no section,
  and it can be turned off with the recording (`[gitlab] atop = false`).

### Changed

- **Caching a built stage is several times faster.** Storing an image — the tail of every
  stage a build does not restore from cache, and of every publish — used a single core no
  matter how many the host had. It now runs across all of them: on a 12-core host,
  snapshotting a ~4.7 GiB image into the cache drops from about two minutes to under half
  a minute. Nothing about the stored result changes, so existing caches keep deduplicating
  against it.

### Fixed

- **A guest dialling an address the network cannot carry now fails at once.** A connection to
  documentation, loopback, link-local, multicast or broadcast space appeared to connect and
  then died on the first read seconds later, because the switch answered the guest before
  trying the destination. Such a dial is now refused as it is opened, the way any unreachable
  address behaves. Reaching the host's own LAN is unaffected.
- **A compose unit's image is reused again on hosts whose `blkid` is busybox's.** Its
  freshness is decided by the filesystem UUID stamped in the image, but reading that back
  went through `blkid`, which on a musl/busybox host answers in its own format and reports
  success — so the UUID never matched, every unit rebuilt from scratch on each run, and no
  build cache could help. The UUID is now read from the image itself.
- **A corrupt run-config sidecar fails the push instead of vanishing.** A bundle whose
  `runner.ext4.json` no longer parsed was published without it, so the image booted
  without its `Env`/`User` and nothing pointed at why. Pushing such a bundle is now an
  error naming the sidecar; a bundle without one is unaffected.
- **A bundle can be published to a local store.** `vk registry push` and `vk build --tag`
  failed outright whenever the configured registry was a store directory rather than a
  server, complaining that the path was not a valid image reference — while builds could
  already share their images through such a store. Both now write straight into the store.
- **A build log off a terminal now says how long each step took.** Every finished step
  reported `0.0s` whenever the output was not a terminal — a git hook, a CI log, a streamed
  service build — so the durations were missing from exactly the places they get read after
  the fact, and a slow build gave no clue which step it was spent in. They now carry each
  step's real run time, as the live dashboard already did.

## [0.32.0] - 2026-08-11

### Added

- **A CI job now reports how full it filled its writable layer.** Where a job builds on an
  in-guest overlay above its checkout, everything it writes under `CI_PROJECT_DIR` is RAM
  capped at that layer's size — a wall that fails the job for want of space while every disk
  on the host sits empty and the `written` figure beside it says it wrote nothing at all. The
  job's usage line, the "most this job has used lately" line and `vk gitlab usage` now carry
  the high-water mark against that capacity (`overlay 15.9 GiB of 16.0 GiB`), so a job running
  out of room is visible before it fails and `MICROVM_MEM` can be raised on evidence rather
  than on a guess. A job whose checkout is mounted read-write has no such layer and reports
  none, as does one on a guest too old to be asked.
- **The writable layer a CI job builds on is now sized by the runner, and larger by default.**
  `[gitlab] checkout_overlay_size` says how much of a job's VM memory that layer may take —
  `"80%"` by default, where the kernel's own tmpfs default left it at half. That older figure is
  the one that protects a general-purpose machine's services from an unevictable tmpfs, which a
  one-shot job guest has none of, and it fails builds the VM had the memory for. Raising it costs
  nothing below the cap and reserves no extra host memory, so the jobs it changes are the ones
  that were already running out of room. Set `"50%"` for the previous behaviour, or an absolute
  `"12G"`.
- **A raw disk image can be exported for VMware.** `vk export vmdk disk.raw` packages a
  bootable raw disk (e.g. a `vk build --disk` artifact) as a streamOptimized VMDK — the
  compressed subformat vSphere's OVF/OVA import streams — natively, with no qemu-img.
  `vk export ova` wraps that VMDK in a one-file OVA appliance (OVF descriptor + SHA256
  manifest) ESXi/vCenter import directly, with `--name`, `--cpus`, `--mem`, `--guest-os`
  and `--firmware bios|efi` describing the VM — no ovftool, no vSphere in the build.
- **An auto-install ISO can be built natively.** `vk export iso` packages a staged
  directory tree as a bootable ISO 9660 image — Rock Ridge names, an El Torito catalog
  with BIOS and/or UEFI entries (`--bios-boot`/`--efi-boot`, boot info table included),
  and an optional `--hybrid-mbr` making the same file USB-writable — the medium for an
  unattended image-based installer, with no xorriso on the host. See
  [the appliance guide](docs/appliance.md) for the recipe.
- **Compose services can size their own guests.** A service declares its vCPUs and RAM with
  `x-virtkit: { cpus:, mem: }` in the compose file (default 2 vCPUs / 1G as before), and
  `vk run --service-cpus`/`--service-mem NAME=VALUE` override it per run. In CI, a
  `compose:` fleet's services follow the same marker, clamped to the host `[vm]
  max_cpus`/`max_mem` ceilings exactly like a job's own `MICROVM_CPUS`/`MICROVM_MEM`.
- **A runner's memory budget can follow the size of the host.** `[schedule] mem_budget` now
  takes a percentage such as `"50%"` as well as an exact `"48G"`, so one configuration leaves
  the same proportional headroom on runners with different amounts of RAM.
- **Unused GitLab host checkouts are reclaimed.** A checkout no job has wanted for the cache
  window is removed before the next one is taken, and `vk gc` now sweeps checkouts alongside
  image bases — so a RAM-backed `checkout_dir` no longer fills up with the repositories of
  jobs that have moved on. A checkout a job is using is never removed, by either sweep, and
  a `checkout_dir` shared with another executor keeps virtkit's trees in a directory of their
  own, so the sweep never considers anything else there. Checkouts an earlier release left
  directly in such a shared directory stay put for the operator to remove, and are cloned afresh
  once; those under the default root keep working and join the sweep once a job has used them
  again. Set `[gitlab] checkout_cache_idle_secs` to keep checkouts longer than image bases where
  clones are expensive.

### Changed

- **Runner concurrency now follows host memory too.** `vk tune` limits new slots by what the
  host still has available after keeping 15% of its RAM free, as well as by the guest memory
  budget. A large RAM-backed repository checkout or a service sharing the box therefore lowers
  concurrency by what it actually occupies, instead of needing a guessed fixed reserve inside
  `[schedule] mem_budget`.

### Fixed

- **Freed guest memory returns to the host from every VM, under either VMM.** `[vm] balloon =
  false` was ignored by the default backend, and conversely under cloud-hypervisor only the CI
  job VM had a balloon at all — compose service, build, and `vk run` VMs held their peak memory
  until poweroff, so a service that had finished its busy phase still counted against the jobs
  sharing the host. All of them now balloon, and the setting is honored whichever VMM is
  configured.

## [0.31.0] - 2026-07-30

### Added

- **A runner can cap the memory its jobs boot at once.** Set `[schedule] mem_budget` and each
  CI job claims the guest RAM it needs before booting, waiting its turn when the host is full
  instead of pushing it into the OOM killer — which until now picked a VM to kill and failed
  that job mid-stage. Jobs go in oldest-first, a waiting job says so in its trace, and one that
  waits past `wait_timeout_secs` fails as a system failure, so a job that asks to be retried
  can land on another runner. A job asking for more memory than the whole budget is clamped to
  it, as it already is to `[vm] max_mem`. Unset, nothing changes: every job starts as soon as
  gitlab-runner hands it over.
- **A busy runner can stop taking work instead of overcommitting.** `vk tune`, run from a
  timer, works out how many jobs this host can hold and leaves the figure for `vk-runnerctl`
  — a new, deliberately tiny binary, the only part of virtkit that runs as root — to write
  into gitlab-runner's `concurrent`. Jobs beyond it stay pending in GitLab rather than
  occupying a slot on a full host, and the runner's capacity follows the load instead of
  being guessed once. `vk-runnerctl` takes no arguments and no paths, so granting it root
  grants nothing else; see the GitLab CI guide for the timer and sudoers forms.
- **A runner can schedule on what jobs really use, not what they ask for.** With
  `[schedule] from_history`, a job is admitted against what runs of that same job have
  actually been using instead of a declared size it almost never reaches, so a host holds far
  more jobs for the same memory. Changing a job's `MICROVM_MEM` starts its history again. The
  guest still gets every byte it declares; only the host's bookkeeping changes, and only when
  you turn it on. Every job trace now ends with what that job has been using and over how many
  runs either way, so a host can be sized from it before deciding to reserve that way.
- **Builds, runs and CI jobs report what they used.** A build and a `vk run` now end with the
  CPU time, the peak memory, and the disk and network traffic they cost the host, and a CI job
  trace ends with the same for the microVM its stages ran in — a ceiling on the CPU, memory and
  disk, and what the guests pulled through the network — to size `[build] mem`/`--mem`/
  `MICROVM_MEM` and `[build] cpus`/`--cpus`/`MICROVM_CPUS` from what the work costs rather than
  by guess. Where several guests run at once — concurrent build stages, a compose fleet — the
  report gives both what they held together and the largest single process.
- **`vk gitlab usage` sizes a project.** One command lists every job this runner remembers for
  a project — what each has been peaking at, the runs behind it, the disk and network it
  moves, and what its next run would reserve — closing with what they would all reserve at
  once against the host's `[schedule] mem_budget`. A job can print its own project's report
  into its trace with `MICROVM_USAGE_REPORT: "1"`, so a project can be sized from the GitLab
  UI without a shell on the runner.
- **Every CI job trace says what that job reaches out to.** A job reports the external names
  its guests have resolved — not just this run's, but everything the job has contacted since
  its egress policy was last changed, so a nightly step's host is on the list even in a
  pipeline that did not run one. That list is the `[egress] allow_name` the job needs, without
  turning anything on first; narrowing the allowlist starts it again, since names reached under
  looser rules say nothing about the job under the new ones. Audit mode keeps its own job: the
  per-run counts, and the IPs a job dialed with no name behind them. The list lives under the
  runner's state dir, readable only by the user the runner runs as, and can be deleted at any
  time — a job then starts collecting again.

## [0.30.0] - 2026-07-26

### Added

- **`vk update`.** Upgrade `vk` in place from its GitHub releases — the latest by
  default, or the version you name. It shows what it will install and asks first
  (`--yes` for unattended use), and VMs already running keep going. `--check` reports
  whether a newer release is available without installing it, exiting 1 when there is
  one.
- **Build steps can read from an external image.** `COPY --from=<image>` and
  `RUN --mount=…,from=<image>` now work in a build: a step reads files straight out of any
  image you name, with no stage to declare for it. Each such image is fetched once per
  build, and a build rereads it when the tag moves. A build stage may no longer be named
  `scratch`, since `--from=scratch` always means the empty base a writable `RUN --mount`
  gets — a stage by that name could never be read from.
- **Extra build contexts.** `--build-context <name>=<dir>`, on `vk build` and on a `vk run -f`,
  lets a build read files from a directory outside the Dockerfile's own context:
  `COPY --from=<name>` or `RUN --mount=…,from=<name>` reads that host directory, so a project
  no longer has to copy outside files in before every build. The directory is read-only to the
  build, and a build rereads it when the files it copies change. A `.dockerignore` in it decides
  what a `COPY` from it takes, exactly as it does for the Dockerfile's own context. A name only
  takes effect when the Dockerfile has no stage of that name, so declaring one can never change
  what an existing Dockerfile means. A CI job gets the same thing from its `dockerfile:` image —
  `?buildcontext=<name>=<dir>` names an extra directory from the job's own checkout — and a
  compose service declares its own with `build.additional_contexts` (directories, resolved
  against the compose file like `build.context`; compose's remote forms are refused).

### Fixed

- **A cached build no longer keeps scratch mountpoints a cold build drops.** Building on a
  base that ships no `/proc`, `/sys`, `/dev`, `/run` or `/tmp` — `FROM scratch` and the
  minimal images — left those mountpoints in the artifact whenever a build reused the
  cache, and they then persisted into everything built on top; the same went for a bind
  target a build step created, on any base. Entries an earlier `vk` already cached keep
  the old contents until the step is rebuilt.

## [0.29.0] - 2026-07-24

### Added

- **`RUN --mount=type=tmpfs` in builds.** A build step can now mount a fresh
  RAM-backed scratch at the target for its duration (with an optional `size=`
  cap); the contents are discarded afterwards and never enter the committed layer.

### Fixed

- Guest DNS no longer breaks when the host's `resolv.conf` separates `nameserver`
  from its address with a tab (or any whitespace) instead of a single space.
- A `USER` given as `user:group`, `uid:gid`, a mixed name/id, or a bare numeric id
  now resolves like Docker's, instead of only the bare-name form working.
- A `COPY` with a relative destination now lands under the active `WORKDIR`, as
  Docker does, instead of at the image root.

## [0.28.0] - 2026-07-24

### Added

- **`vk run --pmu`.** Expose the guest PMU (libkrun backend): CPUID leaf 0xA is left as
  KVM reports it instead of zeroed, so in-guest `perf` gets hardware counters (cycles,
  instructions) via KVM's vPMU. Off by default and deliberately opt-in: host performance
  counters are a side-channel surface, so enable it only for trusted guests (a dev VM),
  never untrusted CI jobs. Needs `kvm.enable_pmu=Y` on the host; the cloud-hypervisor
  backend has no equivalent and warns.

## [0.27.0] - 2026-07-23

### Added

- **`vk list` and `vk stop`.** A `vk run --state-dir` now registers its VM, so `vk list` shows
  the running VMs (pid, uptime, name, the directory each was launched from, and its exec
  address) and `vk stop` brings one down by that directory (or `--all`) — no more grepping the
  process table to find and kill a background VM. `vk list --json` feeds scripts.
- **`vk list --stale`.** Reports, per running VM, whether its root image still matches the
  working tree — whether a fresh `vk run` would rebuild it; for a compose run the verdict
  covers the `build:` services' images too, so a service's Dockerfile drift flags the
  workload. Opt-in: it resolves base image digests (network I/O), so plain `vk list` stays
  offline.
- **`vk status --stale`.** Prints a single `fresh` / `stale` / `unknown` word for the VM
  launched from the current directory (or a given `DIR`), so a script can check image
  freshness with a plain string compare — no JSON parsing needed.
- **Compose services in `vk list` and `vk exec`.** A compose run's declared sibling services
  (running or startable on demand) now show up in `vk list` (`app (+db, redis)`, and as a
  `services` array under `--json`), and `vk exec --service NAME` runs a command in a named
  running service instead of the primary.

### Changed

- **`vk status` selects a VM by directory.** Now an everyday command that, like `vk list`/`vk
  stop`, probes the VM launched from the current directory (or a given `DIR`); a raw agent
  address still works for tooling that already knows the socket. Previously it was hidden and
  only accepted a hand-built `vsock-auto://…` address.
- **`vk exec` selects a VM by directory, and takes the command after `--`.** Like
  `vk status`/`vk list`/`vk stop`, the optional leading target is a directory resolved
  through the VM registry (default: the current directory); a raw `scheme://…` agent
  address still dials directly. The command is now the trailing `-- …` group
  (`vk exec -- ls -la`) — breaking: previously it followed a mandatory raw address,
  no `--` needed.

### Fixed

- **Single-file bind: reading a bound file immediately after an atomic-rename replace.** A
  guest that rewrote a bound file (temp + rename) and then re-read it right away could see a
  stale length or a transient "not found" until a one-second cache window elapsed. The
  single-file mount now disables entry/attr caching (it serves one file — caching bought
  nothing), so a read straight after the replace always resolves the current file.

## [0.26.0] - 2026-07-23

### Added

- **Direct-IP egress is now audited.** Egress to a hardcoded IP never touches the switch's
  resolver, so it left no trace in the egress audit, which recorded only resolved domain names.
  Direct dials are now recorded and printed as a separate "external IPs/ports contacted (audit)"
  block on every surface (`vk run`, `vk build`, and the GitLab executor).

### Fixed

- **A dead egress backend now fails fast instead of hanging the guest.** The switch dialed a
  flow's real destination without a timeout, so an unreachable backend stalled the guest for
  roughly two minutes on the OS default SYN retries. The dial is now bounded (10s), degrading a
  dead backend to a prompt connection error.
- **Single-file binds no longer corrupt shrinking rewrites.** A single-file bind now implements
  `readdirplus` (it advertised `DO_READDIRPLUS` but never implemented it, so `ls` on the mount
  failed with ENOSYS) and supports atomic-rename writers via `create`/`rename`/`unlink`. A
  guest-created temp is backed by a fresh host file under a vk-controlled name in the bound
  file's directory, so the rename onto the target is atomic while a pre-existing sibling still
  can never be opened (single-file read isolation is preserved). Previously writers could not
  create their temp and fell back to a non-truncating in-place rewrite, leaving a stale tail when
  the new content was shorter — silent corruption of e.g. `~/.claude.json`.

## [0.25.0] - 2026-07-23

### Added

- **Overlay mode for `vk run -v` volumes.** `-v HOST:GUEST:overlay` shares the host directory
  read-only and layers a RAM-backed overlay on top guest-side, so the guest reads the host
  tree but every write stays in the guest and never reaches the host — the same isolation CI's
  `checkout_overlay` already gives, now on a plain `vk run` (e.g. a pre-commit hook that checks
  the tree without being able to mutate it).
- **Inline comments in the `MICROVM_EGRESS_*` lists.** A `#` in an egress job variable begins
  an end-of-line comment, so a YAML block-scalar allowlist can annotate each entry inline
  (`crates.io   # Rust registry`) instead of duplicating the entries in a separate comment.

### Changed

- **Faster builds that probe many missing paths.** virtio-fs now caches negative lookups, so
  guest tools that walk include or `PATH` directories no longer pay a host round-trip for each
  nonexistent path.
- **Faster unlink-heavy build phases.** Removing a file no longer triggers a redundant
  per-file timestamp flush to the host, cutting 30-40% off unlink-heavy phases.

### Fixed

- **Clean journal on power-off.** The guest now freezes its root filesystem (FIFREEZE) before
  `reboot`, checkpointing the ext4 journal and clearing its needs-recovery flag on disk.
  Previously power-off only `sync`ed, so a journaled root (an OCI/docker-image boot) was left
  with a dirty journal and the next mount of a persisted or checkpointed disk ran journal
  recovery.
- **Exported images now carry their content-freshness UUID.** `vk build --out`, `vk build
  --compose` and `vk run --compose --primary` stamp the exported ext4's UUID with
  `fingerprint([stage_key])` (as a build-tier unit already was), so `vk fingerprint` matches a
  freshly built image. Previously only the build-tier/`ensure` path stamped it; the plain
  export left the flattened base/cache UUID, so a freshness check against an exported image
  (e.g. a dev-VM staleness probe on `root.ext4`) always reported stale.

## [0.24.0] - 2026-07-22

### Added

- **Separate build/run egress allowlists for CI.** `[egress]` now governs the run phase (the
  booted job guest and its service VMs) and a new `[egress.build]` governs the build phase (a
  git-defined image / compose `build:` service's `RUN` steps) — previously the build ran with
  unrestricted egress. A CI job may only *narrow* either cap via `MICROVM_EGRESS_ALLOW_IP` /
  `MICROVM_EGRESS_ALLOW_NAME` (run) and `MICROVM_BUILD_EGRESS_ALLOW_IP` /
  `MICROVM_BUILD_EGRESS_ALLOW_NAME` (build), never widen; set them at the GitLab group/project
  level and override per job.
- **Per-service egress.** A `services:` entry (or compose sibling) can set its own
  `MICROVM_EGRESS_ALLOW_IP` / `MICROVM_EGRESS_ALLOW_NAME` in its `variables:` to get an egress
  allowlist distinct from the primary — e.g. a database service pinned to no external egress
  (`MICROVM_EGRESS_ALLOW_NAME: ""`) while the job keeps its own. It narrows the host `[egress]`
  cap like any other request; a service that sets nothing shares the run policy. The switch
  now enforces egress per source VM, with DNS pins scoped per source so one service's
  resolution never admits another's connection.
- **`allowlist = []` now denies everything.** An explicit empty allow list means "nothing
  allowed"; leaving a list absent keeps it unrestricted (unchanged). A phase is unrestricted
  only when both its lists are absent.
- **Egress audit mode**: the switch records every external domain a guest resolves and prints
  a "domains contacted" summary, letting a job observe its egress — with or without an
  allowlist — to discover the allowlist it needs. Enable it in CI with `[egress] audit` /
  `[egress.build] audit` (or the `MICROVM_EGRESS_AUDIT` / `MICROVM_BUILD_EGRESS_AUDIT` job
  variables), or on the command line with `vk run --audit-egress` for the booted guest and
  `--build-audit-egress` (on `vk run` and `vk build`) for a build's `RUN` steps.

## [0.23.0] - 2026-07-22

### Added

- GitLab jobs whose egress the switch blocked now see each refused destination reported in
  the job trace, so a script that fails for lack of network access shows why instead of
  failing silently.

### Changed

- Boot and concurrent-lock progress lines now name the image ref being booted and the operation
  (pull vs build) with a human-readable image or service name, instead of a bare `build` literal
  and a build fingerprint.
- Registry pull progress now names the stage, base image, or bundle being fetched instead of
  only the content-addressed cache digest.
- The job trace no longer echoes git's own fetch/clone transfer summary for the host checkout;
  virtkit's `host checkout of <sha>` line stands in for it.
- The host checkout no longer spills git's orphan-commit warning ("leaving N commits behind")
  into the job trace when it moves to a force-pushed ref.

### Fixed

- GitLab jobs no longer start their script before the declared `services:` are ready: a service
  that is slow or fails to boot now fails the job's prepare stage with a named error instead of
  surfacing as an opaque connection failure once the script first reaches it.
- A `services:` container now counts as ready only once it accepts connections on the ports its
  image exposes, not merely once its guest has booted, so a job no longer races a service that
  is still initializing.
- Compose service VMs on a switch subnet other than the default can now reach off-subnet hosts;
  they were booted without a gateway and fell back to an off-link default route that failed to
  install.
- Guest processes that use POSIX shared memory (Python `multiprocessing`, redis-py's shm locks)
  no longer fail on a missing `/dev/shm`; the guest mounts a tmpfs there at boot.

## [0.22.0] - 2026-07-22

### Added

- The config file is now looked up along a standard chain — the first of `--config <path>`
  (a new global flag), `$VIRTKIT_CONFIG`, `~/.config/virtkit/config.toml`,
  `/etc/virtkit/config.toml` wins — so a rootless user gets a real config location
  instead of needing the environment variable.
- `vk config` prints the effective configuration (the defaults merged with the loaded
  file) as TOML, naming which file it came from; `vk config --example` prints an
  annotated template to start from, and `vk config --path` prints the resolved path.
  `vk check` now also reports the config file in use.
- `vk paths` prints the effective host paths — config file, state dir, image cache,
  registry store — where each value comes from, and how to override it.
- `[gitlab] checkout_overlay` (default on): jobs build the `host_checkout` tree on an
  in-guest overlay — the virtio-fs share becomes the read-only lower layer, all writes go
  to a guest tmpfs — so metadata-heavy builds run at guest-native speed instead of paying a
  synchronous virtio-fs round-trip per file operation. The read-only export also means the
  guest can no longer modify the host checkout. Build writes now count against guest RAM
  (capped at half the VM memory); raise `MICROVM_MEM` for jobs with large build trees.

### Changed

- A top-level `vmm` config key selects the VMM backend (`libkrun` or `cloud-hypervisor`),
  so a host need not set `VIRTKIT_VMM` in every environment; the environment variable still
  overrides the key when set.
- `vk run --console-serial` replaces the `VIRTKIT_CONSOLE_SERIAL` environment variable for
  keeping `console=ttyS0` with a BYO stock kernel whose virtio-console is modular.
- Build-guest tuning moved from environment variables to the `[build]` config section:
  `jobs`, `cpus`, `mem`, and `cache_checkpoint_secs` replace `VIRTKIT_BUILD_JOBS`,
  `VIRTKIT_BUILD_CPUS`, `VIRTKIT_BUILD_MEM`, and `VIRTKIT_BUILD_CACHE_CHECKPOINT_SECS`
  (which are no longer read). `vk build --build-jobs` still overrides `jobs`.
- `vk run --cloud-hypervisor` now defaults to the `cloud_hypervisor` binary set in the
  config (matching `vk build`), instead of ignoring it and always using `cloud-hypervisor`
  from `PATH`.
- `vk --help` now shows only the everyday commands (`run`, `build`, `exec`, `gc`,
  `check`) plus usage examples; `vk help-all` lists the advanced/plumbing commands.
- The host image-cache sweep is now `vk gc` (was `vk cache gc`).
- `vk check` no longer checks the CI-executor features (`gitlab`, `services`) by
  default; name them with `--feature` to check them.

### Fixed

- `[gitlab] host_checkout` jobs whose image runs as a non-root user no longer fail with
  `Permission denied` under `/builds`. (The map shipped in 0.21.0 did not actually work for
  a non-root job.)
- A guest connection to an egress-denied destination now fails immediately with
  `ECONNREFUSED` instead of stalling until the guest's own read timeout.
- Reverse-DNS (PTR) lookups from a guest are now forwarded to the upstream resolver
  instead of being refused with `NXDOMAIN`, so tools that reverse-resolve an
  already-permitted peer no longer stall or emit log noise.

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

[Unreleased]: https://github.com/virtkit-dev/virtkit/compare/v0.43.0...HEAD
[0.43.0]: https://github.com/virtkit-dev/virtkit/compare/v0.42.0...v0.43.0
[0.42.0]: https://github.com/virtkit-dev/virtkit/compare/v0.41.0...v0.42.0
[0.41.0]: https://github.com/virtkit-dev/virtkit/compare/v0.40.0...v0.41.0
[0.40.0]: https://github.com/virtkit-dev/virtkit/compare/v0.39.0...v0.40.0
[0.39.0]: https://github.com/virtkit-dev/virtkit/compare/v0.38.0...v0.39.0
[0.38.0]: https://github.com/virtkit-dev/virtkit/compare/v0.37.0...v0.38.0
[0.37.0]: https://github.com/virtkit-dev/virtkit/compare/v0.36.0...v0.37.0
[0.36.0]: https://github.com/virtkit-dev/virtkit/compare/v0.35.0...v0.36.0
[0.35.0]: https://github.com/virtkit-dev/virtkit/compare/v0.34.0...v0.35.0
[0.34.0]: https://github.com/virtkit-dev/virtkit/compare/v0.33.0...v0.34.0
[0.33.0]: https://github.com/virtkit-dev/virtkit/compare/v0.32.0...v0.33.0
[0.32.0]: https://github.com/virtkit-dev/virtkit/compare/v0.31.0...v0.32.0
[0.31.0]: https://github.com/virtkit-dev/virtkit/compare/v0.30.0...v0.31.0
[0.30.0]: https://github.com/virtkit-dev/virtkit/compare/v0.29.0...v0.30.0
[0.29.0]: https://github.com/virtkit-dev/virtkit/compare/v0.28.0...v0.29.0
[0.28.0]: https://github.com/virtkit-dev/virtkit/compare/v0.27.0...v0.28.0
[0.27.0]: https://github.com/virtkit-dev/virtkit/compare/v0.26.0...v0.27.0
[0.26.0]: https://github.com/virtkit-dev/virtkit/compare/v0.25.0...v0.26.0
[0.25.0]: https://github.com/virtkit-dev/virtkit/compare/v0.24.0...v0.25.0
[0.24.0]: https://github.com/virtkit-dev/virtkit/compare/v0.23.0...v0.24.0
[0.23.0]: https://github.com/virtkit-dev/virtkit/compare/v0.22.0...v0.23.0
[0.22.0]: https://github.com/virtkit-dev/virtkit/compare/v0.21.0...v0.22.0
[0.21.0]: https://github.com/virtkit-dev/virtkit/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/virtkit-dev/virtkit/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/virtkit-dev/virtkit/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/virtkit-dev/virtkit/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/virtkit-dev/virtkit/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/virtkit-dev/virtkit/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/virtkit-dev/virtkit/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/virtkit-dev/virtkit/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/virtkit-dev/virtkit/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/virtkit-dev/virtkit/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/virtkit-dev/virtkit/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/virtkit-dev/virtkit/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/virtkit-dev/virtkit/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/virtkit-dev/virtkit/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/virtkit-dev/virtkit/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/virtkit-dev/virtkit/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/virtkit-dev/virtkit/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/virtkit-dev/virtkit/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/virtkit-dev/virtkit/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/virtkit-dev/virtkit/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/virtkit-dev/virtkit/compare/v0.1.10...v0.2.0
[0.1.10]: https://github.com/virtkit-dev/virtkit/compare/v0.1.9...v0.1.10
[0.1.9]: https://github.com/virtkit-dev/virtkit/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/virtkit-dev/virtkit/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/virtkit-dev/virtkit/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/virtkit-dev/virtkit/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/virtkit-dev/virtkit/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/virtkit-dev/virtkit/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/virtkit-dev/virtkit/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/virtkit-dev/virtkit/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/virtkit-dev/virtkit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/virtkit-dev/virtkit/releases/tag/v0.1.0
