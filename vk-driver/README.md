# virtkit — host driver

The `virtkit` binary is the host side of the toolkit: image building and
conversion, the userspace network switch, the compose service runner, and the
GitLab CI executor. See the [workspace README](../README.md) for an
architecture overview and build instructions.

## Configuration

The first file found is read: `--config <path>`, `$VIRTKIT_CONFIG`,
`~/.config/virtkit/config.toml`, `/etc/virtkit/config.toml`. `vk config` prints
the effective configuration (and `vk config --example` an annotated template).
See [`config.example.toml`](config.example.toml) for the full reference;
minimal working configs for each mode are shown below.

## Subcommands

### Compose services

`vk run --compose` boots a docker-compose file's services as microVMs on one
shared LAN (each resolves by name). Three shapes: alongside an image/`-f`
primary, as the primary itself (`--primary`, like `docker compose run`), or
alone — compose up, held until ctrl-c. Inside the primary,
`/run/vk/services/<name>/{state,ctl,log,error}` reads states and
starts/stops services with plain shell writes.

```sh
vk run --compose compose.yml -f Dockerfile --net -- cargo test
vk run --compose compose.yml --primary app        # docker compose run app
vk run --compose compose.yml                      # compose up (ctrl-c stops)
```

Service images come from a registry (`image:`) or are built in-process
(`build:`, each `RUN` in a microVM, instruction-cached — repeat runs restore
instead of rebuilding). `build.dockerfile` also accepts a **list** — a vk
extension merging the files into one stage namespace, so a `FROM` or
`COPY --from` in one file can name a stage declared in another; all files
share the service's single `context`:

```yaml
services:
  redis:
    image: redis:7-alpine             # pulled, fingerprinted by manifest digest
  db:
    build: ./db                       # shorthand: context ./db, ./db/Dockerfile
  api:
    build:
      context: ./api                  # default "." (relative to the compose file)
      dockerfile: api.Dockerfile      # default "Dockerfile"
      target: runtime                 # stage to build (default: the last)
      additional_contexts:            # extra dirs a COPY --from=<name> may read
        shared: ../shared             #   (relative to the compose file, like context;
                                      #    also the `- shared=../shared` list form)
      args:
        VERSION: "1.2"
  app:
    build:
      context: .
      dockerfile: [base.Dockerfile, app.Dockerfile]  # one merged stage namespace
      target: app                     # may build on stages from base.Dockerfile
    depends_on: [db, redis]
```

Also supported per service: `environment`, `command`, `entrypoint`, `user`,
`hostname`, `volumes` (bind mounts), `depends_on` and `profiles`; any other
compose key is a hard error rather than a silent behavior change.

---

### Network switch

Userspace L2 gateway for microVMs: ARP, DHCP, a service-name DNS resolver, and
transparent TCP/UDP egress — no host privileges, multiple VMs on one LAN.
Spawned per run/job; can also run standalone:

```sh
vk switch \
  --listen /run/virtkit/vm0-net.sock \
  --listen /run/virtkit/vm1-net.sock \
  --gateway 192.168.127.1 --prefix 24 \
  --host redis=192.168.127.10
```

---

### Image tools

Build a bootable ext4 image from a rootfs tar (e.g. `docker export`). No
`mke2fs`, no root. The `--uuid` can be set to a content fingerprint so the
image is stale iff the UUID changed.

```sh
# From a docker export:
docker export <container> | vk mkext-tar - out.ext4 \
  --inject /usr/local/bin/vk-agent:/usr/local/bin/vk-agent:0755 \
  --size-gib 8

# From a directory:
vk mkext src/ out.ext4

# Pull an OCI image to a rootfs tar (no docker daemon):
vk oci-pull alpine:3.21 rootfs.tar

# Push/pull a guest bundle to an OCI registry with content-defined chunk dedup
# (CDC + per-chunk zstd; needs a [registry] config). push takes a :tag; pull prints
# the resolved cache dir. Auth is HTTP Basic from [registry]: `username` +
# `password_file` (the password lives in that 0600 file, not in the config), over
# TLS (`ca_file` for a private CA); an empty username means anonymous.
vk registry push ./bundle-dir runner:20260625
vk registry pull runner:20260625
```

---

### Utility subcommands

| Subcommand | Purpose |
|---|---|
| `forward` | Accept on `--listen`, splice to `--to` (opaque byte forwarder). |
| `launch` | Dev: boot any Docker/OCI image as a microVM in one command. |
| `docker-hash` | Compute a content hash for each Dockerfile stage. |
| `virtiofsd` | The bundled vhost-user virtio-fs daemon (passed through to Cloud Hypervisor). |

---

### GitLab CI executor

Runs each CI job in a throwaway microVM. For a task-oriented guide (job variables,
per-phase and per-service egress, services) see
[`docs/gitlab-ci.md`](../docs/gitlab-ci.md). Wire up in
`/etc/gitlab-runner/config.toml`:

```toml
[[runners]]
  [runners.custom]
    config_exec   = "/usr/local/bin/vk"
    config_args   = ["gitlab", "config"]
    prepare_exec  = "/usr/local/bin/vk"
    prepare_args  = ["gitlab", "prepare"]
    run_exec      = "/usr/local/bin/vk"
    run_args      = ["gitlab", "run"]
    cleanup_exec  = "/usr/local/bin/vk"
    cleanup_args  = ["gitlab", "cleanup"]
```

Minimal `config.toml`:

```toml
state_dir = "/var/lib/virtkit"

[local]
# baked guest bundles live under <dir>/<name>/; the default guest is local/default
dir = "/usr/local/lib/virtkit/images"

[net]
mode = "pool"
tap_prefix = "civtap"
count = 32
subnet = "192.168.231.0/24"
```

Manual smoke test (no gitlab-runner):

```sh
export VIRTKIT_CONFIG=/path/to/config.toml VM_JOB_ID=smoke
vk gitlab prepare                     # boots the VM, waits for the agent
printf 'echo hello from $(hostname); id\n' > /tmp/stage.sh
vk gitlab run /tmp/stage.sh build_script
vk gitlab cleanup                     # ACPI poweroff → kill, removes state
```

Job state (overlay, sockets, pidfiles, console/VMM logs) lives in
`<state_dir>/jobs/<job id>/` — `console.log` is where to look when a boot
hangs.

Exit codes follow the custom-executor contract: script failures exit with
`BUILD_FAILURE_EXIT_CODE`; infrastructure failures (VM/vsock unreachable) with
`SYSTEM_FAILURE_EXIT_CODE` so GitLab can retry the job.

#### Guest image selection

`MICROVM_IMAGE` is prefix-based — the part before the first `/` names the source:

- unset → `local/default`.
- `local/<name>` — a bundle directory under `[local] dir` (`<dir>/<name>/`), resolved
  straight from disk. `<name>` is a single safe component; local bundles are never
  tagged or digested.
- `virtkit/<name>[:tag|@sha256:…]` — a bundle in the `[registry]` repo, pulled+cached
  natively with content-defined chunk dedup (CDC + per-chunk zstd).
- `docker/<name>[:tag|@sha256:…]` — an OCI image from the `[docker]` repo, pulled with
  the native OCI client and booted directly (embedded kernel + agent; see below).
- `dockerfile:<path>[?context=<dir>&buildcontext=NAME=DIR&arg=NAME=VALUE][#<stage>]` — a
  git-defined image: built from the job's host-side checkout (the `vk build` path, cached
  and shared across jobs and runners) and booted. Requires `[gitlab] host_checkout`.
- `compose:<file>#<primary>` — a fleet from a compose file in the checkout: `<primary>`
  becomes the job VM, the rest boot as siblings. Same `host_checkout` requirement.

```yaml
my-job:
  variables:
    MICROVM_IMAGE: virtkit/myimage     # :tag (default latest) or @sha256:…
```

With `[docker]` configured, `MICROVM_IMAGE: docker/<name>[:tag|@sha256:…]` boots an OCI
image on demand — the same path `vk run --source oci` uses: the native OCI client pulls
the resolved digest from the `[docker] repo` (the allowlist), flattens it into a sparse
ext4 with `virtkit-agent` injected as PID 1, and boots it on vk's embedded kernel. The
image's Env/User are captured so the guest runs like `docker run` would. Results are
cached (digest-keyed) under `<state_dir>/docker/` and GC'd; no Docker daemon is involved.
