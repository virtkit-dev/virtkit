# virtkit — host driver

The `virtkit` binary is the host side of the toolkit: image building and
conversion, the userspace network switch, the fleet orchestrator, and the
GitLab CI executor. See the [workspace README](../README.md) for an
architecture overview and build instructions.

## Configuration

`/etc/virtkit/config.toml`, override with `VIRTKIT_CONFIG=`.
See [`config.example.toml`](config.example.toml) for the full reference;
minimal working configs for each mode are shown below.

## Subcommands

### Fleet orchestrator

Boots a dev VM + named service VMs on one shared `*.lan` LAN (like
docker-compose but as real VMs). Runs the network switch in-process.

```sh
virtkit fleet \
  --vm vm.ext4 \
  --workdir /path/to/repo \
  --service redis:redis.ext4:192.168.127.10/24:3 \
  --service mysql:mysql.ext4:192.168.127.11/24:4 \
  --hosts redis=192.168.127.10,mysql=192.168.127.11
```

---

### Network switch

Userspace L2 gateway for microVMs: ARP, DHCP, a fleet DNS resolver, and
transparent TCP/UDP egress — no host privileges, multiple VMs on one LAN.
Run in-process by `fleet`; can also run standalone:

```sh
virtkit switch \
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
docker export <container> | virtkit mkext-tar - out.ext4 \
  --inject /usr/local/bin/virtkit-agent:/usr/local/bin/virtkit-agent:0755 \
  --size-gib 8

# From a directory:
virtkit mkext src/ out.ext4

# Pull an OCI image to a rootfs tar (no docker daemon):
virtkit oci-pull alpine:3.21 rootfs.tar

# Push/pull a guest bundle to an OCI registry with content-defined chunk dedup
# (CDC + per-chunk zstd; needs a [registry] config). push takes a :tag; pull prints
# the resolved cache dir. Auth is HTTP Basic from [registry]: `username` +
# `password_file` (the password lives in that 0600 file, not in the config), over
# TLS (`ca_file` for a private CA); an empty username means anonymous.
virtkit registry push ./bundle-dir runner:20260625
virtkit registry pull runner:20260625
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

Runs each CI job in a throwaway microVM. Wire up in
`/etc/gitlab-runner/config.toml`:

```toml
[[runners]]
  [runners.custom]
    config_exec   = "/usr/local/bin/virtkit"
    config_args   = ["gitlab", "config"]
    prepare_exec  = "/usr/local/bin/virtkit"
    prepare_args  = ["gitlab", "prepare"]
    run_exec      = "/usr/local/bin/virtkit"
    run_args      = ["gitlab", "run"]
    cleanup_exec  = "/usr/local/bin/virtkit"
    cleanup_args  = ["gitlab", "cleanup"]
```

Minimal `config.toml`:

```toml
state_dir = "/var/lib/virtkit"

[local]
# baked guest bundles live under <dir>/<name>/; the default guest is local/default
dir = "/usr/local/lib/virtkit/images"
generic_kernel = "/usr/local/lib/virtkit/vmlinux"

[net]
mode = "pool"
tap_prefix = "civtap"
count = 32
subnet = "192.168.231.0/24"
```

Manual smoke test (no gitlab-runner):

```sh
export VIRTKIT_CONFIG=/path/to/config.toml VM_JOB_ID=smoke
virtkit gitlab prepare                     # boots the VM, waits for the agent
printf 'echo hello from $(hostname); id\n' > /tmp/stage.sh
virtkit gitlab run /tmp/stage.sh build_script
virtkit gitlab cleanup                     # ACPI poweroff → kill, removes state
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
- `registry/<name>[:tag|@sha256:…]` — a bundle in the `[registry]` repo, pulled+cached
  natively with content-defined chunk dedup (CDC + per-chunk zstd).
- `docker/<name>[:tag|@sha256:…]` — an on-demand `[convert]` conversion of a docker
  image (see below).

```yaml
my-job:
  variables:
    MICROVM_IMAGE: registry/myimage     # :tag (default latest) or @sha256:…
```

With `[convert]` configured, `MICROVM_IMAGE: docker/<name>[:tag|@sha256:…]`
boots a Docker image on demand: the executor resolves the tag, pulls the image
through the host daemon, and streams it into a sparse ext4 (injecting
`virtkit-agent` as PID 1). Conversions are cached and GC'd; staleness is a
UUID compare against the build fingerprint.
