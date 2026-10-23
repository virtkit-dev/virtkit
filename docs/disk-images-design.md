# Disk images: installed guests and captured services

Status: proposal. Nothing below is implemented.

Two CI needs, one mechanism:

- **A. A provisioned service, reused within its pipeline.** A job boots an appliance as a
  compose service and provisions it (package install, first-boot initialization: minutes).
  Later jobs of the same pipeline start from that state instead of provisioning again.
- **B. Installed systems, cached across pipelines.** An appliance installed from its ISO by
  the distribution's own installer (for instance an older release, the base of an upgrade
  test) is built once, kept, and booted in seconds by any later pipeline.

Both end with a guest disk frozen into a bundle and published to the registry. They differ
in where the disk comes from (a running service, an installer) and in the bundle's scope and
lifetime (one pipeline, or every pipeline until gc).

## What exists

- **UEFI bundles.** `vk run <bundle>` boots a whole disk through the embedded firmware and
  the disk's own boot loader (`uefi.rs`). After the boot, everything assumes Windows:
  readiness is a registry query, `exec` and provisioning go through qemu-ga as SYSTEM, a tap
  address is set with Windows commands. The VM spec has no vsock port.
- **Installs from an ISO, as a Dockerfile.** `FROM winiso:` installs Windows from its ISO
  under vk (`winiso.rs`): an install medium built in a helper VM, Setup on virtio disks, a
  settle boot. Each `RUN`/`COPY` is a qcow2 layer over the previous one, cached by its parent
  and the instruction (`winbuild.rs`), and shared through the build cache registry as
  content-defined chunks, pushed as a diff over the parent's chunks and pulled lazily
  (`wincache.rs`). A host building a layer holds the registry's build lock on its key; the
  others wait for its push, up to `LOCK_WAIT` (3 h), then build it themselves.
- **Linux services** are OCI images on a single ext4 root, booted with vk's kernel or the
  image's (`kernel: image`), vk-agent as preinit (`fullvm.rs`). The writable root is a qcow2
  overlay. A registry push reads a captured qcow2 overlay's changed regions directly and
  reuses its parent's chunks (`registry.rs`, the diff push of a build stage).
- **Snapshots** (`snapshot.rs`) save a UEFI VM's memory, devices and disks. Linux OCI
  services have none.
- **Registry references.** `MICROVM_IMAGE=virtkit/<name>[:tag|@digest]` resolves in the
  host-configured `[registry] repo`; the name and reference are job-controlled
  (`image.rs`). `vk registry put --ttl|--keep` gives files a lifetime; tags expire under
  `vk-registry gc`'s retention.

An installed Debian-based appliance is a partitioned disk: ESP, LVM, btrfs subvolumes,
optionally LUKS, its own GRUB, kernel and initramfs. Only the UEFI path boots it as it is,
through its boot loader, which an upgrade test must exercise anyway (upgrades replace the
kernel and GRUB).

## Design

### 1. vk-agent in disk guests

A Linux disk guest runs vk-agent, as OCI guests do; qemu-ga stays the Windows agent.

- **The binary comes from the host at every boot.** vk attaches a small read-only virtio-blk
  disk labelled `VKAGENT` holding the vk-agent of the running vk. The image only holds a
  launcher: a systemd unit that waits (bounded) for the labelled device, mounts it read-only
  and runs `vk-agent` on vsock. The agent always matches the host's protocol, and the image
  carries no binary to update. A disk rather than virtio-fs: older appliance kernels (4.19)
  predate virtio-fs; they need `virtio_blk`, `virtio_pci` and `vmw_vsock_virtio_transport`
  (checked by the prototype, phase 0).
- **The bundle names its agent.** `vm.json` gains `"agent": "vk-agent" | "qemu-ga"`
  (default `qemu-ga`, today's bundles). With `vk-agent`, the UEFI path adds the agent's
  vsock port and the agent disk to the VM spec, and everything after the boot is the OCI
  path's: readiness is the agent answering, `exec`, `cp`, `vk-agent exec --service`, compose
  healthchecks and stop go through vk-agent. Shutdown presses the ACPI button, then asks the
  agent for a poweroff after `BUTTON_GRACE`, as the UEFI path does with qemu-ga today.
- **Agent ready is not appliance ready.** The agent answers early in the boot; compose
  `healthcheck:` and `depends_on: condition: service_healthy` express the appliance's own
  readiness.
- The launcher records the agent version it ran in the guest's journal, so a run is
  traceable to its toolchain.

### 2. `FROM debiso:` — Debian-installer images as a Dockerfile

```dockerfile
# vk: cpus=4 mem=4G disk=40G
FROM debiso:bastion-10.0.6.iso@sha256:<digest> --boot-args="wabsetup/devel=1" AS installed
RUN /usr/local/sbin/ci-setup.sh
COPY ci-config.json /etc/appliance/
CMD /usr/local/sbin/ci-provision.sh
```

The stage follows `winiso:`; only the medium and the install differ.

1. **Medium.** libkrun has no ATAPI or CD-ROM: the ISO becomes a disk. A helper VM (xorriso,
   cpio) extracts the ISO, patches the boot loader configuration of its UEFI entry (default
   entry, `--boot-args`, `console=ttyS0`, a power-off at the end), and appends a cpio archive
   to the installer's initrd (the kernel concatenates initramfs archives). The archive holds:
   - a `debian-installer-startup.d` hook that finds the medium on virtio-blk by its ISO
     volume label and mounts it at `/cdrom`, ahead of `cdrom-detect`, whose device list
     and USB probe do not reliably cover `/dev/vd*`;
   - a `finish-install.d` hook that installs the vk-agent launcher (§1) into `/target`,
     and writes an install-success marker there;
   - optionally, a preseed fragment pinning the target disk. An installer that picks the
     largest disk (as the Bastion's `partman.sh` does) needs the target disk to be the
     largest; vk makes the target at least one GiB larger than the medium, and says so when
     `disk=` is too small.

   The medium is cached by the ISO's digest, the boot args, the hooks' content and the
   helper's Dockerfile, as `winiso`'s key includes its scripts and helper.
2. **Install.** A UEFI VM boots the medium: disk0 the empty target (`disk=`), disk1 the
   medium, read-only. The run lasts until the installer powers off, bounded by a timeout,
   the serial console streamed to the build output and kept with the failed build's logs.
   A power-off is not a success: the build then checks the install-success marker on the
   target, then boots the target **without the medium** until vk-agent answers. Only then is
   the install published as the stage's base layer, with its UEFI variable store (the boot
   entry the installer wrote) as the template every run copies privately. Cached by the
   medium's key and the disk size.
3. **Layers.** `RUN` and `COPY` run through vk-agent (`/bin/sh -c`, as root), each a qcow2
   layer cached by its parent and the instruction (environment, working directory, copied
   content), pushed and pulled as `wincache` does. `CMD` is the provisioning a compose
   service runs at each start. `--network` behaves as on Windows steps.
4. **Result.** A bundle (`vm.json` with `"agent": "vk-agent"`): `vk run`, a compose service's
   `image:`/`build:`, `FROM` in another Dockerfile, or `vk registry push` under a tag.

The cache across pipelines comes from the build cache registry. The build lock makes
concurrent builders wait for one install; past `LOCK_WAIT`, two may install, and the second
push is the same key's content again, which is harmless.

Licences and secrets stay out of cached layers: the `CMD` provisioning or the consuming job
injects them at run time.

A `debiso:` or `winiso:` image shared across projects is built as a signed recipe by a
builder node, and trusted through its provenance ([the trust model](trust-model.md)).

### 3. Service capture, scoped to a pipeline

A CI job captures a stopped compose service's disk as a bundle:

```sh
vk-agent service commit cypress-runner --as runner    # in the job VM
```

- **Host side.** The request goes over the job's host command channel, so the executor does
  the work: it asks the service's guest for a clean power-off, waits for the VMM to exit (a
  timeout or a kill fails the commit), then pushes the root overlay as a diff over the
  service image's chunks (the build stage's diff push: no flatten), together with the boot
  descriptor the service ran with (kernel, init, cmdline for an OCI service; firmware,
  agent and UEFI variables for a disk guest).
- **Scope.** `pipeline/<name>` is a reference the executor resolves from the job's own
  identity as the node received it, never from the guest. A pipeline's captures live in
  its pipeline namespace, laid out as in
  [the registry hub design](registry-hub.md#4c-pipeline-caches-and-captures):
  `ci-pipeline/<gitlab>/<project id>/<pipeline id>/services/<name>`. Where the identity
  and the credential come from depends on how the job reached the node:
  - **Placed by the hub.** The job's start names its pipeline namespace, and the push uses
    the job's registry token, which only reaches that pipeline's namespace and those the
    hub grants it. The registry enforces the isolation on pushes. Pulls keep the node's
    credential until image pulls use the job's token; until then, the resolver is a
    consumer's only guard.
  - **Run by gitlab-runner, without a hub.** The executor builds the same path under its
    `[registry] repo` and pushes with the node's credential. It takes the GitLab URL from
    the runner's config and the project ID from the job response, never from
    `CUSTOM_ENV_CI_SERVER_URL` or `CUSTOM_ENV_CI_PROJECT_ID`, which a pipeline's own
    variables can override. The pipeline ID comes only from `CUSTOM_ENV_CI_PIPELINE_ID`,
    which they can override too, and cannot be verified off the hub. The isolation is then
    the executor's alone: it holds between projects, and is best effort between pipelines
    of one project.

  In both cases the resolver refuses any reference into `ci-pipeline/` written directly,
  by tag or by digest, so a job reaches captures only through `pipeline/`, and another
  pipeline's are out of reach within the limits above.
- **Publication** is atomic and immutable per job: the commit pushes under the tag
  `job-<job id>` and moves the tag `current`, which `pipeline/<name>` names, last. A retried
  producer job publishes a new capture; consumers started before see the old one whole.
- **Lifetime.** Captures expire when they sit idle past the registry's window for
  `ci-pipeline` (2 days by default, `[[gc.prefix]]` in the registry's config, which the hub
  may lengthen), and go with gc; a job that boots one keeps it alive. A job starting after
  expiry fails with a message naming the producer job to rerun.
- **Consumers** name it like any bundle: `image: virtkit/pipeline/runner` in a compose
  service, or `MICROVM_IMAGE`.

What makes a captured state valid to reboot belongs to the image, not to vk: a one-off
provisioning step separate from a per-boot adaptation (addresses, DNS, keys handed to the
job), services stopped in order before the power-off, and in-memory state (a Redis without
persistence, queued work) dealt with explicitly. vk documents this contract; it does not
guess it.

Publication is shared by §2 and §3; boot descriptors stay per kind. A captured
OCI service stays OCI-booted: capture does not turn it into a UEFI appliance.

## Plan

Each phase ships on its own.

| Phase | Content | Done when |
| --- | --- | --- |
| 0 | Prototype by hand: the oldest ISO to support, medium as virtio-blk, startup and finish-install hooks, install, boot without medium | an old release installs and reboots on its own under vk; the modules it lacks, if any, are known |
| 1 | vk-agent in disk guests: agent disk, launcher, `"agent"` in `vm.json`, vsock in the UEFI spec, readiness/exec/stop through the agent | `vk run`, `vk exec` and a compose service work on a bundle from phase 0, with reboots |
| 2 | Capture and publication: stopped-disk capture, diff push with the boot descriptor, atomic tag move | `vk` captures a stopped run into a bundle that boots the same |
| 3 | Pipeline scope: `vk-agent service commit`, `pipeline/` resolution and refusal of `ci-pipeline/`, the registry's window on `ci-pipeline`, the expiry message; under the hub, the job's token (registry hub step 4c) | two jobs of one pipeline share a capture; a job of another project cannot reach it, with or without the hub, nor, under the hub, one of another pipeline |
| 4 | `FROM debiso:`: medium, install, success checks, layers through vk-agent, cache keys | the phase 0 image builds from a Dockerfile, cached across hosts |
| 5 | Measure: capture size and push time after a chatty initialization; boot time of a capture | numbers recorded here; memory snapshots of disk guests only if boot time warrants them |

## Alternatives considered

- **qemu-ga in Linux guests.** It is what the UEFI path speaks today and many appliances
  install it, but it is a second agent with its own exec and file semantics, and older
  releases may lack it.
- **vk-agent baked into the image.** Simpler launcher, but every cached layer pins an agent
  version, which drifts from the host's.
- **vk-agent fetched over vsock by a stub.** A download protocol of its own, depending on the
  same transport the disk provides.
- **Installing with packer and qemu, then importing.** Reuses existing templates, but the
  disk changes bus between install and run (virtio-scsi to virtio-blk), the firmware's
  variable store stays behind, and every host needs qemu and OVMF.
- **Direct kernel boot of an installed disk.** Skips GRUB, which an upgrade test needs, and
  the preinit would have to assemble LVM, btrfs and LUKS.
- **A tar of the service root as a GitLab artifact.** Gigabytes through the agent and the
  artifact store, no chunk reuse with the base image.
- **Memory snapshots of the service.** Saves the appliance's service start, at the cost of
  snapshot support on the OCI path (vsock state, virtio-fs, clock). Revisited after phase 5.

## Open questions

- The oldest release to support, and so the oldest installer kernel and initrd (phase 0).
- Whether the capture's boot descriptor needs the base image's digest only, or the
  materialized disk's identity as well, when the base image is rebuilt with equal content.
- Retention of `debiso:` layers on CI hosts: the Windows layers' idle sweep
  (`windows_cache_idle_secs`) or the build cache's gc.
