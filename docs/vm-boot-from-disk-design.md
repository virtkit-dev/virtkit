# Booting an OCI-seeded VM from its persistent disk

**Status:** Experimental `vk run --boot-disk` implements part of phase 1 for x86-64 Linux
guests. Compose `boot: disk` remains proposed.

**Source baseline:** virtkit release 0.113.1, plus ext2 block-map support in
`vk-driver/src/ext4_read.rs`. Paths refer to virtkit. The target is an appliance installed from
a Debian ISO. The interfaces and disk formats proposed below are new.

## Decision

Add an opt-in `boot: disk` mode for a service with `persist_root: true`, `kernel: image`, and
`init: image`. The OCI image seeds the machine once. On every subsequent cold start or guest
reboot, vk reads a matched kernel and initrd from **that machine's own `/boot`**. A changed
image tag never replaces the disk. The acceptance test is an appliance that installs kernel B
while running A, requests a reboot from inside the guest, and comes back on B with the same
machine state and a working `vk exec`.

Use direct kernel boot in two phases. First support a GPT disk with an ext2 `/boot` and a
directly mountable btrfs root. Then let Debian's initramfs mount the root so the same boot
reader works with LVM and LUKS. In both phases the image kernel supplies btrfs, the host reads
only the boot partition, and vk retains its pre-systemd handoff. UEFI remains the appropriate
path for testing GRUB, firmware variables, Secure Boot, and bootloader repair.

## Current behavior

Changing the disk passed to `fullvm::prepare` leaves disk lifetime and guest reboot unchanged.

| Boundary | Behavior at the source baseline |
|---|---|
| Boot source | The primary builds or locates the image ext4, calls `fullvm::prepare(&ext4, ...)`, then chooses the persistent disk. A sibling chooses its writable disk but still calls `prepare(&svc.ext4, ...)`. `prepare` requires exactly one `/lib/modules/<release>` directory. For an image kernel it reads `vmlinuz` and `modules.dep`, decompresses the kernel to ELF if necessary, and gathers boot modules. A normal two-kernel upgrade violates that selection rule. `vk-driver/src/run.rs:1907`, `vk-driver/src/run.rs:1956`, `vk-driver/src/units.rs:511`, `vk-driver/src/units.rs:540`, `vk-driver/src/fullvm.rs:88`, `vk-driver/src/fullvm.rs:152`, `vk-driver/src/fullvm.rs:208` |
| Disk lifetime | `ensure_persist_root` materializes a standalone qcow2. A missing or mismatched `.baseid` causes removal and re-materialization. Creation also applies a whole-filesystem ext4 journal fix-up. A partitioned disk needs its own creation path, and a machine upgraded in place needs a different lifetime policy. `vk-driver/src/compose.rs:1892`, `vk-driver/src/compose.rs:1904`, `vk-driver/src/compose.rs:1931` |
| Guest reboot | Both primary and sibling enable in-place reboot. The keeper reaps the old VMM and forks a new child with the same `VmSpec`. Each child reopens the kernel and initramfs at the paths in that spec. Resolving `/boot` only during `vk run` or compose startup would therefore still boot A after an in-guest upgrade to B. `vk-driver/src/run.rs:2731`, `vk-driver/src/units.rs:816`, `vk-driver/src/libkrun_sys.rs:338`, `vk-driver/src/libkrun_sys.rs:635`, `vk-driver/src/libkrun_sys.rs:693` |

Today vk writes the agent as `/init`, raw `.ko` files, the ordered `/virtkit-modules` list, and
optional boot JSON into a cpio. The agent reads the config before pivot, loads the modules, and
mounts `VIRTKIT_PIVOT=/dev/vda` as ext4. In the real root it establishes `/proc`, `/dev`, and
`/sys`, sets the hostname and environment, claims `/run` when needed, mounts shares and disk
volumes, configures networking, and starts the requested services and vsock exec server. For
`init: image` it waits for the server to report that it is listening. If it cannot create the
handoff link, it can proceed unreported only when no `prepare` is requested. The agent runs
any `prepare`, applies `root: ro` if requested, and execs `init_argv` or `/sbin/init`. A failed
handoff leaves the guest available for inspection when exec is running.
`vk-driver/src/initramfs.rs:62`, `vk-driver/src/run.rs:1983`,
`vk-agent/src/init.rs:154`, `vk-agent/src/init.rs:313`, `vk-agent/src/init.rs:377`,
`vk-agent/src/init.rs:419`, `vk-agent/src/init.rs:496`, `vk-agent/src/init.rs:671`,
`vk-agent/src/init.rs:736`.

The btrfs prototype pairs `tools/btrfs-root` with `vk run --root-image`.
With `--kernel image`, vk substitutes the raw root **after** obtaining the kernel and modules
from the image ext4, and the agent probes the root superblock and mounts the detected type. The
converter mounts the source ext4 in a guest and runs `mkfs.btrfs --rootdir` without mounting
the destination; it derives filesystem and device IDs from the input, seeds other UUID
generation, and freezes the clock. It builds a flat filesystem from a moving Debian tag and
package repository, so the proposed partitioned seed needs its own reproducibility test. A
systemd boot on its btrfs root is unverified. The pinned kernel is built from an
`allnoconfig`-based fragment with ext4 and ext2 support. This design requires no btrfs addition
to that fragment. `kernel/Dockerfile:85`, `kernel/kernel-fragment.config:274`.

## Appliance contract

| Component | Source requirement |
|---|---|
| Partitioning | GPT, with LVM VG `vg00` on LUKS, or on a plain PV. A BIOS GRUB partition, a small vfat ESP at `/boot/efi`, and an ext2 `/boot` of a few hundred MB outside the PV. |
| Root and data | `lvroot` holds btrfs. `@rootfs`, `@homefs`, `@roothomefs`, `@varfs`, and `@logfs` mount at `/`, `/home`, `/root`, `/var`, and `/var/log`. The installer mounts `/var` before `/var/log` and `/var/data`, sets per-mount restrictions in fstab, uses `lvswap` for swap, and mounts ext4 `lvdata` at `/var/data`. |
| Unlock and boot files | The LUKS key is a file on `/boot`, named in crypttab with `passdev` and the boot filesystem's UUID, for unattended unlock. Each `vmlinuz-<release>` from `linux-image-amd64` has its `initrd.img-<release>`, and GRUB is installed for BIOS and EFI. |
| Upgrade | The machine upgrades itself with apt and asks for a reboot; the newest installed kernel, by version sort, is the one it expects to run next. Old kernels get removed to keep `/boot` from filling, so an older working pair cannot be assumed to exist. |

An OCI-built image of such a machine differs from an ISO installation in ways the seed builder
must address. Its compose service may use `prepare`, explicit systemd arguments, `root: ro`, a
read-only workspace share, and a separate qcow2 volume at `/var/data`. The image may lack
`initramfs-tools` and `cryptsetup-initramfs`, and its setup may regenerate fstab from the
running machine's mounts. A builder must verify the actual initrd and effective mount
configuration. Installing a kernel package alone is insufficient.

## Boot options

Boot-time estimates reflect the stages each path runs. Timings are unmeasured.

| Path | Kernel updates and layout fidelity | Handoff, cost, and recovery |
|---|---|---|
| **A. Direct kernel, distro initrd followed by vk cpio** | Read the installed pair from ext2 on each boot. Preserve the distro archive and append vk's `/init`. The distro modules are available to vk's `/init`. The distro root discovery scripts do not run. The agent can mount a known btrfs partition and named subvolumes. Supporting LUKS/LVM here would require another implementation of appliance boot policy. | Closest to today's handoff and one kernel start. Adds qcow2/GPT/ext2 reads, kernel extraction, and loading a potentially much larger initrd. An explicit pair and deterministic cpio give an auditable boot input. The host processes guest-controlled metadata and kernel bytes. A missing driver or unusable pair can fail before vsock exists. |
| **B. Direct kernel, distro `/init`, vk handoff hook** | Use the same pair and boot reader. Debian scripts perform device discovery, unlock, VG activation, and root mount with `subvol=@rootfs`. The agent keeps PID 1 while Debian's child process reports the mounted root through a late hook. This exercises the installed initramfs on every upgrade. | Retains the full handoff if the hook runs before systemd. One kernel start plus distro discovery and unlock time. Adds a versioned guest integration and dependency on initrd regeneration. A missing hook, bad crypttab, or missing key can prevent handoff. Host parsing and fallback are shared with A. |
| **C. Pinned-kernel loader followed by kexec** | Boot a small vk guest, read `/boot` there, then start the installed kernel and initrd with the final command line. A separate ext2 `/boot` keeps btrfs out of the loader. The second kernel can use A or B for root. | Moves GPT/ext2 and payload interpretation into the guest. The VMM still exposes the qcow2 block device. Costs a loader boot, a second kernel transition, and an additional pinned component. Shares, networking, exec, `prepare`, remount, and status must belong to the final kernel. kexec support in the effective pinned configuration and reliable device reinitialization under libkrun are **unverified**. Recovery needs a host deadline across both stages. |
| **D. UEFI firmware and GRUB from disk** | Firmware loads the guest bootloader. The guest owns GRUB defaults, saved entries, kernel command line, and initrd selection. This is the path that can test an appliance upgrade which also changes the bootloader. No host GPT, ext2, LVM, or kernel extraction is needed for selection. | Firmware, GRUB, and distro initialization add stages. Reproducing a boot requires the disk, firmware, and variable store. A damaged ESP, missing boot entry, bad GRUB configuration, or bad default needs firmware/GRUB recovery. The present UEFI spec starts with no shares, vsock ports, or initramfs and uses qemu-ga. A Linux pre-init integration and dynamic vk configuration transport are still needed for this compose contract. `vk-driver/src/uefi.rs:31`, `vk-driver/src/uefi.rs:399`, `vk-driver/src/uefi.rs:609` |

Choose A for the first deliverable and B for appliance storage fidelity. The existing
disk-image design proposes UEFI for installed appliances and a systemd launcher for a
host-supplied agent. A service first starting under
systemd cannot run the existing `prepare` before systemd takes PID 1. Share the Linux guest
control work where possible and keep a firmware-boot test for GRUB upgrades.
`docs/disk-images-design.md:42`, `docs/disk-images-design.md:54`.

With `vk build --disk`, a Dockerfile stage partitions the disk and installs a bootloader
(`docs/appliance.md:3`). The proposed seed builder uses its own recipe for the btrfs subvolume
tree, layout version, and IDs derived from the seed digest. The disk build leaves that layout
to the Dockerfile.

## Phase 1 — Boot a persistent btrfs machine

### Surface and ownership

Proposed compose spelling for a new machine:

```yaml
services:
  appliance:
    image: appliance-runner
    x-virtkit:
      persist_root: true
      boot: disk
      disk_layout: btrfs
      kernel: image
      init: image
      prepare: [/root/prepare.sh]
      init_argv: [/lib/systemd/systemd, --system, --unit=multi-user.target]
      root: ro
```

`boot: disk` selects seed-once persistence and disk kernel discovery together. `kernel: image`
names the guest's kernel family. Its installed version comes from the disk. Existing compose
files keep their `.baseid` behavior. For `vk run --primary`, use the same service state as
compose. For standalone use, propose `vk run --boot disk --state-dir DIR --disk-layout btrfs
--kernel image --init image IMAGE`. Require an explicit machine state directory outside
compose. Reject throwaway roots, RAM boots, incompatible kernel/init axes, and two owners for
one disk. The prototype's `--root-image` alone has different kernel-selection semantics.

On first creation, record seed digest, layout version, disk identity, boot partition identity,
and the OCI runtime defaults needed for later handoffs. Publish the complete state directory
atomically after syncing the seed disk and metadata. Acquire an exclusive machine lock before
inspection or creation and retain it across reset and VMM lifetime. Subsequent starts must work
with the seed evicted or the registry offline. Apply current compose overrides to the recorded
defaults. Display a changed seed digest when known. Only an explicit offline reseed may replace
the disk. Refuse automatic adoption of an existing `.baseid` root or a disk with missing
identity metadata, and preserve it for migration or recovery. Today's managed name is
`<anchor>/roots/<service>.qcow2`. `vk-driver/src/compose.rs:1821`.

### Build the seed

1. Resolve the OCI input by digest. Reuse the existing merged OCI-to-ext4 path or a Dockerfile
   build's ext4 as a read-only staging input. Build the whole disk in a disposable helper VM.
   Keep host loop devices, mounts, and device mapper out of the workflow.
   `vk-driver/src/run.rs:1909`.
2. Create aligned GPT partitions for BIOS GRUB, the ESP, ext2 `/boot`, and a plain btrfs root.
   Populate `/boot` and `/boot/efi` separately, leaving empty mountpoints underneath. Fix
   partition sizes in the versioned layout. Check that the boot partition can hold the
   supported upgrade pair and the appliance's required free-space margin. Phase 1 can keep the
   runner's existing `/var/data` volume. The layout with `vg00`, swap, and `lvdata` belongs to
   phase 2.
3. Stage **sibling directories** `@rootfs`, `@homefs`, `@roothomefs`, `@varfs`, and `@logfs`.
   Place each subtree's contents in its destination once. In particular, `@varfs/log` and
   `@varfs/data` are mountpoints. Preserve numeric owners, modes, symlinks, capabilities,
   xattrs, and hardlinks within each destination. Report hardlinks that would cross filesystems
   or subvolumes. Pin a `btrfs-progs` version whose `--subvol` accepts `default:` and `rw:`.
   Version 6.14 supports both. The prototype installs the distribution package without a
   version pin. The directories must already exist in `--rootdir`.
   [mkfs.btrfs options](https://btrfs.readthedocs.io/en/stable/mkfs.btrfs.html)

   ```sh
   mkfs.btrfs --rootdir "$tree" \
       --subvol default:@rootfs --subvol rw:@homefs \
       --subvol rw:@roothomefs --subvol rw:@varfs \
       --subvol rw:@logfs "$root_partition"
   ```

4. Write a matching fstab with stable device identities, explicit subvolumes, and appliance
   mount flags. Install the initramfs tooling and persistent module configuration required by
   this layout. Generate the initial distro initrd with the final boot tree in place. Validate
   the pair, module loader, and drivers before publishing. An OCI runner whose image lacks
   these inputs needs a disk-capable build target. Keep dependency installation pinned and
   outside the start path.
5. Pin the converter image, tools, filesystem features, ordering, sector size, geometry,
   timestamps, UUID inputs, and initrd compression. Derive each nonsecret ID from the seed
   digest, layout version, and object role. Compare logical disk hashes from two independent
   builds and verify the populated trees before promising reproducibility. Apply qcow2
   materialization to the **whole disk**, skipping the current ext4-at-offset-zero journal
   edit. Byte reproducibility applies to the distributable seed. A live machine may change on
   its first boot.

### Resolve `/boot` before each VMM launch

Use one resolver for the primary, siblings, cold starts, guest resets, and host-requested hard
resets. Pass the keeper a machine disk reference, boot policy, and current handoff config. For
each fresh launch, after the previous VMM has exited and released the disk, resolve a new
payload and construct that attempt's `VmSpec`. Keep payload files or sealed descriptors private
and alive for that attempt. Preserve the keeper's stop precedence and reboot-storm guard. A
memory restore, if supported later, must resume its original state and resolve again only on
the next fresh boot. `vk-driver/src/libkrun_sys.rs:627`, `vk-driver/src/libkrun_sys.rs:650`,
`vk-driver/src/libkrun_sys.rs:706`.

**Selection rule.** For the Debian amd64 profile, enumerate regular files named
`vmlinuz-<release>` and `initrd.img-<release>` in the root of the designated boot filesystem.
Require an exact release match and a supported flavor. Choose the newest complete pair using
the appliance's version ordering, with the C locale and a defined tie policy. Reject ambiguous
flavors. Report a newer incomplete release as an interrupted update, including which file is
missing. Allow a one-boot explicit release override for recovery. Ignore the `/vmlinuz` and
`/initrd.img` symlinks in `/` of the root filesystem, which would require opening it. GRUB's
selected entry is authoritative only on the firmware path. Version selection must handle ABI
`9` versus `10`, and two different initrds for the same release.

A matching filename alone cannot establish that package installation finished. Have the seed
install a final boot-file hook that atomically publishes the release and hashes of the
completed pair on `/boot`, after successful initrd generation. Refresh it on same-release
rebuild and retire it on removal. Seed the first records during conversion. For managed disks
require a matching completion record for eligibility. Report a torn write, missing record, or
stale digest. Any earlier pair still on disk with a matching record remains eligible. The
guest controls these hashes, which identify the bytes across an interrupted update.

**Reader boundary.** Read `standalone qcow2 → bounded logical disk → GPT partition slice → ext2
regular files`. Identify the boot partition by its recorded GPT partition UUID and check its
expected filesystem identity. No scan of `/dev/mapper`, btrfs tree, encrypted PV, or ESP is
needed. The existing qcow2 reader exposes logical reads with sparse zero handling. Its ordinary
opener also resolves backing filenames. The ext reader recognizes raw and qcow2 images and
assumes the filesystem starts at zero. It now reads `mke2fs` geometries (1, 2 or 4 KiB blocks,
128-byte inodes and up, 64-bit descriptors) and ext2 block maps through triple indirection,
holes included, and checks every block pointer against the filesystem size; its tests run
against real `mke2fs -t ext2` images. A partition-offset view (the GPT slice) and the budgets
below remain to add. `vk-driver/src/qcow2.rs:101`, `vk-driver/src/qcow2.rs:115`,
`vk-driver/src/qcow2.rs:167`, `vk-driver/src/ext4_read.rs`.

The trust boundary begins at the opened disk. A guest can rewrite its GPT, filesystem, kernel,
and initrd. A damaged or imported container can also contain unexpected qcow2 metadata. Specify
the following constraints before exposing disk boot:

- Open the owner's disk read-only for discovery under the machine lock. Admit only the
  standalone qcow2 subset vk creates. Reject backing references **before** any pathname
  resolution, external data files, unsupported feature bits, and unsupported clusters. Bound
  virtual size, table allocations, cached L2 tables, and total reads. Use checked offset
  arithmetic at every layer.
- Validate GPT header and entry-array checksums, sector bounds, nonoverlap, and uniqueness of
  the selected partition. Give the filesystem reader only that partition's byte range. Check
  ext superblock geometry, supported features, inode and block references, directory records,
  and indirect-block traversal against both the partition and a work budget. Refuse
  inconsistent metadata. Recovery or fsck is an explicit offline action.
- Open fixed regular filenames inside the boot filesystem. Reject symlinks, path separators in
  release names, device nodes, and excessive directory or record sizes. Never unpack the distro
  archive on the host. Bound the stored kernel, decompressed ELF, initrd, decoder work, and
  total payload relative to guest RAM; libkrun places the initrd below the end of RAM or the
  MMIO gap, whichever is lower, which bounds its size. Validate ELF architecture, load segments
  and address ranges before handing it to libkrun. Existing limits include 256 MiB for the
  kernel and 16 decompression candidates. `vk-driver/src/fullvm.rs:169`,
  `third_party/libkrun/src/arch/src/x86_64/mod.rs:206`.
- Run discovery and decompression in a restricted helper with preopened input and output
  descriptors, no network, no ambient filesystem access, and CPU, memory, time, and output
  limits. A disposable reader VM with a read-only disk and a bounded output channel is an
  alternative if the native reader cannot meet those limits. Its kernel can read ext2 without
  accessing btrfs. Include its extra boot in performance measurements. In either case, validate
  the returned payload at the VMM boundary. Keep initrds and diagnostics private because they
  may carry unlock material.

### Assemble the phase 1 initramfs and hand off

Preserve the complete distro initrd byte stream, including any leading early archive. Append
zero padding to a four-byte boundary and a separately terminated `newc` archive containing vk's
executable `/init` and this boot's config. Verify on every supported kernel that the final
regular `/init` wins. The Linux format permits multiple compressed and uncompressed members.
The selected kernel must support the distro member's compression. [Linux initramfs buffer
format](https://www.kernel.org/doc/html/v6.18/driver-api/early-userspace/buffer-format.html)

The distro initrd supplies **files**, not a running module loader. Today vk passes raw module
files to `finit_module` in its own load order and logs failures. For this path, have the seed's
initramfs-tools configuration include a working `modprobe`, dependency indexes, and the closure
for virtio PCI/block, btrfs, ext2/vfat, vsock, and the enabled net/virtiofs features. Have vk's
`/init` invoke that loader inside the guest against the **running** release. Check required
devices, mounts, and transports before handoff. Reapply the inclusion rules on every
`update-initramfs`. Never borrow a `.ko` from the OCI seed or infer that a missing module is
built in. `vk-driver/src/fullvm.rs:21`, `vk-driver/src/fullvm.rs:100`,
`vk-agent/src/init.rs:881`.

vk supplies the kernel command line. Replace `VIRTKIT_PIVOT=/dev/vda` with the root
partition's GPT UUID and `subvol=@rootfs`. Give the agent a bounded wait for the partition,
then mount `@rootfs` as writable btrfs for setup in place of the current ext4 mount.
Mount the sibling subvolumes, `/boot`, the ESP, and any required data filesystem in
parent-before-child order. **The same ext2 partition from which vk read the kernel must be
mounted at `/boot` before `prepare` or any package script runs.** Refuse a conflicting compose
volume or an unexpected existing mount. A package writing to a hidden `/boot` directory could
otherwise report a successful upgrade that vk never sees.

Continue through the existing post-pivot handoff code. Preserve the environment and `/run`,
shares, disk volumes, assigned network, exec and optional SSH/control services. Start exec
before `prepare`. Run `prepare` once per boot attempt on the writable real root with the final
mounts visible. Apply `root: ro` immediately before exec and preserve each child mount's
specified flags. Verify that remounting the btrfs root delivers the requested per-mount
behavior with writable sibling subvolumes. Fail the handoff if it cannot. `root: ro` describes
`/` **at handoff**. The appliance's systemd may subsequently remount it writable according to
fstab. Pass `init_argv` as an argument vector without shell interpretation.
`vk-agent/src/init.rs:424`, `vk-agent/src/init.rs:450`, `vk-agent/src/init.rs:529`,
`vk-agent/src/init.rs:645`, `tests/root-ro-e2e.sh`.

## Phase 2 — Let the appliance initramfs mount root

Keep the phase 1 boot reader and pair selection. Extend the seed layout to GPT → optional LUKS
→ LVM `vg00` → `lvroot`, `lvswap`, and `lvdata`, with the ext2 `/boot` and ESP outside that
stack. Build the PV, VG, LVs, and optional encrypted container in an isolated provisioning VM
that has the required device-mapper support. Populate `lvroot` with the same btrfs tree.
Populate ext4 `lvdata` with `/var/data` data and remove the external compose mount for this
profile. Write fstab and crypttab against the actual identities, then regenerate every
supported initrd.

Use a reproducible plaintext seed or recipe and personalize encrypted disks per machine with
fresh key material and salts. Deterministic UUID generation must never feed key generation.
Support the appliance's `/boot`-based `passdev` policy explicitly when fidelity requires it.
Anyone with a copy of such a disk can also read its boot-stored unlock material. Keep it out of
shared seed caches, logs, and command lines. Installer-time secrets must not become shared VM
credentials.

Keep the agent as PID 1 and let it run the distro `/init` as its child for discovery. Append
vk's agent and boot config at reserved paths, leaving `/init` intact. Install a versioned
initramfs-tools build hook in the guest so kernel upgrades preserve the needed modules and
cryptsetup/LVM tooling. Pass the distro its `root=`, `rootfstype=btrfs`, and
`rootflags=subvol=@rootfs`. Carry vk's final read-only handoff request separately so distro
discovery can yield a writable mount for `prepare`.

A concrete integration point is Debian's final `run-init`. vk's appended archive replaces the
initrd's `run-init` with a stand-in, so when the distro `/init` execs it on the mounted root,
the stand-in names that root to the agent instead of exec'ing an init, and `/init` ends. The
agent, still PID 1, moves into that **already mounted** root, verifies it, mounts the remaining
appliance filesystems, and runs the shared handoff code. Reuse the moved `/run`, `/dev`,
`/proc`, and `/sys`. Replacing `/run` would hide the config and could lose distro boot state.
Debian's implementation tries other init programs if its requested init fails validation. The
managed integration must fail closed before that fallback can bypass `prepare` or the read-only
handoff. Test this with a missing agent and a missing stand-in, including an initrd regenerated
by an actual package upgrade. [Debian initramfs-tools 0.142+deb12u3,
`init`](https://sources.debian.org/src/initramfs-tools/0.142%2Bdeb12u3/init/)

## Failure, fallback, and observability

Record each attempt in host-owned machine state before boot. Include a boot generation,
selected release, pair digests, layout, and reason for selection. Retain the serial log and a
bounded failure reason. Bind guest status to the current generation so a stale socket or
response cannot confirm a new kernel. Expose the selected and running releases, trial outcome,
and any fallback in `vk status`.

Use the existing `handoff:pending`, `handoff:done`, and `handoff:failed` meanings. `done`
represents the image init taking PID 1. The exec server tracks the pre-exec report and closure
of the close-on-exec link. A listening server by itself is too early to promote a kernel.
Confirm a trial only after the current generation reports `done` and the expected `uname -r`.
An appliance health check may raise this success threshold. `vk-core/src/messages.rs:282`,
`vk-agent/src/handoff.rs:89`, `vk-agent/src/handoff.rs:151`.

| Outcome | Proposed action |
|---|---|
| New pair fails extraction, panics, resets early, or exceeds the early-boot deadline | Try the last confirmed release **once**, after the old VMM exits and only if its complete matching pair is still on disk. Record failure against the candidate digests so the same broken bytes are not retried at every start. A changed pair or explicit operator retry opens a new trial. |
| `prepare` started, the read-only remount failed, or `init_argv` could not exec | Preserve the inspectable failed guest and its exec channel when available. Report the existing handoff failure. Do not replay appliance setup automatically. For a reliable boundary, have the agent obtain a generation-specific host acknowledgement before entering `prepare`. The keeper records that point durably before acknowledging. |
| Operator stopped the machine, the keeper crashed, or the attempt stage is uncertain | Honor the stop. Record an interrupted attempt. Require an explicit retry when `prepare` may have run. A slow `prepare` with a live status channel must not expire the early-kernel watchdog. |
| First boot has no confirmed pair, the previous release was purged, both attempts fail, or the boot filesystem is unreadable | Stop with the disk intact, show the attempted releases and console evidence, and allow offline repair or an explicit one-boot selection. Never silently boot the seed kernel or replace the machine from OCI. |

Fallback changes the kernel/initrd pair for the next attempt on the **same disk**. It cannot
undo package migrations, restore removed `/lib/modules/<release>`, or guarantee that an older
kernel can mount a filesystem upgraded with new features. Full appliance rollback requires a
coordinated offline backup of the root and data disks. A successful fallback must remain
visible because the appliance's next upgrade checks whether the latest installed kernel is
running.

## Release gates and open questions

1. **Upgrade across both launch boundaries.** Seed a Debian fixture on A, install a pinned
   `linux-image` B through apt, and let its maintainer scripts rebuild `/boot`. Record the
   machine ID, boot ID, and a data marker. Trigger `systemctl reboot` inside the guest. Require
   a new boot ID, `uname -r=B`, matching installed modules, systemd as PID 1, successful
   handoff, usable shares/network/exec, and unchanged machine ID and data. Repeat through
   stop/start and compose down/up, for both primary and sibling. Change the seed digest and
   repeat with the registry unavailable. Legacy `persist_root` must still pass its
   reset-on-image-change test. `vk-driver/src/compose.rs:3427`.
2. **Btrfs and handoff.** Inspect mount IDs, sources, subvolume names, and flags in `prepare`
   and at PID 1 entry. Write markers under all five subvolumes and `/var/data`, then verify
   them after reboot. Check that `/boot` is the designated ext2 partition, the ESP is mounted,
   and `/var/log` and `/var/data` remain visible under the mounted `/var`. Exercise `root: ro`,
   a long and a failing `prepare`, exact `init_argv`, and stop during setup. Extend the
   behavior covered by `tests/root-ro-e2e.sh` and `tests/fullvm-compose-ctl-e2e.sh`. Test fstab
   regeneration by the appliance's setup as well as the initial fstab.
3. **Pair publication and recovery.** Exercise early microcode plus compressed initrd plus vk
   cpio, same-release initrd regeneration, missing modules, a truncated initrd, an interrupted
   package installation, and a kernel that never reaches vsock. Observe one fallback,
   digest-based suppression, and successful retry after repair. Remove the confirmed kernel,
   interrupt the keeper at each durable transition, and verify that no recovery path reseeds
   storage or runs a failed `prepare` twice.
4. **Reader and seed validation.** Extend the reader's `mke2fs` tests to the GPT-sliced reader
   and the budgets. Cover sparse qcow2 reads, bad GPT checksums and partition lengths,
   malformed directories, unsupported features, symlinks, allocation caps, compressed payload
   limits, and competing starts. Require bounded failure, no host pathname traversal, and no
   disk writes during discovery. Build the seed twice from pinned inputs and compare logical
   disk bytes. Check ownership, xattrs, hardlinks, and free space from a booted guest.
5. **Appliance fidelity.** Qualify plain LVM first, then LUKS with unattended `passdev` unlock.
   Verify the complete LV and subvolume topology, swap, `/var/data`, mount restrictions, initrd
   hook persistence, and absence of unlock material from host logs. Run the appliance's own
   upgrade, reboot, check the new running kernel and application health, and run the next
   upgrade's initial kernel check. Separately boot through UEFI for any claim about GRUB or EFI
   repair.
6. **Measurements and remaining decisions.** Measure cold `/boot` discovery, kernel decoding,
   payload size, peak helper memory, time to exec-server availability, and time to handoff for
   A and B. Use those measurements to set size caps and boot deadlines. Specify the completion
   record (its file name and format on `/boot`, and its hook's order relative to
   initramfs-tools' `postinst.d` hook). Resolve the oldest supported Debian initramfs-tools
   version, the fail-closed hook mechanism, per-mount read-only behavior across btrfs
   subvolumes, and the retention policy for the last confirmed release before enabling the
   corresponding profile.
