# Windows guests: how they work

The README's [Windows guests](../README.md#windows-guests) section says how to build, run and
reach a Windows machine, and [`examples/windows`](../examples/windows) builds whole labs. This
page is the other half: how vk boots and drives Windows, what each piece does, and what is
known not to work yet.

A Windows machine is a UEFI guest on virtio devices, in the same embedded VMM as vk's Linux
guests (no QEMU, no AHCI emulation, no other VMM on the host), driven through its qemu-ga
agent instead of vk-agent.

## Overview

```text
 Dockerfile ─► vk build ─► winiso install (cached) ─► RUN/COPY layers (qcow2, cached) ─► bundle
                                                                                          │
 compose file ─► vk run --compose ─► manager ─► winsvc: boot, wait, secrets, provisioning │
                                       │                                                  ▼
                                       └──────────────► libkrun VMM (boot child) ◄── vm.json
                                                         ├ UEFI firmware (embedded)
                                                         ├ virtio-pci: blk, net, console, rng
                                                         ├ uefi-vars: UEFI variables (vk-uefi-vars)
                                                         ├ TPM 2.0 CRB: vk-tpm
                                                         └ ACPI, SMBIOS, Hyper-V, pvpanic
 vk exec / cp / healthcheck ─► qemu-ga over virtio-serial (qga.sock in the run dir)
```

## Firmware

The firmware is edk2's `OvmfPkg/CloudHv` platform, built by `./build-firmware.sh` from the
nixpkgs revision the build image pins (the `firmware` output of
`.devcontainer/nix/flake.nix`), with Secure Boot and the TPM on and without SMM, which libkrun
does not emulate. `build.sh` embeds it into `vk` (`VIRTKIT_UEFI_FIRMWARE` names another at run
time); libkrun loads it as a PVH ELF, like a Linux kernel. Two variable store templates come
with it: an empty one, and one with Microsoft's Secure Boot keys enrolled
(`firmware=uefi-secboot`).

One local patch, `.devcontainer/nix/firmware/cloudhv-host-variables.patch`, changes the build's
configuration only:

- The UEFI variables are the host's. edk2's variable driver for a variable service outside the
  guest (`VirtMmCommunicationDxe` with `VariableSmmRuntimeDxe`, written for QEMU's `uefi-vars`
  device) replaces the platform's own, which kept them in the guest and checked signed writes
  there. vk's `vk-uefi-vars` is that service: it keeps the variables in `uefi-vars.fd`, checks
  PK, KEK, db and dbx updates against the keys above them, and enforces the firmware's variable
  policies, out of the guest kernel's reach. The variable driver's runtime cache is off, as
  that client requires (it stops the boot otherwise). See [the design](uefi-vars-design.md).
- edk2's TCG MOR driver is in, so the firmware has the `MemoryOverwriteRequestControl`
  variable BitLocker looks for with a TPM. MorLock is not supported.

The default output of the firmware derivation keeps edk2's build tree, with each module's
`.debug` ELF: their addresses are the modules' RVAs, which is how a fault in the firmware is
mapped back to its source.

## VMM

libkrun is vendored under `third_party/libkrun`; its `VENDOR.md` lists every local patch with
its rationale and test. For Windows they add:

- the platform devices Windows and the firmware expect: an ACPI PM timer, a PCI host bridge at
  00:00.0 that the CloudHv firmware identifies, a CMOS real-time clock, COM1/COM2, ACPI
  processor objects, a FACS in the XSDT, a 32-bit PCI hole the firmware assigns BARs in;
- virtio-pci with MSI-X and QEMU's subsystem IDs, which the virtio-win drivers bind to, and
  device reset (Windows' drivers reset their devices as they start; virtio-net keeps its
  backend across a reset, since it owns the tap or socket and must not open it twice);
- the UEFI variable service's device (`uefi-vars`, edk2's QemuUefiVars register interface, DMA
  transfers) and the fw_cfg file the firmware finds it through, in front of `vk-uefi-vars`; a
  snapshot taken before it, with the CFI flash the variables used to live on, restores with the
  flash;
- a TPM 2.0 CRB device backed by `vk-tpm`, a TPM 2.0 in Rust inside `vk` (no swtpm on the
  host), its state in `tpm-state`;
- SMBIOS tables with a per-machine UUID, a VM generation ID, KVM's Hyper-V enlightenments,
  pvpanic (a guest crash is logged to the run's `console.vmm.log`);
- on an AMD host that is itself a VM (WSL2, Azure), the guest's debug exceptions taken by the
  VMM, which steps over `int1`: Hyper-V's nested SVM reports an `int1`'s exception with the
  instruction pointer still on it, the guest ran it again forever, and Windows' PatchGuard
  runs one now and then;
- pause and resume, and snapshot and restore of memory, CPU and device state.

## Driver (`vk-driver`)

| Module | Role |
| --- | --- |
| `winiso` | The unattended install: the FAT32 install disk (made in a Linux helper VM), Setup, the first boots' servicing, the settle step. |
| `winbuild` | Windows Dockerfile stages: the `RUN`/`COPY` layers through qemu-ga, sysprep, the bundle. |
| `uefi` | Booting a UEFI guest: its spec, the firmware, its run directory, waiting for Windows to finish starting, stopping it. |
| `qga` | The qemu-ga client: one connection at a time, resynchronized after a guest reboot. |
| `relay` | The boot child's sockets: qemu-ga shared among its clients, COM1's input. |
| `winexec` | Commands through qemu-ga: a script staged in the guest, its output streamed back, its exit code; file copies. |
| `winsvc` | A Windows compose service: secrets, provisioning with restarts, stop. |
| `wintap` | A guest on a host tap: its static address and the run's names, set over qemu-ga. |
| `snapshot` | `vk snapshot` of a machine or a run, and the snapshot bundle. |
| `vmmctl` | The run's `vmm.sock`: pause, resume, snapshot. |
| `console` | `vk console` on the serial console. |

The run directory of a Windows machine holds its overlays (`disk0.qcow2`), `uefi-vars.fd`,
`tpm-state`, `system-uuid`, `vmgenid`, the qemu-ga socket (`qga.sock`), the control socket
(`vmm.sock`), the serial console (`console.log`, `console.sock`) and the VMM's own log
(`console.vmm.log`).

A stop presses the ACPI power button and, if Windows is still up 10 seconds later, asks
qemu-ga to shut it down; the guest then has three minutes, after which vk ends the VM through
its own quit, which flushes the disks (a kill would leave a qcow2 overlay's cached metadata
unwritten, and the next run of a kept disk would corrupt it).

## Tests

- `tests/windows-ad-e2e.sh`: the AD lab (a DC, a Linux job creating its users, two members,
  RDP sign-ins), then a snapshot of the lab and its restore.
- `tests/windows-rdp-e2e.sh`: a full Remote Desktop session into a standalone server.
- `tests/release-e2e.sh` runs both when `ISO_DIR` names where the ISOs are.

## Known limits

- **A domain controller ignores the ACPI power button**: its winlogon waits on the Group Policy
  client, which on a domain controller started as a new machine can last as long as it runs.
  vk then asks qemu-ga after 10 seconds, and Active Directory takes most of a minute to stop.
- **Windows expects things a VM does not have**, which it logs at each first boot: TPM-WMI 519
  ("TPM has been cleared", Windows taking ownership of a new TPM), 1040 and 1041 (no EK
  certificate, so the device cannot be attested), and with Secure Boot off, 1796 (the Secure
  Boot update task cannot apply its updates).
- **A guest on a host tap gets its static address over qemu-ga**, once it answers, about a
  minute after it starts; until then the adapter has what DHCP on the tap gave it, or nothing.
- **A Windows compose service also has an address on the run's switch**, from the top of the
  subnet down (.254, .253, ...), like any compose service, besides its tap.
- **Build steps run without a TPM**: a key sealed to an ephemeral TPM would leave the layer
  unbootable.
- **No hardware breakpoints in a guest on an AMD host that is itself a VM** (WSL2, Azure): the
  VMM takes the guest's debug exceptions there to step over `int1` (see VMM above), so a kernel
  debugger's hardware breakpoints and watchpoints in the guest do not fire.
- **Secure Boot without SMM** guards the boot chain: the variables are out of the guest's reach
  now, but the firmware itself runs unprotected from the guest's kernel while it boots.

## Secure Boot database updates

Windows' Secure-Boot-Update task writes authenticated variables (db, dbx, KEK) at run time.
While the firmware checked those writes itself, the first one stopped the guest with bug check
0x1E: a memory image of the faulting guest (`vk snapshot` taken just before, the guest-physical
fault address from its crash dump, and the bytes there matched against the firmware modules'
`.debug` files) put the fault in `CRYPTO_new_ex_data`, OpenSSL linked into
`VariableRuntimeDxe`, following a pointer into the crypto heap by its physical address. The
crypto state built during boot keeps physical addresses, and Windows, unlike Linux, maps the
runtime services only at the virtual addresses it gives them. The variables are now the host's
(above), and no signature is checked in the guest any more: the same update on Windows 11
applies (event 1034, dbx from 76 to 14072 bytes) and dbx keeps it across a restart.
