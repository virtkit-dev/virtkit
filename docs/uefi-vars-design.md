# vk-uefi-vars: a Windows guest's UEFI variables, on the host

## Why

A Windows guest's firmware (edk2's CloudHv platform) used to keep its UEFI variables itself:
a variable driver in the guest, its store on a flash device libkrun backs with a file. Without
SMM, which libkrun does not emulate, that driver also checked authenticated writes in the
guest, with OpenSSL linked into it. Two problems followed.

- **Secure Boot updates crashed Windows.** OpenSSL's state, built while the firmware boots,
  links its parts by physical addresses. Windows maps the runtime services elsewhere and calls
  them there, so the first signature check at run time (Windows' Secure-Boot-Update task writing
  dbx) followed a physical address and the guest stopped with bug check 0x1E, in
  `CRYPTO_new_ex_data` of `VariableRuntimeDxe`. Linux guests never saw it: Linux also maps the
  runtime services at their physical addresses.
- **Secure Boot guarded little.** The guest's kernel could rewrite the flash, and with it PK,
  KEK, db and dbx.

On a physical machine both are SMM's job: the variable driver and its checks run where the OS
cannot reach. vk does the same on the host, with no change to edk2's code: edk2 already has a
client for a variable service outside the guest (`VirtMmCommunicationDxe`, written for QEMU's
`uefi-vars` device), and the firmware build only swaps drivers and turns off the variable
runtime cache, which that client refuses, as OVMF's own `QEMU_PV_VARS` build does
(`.devcontainer/nix/firmware/cloudhv-host-variables.patch`).

## Architecture

```text
 guest: Windows ── runtime services ──► VariableSmmRuntimeDxe (edk2, unchanged)
                                            │ MM messages (EFI_MM_COMMUNICATE_HEADER)
                                            ▼
                                       VirtMmCommunicationDxe (edk2, unchanged)
                                            │ registers + DMA of a 64 KiB buffer
 ───────────────────────────────────────────┼──────────────────────────────────────────
 host: libkrun                         uefi-vars device (0xFED50000)  fw_cfg (0x510)
                                            │                         "etc/hardware-info"
                                            ▼
                                       vk-uefi-vars::Service ──► uefi-vars.fd (store file)
```

- **Discovery.** The client reads `etc/hardware-info` through fw_cfg (traditional I/O ports,
  no DMA), which names the device's MMIO page. The firmware stops with a message if it is not
  there (`PcdQemuVarsRequire`).
- **Transport.** The firmware gives the device its communication buffer's guest-physical
  address once; each `DMA_MM` command has the device read the buffer, the service answer in
  place, and the device write it back before the command's status reads back.
- **The service** (`vk-uefi-vars`) handles two MM handlers: the variable protocol
  (`gEfiSmmVariableProtocolGuid`: GetVariable, GetNextVariableName, SetVariable,
  QueryVariableInfo, ready-to-boot, exit-boot-services, variable locks, payload size) and
  variable policies (`gVarCheckPolicyLibMmiHandlerGuid`). It follows the semantics of edk2's
  own SMM variable driver (`VariableSmm.c`, `Variable.c`, `AuthService.c`), from which status
  codes and checks are taken.

## What the service checks

- **Attributes and phases**: runtime access needs boot-service access; a variable keeps its
  attributes; after ExitBootServices only runtime variables are visible, volatile ones and those
  without runtime access are write-protected, and new ones must be non-volatile and runtime.
- **Time-based authenticated writes** (UEFI 2.10 §8.2.2): an `EFI_VARIABLE_AUTHENTICATION_2`
  with a PKCS#7 signature over the name, vendor GUID, attributes, timestamp and data; a
  timestamp later than the stored one, unless the write appends.
  - PK by the PK, KEK by the PK, db/dbx/dbt/dbr by a KEK or the PK; in setup mode (no PK) a
    well-formed write goes unchecked, as edk2 allows without `PcdRequireSelfSignedPk`.
  - Any other time-based authenticated variable by the signer that created it (identified by
    the SHA-256 of its chain's top certificate, recorded in `VkAuthVarSigners` in edk2's certdb
    namespace, which the guest cannot write).
  - Appends to the signature databases skip the signatures already there.
  - PKCS#7 is checked as edk2's `Pkcs7Verify` checks it: every signer found among the
    signature's certificates, its signature good (over the signed attributes, whose
    `messageDigest` must match, or over the content), and chaining to a trusted certificate
    through the signature's certificates. No validity periods or key usages: the certificates
    that sign Microsoft's updates have expired. RSA PKCS#1 v1.5 with SHA-1 to SHA-512 (RustCrypto);
    the ASN.1 is parsed by a small DER/BER reader (`der.rs`).
- **The modes**: SetupMode, SecureBoot, AuditMode, DeployedMode, SignatureSupport and VendorKeys
  are the service's, volatile and read-only, recomputed when the keys change; the `*Default`
  variables and the signer records are read-only too.
- **Variable policies** the firmware registers (size bounds, attributes a variable must or must
  not have, lock now, on create, on another variable's state), until it locks the interface at
  the end of DXE; variables locked through EDKII_VARIABLE_LOCK_PROTOCOL become read-only then.

## Store and state

- **The store file** is edk2's variable store flash image, the format machines already had
  (`uefi-vars.fd`, 528 KiB): a firmware volume holding an authenticated variable store. The
  service reads its variables at start and, after a write that changed a non-volatile one,
  writes them back compacted; the device replaces the file through a synced rename. Existing
  machines, the store templates and snapshots keep working unchanged, and the file stays
  readable by edk2's own driver.
- **A snapshot** keeps what is not in the file (`UefiVarsState`): the phase, the volatile
  variables the OS reads at run time (BootCurrent, OsIndicationsSupported, ...), the policies
  and the locks.
- **Older snapshots**, taken with the flash, hold the old firmware in their memory: they restore
  with the flash device, as before.

## Limits

- No hardware error records (`HwErrRec`), as the flash build had none.
- MorLock is not supported; MOR itself is a plain variable (edk2's TCG MOR driver creates it).
- `VIRTKIT_UEFI_FIRMWARE` naming a firmware built for the flash boots without variables.

## Tests

- `vk-uefi-vars`'s unit tests: variable semantics, phases, persistence, the MM encoding,
  Secure Boot enrollment and signed updates with keys and signatures made in the test, private
  authenticated variables, snapshot state.
- The fw_cfg directory test in libkrun.
- On a guest: Windows 11 with Secure Boot applying Microsoft's dbx update through its
  Secure-Boot-Update task (event 1034, dbx from 76 to 14072 bytes, kept across a restart), and
  Windows Server writing a variable, snapshotted, restored and writing again.
