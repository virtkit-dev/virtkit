# vk-tpm: a TPM 2.0 in Rust

Status: phase 1 and part of phase 2 are implemented: the engine skeleton, the first commands,
hierarchies, the dictionary-attack protection, the PCR and hash commands. They were tested
against libtpms. This document describes the target and the plan for getting there;
[Deviations](#deviations-from-libtpms) lists where `vk-tpm` answers differently, on purpose.

`vk-tpm` is to replace libtpms and the OpenSSL it computes with as the engine behind libkrun's
TPM CRB device (`third_party/libkrun/src/devices/src/legacy/x86_64/tpm.rs`). Those are ~300k
lines of C, linked statically into `vk`. The replacement is a workspace crate with no C, whose
crypto comes from RustCrypto crates. It is written to the TCG TPM 2.0 Library specification
(Parts 1-3), and libtpms is its executable reference.

## Why

- **Supply chain and build.** libtpms and OpenSSL are the only C in `vk` that is not a crate's
  vendored build. They need a dedicated nix output (`tpmLibs`), a musl static OpenSSL, and
  `VK_LIBTPMS_DIR` plumbing.
- **Memory safety at a trust boundary.** Every command byte comes from the guest. libtpms has
  had out-of-bounds CVEs in exactly that path, e.g. CVE-2021-3746 and CVE-2023-1017/1018.
- **One TPM per process.** libtpms keeps global state, so the device has a process-wide lock
  and static callbacks. `vk-tpm` is a value: any number of TPMs per process, and tests run in
  parallel.
- **Readable state.** The state is ours, versioned, and documented below. libtpms' blobs are
  opaque and tied to its internal layout.

## Scope

The target guests are Windows 10/11/Server on OVMF, with Linux as a secondary target. Commands
are grouped by who needs them. Anything outside the list answers `TPM_RC_COMMAND_CODE`, and
`TPM_CAP_COMMANDS` lists exactly what is implemented, with exact TPMA_CC attributes (resource
managers parse these), so a client never tries a missing command.

**MUST: edk2 Tcg2 plus Windows (TBS, the provisioning task, BitLocker, PCP KSP / Hello,
attestation):**

| Area | Commands |
|---|---|
| Lifecycle | Startup, Shutdown, SelfTest, IncrementalSelfTest, GetTestResult, GetCapability, GetRandom, StirRandom, TestParms, ReadClock |
| PCR | PCR_Extend, PCR_Event, PCR_Read, PCR_Allocate, PCR_Reset |
| Hierarchy, DA | HierarchyControl, HierarchyChangeAuth, ChangeEPS, ChangePPS, Clear, ClearControl, SetPrimaryPolicy, DictionaryAttackLockReset, DictionaryAttackParameters |
| Objects | CreatePrimary, Create, CreateLoaded, Load, LoadExternal, ReadPublic, ObjectChangeAuth, Unseal, EvictControl, FlushContext, ContextSave, ContextLoad |
| Crypto | Sign, VerifySignature, RSA_Encrypt, RSA_Decrypt, ECDH_KeyGen, ECDH_ZGen, ECC_Parameters, HMAC, Hash, HashSequenceStart, HMAC_Start, SequenceUpdate, SequenceComplete, EventSequenceComplete, EncryptDecrypt(2) |
| Sessions, policy | StartAuthSession, PolicyRestart, PolicyPCR, PolicyAuthValue, PolicyPassword, PolicyOR, PolicySecret, PolicySigned, PolicyCommandCode, PolicyGetDigest, PolicyAuthorize, PolicyNV, PolicyLocality, PolicyCpHash, PolicyNameHash |
| Attestation | Quote, Certify, CertifyCreation, GetTime, GetSessionAuditDigest, ActivateCredential, MakeCredential |
| NV | NV_DefineSpace, NV_UndefineSpace, NV_UndefineSpaceSpecial, NV_ReadPublic, NV_Read, NV_Write, NV_Increment, NV_Extend, NV_SetBits, NV_WriteLock, NV_ReadLock, NV_GlobalWriteLock, NV_ChangeAuth |

**SHOULD: Linux tooling (systemd-cryptenroll / pcrlock, clevis, tpm2-tools, the kernel's
HMAC-session encryption since 6.10):** Duplicate, Import, Rewrap, PolicyTicket,
PolicyDuplicationSelect, PolicyNvWritten, PolicyTemplate, PolicyAuthorizeNV,
PolicyCounterTimer, PolicyPhysicalPresence, NV_Certify, GetCommandAuditDigest,
SetCommandCodeAuditStatus, ClockSet, ClockRateAdjust, PCR_SetAuthPolicy, PCR_SetAuthValue,
EC_Ephemeral, ZGen_2Phase.

**Stubbed (TPM_RC_COMMAND_CODE, not listed):**
- Field upgrade: FieldUpgradeStart, FieldUpgradeData, FirmwareRead.
- ECDAA: Commit (so TPM_PT_SPLIT_MAX = 0).
- PP_Commands and SetAlgorithmSet: platform-specific, and no guest relies on them.
- Attached components and ACT: AC_*, Policy_AC_SendSelect, ACT_SetTimeout.
- Vendor_TCG_Test.
- The 1.83 additions nobody sends yet: NV_DefineSpace2, NV_ReadPublic2, SetCapability,
  ReadOnlyControl, PolicyTransportSPDM, CertifyX509, ECC_Encrypt/Decrypt, PolicyCapability,
  PolicyParameters.

Unlike libtpms, `vk-tpm` ships no physical-presence commands. OVMF's PPI flows use
platform auth only before it randomizes the platform hierarchy, so they need none.

**Algorithms.** TPM_CAP_ALGS lists only what is implemented.

| Algorithm | Required by | Crate |
|---|---|---|
| SHA-1, SHA-256 | PCR banks; Windows 11 requires SHA-256 | `sha1`, `sha2` |
| SHA-384, SHA-512 | libtpms' default banks; cheap | `sha2` |
| HMAC, KDFa (SP 800-108 counter mode) | Sessions, object protection; Entra join needs HMAC | `hmac` |
| KDFe (SP 800-56A) | ECC salt, ECC MakeCredential | `sha2` |
| AES-128/256 CFB | Parameter encryption, symmetric storage keys, contexts | `aes`, `cfb-mode` (new) |
| XOR obfuscation | Parameter encryption | KDFa |
| RSA 2048 (3072 SHOULD): RSASSA, RSAPSS, RSAES, OAEP, MGF1 | EK, SRK, BitLocker, PCP KSP | `rsa` |
| ECC NIST P-256 (P-384 SHOULD): ECDSA, ECDH | ECC EK/SRK, the kernel's null-key sessions | `p256`/`p384`, `ecdsa` |
| KEYEDHASH | Sealed objects (BitLocker) | — |

Out of scope: ECDAA, ECSchnorr, SM2/SM3/SM4, ECMQV, KDF2, TDES, Camellia, CMAC and BN curves.
libtpms' `default-v1` profile enables most of them, but none of our guests uses them.

**Dependencies.** Each crate is RustCrypto, pure Rust and musl-static. All of them are already
in `Cargo.lock` through russh/rustls, except `cfb-mode`, a ~300-line mode-of-operation crate
over `aes`. They are added only when a phase needs them:

- phase 1: `sha1`, `sha2`, `getrandom`, `subtle` (constant-time comparison), `zeroize`
  (wiping secrets).
- phase 2: `hmac`, `aes`, `cfb-mode`.
- phase 3: `rsa`, `p256`, `ecdsa`.

The `rsa` crate carries RUSTSEC-2023-0071 (Marvin: timing in PKCS#1 v1.5 decryption), which
`.cargo/audit.toml` already suppresses for russh. A TPM decrypts guest-chosen ciphertexts with
its EK (ActivateCredential, salted sessions), so phase 3 must either use an `rsa` release built
on constant-time `crypto-bigint`, or blind the private operation and confirm it with timing
tests. This is an open item.

## Architecture

```
vk-tpm/src/
  lib.rs         Tpm: the engine API; command header, handle area, authorization area, response
  marshal.rs     Reader/Writer: bounds-checked big-endian wire format, TPM2B, TPML counts
  rc.rs          TPM_RC values; handle/parameter/session numbering of format-one codes
  alg.rs         implemented algorithms (TPM_CAP_ALGS), hash dispatch, serializable hash state
  crypt.rs       HMAC, over RustCrypto
  entity.rs      handles: interface types, load status, Names, authValues, authPolicies
  session.rs     the authorization area: password sessions, and the response's
  hierarchy.rs   hierarchy auths, policies, proofs, enables; dictionary-attack logic; the
                 hierarchy and DA commands
  object.rs      transient object slots; hash and event sequences, TPM2_Hash, FlushContext
  pcr.rs         PCR banks, PC Client attributes, startup/save/extend/reset/read
  state.rs       Permanent / Volatile state, versioned serialization
  commands.rs    command table (code, handle kinds, auth count, TPMA_CC) and the lifecycle and
                 PCR command bodies
  capability.rs  TPM2_GetCapability
```

Later phases grow `session.rs` (HMAC and policy sessions, cpHash/rpHash, parameter
encryption) and `object.rs` (TPMT_PUBLIC/SENSITIVE, protection, primaries), and add
`context.rs`, `nv.rs` and `policy.rs`.

Command processing follows Part 3's order exactly, because the response code a guest sees for
a malformed command depends on it:

1. The header: tag (`TPM_RC_BAD_TAG`, or `TPM_RC_VALUE` for an unknown TPM_ST), size
   (`TPM_RC_COMMAND_SIZE`), code (`TPM_RC_COMMAND_CODE`).
2. Startup state (`TPM_RC_INITIALIZE`).
3. Handles: check each kind (`+ TPM_RC_H + n`), then, after reading all handles, check that
   each names an enabled hierarchy or loaded object (EntityGetLoadStatus).
4. Authorization area: its size, then each session's unmarshalling, kind, attributes and
   nonce, then each authorization in turn (`+ TPM_RC_S + n`).
5. Parameters (`+ TPM_RC_P + n`), with any leftover bytes `TPM_RC_SIZE`.
6. Execution, then the response with its authorization area.

A command parses all its parameters before it acts, so a refused command changes nothing,
except that a failed authorization counts against the dictionary-attack protection before the
parameters are read, as in the reference implementation.

**Determinism.** Each primary key derives from its hierarchy's seed through KDFa, keyed by the
template. RSA primaries use a DRBG seeded the same way, so a TPM recreates the same EK/SRK
every boot. The RSA prime search is ours, so our primaries will not equal libtpms' even from
identical seeds; libtpms' own algorithm is `SEED_COMPAT_LEVEL`-specific.

## Engine interface (what libkrun's device calls)

It mirrors what `tpm.rs` (at 2ba84aa2) does with libtpms, so the device swaps one for the other:

| `tpm.rs` today (libtpms) | `vk-tpm` |
|---|---|
| `TPMLIB_SetBufferSize(BUFFER_SIZE)`, which must equal it | `vk_tpm::MAX_COMMAND_SIZE == BUFFER_SIZE` (0xf80), a `const` assertion in the device |
| `TPMLIB_SetProfile({"Name":"default-v1"})` | none: the implemented set is fixed per state format version |
| new TPM when the state file is `NotFound` | `Tpm::manufacture()`, then store `permanent_state()` |
| `nvram_loaddata` from the file, then `TPMLIB_MainInit` | `Tpm::power_on(&bytes)` (a `StateError` is the old `TPM_FAIL`) |
| snapshot restore: write the file, `SetState(PERMANENT)`, `SetState(VOLATILE)`, `MainInit` | `Tpm::restore(&saved.permanent, &saved.volatile)`, and write the file |
| `TPMLIB_Process` | `Tpm::process(&cmd) -> Vec<u8>`, never fails, at most `MAX_COMMAND_SIZE` bytes |
| `nvram_storedata("permall")` callback | after `process`, `if tpm.take_permanent_changed() { write_atomic(path, &tpm.permanent_state()) }`, before the CRB clears START so a guest never sees a response whose state is not durable |
| `TPMLIB_GetState(PERMANENT / VOLATILE)` for a snapshot | `permanent_state()` / `volatile_state()`, both `Zeroizing` |
| `RUNNING` / `PERMANENT_STATE` globals | none: a `Tpm` is a value owned by the `TpmCrb` |

`permanent_state()` and `volatile_state()` return `Zeroizing<Vec<u8>>` to protect the seeds
and the platform's and sequences' authValues, respectively. `process` compares permanent state
before and after each command, so `take_permanent_changed` reports every change, including
counted authorization failures, without per-command bookkeeping. The file keeps
`write_atomic`'s guarantees: 0600, fsync, rename, then a directory fsync. The locality stays 0,
as the device grants only locality 0. `process` will take one when the device offers more.

The libkrun crates are a separate cargo workspace. Their `devices` crate depends on `vk-tpm`
by path, behind its `tpm` feature, and libkrun's lockfile gains the RustCrypto crates
`vk-tpm` uses, which are already in `vk`'s. `VK_LIBTPMS_DIR`, the `tpmLibs` flake output and
the NOTICE entries for libtpms/OpenSSL go away in the same change.

## State

Two blobs, each `magic (8 bytes) ‖ version (u16) ‖ fields`, in the TPM wire format. A reader
refuses an unknown version, a short blob or trailing bytes.

- **Permanent** (`VKTPM-P\0`): EPS, SPS, PPS (64 bytes each, random at manufacture); the
  owner, endorsement and lockout authValues and authPolicies; the platform, storage and
  endorsement proofs; disableClear; the PCR allocation from the next power on; the DA
  parameters, failed-tries counter and whether lockoutAuth may be tried; the last shutdown
  (none, none with a DA-protected authorization since, CLEAR, or STATE with the saved PCRs,
  their update counter, the enables and the platform authorization) and TPM time at that
  shutdown. Later phases add persistent objects, NV indices, the clock, and the reset/restart
  counters.
- **Volatile** (`VKTPM-V\0`): whether Startup ran, whether it followed an orderly shutdown;
  TPM time and the DA timers; the hierarchy enables and the platform authorization; the PCR
  allocation in use; the PCRs and their update counter; the object slots (hash and event
  sequences, with their hash state). Later phases add sessions, keys and the context counter.

The version is bumped when a field is added; the reader accepts every older version and fills
the new fields with what a TPM upgraded from that version would have. A snapshot is restored
by the `vk` that took it, or a newer one. A state written by a newer `vk` is refused. Until a
`vk` stores a `vk-tpm` state outside tests, the format stays at version 1 and changes in
place.

A sequence's hash state is serialized as RustCrypto's `SerializableState` gives it (block
state, length, buffered bytes). That format belongs to the `sha1`/`sha2` crates: an upgrade
that changes it must bump the state version.

**No migration from libtpms.** libtpms' blob is its internal NV layout, so converting it would
mean parsing `NVMarshal.c`'s format, including its seeds. A machine that switches engines gets
a new TPM: new seeds, so a new EK and SRK. Anything sealed to the old TPM is lost: BitLocker
asks for its recovery key once, then reseals, and Windows Hello keys must be re-enrolled. The
device must therefore recognize a libtpms state (its blob is not `VKTPM-P`) and fail loudly
rather than silently manufacture over it. `vk` then offers either to keep the libtpms build for
that machine or to reset its TPM explicitly. The default for new machines is decided when
phase 5 lands.

## Deviations from libtpms

Where `vk-tpm` answers differently from libtpms, on purpose (the differential tests, at tag
`vk-tpm-differential`, exempted exactly these):

- **Identity.** TPM_PT_MANUFACTURER, the vendor strings, the firmware version and SVN are
  ours; TPM_PT_TOTAL/LIBRARY_COMMANDS count what is implemented.
- **Not implemented** (yet, or out of scope): those commands are TPM_RC_COMMAND_CODE, and
  absent from TPM_CAP_COMMANDS; the algorithms are absent from TPM_CAP_ALGS.
- **A failed Startup(STATE) keeps a pending DA failure.** libtpms clears its "DA used" mark
  before it checks the startup type, so the Startup(CLEAR) that follows forgets the failure
  it should count; `vk-tpm` refuses the command without changing anything.
- **Every Startup clears the "DA used" mark.** libtpms keeps it set through a Startup in
  lockout or with recoveryTime 0, and then does not mark the next DA-protected use, so losing
  power after it counts nothing; `vk-tpm` marks it, and counts the failure.
- **Persistence.** `vk-tpm` reports every change to the permanent state; libtpms skips writing
  a disabled lockoutAuth when lockoutRecovery is 0 (the next Startup re-enables it anyway).

Quirks of the reference implementation that `vk-tpm` keeps, so it answers the same:
TPM2_PCR_Allocate takes effect at the next power on and TPM2_Clear drops a pending one
(libtpms rewrites its whole PERSISTENT_DATA there); a PCR not allocated keeps its value
through a Startup; TPM2_DictionaryAttackParameters leaves failedTries alone.

## Security

- **Input bounds.** Every read goes through `Reader`, which bounds-checks and has no
  `unsafe`. The crate denies (through CI's `-D warnings`) clippy's `unwrap_used`,
  `expect_used`, `panic`, `indexing_slicing` and `arithmetic_side_effects` outside tests. A
  command is at most 0xf80 bytes, and every list is capped by its TPML maximum.
- **Constant time.** Authorization comparisons use `subtle::ConstantTimeEq`. This covers
  passwords now, and HMACs and policy digests later. Secret-dependent crypto is left to
  RustCrypto's constant-time implementations; the RSA caveat is above.
- **Secrets.** Seeds and proofs are `Zeroizing<[u8; 64]>`; authValues are `Zeroizing`, and so
  are both serialized states. Later phases do the same for session keys, sensitive areas and
  private keys.
- **Entropy.** It comes from `getrandom`, the host's CSPRNG, for seeds, nonces and GetRandom.
  StirRandom will mix guest input into a DRBG of our own (HMAC-DRBG), never replacing host
  entropy.
- **DA logic** follows `DA.c` and `SessionProcess.c`, with libtpms' build switches
  (`USE_DA_USED`, `ACCUMULATE_SELF_HEAL_TIMER`). A failure on a DA-protected entity counts; a
  non-orderly startup counts one failure if a DA-protected authValue was used since the last
  Startup; a failed lockoutAuth disables it until lockoutRecovery passes (or the next Startup,
  when that is 0). Failures are counted in the permanent state before the response leaves, so
  a guest cannot roll the counter back by crashing the VM. So far lockout is the only
  DA-protected entity: hierarchies, PCRs and sequences are exempt.
- **Response size.** A response that would exceed the buffer is `TPM_RC_FAILURE`, never
  truncated.

## Test strategy

1. **Unit tests**, co-located and fast: marshalling, response codes, PCR semantics, state round
   trips, and the engine end to end (`src/tests.rs`).
2. **Differential tests against libtpms**, removed in phase 5 with libtpms itself (they needed
   a static libtpms and OpenSSL in the build image). They last ran, all green, at tag
   `vk-tpm-differential` (the end of phase 4), with
   `VK_LIBTPMS_DIR=/opt/tpm cargo test -p vk-tpm --features libtpms --test differential` in the
   dev VM; `git show vk-tpm-differential:vk-tpm/tests/differential.rs` and its modules are the
   harness, and that tag's build image the libtpms they ran against (the `tpmLibs` flake output). What
   they did (`tests/differential.rs`, feature `libtpms`):
   - Setup:
     - Both engines are linked into one test binary in the dev VM. libtpms and its libcrypto
       come statically from `VK_LIBTPMS_DIR=/opt/tpm`.
     - libtpms is configured exactly as the CRB device configures it: `default-v1`, a 0xf80
       buffer, locality 0. Its permanent state is held in memory, so a test can power-cycle
       it.
   - What is compared:
     - Responses are compared **byte for byte** wherever the TPM is deterministic.
     - **By shape** (code, length, header) for GetRandom.
     - **By subset** for TPM_CAP_ALGS and TPM_CAP_COMMANDS: ours ⊆ libtpms', with identical
       attributes.
     - **Key by key, with an explicit exemption list** for TPM properties: our identity, and
       what is not implemented yet.
   - Both TPMs could carry the same seeds and proofs: the test patched them into libtpms'
     stored PERSISTENT_DATA (found by its magic, the fields before them skipped by their
     sizes) and power-cycled it, and gave vk-tpm the same through a hidden setter that only
     the `libtpms` feature compiled (at the tag; neither is in the tree). Hash tickets were
     compared byte for byte this way; later, names, policy digests, symmetric and keyed-hash
     primaries, RSASSA signatures, NV contents and Quote's attest structure.
   - Randomized outputs are cross-verified instead: ECDSA/PSS signatures are verified by the
     other engine, and OAEP ciphertexts are decrypted by the other.
   - A **mutation pass** flips bits in a corpus of well-formed commands with a fixed-seed
     xorshift. It compares both answers wherever the command is one `vk-tpm` implements.
3. **TPM 2.0 test suites** over a socket. A small `vk-tpm` binary (test-only) will serve the
   MS simulator protocol: port 2321 for commands, 2322 for platform signals (power, NV,
   cancel). It runs:
   - **IBM TSS `reg.sh`**, the most complete open suite, which swtpm already runs in its CI
     with patches we can reuse;
   - **tpm2-tools integration tests**, which exercise the clevis/systemd flows;
   - selected **tpm2-tss ESAPI tests**.
   The TCG compliance suite is members-only.
4. **Fuzzing**: `cargo fuzz` on `Tpm::process` and on state deserialization, seeded with the
   differential corpus. The invariants are no panic, a response within the size limit, and a
   state that round-trips.
5. **Guests**, end to end, before the default flips: Windows 11 (Get-Tpm `TpmReady`,
   BitLocker TPM-only and TPM+PIN through a reboot and a snapshot restore, Windows Hello
   PIN, `tpmtool getdeviceinformation`) and Linux (`systemd-cryptenroll --tpm2-pcrs=7`, the
   kernel's TPM selftests).

## Phases

| # | Content | Size (rough) |
|---|---|---|
| 1 | **Done.** Crate, marshalling, RCs, state format; Startup, Shutdown, SelfTest, GetCapability, GetRandom, PCR_Read, PCR_Extend; password sessions; the libtpms differential harness (ran at tag `vk-tpm-differential`, not kept) | ~3 kLoC, half of it tests |
| 2 | Sessions and hierarchies: StartAuthSession (unsalted, bound, RSA/ECC-salted), HMAC sessions, cpHash/rpHash/names, parameter encryption (AES-CFB, XOR), KDFa/KDFe, DA logic, Hierarchy*, Clear*, PCR_Allocate/Reset/Event, StirRandom, GetTestResult, TestParms, ReadClock, hash/HMAC sequences | ~4 kLoC |
| 3 | Objects: TPMT_PUBLIC/SENSITIVE, protection (symmetric + integrity), CreatePrimary (deterministic), Create/Load/ReadPublic/Unseal/ObjectChangeAuth/LoadExternal, contexts (ContextSave/Load/Flush, EvictControl), Sign/Verify, RSA_Encrypt/Decrypt, ECDH, EncryptDecrypt | ~5 kLoC |
| 4 | NV indices (all types and attributes), the policy commands, attestation (Quote, Certify*, GetTime, audit digests, Make/ActivateCredential), EK provisioning at manufacture (EK at 0x81010001 and an EK certificate in 0x01C00002, signed by a per-host virtkit CA) | ~4 kLoC |
| 5 | Integration: libkrun device on `vk-tpm`, MS-simulator socket server and the IBM TSS / tpm2-tools runs, fuzzing, Windows and Linux guest validation, removal of libtpms | ~1.5 kLoC + validation |
