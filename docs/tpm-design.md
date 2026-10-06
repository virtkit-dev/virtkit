# vk-tpm: a TPM 2.0 in Rust

Status: phases 1 to 3 are implemented: the engine skeleton, sessions, hierarchies, the
dictionary-attack protection, the PCR and hash commands, and objects: keys, primary keys,
contexts, persistent objects, signing, RSA and ECDH; all tested against libtpms. This document
describes the target and the plan for getting there; [Deviations](#deviations-from-libtpms) lists
where `vk-tpm` answers differently, on purpose.

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

TPM2_HMAC and TPM2_HMAC_Start are TPM2_MAC and TPM2_MAC_Start in libtpms (the same codes and
wire format, a MAC scheme where a hash was); `vk-tpm` takes the same parameters, with an HMAC
only.
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
- phase 3: `rsa` 0.10.0-rc (the release candidate russh already uses, on constant-time
  `crypto-bigint` 0.7; `hazmat` for raw RSA), `p256` 0.14 and `ecdsa` 0.17 (ECDSA, the hedged
  RFC 6979 nonce, and the curve arithmetic ECDH needs), `crypto-bigint` and `crypto-primes` (the
  primary keys' derivations, below: both are what `rsa` computes with), `getrandom`'s `sys_rng`
  (the host's CSPRNG as a `rand_core` RNG: RSA blinding, ECDSA nonces). `sha1`/`sha2` gain their
  `oid` feature (the DigestInfo of PKCS#1 v1.5 signatures).

### RSA and the Marvin attack

The `rsa` crate carries RUSTSEC-2023-0071 (Marvin: timing in RSA decryption). It matters here: a
TPM decrypts guest-chosen ciphertexts. An EK (a restricted decryption key) does so without any
authorization, for TPM2_StartAuthSession's salt (and phase 4's ActivateCredential), always with
OAEP; an unrestricted key the caller is authorized to use does with TPM2_RSA_Decrypt, with any
padding, raw RSA included. The decision:

- `rsa` 0.10.0-rc on `crypto-bigint` 0.7, which carries the upstream fixes the advisory waits on
  (constant-time modular exponentiation, constant-time padding checks; issue #626, PR #680), not
  0.9 on `num-bigint-dig`.
- Every private-key operation is blinded (signatures included), on top of the constant-time
  exponentiation.
- OAEP is decoded in constant time, and all its failures (first byte, label hash, separator)
  are one response code, TPM_RC_VALUE, after the same work: no Manger oracle. This is the EK's
  path.
- PKCS#1 v1.5 (RSAES) decryption uses implicit rejection (draft-irtf-cfrg-rsa-guidance), as
  OpenSSL 3.2+ does, so libtpms too: a malformed ciphertext decrypts to a message derived from
  the private exponent and the ciphertext, the same one every time, and never to an error. No
  Bleichenbacher oracle, not even in the result. `vk-tpm`'s synthetic messages are OpenSSL's, byte
  for byte (the differential tests compare them), which needs the private exponent libtpms gives
  OpenSSL: d modulo λ(n) from 2048 bits with e above 2^16, modulo φ(n) otherwise.
- `decryption_time_does_not_depend_on_the_padding` (ignored by default; run optimized) times
  valid against invalid ciphertexts, interleaved: on the dev VM the medians of RSA-2048
  decryptions differ by 0.01% (OAEP) and 0.00% (RSAES), at ~2.6 ms each.

`.cargo/audit.toml` keeps the advisory suppressed, with this reasoning, until `rsa` 0.10 is
released.

## Architecture

```
vk-tpm/src/
  lib.rs         Tpm: the engine API; command header, handle area, authorization area, response
  marshal.rs     Reader/Writer: bounds-checked big-endian wire format, TPM2B, TPML counts
  rc.rs          TPM_RC values; handle/parameter/session numbering of format-one codes
  alg.rs         implemented algorithms (TPM_CAP_ALGS), hash dispatch, serializable hash state
  crypt.rs       HMAC, KDFa, KDFe, XOR obfuscation, AES-CFB, over RustCrypto
  entity.rs      handles: interface types, load status, Names, authValues, authPolicies
  session.rs     sessions; the authorization area: cpHash/rpHash, HMACs, parameter encryption,
                 audit; StartAuthSession
  hierarchy.rs   hierarchy auths, policies, proofs, enables; dictionary-attack logic; the
                 hierarchy and DA commands
  object.rs      transient object slots, persistent objects copied in for a command; hash, HMAC
                 and event sequences, TPM2_Hash, TPM2_HMAC
  public.rs      TPMT_PUBLIC, TPMT_SENSITIVE: wire format, Names, attribute and scheme checks
  key.rs         loaded keys; primary and ordinary object creation, wrapping (Create/Load),
                 the object commands, EvictControl, salt and credential decryption
  asym.rs        RSA and ECC P-256 over RustCrypto: key generation, signatures, encryption,
                 ECDH, implicit rejection
  drbg.rs        the reference implementation's CTR_DRBG, which primary keys derive from
  signing.rs     Sign, VerifySignature, RSA_Encrypt/Decrypt, ECDH_KeyGen/ZGen, ECC_Parameters
  context.rs     ContextSave, ContextLoad, FlushContext; saved sessions and the context gap
  pcr.rs         PCR banks, PC Client attributes, startup/save/extend/reset/read
  state.rs       Permanent / Volatile state, versioned serialization
  commands.rs    command table (code, handle kinds, auth count, TPMA_CC, parameter encryption)
                 and the lifecycle and PCR command bodies
  capability.rs  TPM2_GetCapability
```

Later phases add `nv.rs`, `policy.rs` and `attest.rs`.

Command processing follows Part 3's order exactly, because the response code a guest sees for
a malformed command depends on it:

1. The header: tag (`TPM_RC_BAD_TAG`, or `TPM_RC_VALUE` for an unknown TPM_ST), size
   (`TPM_RC_COMMAND_SIZE`), code (`TPM_RC_COMMAND_CODE`).
2. Startup state (`TPM_RC_INITIALIZE`).
3. Handles, each checked against its kind (`+ TPM_RC_H + n`), then, all read, that each names
   something present: an enabled hierarchy, a loaded object or session (EntityGetLoadStatus).
4. Authorization area: its size, then each session's unmarshalling, kind, attributes and
   nonce, then each authorization in turn (`+ TPM_RC_S + n`), then the first parameter's
   decryption.
5. Parameters (`+ TPM_RC_P + n`), with any leftover bytes `TPM_RC_SIZE`.
6. Execution, then the response: new TPM nonces, the first parameter encrypted, audit
   digests, each session's HMAC; sessions without continueSession are flushed.

A command parses all its parameters before it acts, so a refused command changes nothing,
except that a failed authorization counts against the dictionary-attack protection before the
parameters are read, as in the reference implementation.

**Determinism.** A primary key is recreated, the same key, from its hierarchy's seed and its
template, every boot. As in the reference implementation (`DRBG_InstantiateSeeded`), a CTR_DRBG
(AES-256) is seeded through the reference's own derivation function with the seed, "Primary
Object Creation", the template's Name and the caller's sensitive data; an endorsement key's
generator also takes the storage and endorsement proofs before its seed is drawn. Every value
is drawn as the reference draws it:

- an ECC private key: 40 bytes, reduced modulo n - 1, plus one (FIPS 186-4 B.4.1);
- a keyed hash's or a symmetric key's secret: the digest or key size;
- then the seed that protects a parent's children (and makes a symmetric object's unique).

So `vk-tpm`'s ECC, keyed-hash and symmetric primaries are the very keys libtpms derives from
the same seeds: the differential tests compare them byte for byte (outPublic, creation data,
ticket, Name), and load each other's wrapped children.

RSA primaries are not: the reference sieves for primes in a way that depends on its
`SEED_COMPAT_LEVEL`. `vk-tpm`'s prime search is its own, defined by the arithmetic alone so that
a crate upgrade cannot change an EK: each prime is the first one at or above a candidate drawn
from the generator (its top two bits and low bit set, so the modulus has exactly its size) that
is not 1 modulo the exponent, found by sieving with small primes and testing with Baillie-PSW
(`crypto-primes`); |p - q| must exceed 2^(bits/2 - 100). Non-primary keys run the same code
from a generator seeded with 64 bytes of host entropy.

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

`permanent_state()` returns `Zeroizing<Vec<u8>>`: it holds the seeds; `volatile_state()` too,
for the platform authValue and the session keys. `process` compares the permanent state
before and after each command, so `take_permanent_changed` reports any change, a counted
authorization failure included, without each command having to remember to. The file keeps
`write_atomic`'s guarantees: 0600, fsync, rename, then a directory fsync. The locality stays 0,
as the device grants only locality 0. `process` will take one when the device offers more.

The libkrun crates are a separate cargo workspace. Their `devices` crate depends on `vk-tpm`
by path, behind its `tpm` feature, and libkrun's lockfile gains the RustCrypto crates
`vk-tpm` uses, which are already in `vk`'s. `VK_LIBTPMS_DIR`, the `tpmLibs` flake output and
the NOTICE entries for libtpms/OpenSSL go away in the same change.

## State

Two blobs, each `magic (8 bytes) ‖ version (u16) ‖ fields`, in the TPM wire format. A reader
refuses an unknown version, a short blob or trailing bytes. It never guesses.

- **Permanent** (`VKTPM-P\0`): EPS, SPS, PPS (64 bytes each, random at manufacture); the
  owner, endorsement and lockout authValues and authPolicies; the platform, storage and
  endorsement proofs; disableClear; the PCR allocation from the next power on; the DA
  parameters, failed-tries counter and whether lockoutAuth may be tried; the last shutdown
  (none, none with a DA-protected authorization since, CLEAR, or STATE with the saved PCRs,
  their update counter, the enables and the platform authorization, and what a restart or a
  resume keeps: the null hierarchy's proof and seed, the clear and restart counts, the context
  counters and the saved sessions) and TPM time at that shutdown; the persistent objects (at
  most 16); resetCount and totalResetCount; Clock and whether it is safe. Later phases add NV
  indices.
- **Volatile** (`VKTPM-V\0`): whether Startup ran, whether it followed an orderly shutdown;
  TPM time and the DA timers; the hierarchy enables and the platform authorization; the PCR
  allocation in use; the PCRs and their update counter; the object slots (keys, and hash, HMAC
  and event sequences with their hash state); the session handles (free, a loaded session, or
  a saved session's context sequence number) and which session audits exclusively; the null
  hierarchy's proof and seed; the clear and restart counts; the context counters.

A key is stored as its public and sensitive areas (the TPM's wire format), its Name and
qualified name, its hierarchy and flags. An RSA key's private key is rebuilt from its prime
when the state is read, never stored.

Clock (TPM2_ReadClock) is in the permanent state, but a change to Clock alone does not mark it
changed (`take_permanent_changed`): it is stored with the next real change, as libtpms does.
Clock is safe again (and would be written to NV by the reference) each time it crosses a 2^12
ms boundary; a startup that does not follow an orderly shutdown makes it unsafe, since the
stored value may be behind one reported.

The version is bumped when a field is added; the reader accepts every older version and fills
the new fields with what a TPM upgraded from that version would have. A snapshot is restored
by the `vk` that took it, or a newer one. A state written by a newer `vk` is refused. Until a
`vk` stores a `vk-tpm` state outside tests, the format stays at version 1 and changes in
place.

A sequence's hash state is serialized as RustCrypto's `SerializableState` gives it (block
state, length, buffered bytes). That format belongs to the `sha1`/`sha2` crates: an upgrade
that changes it must bump the state version. An HMAC sequence is kept as RFC 2104 has it (the
inner hash, started with the key XOR ipad, and the padded key), since `hmac`'s state does not
serialize.

**Contexts.** A context (TPM2_ContextSave) holds the object or session as the volatile state
serializes it, after its sequence number, encrypted with AES-256-CFB under KDFa(SHA-512, the
hierarchy's proof, "CONTEXT", sequence, handle), with an HMAC-SHA512 under the proof over
totalResetCount, clearCount for an stClear object, the sequence, the handle and the ciphertext
(Part 1 30.3.2). No context loads after a TPM Reset (and a temporary object's never, the null
proof being new), nor an stClear object's after a Restart. The blob is `vk-tpm`'s own; around it
(sequence numbers, saved handles, hierarchies, the context gap, saved sessions keeping their
handles across a Restart) everything is the reference's. Windows pads TPM2_ContextLoad to
TPM_PT_MAX_OBJECT_CONTEXT; libtpms takes the padding, and so does `vk-tpm`.

**No migration from libtpms.** libtpms' blob is its internal NV layout, so converting it would
mean parsing `NVMarshal.c`'s format, including its seeds. A machine that switches engines gets
a new TPM: new seeds, so a new EK and SRK. Anything sealed to the old TPM is lost: BitLocker
asks for its recovery key once, then reseals, and Windows Hello keys must be re-enrolled. The
device must therefore recognize a libtpms state (its blob is not `VKTPM-P`) and fail loudly
rather than silently manufacture over it. `vk` then offers either to keep the libtpms build for
that machine or to reset its TPM explicitly. The default for new machines is decided when
phase 5 lands.

## Deviations from libtpms

Where `vk-tpm` answers differently from libtpms, on purpose (the differential tests exempt
exactly these):

- **Identity.** TPM_PT_MANUFACTURER, the vendor strings, the firmware version and SVN are
  ours; TPM_PT_TOTAL/LIBRARY_COMMANDS count what is implemented.
- **Not implemented** (yet, or out of scope): those commands are TPM_RC_COMMAND_CODE, and
  absent from TPM_CAP_COMMANDS; the algorithms are absent from TPM_CAP_ALGS. In
  TPM2_StartAuthSession, TDES, Camellia and SM4 are TPM_RC_SYMMETRIC, where libtpms'
  `default-v1` profile accepts them; a `tpmKey` is necessarily a sequence, so TPM_RC_KEY.
- **A failed Startup(STATE) keeps a pending DA failure.** libtpms clears its "DA used" mark
  before it checks the startup type, so the Startup(CLEAR) that follows forgets the failure
  it should count; `vk-tpm` refuses the command without changing anything.
- **Every Startup clears the "DA used" mark.** libtpms keeps it set through a Startup in
  lockout or with recoveryTime 0, and then does not mark the next DA-protected use, so losing
  power after it counts nothing; `vk-tpm` marks it, and counts the failure.
- **Persistence.** `vk-tpm` reports every change to the permanent state; libtpms skips writing
  a disabled lockoutAuth when lockoutRecovery is 0 (the next Startup re-enables it anyway).
- **Algorithms of phase 3.** Only NIST P-256: another curve is TPM_RC_CURVE where it is
  unmarshalled (libtpms' `default-v1` takes P-192 to P-521, BN-256/638, SM2), in
  TPM2_ECC_Parameters and TPM2_TestParms too; TDES, Camellia and SM4 keys are
  TPM_RC_SYMMETRIC. Schemes `vk-tpm` cannot run are taken as identifiers, as libtpms takes them,
  and fail where they would be used: signing or verifying with ECDAA, EC-Schnorr or SM2 is
  TPM_RC_SCHEME, and so is a CMAC (TPM2_MAC/MAC_Start with a symmetric key).
- **RSA primaries** are other keys than libtpms' from the same seeds (see Determinism).
- **Contexts** are `vk-tpm`'s blobs, of other sizes than libtpms'.
- **TPM2_Clear deletes the owner's and the endorsement's persistent objects**, as Part 3
  says; libtpms keeps them (its NvFlushHierarchy does not find their hierarchy).
- **TPM_PT_HR_PERSISTENT_AVAIL**: `vk-tpm` keeps at most 16 persistent objects; libtpms as many
  as its NV holds.
- **TPM2_StirRandom** takes the data and drops it: every random byte comes from the host's
  CSPRNG, which guest data cannot make better (libtpms mixes it into its own DRBG).
- **An RSA public key with an even exponent** cannot encrypt (RSAES, OAEP: TPM_RC_FAILURE);
  `rsa` refuses one. No TPM-made key has one.

Quirks of the reference implementation that `vk-tpm` keeps, so it answers the same:
TPM2_PCR_Allocate takes effect at the next power on and TPM2_Clear drops a pending one
(libtpms rewrites its whole PERSISTENT_DATA there); a PCR not allocated keeps its value
through a Startup; TPM2_DictionaryAttackParameters leaves failedTries alone; XOR parameter
obfuscation uses the session's hash, not the one its TPMT_SYM_DEF names; a session's first
audit unbinds it. And from phase 3: TPM2_Create answers TPM_RC_OBJECT_MEMORY when every slot is
taken, though it loads nothing; a persistent object a command names takes a slot for the
command (so a child loaded under a persistent parent gets the next slot's handle); a creation
ticket for the null hierarchy is an HMAC with the null proof; TPM2_RSA_Encrypt answers
TPM_RC_FAILURE for a message too long for its padding (OpenSSL's error); RSAES decryption never
fails on padding (implicit rejection); the platform may remove an owner's persistent object;
TPM2_Clear also starts Clock over.

## Security

- **Input bounds.** Every read goes through `Reader`, which bounds-checks and has no
  `unsafe`. The crate denies (through CI's `-D warnings`) clippy's `unwrap_used`,
  `expect_used`, `panic`, `indexing_slicing` and `arithmetic_side_effects` outside tests. A
  command is at most 0xf80 bytes, and every list is capped by its TPML maximum.
- **Constant time.** Authorization comparisons use `subtle::ConstantTimeEq`: passwords,
  command HMACs, policy digests, and a bound session's bind value (which holds the authValue).
  Secret-dependent crypto is left to RustCrypto's constant-time implementations; the RSA
  caveat is above.
- **Secrets.** Seeds and proofs are `Zeroizing<[u8; 64]>`; authValues, session keys, HMAC
  keys and KDF outputs are `Zeroizing`, and so are both serialized states, sensitive areas
  (authValue, seed, secret), wrapped and decrypted buffers, and the primary-key DRBG's state.
  `rsa`'s private keys wipe themselves; the prime search wipes its rejected candidates (the
  sieve's internal state is `crypto-primes`').
- **Entropy.** It comes from `getrandom`, the host's CSPRNG, for seeds, nonces, GetRandom,
  the secrets of ordinary objects, IVs, RSA blinding and ECDSA's hedged nonces. StirRandom
  changes nothing (see Deviations).
- **RSA** private operations are blinded and constant time, their decryption paddings too: see
  "RSA and the Marvin attack".
- **DA logic** follows `DA.c` and `SessionProcess.c`, with libtpms' build switches
  (`USE_DA_USED`, `ACCUMULATE_SELF_HEAL_TIMER`). A failure on a DA-protected entity, or
  through a session bound to one, counts; a non-orderly startup counts one failure if a
  DA-protected authValue was used since the last Startup; a failed lockoutAuth disables it
  until lockoutRecovery passes (or the next Startup, when that is 0). Failures are counted in
  the permanent state before the response leaves, so a guest cannot roll the counter back by
  crashing the VM. In phase 2, lockout is the only DA-protected entity: hierarchies, PCRs and
  sequences are exempt; a key is unless it has noDA. A key's authValue serves the USER role
  only with userWithAuth, the ADMIN role only without adminWithPolicy (a policy session is
  then required: TPM_RC_AUTH_TYPE, and TPM_RC_POLICY_FAIL until PolicyCommandCode exists).
- **Response size.** A response that would exceed the buffer is `TPM_RC_FAILURE`, never
  truncated.

## Test strategy

1. **Unit tests**, co-located and fast: marshalling, response codes, PCR semantics, state round
   trips, and the engine end to end (`src/tests.rs`).
2. **Differential tests against libtpms** (`tests/differential.rs`, feature `libtpms`).
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
   - Both TPMs can carry the same seeds and proofs: the test patches them into libtpms'
     stored PERSISTENT_DATA (found by its magic, the fields before them skipped by their
     sizes) and power-cycles it, and gives vk-tpm the same through a hidden setter that only
     the `libtpms` feature compiles. Hash tickets are compared byte for byte this way; later,
     names, policy digests, symmetric and keyed-hash primaries, RSASSA signatures, NV
     contents and Quote's attest structure.
   - Sessions carry each TPM's random nonces, so their HMACs cannot match byte for byte.
     A client written from Part 1 apart from the engine (`tests/client`) drives one session
     per TPM: it computes the command HMACs and parameter encryption, checks each TPM's
     response HMACs, decrypts the responses and compares them. This cross-checks KDFa, XOR
     and AES-CFB parameter encryption, cpHash/rpHash, bound, policy and audit sessions.
   - Randomized outputs are cross-verified instead: ECDSA/PSS signatures are verified by the
     other engine, and OAEP/RSAES ciphertexts are decrypted by the other.
   - Objects (`tests/objects`): ECC, keyed-hash and symmetric primaries of every hierarchy are
     compared byte for byte (with outside info, PCRs and a sealed secret in the creation
     data); RSA primaries by shape, each engine's signature verified by the other. Children
     each engine creates under the shared ECC storage key are loaded by both (sealed data,
     HMAC, ECDSA, storage and RSA-1024 keys), re-wrapped by ObjectChangeAuth and loaded again;
     tampered blobs are refused alike. A fixed RSA-2048 key (TPM2_LoadExternal) gives
     identical RSASSA signatures, raw RSA and RSAES implicit-rejection results; a fixed P-256
     key identical ECDH. Contexts are compared by header and by what loading them answers
     (objects, sessions, gap, restart, reset); persistent objects by handle lists and the
     slots they take; salted sessions (RSA-OAEP and ECDH salts) by the client checking each
     TPM's HMACs; templates, LoadExternal inputs and object authorization (roles, DA,
     bound and policy sessions) by response code.
   - A **mutation pass** flips bits in a corpus of well-formed commands with a fixed-seed
     xorshift: 60k commands over every implemented command, sessions and objects included, on
     seeded TPMs (re-seeded after a mutation that changes the seeds, after an RSA primary,
     and every 3000 commands). It compares both answers wherever the command is one `vk-tpm`
     implements, by shape where a session's nonce or a random value is in it (a context by its
     header), and skips an algorithm `vk-tpm` does not implement (re-seeding if libtpms made a
     key of it).
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
| 1 | **Done.** Crate, marshalling, RCs, state format; Startup, Shutdown, SelfTest, GetCapability, GetRandom, PCR_Read, PCR_Extend; password sessions; the libtpms differential harness | ~3 kLoC, half of it tests |
| 2 | **Done.** StartAuthSession (unsalted; bound or not; HMAC, policy, trial), HMAC sessions, cpHash/rpHash/names, parameter encryption (AES-CFB, XOR), audit sessions, KDFa/KDFe, DA logic, HierarchyControl, HierarchyChangeAuth, SetPrimaryPolicy, Clear, ClearControl, ChangeEPS, ChangePPS, DictionaryAttackLockReset/Parameters, PCR_Allocate/Reset/Event, Hash, hash and event sequences, FlushContext | ~5.5 kLoC, half of it tests |
| 3 | **Done.** Objects: TPMT_PUBLIC/SENSITIVE, protection (symmetric + integrity), CreatePrimary (deterministic), Create/Load/ReadPublic/Unseal/ObjectChangeAuth/LoadExternal, contexts (ContextSave/Load/Flush, saved sessions), EvictControl, Sign/VerifySignature, RSA_Encrypt/Decrypt, ECDH_KeyGen/ZGen, ECC_Parameters, RSA/ECC-salted sessions, HMAC/HMAC_Start and HMAC sequences, TestParms, StirRandom, GetTestResult, ReadClock (with Clock and the reset counters in the state) | ~6.5 kLoC, 40% of it tests |
| 4 | NV indices (all types and attributes), the policy commands (PolicyCommandCode then lets a policy session take the ADMIN role), attestation (Quote, Certify*, GetTime, audit digests, Make/ActivateCredential), EK provisioning at manufacture (EK at 0x81010001 and an EK certificate in 0x01C00002, signed by a per-host virtkit CA). Left over from phase 3: CreateLoaded, EncryptDecrypt(2) | ~4.5 kLoC |
| 5 | Integration: libkrun device on `vk-tpm`, MS-simulator socket server and the IBM TSS / tpm2-tools runs, fuzzing, Windows and Linux guest validation, removal of libtpms | ~1.5 kLoC + validation |
