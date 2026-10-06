// A TPM 2.0 for the guest (local patch, see VENDOR.md): virtkit's vk-tpm engine, linked into the
// VMM, behind the TCG PC Client CRB interface (Command Response Buffer) at a fixed MMIO address,
// as QEMU's tpm-crb device presents swtpm. The ACPI tables declare it (a TPM2 table, start method
// 7, and an MSFT0101 device), so the firmware measures the boot into it and Windows uses it
// (BitLocker, Windows 11's requirements).
//
// The TPM's permanent state (its seeds, NV indices, hierarchy auths) lives in a file the VMM keeps
// per machine, written each time a command changes it, before the guest sees the response.
// Commands run on the vCPU that starts them: the CRB register is busy until the response is in
// the buffer.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use log::error;
use vk_tpm::{EkKind, Tpm};
use zeroize::{Zeroize, Zeroizing};

use crate::bus::BusDevice;

/// The CRB interface's MMIO size: locality 0's registers and its command/response buffer.
pub const TPM_CRB_SIZE: u64 = 0x1000;
/// Where the command/response buffer starts in the CRB space, and its size.
const DATA_BUFFER: usize = 0x80;
const BUFFER_SIZE: usize = TPM_CRB_SIZE as usize - DATA_BUFFER;

// Register offsets (TCG PC Client Platform TPM Profile, CRB interface, locality 0).
const LOC_STATE: usize = 0x00;
const LOC_CTRL: usize = 0x08;
const LOC_STS: usize = 0x0c;
const INTF_ID: usize = 0x30;
const INTF_ID_HI: usize = 0x34;
const CTRL_REQ: usize = 0x40;
const CTRL_STS: usize = 0x44;
const CTRL_CANCEL: usize = 0x48;
const CTRL_START: usize = 0x4c;
const CTRL_CMD_SIZE: usize = 0x58;
const CTRL_CMD_LADDR: usize = 0x5c;
const CTRL_CMD_HADDR: usize = 0x60;
const CTRL_RSP_SIZE: usize = 0x64;
const CTRL_RSP_ADDR: usize = 0x68;

const LOC_STATE_ESTABLISHED: u32 = 1 << 0;
const LOC_STATE_ASSIGNED: u32 = 1 << 1;
const LOC_STATE_VALID: u32 = 1 << 7;
const LOC_CTRL_REQUEST_ACCESS: u32 = 1 << 0;
const LOC_CTRL_RELINQUISH: u32 = 1 << 1;
const LOC_STS_GRANTED: u32 = 1 << 0;
const CTRL_REQ_CMD_READY: u32 = 1 << 0;
const CTRL_REQ_GO_IDLE: u32 = 1 << 1;
const CTRL_STS_IDLE: u32 = 1 << 1;

/// INTF_ID: an active CRB interface (type 1, version 1), locality 0 only, 64-byte transfers, CRB
/// selected; INTF_ID_HI: the vendor and device ids QEMU uses (IBM, 1).
const INTF_ID_VALUE: u32 = 1 | (1 << 4) | (3 << 11) | (1 << 14) | (1 << 17);
const INTF_ID_HI_VALUE: u32 = 0x1014 | (1 << 16);

// vk-tpm takes the commands the buffer holds and answers within it.
const _: () = assert!(vk_tpm::MAX_COMMAND_SIZE == BUFFER_SIZE);

/// TPM_ST_NO_SESSIONS, 10 bytes, TPM_RC_FAILURE: every response once the TPM's state could not
/// be stored.
const FAILURE: [u8; 10] = [0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x01];

/// What a libtpms TPM's permanent state (its "permall" blob, NVMarshal.c) has after its u16
/// version: PERSISTENT_ALL_MAGIC.
const LIBTPMS_MAGIC: [u8; 4] = 0xab36_4723u32.to_be_bytes();

/// Write `bytes` at `path` whole or not at all, and durably, readable by its owner only: a
/// staging file beside it, synced, renamed over it, then the directory synced.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    // A crash's leftover; `create_new` refuses whatever else is there, a symlink included.
    match std::fs::remove_file(&tmp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)?;
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    File::open(dir.unwrap_or(Path::new(".")))?.sync_all()
}

/// Why `permanent`, the permanent state in `what`, starts no TPM. A libtpms TPM's (the engine
/// before vk-tpm) is named as such: its seeds cannot be carried over, so `remedy` says what the
/// owner can do instead.
fn state_error(what: &str, permanent: &[u8], e: vk_tpm::StateError, remedy: &str) -> io::Error {
    if permanent.get(2..6) == Some(&LIBTPMS_MAGIC[..]) {
        return io::Error::other(format!(
            "{what}: this machine's TPM state was made by libtpms, which this VMM no longer \
             runs, and it cannot be converted: {remedy}"
        ));
    }
    io::Error::other(format!("{what}: {e}"))
}

/// A new TPM, with the RSA 2048 and NIST P-256 endorsement keys of the EK Credential Profile's
/// default templates made persistent (0x81010001, 0x81010002), without certificates (see
/// docs/tpm-design.md, "EK certificate").
fn manufacture() -> io::Result<Tpm> {
    let mut tpm = Tpm::manufacture().map_err(io::Error::other)?;
    for kind in [EkKind::Rsa2048, EkKind::EccNistP256] {
        tpm.provision_endorsement_key(kind, None)
            .map_err(|rc| io::Error::other(format!("provisioning the {kind:?} EK: {rc:?}")))?;
    }
    Ok(tpm)
}

/// The TPM, its permanent state kept in a file.
struct Engine {
    tpm: Tpm,
    path: PathBuf,
    /// Storing the permanent state failed: the TPM answers TPM_RC_FAILURE from then on, as a
    /// TPM whose NV fails does, rather than go on from a state the file does not have.
    failed: bool,
}

impl Engine {
    /// The TPM whose permanent state is in `path` (a new TPM when the file is missing), or
    /// `saved`, a snapshot's, whose permanent state is first written to `path`.
    fn start(path: &Path, saved: Option<&TpmState>) -> io::Result<Engine> {
        let tpm = match saved {
            Some(saved) => {
                let tpm = Tpm::restore(&saved.permanent, &saved.volatile).map_err(|e| {
                    let remedy = "restore the snapshot with the vk that took it";
                    state_error("the snapshot's TPM", &saved.permanent, e, remedy)
                })?;
                // The machine's next start goes on from the snapshot's TPM.
                write_atomic(path, &saved.permanent)?;
                tpm
            }
            None => match std::fs::read(path) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    let mut tpm = manufacture()?;
                    write_atomic(path, &tpm.permanent_state())?;
                    // Stored: the first command needs no store of its own.
                    tpm.take_permanent_changed();
                    tpm
                }
                // Only a missing file is a new TPM: one that cannot be read fails the TPM rather
                // than have it replaced by a new one, whose keys would not open what the guest
                // sealed.
                Err(e) => {
                    let what = format!("reading {}: {e}", path.display());
                    return Err(io::Error::new(e.kind(), what));
                }
                Ok(bytes) => {
                    let bytes = Zeroizing::new(bytes);
                    Tpm::power_on(&bytes).map_err(|e| {
                        let remedy = "remove it to give the machine a new TPM; what the guest \
                                      sealed to the old one is lost (BitLocker then asks for its \
                                      recovery key)";
                        state_error(&path.display().to_string(), &bytes, e, remedy)
                    })?
                }
            },
        };
        Ok(Engine {
            tpm,
            path: path.to_path_buf(),
            failed: false,
        })
    }

    /// Run one command, returning its response, once what it changed in the permanent state
    /// is in the file.
    fn process(&mut self, command: &[u8]) -> Vec<u8> {
        if self.failed {
            return FAILURE.to_vec();
        }
        let response = self.tpm.process(command);
        if self.tpm.take_permanent_changed()
            && let Err(e) = write_atomic(&self.path, &self.tpm.permanent_state())
        {
            error!(
                "TPM: writing {}: {e}; it fails every command from now on",
                self.path.display()
            );
            self.failed = true;
            return FAILURE.to_vec();
        }
        response
    }
}

/// The device's state for a snapshot: the CRB's, and the TPM's permanent and volatile state,
/// so that a snapshot restores without the file the permanent state lives in. Wiped when
/// dropped: the TPM's state holds its seeds and session keys, the buffer the last response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "snapshot", derive(serde::Serialize, serde::Deserialize))]
pub struct TpmState {
    pub registers: Vec<u8>,
    pub buffer: Vec<u8>,
    pub permanent: Vec<u8>,
    pub volatile: Vec<u8>,
}

impl Drop for TpmState {
    fn drop(&mut self) {
        self.buffer.zeroize();
        self.permanent.zeroize();
        self.volatile.zeroize();
    }
}

/// The TPM's CRB interface, at `base`.
pub struct TpmCrb {
    engine: Engine,
    registers: [u8; DATA_BUFFER],
    buffer: Vec<u8>,
}

impl TpmCrb {
    /// A TPM whose permanent state is `state` (a new TPM when the file is missing), its CRB
    /// interface mapped at `base`; or, given `saved`, a snapshot's, the TPM it holds (its
    /// permanent state then replaces the file's).
    pub fn new(state: &Path, base: u64, saved: Option<&TpmState>) -> io::Result<TpmCrb> {
        if let Some(saved) = saved
            && (saved.registers.len() != DATA_BUFFER || saved.buffer.len() != BUFFER_SIZE)
        {
            return Err(io::Error::other("the TPM state is not a CRB's"));
        }
        let mut crb = TpmCrb {
            engine: Engine::start(state, saved)?,
            registers: [0; DATA_BUFFER],
            buffer: vec![0; BUFFER_SIZE],
        };
        if let Some(saved) = saved {
            crb.registers.copy_from_slice(&saved.registers);
            crb.buffer.copy_from_slice(&saved.buffer);
            return Ok(crb);
        }
        let buffer = base + DATA_BUFFER as u64;
        crb.set(LOC_STATE, LOC_STATE_VALID | LOC_STATE_ESTABLISHED);
        crb.set(INTF_ID, INTF_ID_VALUE);
        crb.set(INTF_ID_HI, INTF_ID_HI_VALUE);
        crb.set(CTRL_STS, CTRL_STS_IDLE);
        crb.set(CTRL_CMD_SIZE, BUFFER_SIZE as u32);
        crb.set(CTRL_CMD_LADDR, buffer as u32);
        crb.set(CTRL_CMD_HADDR, (buffer >> 32) as u32);
        crb.set(CTRL_RSP_SIZE, BUFFER_SIZE as u32);
        crb.set(CTRL_RSP_ADDR, buffer as u32);
        crb.set(CTRL_RSP_ADDR + 4, (buffer >> 32) as u32);
        Ok(crb)
    }

    fn get(&self, offset: usize) -> u32 {
        u32::from_le_bytes(self.registers[offset..offset + 4].try_into().unwrap())
    }

    fn set(&mut self, offset: usize, value: u32) {
        self.registers[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Whether a command may start, as on QEMU: locality 0 is the driver's and it has
    /// brought the interface out of idle (cmdReady).
    fn ready(&self) -> bool {
        self.get(LOC_STATE) & LOC_STATE_ASSIGNED != 0 && self.get(CTRL_STS) & CTRL_STS_IDLE == 0
    }

    /// Run the command in the buffer and put its response there.
    fn execute(&mut self) {
        let size = u32::from_be_bytes(self.buffer[2..6].try_into().unwrap()) as usize;
        let size = size.clamp(10, BUFFER_SIZE);
        let response = self.engine.process(&self.buffer[..size]);
        let len = response.len().min(BUFFER_SIZE);
        self.buffer[..len].copy_from_slice(&response[..len]);
    }

    pub fn save_state(&self) -> TpmState {
        TpmState {
            registers: self.registers.to_vec(),
            buffer: self.buffer.clone(),
            permanent: self.engine.tpm.permanent_state().to_vec(),
            volatile: self.engine.tpm.volatile_state().to_vec(),
        }
    }
}

impl BusDevice for TpmCrb {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        let offset = offset as usize;
        for (i, b) in data.iter_mut().enumerate() {
            let at = offset + i;
            *b = if at < DATA_BUFFER {
                self.registers[at]
            } else {
                self.buffer.get(at - DATA_BUFFER).copied().unwrap_or(0)
            };
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        let offset = offset as usize;
        if offset >= DATA_BUFFER {
            let at = offset - DATA_BUFFER;
            let end = (at + data.len()).min(BUFFER_SIZE);
            if at < end {
                self.buffer[at..end].copy_from_slice(&data[..end - at]);
            }
            return;
        }
        let mut word = [0u8; 4];
        let n = data.len().min(4);
        word[..n].copy_from_slice(&data[..n]);
        let value = u32::from_le_bytes(word);
        match offset {
            LOC_CTRL => {
                if value & LOC_CTRL_REQUEST_ACCESS != 0 {
                    self.set(LOC_STATE, self.get(LOC_STATE) | LOC_STATE_ASSIGNED);
                    self.set(LOC_STS, LOC_STS_GRANTED);
                }
                if value & LOC_CTRL_RELINQUISH != 0 {
                    self.set(LOC_STATE, self.get(LOC_STATE) & !LOC_STATE_ASSIGNED);
                    self.set(LOC_STS, 0);
                }
            }
            CTRL_REQ => {
                if value & CTRL_REQ_CMD_READY != 0 {
                    self.set(CTRL_STS, self.get(CTRL_STS) & !CTRL_STS_IDLE);
                }
                if value & CTRL_REQ_GO_IDLE != 0 {
                    self.set(CTRL_STS, self.get(CTRL_STS) | CTRL_STS_IDLE);
                }
            }
            // A command runs to completion before the write returns, so CTRL_START reads 0
            // again at once: nothing to cancel.
            CTRL_CANCEL => {}
            CTRL_START if value & 1 != 0 && self.ready() => self.execute(),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    const BASE: u64 = 0xfed4_0000;

    fn write32(crb: &mut TpmCrb, offset: usize, value: u32) {
        crb.write(0, offset as u64, &value.to_le_bytes());
    }

    fn read32(crb: &mut TpmCrb, offset: usize) -> u32 {
        let mut b = [0u8; 4];
        crb.read(0, offset as u64, &mut b);
        u32::from_le_bytes(b)
    }

    /// Send `command` the way a CRB driver does and return the response.
    fn transact(crb: &mut TpmCrb, command: &[u8]) -> Vec<u8> {
        write32(crb, LOC_CTRL, LOC_CTRL_REQUEST_ACCESS);
        assert_eq!(read32(crb, LOC_STS) & LOC_STS_GRANTED, LOC_STS_GRANTED);
        write32(crb, CTRL_REQ, CTRL_REQ_CMD_READY);
        assert_eq!(read32(crb, CTRL_STS) & CTRL_STS_IDLE, 0);
        crb.write(0, DATA_BUFFER as u64, command);
        write32(crb, CTRL_START, 1);
        assert_eq!(read32(crb, CTRL_START), 0, "the command has completed");
        let mut header = [0u8; 10];
        crb.read(0, DATA_BUFFER as u64, &mut header);
        let size = u32::from_be_bytes(header[2..6].try_into().unwrap()) as usize;
        let mut response = vec![0u8; size];
        crb.read(0, DATA_BUFFER as u64, &mut response);
        write32(crb, CTRL_REQ, CTRL_REQ_GO_IDLE);
        response
    }

    fn rc(response: &[u8]) -> u32 {
        u32::from_be_bytes(response[6..10].try_into().unwrap())
    }

    /// A fresh directory for one test's state file.
    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("krun-tpm-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    const STARTUP_CLEAR: [u8; 12] = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x44, 0, 0];
    const GET_RANDOM_8: [u8; 12] = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7b, 0, 8];

    /// A command: `tag`, then `code`, `handles` and, with sessions, the empty password session
    /// (TPM_RS_PW) for each handle that takes one, then `params`.
    fn command(code: u32, handles: &[u32], auths: usize, params: &[u8]) -> Vec<u8> {
        let tag: u16 = if auths > 0 { 0x8002 } else { 0x8001 };
        let mut c = tag.to_be_bytes().to_vec();
        c.extend([0; 4]);
        c.extend(code.to_be_bytes());
        for handle in handles {
            c.extend(handle.to_be_bytes());
        }
        if auths > 0 {
            c.extend((9 * auths as u32).to_be_bytes());
            for _ in 0..auths {
                c.extend([0x40, 0, 0, 0x09, 0, 0, 0, 0, 0]);
            }
        }
        c.extend(params);
        let size = c.len() as u32;
        c[2..6].copy_from_slice(&size.to_be_bytes());
        c
    }

    /// A TPM2B of `bytes`.
    fn sized(bytes: &[u8]) -> Vec<u8> {
        let mut out = (bytes.len() as u16).to_be_bytes().to_vec();
        out.extend(bytes);
        out
    }

    /// Read the TPM2B at `*at` in `response`, moving past it.
    fn take_sized<'a>(response: &'a [u8], at: &mut usize) -> &'a [u8] {
        let len = u16::from_be_bytes(response[*at..*at + 2].try_into().unwrap()) as usize;
        let out = &response[*at..*at + 2 + len];
        *at += 2 + len;
        out
    }

    fn u32_at(response: &[u8], at: usize) -> u32 {
        u32::from_be_bytes(response[at..at + 4].try_into().unwrap())
    }

    /// Seal `secret` under a new ECC P-256 storage primary of the owner and load it, through
    /// the CRB; returns the sealed object's handle.
    fn seal(crb: &mut TpmCrb, secret: &[u8]) -> u32 {
        const TPM_CC_CREATE_PRIMARY: u32 = 0x131;
        const TPM_CC_CREATE: u32 = 0x153;
        const TPM_CC_LOAD: u32 = 0x157;
        // An empty authValue and no data.
        let no_sensitive = sized(&[0, 0, 0, 0]);
        // ECC, SHA-256; fixedTPM, fixedParent, sensitiveDataOrigin, userWithAuth, noDA,
        // restricted, decrypt; no policy; AES-128-CFB, no scheme, NIST P-256, no KDF; empty
        // point.
        let storage = sized(&[
            0x00, 0x23, 0x00, 0x0b, 0x00, 0x03, 0x04, 0x72, 0x00, 0x00, 0x00, 0x06, 0x00, 0x80,
            0x00, 0x43, 0x00, 0x10, 0x00, 0x03, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
        ]);
        let no_creation = [0, 0, 0, 0, 0, 0];
        let params = [no_sensitive, storage, no_creation.to_vec()].concat();
        let primary = transact(
            crb,
            &command(TPM_CC_CREATE_PRIMARY, &[0x4000_0001], 1, &params),
        );
        assert_eq!(rc(&primary), 0);
        let parent = u32_at(&primary, 10);

        // KEYEDHASH, SHA-256; fixedTPM, fixedParent, userWithAuth, noDA; no policy, no scheme.
        let sensitive = sized(&[&[0, 0][..], &sized(secret)].concat());
        let sealed = sized(&[
            0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x04, 0x52, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
        ]);
        let params = [sensitive, sealed, no_creation.to_vec()].concat();
        let created = transact(crb, &command(TPM_CC_CREATE, &[parent], 1, &params));
        assert_eq!(rc(&created), 0);
        let mut at = 14; // the header, then parameterSize
        let private = take_sized(&created, &mut at).to_vec();
        let public = take_sized(&created, &mut at).to_vec();

        let loaded = transact(
            crb,
            &command(TPM_CC_LOAD, &[parent], 1, &[private, public].concat()),
        );
        assert_eq!(rc(&loaded), 0);
        u32_at(&loaded, 10)
    }

    /// What TPM2_Unseal returns for the object at `handle`.
    fn unseal(crb: &mut TpmCrb, handle: u32) -> Vec<u8> {
        const TPM_CC_UNSEAL: u32 = 0x15e;
        let response = transact(crb, &command(TPM_CC_UNSEAL, &[handle], 1, &[]));
        assert_eq!(rc(&response), 0);
        let mut at = 14;
        take_sized(&response, &mut at)[2..].to_vec()
    }

    /// PCR 16's SHA-256 bank, through TPM2_PCR_Read.
    fn read_pcr16(crb: &mut TpmCrb) -> Vec<u8> {
        const TPM_CC_PCR_READ: u32 = 0x17e;
        // One selection: SHA-256, 3 bytes, PCR 16.
        let selection = [0, 0, 0, 1, 0x00, 0x0b, 3, 0, 0, 1];
        let response = transact(crb, &command(TPM_CC_PCR_READ, &[], 0, &selection));
        assert_eq!(rc(&response), 0);
        // The update counter, the selection read, one digest.
        let at = 10 + 4 + selection.len() + 4;
        response[at + 2..].to_vec()
    }

    #[test]
    fn a_crb_tpm_answers_commands_keeps_its_state_and_snapshots() {
        let dir = test_dir("crb");
        let state = dir.join("tpm-state");

        let mut crb = TpmCrb::new(&state, BASE, None).unwrap();
        assert_eq!(
            read32(&mut crb, INTF_ID) & 0xf,
            1,
            "an active CRB interface"
        );
        assert_eq!(read32(&mut crb, CTRL_CMD_LADDR), 0xfed4_0080);
        assert_eq!(read32(&mut crb, CTRL_CMD_SIZE), 0xf80);
        assert!(
            std::fs::metadata(&state).unwrap().len() > 0,
            "a new TPM, stored"
        );
        assert_eq!(mode(&state), 0o600);

        // START does nothing until the driver has the locality and the interface is ready.
        crb.write(0, DATA_BUFFER as u64, &STARTUP_CLEAR);
        write32(&mut crb, CTRL_START, 1);
        write32(&mut crb, LOC_CTRL, LOC_CTRL_REQUEST_ACCESS);
        write32(&mut crb, CTRL_START, 1);
        let mut buffer = [0u8; 12];
        crb.read(0, DATA_BUFFER as u64, &mut buffer);
        assert_eq!(buffer, STARTUP_CLEAR, "START ran a command");

        assert_eq!(rc(&transact(&mut crb, &STARTUP_CLEAR)), 0);
        // The EKs are there, persistent (TPM2_ReadPublic).
        for ek in [0x8101_0001, 0x8101_0002] {
            assert_eq!(rc(&transact(&mut crb, &command(0x173, &[ek], 0, &[]))), 0);
        }
        let random = transact(&mut crb, &GET_RANDOM_8);
        assert_eq!(rc(&random), 0);
        assert_eq!(random.len(), 10 + 2 + 8);

        // PCR 16 (debug) starts at zeros; extending it hashes the digest in.
        const TPM_CC_PCR_EXTEND: u32 = 0x182;
        assert_eq!(read_pcr16(&mut crb), [0; 32]);
        let extend = [&[0, 0, 0, 1, 0x00, 0x0b][..], &[0xa5; 32]].concat();
        let extended = transact(&mut crb, &command(TPM_CC_PCR_EXTEND, &[16], 1, &extend));
        assert_eq!(rc(&extended), 0);
        let pcr = read_pcr16(&mut crb);
        assert_ne!(pcr, [0; 32]);

        // A secret sealed through the CRB unseals; a snapshot taken then (without the file)
        // restores a started TPM with the object loaded and the PCR as it was: a second
        // Startup is refused (TPM_RC_INITIALIZE).
        let sealed = seal(&mut crb, b"the disk key");
        assert_eq!(unseal(&mut crb, sealed), b"the disk key");
        let saved = crb.save_state();
        drop(crb);
        std::fs::remove_file(&state).unwrap();
        let mut crb = TpmCrb::new(&state, BASE, Some(&saved)).unwrap();
        assert_eq!(read32(&mut crb, CTRL_CMD_LADDR), 0xfed4_0080);
        assert_eq!(rc(&transact(&mut crb, &STARTUP_CLEAR)), 0x100);
        assert_eq!(unseal(&mut crb, sealed), b"the disk key");
        assert_eq!(read_pcr16(&mut crb), pcr);
        assert_eq!(std::fs::read(&state).unwrap(), saved.permanent);
        assert_eq!(mode(&state), 0o600);
        // Two TPMs run side by side, each on its own state.
        let other = TpmCrb::new(&dir.join("other"), BASE, None).unwrap();
        drop((crb, other));

        // The same file brings back the same TPM, which starts as after a power cycle: the
        // object and the PCR are gone, the seeds are not.
        let mut crb = TpmCrb::new(&state, BASE, None).unwrap();
        assert_eq!(rc(&transact(&mut crb, &STARTUP_CLEAR)), 0);
        assert_eq!(read_pcr16(&mut crb), [0; 32]);
        let resealed = seal(&mut crb, b"again");
        assert_eq!(unseal(&mut crb, resealed), b"again");
        drop(crb);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_state_file_that_is_no_vk_tpm_state_fails_the_tpm_and_is_kept() {
        let dir = test_dir("foreign");
        let state = dir.join("tpm-state");

        // An empty file is a TPM lost, not a new one.
        std::fs::write(&state, b"").unwrap();
        assert!(TpmCrb::new(&state, BASE, None).is_err());
        assert!(std::fs::read(&state).unwrap().is_empty());

        // libtpms' permanent state: its version, then its magic.
        let libtpms = [0, 4, 0xab, 0x36, 0x47, 0x23, 0, 4, 2, 0x9f];
        std::fs::write(&state, libtpms).unwrap();
        let err = TpmCrb::new(&state, BASE, None).err().unwrap().to_string();
        assert!(err.contains("made by libtpms"), "{err}");
        assert_eq!(std::fs::read(&state).unwrap(), libtpms);

        // Nor does a snapshot of a libtpms TPM restore.
        let saved = TpmState {
            registers: vec![0; DATA_BUFFER],
            buffer: vec![0; BUFFER_SIZE],
            permanent: libtpms.to_vec(),
            volatile: vec![0; 16],
        };
        let err = TpmCrb::new(&dir.join("restored"), BASE, Some(&saved))
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("made by libtpms"), "{err}");
        assert!(!dir.join("restored").exists());

        // An unreadable file is refused as well (a directory in its place here).
        let unreadable = dir.join("unreadable");
        std::fs::create_dir(&unreadable).unwrap();
        assert!(TpmCrb::new(&unreadable, BASE, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_tpm_whose_state_cannot_be_stored_fails_every_command() {
        let dir = test_dir("unwritable");
        let state = dir.join("tpm-state");
        let mut crb = TpmCrb::new(&state, BASE, None).unwrap();
        let stored = std::fs::read(&state).unwrap();
        // The staging file can no longer be made (root makes it anyway: nothing to test).
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        if std::fs::write(dir.join("probe"), b"").is_err() {
            // TPM2_Startup is the first command to change the permanent state (resetCount).
            assert_eq!(rc(&transact(&mut crb, &STARTUP_CLEAR)), 0x101);
            assert_eq!(rc(&transact(&mut crb, &GET_RANDOM_8)), 0x101);
            assert_eq!(std::fs::read(&state).unwrap(), stored);
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
