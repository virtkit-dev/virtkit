// A TPM 2.0 for the guest (local patch, see VENDOR.md): libtpms, linked into the VMM, behind the
// TCG PC Client CRB interface (Command Response Buffer) at a fixed MMIO address, as QEMU's
// tpm-crb device presents swtpm. The ACPI tables declare it (a TPM2 table, start method 7, and an
// MSFT0101 device), so the firmware measures the boot into it and Windows uses it (BitLocker,
// Windows 11's requirements).
//
// The TPM's permanent state (its seeds, NV indices, hierarchy auths) lives in a file the VMM keeps
// per machine, written each time the TPM changes it. Commands run on the vCPU that starts them:
// the CRB register is busy until the response is in the buffer.

use std::ffi::{CStr, c_char, c_int};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use log::error;

use crate::bus::BusDevice;

mod ffi {
    use std::ffi::{c_char, c_int};

    pub const TPM_SUCCESS: u32 = 0;
    pub const TPM_FAIL: u32 = 9;
    /// No such state yet: libtpms then manufactures a new TPM.
    pub const TPM_RETRY: u32 = 0x800;
    pub const TPMLIB_TPM_VERSION_2: c_int = 1;
    pub const TPMLIB_STATE_PERMANENT: c_int = 1 << 0;
    pub const TPMLIB_STATE_VOLATILE: c_int = 1 << 1;

    #[repr(C)]
    pub struct Callbacks {
        pub size_of_struct: c_int,
        pub nvram_init: Option<extern "C" fn() -> u32>,
        pub nvram_loaddata:
            Option<unsafe extern "C" fn(*mut *mut u8, *mut u32, u32, *const c_char) -> u32>,
        pub nvram_storedata:
            Option<unsafe extern "C" fn(*const u8, u32, u32, *const c_char) -> u32>,
        pub nvram_deletename: Option<unsafe extern "C" fn(u32, *const c_char, u8) -> u32>,
        pub io_init: Option<extern "C" fn() -> u32>,
        pub io_getlocality: Option<unsafe extern "C" fn(*mut u32, u32) -> u32>,
        pub io_getphysicalpresence: Option<unsafe extern "C" fn(*mut u8, u32) -> u32>,
    }

    unsafe extern "C" {
        pub fn TPMLIB_ChooseTPMVersion(version: c_int) -> u32;
        pub fn TPMLIB_RegisterCallbacks(callbacks: *mut Callbacks) -> u32;
        pub fn TPMLIB_SetBufferSize(wanted: u32, min: *mut u32, max: *mut u32) -> u32;
        pub fn TPMLIB_SetProfile(profile: *const c_char) -> u32;
        pub fn TPMLIB_SetState(state: c_int, buffer: *const u8, len: u32) -> u32;
        pub fn TPMLIB_GetState(state: c_int, buffer: *mut *mut u8, len: *mut u32) -> u32;
        pub fn TPMLIB_MainInit() -> u32;
        pub fn TPMLIB_Terminate();
        pub fn TPMLIB_Process(
            response: *mut *mut u8,
            response_size: *mut u32,
            response_buffer_size: *mut u32,
            command: *mut u8,
            command_size: u32,
        ) -> u32;
    }
}

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

/// The profile a new TPM is manufactured with: every command and algorithm libtpms has. A TPM's
/// state carries its profile, which libtpms keeps over this one.
const PROFILE: &CStr = c"{\"Name\":\"default-v1\"}";

/// The file the running TPM keeps its permanent state in, for libtpms' callbacks.
static PERMANENT_STATE: Mutex<Option<PathBuf>> = Mutex::new(None);
/// libtpms is one TPM per process.
static RUNNING: AtomicBool = AtomicBool::new(false);

/// The name libtpms gives its permanent state.
const PERMANENT: &CStr = c"permall";

fn name_is_permanent(name: *const c_char) -> bool {
    // SAFETY: libtpms passes a NUL-terminated name.
    !name.is_null() && unsafe { CStr::from_ptr(name) } == PERMANENT
}

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

extern "C" fn nvram_init() -> u32 {
    ffi::TPM_SUCCESS
}

unsafe extern "C" fn nvram_loaddata(
    data: *mut *mut u8,
    length: *mut u32,
    _tpm_number: u32,
    name: *const c_char,
) -> u32 {
    if !name_is_permanent(name) {
        return ffi::TPM_RETRY;
    }
    let Some(path) = PERMANENT_STATE.lock().unwrap().clone() else {
        return ffi::TPM_FAIL;
    };
    // Only a missing file is a new TPM: one that cannot be read fails the TPM rather than
    // have it replaced by a new one, whose keys would not open what the guest sealed.
    let bytes = match std::fs::read(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return ffi::TPM_RETRY,
        Err(e) => {
            error!("TPM: reading {}: {e}", path.display());
            return ffi::TPM_FAIL;
        }
        Ok(bytes) if bytes.is_empty() => {
            error!("TPM: {} is empty", path.display());
            return ffi::TPM_FAIL;
        }
        Ok(bytes) => bytes,
    };
    let Ok(len) = u32::try_from(bytes.len()) else {
        return ffi::TPM_FAIL;
    };
    // libtpms frees what it is given with free().
    // SAFETY: malloc of the state's size; the copy fills exactly that.
    unsafe {
        let buffer = libc::malloc(bytes.len()).cast::<u8>();
        if buffer.is_null() {
            return ffi::TPM_FAIL;
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len());
        *data = buffer;
        *length = len;
    }
    ffi::TPM_SUCCESS
}

unsafe extern "C" fn nvram_storedata(
    data: *const u8,
    length: u32,
    _tpm_number: u32,
    name: *const c_char,
) -> u32 {
    // The volatile state goes with a snapshot instead (`TpmCrb::save_state`).
    if !name_is_permanent(name) {
        return ffi::TPM_SUCCESS;
    }
    let Some(path) = PERMANENT_STATE.lock().unwrap().clone() else {
        return ffi::TPM_FAIL;
    };
    // SAFETY: libtpms passes `length` readable bytes.
    let bytes = unsafe { std::slice::from_raw_parts(data, length as usize) };
    match write_atomic(&path, bytes) {
        Ok(()) => ffi::TPM_SUCCESS,
        Err(e) => {
            error!("TPM: writing {}: {e}", path.display());
            ffi::TPM_FAIL
        }
    }
}

unsafe extern "C" fn nvram_deletename(_tpm_number: u32, _name: *const c_char, _must: u8) -> u32 {
    ffi::TPM_SUCCESS
}

extern "C" fn io_init() -> u32 {
    ffi::TPM_SUCCESS
}

unsafe extern "C" fn io_getlocality(locality: *mut u32, _tpm_number: u32) -> u32 {
    // SAFETY: libtpms passes a valid pointer.
    unsafe { *locality = 0 };
    ffi::TPM_SUCCESS
}

unsafe extern "C" fn io_getphysicalpresence(present: *mut u8, _tpm_number: u32) -> u32 {
    // SAFETY: libtpms passes a valid pointer.
    unsafe { *present = 0 };
    ffi::TPM_SUCCESS
}

/// libtpms, started: a TPM 2.0 whose permanent state is a file.
///
/// An `Engine` exists exactly while libtpms is started in this process (`RUNNING`), and only
/// dropping it terminates libtpms, once: it is never started again under the same `Engine`.
struct Engine;

impl Engine {
    /// Start the TPM on the permanent state in `state` (a new TPM when the file is missing),
    /// or on `saved`, a snapshot's, whose permanent state is first written to `state`.
    fn start(state: &Path, saved: Option<&TpmState>) -> io::Result<Engine> {
        if RUNNING.swap(true, Ordering::SeqCst) {
            return Err(io::Error::other("a TPM is already running in this process"));
        }
        *PERMANENT_STATE.lock().unwrap() = Some(state.to_path_buf());
        // From here, dropping it undoes the above, and terminates libtpms (which frees what a
        // failed start allocated).
        let engine = Engine;
        let mut callbacks = ffi::Callbacks {
            size_of_struct: std::mem::size_of::<ffi::Callbacks>() as c_int,
            nvram_init: Some(nvram_init),
            nvram_loaddata: Some(nvram_loaddata),
            nvram_storedata: Some(nvram_storedata),
            nvram_deletename: Some(nvram_deletename),
            io_init: Some(io_init),
            io_getlocality: Some(io_getlocality),
            io_getphysicalpresence: Some(io_getphysicalpresence),
        };
        let check = |what: &str, rc: u32| {
            if rc == ffi::TPM_SUCCESS {
                Ok(())
            } else {
                Err(io::Error::other(format!("libtpms {what}: error {rc:#x}")))
            }
        };
        let set_state = |what: &str, kind: c_int, blob: &[u8]| {
            let len = u32::try_from(blob.len()).map_err(io::Error::other)?;
            // SAFETY: libtpms copies `len` bytes of `blob`.
            check(what, unsafe {
                ffi::TPMLIB_SetState(kind, blob.as_ptr(), len)
            })
        };
        // SAFETY: libtpms' documented start sequence; it copies the callbacks and the profile.
        unsafe {
            check(
                "version",
                ffi::TPMLIB_ChooseTPMVersion(ffi::TPMLIB_TPM_VERSION_2),
            )?;
            check("callbacks", ffi::TPMLIB_RegisterCallbacks(&mut callbacks))?;
            // Exactly the CRB buffer, which the TPM then reports: a larger one would let a
            // response overflow it, a smaller one refuse commands the CRB takes.
            let size = ffi::TPMLIB_SetBufferSize(
                BUFFER_SIZE as u32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if size as usize != BUFFER_SIZE {
                return Err(io::Error::other(format!(
                    "libtpms takes a {size}-byte buffer, not the CRB's {BUFFER_SIZE}"
                )));
            }
            check("profile", ffi::TPMLIB_SetProfile(PROFILE.as_ptr()))?;
        }
        // The permanent state first, as libtpms requires, then the volatile one; MainInit
        // takes them instead of loading the file, which keeps the permanent state for the
        // machine's next start.
        if let Some(saved) = saved {
            write_atomic(state, &saved.permanent)?;
            set_state(
                "permanent state",
                ffi::TPMLIB_STATE_PERMANENT,
                &saved.permanent,
            )?;
            set_state(
                "volatile state",
                ffi::TPMLIB_STATE_VOLATILE,
                &saved.volatile,
            )?;
        }
        // SAFETY: as above.
        check("init", unsafe { ffi::TPMLIB_MainInit() })?;
        Ok(engine)
    }

    /// Run one command, returning its response; a failure is a TPM_RC_FAILURE response.
    fn process(&mut self, command: &[u8]) -> Vec<u8> {
        let mut command = command.to_vec();
        let mut response: *mut u8 = std::ptr::null_mut();
        let (mut size, mut capacity) = (0u32, 0u32);
        // SAFETY: libtpms allocates the response with malloc; it is copied, then freed.
        unsafe {
            let rc = ffi::TPMLIB_Process(
                &mut response,
                &mut size,
                &mut capacity,
                command.as_mut_ptr(),
                command.len() as u32,
            );
            let out = if rc == ffi::TPM_SUCCESS && !response.is_null() {
                std::slice::from_raw_parts(response, size as usize).to_vec()
            } else {
                error!("TPM: processing a command failed ({rc:#x})");
                // TPM_ST_NO_SESSIONS, 10 bytes, TPM_RC_FAILURE.
                vec![0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x01, 0x01]
            };
            libc::free(response.cast());
            out
        }
    }

    /// The running TPM's permanent or volatile (PCRs, loaded objects, sessions) state.
    fn state(&self, kind: c_int) -> io::Result<Vec<u8>> {
        let mut buffer: *mut u8 = std::ptr::null_mut();
        let mut len = 0u32;
        // SAFETY: libtpms allocates the state with malloc; it is copied, then freed.
        unsafe {
            let rc = ffi::TPMLIB_GetState(kind, &mut buffer, &mut len);
            let out = (rc == ffi::TPM_SUCCESS && !buffer.is_null())
                .then(|| std::slice::from_raw_parts(buffer, len as usize).to_vec());
            libc::free(buffer.cast());
            out.ok_or_else(|| io::Error::other(format!("libtpms state {kind}: error {rc:#x}")))
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: libtpms was started (or its start attempted) in `start`.
        unsafe { ffi::TPMLIB_Terminate() };
        *PERMANENT_STATE.lock().unwrap() = None;
        RUNNING.store(false, Ordering::SeqCst);
    }
}

/// The device's state for a snapshot: the CRB's, and the TPM's permanent and volatile state,
/// so that a snapshot restores without the file the permanent state lives in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "snapshot", derive(serde::Serialize, serde::Deserialize))]
pub struct TpmState {
    pub registers: Vec<u8>,
    pub buffer: Vec<u8>,
    pub permanent: Vec<u8>,
    pub volatile: Vec<u8>,
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

    pub fn save_state(&self) -> io::Result<TpmState> {
        Ok(TpmState {
            registers: self.registers.to_vec(),
            buffer: self.buffer.clone(),
            permanent: self.engine.state(ffi::TPMLIB_STATE_PERMANENT)?,
            volatile: self.engine.state(ffi::TPMLIB_STATE_VOLATILE)?,
        })
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

    const STARTUP_CLEAR: [u8; 12] = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x44, 0, 0];
    const GET_RANDOM_8: [u8; 12] = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x7b, 0, 8];

    /// The running TPM's profile, as libtpms reports it.
    fn active_profile() -> String {
        unsafe extern "C" {
            fn TPMLIB_GetInfo(flags: c_int) -> *mut c_char;
        }
        const TPMLIB_INFO_ACTIVE_PROFILE: c_int = 32;
        // SAFETY: libtpms returns a malloc'd NUL-terminated string, copied then freed.
        unsafe {
            let info = TPMLIB_GetInfo(TPMLIB_INFO_ACTIVE_PROFILE);
            assert!(!info.is_null());
            let out = CStr::from_ptr(info).to_string_lossy().into_owned();
            libc::free(info.cast());
            out
        }
    }

    // libtpms is one TPM per process: every TPM of the tests is in this one.
    #[test]
    fn a_crb_tpm_answers_commands_keeps_its_state_and_snapshots() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("krun-tpm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
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
            TpmCrb::new(&state, BASE, None).is_err(),
            "one TPM per process"
        );
        assert!(
            active_profile().contains("default-v1"),
            "{}",
            active_profile()
        );

        // START does nothing until the driver has the locality and the interface is ready.
        crb.write(0, DATA_BUFFER as u64, &STARTUP_CLEAR);
        write32(&mut crb, CTRL_START, 1);
        write32(&mut crb, LOC_CTRL, LOC_CTRL_REQUEST_ACCESS);
        write32(&mut crb, CTRL_START, 1);
        let mut buffer = [0u8; 12];
        crb.read(0, DATA_BUFFER as u64, &mut buffer);
        assert_eq!(buffer, STARTUP_CLEAR, "START ran a command");

        assert_eq!(rc(&transact(&mut crb, &STARTUP_CLEAR)), 0);
        let random = transact(&mut crb, &GET_RANDOM_8);
        assert_eq!(rc(&random), 0);
        assert_eq!(random.len(), 10 + 2 + 8);
        let metadata = std::fs::metadata(&state).unwrap();
        assert!(metadata.len() > 0, "the new TPM wrote its permanent state");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

        // A snapshot taken after startup restores a started TPM, without the file: a second
        // Startup is refused (TPM_RC_INITIALIZE), and the TPM keeps serving commands.
        let saved = crb.save_state().unwrap();
        assert!(!saved.permanent.is_empty());
        drop(crb);
        std::fs::remove_file(&state).unwrap();
        let mut crb = TpmCrb::new(&state, BASE, Some(&saved)).unwrap();
        assert_eq!(read32(&mut crb, CTRL_CMD_LADDR), 0xfed4_0080);
        assert_eq!(rc(&transact(&mut crb, &STARTUP_CLEAR)), 0x100);
        assert_eq!(rc(&transact(&mut crb, &GET_RANDOM_8)), 0);
        let permanent = std::fs::read(&state).expect("the restore wrote the permanent state");
        assert_eq!(
            std::fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(crb);

        // The same file brings back the same TPM, which starts as after a power cycle.
        let mut crb = TpmCrb::new(&state, BASE, None).unwrap();
        assert_eq!(rc(&transact(&mut crb, &STARTUP_CLEAR)), 0);
        assert_eq!(std::fs::read(&state).unwrap().len(), permanent.len());
        drop(crb);

        // An empty file is a TPM lost, not a new one.
        std::fs::write(&state, b"").unwrap();
        assert!(TpmCrb::new(&state, BASE, None).is_err());
        assert!(std::fs::read(&state).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
