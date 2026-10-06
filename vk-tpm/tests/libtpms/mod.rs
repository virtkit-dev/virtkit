//! libtpms, the reference the differential tests compare against: one TPM per process, behind
//! a lock, with its permanent state kept in memory so a test can power-cycle it.

#![allow(unsafe_code)]

use std::ffi::{CStr, c_char, c_int};
use std::sync::{Mutex, MutexGuard};

mod ffi {
    use std::ffi::{c_char, c_int};

    pub const TPM_SUCCESS: u32 = 0;
    pub const TPM_FAIL: u32 = 9;
    pub const TPM_RETRY: u32 = 0x800;
    pub const TPMLIB_TPM_VERSION_2: c_int = 1;

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

    // build.rs puts VK_LIBTPMS_DIR/lib on the search path; libtpms needs libcrypto after it.
    #[link(name = "tpms", kind = "static")]
    unsafe extern "C" {
        pub fn TPMLIB_ChooseTPMVersion(version: c_int) -> u32;
        pub fn TPMLIB_RegisterCallbacks(callbacks: *mut Callbacks) -> u32;
        pub fn TPMLIB_SetBufferSize(wanted: u32, min: *mut u32, max: *mut u32) -> u32;
        pub fn TPMLIB_SetProfile(profile: *const c_char) -> u32;
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

    #[link(name = "crypto", kind = "static")]
    unsafe extern "C" {}

    unsafe extern "C" {
        pub fn malloc(size: usize) -> *mut u8;
        pub fn free(ptr: *mut u8);
    }
}

/// The permanent state libtpms last stored ("permall"), and whether one is running.
struct Shared {
    permanent: Option<Vec<u8>>,
    running: bool,
}

static SHARED: Mutex<Shared> = Mutex::new(Shared {
    permanent: None,
    running: false,
});
/// Serializes the tests: libtpms is one TPM per process.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn shared() -> MutexGuard<'static, Shared> {
    SHARED.lock().unwrap_or_else(|e| e.into_inner())
}

fn is_permanent(name: *const c_char) -> bool {
    // SAFETY: libtpms passes a NUL-terminated name.
    !name.is_null() && unsafe { CStr::from_ptr(name) } == c"permall"
}

extern "C" fn ok() -> u32 {
    ffi::TPM_SUCCESS
}

unsafe extern "C" fn load(
    data: *mut *mut u8,
    length: *mut u32,
    _: u32,
    name: *const c_char,
) -> u32 {
    let Some(state) = shared().permanent.clone().filter(|_| is_permanent(name)) else {
        return ffi::TPM_RETRY;
    };
    // SAFETY: libtpms frees what it is given with free(); the copy fills the allocation.
    unsafe {
        let buffer = ffi::malloc(state.len());
        if buffer.is_null() {
            return ffi::TPM_FAIL;
        }
        std::ptr::copy_nonoverlapping(state.as_ptr(), buffer, state.len());
        *data = buffer;
        *length = state.len() as u32;
    }
    ffi::TPM_SUCCESS
}

unsafe extern "C" fn store(data: *const u8, length: u32, _: u32, name: *const c_char) -> u32 {
    if is_permanent(name) {
        // SAFETY: libtpms passes `length` readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(data, length as usize) };
        shared().permanent = Some(bytes.to_vec());
    }
    ffi::TPM_SUCCESS
}

unsafe extern "C" fn delete(_: u32, _: *const c_char, _: u8) -> u32 {
    ffi::TPM_SUCCESS
}

unsafe extern "C" fn locality(locality: *mut u32, _: u32) -> u32 {
    // SAFETY: libtpms passes a valid pointer.
    unsafe { *locality = 0 };
    ffi::TPM_SUCCESS
}

unsafe extern "C" fn presence(present: *mut u8, _: u32) -> u32 {
    // SAFETY: libtpms passes a valid pointer.
    unsafe { *present = 0 };
    ffi::TPM_SUCCESS
}

/// A running libtpms, owned by one test at a time.
pub struct LibTpms {
    _turn: MutexGuard<'static, ()>,
}

impl LibTpms {
    /// A newly manufactured TPM, set up as libkrun's CRB device sets it up.
    pub fn manufacture() -> LibTpms {
        let turn = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        shared().permanent = None;
        let tpm = LibTpms { _turn: turn };
        tpm.start();
        tpm
    }

    fn start(&self) {
        let buffer_size = vk_tpm::MAX_COMMAND_SIZE as u32;
        let mut callbacks = ffi::Callbacks {
            size_of_struct: std::mem::size_of::<ffi::Callbacks>() as c_int,
            nvram_init: Some(ok),
            nvram_loaddata: Some(load),
            nvram_storedata: Some(store),
            nvram_deletename: Some(delete),
            io_init: Some(ok),
            io_getlocality: Some(locality),
            io_getphysicalpresence: Some(presence),
        };
        // SAFETY: libtpms' documented start sequence; it copies the callbacks.
        unsafe {
            assert_eq!(ffi::TPMLIB_ChooseTPMVersion(ffi::TPMLIB_TPM_VERSION_2), 0);
            assert_eq!(ffi::TPMLIB_RegisterCallbacks(&mut callbacks), 0);
            let size =
                ffi::TPMLIB_SetBufferSize(buffer_size, std::ptr::null_mut(), std::ptr::null_mut());
            assert_eq!(size, buffer_size, "libtpms buffer size");
            // The profile libkrun's device gives a new TPM.
            assert_eq!(
                ffi::TPMLIB_SetProfile(c"{\"Name\":\"default-v1\"}".as_ptr()),
                0
            );
            assert_eq!(ffi::TPMLIB_MainInit(), 0, "libtpms init");
        }
        shared().running = true;
    }

    /// Replace the seeds and proofs (EPS, SPS, PPS, phProof, shProof, ehProof) in the stored
    /// permanent state, and power-cycle so the TPM uses them.
    pub fn set_secrets(&mut self, secrets: &[[u8; 64]; 6]) {
        self.stop();
        {
            let mut shared = shared();
            let state = shared.permanent.as_mut().expect("a stored permanent state");
            patch_secrets(state, secrets);
        }
        self.start();
    }

    /// Power-cycle: the TPM starts again from the permanent state it stored.
    pub fn power_cycle(&mut self) {
        self.stop();
        self.start();
    }

    fn stop(&mut self) {
        // Not under the lock: libtpms may store its state (a callback) as it terminates.
        if std::mem::take(&mut shared().running) {
            // SAFETY: the TPM was started.
            unsafe { ffi::TPMLIB_Terminate() };
        }
    }

    pub fn process(&mut self, command: &[u8]) -> Vec<u8> {
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
            assert_eq!(rc, 0, "TPMLIB_Process");
            assert!(!response.is_null());
            let out = std::slice::from_raw_parts(response, size as usize).to_vec();
            ffi::free(response);
            out
        }
    }
}

/// PERSISTENT_DATA in libtpms' "permall" blob (NVMarshal.c, PERSISTENT_DATA_Marshal): a header
/// (version, magic, min_version), disableClear, three algorithms, three policies and three
/// authValues (TPM2Bs), then the three seeds and the three proofs, each a TPM2B of 64 bytes.
fn patch_secrets(state: &mut [u8], secrets: &[[u8; 64]; 6]) {
    const PERSISTENT_DATA_MAGIC: [u8; 4] = 0x1221_3443u32.to_be_bytes();
    let magic = state
        .windows(4)
        .position(|w| w == PERSISTENT_DATA_MAGIC)
        .expect("PERSISTENT_DATA in the permanent state");
    // The magic, min_version, disableClear and the three algorithms.
    let mut at = magic + 4 + 2 + 1 + 3 * 2;
    let mut tpm2b = |state: &mut [u8], replace: Option<&[u8; 64]>| {
        let size = u16::from_be_bytes([state[at], state[at + 1]]) as usize;
        if let Some(value) = replace {
            assert_eq!(size, value.len(), "a seed or proof of {size} bytes");
            state[at + 2..at + 2 + size].copy_from_slice(value);
        }
        at += 2 + size;
    };
    for _ in 0..6 {
        tpm2b(state, None); // policies and authValues
    }
    for secret in secrets {
        tpm2b(state, Some(secret));
    }
}

impl Drop for LibTpms {
    fn drop(&mut self) {
        self.stop();
    }
}
