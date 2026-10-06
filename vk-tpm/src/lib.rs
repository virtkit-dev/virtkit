//! A TPM 2.0 (TCG TPM 2.0 Library specification), in Rust: the engine behind a VMM's TPM
//! device. The device hands it each command the guest wrote and copies the response back;
//! it keeps the TPM's state, which this crate serializes (see [`Tpm::permanent_state`]).
//!
//! See `docs/tpm-design.md` for the scope (which commands, which algorithms) and the plan.
//!
//! Every command byte is guest-controlled: parsing goes through [`marshal::Reader`], which
//! bounds-checks each read, and no path panics on input.

#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )
)]

mod alg;
mod capability;
mod commands;
mod marshal;
mod pcr;
mod rc;
mod state;

use marshal::{Reader, Writer};
pub use rc::Rc;
pub use state::StateError;
use state::{Permanent, Volatile};
use zeroize::Zeroizing;

/// The largest command (and response) the TPM takes: the buffer of libkrun's CRB device
/// (its 4 KiB MMIO page less the registers), which the TPM reports as TPM_PT_MAX_COMMAND_SIZE.
pub const MAX_COMMAND_SIZE: usize = 0xf80;

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_ST_SESSIONS: u16 = 0x8002;
const HEADER_SIZE: usize = 10;
/// The locality every command comes from: the device offers locality 0 only.
const LOCALITY: u8 = 0;

/// A TPM: its permanent state (what survives power-off) and its volatile state.
pub struct Tpm {
    permanent: Permanent,
    volatile: Volatile,
    /// The permanent state changed since [`Tpm::take_permanent_changed`] last said so.
    permanent_changed: bool,
}

impl Tpm {
    /// A newly manufactured TPM (fresh seeds), powered on. Its permanent state is new: store it.
    pub fn manufacture() -> Result<Tpm, StateError> {
        Ok(Tpm {
            permanent: Permanent::manufacture()?,
            volatile: Volatile::power_on(),
            permanent_changed: true,
        })
    }

    /// The TPM whose permanent state is `permanent` (as [`Tpm::permanent_state`] returned it),
    /// powered on: it waits for TPM2_Startup.
    pub fn power_on(permanent: &[u8]) -> Result<Tpm, StateError> {
        Ok(Tpm {
            permanent: Permanent::deserialize(permanent)?,
            volatile: Volatile::power_on(),
            permanent_changed: false,
        })
    }

    /// The TPM as a snapshot saved it: both states, as [`Tpm::permanent_state`] and
    /// [`Tpm::volatile_state`] returned them.
    pub fn restore(permanent: &[u8], volatile: &[u8]) -> Result<Tpm, StateError> {
        Ok(Tpm {
            permanent: Permanent::deserialize(permanent)?,
            volatile: Volatile::deserialize(volatile)?,
            permanent_changed: false,
        })
    }

    /// What the TPM keeps across power-off; it holds the seeds, so store it as a secret.
    pub fn permanent_state(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.permanent.serialize())
    }

    /// What a snapshot must add to the permanent state to bring the running TPM back.
    pub fn volatile_state(&self) -> Vec<u8> {
        self.volatile.serialize()
    }

    /// Whether the permanent state changed since the last call: the caller then stores
    /// [`Tpm::permanent_state`] before it hands the guest the response.
    pub fn take_permanent_changed(&mut self) -> bool {
        std::mem::take(&mut self.permanent_changed)
    }

    /// Run one command and return its response, at most [`MAX_COMMAND_SIZE`] bytes. A command
    /// that fails gets the 10-byte error response the specification gives.
    pub fn process(&mut self, command: &[u8]) -> Vec<u8> {
        self.execute(command).unwrap_or_else(|rc| {
            let mut w = Writer::new();
            w.u16(TPM_ST_NO_SESSIONS).u32(HEADER_SIZE as u32).u32(rc.0);
            w.into_bytes()
        })
    }

    fn execute(&mut self, command: &[u8]) -> rc::Result<Vec<u8>> {
        let mut r = Reader::new(command);
        let tag = r.u16()?;
        if tag != TPM_ST_NO_SESSIONS && tag != TPM_ST_SESSIONS {
            return Err(if is_structure_tag(tag) {
                Rc::BAD_TAG
            } else {
                Rc::VALUE
            });
        }
        let size = usize::try_from(r.u32()?).map_err(|_| Rc::COMMAND_SIZE)?;
        if size != command.len() || size > MAX_COMMAND_SIZE {
            return Err(Rc::COMMAND_SIZE);
        }
        let code = r.u32()?;
        let cmd = commands::find(code).ok_or(Rc::COMMAND_CODE)?;
        // Before TPM2_Startup the TPM takes nothing else, and after it, not Startup again.
        if self.volatile.started == (code == commands::TPM_CC_STARTUP) {
            return Err(Rc::INITIALIZE);
        }

        let mut handles = Vec::with_capacity(cmd.handles.len());
        for (n, kind) in (1..).zip(cmd.handles) {
            let handle = r.u32().map_err(|rc| rc.handle(n))?;
            kind.check(handle).map_err(|rc| rc.handle(n))?;
            handles.push(handle);
        }

        let sessions = if tag == TPM_ST_SESSIONS {
            let auth_size = usize::try_from(r.u32()?).map_err(|_| Rc::SIZE)?;
            if auth_size < 9 || auth_size > r.len() {
                return Err(Rc::SIZE);
            }
            let area = r.take(auth_size)?;
            if !cmd.sessions {
                return Err(Rc::AUTH_CONTEXT);
            }
            authorize(cmd, &handles, area)?
        } else {
            if cmd.auth > 0 {
                return Err(Rc::AUTH_MISSING);
            }
            Vec::new()
        };

        let mut out = Writer::new();
        (cmd.run)(self, &handles, &mut r, &mut out)?;

        let params = out.into_bytes();
        let mut w = Writer::new();
        w.u16(tag).u32(0).u32(Rc::SUCCESS.0);
        if tag == TPM_ST_SESSIONS {
            w.count(params.len());
        }
        w.bytes(&params);
        for attributes in sessions {
            // A password session answers with an empty nonce and HMAC, and stays open.
            w.u16(0).u8(attributes | CONTINUE_SESSION).u16(0);
        }
        let mut response = w.into_bytes();
        let len = u32::try_from(response.len()).map_err(|_| Rc::FAILURE)?;
        if response.len() > MAX_COMMAND_SIZE {
            return Err(Rc::FAILURE);
        }
        if let Some(size) = response.get_mut(2..6) {
            size.copy_from_slice(&len.to_be_bytes());
        }
        Ok(response)
    }

    fn mark_permanent_changed(&mut self) {
        self.permanent_changed = true;
    }
}

/// A TPM_ST the reference implementation knows: a command with another one is TPM_RC_BAD_TAG,
/// one with an unknown tag TPM_RC_VALUE (as libtpms answers).
fn is_structure_tag(tag: u16) -> bool {
    matches!(tag, 0x00c4 | 0x8000..=0x8002 | 0x8014..=0x801a | 0x8021..=0x8025)
}

/// TPM_RS_PW: the password session, which authorizes with the entity's authValue in clear.
const TPM_RS_PW: u32 = 0x4000_0009;
const HMAC_SESSIONS: std::ops::RangeInclusive<u32> = 0x0200_0000..=0x0200_003f;
const POLICY_SESSIONS: std::ops::RangeInclusive<u32> = 0x0300_0000..=0x0300_003f;
const MAX_SESSIONS: usize = 3;
/// The largest nonce or HMAC/password a session carries (sizeof(TPMU_HA)).
const MAX_AUTH: usize = alg::MAX_DIGEST;

// TPMA_SESSION bits.
const CONTINUE_SESSION: u8 = 0x01;
const AUDIT_EXCLUSIVE: u8 = 0x02;
const AUDIT_RESET: u8 = 0x04;
const RESERVED: u8 = 0x18;
const DECRYPT: u8 = 0x20;
const ENCRYPT: u8 = 0x40;
const AUDIT: u8 = 0x80;

/// Check the authorization area against the handles that need one, and return the attributes
/// of each session (for the response). Only password sessions exist so far: any other session
/// handle is one that is not loaded.
fn authorize(cmd: &commands::Command, handles: &[u32], mut area: Reader) -> rc::Result<Vec<u8>> {
    let mut sessions: Vec<(u32, u8, &[u8])> = Vec::new();
    while !area.is_empty() {
        let n = u32::try_from(sessions.len())
            .map_err(|_| Rc::FAILURE)?
            .saturating_add(1);
        if sessions.len() == MAX_SESSIONS {
            return Err(Rc::SIZE.session(n));
        }
        let handle = area.u32().map_err(|rc| rc.session(n))?;
        if handle != TPM_RS_PW
            && !HMAC_SESSIONS.contains(&handle)
            && !POLICY_SESSIONS.contains(&handle)
        {
            return Err(Rc::VALUE.session(n));
        }
        let nonce = area.tpm2b(MAX_AUTH).map_err(|rc| rc.session(n))?;
        let attributes = area.u8().map_err(|rc| rc.session(n))?;
        if attributes & RESERVED != 0 {
            return Err(Rc::RESERVED_BITS.session(n));
        }
        let password = area.tpm2b(MAX_AUTH).map_err(|rc| rc.session(n))?;
        if handle != TPM_RS_PW {
            return Err(Rc(Rc::REFERENCE_S0.0.saturating_add(n.saturating_sub(1))));
        }
        if attributes & (ENCRYPT | DECRYPT | AUDIT | AUDIT_EXCLUSIVE | AUDIT_RESET) != 0 {
            return Err(Rc::ATTRIBUTES.session(n));
        }
        if !nonce.is_empty() {
            return Err(Rc::NONCE.session(n));
        }
        sessions.push((handle, attributes, password));
    }
    if cmd.auth > sessions.len() {
        return Err(Rc::AUTH_MISSING);
    }
    for (n, (i, (_, _, password))) in (1..).zip(sessions.iter().enumerate()) {
        // Session i authorizes handle i; a password session must have one to authorize.
        let Some(&handle) = handles.get(i).filter(|_| i < cmd.auth) else {
            return Err(Rc::HANDLE.session(n));
        };
        if !password_matches(password, &auth_value(handle)) {
            // PCRs are exempt from dictionary-attack protection: a plain TPM_RC_BAD_AUTH.
            return Err(Rc::BAD_AUTH.session(n));
        }
    }
    Ok(sessions.into_iter().map(|(_, a, _)| a).collect())
}

/// The authValue of the entity `handle` names. Only PCRs (and TPM_RH_NULL) can be authorized
/// so far, and their authValue is empty.
fn auth_value(_handle: u32) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(Vec::new())
}

/// A password matches an authValue when they are equal once trailing zeros are dropped from
/// the password (Part 1, "password authorizations"), compared in constant time.
fn password_matches(password: &[u8], auth_value: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    let end = password
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |i| i.saturating_add(1));
    let password = password.get(..end).unwrap_or_default();
    password.ct_eq(auth_value).into()
}

#[cfg(test)]
mod tests;
