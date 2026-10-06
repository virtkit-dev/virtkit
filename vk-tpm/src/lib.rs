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
mod crypt;
mod entity;
mod hierarchy;
mod marshal;
mod object;
mod pcr;
mod rc;
mod session;
mod state;

use std::time::Instant;

use marshal::{Reader, Writer};
pub use rc::Rc;
pub use state::StateError;
use state::{Permanent, Shutdown, Volatile};
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
    clock: Clock,
    /// The permanent state changed since [`Tpm::take_permanent_changed`] last said so.
    permanent_changed: bool,
}

impl Tpm {
    /// A newly manufactured TPM (fresh seeds), powered on. Its permanent state is new: store it.
    pub fn manufacture() -> Result<Tpm, StateError> {
        let permanent = Permanent::manufacture()?;
        Ok(Tpm {
            volatile: Volatile::power_on(&permanent),
            permanent,
            clock: Clock::starting_at(0),
            permanent_changed: true,
        })
    }

    /// The TPM whose permanent state is `permanent` (as [`Tpm::permanent_state`] returned it),
    /// powered on: it waits for TPM2_Startup.
    pub fn power_on(permanent: &[u8]) -> Result<Tpm, StateError> {
        let permanent = Permanent::deserialize(permanent)?;
        Ok(Tpm {
            volatile: Volatile::power_on(&permanent),
            permanent,
            clock: Clock::starting_at(0),
            permanent_changed: false,
        })
    }

    /// The TPM as a snapshot saved it: both states, as [`Tpm::permanent_state`] and
    /// [`Tpm::volatile_state`] returned them. Its time goes on from the snapshot's.
    pub fn restore(permanent: &[u8], volatile: &[u8]) -> Result<Tpm, StateError> {
        let volatile = Volatile::deserialize(volatile)?;
        Ok(Tpm {
            permanent: Permanent::deserialize(permanent)?,
            clock: Clock::starting_at(volatile.time),
            volatile,
            permanent_changed: false,
        })
    }

    /// What the TPM keeps across power-off; it holds the seeds, so store it as a secret.
    pub fn permanent_state(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.permanent.serialize())
    }

    /// Differential tests only: give the TPM these seeds and proofs (EPS, SPS, PPS, phProof,
    /// shProof, ehProof), which the test gives libtpms too, so that what derives from them
    /// (tickets, primary keys) can be compared byte for byte.
    #[cfg(feature = "libtpms")]
    #[doc(hidden)]
    pub fn set_secrets_for_tests(&mut self, secrets: &[[u8; state::SEED_SIZE]; 6]) {
        let [eps, sps, pps, ph, sh, eh] = secrets.map(Zeroizing::new);
        let h = &mut self.permanent.hierarchies;
        (h.ph_proof, h.sh_proof, h.eh_proof) = (ph, sh, eh);
        let p = &mut self.permanent;
        (p.eps, p.sps, p.pps) = (eps, sps, pps);
    }

    /// What a snapshot must add to the permanent state to bring the running TPM back. It holds
    /// secrets too (the platform's authValue, session keys), so store it as one.
    pub fn volatile_state(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.volatile.serialize())
    }

    /// Whether the permanent state changed since the last call: the caller then stores
    /// [`Tpm::permanent_state`] before it hands the guest the response.
    pub fn take_permanent_changed(&mut self) -> bool {
        std::mem::take(&mut self.permanent_changed)
    }

    /// Run one command and return its response, at most [`MAX_COMMAND_SIZE`] bytes. A command
    /// that fails gets the 10-byte error response the specification gives.
    pub fn process(&mut self, command: &[u8]) -> Vec<u8> {
        // Whatever the command does to the permanent state, a failed authorization included,
        // is noticed here, so the caller stores it before the guest sees the response.
        let before = self.permanent_state();
        let response = self.execute(command).unwrap_or_else(|rc| {
            let mut w = Writer::new();
            w.u16(TPM_ST_NO_SESSIONS).u32(HEADER_SIZE as u32).u32(rc.0);
            w.into_bytes()
        });
        if *self.permanent_state() != *before {
            self.permanent_changed = true;
        }
        response
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
        if self.volatile.started {
            self.update_time();
            self.da_self_heal();
        }

        let mut handles = Vec::with_capacity(cmd.handles.len());
        for (n, kind) in (1..).zip(cmd.handles) {
            let handle = r.u32().map_err(|rc| rc.handle(n))?;
            kind.check(handle).map_err(|rc| rc.handle(n))?;
            handles.push(handle);
        }
        self.check_loaded(&handles)?;

        let (mut area, params) = if tag == TPM_ST_SESSIONS {
            let auth_size = usize::try_from(r.u32()?).map_err(|_| Rc::SIZE)?;
            if auth_size < 9 || auth_size > r.len() {
                return Err(Rc::SIZE);
            }
            let area = r.take(auth_size)?;
            if !cmd.sessions {
                return Err(Rc::AUTH_CONTEXT);
            }
            let mut area = self.read_area(cmd, area, &handles)?;
            let params = self.authorize(cmd, &handles, &mut area, r.rest())?;
            (Some(area), params)
        } else {
            if cmd.auth > 0 {
                return Err(Rc::AUTH_MISSING);
            }
            (None, Zeroizing::new(r.rest().to_vec()))
        };

        let mut out = Out::default();
        (cmd.run)(self, &handles, &mut Reader::new(&params), &mut out)?;

        let mut params = std::mem::take(&mut out.params).into_bytes();
        let sessions = self.respond(cmd, area.as_mut(), &mut params)?;
        let mut w = Writer::new();
        w.u16(tag).u32(0).u32(Rc::SUCCESS.0);
        if let Some(handle) = out.handle {
            w.u32(handle);
        }
        if tag == TPM_ST_SESSIONS {
            w.count(params.len());
        }
        w.bytes(&params).bytes(&sessions);
        // A sequence that completed goes only now: the response's authorizations needed it.
        if let Some(handle) = out.flush {
            self.flush_object(handle);
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

    /// Bring TPM time up to now (TimeUpdate).
    fn update_time(&mut self) {
        self.volatile.time = self.clock.now().max(self.volatile.time);
    }

    /// Void an orderly shutdown recorded since Startup (g_clearOrderly): a command changed what
    /// TPM2_Shutdown saved, so the next Startup may not resume from it.
    fn clear_orderly(&mut self) {
        if self.permanent.shutdown.is_orderly() {
            self.permanent.shutdown = if self.volatile.da_used {
                Shutdown::DaUsed
            } else {
                Shutdown::None
            };
        }
    }
}

/// What a command answers: the handle it created, if it returns one, and its parameters.
#[derive(Default)]
pub struct Out {
    pub handle: Option<u32>,
    pub params: Writer,
    /// An object to flush once the response is built (a completed sequence).
    pub flush: Option<u32>,
}

impl std::ops::Deref for Out {
    type Target = Writer;
    fn deref(&self) -> &Writer {
        &self.params
    }
}

impl std::ops::DerefMut for Out {
    fn deref_mut(&mut self) -> &mut Writer {
        &mut self.params
    }
}

/// The TPM's time source: milliseconds since power on (or since the snapshot's time), from the
/// host's monotonic clock.
struct Clock {
    origin: Instant,
    base: u64,
}

impl Clock {
    fn starting_at(base: u64) -> Clock {
        Clock {
            origin: Instant::now(),
            base,
        }
    }

    fn now(&self) -> u64 {
        let elapsed = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.base.saturating_add(elapsed)
    }

    /// Tests: let `ms` pass at once.
    #[cfg(test)]
    fn advance(&mut self, ms: u64) {
        self.base = self.base.saturating_add(ms);
    }
}

/// A TPM_ST the reference implementation knows: a command with another one is TPM_RC_BAD_TAG,
/// one with an unknown tag TPM_RC_VALUE (as libtpms answers).
fn is_structure_tag(tag: u16) -> bool {
    matches!(tag, 0x00c4 | 0x8000..=0x8002 | 0x8014..=0x801a | 0x8021..=0x8025)
}

#[cfg(test)]
mod tests;
