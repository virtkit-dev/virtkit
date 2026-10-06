//! Saved contexts (Part 1, "Context Management"; `ContextCommands.c`, `Context_spt.c`, and the
//! context half of `Session.c`): TPM2_ContextSave, TPM2_ContextLoad and TPM2_FlushContext.
//!
//! A context leaves the TPM encrypted and integrity-protected with keys derived from the proof
//! of its hierarchy (the null hierarchy's for sessions and temporary objects):
//!
//! - key ‖ IV = KDFa(SHA-512, proof, "CONTEXT", sequence, handle), AES-256-CFB over
//!   sequence ‖ the object or session, as vk-tpm serializes it (`state.rs`);
//! - integrity = HMAC-SHA512(proof, totalResetCount [‖ clearCount] ‖ sequence ‖ handle ‖
//!   the ciphertext): no context loads after a TPM Reset, nor an stClear object's (handle
//!   0x80000002, clearCount in the HMAC) after a Restart.
//!
//! The blob is vk-tpm's, not libtpms' (whose own is its internal OBJECT layout); everything
//! around it (sequence numbers, handles, the context gap) is the reference's.
//!
//! A saved session keeps its handle; its slot in the handle table holds the context's
//! sequence number, so only the latest context of a session loads, once. Sequence numbers come
//! from one counter; a saved session older than 2^16 contexts would be ambiguous, so the TPM
//! refuses to go further (TPM_RC_CONTEXT_GAP) until it is loaded or flushed.

use zeroize::Zeroizing;

use crate::alg::{Hash, MAX_DIGEST};
use crate::commands::{end, first};
use crate::crypt;
use crate::entity::{TPM_HT_TRANSIENT, handle_type, is_session};
use crate::marshal::{Reader, Writer};
use crate::object::{self, Object};
use crate::rc::{Rc, Result};
use crate::session::{MAX_LOADED, Session, SessionSlot};
use crate::{Out, Tpm};

/// The first session context sequence number after a TPM Reset (MAX_LOADED_SESSIONS + 1: the
/// reference's context array keeps 1..=3 for loaded sessions).
pub const FIRST_CONTEXT: u64 = MAX_LOADED as u64 + 1;
/// The context array keeps 16 bits of a sequence number.
const SLOT_MASK: u64 = 0xffff;
/// How far a saved session's context may fall behind the counter (MAX_CONTEXT_GAP).
const MAX_CONTEXT_GAP: u64 = SLOT_MASK + 1;
/// TPM_PT_MAX_OBJECT_CONTEXT: what Windows pads TPM2_ContextLoad's context to.
pub const MAX_OBJECT_CONTEXT: usize = 0xd4c;
/// TPM2B_CONTEXT_DATA: sizeof(TPMS_CONTEXT_DATA), an integrity digest and MAX_CONTEXT_SIZE.
const MAX_CONTEXT_DATA: usize = 2 + MAX_DIGEST + 2 + 2680;
/// The saved handle of an object context (TPMI_DH_SAVED): a key, a sequence, an stClear key.
const SAVED_OBJECT: u32 = 0x8000_0000;
const SAVED_SEQUENCE: u32 = 0x8000_0001;
const SAVED_ST_CLEAR: u32 = 0x8000_0002;
/// The context integrity's hash (CONTEXT_INTEGRITY_HASH_ALG) and cipher key size.
const CONTEXT_HASH: Hash = Hash::Sha512;
const CONTEXT_KEY: usize = 32;

fn masked(sequence: u64) -> u64 {
    sequence & SLOT_MASK
}

/// A TPMS_CONTEXT.
struct Context<'a> {
    sequence: u64,
    handle: u32,
    hierarchy: u32,
    blob: &'a [u8],
}

impl Tpm {
    /// The handle index and sequence number of the oldest saved session.
    fn oldest_saved(&self) -> Option<(usize, u64)> {
        (self.volatile.sessions.iter().enumerate())
            .filter_map(|(i, s)| match s {
                SessionSlot::Saved(sequence) => Some((i, *sequence)),
                _ => None,
            })
            .min_by_key(|(_, sequence)| *sequence)
    }

    /// The context counter has come around to the oldest saved session: one more context
    /// would make it ambiguous.
    pub fn oldest_saved_is_due(&self) -> bool {
        self.oldest_saved()
            .is_some_and(|(_, oldest)| masked(oldest) == masked(self.volatile.context_counter))
    }

    /// ComputeContextProtectionKey: AES-256 key and IV.
    fn context_keys(&self, c: &Context) -> Zeroizing<Vec<u8>> {
        crypt::kdfa(
            CONTEXT_HASH,
            self.proof(c.hierarchy).as_slice(),
            b"CONTEXT",
            &c.sequence.to_be_bytes(),
            &c.handle.to_be_bytes(),
            CONTEXT_KEY + crypt::AES_BLOCK,
        )
    }

    /// ComputeContextIntegrity.
    fn context_integrity(&self, c: &Context, encrypted: &[u8]) -> Vec<u8> {
        let reset = self.permanent.total_reset_count.to_be_bytes();
        let clear = self.volatile.clear_count.to_be_bytes();
        let mut parts: Vec<&[u8]> = vec![&reset];
        if c.handle == SAVED_ST_CLEAR {
            parts.push(&clear);
        }
        let (sequence, handle) = (c.sequence.to_be_bytes(), c.handle.to_be_bytes());
        parts.extend([&sequence[..], &handle[..], encrypted]);
        crypt::hmac(CONTEXT_HASH, self.proof(c.hierarchy).as_slice(), &parts)
    }

    /// SessionContextSave: the session leaves its slot; its handle keeps the context's sequence.
    fn save_session(&mut self, handle: u32) -> Result<u64> {
        if self.oldest_saved_is_due() {
            return Err(Rc::CONTEXT_GAP);
        }
        let v = &mut self.volatile;
        let sequence = v.context_counter;
        let slot = (v.sessions.get_mut(session_index(handle))).ok_or(Rc::FAILURE)?;
        *slot = SessionSlot::Saved(sequence);
        v.context_counter = v.context_counter.wrapping_add(1);
        // Masked, a sequence number never looks like a loaded session's slot (1..=3).
        if masked(v.context_counter) == 0 {
            v.context_counter = v.context_counter.wrapping_add(FIRST_CONTEXT);
        }
        Ok(sequence)
    }
}

fn session_index(handle: u32) -> usize {
    usize::try_from(handle & 0x00ff_ffff).unwrap_or(usize::MAX)
}

/// A TPMI_DH_CONTEXT: a session or a transient object handle.
fn read_context_handle(r: &mut Reader) -> Result<u32> {
    let h = r.u32()?;
    if is_session(h) || object::slot(h).is_some() {
        Ok(h)
    } else {
        Err(Rc::VALUE)
    }
}

/// TPM2_ContextSave: an object's context (it stays loaded), or a session's (it is unloaded,
/// and keeps its handle).
pub fn context_save(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    end(r)?;
    let handle = first(handles)?;
    let mut payload = Writer::new();
    let (sequence, saved_handle, hierarchy) = if handle_type(handle) == TPM_HT_TRANSIENT {
        let object = tpm.object(handle).ok_or(Rc::FAILURE)?;
        object.write(&mut payload);
        let (saved, hierarchy) = match object {
            Object::Sequence(_) => (SAVED_SEQUENCE, crate::entity::TPM_RH_NULL),
            Object::Key(k) if k.st_clear => (SAVED_ST_CLEAR, k.hierarchy),
            Object::Key(k) => (SAVED_OBJECT, k.hierarchy),
        };
        let id = tpm.volatile.object_context_id.wrapping_add(1);
        if id == 0 {
            return Err(Rc::FAILURE);
        }
        tpm.volatile.object_context_id = id;
        (id, saved, hierarchy)
    } else {
        tpm.session(handle).ok_or(Rc::FAILURE)?.write(&mut payload);
        (
            tpm.save_session(handle)?,
            handle,
            crate::entity::TPM_RH_NULL,
        )
    };
    let c = Context {
        sequence,
        handle: saved_handle,
        hierarchy,
        blob: &[],
    };
    let mut plain = Writer::with_capacity(MAX_CONTEXT_DATA);
    plain.u64(sequence).bytes(&payload.into_bytes());
    let mut data = Zeroizing::new(plain.into_bytes());
    let keys = tpm.context_keys(&c);
    let (key, iv) = keys.split_at_checked(CONTEXT_KEY).ok_or(Rc::FAILURE)?;
    crypt::aes_cfb(key, iv, &mut data, true)?;
    let integrity = tpm.context_integrity(&c, &data);
    let mut blob = Writer::new();
    blob.tpm2b(&integrity).bytes(&data);
    let blob = blob.into_bytes();
    if blob.len() > MAX_CONTEXT_DATA {
        return Err(Rc::FAILURE);
    }
    w.u64(sequence)
        .u32(saved_handle)
        .u32(hierarchy)
        .tpm2b(&blob);
    tpm.clear_orderly();
    Ok(())
}

/// A TPMI_DH_SAVED.
fn read_saved_handle(r: &mut Reader) -> Result<u32> {
    let h = r.u32()?;
    if is_session(h) || matches!(h, SAVED_OBJECT | SAVED_SEQUENCE | SAVED_ST_CLEAR) {
        Ok(h)
    } else {
        Err(Rc::VALUE)
    }
}

/// TPM2_ContextLoad: an object back into a free slot, or a saved session back into its handle.
pub fn context_load(tpm: &mut Tpm, _: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let total = r.len();
    let c = (|| {
        Ok(Context {
            sequence: r.u64()?,
            handle: read_saved_handle(r)?,
            hierarchy: object::read_hierarchy(r)?,
            blob: r.tpm2b(MAX_CONTEXT_DATA)?,
        })
    })()
    .map_err(|rc: Rc| rc.param(1))?;
    // Windows pads the context to TPM_PT_MAX_OBJECT_CONTEXT; libtpms takes it.
    if total != MAX_OBJECT_CONTEXT {
        end(r)?;
    }
    let mut blob = Reader::new(c.blob);
    let integrity = blob.tpm2b(MAX_DIGEST)?;
    if integrity.len() != CONTEXT_HASH.size() || blob.len() < 8 {
        return Err(Rc::SIZE.param(1));
    }
    let expected = tpm.context_integrity(&c, blob.rest());
    if !bool::from(subtle::ConstantTimeEq::ct_eq(integrity, &expected[..])) {
        return Err(Rc::INTEGRITY.param(1));
    }
    let mut data = Zeroizing::new(blob.rest().to_vec());
    let keys = tpm.context_keys(&c);
    let (key, iv) = keys.split_at_checked(CONTEXT_KEY).ok_or(Rc::FAILURE)?;
    crypt::aes_cfb(key, iv, &mut data, false)?;
    let mut plain = Reader::new(&data);
    if plain.u64()? != c.sequence {
        return Err(Rc::FAILURE);
    }
    if handle_type(c.handle) == TPM_HT_TRANSIENT {
        tpm.hierarchy_enabled(c.hierarchy)
            .map_err(|_| Rc::HIERARCHY.param(1))?;
        let object = Object::read(&mut plain).map_err(|_| Rc::FAILURE)?;
        w.handle = Some(tpm.load_object(object)?);
        return Ok(());
    }
    // A session: the latest context of a session saved since the last TPM Reset.
    let i = session_index(c.handle);
    let valid = matches!(tpm.volatile.sessions.get(i), Some(SessionSlot::Saved(s)) if *s == c.sequence)
        && c.sequence <= tpm.volatile.context_counter
        && tpm.volatile.context_counter.saturating_sub(c.sequence) <= MAX_CONTEXT_GAP;
    if !valid {
        return Err(Rc::HANDLE.param(1));
    }
    let free = MAX_LOADED.saturating_sub(tpm.session_count());
    if free == 0 {
        return Err(Rc::SESSION_MEMORY);
    }
    if free == 1
        && tpm.oldest_saved_is_due()
        && tpm.oldest_saved().is_some_and(|(oldest, _)| oldest != i)
    {
        return Err(Rc::CONTEXT_GAP);
    }
    let session = Session::read(&mut plain).map_err(|_| Rc::FAILURE)?;
    let slot = tpm.volatile.sessions.get_mut(i).ok_or(Rc::FAILURE)?;
    *slot = SessionSlot::Loaded(Box::new(session));
    w.handle = Some(c.handle);
    tpm.clear_orderly();
    Ok(())
}

/// TPM2_FlushContext: unload an object, or a session, loaded or saved.
pub fn flush_context(tpm: &mut Tpm, _: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let handle = read_context_handle(r).map_err(|rc| rc.param(1))?;
    end(r)?;
    if is_session(handle) {
        tpm.flush_session(handle).map_err(|rc| rc.param(1))
    } else if tpm.object(handle).is_some() {
        tpm.flush_object(handle);
        Ok(())
    } else {
        Err(Rc::HANDLE.param(1))
    }
}
