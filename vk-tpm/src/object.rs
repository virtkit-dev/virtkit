//! Transient objects (Part 1, "Object Structure Elements"): the TPM's [`MAX_OBJECTS`] object
//! slots, named TRANSIENT_FIRST + slot. A slot holds a key (or any object with a public area,
//! `key.rs`) or a sequence: hash, HMAC and event sequences live here, with the commands that
//! drive them (Part 3, "Hash/HMAC/Event Sequences") and TPM2_Hash, which shares their tickets.
//!
//! A persistent object a command names is copied into a free slot for that command, and its
//! handle replaced with the slot's, as the reference implementation does (ObjectLoadEvict): the
//! slot counts against the ones the command may need, and is freed once the command is done.

use zeroize::Zeroizing;

use crate::alg::{Hash, Hasher, MAX_DIGEST};
use crate::commands::{end, first, write_digest_values};
use crate::crypt;
use crate::entity::{TPM_RH_ENDORSEMENT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM, strip_zeros};
use crate::hierarchy::Auth;
use crate::key::Key;
use crate::marshal::{Reader, Writer};
use crate::rc::{Rc, Result};
use crate::state::{StateError, read_bool};
use crate::{Out, Tpm};

/// How many objects the TPM holds at once (MAX_LOADED_OBJECTS, as libtpms).
pub const MAX_OBJECTS: usize = 3;
pub const TRANSIENT_FIRST: u32 = 0x8000_0000;
/// The largest buffer a sequence or TPM2_Hash takes in one command (TPM2B_MAX_BUFFER).
pub const MAX_BUFFER: usize = 1024;
/// TPM_ST_HASHCHECK, the tag of a TPMT_TK_HASHCHECK.
pub const TPM_ST_HASHCHECK: u16 = 0x8024;
/// TPM_GENERATED_VALUE: what the TPM puts first in the structures it signs. A digest of data
/// that starts with it gets no ticket, so a ticket cannot vouch for a forged attestation.
const TPM_GENERATED_VALUE: [u8; 4] = [0xff, b'T', b'C', b'G'];

/// A loaded object.
pub enum Object {
    Sequence(Sequence),
    Key(Box<Key>),
}

/// A hash or event sequence: data in, digests out at the end.
pub struct Sequence {
    pub auth: Auth,
    pub kind: SequenceKind,
}

pub enum SequenceKind {
    /// A hash sequence (TPM2_HashSequenceStart), and whether its ticket may be issued: its
    /// first block did not start with TPM_GENERATED_VALUE (`safe`, once `started`).
    Hash {
        hasher: Box<Hasher>,
        started: bool,
        safe: bool,
    },
    /// An event sequence: one digest per PCR bank.
    Event { hashers: Vec<Hasher> },
}

impl Object {
    pub fn write(&self, w: &mut Writer) {
        let s = match self {
            Object::Key(key) => {
                w.u8(1);
                key.write(w);
                return;
            }
            Object::Sequence(s) => s,
        };
        w.u8(0).tpm2b(&s.auth);
        match &s.kind {
            SequenceKind::Hash {
                hasher,
                started,
                safe,
            } => {
                w.u8(0).u16(hasher.hash().id()).tpm2b(&hasher.save());
                w.u8((*started).into()).u8((*safe).into());
            }
            SequenceKind::Event { hashers } => {
                w.u8(1).count(hashers.len());
                for h in hashers {
                    w.u16(h.hash().id()).tpm2b(&h.save());
                }
            }
        }
    }

    pub fn read(r: &mut Reader) -> std::result::Result<Object, StateError> {
        if read_bool(r)? {
            return Ok(Object::Key(Box::new(Key::read(r)?)));
        }
        let auth = Zeroizing::new(r.tpm2b(MAX_DIGEST)?.to_vec());
        let hasher = |r: &mut Reader| -> std::result::Result<Hasher, StateError> {
            let hash = Hash::read(r)?;
            Hasher::load(hash, r.tpm2b(usize::from(u16::MAX))?).ok_or(StateError("bad hash state"))
        };
        let kind = match r.u8()? {
            0 => SequenceKind::Hash {
                hasher: Box::new(hasher(r)?),
                started: read_bool(r)?,
                safe: read_bool(r)?,
            },
            1 => {
                let count = r.count(Hash::ALL.len())?;
                SequenceKind::Event {
                    hashers: (0..count)
                        .map(|_| hasher(r))
                        .collect::<std::result::Result<_, _>>()?,
                }
            }
            _ => return Err(StateError("bad object")),
        };
        Ok(Object::Sequence(Sequence { auth, kind }))
    }

    /// The object's authValue, without its trailing zeros.
    pub fn auth(&self) -> &[u8] {
        match self {
            Object::Sequence(s) => &s.auth,
            Object::Key(k) => k.auth(),
        }
    }
}

/// The handle of object slot `slot`.
fn handle(slot: usize) -> Result<u32> {
    u32::try_from(slot)
        .ok()
        .and_then(|s| TRANSIENT_FIRST.checked_add(s))
        .ok_or(Rc::FAILURE)
}

/// The slot a transient handle names, whether or not something is loaded there.
pub fn slot(handle: u32) -> Option<usize> {
    usize::try_from(handle.checked_sub(TRANSIENT_FIRST)?)
        .ok()
        .filter(|&s| s < MAX_OBJECTS)
}

impl Tpm {
    /// The object a transient handle names, if one is loaded there.
    pub fn object(&self, handle: u32) -> Option<&Object> {
        self.volatile.objects.get(slot(handle)?)?.as_ref()
    }

    fn object_mut(&mut self, handle: u32) -> Result<&mut Object> {
        let slot = slot(handle).ok_or(Rc::FAILURE)?;
        let object = self.volatile.objects.get_mut(slot).ok_or(Rc::FAILURE)?;
        object.as_mut().ok_or(Rc::FAILURE)
    }

    /// FindEmptyObjectSlot: TPM_RC_OBJECT_MEMORY if every slot is taken.
    pub fn free_slot(&self) -> Result<usize> {
        self.volatile
            .objects
            .iter()
            .position(Option::is_none)
            .ok_or(Rc::OBJECT_MEMORY)
    }

    /// Load `object` into the first free slot, and return its handle.
    pub fn load_object(&mut self, object: Object) -> Result<u32> {
        let slot = self.free_slot()?;
        let free = self.volatile.objects.get_mut(slot).ok_or(Rc::FAILURE)?;
        *free = Some(object);
        handle(slot)
    }

    /// Unload the object a handle names (TPM2_FlushContext, or a sequence completed).
    pub fn flush_object(&mut self, handle: u32) {
        if let Some(o) = slot(handle).and_then(|s| self.volatile.objects.get_mut(s)) {
            *o = None;
        }
    }

    /// The handles of the loaded objects, in order.
    pub fn loaded_objects(&self) -> Vec<u32> {
        (self.volatile.objects.iter().enumerate())
            .filter(|(_, o)| o.is_some())
            .filter_map(|(slot, _)| handle(slot).ok())
            .collect()
    }

    /// The persistent object at `handle`.
    pub fn persistent(&self, handle: u32) -> Option<&Key> {
        let list = &self.permanent.persistent;
        list.iter().find(|(h, _)| *h == handle).map(|(_, k)| k)
    }

    /// ObjectLoadEvict: copy persistent object `handle` into a free slot for this command, and
    /// return the slot's handle.
    pub fn load_evict(&mut self, handle: u32, code: u32) -> Result<u32> {
        let enabled = if handle >= crate::key::PLATFORM_PERSISTENT {
            self.volatile.ph_enable
        } else {
            self.volatile.clear.sh_enable
        };
        if !enabled {
            return Err(Rc::HANDLE);
        }
        self.free_slot()?;
        let mut key = self.persistent(handle).ok_or(Rc::HANDLE)?.clone();
        // An endorsement key stays usable for EvictControl alone while the hierarchy is off.
        if key.hierarchy == TPM_RH_ENDORSEMENT
            && !self.volatile.clear.eh_enable
            && code != crate::commands::TPM_CC_EVICT_CONTROL
        {
            return Err(Rc::HANDLE);
        }
        key.evict = Some(handle);
        self.load_object(Object::Key(Box::new(key)))
    }

    /// ObjectCleanupEvict: free the slots persistent objects were copied into for a command.
    pub fn flush_evicted(&mut self) {
        for slot in &mut self.volatile.objects {
            if let Some(Object::Key(k)) = slot
                && k.evict.is_some()
            {
                *slot = None;
            }
        }
    }

    /// TicketComputeHashCheck: the ticket that says the TPM computed `digest` (with `hash`) of
    /// data that did not start with TPM_GENERATED_VALUE: an HMAC with the hierarchy's proof.
    pub fn hash_check(&self, hierarchy: u32, hash: Hash, digest: &[u8]) -> Vec<u8> {
        let tag = TPM_ST_HASHCHECK.to_be_bytes();
        crypt::hmac(
            Hash::Sha512,
            self.proof(hierarchy).as_slice(),
            &[&tag, &hash.id().to_be_bytes(), digest],
        )
    }

    fn write_hash_check(&self, hierarchy: u32, hash: Hash, digest: &[u8], w: &mut Writer) {
        let ticket = self.hash_check(hierarchy, hash, digest);
        w.u16(TPM_ST_HASHCHECK).u32(hierarchy).tpm2b(&ticket);
    }
}

/// A NULL ticket: the TPM vouches for nothing.
fn null_ticket(w: &mut Writer) {
    w.u16(TPM_ST_HASHCHECK).u32(TPM_RH_NULL).tpm2b(&[]);
}

/// TicketIsSafe: the data does not start with TPM_GENERATED_VALUE (and is long enough to tell).
fn is_ticket_safe(data: &[u8]) -> bool {
    data.get(..TPM_GENERATED_VALUE.len())
        .is_some_and(|start| start != TPM_GENERATED_VALUE)
}

/// A TPMI_RH_HIERARCHY+: the hierarchy a ticket is for, or TPM_RH_NULL for none.
pub fn read_hierarchy(r: &mut Reader) -> Result<u32> {
    let h = r.u32()?;
    match h {
        TPM_RH_OWNER | TPM_RH_ENDORSEMENT | TPM_RH_PLATFORM | TPM_RH_NULL => Ok(h),
        _ => Err(Rc::VALUE),
    }
}

/// TPM2_Hash: a digest, with a ticket for `hierarchy` unless the data starts with
/// TPM_GENERATED_VALUE.
pub fn hash(tpm: &mut Tpm, _: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let data = r.tpm2b(MAX_BUFFER).map_err(|rc| rc.param(1))?;
    let hash = Hash::read(r).map_err(|rc| rc.param(2))?;
    let hierarchy = read_hierarchy(r).map_err(|rc| rc.param(3))?;
    end(r)?;
    let digest = hash.digest(&[data]);
    w.tpm2b(&digest);
    let generated = data.len() >= TPM_GENERATED_VALUE.len() && !is_ticket_safe(data);
    if hierarchy == TPM_RH_NULL || generated {
        null_ticket(w);
    } else {
        tpm.write_hash_check(hierarchy, hash, &digest, w);
    }
    Ok(())
}

/// TPM2_HashSequenceStart: a hash sequence, or with TPM_ALG_NULL an event sequence.
pub fn hash_sequence_start(tpm: &mut Tpm, _: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let auth = Zeroizing::new(strip_zeros(r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(1))?).to_vec());
    let hash = Hash::read_or_null(r).map_err(|rc| rc.param(2))?;
    end(r)?;
    let kind = match hash {
        Some(hash) => SequenceKind::Hash {
            hasher: Box::new(Hasher::new(hash)),
            started: false,
            safe: false,
        },
        None => SequenceKind::Event {
            hashers: Hash::ALL.into_iter().map(Hasher::new).collect(),
        },
    };
    w.handle = Some(tpm.load_object(Object::Sequence(Sequence { auth, kind }))?);
    Ok(())
}

/// The sequence a handle names; TPM_RC_MODE (handle `n`) for any other object.
fn sequence_mut(tpm: &mut Tpm, handle: u32, n: u32) -> Result<&mut Sequence> {
    match tpm.object_mut(handle)? {
        Object::Sequence(s) => Ok(s),
        Object::Key(_) => Err(Rc::MODE.handle(n)),
    }
}

/// TPM2_SequenceUpdate: more data into a sequence.
pub fn sequence_update(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let data = r.tpm2b(MAX_BUFFER).map_err(|rc| rc.param(1))?;
    end(r)?;
    let sequence = sequence_mut(tpm, first(handles)?, 1)?;
    match &mut sequence.kind {
        SequenceKind::Hash {
            hasher,
            started,
            safe,
        } => {
            if !*started {
                *started = true;
                *safe = is_ticket_safe(data);
            }
            hasher.update(data);
        }
        SequenceKind::Event { hashers } => {
            for h in hashers {
                h.update(data);
            }
        }
    }
    Ok(())
}

/// TPM2_SequenceComplete: a hash sequence's digest and ticket. The sequence is flushed.
pub fn sequence_complete(
    tpm: &mut Tpm,
    handles: &[u32],
    r: &mut Reader,
    w: &mut Out,
) -> Result<()> {
    let data = r.tpm2b(MAX_BUFFER).map_err(|rc| rc.param(1))?;
    let hierarchy = read_hierarchy(r).map_err(|rc| rc.param(2))?;
    end(r)?;
    let handle = first(handles)?;
    let sequence = sequence_mut(tpm, handle, 1)?;
    match &mut sequence.kind {
        SequenceKind::Hash {
            hasher,
            started,
            safe,
        } => {
            let hash = hasher.hash();
            let mut hasher = Hasher::clone(hasher);
            hasher.update(data);
            let digest = hasher.finish();
            let safe = if *started {
                *safe
            } else {
                is_ticket_safe(data)
            };
            w.tpm2b(&digest);
            if hierarchy == TPM_RH_NULL || !safe {
                null_ticket(w);
            } else {
                tpm.write_hash_check(hierarchy, hash, &digest, w);
            }
        }
        SequenceKind::Event { .. } => return Err(Rc::MODE.handle(1)),
    }
    w.flush = Some(handle);
    Ok(())
}

/// TPM2_EventSequenceComplete: an event sequence's digests, each extended into the PCR (unless
/// it is TPM_RH_NULL). The sequence is flushed.
pub fn event_sequence_complete(
    tpm: &mut Tpm,
    handles: &[u32],
    r: &mut Reader,
    w: &mut Out,
) -> Result<()> {
    let data = r.tpm2b(MAX_BUFFER).map_err(|rc| rc.param(1))?;
    end(r)?;
    let pcr = first(handles)?;
    let handle = handles.get(1).copied().ok_or(Rc::FAILURE)?;
    let sequence = sequence_mut(tpm, handle, 2)?;
    let SequenceKind::Event { hashers } = &sequence.kind else {
        return Err(Rc::MODE.handle(2));
    };
    let digests: Vec<_> = (hashers.iter())
        .map(|h| {
            let mut h = h.clone();
            h.update(data);
            (h.hash(), h.finish())
        })
        .collect();
    if let Some(pcr) = tpm.pcr_to_extend(pcr)? {
        tpm.extend(pcr, &digests);
    }
    write_digest_values(w, &digests);
    w.flush = Some(handle);
    Ok(())
}
