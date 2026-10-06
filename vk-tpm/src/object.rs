//! Transient objects (Part 1, "Object Structure Elements"): the TPM's [`MAX_OBJECTS`] object
//! slots, named TRANSIENT_FIRST + slot. So far only hash and event sequences live in them, with
//! the commands that drive them (Part 3, "Hash/HMAC/Event Sequences") and TPM2_Hash, which
//! shares their tickets.

use zeroize::Zeroizing;

use crate::alg::{Hash, Hasher, MAX_DIGEST};
use crate::commands::{end, first, write_digest_values};
use crate::crypt;
use crate::entity::{TPM_RH_ENDORSEMENT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM, strip_zeros};
use crate::hierarchy::Auth;
use crate::marshal::{Reader, Writer};
use crate::rc::{Rc, Result};
use crate::state::{StateError, read_bool};
use crate::{Out, Tpm};

/// How many objects the TPM holds at once (MAX_LOADED_OBJECTS, as libtpms).
pub const MAX_OBJECTS: usize = 3;
pub const TRANSIENT_FIRST: u32 = 0x8000_0000;
/// The largest buffer a sequence or TPM2_Hash takes in one command (TPM2B_MAX_BUFFER).
const MAX_BUFFER: usize = 1024;
/// TPM_ST_HASHCHECK, the tag of a TPMT_TK_HASHCHECK.
const TPM_ST_HASHCHECK: u16 = 0x8024;
/// TPM_GENERATED_VALUE: what the TPM puts first in the structures it signs. A digest of data
/// that starts with it gets no ticket, so a ticket cannot vouch for a forged attestation.
const TPM_GENERATED_VALUE: [u8; 4] = [0xff, b'T', b'C', b'G'];

/// A loaded object.
pub enum Object {
    Sequence(Sequence),
}

/// A hash or event sequence (TPM2_HashSequenceStart): data in, digests out at the end.
pub struct Sequence {
    pub auth: Auth,
    pub kind: SequenceKind,
}

pub enum SequenceKind {
    /// A hash sequence, and whether its ticket may be issued: its first block did not start
    /// with TPM_GENERATED_VALUE (`safe`, once `started`).
    Hash {
        hasher: Box<Hasher>,
        started: bool,
        safe: bool,
    },
    /// An event sequence: one digest per PCR bank.
    Event { hashers: Vec<Hasher> },
}

impl Object {
    /// The object's authValue (a sequence's, as TPM2_HashSequenceStart set it).
    pub fn auth(&self) -> &Auth {
        match self {
            Object::Sequence(s) => &s.auth,
        }
    }

    pub fn write(&self, w: &mut Writer) {
        let Object::Sequence(s) = self;
        w.tpm2b(&s.auth);
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
}

/// The handle of object slot `slot`.
fn handle(slot: usize) -> Result<u32> {
    u32::try_from(slot)
        .ok()
        .and_then(|s| TRANSIENT_FIRST.checked_add(s))
        .ok_or(Rc::FAILURE)
}

/// The slot a transient handle names, whether or not something is loaded there.
fn slot(handle: u32) -> Option<usize> {
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

    /// Load `object` into the first free slot, and return its handle.
    fn load_object(&mut self, object: Object) -> Result<u32> {
        let (slot, free) = (self.volatile.objects.iter_mut().enumerate())
            .find(|(_, o)| o.is_none())
            .ok_or(Rc::OBJECT_MEMORY)?;
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

    /// TicketComputeHashCheck: the ticket that says the TPM computed `digest` (with `hash`) of
    /// data that did not start with TPM_GENERATED_VALUE: an HMAC with the hierarchy's proof.
    fn hash_check(&self, hierarchy: u32, hash: Hash, digest: &[u8], w: &mut Writer) {
        let h = &self.permanent.hierarchies;
        let proof = match hierarchy {
            TPM_RH_PLATFORM => &h.ph_proof,
            TPM_RH_ENDORSEMENT => &h.eh_proof,
            _ => &h.sh_proof,
        };
        let tag = TPM_ST_HASHCHECK.to_be_bytes();
        let ticket = crypt::hmac(
            Hash::Sha512,
            proof.as_slice(),
            &[&tag, &hash.id().to_be_bytes(), digest],
        );
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
fn read_hierarchy(r: &mut Reader) -> Result<u32> {
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
        tpm.hash_check(hierarchy, hash, &digest, w);
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

/// TPM2_SequenceUpdate: more data into a sequence.
pub fn sequence_update(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let data = r.tpm2b(MAX_BUFFER).map_err(|rc| rc.param(1))?;
    end(r)?;
    let Object::Sequence(sequence) = tpm.object_mut(first(handles)?)?;
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
    let Object::Sequence(sequence) = tpm.object_mut(handle)?;
    let SequenceKind::Hash {
        hasher,
        started,
        safe,
    } = &mut sequence.kind
    else {
        return Err(Rc::MODE.handle(1));
    };
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
        tpm.hash_check(hierarchy, hash, &digest, w);
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
    let Object::Sequence(sequence) = tpm.object_mut(handle)?;
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

/// TPM2_FlushContext: unload an object or a session.
pub fn flush_context(tpm: &mut Tpm, _: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    // TPMI_DH_CONTEXT: a session or a transient object handle.
    let handle = (|| {
        let h = r.u32()?;
        let session = crate::entity::is_session(h);
        if session || slot(h).is_some() {
            Ok(h)
        } else {
            Err(Rc::VALUE)
        }
    })()
    .map_err(|rc| rc.param(1))?;
    end(r)?;
    if tpm.object(handle).is_some() {
        tpm.flush_object(handle);
        Ok(())
    } else {
        // No session can be loaded yet.
        Err(Rc::HANDLE.param(1))
    }
}
