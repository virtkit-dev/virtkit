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
use crate::commands::{end, first, read_yes_no, write_digest_values};
use crate::crypt;
use crate::entity::{TPM_RH_ENDORSEMENT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM, strip_zeros};
use crate::hierarchy::Auth;
use crate::key::{Key, hash_block_size};
use crate::marshal::{Reader, Writer};
use crate::public::{Params, TPM_ALG_CMAC, TPM_ALG_ECB, Type, attr, is_block_mode};
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

/// A hash, HMAC or event sequence: data in, digests out at the end.
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
    /// An HMAC sequence (TPM2_HMAC_Start), kept as RFC 2104 has it so it can be saved: the
    /// inner hash, started with the key XOR ipad, and the key (padded to the hash's block) the
    /// outer hash needs at the end.
    Hmac {
        inner: Box<Hasher>,
        key: Zeroizing<Vec<u8>>,
    },
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
            SequenceKind::Hmac { inner, key } => {
                w.u8(2).u16(inner.hash().id()).tpm2b(&inner.save());
                w.tpm2b(key);
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
            2 => SequenceKind::Hmac {
                inner: Box::new(hasher(r)?),
                key: Zeroizing::new(r.tpm2b(128)?.to_vec()),
            },
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
        SequenceKind::Hmac { inner, .. } => inner.update(data),
    }
    Ok(())
}

/// TPM2_SequenceComplete: a hash sequence's digest and ticket, or an HMAC sequence's HMAC. The
/// sequence is flushed.
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
        SequenceKind::Hmac { inner, key } => {
            let mut inner = Hasher::clone(inner);
            inner.update(data);
            w.tpm2b(&hmac_finish(inner, key));
            null_ticket(w);
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

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// The HMAC key padded to the hash's block (hashed first if longer): RFC 2104's K0.
fn hmac_key(hash: Hash, key: &[u8]) -> Zeroizing<Vec<u8>> {
    let block = hash_block_size(hash);
    let mut k = Zeroizing::new(if key.len() > block {
        hash.digest(&[key])
    } else {
        key.to_vec()
    });
    k.resize(block, 0);
    k
}

/// An HMAC sequence's inner hash, started.
fn hmac_start(hash: Hash, key: &[u8]) -> (Box<Hasher>, Zeroizing<Vec<u8>>) {
    let k = hmac_key(hash, key);
    let ipad = Zeroizing::new(k.iter().map(|b| b ^ IPAD).collect::<Vec<u8>>());
    let mut inner = Hasher::new(hash);
    inner.update(&ipad);
    (Box::new(inner), k)
}

/// The HMAC: H(K0 ^ opad ‖ inner).
fn hmac_finish(inner: Hasher, key: &[u8]) -> Vec<u8> {
    let hash = inner.hash();
    let inner = inner.finish();
    let opad = Zeroizing::new(key.iter().map(|b| b ^ OPAD).collect::<Vec<u8>>());
    hash.digest(&[&opad, &inner])
}

/// TPMI_ALG_MAC_SCHEME+: a hash for an HMAC (or CMAC, which vk-tpm does not implement); None
/// for TPM_ALG_NULL.
fn read_mac_scheme(r: &mut Reader) -> Result<Option<u16>> {
    match r.u16()? {
        crate::alg::TPM_ALG_NULL => Ok(None),
        TPM_ALG_CMAC => Ok(Some(TPM_ALG_CMAC)),
        id if Hash::from_id(id).is_some() => Ok(Some(id)),
        _ => Err(Rc::SYMMETRIC),
    }
}

/// CryptSelectMac and the key checks of TPM2_MAC and TPM2_MAC_Start (TPM2_HMAC and
/// TPM2_HMAC_Start, the same commands before CMAC): the key and the hash to HMAC with.
fn mac_key(tpm: &Tpm, handle: u32, scheme: Option<u16>) -> Result<(Hash, Zeroizing<Vec<u8>>)> {
    let key = tpm.key(handle).ok_or(Rc::TYPE.handle(1))?;
    let own = match &key.public.params {
        Params::KeyedHash(s) => s.hash.map(Hash::id),
        Params::SymCipher(def) => Some(def.mode).filter(|&m| m != crate::alg::TPM_ALG_NULL),
        _ => return Err(Rc::TYPE.handle(1)),
    };
    let mac = match (scheme, own) {
        (Some(s), Some(o)) if s != o => return Err(Rc::VALUE.param(2)),
        (Some(s), _) => s,
        (None, Some(o)) => o,
        (None, None) => return Err(Rc::VALUE.param(2)),
    };
    // A symmetric key would do CMAC, not implemented; a keyed hash takes a hash.
    let hash = match (key.public.kind(), Hash::from_id(mac)) {
        (Type::KeyedHash, Some(hash)) => hash,
        _ => return Err(Rc::SCHEME.param(2)),
    };
    if key.public.has(attr::RESTRICTED) {
        return Err(Rc::ATTRIBUTES.handle(1));
    }
    if !key.public.has(attr::SIGN) {
        return Err(Rc::KEY.handle(1));
    }
    let secret = key.sensitive.as_ref().map_or(&[][..], |s| &s.secret);
    Ok((hash, Zeroizing::new(secret.to_vec())))
}

/// TPM2_HMAC_Start (TPM2_MAC_Start): an HMAC sequence with a keyed-hash key.
pub fn hmac_start_command(
    tpm: &mut Tpm,
    handles: &[u32],
    r: &mut Reader,
    w: &mut Out,
) -> Result<()> {
    let auth = Zeroizing::new(strip_zeros(r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(1))?).to_vec());
    let scheme = read_mac_scheme(r).map_err(|rc| rc.param(2))?;
    end(r)?;
    let (hash, key) = mac_key(tpm, first(handles)?, scheme)?;
    let (inner, key) = hmac_start(hash, &key);
    let kind = SequenceKind::Hmac { inner, key };
    w.handle = Some(tpm.load_object(Object::Sequence(Sequence { auth, kind }))?);
    Ok(())
}

/// TPM2_HMAC (TPM2_MAC): the HMAC of a buffer, in one command.
pub fn hmac(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let data = r.tpm2b(MAX_BUFFER).map_err(|rc| rc.param(1))?;
    let scheme = read_mac_scheme(r).map_err(|rc| rc.param(2))?;
    end(r)?;
    let (hash, key) = mac_key(tpm, first(handles)?, scheme)?;
    w.tpm2b(&crypt::hmac(hash, &key, &[data]));
    Ok(())
}

/// TPMI_ALG_CIPHER_MODE+: a block cipher mode, or TPM_ALG_NULL.
fn read_cipher_mode(r: &mut Reader) -> Result<u16> {
    let mode = r.u16()?;
    if mode == crate::alg::TPM_ALG_NULL || is_block_mode(mode) {
        Ok(mode)
    } else {
        Err(Rc::MODE)
    }
}

/// The parameters of TPM2_EncryptDecrypt and TPM2_EncryptDecrypt2, and the numbers errors give
/// them in each (`blame`: mode, ivIn, inData).
struct Cipher<'a> {
    decrypt: bool,
    mode: u16,
    iv: &'a [u8],
    data: &'a [u8],
    blame: (u32, u32, u32),
}

/// EncryptDecryptShared: `data` through an unrestricted symmetric key, its decrypt attribute
/// to decrypt, its sign attribute to encrypt; the key's mode, or the caller's if it has none.
fn encrypt_decrypt_shared(tpm: &Tpm, handle: u32, c: &Cipher, w: &mut Out) -> Result<()> {
    let (blame_mode, blame_iv, blame_data) = c.blame;
    let key = tpm.key(handle).ok_or(Rc::KEY.handle(1))?;
    let Params::SymCipher(def) = &key.public.params else {
        return Err(Rc::KEY.handle(1));
    };
    let allowed = if c.decrypt { attr::DECRYPT } else { attr::SIGN };
    if key.public.has(attr::RESTRICTED) || !key.public.has(allowed) {
        return Err(Rc::ATTRIBUTES.handle(1));
    }
    let null = crate::alg::TPM_ALG_NULL;
    if def.mode != null && !is_block_mode(def.mode) {
        return Err(Rc::MODE.handle(1));
    }
    let mode = match (def.mode, c.mode) {
        (own, asked) if own != null && asked != null && asked != own => {
            return Err(Rc::MODE.param(blame_mode));
        }
        (own, _) if own != null => own,
        (_, asked) if asked != null => asked,
        _ => return Err(Rc::MODE.param(blame_mode)),
    };
    let iv_size = if mode == TPM_ALG_ECB {
        0
    } else {
        crypt::AES_BLOCK
    };
    if c.iv.len() != iv_size {
        return Err(Rc::SIZE.param(blame_iv));
    }
    if (mode == TPM_ALG_ECB || mode == crate::public::TPM_ALG_CBC)
        && !c.data.len().is_multiple_of(crypt::AES_BLOCK)
    {
        return Err(Rc::SIZE.param(blame_data));
    }
    let secret = key.sensitive.as_ref().map_or(&[][..], |s| &s.secret);
    let mut data = Zeroizing::new(c.data.to_vec());
    let mut iv = [0u8; crypt::AES_BLOCK];
    iv.get_mut(..c.iv.len())
        .ok_or(Rc::FAILURE)?
        .copy_from_slice(c.iv);
    let iv_out = crypt::aes_mode(secret, mode, iv, &mut data, c.decrypt)?;
    w.tpm2b(&data);
    w.tpm2b(iv_out.get(..iv_size).ok_or(Rc::FAILURE)?);
    Ok(())
}

/// TPM2_EncryptDecrypt: data through a symmetric key.
pub fn encrypt_decrypt(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let decrypt = read_yes_no(r).map_err(|rc| rc.param(1))?;
    let mode = read_cipher_mode(r).map_err(|rc| rc.param(2))?;
    let iv = r.tpm2b(crypt::AES_BLOCK).map_err(|rc| rc.param(3))?;
    let data = r.tpm2b(MAX_BUFFER).map_err(|rc| rc.param(4))?;
    end(r)?;
    let c = Cipher {
        decrypt,
        mode,
        iv,
        data,
        blame: (2, 3, 4),
    };
    encrypt_decrypt_shared(tpm, first(handles)?, &c, w)
}

/// TPM2_EncryptDecrypt2: TPM2_EncryptDecrypt with the data first, so a session may encrypt it.
pub fn encrypt_decrypt2(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let data = r.tpm2b(MAX_BUFFER).map_err(|rc| rc.param(1))?;
    let decrypt = read_yes_no(r).map_err(|rc| rc.param(2))?;
    let mode = read_cipher_mode(r).map_err(|rc| rc.param(3))?;
    let iv = r.tpm2b(crypt::AES_BLOCK).map_err(|rc| rc.param(4))?;
    end(r)?;
    let c = Cipher {
        decrypt,
        mode,
        iv,
        data,
        blame: (3, 4, 1),
    };
    encrypt_decrypt_shared(tpm, first(handles)?, &c, w)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_hmac_sequence_is_hmac() {
        for hash in Hash::ALL {
            for key in [&b"k"[..], &[7; 200]] {
                let (mut inner, k) = hmac_start(hash, key);
                inner.update(b"some ");
                let saved = Hasher::load(hash, &inner.save()).unwrap();
                let mut inner = saved;
                inner.update(b"data");
                assert_eq!(
                    hmac_finish(inner, &k),
                    crypt::hmac(hash, key, &[b"some data"])
                );
            }
        }
    }
}
