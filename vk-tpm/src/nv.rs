//! NV indices (Part 1, "NV Memory"; Part 3, "Non-volatile Storage"; the reference
//! implementation's `NV_spt.c` and `NvDynamic.c`): TPM2_NV_DefineSpace and the commands that use
//! an index.
//!
//! An index lives in the permanent state: its public area, authValue and data. An index with
//! TPMA_NV_ORDERLY is the exception, as in the reference: its attributes and data live in RAM
//! (the volatile state) and reach the permanent state only at TPM2_Shutdown, or when the TPM
//! must not lose them (the index is defined or deleted, a counter is first written or crosses a
//! [`MAX_ORDERLY_COUNT`] boundary). A TPM that loses power without an orderly shutdown starts
//! again from what was last stored, and moves each orderly counter past any value it may have
//! reported.
//!
//! The index's type (TPM_NT) decides what its data is: ordinary bytes, a counter, a bit field, an
//! extend digest, or a PIN pass/fail counter and limit (each 8 bytes but the extend digest).

use zeroize::Zeroizing;

use crate::alg::{Hash, MAX_DIGEST};
use crate::commands::{end, first};
use crate::entity::{TPM_RH_OWNER, TPM_RH_PLATFORM, strip_zeros};
use crate::hierarchy::Auth;
use crate::marshal::{Reader, Writer};
use crate::pcr::Startup;
use crate::rc::{Rc, Result};
use crate::state::StateError;
use crate::{Out, Tpm};

/// The first and last NV index handles (TPM_HT_NV_INDEX).
pub const NV_INDEX_FIRST: u32 = 0x0100_0000;
pub const NV_INDEX_LAST: u32 = 0x01ff_ffff;
/// The largest index (MAX_NV_INDEX_SIZE) and the most one command reads or writes
/// (MAX_NV_BUFFER_SIZE), as libtpms has them.
pub const MAX_NV_INDEX_SIZE: usize = 2048;
pub const MAX_NV_BUFFER_SIZE: usize = 1024;
/// RAM for orderly indices (RAM_INDEX_SPACE), each taking a 12-byte header and its data, as in
/// the reference.
const RAM_INDEX_SPACE: usize = 512;
const RAM_HEADER: usize = 12;
/// An orderly counter is stored at least every 2^ORDERLY_BITS increments; after a power loss it
/// resumes past the next such boundary.
pub const MAX_ORDERLY_COUNT: u64 = (1 << 8) - 1;
/// The NV memory indices may take: each costs [`INDEX_COST`] plus its data (an orderly index's
/// data lives in RAM). vk-tpm's own budget (libtpms shares its NV with the persistent objects).
const NV_INDEX_SPACE: usize = 64 * 1024;
const INDEX_COST: usize = 160;

/// TPMA_NV bits.
pub mod attr {
    pub const PPWRITE: u32 = 1 << 0;
    pub const OWNERWRITE: u32 = 1 << 1;
    pub const AUTHWRITE: u32 = 1 << 2;
    pub const POLICYWRITE: u32 = 1 << 3;
    /// TPM_NT, bits 4 to 7.
    pub const TPM_NT_SHIFT: u32 = 4;
    pub const TPM_NT: u32 = 0xf << TPM_NT_SHIFT;
    pub const POLICY_DELETE: u32 = 1 << 10;
    pub const WRITELOCKED: u32 = 1 << 11;
    pub const WRITEALL: u32 = 1 << 12;
    pub const WRITEDEFINE: u32 = 1 << 13;
    pub const WRITE_STCLEAR: u32 = 1 << 14;
    pub const GLOBALLOCK: u32 = 1 << 15;
    pub const PPREAD: u32 = 1 << 16;
    pub const OWNERREAD: u32 = 1 << 17;
    pub const AUTHREAD: u32 = 1 << 18;
    pub const POLICYREAD: u32 = 1 << 19;
    pub const NO_DA: u32 = 1 << 25;
    pub const ORDERLY: u32 = 1 << 26;
    pub const CLEAR_STCLEAR: u32 = 1 << 27;
    pub const READLOCKED: u32 = 1 << 28;
    pub const WRITTEN: u32 = 1 << 29;
    pub const PLATFORMCREATE: u32 = 1 << 30;
    pub const READ_STCLEAR: u32 = 1 << 31;
    /// The bits TPMA_NV_Unmarshal refuses with TPM_RC_RESERVED_BITS.
    pub const RESERVED: u32 = 0x0000_0300 | 0x01f0_0000;
}

/// TPM_NT: what an index's data is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Ordinary,
    Counter,
    Bits,
    Extend,
    PinFail,
    PinPass,
}

impl Kind {
    /// The type the attributes give, if it is one the TPM has.
    pub fn of(attributes: u32) -> Option<Kind> {
        Some(match (attributes & attr::TPM_NT) >> attr::TPM_NT_SHIFT {
            0x0 => Kind::Ordinary,
            0x1 => Kind::Counter,
            0x2 => Kind::Bits,
            0x4 => Kind::Extend,
            0x8 => Kind::PinFail,
            0x9 => Kind::PinPass,
            _ => return None,
        })
    }

    fn is_pin(self) -> bool {
        matches!(self, Kind::PinFail | Kind::PinPass)
    }
}

/// A TPMS_NV_PUBLIC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NvPublic {
    pub index: u32,
    pub name_alg: Hash,
    pub attributes: u32,
    pub auth_policy: Vec<u8>,
    pub data_size: u16,
}

impl NvPublic {
    pub fn read(r: &mut Reader) -> Result<NvPublic> {
        let index = read_index(r)?;
        let name_alg = Hash::read(r)?;
        let attributes = r.u32()?;
        if attributes & attr::RESERVED != 0 {
            return Err(Rc::RESERVED_BITS);
        }
        let auth_policy = r.tpm2b(MAX_DIGEST)?.to_vec();
        let data_size = r.u16()?;
        if usize::from(data_size) > MAX_NV_INDEX_SIZE {
            return Err(Rc::SIZE);
        }
        Ok(NvPublic {
            index,
            name_alg,
            attributes,
            auth_policy,
            data_size,
        })
    }

    /// A TPM2B_NV_PUBLIC: its size must be exactly the structure's.
    pub fn read_sized(r: &mut Reader) -> Result<NvPublic> {
        let size = usize::from(r.u16()?);
        if size == 0 {
            return Err(Rc::SIZE);
        }
        let before = r.len();
        let public = NvPublic::read(r)?;
        if before.saturating_sub(r.len()) != size {
            return Err(Rc::SIZE);
        }
        Ok(public)
    }

    pub fn write(&self, w: &mut Writer) {
        w.u32(self.index)
            .u16(self.name_alg.id())
            .u32(self.attributes)
            .tpm2b(&self.auth_policy)
            .u16(self.data_size);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.write(&mut w);
        w.into_bytes()
    }

    /// The index's Name: nameAlg ‖ H(TPMS_NV_PUBLIC), its attributes as they are now.
    pub fn name(&self) -> Vec<u8> {
        let hash = self.name_alg;
        [
            &hash.id().to_be_bytes()[..],
            &hash.digest(&[&self.to_bytes()]),
        ]
        .concat()
    }

    pub fn has(&self, attribute: u32) -> bool {
        self.attributes & attribute != 0
    }

    pub fn kind(&self) -> Option<Kind> {
        Kind::of(self.attributes)
    }

    pub fn size(&self) -> usize {
        usize::from(self.data_size)
    }

    /// The data size fits the index's type: an extend index holds a digest of its nameAlg, a
    /// counter, bit field or PIN index 8 bytes.
    fn size_fits(&self) -> bool {
        match self.kind() {
            Some(Kind::Ordinary) => self.size() <= MAX_NV_INDEX_SIZE,
            Some(Kind::Extend) => self.size() == self.name_alg.size(),
            Some(_) => self.size() == 8,
            None => false,
        }
    }
}

/// A TPMI_RH_NV_INDEX.
pub fn read_index(r: &mut Reader) -> Result<u32> {
    let handle = r.u32()?;
    if is_nv_index(handle) {
        Ok(handle)
    } else {
        Err(Rc::VALUE)
    }
}

pub fn is_nv_index(handle: u32) -> bool {
    (NV_INDEX_FIRST..=NV_INDEX_LAST).contains(&handle)
}

/// An NV index as the permanent state keeps it. For an orderly index, `public.attributes` and
/// `data` are what was last stored; the TPM uses its RAM copy ([`OrderlyRam`]).
#[derive(Clone)]
pub struct NvIndex {
    pub public: NvPublic,
    pub auth: Auth,
    pub data: Zeroizing<Vec<u8>>,
}

impl NvIndex {
    pub fn write(&self, w: &mut Writer) {
        self.public.write(w);
        w.tpm2b(&self.auth).tpm2b(&self.data);
    }

    pub fn read(r: &mut Reader) -> std::result::Result<NvIndex, StateError> {
        let public = NvPublic::read(r)?;
        let auth = Zeroizing::new(r.tpm2b(MAX_DIGEST)?.to_vec());
        let data = Zeroizing::new(r.tpm2b(MAX_NV_INDEX_SIZE)?.to_vec());
        if data.len() != public.size() || !public.size_fits() {
            return Err(StateError("bad NV index"));
        }
        Ok(NvIndex { public, auth, data })
    }

    /// The memory it takes from [`NV_INDEX_SPACE`].
    fn cost(&self) -> usize {
        if self.public.has(attr::ORDERLY) {
            INDEX_COST
        } else {
            INDEX_COST.saturating_add(self.data.len())
        }
    }
}

/// An orderly index's attributes and data, in RAM (the volatile state).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderlyRam {
    pub index: u32,
    pub attributes: u32,
    pub data: Zeroizing<Vec<u8>>,
}

impl OrderlyRam {
    pub fn write(&self, w: &mut Writer) {
        w.u32(self.index).u32(self.attributes).tpm2b(&self.data);
    }

    pub fn read(r: &mut Reader) -> std::result::Result<OrderlyRam, StateError> {
        Ok(OrderlyRam {
            index: r.u32()?,
            attributes: r.u32()?,
            data: Zeroizing::new(r.tpm2b(MAX_NV_INDEX_SIZE)?.to_vec()),
        })
    }

    pub fn read_list(r: &mut Reader) -> std::result::Result<Vec<OrderlyRam>, StateError> {
        let count = r.count(RAM_INDEX_SPACE / RAM_HEADER)?;
        (0..count).map(|_| OrderlyRam::read(r)).collect()
    }

    pub fn write_list(w: &mut Writer, list: &[OrderlyRam]) {
        w.count(list.len());
        for ram in list {
            ram.write(w);
        }
    }
}

/// The RAM copies of the orderly indices, as the permanent state last stored them.
pub fn orderly_images(indices: &[NvIndex]) -> Vec<OrderlyRam> {
    (indices.iter())
        .filter(|i| i.public.has(attr::ORDERLY))
        .map(|i| OrderlyRam {
            index: i.public.index,
            attributes: i.public.attributes,
            data: i.data.clone(),
        })
        .collect()
}

/// The NV indices, then the highest value a deleted counter had (the reference keeps it at the
/// end of its NV list): a new counter starts above it.
pub fn write_nv(w: &mut Writer, indices: &[NvIndex], max_counter: u64) {
    w.count(indices.len());
    for index in indices {
        index.write(w);
    }
    w.u64(max_counter);
}

pub fn read_nv(r: &mut Reader) -> std::result::Result<(Vec<NvIndex>, u64), StateError> {
    let count = r.count(NV_INDEX_SPACE / INDEX_COST)?;
    let mut indices: Vec<NvIndex> = Vec::with_capacity(count);
    for _ in 0..count {
        let index = NvIndex::read(r)?;
        if indices
            .last()
            .is_some_and(|last| last.public.index >= index.public.index)
        {
            return Err(StateError("NV indices out of order"));
        }
        indices.push(index);
    }
    if nv_used(&indices) > NV_INDEX_SPACE || ram_used(&indices) > RAM_INDEX_SPACE {
        return Err(StateError("NV indices over their memory"));
    }
    Ok((indices, r.u64()?))
}

/// The memory the indices take from [`NV_INDEX_SPACE`].
fn nv_used(indices: &[NvIndex]) -> usize {
    indices.iter().map(NvIndex::cost).sum()
}

/// The memory the orderly indices take from [`RAM_INDEX_SPACE`].
fn ram_used(indices: &[NvIndex]) -> usize {
    (indices.iter())
        .filter(|i| i.public.has(attr::ORDERLY))
        .map(|i| RAM_HEADER.saturating_add(i.data.len()))
        .sum()
}

/// A snapshot restores one RAM copy per orderly index, matching its size and attributes
/// except those commands change.
pub fn check_orderly(
    indices: &[NvIndex],
    ram: &[OrderlyRam],
) -> std::result::Result<(), StateError> {
    const CHANGING: u32 = attr::WRITTEN | attr::WRITELOCKED | attr::READLOCKED;
    let is_copy = |o: &OrderlyRam| {
        indices.iter().any(|i| {
            i.public.index == o.index
                && i.public.has(attr::ORDERLY)
                && (i.public.attributes ^ o.attributes) & !CHANGING == 0
                && o.data.len() == i.public.size()
        })
    };
    let unique = (ram.iter().enumerate())
        .all(|(n, o)| ram.iter().take(n).all(|earlier| earlier.index != o.index));
    let orderly = (indices.iter())
        .filter(|i| i.public.has(attr::ORDERLY))
        .count();
    if ram.len() == orderly && unique && ram.iter().all(is_copy) {
        Ok(())
    } else {
        Err(StateError("bad orderly NV RAM"))
    }
}

/// What an index's data holds before it is written: NV memory's erased state (0xff), or RAM's
/// (zeros) for an orderly index, as in the reference. A written index's data is all
/// written; one partly written (a PIN index) keeps the rest.
fn erased(orderly: bool) -> u8 {
    if orderly { 0 } else { 0xff }
}

/// TPMS_NV_PIN_COUNTER_PARAMETERS: pinCount, then pinLimit, each big-endian.
fn pin(data: &[u8]) -> (u32, u32) {
    let word = |i: usize| {
        data.get(i..i.saturating_add(4))
            .and_then(|b| b.try_into().ok())
            .map_or(0, u32::from_be_bytes)
    };
    (word(0), word(4))
}

impl Tpm {
    fn nv_position(&self, index: u32) -> Option<usize> {
        let list = &self.permanent.nv;
        list.binary_search_by_key(&index, |i| i.public.index).ok()
    }

    fn nv_entry(&self, index: u32) -> Option<&NvIndex> {
        self.permanent.nv.get(self.nv_position(index)?)
    }

    fn orderly_ram(&self, index: u32) -> Option<&OrderlyRam> {
        self.volatile.nv_orderly.iter().find(|o| o.index == index)
    }

    /// The index's public area, its attributes as they are now (an orderly index's from RAM).
    pub fn nv_public(&self, index: u32) -> Option<NvPublic> {
        let entry = self.nv_entry(index)?;
        let mut public = entry.public.clone();
        if let Some(ram) = self
            .orderly_ram(index)
            .filter(|_| public.has(attr::ORDERLY))
        {
            public.attributes = ram.attributes;
        }
        Some(public)
    }

    /// The index a command names (EntityGetLoadStatus checked it exists).
    fn index_public(&self, index: u32) -> Result<NvPublic> {
        self.nv_public(index).ok_or(Rc::FAILURE)
    }

    /// The index's data as it is now.
    pub fn nv_data(&self, index: u32) -> Option<&[u8]> {
        let entry = self.nv_entry(index)?;
        if entry.public.has(attr::ORDERLY)
            && let Some(ram) = self.orderly_ram(index)
        {
            return Some(&ram.data);
        }
        Some(&entry.data)
    }

    /// The index's authValue, without trailing zeros.
    pub fn nv_auth(&self, index: u32) -> Option<&[u8]> {
        self.nv_entry(index).map(|e| strip_zeros(&e.auth))
    }

    /// How many indices are defined, and how many of them are counters.
    pub fn nv_counts(&self) -> (usize, usize) {
        let counters = (self.permanent.nv.iter())
            .filter(|i| i.public.kind() == Some(Kind::Counter))
            .count();
        (self.permanent.nv.len(), counters)
    }

    /// The handles of the defined indices, in order.
    pub fn nv_handles(&self) -> Vec<u32> {
        self.permanent.nv.iter().map(|i| i.public.index).collect()
    }

    /// TPM_PT_NV_COUNTERS_AVAIL: how many more counters fit, in NV and (orderly) in RAM.
    pub fn nv_counters_available(&self) -> usize {
        let nv = NV_INDEX_SPACE
            .saturating_sub(nv_used(&self.permanent.nv))
            .checked_div(INDEX_COST.saturating_add(8));
        let ram = RAM_INDEX_SPACE
            .saturating_sub(ram_used(&self.permanent.nv))
            .checked_div(RAM_HEADER.saturating_add(8));
        nv.unwrap_or(0).min(ram.unwrap_or(0))
    }

    /// NvIndexIsAccessible: the index exists, and the hierarchy it belongs to (the platform's
    /// NV for PLATFORMCREATE, else the owner's) is enabled.
    pub fn nv_accessible(&self, index: u32) -> Result<()> {
        let public = self.nv_public(index).ok_or(Rc::HANDLE)?;
        let enabled = if public.has(attr::PLATFORMCREATE) {
            self.volatile.clear.ph_enable_nv
        } else {
            self.volatile.clear.sh_enable
        };
        if enabled { Ok(()) } else { Err(Rc::HANDLE) }
    }

    fn orderly_ram_mut(&mut self, index: u32) -> Option<&mut OrderlyRam> {
        self.volatile
            .nv_orderly
            .iter_mut()
            .find(|o| o.index == index)
    }

    /// The index's attributes and data as the TPM uses them (an orderly index's RAM copy).
    fn nv_live_mut(&mut self, index: u32) -> Option<(&mut u32, &mut Zeroizing<Vec<u8>>)> {
        if self.nv_entry(index)?.public.has(attr::ORDERLY) {
            let ram = self.orderly_ram_mut(index)?;
            Some((&mut ram.attributes, &mut ram.data))
        } else {
            let i = self.nv_position(index)?;
            let entry = self.permanent.nv.get_mut(i)?;
            Some((&mut entry.public.attributes, &mut entry.data))
        }
    }

    /// NvWriteIndexAttributes: set the index's attributes. Store an orderly index's RAM copy
    /// at once (the reference's UT_ORDERLY) so locks survive power loss; invalidate the
    /// recorded orderly shutdown.
    fn nv_set_attributes(&mut self, index: u32, attributes: u32) {
        if let Some((current, _)) = self.nv_live_mut(index) {
            *current = attributes;
        }
        if attributes & attr::ORDERLY != 0 {
            self.clear_orderly();
            self.nv_store_orderly();
        }
    }

    /// NvWriteIndexData: write `bytes` at `offset` (the caller checked the range). The first
    /// write sets TPMA_NV_WRITTEN, and erases an ordinary index first; writing an orderly index
    /// voids the orderly shutdown recorded.
    fn nv_write(&mut self, index: u32, offset: usize, bytes: &[u8]) -> Result<()> {
        let (attributes, data) = self.nv_live_mut(index).ok_or(Rc::FAILURE)?;
        let first = *attributes & attr::WRITTEN == 0;
        let orderly = *attributes & attr::ORDERLY != 0;
        let kind = Kind::of(*attributes);
        *attributes |= attr::WRITTEN;
        if first && kind == Some(Kind::Ordinary) {
            data.fill(erased(orderly));
        }
        let end = offset.checked_add(bytes.len()).ok_or(Rc::FAILURE)?;
        data.get_mut(offset..end)
            .ok_or(Rc::FAILURE)?
            .copy_from_slice(bytes);
        if orderly {
            self.clear_orderly();
            // The reference stores the RAM copy at once when a counter is first written.
            if first && kind == Some(Kind::Counter) {
                self.nv_store_orderly();
            }
        }
        Ok(())
    }

    fn nv_write_u64(&mut self, index: u32, value: u64) -> Result<()> {
        self.nv_write(index, 0, &value.to_be_bytes())
    }

    /// NvGetUINT64Data: a counter's, bit field's or PIN index's 8 bytes.
    fn nv_u64(&self, index: u32) -> u64 {
        self.nv_data(index)
            .and_then(|d| d.get(..8))
            .and_then(|b| b.try_into().ok())
            .map_or(0, u64::from_be_bytes)
    }

    /// NvUpdateIndexOrderlyData: store the RAM copies of the orderly indices.
    pub fn nv_store_orderly(&mut self) {
        for ram in &self.volatile.nv_orderly {
            let list = &self.permanent.nv;
            let Ok(i) = list.binary_search_by_key(&ram.index, |e| e.public.index) else {
                continue;
            };
            if let Some(entry) = self.permanent.nv.get_mut(i) {
                entry.public.attributes = ram.attributes;
                entry.data.clone_from(&ram.data);
            }
        }
    }

    /// NvDeleteIndex: a written counter's value is remembered, so a counter defined later
    /// starts above it.
    fn nv_delete(&mut self, index: u32) {
        let Some(public) = self.nv_public(index) else {
            return;
        };
        if public.kind() == Some(Kind::Counter) && public.has(attr::WRITTEN) {
            let value = self.nv_u64(index);
            let max = &mut self.permanent.nv_max_counter;
            *max = (*max).max(value);
        }
        self.permanent.nv.retain(|e| e.public.index != index);
        self.volatile.nv_orderly.retain(|o| o.index != index);
        if public.has(attr::ORDERLY) {
            self.nv_store_orderly();
        }
    }

    /// The owner's part of TPM2_Clear (NvFlushHierarchy): every index not PLATFORMCREATE goes.
    pub fn nv_flush_owner(&mut self) {
        let owned: Vec<u32> = (self.permanent.nv.iter())
            .filter(|e| !e.public.has(attr::PLATFORMCREATE))
            .map(|e| e.public.index)
            .collect();
        for index in owned {
            self.nv_delete(index);
        }
    }

    /// NvEntityStartup: the orderly indices come back from what was stored; and unless the TPM
    /// resumes, each index loses its read lock, a write lock that does not outlive the Startup,
    /// and (TPMA_NV_CLEAR_STCLEAR, or an orderly index at a TPM Reset) its data. An orderly
    /// counter that may have counted past what was stored skips to the next boundary.
    pub fn nv_startup(&mut self, kind: Startup, orderly: bool) {
        self.volatile.nv_orderly = orderly_images(&self.permanent.nv);
        if kind == Startup::Resume {
            return;
        }
        let startup = |attributes: u32| {
            let mut a = attributes & !attr::READLOCKED;
            if Kind::of(a) != Some(Kind::Counter)
                && (a & attr::CLEAR_STCLEAR != 0
                    || (a & attr::ORDERLY != 0 && kind == Startup::Reset))
            {
                a &= !attr::WRITTEN;
            }
            if a & attr::WRITTEN == 0 || a & attr::WRITEDEFINE == 0 {
                a &= !attr::WRITELOCKED;
            }
            a
        };
        for entry in &mut self.permanent.nv {
            if !entry.public.has(attr::ORDERLY) {
                entry.public.attributes = startup(entry.public.attributes);
            }
        }
        for ram in &mut self.volatile.nv_orderly {
            ram.attributes = startup(ram.attributes);
            if Kind::of(ram.attributes) == Some(Kind::Counter) && !orderly {
                let value = ram.data.get(..8).and_then(|b| b.try_into().ok());
                let value = value.map_or(0, u64::from_be_bytes) | MAX_ORDERLY_COUNT;
                if let Some(d) = ram.data.get_mut(..8) {
                    d.copy_from_slice(&value.to_be_bytes());
                }
            }
        }
    }

    /// IsAuthValueAvailable for an index: AUTHWRITE for a write, else AUTHREAD (a PIN index:
    /// while its count is below its limit).
    pub fn nv_auth_value_available(&self, index: u32, write: bool) -> bool {
        let Some(public) = self.nv_public(index) else {
            return false;
        };
        if write {
            return public.has(attr::AUTHWRITE);
        }
        if public.kind().is_some_and(Kind::is_pin) {
            let (count, limit) = pin(self.nv_data(index).unwrap_or_default());
            return public.has(attr::WRITTEN) && count < limit;
        }
        public.has(attr::AUTHREAD)
    }

    /// IsAuthPolicyAvailable for an index: it has an authPolicy, and the role (ADMIN), or
    /// POLICYWRITE for a write, POLICYREAD otherwise, allows a policy session.
    pub fn nv_auth_policy_available(&self, index: u32, admin: bool, write: bool) -> bool {
        let Some(public) = self.nv_public(index) else {
            return false;
        };
        let allowed = if admin {
            true
        } else if write {
            public.has(attr::POLICYWRITE)
        } else {
            public.has(attr::POLICYREAD)
        };
        !public.auth_policy.is_empty() && allowed
    }

    /// After an authorization of a written PIN index (CheckAuthSession): a PIN fail index
    /// counts the failure or starts over on success, a PIN pass index counts the success.
    pub fn nv_pin_authorized(&mut self, index: u32, success: bool) -> Result<()> {
        let Some(public) = self.nv_public(index) else {
            return Ok(());
        };
        if !public.has(attr::WRITTEN) {
            return Ok(());
        }
        let (count, limit) = pin(self.nv_data(index).unwrap_or_default());
        let count = match public.kind() {
            Some(Kind::PinFail) if success => 0,
            Some(Kind::PinFail) => count.wrapping_add(1),
            Some(Kind::PinPass) if success => count.wrapping_add(1),
            _ => return Ok(()),
        };
        let mut bytes = [0u8; 8];
        bytes[..4].copy_from_slice(&count.to_be_bytes());
        bytes[4..].copy_from_slice(&limit.to_be_bytes());
        self.nv_write(index, 0, &bytes)
    }

    /// Whether the index is a PIN index (TPM2_StartAuthSession may not bind to one).
    pub fn nv_is_pin(&self, index: u32) -> bool {
        self.nv_public(index)
            .and_then(|p| p.kind())
            .is_some_and(Kind::is_pin)
    }
}

/// NvReadAccessChecks: `auth` (owner, platform, or the index) may read the index, which is not
/// read-locked and was written.
pub fn read_access(auth: u32, index: u32, public: &NvPublic) -> Result<()> {
    if public.has(attr::READLOCKED) {
        return Err(Rc::NV_LOCKED);
    }
    let allowed = match auth {
        TPM_RH_OWNER => public.has(attr::OWNERREAD),
        TPM_RH_PLATFORM => public.has(attr::PPREAD),
        _ => auth == index,
    };
    if !allowed {
        return Err(Rc::NV_AUTHORIZATION);
    }
    if !public.has(attr::WRITTEN) {
        return Err(Rc::NV_UNINITIALIZED);
    }
    Ok(())
}

/// NvWriteAccessChecks: `auth` may write the index, which is not write-locked.
pub fn write_access(auth: u32, index: u32, public: &NvPublic) -> Result<()> {
    if public.has(attr::WRITELOCKED) {
        return Err(Rc::NV_LOCKED);
    }
    let allowed = match auth {
        TPM_RH_OWNER => public.has(attr::OWNERWRITE),
        TPM_RH_PLATFORM => public.has(attr::PPWRITE),
        _ => auth == index,
    };
    if allowed {
        Ok(())
    } else {
        Err(Rc::NV_AUTHORIZATION)
    }
}

/// The authorizing handle and the index of a command that takes both.
fn auth_and_index(handles: &[u32]) -> Result<(u32, u32)> {
    Ok((first(handles)?, handles.get(1).copied().ok_or(Rc::FAILURE)?))
}

/// TPM2_NV_DefineSpace (NvDefineSpace).
pub fn define_space(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let auth = Zeroizing::new(r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(1))?.to_vec());
    let public = NvPublic::read_sized(r).map_err(|rc| rc.param(2))?;
    end(r)?;
    let auth_handle = first(handles)?;
    let a = public.attributes;
    let has = |bit| a & bit != 0;
    let digest_size = public.name_alg.size();
    if !public.auth_policy.is_empty() && public.auth_policy.len() != digest_size {
        return Err(Rc::SIZE.param(2));
    }
    let auth = Zeroizing::new(strip_zeros(&auth).to_vec());
    if auth.len() > digest_size {
        return Err(Rc::SIZE.param(1));
    }
    if auth_handle == TPM_RH_PLATFORM && !tpm.volatile.clear.ph_enable_nv {
        return Err(Rc::HIERARCHY.handle(1));
    }
    let kind = Kind::of(a).ok_or(Rc::ATTRIBUTES.param(2))?;
    if !public.size_fits() {
        return Err(Rc::SIZE.param(2));
    }
    let kind_ok = match kind {
        Kind::Counter => !has(attr::CLEAR_STCLEAR),
        Kind::PinFail => {
            has(attr::NO_DA)
                && !has(attr::AUTHWRITE)
                && !has(attr::GLOBALLOCK)
                && !has(attr::WRITEDEFINE)
        }
        Kind::PinPass => !has(attr::AUTHWRITE) && !has(attr::GLOBALLOCK) && !has(attr::WRITEDEFINE),
        _ => true,
    };
    if !kind_ok
        || has(attr::WRITTEN)
        || has(attr::WRITELOCKED)
        || has(attr::READLOCKED)
        || a & (attr::OWNERREAD | attr::PPREAD | attr::AUTHREAD | attr::POLICYREAD) == 0
        || a & (attr::OWNERWRITE | attr::PPWRITE | attr::AUTHWRITE | attr::POLICYWRITE) == 0
        || (has(attr::CLEAR_STCLEAR) && has(attr::WRITEDEFINE))
    {
        return Err(Rc::ATTRIBUTES.param(2));
    }
    if has(attr::PLATFORMCREATE) != (auth_handle == TPM_RH_PLATFORM) {
        return Err(Rc::ATTRIBUTES.handle(1));
    }
    if has(attr::POLICY_DELETE) && auth_handle != TPM_RH_PLATFORM {
        return Err(Rc::ATTRIBUTES.param(2));
    }
    if public.size() > MAX_NV_BUFFER_SIZE && has(attr::WRITEALL) {
        return Err(Rc::SIZE.param(2));
    }
    if tpm.nv_position(public.index).is_some() {
        return Err(Rc::NV_DEFINED);
    }
    let entry = NvIndex {
        data: Zeroizing::new(vec![erased(has(attr::ORDERLY)); public.size()]),
        public,
        auth,
    };
    if nv_used(&tpm.permanent.nv).saturating_add(entry.cost()) > NV_INDEX_SPACE {
        return Err(Rc::NV_SPACE);
    }
    let orderly = entry.public.has(attr::ORDERLY);
    let ram_needed = RAM_HEADER.saturating_add(entry.data.len());
    if orderly && ram_used(&tpm.permanent.nv).saturating_add(ram_needed) > RAM_INDEX_SPACE {
        return Err(Rc::NV_SPACE);
    }
    let (index, size) = (entry.public.index, entry.public.data_size);
    let list = &mut tpm.permanent.nv;
    let at = list.partition_point(|e| e.public.index < index);
    list.insert(at, entry);
    if orderly {
        tpm.volatile.nv_orderly.push(OrderlyRam {
            index,
            attributes: a,
            data: Zeroizing::new(vec![0; usize::from(size)]),
        });
        tpm.nv_store_orderly();
    }
    Ok(())
}

/// TPM2_NV_UndefineSpace: the owner may not delete what the platform created, and nobody an
/// index that needs its policy to be deleted (TPM2_NV_UndefineSpaceSpecial).
pub fn undefine_space(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    end(r)?;
    let (auth, index) = auth_and_index(handles)?;
    let public = tpm.index_public(index)?;
    if public.has(attr::POLICY_DELETE) {
        return Err(Rc::ATTRIBUTES.handle(2));
    }
    if auth == TPM_RH_OWNER && public.has(attr::PLATFORMCREATE) {
        return Err(Rc::NV_AUTHORIZATION);
    }
    tpm.nv_delete(index);
    Ok(())
}

/// TPM2_NV_UndefineSpaceSpecial: an index with TPMA_NV_POLICY_DELETE, its policy satisfied (the
/// ADMIN role) and the platform's authorization given.
pub fn undefine_space_special(
    tpm: &mut Tpm,
    handles: &[u32],
    r: &mut Reader,
    _: &mut Out,
) -> Result<()> {
    end(r)?;
    let index = first(handles)?;
    if !tpm.index_public(index)?.has(attr::POLICY_DELETE) {
        return Err(Rc::ATTRIBUTES.handle(1));
    }
    tpm.nv_delete(index);
    Ok(())
}

/// TPM2_NV_ReadPublic: the public area and Name.
pub fn read_public(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    end(r)?;
    let public = tpm.index_public(first(handles)?)?;
    w.tpm2b(&public.to_bytes()).tpm2b(&public.name());
    Ok(())
}

/// TPM2_NV_Write: an ordinary (or PIN) index's bytes, whole if TPMA_NV_WRITEALL.
pub fn write(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let data = r.tpm2b(MAX_NV_BUFFER_SIZE).map_err(|rc| rc.param(1))?;
    let offset = usize::from(r.u16().map_err(|rc| rc.param(2))?);
    end(r)?;
    let (auth, index) = auth_and_index(handles)?;
    let public = tpm.index_public(index)?;
    write_access(auth, index, &public)?;
    if matches!(
        public.kind(),
        Some(Kind::Counter | Kind::Bits | Kind::Extend)
    ) {
        return Err(Rc::ATTRIBUTES);
    }
    if offset > public.size() {
        return Err(Rc::VALUE.param(2));
    }
    if data.len() > public.size().saturating_sub(offset) {
        return Err(Rc::NV_RANGE);
    }
    if public.has(attr::WRITEALL) && data.len() < public.size() {
        return Err(Rc::NV_RANGE);
    }
    tpm.nv_write(index, offset, data)
}

/// TPM2_NV_Increment: a counter; its first value is above any counter's deleted before.
pub fn increment(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    end(r)?;
    let (auth, index) = auth_and_index(handles)?;
    let public = tpm.index_public(index)?;
    write_access(auth, index, &public)?;
    if public.kind() != Some(Kind::Counter) {
        return Err(Rc::ATTRIBUTES.handle(2));
    }
    let value = if public.has(attr::WRITTEN) {
        tpm.nv_u64(index)
    } else {
        tpm.permanent.nv_max_counter
    };
    let value = value.wrapping_add(1);
    tpm.nv_write_u64(index, value)?;
    // An orderly counter is stored each time it crosses a boundary.
    if public.has(attr::ORDERLY) && value & MAX_ORDERLY_COUNT == 0 {
        tpm.nv_store_orderly();
    }
    Ok(())
}

/// TPM2_NV_Extend: an extend index's digest := H(digest ‖ data).
pub fn extend(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let data = r.tpm2b(MAX_NV_BUFFER_SIZE).map_err(|rc| rc.param(1))?;
    end(r)?;
    let (auth, index) = auth_and_index(handles)?;
    let public = tpm.index_public(index)?;
    write_access(auth, index, &public)?;
    if public.kind() != Some(Kind::Extend) {
        return Err(Rc::ATTRIBUTES.handle(2));
    }
    let hash = public.name_alg;
    let old = if public.has(attr::WRITTEN) {
        tpm.nv_data(index).unwrap_or_default().to_vec()
    } else {
        vec![0; hash.size()]
    };
    let digest = hash.digest(&[&old, data]);
    tpm.nv_write(index, 0, &digest)
}

/// TPM2_NV_SetBits: OR bits into a bit field.
pub fn set_bits(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let bits = r.u64().map_err(|rc| rc.param(1))?;
    end(r)?;
    let (auth, index) = auth_and_index(handles)?;
    let public = tpm.index_public(index)?;
    write_access(auth, index, &public)?;
    if public.kind() != Some(Kind::Bits) {
        return Err(Rc::ATTRIBUTES.handle(2));
    }
    let old = if public.has(attr::WRITTEN) {
        tpm.nv_u64(index)
    } else {
        0
    };
    tpm.nv_write_u64(index, old | bits)
}

/// TPM2_NV_WriteLock: lock writes until the next Startup (TPMA_NV_WRITE_STCLEAR) or for good
/// (TPMA_NV_WRITEDEFINE, once written). Locking a locked index succeeds.
pub fn write_lock(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    end(r)?;
    let (auth, index) = auth_and_index(handles)?;
    let public = tpm.index_public(index)?;
    match write_access(auth, index, &public) {
        Ok(()) => {}
        Err(rc) if rc == Rc::NV_AUTHORIZATION => return Err(rc),
        Err(_) => return Ok(()),
    }
    if !public.has(attr::WRITEDEFINE) && !public.has(attr::WRITE_STCLEAR) {
        return Err(Rc::ATTRIBUTES.handle(2));
    }
    tpm.nv_set_attributes(index, public.attributes | attr::WRITELOCKED);
    Ok(())
}

/// TPM2_NV_ReadLock: lock reads until the next Startup (TPMA_NV_READ_STCLEAR). Locking a
/// locked or never written index succeeds.
pub fn read_lock(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    end(r)?;
    let (auth, index) = auth_and_index(handles)?;
    let public = tpm.index_public(index)?;
    match read_access(auth, index, &public) {
        Err(rc) if rc == Rc::NV_AUTHORIZATION => return Err(rc),
        Err(rc) if rc == Rc::NV_LOCKED => return Ok(()),
        _ => {}
    }
    if !public.has(attr::READ_STCLEAR) {
        return Err(Rc::ATTRIBUTES.handle(2));
    }
    tpm.nv_set_attributes(index, public.attributes | attr::READLOCKED);
    Ok(())
}

/// TPM2_NV_GlobalWriteLock: write-lock every index with TPMA_NV_GLOBALLOCK.
pub fn global_write_lock(tpm: &mut Tpm, _: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    end(r)?;
    for index in tpm.nv_handles() {
        if let Some(public) = tpm.nv_public(index)
            && public.has(attr::GLOBALLOCK)
        {
            tpm.nv_set_attributes(index, public.attributes | attr::WRITELOCKED);
        }
    }
    Ok(())
}

/// TPM2_NV_Read: `size` bytes from `offset`.
pub fn read(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let size = usize::from(r.u16().map_err(|rc| rc.param(1))?);
    let offset = usize::from(r.u16().map_err(|rc| rc.param(2))?);
    end(r)?;
    let (auth, index) = auth_and_index(handles)?;
    let public = tpm.index_public(index)?;
    read_access(auth, index, &public)?;
    if size > MAX_NV_BUFFER_SIZE {
        return Err(Rc::VALUE.param(1));
    }
    if offset > public.size() {
        return Err(Rc::VALUE.param(2));
    }
    if size > public.size().saturating_sub(offset) {
        return Err(Rc::NV_RANGE);
    }
    let data = tpm.nv_data(index).unwrap_or_default();
    let end = offset.saturating_add(size);
    w.tpm2b(data.get(offset..end).ok_or(Rc::FAILURE)?);
    Ok(())
}

/// TPM2_NV_ChangeAuth: a new authValue (the ADMIN role: the index's policy).
pub fn change_auth(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let new_auth = r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(1))?;
    end(r)?;
    let index = first(handles)?;
    let public = tpm.index_public(index)?;
    let new_auth = strip_zeros(new_auth);
    if new_auth.len() > public.name_alg.size() {
        return Err(Rc::SIZE.param(1));
    }
    let i = tpm.nv_position(index).ok_or(Rc::FAILURE)?;
    let entry = tpm.permanent.nv.get_mut(i).ok_or(Rc::FAILURE)?;
    entry.auth = Zeroizing::new(new_auth.to_vec());
    Ok(())
}
