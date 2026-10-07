//! edk2's variable store flash image, which is also this service's file: a firmware volume
//! holding an authenticated variable store, followed by the fault-tolerant write areas edk2
//! keeps there. The machines vk made before the service (and the store templates it ships)
//! have one; the service reads it, and writes the variables back in place, so that a store
//! stays readable by the firmware's own variable driver as before.

use crate::codec::{Reader, Short, align_up, get, put};
use crate::guid;
use crate::store::{EfiTime, STORED_ATTRIBUTES, Store, Variable};

/// VARIABLE_STORE_HEADER: signature GUID, size, format, state, reserved.
const STORE_HEADER_SIZE: usize = 28;
const VARIABLE_STORE_FORMATTED: u8 = 0x5a;
const VARIABLE_STORE_HEALTHY: u8 = 0xfe;
/// AUTHENTICATED_VARIABLE_HEADER's StartId.
const VARIABLE_DATA: u16 = 0x55aa;
const VAR_ADDED: u8 = 0x3f;
const VAR_IN_DELETED_TRANSITION: u8 = 0xfe;
/// EFI_FIRMWARE_VOLUME_HEADER's signature, "_FVH".
const FVH_SIGNATURE: u32 = 0x4856_465f;

/// Why a store image was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// Not an edk2 variable store flash image.
    NotAStore(&'static str),
    /// The variables no longer fit the image.
    Full,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NotAStore(why) => write!(f, "not an edk2 variable store: {why}"),
            StoreError::Full => write!(f, "the variables no longer fit the store"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<Short> for StoreError {
    fn from(_: Short) -> Self {
        StoreError::NotAStore("truncated")
    }
}

/// A store image: its bytes, where its variables start and end.
#[derive(Clone, Debug)]
pub struct Image {
    bytes: Vec<u8>,
    /// Offset of the variable store header within the image.
    store: usize,
    /// The store's size, from its header (header included).
    store_size: usize,
}

impl Image {
    /// Take an image: the firmware volume header, then the variable store header right after it.
    pub fn parse(bytes: Vec<u8>) -> Result<Image, StoreError> {
        let mut fv = Reader::new(&bytes);
        fv.take(16)?; // ZeroVector
        let fs = fv.guid()?;
        let length = fv.u64()?;
        let signature = fv.u32()?;
        fv.u32()?; // Attributes
        let header_length = usize::from(fv.u16()?);
        if signature != FVH_SIGNATURE || fs != guid::SYSTEM_NV_DATA_FV {
            return Err(StoreError::NotAStore("no NV data firmware volume header"));
        }
        if usize::try_from(length).map_or(true, |l| l > bytes.len()) {
            return Err(StoreError::NotAStore(
                "firmware volume longer than the image",
            ));
        }
        let mut st = Reader::new(get(&bytes, header_length, STORE_HEADER_SIZE)?);
        let sig = st.guid()?;
        let size = usize::try_from(st.u32()?).map_err(|_| StoreError::NotAStore("size"))?;
        let format = st.u8()?;
        let state = st.u8()?;
        if sig != guid::AUTHENTICATED_VARIABLE {
            return Err(StoreError::NotAStore(
                "not the authenticated variable format",
            ));
        }
        if format != VARIABLE_STORE_FORMATTED || state != VARIABLE_STORE_HEALTHY {
            return Err(StoreError::NotAStore("variable store not formatted"));
        }
        if header_length
            .checked_add(size)
            .is_none_or(|end| end > bytes.len())
        {
            return Err(StoreError::NotAStore(
                "variable store larger than the image",
            ));
        }
        Ok(Image {
            bytes,
            store: header_length,
            store_size: size,
        })
    }

    /// The image's bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The room for variables (the store less its header).
    pub fn capacity(&self) -> usize {
        self.store_size.saturating_sub(STORE_HEADER_SIZE)
    }

    /// The variables the store holds: each one added and not deleted, its last copy winning
    /// (edk2 writes a new copy before it marks the old one deleted).
    pub fn variables(&self) -> Result<Store, StoreError> {
        let mut store = Store::default();
        let start = self.store.checked_add(STORE_HEADER_SIZE).ok_or(Short)?;
        let end = self.store.checked_add(self.store_size).ok_or(Short)?;
        let mut at = start;
        while let Some(next) = at.checked_add(crate::store::AUTH_VARIABLE_HEADER_SIZE) {
            if next > end {
                break;
            }
            let mut h = Reader::new(get(
                &self.bytes,
                at,
                crate::store::AUTH_VARIABLE_HEADER_SIZE,
            )?);
            if h.u16()? != VARIABLE_DATA {
                break;
            }
            let state = h.u8()?;
            h.u8()?;
            let attributes = h.u32()?;
            h.u64()?; // MonotonicCount
            let mut ts = [0u8; 16];
            ts.copy_from_slice(h.take(16)?);
            h.u32()?; // PubKeyIndex
            let name_size = usize::try_from(h.u32()?).map_err(|_| Short)?;
            let data_size = usize::try_from(h.u32()?).map_err(|_| Short)?;
            let vendor = h.guid()?;
            let name_at = next;
            let data_at = name_at.checked_add(name_size).ok_or(Short)?;
            let var_end = data_at.checked_add(data_size).ok_or(Short)?;
            if var_end > end {
                return Err(StoreError::NotAStore("a variable runs past the store"));
            }
            if state == VAR_ADDED || state == VAR_ADDED & VAR_IN_DELETED_TRANSITION {
                let name = crate::codec::ucs2_name(get(&self.bytes, name_at, name_size)?).ok_or(
                    StoreError::NotAStore("a variable name is not NUL-terminated"),
                )?;
                let var = Variable {
                    guid: vendor,
                    name,
                    attributes: attributes & STORED_ATTRIBUTES,
                    data: get(&self.bytes, data_at, data_size)?.to_vec(),
                    timestamp: EfiTime(ts),
                };
                let index = store.position(&var.guid, &var.name);
                store.put(index, var);
            }
            at = align_up(var_end, 4).ok_or(Short)?;
        }
        Ok(store)
    }

    /// Write the non-volatile variables of `store` into the image's variable store, compacted,
    /// the rest of the store erased (0xff) as edk2 leaves free space.
    pub fn write(&mut self, store: &Store) -> Result<(), StoreError> {
        let start = self.store.checked_add(STORE_HEADER_SIZE).ok_or(Short)?;
        let end = self.store.checked_add(self.store_size).ok_or(Short)?;
        let area = self.bytes.get_mut(start..end).ok_or(Short)?;
        area.fill(0xff);
        let mut at = 0usize;
        for var in store.iter().filter(|v| v.non_volatile()) {
            let record = record(var)?;
            let record_end = at.checked_add(record.len()).ok_or(StoreError::Full)?;
            if record_end > area.len() {
                return Err(StoreError::Full);
            }
            put(area, at, &record)?;
            at = align_up(record_end, 4).ok_or(StoreError::Full)?;
        }
        Ok(())
    }
}

/// One variable as edk2's authenticated store holds it: header, name, data (unaligned end).
fn record(var: &Variable) -> Result<Vec<u8>, StoreError> {
    let name = crate::codec::ucs2_bytes(&var.name);
    let name_size = u32::try_from(name.len()).map_err(|_| StoreError::Full)?;
    let data_size = u32::try_from(var.data.len()).map_err(|_| StoreError::Full)?;
    let mut out = Vec::with_capacity(
        crate::store::AUTH_VARIABLE_HEADER_SIZE
            .saturating_add(name.len())
            .saturating_add(var.data.len()),
    );
    out.extend_from_slice(&VARIABLE_DATA.to_le_bytes());
    out.push(VAR_ADDED);
    out.push(0);
    out.extend_from_slice(&var.attributes.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&var.timestamp.0);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&name_size.to_le_bytes());
    out.extend_from_slice(&data_size.to_le_bytes());
    out.extend_from_slice(&var.guid.0);
    out.extend_from_slice(&name);
    out.extend_from_slice(&var.data);
    Ok(out)
}
