//! The variables themselves: what a variable is, how they are looked up and enumerated, and the
//! room they may take.

use crate::guid::Guid;

/// EFI_STATUS values the service returns (UINTN, the high bit marking errors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status(pub u64);

const ERR: u64 = 1 << 63;

impl Status {
    pub const SUCCESS: Status = Status(0);
    pub const INVALID_PARAMETER: Status = Status(ERR | 2);
    pub const UNSUPPORTED: Status = Status(ERR | 3);
    pub const BAD_BUFFER_SIZE: Status = Status(ERR | 4);
    pub const BUFFER_TOO_SMALL: Status = Status(ERR | 5);
    pub const WRITE_PROTECTED: Status = Status(ERR | 8);
    pub const OUT_OF_RESOURCES: Status = Status(ERR | 9);
    pub const NOT_FOUND: Status = Status(ERR | 14);
    pub const ACCESS_DENIED: Status = Status(ERR | 15);
    pub const ALREADY_STARTED: Status = Status(ERR | 20);
    pub const SECURITY_VIOLATION: Status = Status(ERR | 26);

    pub fn is_error(self) -> bool {
        self.0 & ERR != 0
    }
}

pub const NON_VOLATILE: u32 = 0x01;
pub const BOOTSERVICE_ACCESS: u32 = 0x02;
pub const RUNTIME_ACCESS: u32 = 0x04;
pub const HARDWARE_ERROR_RECORD: u32 = 0x08;
pub const AUTHENTICATED_WRITE_ACCESS: u32 = 0x10;
pub const TIME_BASED_AUTHENTICATED_WRITE_ACCESS: u32 = 0x20;
pub const APPEND_WRITE: u32 = 0x40;
/// The attributes a variable keeps (EFI_VARIABLE_ATTRIBUTES_MASK minus APPEND_WRITE, which is
/// a property of a write, and the deprecated count-based authentication).
pub const STORED_ATTRIBUTES: u32 = NON_VOLATILE
    | BOOTSERVICE_ACCESS
    | RUNTIME_ACCESS
    | HARDWARE_ERROR_RECORD
    | TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

/// The largest variable (name and data) the service takes, as edk2's 4 MiB OVMF build allows
/// (PcdMaxVariableSize and PcdMaxAuthVariableSize, 0x8400, less a variable header).
pub const MAX_VARIABLE_SIZE: usize = 0x8400 - AUTH_VARIABLE_HEADER_SIZE;
/// The room the non-volatile variables have: what fits the 4 MiB build's store (0x40000) once
/// its headers are counted, so that the store file can always hold them.
pub const NV_STORAGE_SIZE: usize = 0x40000;
/// Volatile variables are few (SecureBoot, SetupMode, ...): a generous fixed budget.
pub const VOLATILE_STORAGE_SIZE: usize = 0x40000;
/// edk2's AUTHENTICATED_VARIABLE_HEADER, which each stored variable costs.
pub const AUTH_VARIABLE_HEADER_SIZE: usize = 60;

/// EFI_TIME, as authenticated variables carry it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EfiTime(pub [u8; 16]);

impl EfiTime {
    /// The fields an ordering compares: year, month, day, hour, minute, second (edk2 ignores
    /// the nanoseconds, as the time zone and daylight fields must be zero).
    fn key(&self) -> (u16, u8, u8, u8, u8, u8) {
        let b = &self.0;
        (
            u16::from_le_bytes([b[0], b[1]]),
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
        )
    }

    /// Whether `self` is later than `other`.
    pub fn later_than(&self, other: &EfiTime) -> bool {
        self.key() > other.key()
    }

    /// Whether the fields an authenticated write must leave zero (Pad1, Nanosecond, TimeZone,
    /// Daylight, Pad2) are zero.
    pub fn is_clean(&self) -> bool {
        self.0
            .get(7..)
            .is_some_and(|rest| rest.iter().all(|b| *b == 0))
    }
}

/// One variable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Variable {
    pub guid: Guid,
    /// The name's UCS-2 code units, without the terminating NUL.
    pub name: Vec<u16>,
    /// STORED_ATTRIBUTES only.
    pub attributes: u32,
    pub data: Vec<u8>,
    /// The last authenticated write's timestamp (time-based authenticated variables).
    pub timestamp: EfiTime,
}

impl Variable {
    pub fn non_volatile(&self) -> bool {
        self.attributes & NON_VOLATILE != 0
    }

    /// The room it takes in a store: header, name with its NUL, data, each aligned on 4 bytes.
    pub fn stored_size(&self) -> usize {
        let name = self.name.len().saturating_add(1).saturating_mul(2);
        AUTH_VARIABLE_HEADER_SIZE
            .saturating_add(name)
            .saturating_add(self.data.len())
            .saturating_add(3)
            & !3
    }
}

/// The variables, in creation order: GetNextVariableName enumerates them so, and a store file
/// keeps them so.
#[derive(Clone, Debug, Default)]
pub struct Store {
    vars: Vec<Variable>,
}

impl Store {
    pub fn iter(&self) -> impl Iterator<Item = &Variable> {
        self.vars.iter()
    }

    pub fn position(&self, guid: &Guid, name: &[u16]) -> Option<usize> {
        self.vars
            .iter()
            .position(|v| v.guid == *guid && v.name == name)
    }

    pub fn find(&self, guid: &Guid, name: &[u16]) -> Option<&Variable> {
        self.position(guid, name).and_then(|i| self.vars.get(i))
    }

    pub fn get(&self, index: usize) -> Option<&Variable> {
        self.vars.get(index)
    }

    /// Replace the variable at `index`, or add `var` at the end.
    pub fn put(&mut self, index: Option<usize>, var: Variable) {
        match index.and_then(|i| self.vars.get_mut(i)) {
            Some(slot) => *slot = var,
            None => self.vars.push(var),
        }
    }

    pub fn remove(&mut self, index: usize) -> Option<Variable> {
        (index < self.vars.len()).then(|| self.vars.remove(index))
    }

    /// The room the non-volatile (or volatile) variables take.
    pub fn used(&self, non_volatile: bool) -> usize {
        self.vars
            .iter()
            .filter(|v| v.non_volatile() == non_volatile)
            .fold(0usize, |sum, v| sum.saturating_add(v.stored_size()))
    }

    pub fn len(&self) -> usize {
        self.vars.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }
}
