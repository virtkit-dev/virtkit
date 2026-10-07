//! edk2's variable policies (VariablePolicyLib), which the firmware registers through the
//! VarCheckPolicy MM handler and the service enforces on SetVariable: size bounds, attributes
//! a variable must or cannot have, and locks.

use crate::codec::{Reader, Short, get};
use crate::guid::Guid;
use crate::store::Status;

const POLICY_ENTRY_REVISION: u32 = 0x0001_0000;
const POLICY_ENTRY_SIZE: usize = 40;
const NO_MIN_SIZE: u32 = 0;
const LOCK_NONE: u8 = 0;
const LOCK_NOW: u8 = 1;
const LOCK_ON_CREATE: u8 = 2;
const LOCK_ON_VAR_STATE: u8 = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Lock {
    None,
    Now,
    OnCreate,
    /// Locked while the variable `name` in `guid` holds the single byte `value`.
    OnVarState {
        guid: Guid,
        name: Vec<u16>,
        value: u8,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// The entry as registered, for a snapshot to register it again.
    raw: Vec<u8>,
    guid: Guid,
    /// None: every variable of the namespace. A '#' matches any hex digit, as in edk2.
    name: Option<Vec<u16>>,
    min_size: u32,
    max_size: u32,
    must_have: u32,
    cant_have: u32,
    lock: Lock,
}

impl Policy {
    /// Parse a VARIABLE_POLICY_ENTRY and what follows it, as REGISTER carries them.
    pub fn parse(bytes: &[u8]) -> Option<Policy> {
        let parse = || -> Result<Policy, Short> {
            let mut r = Reader::new(bytes);
            let version = r.u32()?;
            let size = usize::from(r.u16()?);
            let name_at = usize::from(r.u16()?);
            let guid = r.guid()?;
            let min_size = r.u32()?;
            let max_size = r.u32()?;
            let must_have = r.u32()?;
            let cant_have = r.u32()?;
            let lock_type = r.u8()?;
            if version != POLICY_ENTRY_REVISION || size > bytes.len() || size < POLICY_ENTRY_SIZE {
                return Err(Short);
            }
            let entry = get(bytes, 0, size)?;
            let name = if name_at == 0 || name_at >= size {
                None
            } else {
                Some(name_units(get(
                    entry,
                    name_at,
                    size.saturating_sub(name_at),
                )?)?)
            };
            let lock = match lock_type {
                LOCK_NONE => Lock::None,
                LOCK_NOW => Lock::Now,
                LOCK_ON_CREATE => Lock::OnCreate,
                LOCK_ON_VAR_STATE => {
                    let end = if name_at == 0 { size } else { name_at };
                    let state = get(
                        entry,
                        POLICY_ENTRY_SIZE,
                        end.saturating_sub(POLICY_ENTRY_SIZE),
                    )?;
                    let mut s = Reader::new(state);
                    let guid = s.guid()?;
                    let value = s.u8()?;
                    s.u8()?;
                    Lock::OnVarState {
                        guid,
                        name: name_units(s.rest())?,
                        value,
                    }
                }
                _ => return Err(Short),
            };
            Ok(Policy {
                raw: entry.to_vec(),
                guid,
                name,
                min_size,
                max_size,
                must_have,
                cant_have,
                lock,
            })
        };
        parse().ok()
    }

    fn matches(&self, guid: &Guid, name: &[u16]) -> bool {
        if self.guid != *guid {
            return false;
        }
        let Some(pattern) = &self.name else {
            return true;
        };
        pattern.len() == name.len()
            && pattern.iter().zip(name).all(|(p, c)| {
                *p == *c
                    || (*p == u16::from(b'#')
                        && char::from_u32(u32::from(*c)).is_some_and(|c| c.is_ascii_hexdigit()))
            })
    }

    /// How specific the policy is, to pick the best match: a full name, then wildcards, then
    /// a namespace.
    fn rank(&self) -> usize {
        match &self.name {
            None => 0,
            Some(n) => n
                .iter()
                .filter(|c| **c != u16::from(b'#'))
                .count()
                .saturating_add(1),
        }
    }
}

/// A UCS-2 name ending with NUL within `bytes`, without the NUL.
fn name_units(bytes: &[u8]) -> Result<Vec<u16>, Short> {
    let mut out = Vec::new();
    for c in bytes.as_chunks::<2>().0 {
        let unit = u16::from_le_bytes(*c);
        if unit == 0 {
            return Ok(out);
        }
        out.push(unit);
    }
    Err(Short)
}

/// The registered policies and the interface state.
#[derive(Clone, Debug)]
pub struct Policies {
    list: Vec<Policy>,
    enabled: bool,
    locked: bool,
}

impl Default for Policies {
    fn default() -> Self {
        Policies {
            list: Vec::new(),
            enabled: true,
            locked: false,
        }
    }
}

impl Policies {
    /// (enabled, locked, each policy's entry) for a snapshot.
    pub fn save(&self) -> (bool, bool, Vec<&[u8]>) {
        (
            self.enabled,
            self.locked,
            self.list.iter().map(|p| p.raw.as_slice()).collect(),
        )
    }

    /// Policies a snapshot saved; entries that no longer parse are dropped.
    pub fn restore(enabled: bool, locked: bool, entries: &[Vec<u8>]) -> Policies {
        Policies {
            list: entries.iter().filter_map(|e| Policy::parse(e)).collect(),
            enabled,
            locked,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn disable(&mut self) -> Status {
        if self.locked {
            return Status::WRITE_PROTECTED;
        }
        self.enabled = false;
        Status::SUCCESS
    }

    pub fn lock(&mut self) {
        self.locked = true;
    }

    pub fn register(&mut self, policy: Policy) -> Status {
        if self.locked {
            return Status::WRITE_PROTECTED;
        }
        if self
            .list
            .iter()
            .any(|p| p.guid == policy.guid && p.name == policy.name)
        {
            return Status::ALREADY_STARTED;
        }
        self.list.push(policy);
        Status::SUCCESS
    }

    /// Whether a write of `size` bytes with `attributes` to `name` in `guid` passes the most
    /// specific policy that covers it. `exists` says whether the variable exists; `state`
    /// looks up another variable's value for LOCK_ON_VAR_STATE. A delete (size 0) is only held
    /// to the locks.
    pub fn check(
        &self,
        guid: &Guid,
        name: &[u16],
        attributes: u32,
        size: usize,
        exists: bool,
        state: impl Fn(&Guid, &[u16]) -> Option<Vec<u8>>,
    ) -> Status {
        if !self.enabled {
            return Status::SUCCESS;
        }
        let Some(policy) = self
            .list
            .iter()
            .filter(|p| p.matches(guid, name))
            .max_by_key(|p| p.rank())
        else {
            return Status::SUCCESS;
        };
        let locked = match &policy.lock {
            Lock::None => false,
            Lock::Now => true,
            Lock::OnCreate => exists,
            Lock::OnVarState { guid, name, value } => {
                state(guid, name).is_some_and(|data| data.as_slice() == [*value])
            }
        };
        if locked {
            return Status::WRITE_PROTECTED;
        }
        if size == 0 {
            return Status::SUCCESS;
        }
        let size = u32::try_from(size).unwrap_or(u32::MAX);
        if (policy.min_size != NO_MIN_SIZE && size < policy.min_size)
            || size > policy.max_size
            || attributes & policy.must_have != policy.must_have
            || attributes & policy.cant_have != 0
        {
            return Status::INVALID_PARAMETER;
        }
        Status::SUCCESS
    }
}
