//! edk2's variable policies (VariablePolicyLib), which the firmware registers through the
//! VarCheckPolicy MM handler and the service enforces on SetVariable: size bounds, attributes
//! a variable must or cannot have, and locks.

use crate::codec::{self, Reader, Short, get};
use crate::guid::Guid;
use crate::store::{APPEND_WRITE, Status};

const POLICY_ENTRY_REVISION: u32 = 0x0001_0000;
/// VARIABLE_POLICY_ENTRY: through LockPolicyType and its 3 bytes of padding.
const POLICY_ENTRY_SIZE: usize = 44;
const NO_MIN_SIZE: u32 = 0;
const LOCK_NONE: u8 = 0;
const LOCK_NOW: u8 = 1;
const LOCK_ON_CREATE: u8 = 2;
const LOCK_ON_VAR_STATE: u8 = 3;
/// edk2's MATCH_PRIORITY_MIN: the most wildcards a policy's name may hold.
const MAX_WILDCARDS: usize = 255;

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
    /// Parse a VARIABLE_POLICY_ENTRY and what follows it, as REGISTER carries them, refusing
    /// what edk2's IsValidVariablePolicyStructure refuses: the policy's name, if any, right
    /// after the entry (or after LOCK_ON_VAR_STATE's state variable) and ending with the entry,
    /// each name ending with its only NUL, a nonzero MaxSize, at most 255 wildcards.
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
            if version != POLICY_ENTRY_REVISION
                || size > bytes.len()
                || size < POLICY_ENTRY_SIZE
                || max_size == 0
                || name_at > size
            {
                return Err(Short);
            }
            let entry = get(bytes, 0, size)?;
            let lock = match lock_type {
                LOCK_NONE => Lock::None,
                LOCK_NOW => Lock::Now,
                LOCK_ON_CREATE => Lock::OnCreate,
                LOCK_ON_VAR_STATE => {
                    // VARIABLE_LOCK_ON_VAR_STATE_POLICY: namespace, value, padding, then the
                    // state variable's name, which ends where the policy's name starts.
                    let state = get(
                        entry,
                        POLICY_ENTRY_SIZE,
                        name_at.saturating_sub(POLICY_ENTRY_SIZE),
                    )?;
                    let mut s = Reader::new(state);
                    let guid = s.guid()?;
                    let value = s.u8()?;
                    s.u8()?;
                    Lock::OnVarState {
                        guid,
                        name: codec::ucs2_name(s.rest()).ok_or(Short)?,
                        value,
                    }
                }
                _ => return Err(Short),
            };
            if !matches!(lock, Lock::OnVarState { .. }) && name_at != POLICY_ENTRY_SIZE {
                return Err(Short);
            }
            // No name (the whole namespace) when it would start at the entry's end.
            let name = if name_at == size {
                None
            } else {
                let name = codec::ucs2_name(get(entry, name_at, size.saturating_sub(name_at))?)
                    .ok_or(Short)?;
                if name.iter().filter(|c| **c == u16::from(b'#')).count() > MAX_WILDCARDS {
                    return Err(Short);
                }
                Some(name)
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
                // As edk2: a '#' is always a wildcard, which wants a hex digit, even a '#' there.
                if *p == u16::from(b'#') {
                    char::from_u32(u32::from(*c)).is_some_and(|c| c.is_ascii_hexdigit())
                } else {
                    *p == *c
                }
            })
    }

    /// edk2's match priority, lower is better: a name's wildcards, a namespace's 255.
    fn priority(&self) -> usize {
        match &self.name {
            None => MAX_WILDCARDS,
            Some(n) => n.iter().filter(|c| **c == u16::from(b'#')).count(),
        }
    }
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

    /// Refused, as edk2 refuses it without PcdAllowVariablePolicyEnforcementDisable (FALSE by
    /// default): the firmware cannot switch the policies off.
    pub fn disable(&mut self) -> Status {
        if !self.enabled {
            return Status::ALREADY_STARTED;
        }
        Status::WRITE_PROTECTED
    }

    pub fn locked(&self) -> bool {
        self.locked
    }

    pub fn lock(&mut self) {
        self.locked = true;
    }

    pub fn register(&mut self, policy: Policy) -> Status {
        if self.locked {
            return Status::WRITE_PROTECTED;
        }
        // As edk2: refused when a policy already matches the name exactly (no wildcard used).
        // A namespace-wide policy has no name to match; its second copy is refused too.
        let taken = match &policy.name {
            Some(name) => self
                .list
                .iter()
                .any(|p| p.priority() == 0 && p.matches(&policy.guid, name)),
            None => self
                .list
                .iter()
                .any(|p| p.guid == policy.guid && p.name.is_none()),
        };
        if taken {
            return Status::ALREADY_STARTED;
        }
        self.list.push(policy);
        Status::SUCCESS
    }

    /// Whether a write of `size` bytes with `attributes` to `name` in `guid` passes the most
    /// specific policy that covers it, as edk2's ValidateSetVariable: `attributes` as the caller
    /// gave them, `size` the payload's. `exists` says whether the variable exists; `state` looks
    /// up another variable's value for LOCK_ON_VAR_STATE. A delete (size 0 without
    /// APPEND_WRITE) is only held to the locks.
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
            // The first of the best, as edk2's GetBestPolicyMatch keeps it.
            .min_by_key(|p| p.priority())
        else {
            return Status::SUCCESS;
        };
        // Size and attributes first, then the lock, as edk2's ValidateSetVariable.
        if size != 0 || attributes & APPEND_WRITE != 0 {
            let size = u32::try_from(size).unwrap_or(u32::MAX);
            if (policy.min_size != NO_MIN_SIZE && size < policy.min_size)
                || size > policy.max_size
                || attributes & policy.must_have != policy.must_have
                || attributes & policy.cant_have != 0
            {
                return Status::INVALID_PARAMETER;
            }
        }
        let locked = match &policy.lock {
            Lock::None => false,
            Lock::Now => true,
            Lock::OnCreate => exists,
            Lock::OnVarState { guid, name, value } => {
                state(guid, name).is_some_and(|data| data.as_slice() == [*value])
            }
        };
        if locked {
            Status::WRITE_PROTECTED
        } else {
            Status::SUCCESS
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    const NS: Guid = Guid::new(0x1234_5678, 1, 2, [3; 8]);
    const STATE_NS: Guid = Guid::new(0x8765_4321, 4, 5, [6; 8]);

    fn ucs2(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    /// A VARIABLE_POLICY_ENTRY as edk2 lays it out (packed, 44 bytes), then `lock_policy` and the
    /// variable's name.
    fn entry(lock_type: u8, lock_policy: &[u8], name: &str) -> Vec<u8> {
        let name = ucs2(name);
        let name_at = POLICY_ENTRY_SIZE + lock_policy.len();
        let size = name_at + name.len();
        let mut e = POLICY_ENTRY_REVISION.to_le_bytes().to_vec();
        e.extend_from_slice(&u16::try_from(size).unwrap().to_le_bytes());
        e.extend_from_slice(&u16::try_from(name_at).unwrap().to_le_bytes());
        e.extend_from_slice(&NS.0);
        for v in [0u32, u32::MAX, 0, 0] {
            e.extend_from_slice(&v.to_le_bytes());
        }
        e.extend_from_slice(&[lock_type, 0, 0, 0]);
        e.extend_from_slice(lock_policy);
        e.extend_from_slice(&name);
        e
    }

    #[test]
    fn a_lock_on_var_state_policy_reads_its_state_variable_after_the_entry() {
        // VARIABLE_LOCK_ON_VAR_STATE_POLICY: namespace, value, padding, name.
        let mut state = STATE_NS.0.to_vec();
        state.extend_from_slice(&[1, 0]);
        state.extend_from_slice(&ucs2("Gate"));
        let policy = Policy::parse(&entry(LOCK_ON_VAR_STATE, &state, "Held")).unwrap();
        assert_eq!(
            policy.lock,
            Lock::OnVarState {
                guid: STATE_NS,
                name: "Gate".encode_utf16().collect(),
                value: 1
            }
        );
        assert_eq!(policy.name, Some("Held".encode_utf16().collect()));

        let mut policies = Policies::default();
        assert_eq!(policies.register(policy), Status::SUCCESS);
        let held: Vec<u16> = "Held".encode_utf16().collect();
        let gate = |open: bool| {
            move |g: &Guid, n: &[u16]| {
                (*g == STATE_NS && n.iter().copied().eq("Gate".encode_utf16()))
                    .then(|| vec![u8::from(!open)])
            }
        };
        assert_eq!(
            policies.check(&NS, &held, 7, 1, false, gate(true)),
            Status::SUCCESS
        );
        assert_eq!(
            policies.check(&NS, &held, 7, 1, false, gate(false)),
            Status::WRITE_PROTECTED
        );
    }

    #[test]
    fn an_entry_shorter_than_edk2s_is_refused() {
        // The bytes are all there; only Size says 40.
        let mut short = entry(LOCK_NOW, &[], "");
        short[4..6].copy_from_slice(&40u16.to_le_bytes());
        short[6..8].copy_from_slice(&40u16.to_le_bytes());
        assert!(Policy::parse(&short).is_none());
        assert_eq!(
            Policy::parse(&entry(LOCK_NOW, &[], "X")).unwrap().lock,
            Lock::Now
        );
    }

    #[test]
    fn entries_edk2_refuses_are_refused() {
        let good = entry(LOCK_NOW, &[], "Held");
        assert!(Policy::parse(&good).is_some());
        // MaxSize 0.
        let mut e = good.clone();
        e[28..32].copy_from_slice(&0u32.to_le_bytes());
        assert!(Policy::parse(&e).is_none());
        // The name not right after the entry, or past its end.
        for name_at in [0u16, 40, 46, 200] {
            let mut e = good.clone();
            e[6..8].copy_from_slice(&name_at.to_le_bytes());
            assert!(Policy::parse(&e).is_none(), "name at {name_at}");
        }
        // Bytes after the name's NUL, or a name without one.
        let mut e = good.clone();
        e.extend_from_slice(&[b'X', 0]);
        let size = u16::try_from(e.len()).unwrap();
        e[4..6].copy_from_slice(&size.to_le_bytes());
        assert!(Policy::parse(&e).is_none());
        let mut e = good.clone();
        let last = e.len() - 2;
        e[last] = b'X';
        assert!(Policy::parse(&e).is_none());
        // A state variable's name that does not end where the policy's name starts.
        let mut state = STATE_NS.0.to_vec();
        state.extend_from_slice(&[1, 0]);
        state.extend_from_slice(&ucs2("Gate"));
        state.extend_from_slice(&[0, 0]);
        assert!(Policy::parse(&entry(LOCK_ON_VAR_STATE, &state, "Held")).is_none());
    }

    #[test]
    fn a_policy_without_a_name_covers_its_namespace() {
        let mut e = entry(LOCK_NOW, &[], "");
        e.truncate(POLICY_ENTRY_SIZE);
        let size = u16::try_from(POLICY_ENTRY_SIZE).unwrap();
        e[4..6].copy_from_slice(&size.to_le_bytes());
        let policy = Policy::parse(&e).unwrap();
        assert_eq!(policy.name, None);
        assert!(policy.matches(&NS, &"Anything".encode_utf16().collect::<Vec<_>>()));
    }

    #[test]
    fn a_wildcard_wants_a_hex_digit_and_the_first_best_policy_wins() {
        let name = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
        let none = |_: &Guid, _: &[u16]| None;
        let parse = |lock, n| Policy::parse(&entry(lock, &[], n)).unwrap();
        let mut policies = Policies::default();
        assert_eq!(
            policies.register(parse(LOCK_NOW, "Boot####")),
            Status::SUCCESS
        );
        // A wildcard name matches no name exactly: as in edk2, a second one goes in, and loses
        // to the first, as specific.
        assert_eq!(
            policies.register(parse(LOCK_NONE, "Boot####")),
            Status::SUCCESS
        );
        assert_eq!(
            policies.register(parse(LOCK_NONE, "Boot00##")),
            Status::SUCCESS
        );
        assert_eq!(
            policies.register(parse(LOCK_NONE, "Boot0001")),
            Status::SUCCESS
        );
        assert_eq!(
            policies.register(parse(LOCK_NOW, "Boot0001")),
            Status::ALREADY_STARTED
        );
        // The fewest wildcards decide; among equals, the first registered.
        assert_eq!(
            policies.check(&NS, &name("Boot0001"), 7, 1, false, none),
            Status::SUCCESS
        );
        assert_eq!(
            policies.check(&NS, &name("Boot0002"), 7, 1, false, none),
            Status::SUCCESS
        );
        assert_eq!(
            policies.check(&NS, &name("Boot1001"), 7, 1, false, none),
            Status::WRITE_PROTECTED
        );
        // '#' matches a hex digit only, not a '#'.
        assert_eq!(
            policies.check(&NS, &name("Boot####"), 7, 1, false, none),
            Status::SUCCESS
        );
    }

    #[test]
    fn size_and_attributes_are_checked_before_the_lock() {
        let mut e = entry(LOCK_NOW, &[], "Held");
        e[24..28].copy_from_slice(&2u32.to_le_bytes()); // MinSize
        e[28..32].copy_from_slice(&4u32.to_le_bytes()); // MaxSize
        e[32..36].copy_from_slice(&1u32.to_le_bytes()); // must have NV
        e[36..40].copy_from_slice(&APPEND_WRITE.to_le_bytes()); // cannot have APPEND_WRITE
        let mut policies = Policies::default();
        policies.register(Policy::parse(&e).unwrap());
        let held: Vec<u16> = "Held".encode_utf16().collect();
        let none = |_: &Guid, _: &[u16]| None;
        let check =
            |attributes, size, exists| policies.check(&NS, &held, attributes, size, exists, none);
        assert_eq!(check(7, 8, false), Status::INVALID_PARAMETER, "too large");
        assert_eq!(check(7, 1, false), Status::INVALID_PARAMETER, "too small");
        assert_eq!(check(6, 2, false), Status::INVALID_PARAMETER, "not NV");
        assert_eq!(
            check(7 | APPEND_WRITE, 2, true),
            Status::INVALID_PARAMETER,
            "append"
        );
        // An append of nothing is no delete: held to the size and attributes too.
        assert_eq!(check(7 | APPEND_WRITE, 0, true), Status::INVALID_PARAMETER);
        assert_eq!(check(7, 2, false), Status::WRITE_PROTECTED);
        assert_eq!(
            check(0, 0, true),
            Status::WRITE_PROTECTED,
            "a delete meets only the lock"
        );
    }

    #[test]
    fn lock_on_create_holds_once_the_variable_exists() {
        let mut policies = Policies::default();
        policies.register(Policy::parse(&entry(LOCK_ON_CREATE, &[], "Once")).unwrap());
        let once: Vec<u16> = "Once".encode_utf16().collect();
        let none = |_: &Guid, _: &[u16]| None;
        assert_eq!(
            policies.check(&NS, &once, 7, 1, false, none),
            Status::SUCCESS
        );
        assert_eq!(
            policies.check(&NS, &once, 7, 1, true, none),
            Status::WRITE_PROTECTED
        );
    }

    #[test]
    fn the_policies_cannot_be_disabled_and_a_locked_interface_takes_none() {
        let mut policies = Policies::default();
        assert_eq!(policies.disable(), Status::WRITE_PROTECTED);
        assert!(policies.enabled());
        policies.lock();
        assert!(policies.locked());
        assert_eq!(
            policies.register(Policy::parse(&entry(LOCK_NOW, &[], "Late")).unwrap()),
            Status::WRITE_PROTECTED
        );
    }
}
