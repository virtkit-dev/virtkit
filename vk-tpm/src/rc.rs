//! Response codes (TPM 2.0 Part 2, TPM_RC).
//!
//! A format-one code (bit 7 set) can name what it is about: a handle, a parameter or a session,
//! by number. [`Rc::handle`], [`Rc::param`] and [`Rc::session`] add that, and leave a format-zero
//! code (which has no room for it) alone, as the reference implementation does.

use std::fmt;

/// A TPM_RC.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Rc(pub u32);

const RC_VER1: u32 = 0x100;
const RC_FMT1: u32 = 0x080;
const RC_WARN: u32 = 0x900;
/// In a format-one code: the number names a parameter (else a handle or a session).
const RC_P: u32 = 0x040;
/// In a format-one code naming no parameter: the number names a session (else a handle).
const RC_S: u32 = 0x800;

impl Rc {
    pub const SUCCESS: Rc = Rc(0);
    pub const BAD_TAG: Rc = Rc(0x01e);

    pub const INITIALIZE: Rc = Rc(RC_VER1);
    pub const FAILURE: Rc = Rc(RC_VER1 + 0x001);
    pub const SEQUENCE: Rc = Rc(RC_VER1 + 0x003);
    pub const PP: Rc = Rc(RC_VER1 + 0x010);
    pub const DISABLED: Rc = Rc(RC_VER1 + 0x020);
    pub const EXCLUSIVE: Rc = Rc(RC_VER1 + 0x021);
    pub const AUTH_TYPE: Rc = Rc(RC_VER1 + 0x024);
    pub const AUTH_MISSING: Rc = Rc(RC_VER1 + 0x025);
    pub const POLICY: Rc = Rc(RC_VER1 + 0x026);
    pub const PCR: Rc = Rc(RC_VER1 + 0x027);
    pub const PCR_CHANGED: Rc = Rc(RC_VER1 + 0x028);
    pub const AUTH_UNAVAILABLE: Rc = Rc(RC_VER1 + 0x02f);
    pub const COMMAND_SIZE: Rc = Rc(RC_VER1 + 0x042);
    pub const COMMAND_CODE: Rc = Rc(RC_VER1 + 0x043);
    pub const AUTH_CONTEXT: Rc = Rc(RC_VER1 + 0x045);
    pub const NV_RANGE: Rc = Rc(RC_VER1 + 0x046);
    pub const NV_LOCKED: Rc = Rc(RC_VER1 + 0x048);
    pub const NV_AUTHORIZATION: Rc = Rc(RC_VER1 + 0x049);
    pub const NV_UNINITIALIZED: Rc = Rc(RC_VER1 + 0x04a);
    pub const NV_SPACE: Rc = Rc(RC_VER1 + 0x04b);
    pub const NV_DEFINED: Rc = Rc(RC_VER1 + 0x04c);
    pub const CPHASH: Rc = Rc(RC_VER1 + 0x051);
    pub const NO_RESULT: Rc = Rc(RC_VER1 + 0x054);
    pub const SENSITIVE: Rc = Rc(RC_VER1 + 0x055);

    pub const ASYMMETRIC: Rc = Rc(RC_FMT1 + 0x001);
    pub const ATTRIBUTES: Rc = Rc(RC_FMT1 + 0x002);
    pub const HASH: Rc = Rc(RC_FMT1 + 0x003);
    pub const VALUE: Rc = Rc(RC_FMT1 + 0x004);
    pub const HIERARCHY: Rc = Rc(RC_FMT1 + 0x005);
    pub const KEY_SIZE: Rc = Rc(RC_FMT1 + 0x007);
    pub const MODE: Rc = Rc(RC_FMT1 + 0x009);
    pub const TYPE: Rc = Rc(RC_FMT1 + 0x00a);
    pub const HANDLE: Rc = Rc(RC_FMT1 + 0x00b);
    pub const KDF: Rc = Rc(RC_FMT1 + 0x00c);
    pub const RANGE: Rc = Rc(RC_FMT1 + 0x00d);
    pub const AUTH_FAIL: Rc = Rc(RC_FMT1 + 0x00e);
    pub const NONCE: Rc = Rc(RC_FMT1 + 0x00f);
    pub const SCHEME: Rc = Rc(RC_FMT1 + 0x012);
    pub const SIZE: Rc = Rc(RC_FMT1 + 0x015);
    pub const SYMMETRIC: Rc = Rc(RC_FMT1 + 0x016);
    pub const TAG: Rc = Rc(RC_FMT1 + 0x017);
    pub const SELECTOR: Rc = Rc(RC_FMT1 + 0x018);
    pub const INSUFFICIENT: Rc = Rc(RC_FMT1 + 0x01a);
    pub const SIGNATURE: Rc = Rc(RC_FMT1 + 0x01b);
    pub const KEY: Rc = Rc(RC_FMT1 + 0x01c);
    pub const POLICY_FAIL: Rc = Rc(RC_FMT1 + 0x01d);
    pub const INTEGRITY: Rc = Rc(RC_FMT1 + 0x01f);
    pub const TICKET: Rc = Rc(RC_FMT1 + 0x020);
    pub const RESERVED_BITS: Rc = Rc(RC_FMT1 + 0x021);
    pub const BAD_AUTH: Rc = Rc(RC_FMT1 + 0x022);
    pub const EXPIRED: Rc = Rc(RC_FMT1 + 0x023);
    pub const POLICY_CC: Rc = Rc(RC_FMT1 + 0x024);
    pub const BINDING: Rc = Rc(RC_FMT1 + 0x025);
    pub const CURVE: Rc = Rc(RC_FMT1 + 0x026);
    pub const ECC_POINT: Rc = Rc(RC_FMT1 + 0x027);

    pub const CONTEXT_GAP: Rc = Rc(RC_WARN + 0x001);
    pub const OBJECT_MEMORY: Rc = Rc(RC_WARN + 0x002);
    pub const SESSION_MEMORY: Rc = Rc(RC_WARN + 0x003);
    pub const SESSION_HANDLES: Rc = Rc(RC_WARN + 0x005);
    pub const LOCALITY: Rc = Rc(RC_WARN + 0x007);
    /// TPM_RC_REFERENCE_H0: the first handle names an entity that is not loaded (`+ n` for
    /// handle n).
    pub const REFERENCE_H0: Rc = Rc(RC_WARN + 0x010);
    /// TPM_RC_REFERENCE_S0: the first session is not loaded (`+ n` for session n).
    pub const REFERENCE_S0: Rc = Rc(RC_WARN + 0x018);
    pub const LOCKOUT: Rc = Rc(RC_WARN + 0x021);

    fn is_format_one(self) -> bool {
        self.0 & RC_FMT1 != 0
    }

    /// The same code, about handle `n` (1-based).
    pub fn handle(self, n: u32) -> Rc {
        self.numbered(0, n)
    }

    /// The same code, about parameter `n` (1-based).
    pub fn param(self, n: u32) -> Rc {
        self.numbered(RC_P, n)
    }

    /// The same code, about session `n` (1-based).
    pub fn session(self, n: u32) -> Rc {
        self.numbered(RC_S, n)
    }

    /// The `n`th of `REFERENCE_H0`, `REFERENCE_S0` (0-based): a warning, which has no room to
    /// number what it is about, so the number is added to the code.
    pub fn nth(self, n: usize) -> Rc {
        Rc(self.0.saturating_add(u32::try_from(n).unwrap_or(0)))
    }

    fn numbered(self, kind: u32, n: u32) -> Rc {
        // Handles and sessions have 3 bits for the number, parameters 4; 0 means "unnamed".
        let max = if kind == RC_P { 15 } else { 7 };
        // A code that already names something keeps it (RcSafeAddToResult).
        let named = self.0 & (0xf00 | RC_P) != 0;
        if !self.is_format_one() || named || n == 0 || n > max {
            return self;
        }
        Rc(self.0 | kind | (n << 8))
    }
}

impl fmt::Debug for Rc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TPM_RC({:#05x})", self.0)
    }
}

pub type Result<T> = std::result::Result<T, Rc>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_only_format_one_codes() {
        assert_eq!(Rc::VALUE.param(1), Rc(0x1c4));
        assert_eq!(Rc::VALUE.handle(1), Rc(0x184));
        assert_eq!(Rc::BAD_AUTH.session(1), Rc(0x9a2));
        assert_eq!(Rc::HANDLE.param(2), Rc(0x2cb));
        assert_eq!(Rc::INITIALIZE.param(1), Rc::INITIALIZE);
        assert_eq!(Rc::VALUE.param(0), Rc::VALUE);
        assert_eq!(Rc::VALUE.param(1).session(2), Rc(0x1c4), "already numbered");
        assert_eq!(Rc::REFERENCE_H0.nth(2), Rc(0x912));
    }
}
