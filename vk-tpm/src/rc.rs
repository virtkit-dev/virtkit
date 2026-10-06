//! Response codes (TPM 2.0 Part 2, TPM_RC).
//!
//! A format-one code (bit 7 set) can identify a handle, parameter or session by number.
//! [`Rc::handle`], [`Rc::param`] and [`Rc::session`] add that number, leaving format-zero codes
//! unchanged because they have no room for it, as in the reference implementation.

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
    pub const DISABLED: Rc = Rc(RC_VER1 + 0x020);
    pub const AUTH_TYPE: Rc = Rc(RC_VER1 + 0x024);
    pub const AUTH_MISSING: Rc = Rc(RC_VER1 + 0x025);
    pub const PCR: Rc = Rc(RC_VER1 + 0x027);
    pub const AUTH_UNAVAILABLE: Rc = Rc(RC_VER1 + 0x02f);
    pub const COMMAND_SIZE: Rc = Rc(RC_VER1 + 0x042);
    pub const COMMAND_CODE: Rc = Rc(RC_VER1 + 0x043);
    pub const AUTH_CONTEXT: Rc = Rc(RC_VER1 + 0x045);

    pub const ATTRIBUTES: Rc = Rc(RC_FMT1 + 0x002);
    pub const HASH: Rc = Rc(RC_FMT1 + 0x003);
    pub const VALUE: Rc = Rc(RC_FMT1 + 0x004);
    pub const HIERARCHY: Rc = Rc(RC_FMT1 + 0x005);
    pub const MODE: Rc = Rc(RC_FMT1 + 0x009);
    pub const TYPE: Rc = Rc(RC_FMT1 + 0x00a);
    pub const HANDLE: Rc = Rc(RC_FMT1 + 0x00b);
    pub const AUTH_FAIL: Rc = Rc(RC_FMT1 + 0x00e);
    pub const NONCE: Rc = Rc(RC_FMT1 + 0x00f);
    pub const SIZE: Rc = Rc(RC_FMT1 + 0x015);
    pub const INSUFFICIENT: Rc = Rc(RC_FMT1 + 0x01a);
    pub const RESERVED_BITS: Rc = Rc(RC_FMT1 + 0x021);
    pub const BAD_AUTH: Rc = Rc(RC_FMT1 + 0x022);

    pub const OBJECT_MEMORY: Rc = Rc(RC_WARN + 0x002);
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
