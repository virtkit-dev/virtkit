//! A command's authorization area (Part 1, "Authorizations and Acknowledgments"; the reference
//! implementation's `SessionProcess.c`): reading the sessions, checking each authorization, and
//! the session area of the response.
//!
//! Only password sessions (TPM_RS_PW) exist so far: any other session handle is one that is not
//! loaded.

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::Tpm;
use crate::alg::MAX_DIGEST;
use crate::commands::Command;
use crate::entity::{TPM_RH_LOCKOUT, TPM_RS_PW, is_da_exempt, is_session, strip_zeros};
use crate::marshal::{Reader, Writer};
use crate::rc::{Rc, Result};

/// The most sessions a command may carry.
const MAX_SESSIONS: usize = 3;
/// The largest nonce or HMAC/password a session carries (sizeof(TPMU_HA)).
const MAX_AUTH: usize = MAX_DIGEST;

// TPMA_SESSION bits.
pub const CONTINUE_SESSION: u8 = 0x01;
const AUDIT_EXCLUSIVE: u8 = 0x02;
const AUDIT_RESET: u8 = 0x04;
const RESERVED: u8 = 0x18;
const DECRYPT: u8 = 0x20;
const ENCRYPT: u8 = 0x40;
const AUDIT: u8 = 0x80;

/// One session of a command's authorization area.
pub struct Use {
    pub handle: u32,
    pub attributes: u8,
    /// The password (or, for an HMAC or policy session, the HMAC).
    pub auth: Zeroizing<Vec<u8>>,
    /// The command handle at this session's position, if it needs authorization.
    pub associated: Option<u32>,
}

/// RetrieveSessionData: read every session of the area, each checked on its own.
pub fn read_area(mut area: Reader) -> Result<Vec<Use>> {
    let mut uses: Vec<Use> = Vec::new();
    let mut n: u32 = 0;
    while !area.is_empty() {
        n = n.saturating_add(1);
        if uses.len() == MAX_SESSIONS {
            return Err(Rc::SIZE.session(n));
        }
        let handle = area.u32().map_err(|rc| rc.session(n))?;
        if handle != TPM_RS_PW && !is_session(handle) {
            return Err(Rc::VALUE.session(n));
        }
        let nonce = area.tpm2b(MAX_AUTH).map_err(|rc| rc.session(n))?;
        let attributes = area.u8().map_err(|rc| rc.session(n))?;
        if attributes & RESERVED != 0 {
            return Err(Rc::RESERVED_BITS.session(n));
        }
        let auth = Zeroizing::new(area.tpm2b(MAX_AUTH).map_err(|rc| rc.session(n))?.to_vec());
        if handle != TPM_RS_PW {
            return Err(Rc::REFERENCE_S0.nth(uses.len()));
        }
        // A password session only authorizes, in clear, and has no nonce.
        if attributes & (ENCRYPT | DECRYPT | AUDIT | AUDIT_EXCLUSIVE | AUDIT_RESET) != 0 {
            return Err(Rc::ATTRIBUTES.session(n));
        }
        if !nonce.is_empty() {
            return Err(Rc::NONCE.session(n));
        }
        uses.push(Use {
            handle,
            attributes,
            auth,
            associated: None,
        });
    }
    Ok(uses)
}

impl Tpm {
    /// The rest of ParseSessionBuffer: pair each session with the handle it authorizes, then
    /// check every authorization, in order.
    pub fn authorize(&mut self, cmd: &Command, handles: &[u32], uses: &mut [Use]) -> Result<()> {
        for (i, &handle) in handles.iter().enumerate().take(cmd.auth) {
            let u = uses.get_mut(i).ok_or(Rc::AUTH_MISSING)?;
            u.associated = Some(handle);
        }
        for (n, u) in (1..).zip(uses.iter()) {
            // A password session must have something to authorize.
            let Some(entity) = u.associated else {
                return Err(Rc::HANDLE.session(n));
            };
            self.check_password(entity, &u.auth)
                .map_err(|rc| rc.session(n))?;
        }
        Ok(())
    }

    /// CheckAuthSession and CheckPWAuthSession for a password: the entity's authValue in clear.
    fn check_password(&mut self, entity: u32, password: &[u8]) -> Result<()> {
        if !is_da_exempt(entity) {
            self.check_locked_out(entity == TPM_RH_LOCKOUT)?;
        }
        if password_matches(password, &self.entity_auth(entity)) {
            Ok(())
        } else {
            Err(self.authorization_failed(entity))
        }
    }

    /// IncrementLockout: a failed authorization of `entity` counts against the dictionary-attack
    /// protection (TPM_RC_AUTH_FAIL), unless the entity is exempt (TPM_RC_BAD_AUTH).
    fn authorization_failed(&mut self, entity: u32) -> Rc {
        if is_da_exempt(entity) {
            return Rc::BAD_AUTH;
        }
        self.da_failure(entity == TPM_RH_LOCKOUT);
        Rc::AUTH_FAIL
    }
}

/// The response's session area: for each session, its nonce, attributes and HMAC. A password
/// session answers with an empty nonce and HMAC, and stays open.
pub fn write_response_area(w: &mut Writer, uses: &[Use]) {
    for u in uses {
        w.u16(0).u8(u.attributes | CONTINUE_SESSION).u16(0);
    }
}

/// Compare the password with authValue in constant time after dropping the trailing zeros of
/// both (Part 1, "password authorizations").
fn password_matches(password: &[u8], auth_value: &[u8]) -> bool {
    strip_zeros(password).ct_eq(auth_value).into()
}
