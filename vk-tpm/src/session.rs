//! Authorization sessions (Part 1, "Authorizations and Acknowledgments" and "Session-based
//! encryption"; the reference implementation's `SessionProcess.c` and `Session.c`).
//!
//! A command's authorization area holds up to three sessions. A password session (TPM_RS_PW)
//! carries an authValue in clear. An HMAC session proves knowledge of it with an HMAC keyed
//! by the session key and the authValue, over the command's cpHash and both nonces; a policy
//! session proves the entity's authPolicy was satisfied. HMAC and policy sessions also encrypt
//! a command's first parameter (`decrypt`), the response's first one (`encrypt`), or keep an
//! audit digest of the commands they see (`audit`), and the response carries the TPM's HMAC of
//! it, with a new TPM nonce.

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::alg::{Hash, MAX_DIGEST, TPM_ALG_NULL};
use crate::commands::{Command, Role, end, is_write_operation};
use crate::crypt;
use crate::entity::{
    TPM_HT_NV_INDEX, TPM_HT_POLICY_SESSION, TPM_HT_TRANSIENT, TPM_RH_LOCKOUT, TPM_RH_NULL,
    TPM_RS_PW, handle_type, is_session, strip_zeros,
};
use crate::marshal::{Reader, Writer};
use crate::rc::{Rc, Result};
use crate::state::{StateError, read_bool};
use crate::{LOCALITY, MAX_COMMAND_SIZE, Out, Tpm};

/// How many sessions the TPM holds at once (MAX_LOADED_SESSIONS, as libtpms).
pub const MAX_LOADED: usize = 3;
/// How many session handles there are (MAX_ACTIVE_SESSIONS): loaded or saved sessions.
pub const MAX_ACTIVE: usize = 64;
const HMAC_SESSION_FIRST: u32 = 0x0200_0000;
const POLICY_SESSION_FIRST: u32 = 0x0300_0000;
/// The most sessions a command may carry.
const MAX_SESSIONS: usize = 3;
/// The largest nonce or HMAC/password a session carries (sizeof(TPMU_HA)).
const MAX_AUTH: usize = MAX_DIGEST;
/// The size of a bound session's bind value (sizeof(TPMU_NAME): a TPMT_HA).
const BIND_SIZE: usize = 2 + MAX_DIGEST;

// TPMA_SESSION bits.
pub const CONTINUE_SESSION: u8 = 0x01;
const AUDIT_EXCLUSIVE: u8 = 0x02;
const AUDIT_RESET: u8 = 0x04;
const RESERVED: u8 = 0x18;
const DECRYPT: u8 = 0x20;
const ENCRYPT: u8 = 0x40;
const AUDIT: u8 = 0x80;

const TPM_ALG_AES: u16 = 0x0006;
const TPM_ALG_XOR: u16 = 0x000a;
const TPM_ALG_CFB: u16 = 0x0043;
/// The block cipher modes TPMI_ALG_SYM_MODE takes: CTR, OFB, CBC, CFB, ECB.
const SYM_MODES: std::ops::RangeInclusive<u16> = 0x0040..=0x0044;

/// TPM_SE: what a session is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Hmac,
    Policy,
    /// A policy session that only computes a policy digest; it authorizes nothing.
    Trial,
}

/// The parameter encryption a session does (its TPMT_SYM_DEF).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Symmetric {
    Null,
    /// XOR obfuscation; the hash is the one the definition names, but the session's own is the
    /// one used (as in the reference implementation).
    Xor(Hash),
    /// AES in CFB mode, with a key of these many bits.
    Aes(u16),
}

/// A loaded session.
pub struct Session {
    pub kind: Kind,
    pub hash: Hash,
    pub nonce_tpm: Vec<u8>,
    /// The session key: KDFa of the bind authValue and the salt, empty if there were none.
    pub key: Zeroizing<Vec<u8>>,
    pub symmetric: Symmetric,
    /// For a bound HMAC session, the bind value of the entity (its Name and authValue).
    pub bound: Option<Zeroizing<Vec<u8>>>,
    /// Bound to an entity subject to dictionary-attack protection, lockout in particular.
    pub da_bound: bool,
    pub lockout_bound: bool,
    /// The audit digest, once the session audited a command.
    pub audit: Option<Vec<u8>>,
    /// A policy session's policyDigest.
    pub policy_digest: Vec<u8>,
    /// What else the policy commands so far require of the authorization.
    pub policy: PolicyState,
    /// TPM time when the session started or was last used (policy expirations count from it),
    /// and the time epoch then.
    pub start_time: u64,
    pub epoch: u32,
}

/// What a policy session's commands require besides its policyDigest (the reference's SESSION
/// fields and attributes that SessionResetPolicyData clears).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyState {
    /// TPM2_PolicyCommandCode: the only command the session may authorize (0: any).
    pub command_code: u32,
    /// TPM2_PolicyLocality: the TPMA_LOCALITY the command must come from (0: any).
    pub locality: u8,
    /// What the command must be: its cpHash, the hash of its handles' Names, or the hash of the
    /// template it creates (the reference's u1 union).
    pub bound: Option<(Bound, Vec<u8>)>,
    /// TPM time after which the session authorizes nothing (0: never).
    pub timeout: u64,
    /// TPM2_PolicyPCR: the PCR update counter then; any change voids the session (0: none).
    pub pcr_counter: u32,
    /// TPM2_PolicyAuthValue: the HMAC also proves the authValue.
    pub auth_value_needed: bool,
    /// TPM2_PolicyPassword: the authValue comes in clear.
    pub password_needed: bool,
    /// TPM2_PolicyPhysicalPresence: never satisfied here (no physical presence).
    pub pp_required: bool,
    /// TPM2_PolicyNvWritten: the NV index's TPMA_NV_WRITTEN must be this.
    pub nv_written: Option<bool>,
}

/// What [`PolicyState::bound`] holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bound {
    CpHash,
    Names,
    Template,
}

impl PolicyState {
    fn write(&self, w: &mut Writer) {
        w.u32(self.command_code).u8(self.locality);
        match &self.bound {
            None => w.u8(0),
            Some((kind, digest)) => {
                let kind = match kind {
                    Bound::CpHash => 1,
                    Bound::Names => 2,
                    Bound::Template => 3,
                };
                w.u8(kind).tpm2b(digest)
            }
        };
        w.u64(self.timeout).u32(self.pcr_counter);
        let nv = match self.nv_written {
            None => 0,
            Some(false) => 1,
            Some(true) => 2,
        };
        w.u8(self.auth_value_needed.into())
            .u8(self.password_needed.into())
            .u8(self.pp_required.into())
            .u8(nv);
    }

    fn read(r: &mut Reader) -> std::result::Result<PolicyState, StateError> {
        let (command_code, locality) = (r.u32()?, r.u8()?);
        let kind = match r.u8()? {
            0 => None,
            1 => Some(Bound::CpHash),
            2 => Some(Bound::Names),
            3 => Some(Bound::Template),
            _ => return Err(StateError("bad session")),
        };
        let bound = match kind {
            Some(kind) => Some((kind, r.tpm2b(MAX_DIGEST)?.to_vec())),
            None => None,
        };
        let (timeout, pcr_counter) = (r.u64()?, r.u32()?);
        let (auth_value_needed, password_needed) = (read_bool(r)?, read_bool(r)?);
        let pp_required = read_bool(r)?;
        let nv_written = match r.u8()? {
            0 => None,
            1 => Some(false),
            2 => Some(true),
            _ => return Err(StateError("bad session")),
        };
        Ok(PolicyState {
            command_code,
            locality,
            bound,
            timeout,
            pcr_counter,
            auth_value_needed,
            password_needed,
            pp_required,
            nv_written,
        })
    }
}

impl Session {
    /// SessionResetPolicyData: the policy starts over (TPM2_PolicyRestart, or after a use).
    pub fn reset_policy(&mut self) {
        self.policy_digest.fill(0);
        self.policy = PolicyState::default();
    }
}

impl Session {
    pub fn write(&self, w: &mut Writer) {
        let kind = match self.kind {
            Kind::Hmac => 0,
            Kind::Policy => 1,
            Kind::Trial => 3,
        };
        w.u8(kind)
            .u16(self.hash.id())
            .tpm2b(&self.nonce_tpm)
            .tpm2b(&self.key);
        match self.symmetric {
            Symmetric::Null => w.u16(TPM_ALG_NULL),
            Symmetric::Xor(hash) => w.u16(TPM_ALG_XOR).u16(hash.id()),
            Symmetric::Aes(bits) => w.u16(TPM_ALG_AES).u16(bits),
        };
        match &self.bound {
            Some(bound) => w.u8(1).tpm2b(bound),
            None => w.u8(0),
        };
        w.u8(self.da_bound.into()).u8(self.lockout_bound.into());
        match &self.audit {
            Some(digest) => w.u8(1).tpm2b(digest),
            None => w.u8(0),
        };
        w.tpm2b(&self.policy_digest);
        self.policy.write(w);
        w.u64(self.start_time).u32(self.epoch);
    }

    pub fn read(r: &mut Reader) -> std::result::Result<Session, StateError> {
        let kind = match r.u8()? {
            0 => Kind::Hmac,
            1 => Kind::Policy,
            3 => Kind::Trial,
            _ => return Err(StateError("bad session")),
        };
        let hash = Hash::read(r)?;
        let nonce_tpm = r.tpm2b(MAX_AUTH)?.to_vec();
        let key = Zeroizing::new(r.tpm2b(MAX_DIGEST)?.to_vec());
        let symmetric = match r.u16()? {
            TPM_ALG_NULL => Symmetric::Null,
            TPM_ALG_XOR => Symmetric::Xor(Hash::read(r)?),
            TPM_ALG_AES => match r.u16()? {
                bits @ (128 | 192 | 256) => Symmetric::Aes(bits),
                _ => return Err(StateError("bad session")),
            },
            _ => return Err(StateError("bad session")),
        };
        let bound = if read_bool(r)? {
            Some(Zeroizing::new(r.tpm2b(BIND_SIZE)?.to_vec()))
        } else {
            None
        };
        let (da_bound, lockout_bound) = (read_bool(r)?, read_bool(r)?);
        let audit = if read_bool(r)? {
            Some(r.tpm2b(MAX_DIGEST)?.to_vec())
        } else {
            None
        };
        Ok(Session {
            kind,
            hash,
            nonce_tpm,
            key,
            symmetric,
            bound,
            da_bound,
            lockout_bound,
            audit,
            policy_digest: r.tpm2b(MAX_DIGEST)?.to_vec(),
            policy: PolicyState::read(r)?,
            start_time: r.u64()?,
            epoch: r.u32()?,
        })
    }
}

/// A session handle's slot: free, a loaded session, or a saved one (TPM2_ContextSave), which
/// keeps its handle and the sequence number of the context that holds it (contextArray).
pub enum SessionSlot {
    Free,
    Loaded(Box<Session>),
    Saved(u64),
}

/// One session of a command's authorization area.
pub struct Use {
    pub handle: u32,
    pub nonce_caller: Vec<u8>,
    /// As the command sent them, then as the response gives them back.
    pub attributes: u8,
    /// The password, or the HMAC.
    pub auth: Zeroizing<Vec<u8>>,
    /// The entity it authorizes: the command's handle at its position, if that one needs an
    /// authorization.
    pub associated: Option<u32>,
    /// The entity's authValue keys the HMACs (an HMAC session not bound to it).
    include_auth: bool,
}

/// A command's authorization area, and what its HMACs are computed over.
pub struct Area {
    code: u32,
    /// The role the first handle takes (the others take USER).
    role: Role,
    /// The command writes an NV index (IsWriteOperation).
    write: bool,
    /// The Names of the command's handles.
    names: Vec<Vec<u8>>,
    /// The parameters as the command carried them (encrypted).
    params: Vec<u8>,
    pub uses: Vec<Use>,
    decrypt: Option<usize>,
    encrypt: Option<usize>,
    audit: Option<usize>,
}

impl Area {
    /// cpHash: H(commandCode ‖ Names ‖ parameters).
    fn cp_hash(&self, hash: Hash) -> Vec<u8> {
        let code = self.code.to_be_bytes();
        let mut parts: Vec<&[u8]> = vec![&code];
        parts.extend(self.names.iter().map(Vec::as_slice));
        parts.push(&self.params);
        hash.digest(&parts)
    }
}

/// rpHash: H(responseCode ‖ commandCode ‖ parameters), the response code always success.
fn rp_hash(hash: Hash, code: u32, params: &[u8]) -> Vec<u8> {
    hash.digest(&[&Rc::SUCCESS.0.to_be_bytes(), &code.to_be_bytes(), params])
}

/// The index of a session handle (its slot in the handle space).
fn index(handle: u32) -> usize {
    usize::try_from(handle & 0x00ff_ffff).unwrap_or(usize::MAX)
}

impl Tpm {
    /// The session a handle names, if it is loaded.
    pub fn session(&self, handle: u32) -> Option<&Session> {
        match self.volatile.sessions.get(index(handle))? {
            SessionSlot::Loaded(s) => Some(s),
            _ => None,
        }
    }

    pub fn session_mut(&mut self, handle: u32) -> Result<&mut Session> {
        match self.volatile.sessions.get_mut(index(handle)) {
            Some(SessionSlot::Loaded(s)) => Ok(s),
            _ => Err(Rc::FAILURE),
        }
    }

    /// The session a handle names, if one of that type is loaded there.
    pub fn loaded_session(&self, handle: u32) -> Option<&Session> {
        let session = self.session(handle)?;
        let policy = handle_type(handle) == TPM_HT_POLICY_SESSION;
        (policy == (session.kind != Kind::Hmac)).then_some(session)
    }

    /// The handles of the loaded sessions, from index `from` on (TPM_HT_LOADED_SESSION).
    pub fn loaded_sessions(&self, from: u32) -> Vec<u32> {
        let from = index(from);
        (self.volatile.sessions.iter().enumerate())
            .skip(from)
            .filter_map(|(i, s)| {
                let SessionSlot::Loaded(s) = s else {
                    return None;
                };
                let first = match s.kind {
                    Kind::Hmac => HMAC_SESSION_FIRST,
                    _ => POLICY_SESSION_FIRST,
                };
                first.checked_add(u32::try_from(i).ok()?)
            })
            .collect()
    }

    /// The handles of the saved sessions, from index `from` on (TPM_HT_SAVED_SESSION), each as
    /// an HMAC session handle (the reference does not tell them apart).
    pub fn saved_sessions(&self, from: u32) -> Vec<u32> {
        (self.volatile.sessions.iter().enumerate())
            .skip(index(from))
            .filter(|(_, s)| matches!(s, SessionSlot::Saved(_)))
            .filter_map(|(i, _)| HMAC_SESSION_FIRST.checked_add(u32::try_from(i).ok()?))
            .collect()
    }

    /// How many sessions are loaded.
    pub fn session_count(&self) -> usize {
        (self.volatile.sessions.iter())
            .filter(|s| matches!(s, SessionSlot::Loaded(_)))
            .count()
    }

    /// How many session handles are taken, by loaded or saved sessions.
    pub fn active_sessions(&self) -> usize {
        (self.volatile.sessions.iter())
            .filter(|s| !matches!(s, SessionSlot::Free))
            .count()
    }

    /// TPM2_FlushContext of a session, loaded or saved.
    pub fn flush_session(&mut self, handle: u32) -> Result<()> {
        let slot = self.volatile.sessions.get_mut(index(handle));
        let slot = slot
            .filter(|s| !matches!(s, SessionSlot::Free))
            .ok_or(Rc::HANDLE)?;
        *slot = SessionSlot::Free;
        if self.volatile.exclusive_audit == Some(handle) {
            self.volatile.exclusive_audit = None;
        }
        Ok(())
    }

    /// SessionComputeBoundEntity: the entity's Name, zero-padded to a TPMU_NAME, with its
    /// authValue XORed into the end. A session bound to it skips the authValue when it
    /// authorizes it.
    fn bind_value(&self, entity: u32) -> Zeroizing<Vec<u8>> {
        let mut bind = Zeroizing::new(self.entity_name(entity));
        bind.resize(BIND_SIZE, 0);
        let auth = self.entity_auth(entity);
        let start = BIND_SIZE.saturating_sub(auth.len());
        for (b, a) in bind.iter_mut().skip(start).zip(auth.iter()) {
            *b ^= a;
        }
        bind
    }

    /// RetrieveSessionData: read every session of the area, each checked on its own and
    /// against the sessions loaded, and note which encrypts, decrypts and audits.
    pub fn read_area(&self, cmd: &Command, mut area: Reader, handles: &[u32]) -> Result<Area> {
        let mut a = Area {
            code: cmd.code,
            role: cmd.role,
            write: is_write_operation(cmd.code),
            names: handles.iter().map(|&h| self.entity_name(h)).collect(),
            params: Vec::new(),
            uses: Vec::new(),
            decrypt: None,
            encrypt: None,
            audit: None,
        };
        while !area.is_empty() {
            let i = a.uses.len();
            let n = u32::try_from(i.saturating_add(1)).map_err(|_| Rc::FAILURE)?;
            if i == MAX_SESSIONS {
                return Err(Rc::SIZE.session(n));
            }
            let handle = area.u32().map_err(|rc| rc.session(n))?;
            if handle != TPM_RS_PW && !is_session(handle) {
                return Err(Rc::VALUE.session(n));
            }
            let nonce_caller = area.tpm2b(MAX_AUTH).map_err(|rc| rc.session(n))?.to_vec();
            let attributes = area.u8().map_err(|rc| rc.session(n))?;
            if attributes & RESERVED != 0 {
                return Err(Rc::RESERVED_BITS.session(n));
            }
            let auth = Zeroizing::new(area.tpm2b(MAX_AUTH).map_err(|rc| rc.session(n))?.to_vec());
            if handle == TPM_RS_PW {
                // A password session only authorizes, in clear, and has no nonce.
                let others = ENCRYPT | DECRYPT | AUDIT | AUDIT_EXCLUSIVE | AUDIT_RESET;
                if attributes & others != 0 {
                    return Err(Rc::ATTRIBUTES.session(n));
                }
                if !nonce_caller.is_empty() {
                    return Err(Rc::NONCE.session(n));
                }
            } else {
                self.check_session_use(cmd, &mut a, handle, attributes, n)?;
            }
            a.uses.push(Use {
                handle,
                nonce_caller,
                attributes,
                auth,
                associated: None,
                include_auth: true,
            });
        }
        Ok(a)
    }

    /// The checks RetrieveSessionData makes of an HMAC or policy session, session `n` of
    /// the area: loaded, of its handle's type, used once, and fit for what its attributes ask.
    fn check_session_use(
        &self,
        cmd: &Command,
        a: &mut Area,
        handle: u32,
        attributes: u8,
        n: u32,
    ) -> Result<()> {
        let i = a.uses.len();
        let Some(session) = self.session(handle) else {
            return Err(Rc::REFERENCE_S0.nth(i));
        };
        if self.loaded_session(handle).is_none()
            || a.uses.iter().take(i).any(|other| other.handle == handle)
        {
            return Err(Rc::HANDLE.session(n));
        }
        if attributes & DECRYPT != 0 {
            if !cmd.decrypt || a.decrypt.is_some() {
                return Err(Rc::ATTRIBUTES.session(n));
            }
            if session.symmetric == Symmetric::Null {
                return Err(Rc::SYMMETRIC.session(n));
            }
            a.decrypt = Some(i);
        }
        if attributes & ENCRYPT != 0 {
            if !cmd.encrypt || a.encrypt.is_some() {
                return Err(Rc::ATTRIBUTES.session(n));
            }
            if session.symmetric == Symmetric::Null {
                return Err(Rc::SYMMETRIC.session(n));
            }
            a.encrypt = Some(i);
        }
        if attributes & AUDIT != 0 {
            if a.audit.is_some() || session.kind != Kind::Hmac {
                return Err(Rc::ATTRIBUTES.session(n));
            }
            // Once a session audits, it may ask to be the only one that has since.
            let exclusive = self.volatile.exclusive_audit == Some(handle);
            if attributes & AUDIT_RESET == 0
                && session.audit.is_some()
                && attributes & AUDIT_EXCLUSIVE != 0
                && !exclusive
            {
                return Err(Rc::EXCLUSIVE);
            }
            a.audit = Some(i);
        }
        Ok(())
    }

    /// The rest of ParseSessionBuffer: pair each session with the handle it authorizes, check
    /// every authorization in order, then decrypt the first parameter. Returns the parameters
    /// to run the command with.
    pub fn authorize(
        &mut self,
        cmd: &Command,
        handles: &[u32],
        a: &mut Area,
        params: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        a.params = params.to_vec();
        for (i, &handle) in handles.iter().enumerate().take(cmd.auth) {
            let u = a.uses.get_mut(i).ok_or(Rc::AUTH_MISSING)?;
            u.associated = Some(handle);
        }
        for i in 0..a.uses.len() {
            let n = u32::try_from(i.saturating_add(1)).map_err(|_| Rc::FAILURE)?;
            let u = a.uses.get(i).ok_or(Rc::FAILURE)?;
            if u.handle == TPM_RS_PW {
                // A password session must have something to authorize.
                if u.associated.is_none() {
                    return Err(Rc::HANDLE.session(n));
                }
            } else {
                let session = self.session(u.handle).ok_or(Rc::FAILURE)?;
                // A trial session authorizes nothing, nor encrypts or audits.
                if session.kind == Kind::Trial {
                    return Err(Rc::ATTRIBUTES.session(n));
                }
                // A session bound to a DA-protected entity is locked out with it.
                if session.da_bound {
                    self.check_locked_out(session.lockout_bound)?;
                }
            }
            if u.associated.is_some() {
                self.check_authorization(a, i).map_err(|rc| rc.session(n))?;
            } else {
                // A session that authorizes nothing must at least encrypt or audit.
                if u.attributes & (AUDIT | ENCRYPT | DECRYPT) == 0 {
                    return Err(Rc::ATTRIBUTES.session(n));
                }
                if let Some(u) = a.uses.get_mut(i) {
                    u.include_auth = false;
                }
                self.check_hmac(a, i).map_err(|rc| rc.session(n))?;
            }
        }
        // Decrypted, it may hold a secret (a new authValue).
        let mut params = Zeroizing::new(params.to_vec());
        if let Some(i) = a.decrypt {
            let n = u32::try_from(i.saturating_add(1)).map_err(|_| Rc::FAILURE)?;
            self.decrypt_parameter(a, i, &mut params)
                .map_err(|rc| rc.session(n))?;
        }
        Ok(params)
    }

    /// CheckAuthSession: session `i` authorizes the entity it is associated with.
    fn check_authorization(&mut self, a: &mut Area, i: usize) -> Result<()> {
        let u = a.uses.get(i).ok_or(Rc::FAILURE)?;
        let entity = u.associated.ok_or(Rc::FAILURE)?;
        let kind = (u.handle != TPM_RS_PW)
            .then(|| self.session(u.handle).map(|s| s.kind))
            .flatten();
        let include_auth = match kind {
            None => true,
            // An HMAC session bound to the entity already has its authValue in the key.
            Some(Kind::Hmac) => {
                let bound = self.session(u.handle).and_then(|s| s.bound.as_deref());
                // The bind value holds the authValue: compared in constant time.
                !bound.is_some_and(|b| b.ct_eq(&self.bind_value(entity)).into())
            }
            // A policy session uses the authValue only if TPM2_PolicyAuthValue or
            // TPM2_PolicyPassword asked for it.
            Some(_) => self
                .session(u.handle)
                .is_some_and(|s| s.policy.auth_value_needed || s.policy.password_needed),
        };
        if let Some(u) = a.uses.get_mut(i) {
            u.include_auth = include_auth;
        }
        if include_auth && !self.is_da_exempt(entity) {
            self.check_locked_out(entity == TPM_RH_LOCKOUT)?;
        }
        // Only the first handle of a command takes another role than USER.
        let role = if i == 0 { a.role } else { Role::User };
        if matches!(kind, Some(Kind::Policy | Kind::Trial)) {
            if !self.auth_policy_available(entity, role, a.write) {
                return Err(Rc::AUTH_UNAVAILABLE);
            }
            let session = self.session(u_handle(a, i)?).ok_or(Rc::FAILURE)?;
            self.check_policy_session(session, a, entity, role)?;
        } else {
            if self.policy_required(entity, role) {
                return Err(Rc::AUTH_TYPE);
            }
            if !self.auth_value_available(entity, role, a.write) {
                return Err(Rc::AUTH_UNAVAILABLE);
            }
        }
        let password = kind.is_none() || self.password_needed(u_handle(a, i)?);
        let result = if password {
            let u = a.uses.get(i).ok_or(Rc::FAILURE)?;
            if password_matches(&u.auth, &self.entity_auth(entity)) {
                Ok(())
            } else {
                Err(self.authorization_failed(a, i))
            }
        } else {
            self.check_hmac(a, i)
        };
        // A PIN index counts its authorizations: a pass index the successes, a fail index the
        // failures since the last success.
        if include_auth && handle_type(entity) == TPM_HT_NV_INDEX {
            self.nv_pin_authorized(entity, result.is_ok())?;
        }
        result
    }

    /// The session asked for the authValue in clear (TPM2_PolicyPassword).
    fn password_needed(&self, handle: u32) -> bool {
        self.session(handle)
            .is_some_and(|s| s.kind != Kind::Hmac && s.policy.password_needed)
    }

    /// CheckPolicyAuthSession: the policy session reached the entity's authPolicy, and the
    /// command is one its policy commands allow (code, locality, cpHash or Names or template,
    /// time, PCRs, NV index written or not). `role` is the role the entity takes.
    fn check_policy_session(
        &self,
        session: &Session,
        a: &Area,
        entity: u32,
        role: Role,
    ) -> Result<()> {
        let p = &session.policy;
        if a.code == crate::commands::TPM_CC_POLICY_SECRET
            && !p.password_needed
            && !p.auth_value_needed
        {
            return Err(Rc::MODE);
        }
        if p.pcr_counter != 0 && p.pcr_counter != self.volatile.pcrs.counter {
            return Err(Rc::PCR_CHANGED);
        }
        let policy = self.entity_policy(entity);
        let digest_matches: bool = session.policy_digest.ct_eq(&policy.digest).into();
        if !digest_matches || policy.hash != Some(session.hash) {
            return Err(Rc::POLICY_FAIL);
        }
        if p.timeout != 0
            && (p.timeout < self.volatile.time || session.epoch != self.permanent.time_epoch)
        {
            return Err(Rc::EXPIRED);
        }
        if p.command_code != 0 {
            if p.command_code != a.code {
                return Err(Rc::POLICY_CC);
            }
        } else if role != Role::User {
            // The ADMIN and DUP roles need a policy bound to the command.
            return Err(Rc::POLICY_FAIL);
        }
        if p.locality != 0 && (p.locality & (1 << LOCALITY) == 0 || p.locality > 31) {
            return Err(Rc::LOCALITY);
        }
        if p.pp_required {
            return Err(Rc::PP);
        }
        if let Some((kind, digest)) = &p.bound {
            let hash = session.hash;
            let computed = match kind {
                Bound::CpHash => Some(a.cp_hash(hash)),
                Bound::Names => {
                    let names: Vec<&[u8]> = a.names.iter().map(Vec::as_slice).collect();
                    Some(hash.digest(&names))
                }
                Bound::Template => template_hash(a.code, &a.params, hash),
            };
            if !computed.is_some_and(|c| bool::from(c.ct_eq(digest))) {
                return Err(Rc::POLICY_FAIL);
            }
        }
        if let Some(written) = p.nv_written {
            let public = (handle_type(entity) == TPM_HT_NV_INDEX)
                .then(|| self.nv_public(entity))
                .flatten();
            let public = public.ok_or(Rc::POLICY_FAIL)?;
            if public.has(crate::nv::attr::WRITTEN) != written {
                return Err(Rc::POLICY_FAIL);
            }
        }
        Ok(())
    }

    /// CheckSessionHMAC: the HMAC session `i` carries is the one the TPM computes.
    fn check_hmac(&mut self, a: &Area, i: usize) -> Result<()> {
        let u = a.uses.get(i).ok_or(Rc::FAILURE)?;
        let session = self.session(u.handle).ok_or(Rc::FAILURE)?;
        let key = self.hmac_key(session, u);
        // With no key at all, the empty HMAC is the right one.
        let matches = if key.is_empty() && u.auth.is_empty() {
            true
        } else {
            // The first session, when it authorizes, also covers the nonces of the sessions
            // that decrypt and encrypt, so these cannot be swapped.
            let mut extra: Vec<&[u8]> = Vec::new();
            if i == 0 && u.associated.is_some() {
                let nonce = |j: usize| {
                    let other = a.uses.get(j)?;
                    Some(self.session(other.handle)?.nonce_tpm.as_slice())
                };
                if let Some(j) = a.decrypt.filter(|&j| j != i) {
                    extra.extend(nonce(j));
                }
                if let Some(j) = a.encrypt.filter(|&j| j != i && Some(j) != a.decrypt) {
                    extra.extend(nonce(j));
                }
            }
            let cp_hash = a.cp_hash(session.hash);
            let attributes = [u.attributes];
            let mut parts: Vec<&[u8]> = vec![&cp_hash, &u.nonce_caller, &session.nonce_tpm];
            parts.extend(extra);
            parts.push(&attributes);
            let hmac = Zeroizing::new(crypt::hmac(session.hash, &key, &parts));
            u.auth.ct_eq(&hmac).into()
        };
        if matches {
            Ok(())
        } else {
            Err(self.authorization_failed(a, i))
        }
    }

    /// The key of a session's HMACs: the session key, and the authValue of the entity it
    /// authorizes unless it is bound to it.
    fn hmac_key(&self, session: &Session, u: &Use) -> Zeroizing<Vec<u8>> {
        let mut key = session.key.clone();
        if let Some(entity) = u.associated.filter(|_| u.include_auth) {
            key.extend_from_slice(&self.entity_auth(entity));
        }
        key
    }

    /// IncrementLockout: a failed authorization counts against the dictionary-attack
    /// protection (TPM_RC_AUTH_FAIL) when the entity, or the entity the session is bound to,
    /// is subject to it; otherwise it is a plain TPM_RC_BAD_AUTH.
    fn authorization_failed(&mut self, a: &Area, i: usize) -> Rc {
        let Some(u) = a.uses.get(i) else {
            return Rc::FAILURE;
        };
        // TPM_RH_UNASSIGNED, for a session that authorizes nothing, is exempt.
        let mut entity = u.associated.unwrap_or(TPM_RH_NULL);
        if let Some(session) = (u.handle != TPM_RS_PW)
            .then(|| self.session(u.handle))
            .flatten()
        {
            if session.lockout_bound {
                entity = TPM_RH_LOCKOUT;
            }
            if !session.da_bound && (self.is_da_exempt(entity) || !u.include_auth) {
                return Rc::BAD_AUTH;
            }
        } else if self.is_da_exempt(entity) {
            return Rc::BAD_AUTH;
        }
        self.da_failure(entity == TPM_RH_LOCKOUT);
        Rc::AUTH_FAIL
    }

    /// CryptParameterDecryption: decrypt the first parameter, a TPM2B, in place.
    fn decrypt_parameter(&self, a: &Area, i: usize, params: &mut [u8]) -> Result<()> {
        let u = a.uses.get(i).ok_or(Rc::FAILURE)?;
        let session = self.session(u.handle).ok_or(Rc::FAILURE)?;
        let data = leading_tpm2b(params)?;
        let extra = u
            .associated
            .map(|e| self.entity_auth(e))
            .unwrap_or_default();
        let nonces = (&u.nonce_caller[..], &session.nonce_tpm[..]);
        param_crypt(session, &extra, nonces, data, false)
    }

    /// BuildResponseSession: new TPM nonces, the first response parameter encrypted, the audit
    /// digests updated, then each session's acknowledgment. Sessions that do not continue are
    /// flushed. Without an authorization area, only the audit exclusivity changes.
    pub fn respond(
        &mut self,
        cmd: &Command,
        a: Option<&mut Area>,
        params: &mut [u8],
    ) -> Result<Vec<u8>> {
        let mut w = Writer::new();
        let Some(a) = a else {
            if cmd.sessions {
                self.volatile.exclusive_audit = None;
            }
            return Ok(w.into_bytes());
        };
        for u in &a.uses {
            if u.handle != TPM_RS_PW {
                let session = self.session_mut(u.handle)?;
                getrandom::fill(&mut session.nonce_tpm).map_err(|_| Rc::FAILURE)?;
            }
        }
        if let Some(i) = a.encrypt {
            let u = a.uses.get(i).ok_or(Rc::FAILURE)?;
            let session = self.session(u.handle).ok_or(Rc::FAILURE)?;
            let data = leading_tpm2b(params).map_err(|_| Rc::FAILURE)?;
            let extra = u
                .associated
                .map(|e| self.entity_auth(e))
                .unwrap_or_default();
            let nonces = (&session.nonce_tpm[..], &u.nonce_caller[..]);
            param_crypt(session, &extra, nonces, data, true)?;
        }
        self.update_audit(a, params)?;
        for u in &a.uses {
            if u.handle == TPM_RS_PW {
                // A password session answers with an empty nonce and HMAC, and stays open.
                w.u16(0).u8(u.attributes | CONTINUE_SESSION).u16(0);
                continue;
            }
            let session = self.session(u.handle).ok_or(Rc::FAILURE)?;
            let key = self.hmac_key(session, u);
            // No HMAC without a key, nor after TPM2_PolicyPassword.
            let password = session.policy.password_needed && session.kind != Kind::Hmac;
            let hmac = if password || (key.is_empty() && u.auth.is_empty()) {
                Vec::new()
            } else {
                let rp_hash = rp_hash(session.hash, a.code, params);
                let parts: [&[u8]; 4] = [
                    &rp_hash,
                    &session.nonce_tpm,
                    &u.nonce_caller,
                    &[u.attributes],
                ];
                crypt::hmac(session.hash, &key, &parts)
            };
            w.tpm2b(&session.nonce_tpm).u8(u.attributes).tpm2b(&hmac);
            if u.attributes & CONTINUE_SESSION == 0 {
                self.flush_session(u.handle)?;
                continue;
            }
            // A policy session starts over once used, its expirations counting from now.
            let (time, epoch) = (self.volatile.time, self.permanent.time_epoch);
            let session = self.session_mut(u.handle)?;
            if session.kind != Kind::Hmac {
                session.reset_policy();
                (session.start_time, session.epoch) = (time, epoch);
            }
        }
        Ok(w.into_bytes())
    }

    /// UpdateAuditSessionStatus: extend the audit session's digest with this command, which
    /// keeps it exclusive if no other command came between.
    fn update_audit(&mut self, a: &mut Area, params: &[u8]) -> Result<()> {
        let Some(i) = a.audit else {
            self.volatile.exclusive_audit = None;
            return Ok(());
        };
        let u = a.uses.get(i).ok_or(Rc::FAILURE)?;
        let (handle, reset) = (u.handle, u.attributes & AUDIT_RESET != 0);
        let hash = self.session(handle).ok_or(Rc::FAILURE)?.hash;
        let cp_hash = a.cp_hash(hash);
        let rp_hash = rp_hash(hash, a.code, params);
        let session = self.session_mut(handle)?;
        let exclusive = match &session.audit {
            Some(_) if !reset => self.volatile.exclusive_audit == Some(handle),
            // A first or reset audit starts from zeros, exclusive, and is no longer bound.
            _ => {
                session.audit = Some(vec![0; hash.size()]);
                session.bound = None;
                true
            }
        };
        let session = self.session_mut(handle)?;
        if let Some(digest) = &mut session.audit {
            *digest = hash.digest(&[digest, &cp_hash, &rp_hash]);
        }
        self.volatile.exclusive_audit = exclusive.then_some(handle);
        let u = a.uses.get_mut(i).ok_or(Rc::FAILURE)?;
        if exclusive {
            u.attributes |= AUDIT_EXCLUSIVE;
        } else {
            u.attributes &= !AUDIT_EXCLUSIVE;
        }
        Ok(())
    }

    /// SessionCreate: a new session in the first free handle, keyed by the bind entity's
    /// authValue and the salt.
    fn create_session(
        &mut self,
        kind: Kind,
        hash: Hash,
        nonce_caller: &[u8],
        symmetric: Symmetric,
        bind: u32,
        salt: &[u8],
    ) -> Result<(u32, Vec<u8>)> {
        if self.session_count() >= MAX_LOADED {
            return Err(Rc::SESSION_MEMORY);
        }
        // The last free slot is kept for the oldest saved session, should it need to come
        // back before the context counter catches up with it.
        if self.session_count().saturating_add(1) == MAX_LOADED && self.oldest_saved_is_due() {
            return Err(Rc::CONTEXT_GAP);
        }
        let i = (self.volatile.sessions.iter())
            .position(|s| matches!(s, SessionSlot::Free))
            .ok_or(Rc::SESSION_HANDLES)?;
        let mut nonce_tpm = vec![0; nonce_caller.len()];
        getrandom::fill(&mut nonce_tpm).map_err(|_| Rc::FAILURE)?;
        let key = if bind == TPM_RH_NULL && salt.is_empty() {
            Zeroizing::new(Vec::new())
        } else {
            let mut secret = self.entity_auth(bind);
            secret.extend_from_slice(salt);
            crypt::kdfa(hash, &secret, b"ATH", &nonce_tpm, nonce_caller, hash.size())
        };
        let bound = (bind != TPM_RH_NULL && kind == Kind::Hmac).then(|| self.bind_value(bind));
        let da_bound = bind != TPM_RH_NULL && !self.is_da_exempt(bind);
        let session = Session {
            kind,
            hash,
            nonce_tpm: nonce_tpm.clone(),
            key,
            symmetric,
            bound,
            da_bound,
            lockout_bound: da_bound && bind == TPM_RH_LOCKOUT,
            audit: None,
            policy_digest: if kind == Kind::Hmac {
                Vec::new()
            } else {
                vec![0; hash.size()]
            },
            policy: PolicyState::default(),
            start_time: self.volatile.time,
            epoch: self.permanent.time_epoch,
        };
        let slot = self.volatile.sessions.get_mut(i).ok_or(Rc::FAILURE)?;
        *slot = SessionSlot::Loaded(Box::new(session));
        let first = if kind == Kind::Hmac {
            HMAC_SESSION_FIRST
        } else {
            POLICY_SESSION_FIRST
        };
        let handle = first.checked_add(u32::try_from(i).map_err(|_| Rc::FAILURE)?);
        Ok((handle.ok_or(Rc::FAILURE)?, nonce_tpm))
    }
}

/// CompareTemplateHash: the digest of the template (TPM2B_PUBLIC's contents) TPM2_Create,
/// TPM2_CreatePrimary or TPM2_CreateLoaded carries after its TPM2B_SENSITIVE_CREATE; None for
/// another command, or parameters too short.
fn template_hash(code: u32, params: &[u8], hash: Hash) -> Option<Vec<u8>> {
    use crate::commands::{TPM_CC_CREATE, TPM_CC_CREATE_LOADED, TPM_CC_CREATE_PRIMARY};
    if !matches!(
        code,
        TPM_CC_CREATE | TPM_CC_CREATE_PRIMARY | TPM_CC_CREATE_LOADED
    ) {
        return None;
    }
    let mut r = Reader::new(params);
    let skip = usize::from(r.u16().ok()?);
    r.bytes(skip).ok()?;
    let size = usize::from(r.u16().ok()?);
    Some(hash.digest(&[r.bytes(size).ok()?]))
}

/// The session handle of session `i` of the area.
fn u_handle(a: &Area, i: usize) -> Result<u32> {
    a.uses.get(i).map(|u| u.handle).ok_or(Rc::FAILURE)
}

/// The contents of the TPM2B a parameter area starts with: what parameter encryption covers.
fn leading_tpm2b(params: &mut [u8]) -> Result<&mut [u8]> {
    let (size, data) = params
        .split_first_chunk_mut::<2>()
        .ok_or(Rc::INSUFFICIENT)?;
    let size = usize::from(u16::from_be_bytes(*size));
    if size > MAX_COMMAND_SIZE {
        return Err(Rc::SIZE);
    }
    data.get_mut(..size).ok_or(Rc::SIZE)
}

/// Encrypt (or decrypt) a parameter with a session's symmetric algorithm, keyed by the session
/// key and `extra` (the authValue of the entity it authorizes), and the nonces, newer first.
fn param_crypt(
    session: &Session,
    extra: &[u8],
    (newer, older): (&[u8], &[u8]),
    data: &mut [u8],
    encrypt: bool,
) -> Result<()> {
    let key = Zeroizing::new([&session.key[..], extra].concat());
    match session.symmetric {
        // The session's hash, whatever the definition said.
        Symmetric::Xor(_) => {
            crypt::xor_obfuscate(session.hash, &key, newer, older, data);
            Ok(())
        }
        Symmetric::Aes(bits) => {
            let key_size = usize::from(bits / 8);
            let stream = crypt::kdfa(
                session.hash,
                &key,
                b"CFB",
                newer,
                older,
                key_size + crypt::AES_BLOCK,
            );
            let (aes_key, iv) = stream.split_at_checked(key_size).ok_or(Rc::FAILURE)?;
            crypt::aes_cfb(aes_key, iv, data, encrypt)
        }
        Symmetric::Null => Err(Rc::FAILURE),
    }
}

/// A password matches an authValue when they are equal once trailing zeros are dropped from
/// both (Part 1, "password authorizations"), compared in constant time.
fn password_matches(password: &[u8], auth_value: &[u8]) -> bool {
    strip_zeros(password).ct_eq(auth_value).into()
}

/// A TPMT_SYM_DEF+, as TPM2_StartAuthSession takes it: the algorithm, its key size, its mode.
fn read_symmetric(r: &mut Reader) -> Result<(Symmetric, u16)> {
    match r.u16()? {
        TPM_ALG_NULL => Ok((Symmetric::Null, TPM_ALG_NULL)),
        TPM_ALG_XOR => Ok((Symmetric::Xor(Hash::read(r)?), TPM_ALG_NULL)),
        TPM_ALG_AES => {
            let bits = match r.u16()? {
                bits @ (128 | 192 | 256) => bits,
                _ => return Err(Rc::VALUE),
            };
            let mode = r.u16()?;
            if mode != TPM_ALG_NULL && !SYM_MODES.contains(&mode) {
                return Err(Rc::MODE);
            }
            Ok((Symmetric::Aes(bits), mode))
        }
        // TDES, Camellia and SM4 are out of scope.
        _ => Err(Rc::SYMMETRIC),
    }
}

/// TPM2_StartAuthSession: an HMAC, policy or trial session, bound to an entity or not, salted
/// or not: the salt comes encrypted to `tpmKey` (RSA-OAEP, or ECDH and KDFe).
pub fn start_auth_session(
    tpm: &mut Tpm,
    handles: &[u32],
    r: &mut Reader,
    w: &mut Out,
) -> Result<()> {
    let nonce_caller = r.tpm2b(MAX_AUTH).map_err(|rc| rc.param(1))?;
    let encrypted_salt = r
        .tpm2b(crate::key::MAX_ENCRYPTED_SECRET)
        .map_err(|rc| rc.param(2))?;
    let kind = match r.u8().map_err(|rc| rc.param(3))? {
        0x00 => Kind::Hmac,
        0x01 => Kind::Policy,
        0x03 => Kind::Trial,
        _ => return Err(Rc::VALUE.param(3)),
    };
    let (symmetric, mode) = read_symmetric(r).map_err(|rc| rc.param(4))?;
    let hash = Hash::read(r).map_err(|rc| rc.param(5))?;
    end(r)?;
    if nonce_caller.len() < 16 || nonce_caller.len() > hash.size() {
        return Err(Rc::SIZE.param(1));
    }
    let tpm_key = handles.first().copied().ok_or(Rc::FAILURE)?;
    let salt = if tpm_key == TPM_RH_NULL {
        if !encrypted_salt.is_empty() {
            return Err(Rc::VALUE.param(2));
        }
        Zeroizing::new(Vec::new())
    } else {
        let key = tpm.key(tpm_key).ok_or(Rc::KEY.handle(1))?;
        if !key.public.kind().is_asymmetric() {
            return Err(Rc::KEY.handle(1));
        }
        if encrypted_salt.is_empty() {
            return Err(Rc::VALUE.param(2));
        }
        if key.public_only() {
            return Err(Rc::HANDLE.handle(1));
        }
        if !key.public.has(crate::public::attr::DECRYPT) {
            return Err(Rc::ATTRIBUTES.handle(1));
        }
        key.decrypt_secret(b"SECRET\0", encrypted_salt)
            .map_err(|_| Rc::VALUE.param(2))?
    };
    let bind = handles.get(1).copied().ok_or(Rc::FAILURE)?;
    if handle_type(bind) == TPM_HT_TRANSIENT && tpm.key(bind).is_some_and(|k| k.public_only()) {
        return Err(Rc::HANDLE.handle(2));
    }
    // A PIN index's authValue counts its uses: no session may hold it.
    if handle_type(bind) == TPM_HT_NV_INDEX && tpm.nv_is_pin(bind) {
        return Err(Rc::HANDLE.handle(2));
    }
    if matches!(symmetric, Symmetric::Aes(_)) && mode != TPM_ALG_CFB {
        return Err(Rc::MODE.param(4));
    }
    let (handle, nonce_tpm) =
        tpm.create_session(kind, hash, nonce_caller, symmetric, bind, &salt)?;
    w.handle = Some(handle);
    w.tpm2b(&nonce_tpm);
    Ok(())
}
