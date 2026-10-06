//! Enhanced authorization (Part 1, "Enhanced Authorization"; Part 3, "Enhanced Authorization
//! (EA) Commands"; the reference implementation's `EACommands.c`, `Policy_spt.c`): the policy
//! commands, each of which extends a policy session's policyDigest and, unless the session is a
//! trial, checks its assertion now or records what the authorization must check later
//! ([`crate::session::PolicyState`]).
//!
//! A policyDigest is extended as H(policyDigest ‖ commandCode ‖ arguments). Tickets (from
//! TPM2_PolicySigned and TPM2_PolicySecret, for TPM2_PolicyTicket) are HMACs with a hierarchy's
//! proof, as in the reference.

use subtle::ConstantTimeEq;

use crate::alg::{Hash, MAX_DIGEST};
use crate::commands::{
    TPM_CC_DUPLICATE, TPM_CC_POLICY_AUTH_VALUE, TPM_CC_POLICY_AUTHORIZE,
    TPM_CC_POLICY_AUTHORIZE_NV, TPM_CC_POLICY_COMMAND_CODE, TPM_CC_POLICY_COUNTER_TIMER,
    TPM_CC_POLICY_CP_HASH, TPM_CC_POLICY_DUPLICATION_SELECT, TPM_CC_POLICY_LOCALITY,
    TPM_CC_POLICY_NAME_HASH, TPM_CC_POLICY_NV, TPM_CC_POLICY_NV_WRITTEN, TPM_CC_POLICY_OR,
    TPM_CC_POLICY_PCR, TPM_CC_POLICY_PHYSICAL_PRESENCE, TPM_CC_POLICY_SECRET, TPM_CC_POLICY_SIGNED,
    TPM_CC_POLICY_TEMPLATE, end, find, read_yes_no,
};
use crate::crypt;
use crate::entity::{
    MAX_NAME, TPM_HT_NV_INDEX, TPM_HT_PERMANENT, TPM_HT_TRANSIENT, TPM_RH_ENDORSEMENT, TPM_RH_NULL,
    TPM_RH_OWNER, TPM_RH_PLATFORM, handle_type,
};
use crate::marshal::{Reader, Writer};
use crate::nv;
use crate::object::read_hierarchy;
use crate::pcr;
use crate::rc::{Rc, Result};
use crate::session::{Bound, Kind, Session};
use crate::signing::{self, TPM_ST_VERIFIED};
use crate::{Out, Tpm};

/// TPM_ST_AUTH_SECRET and TPM_ST_AUTH_SIGNED, the tags of a TPMT_TK_AUTH.
const TPM_ST_AUTH_SECRET: u16 = 0x8023;
const TPM_ST_AUTH_SIGNED: u16 = 0x8025;
/// A ticket's timeout has this bit set when it expires at the next TPM Reset.
const EXPIRATION_BIT: u64 = 1 << 63;
/// sizeof(TPMT_HA): how much of an NV index TPM2_PolicyAuthorizeNV reads.
const TPMT_HA_SIZE: usize = 2 + MAX_DIGEST;
/// TPMS_TIME_INFO marshalled: time, clock, resetCount, restartCount, safe.
const TIME_INFO_SIZE: usize = 8 + 8 + 4 + 4 + 1;

/// The policy session a policy command names: its last handle.
fn session_handle(handles: &[u32]) -> Result<u32> {
    handles.last().copied().ok_or(Rc::FAILURE)
}

impl Session {
    fn is_trial(&self) -> bool {
        self.kind == Kind::Trial
    }

    /// policyDigest := H(policyDigest ‖ code ‖ parts).
    fn extend(&mut self, code: u32, parts: &[&[u8]]) {
        let code = code.to_be_bytes();
        let mut all: Vec<&[u8]> = vec![&self.policy_digest, &code];
        all.extend_from_slice(parts);
        self.policy_digest = self.hash.digest(&all);
    }

    /// PolicyDigestClear: zeros of the session's digest size.
    fn clear_digest(&mut self) {
        self.policy_digest = vec![0; self.hash.size()];
    }

    /// PolicyContextUpdate: extend with the code and a Name, then (if any) the policyRef; bind
    /// the session to a cpHash; keep the earliest timeout.
    fn context_update(
        &mut self,
        code: u32,
        name: &[u8],
        policy_ref: Option<&[u8]>,
        cp_hash: &[u8],
        timeout: u64,
    ) {
        self.extend(code, &[name]);
        if let Some(policy_ref) = policy_ref {
            self.policy_digest = self.hash.digest(&[&self.policy_digest, policy_ref]);
        }
        if !cp_hash.is_empty() {
            self.policy.bound = Some((Bound::CpHash, cp_hash.to_vec()));
        }
        if timeout != 0 && (self.policy.timeout == 0 || self.policy.timeout > timeout) {
            self.policy.timeout = timeout;
        }
    }
}

impl Tpm {
    fn policy_session(&mut self, handle: u32) -> Result<&mut Session> {
        self.session_mut(handle)
    }

    /// ComputeAuthTimeout: when an authorization given `expiration` seconds expires (0: never):
    /// from the session's start if bound to its nonce, else at that absolute time.
    fn auth_timeout(&self, session: &Session, expiration: i32, nonce: &[u8]) -> u64 {
        if expiration == 0 {
            return 0;
        }
        let seconds = u64::from(expiration.unsigned_abs().min(i32::MAX.unsigned_abs()));
        let ms = seconds.saturating_mul(1000);
        if nonce.is_empty() {
            ms.saturating_add(self.volatile.time % 1000)
        } else {
            session.start_time.saturating_add(ms)
        }
    }

    /// PolicyParameterChecks: the nonce is the session's, the authorization has not expired,
    /// and the cpHash fits the session (`blame`: the parameters for nonce, cpHash, expiration).
    fn policy_parameter_checks(
        &self,
        session: &Session,
        timeout: u64,
        cp_hash: &[u8],
        nonce: Option<&[u8]>,
        (blame_nonce, blame_cp_hash, blame_expiration): (u32, u32, u32),
    ) -> Result<()> {
        if let Some(nonce) = nonce.filter(|n| !n.is_empty())
            && !bool::from(nonce.ct_eq(&session.nonce_tpm))
        {
            return Err(Rc::NONCE.param(blame_nonce));
        }
        if timeout != 0
            && (timeout < self.volatile.time || session.epoch != self.permanent.time_epoch)
        {
            return Err(Rc::EXPIRED.param(blame_expiration));
        }
        if !cp_hash.is_empty() {
            if cp_hash.len() != session.policy_digest.len() {
                return Err(Rc::SIZE.param(blame_cp_hash));
            }
            if let Some((_, bound)) = &session.policy.bound
                && bound.as_slice() != cp_hash
            {
                return Err(Rc::CPHASH);
            }
        }
        Ok(())
    }

    /// TicketComputeAuth: HMAC(proof, tag ‖ cpHash ‖ policyRef ‖ Name ‖ timeout [‖ epoch
    /// [‖ totalResetCount]]).
    fn auth_ticket(
        &self,
        tag: u16,
        hierarchy: u32,
        (timeout, expires_on_reset): (u64, bool),
        cp_hash: &[u8],
        policy_ref: &[u8],
        name: &[u8],
    ) -> Vec<u8> {
        let tag = tag.to_be_bytes();
        let timeout_bytes = timeout.to_be_bytes();
        let epoch = self.permanent.time_epoch.to_be_bytes();
        let resets = self.permanent.total_reset_count.to_be_bytes();
        let mut parts: Vec<&[u8]> = vec![&tag, cp_hash, policy_ref, name, &timeout_bytes];
        if timeout != 0 {
            parts.push(&epoch);
            if expires_on_reset {
                parts.push(&resets);
            }
        }
        crypt::hmac(Hash::Sha512, self.proof(hierarchy).as_slice(), &parts)
    }

    /// EntityGetHierarchy: the hierarchy whose proof makes an entity's tickets.
    fn entity_hierarchy(&self, handle: u32) -> u32 {
        match handle_type(handle) {
            TPM_HT_PERMANENT => match handle {
                TPM_RH_PLATFORM | TPM_RH_ENDORSEMENT | TPM_RH_NULL => handle,
                _ => TPM_RH_OWNER,
            },
            TPM_HT_NV_INDEX => {
                let platform = self
                    .nv_public(handle)
                    .is_some_and(|p| p.has(nv::attr::PLATFORMCREATE));
                if platform {
                    TPM_RH_PLATFORM
                } else {
                    TPM_RH_OWNER
                }
            }
            TPM_HT_TRANSIENT => self.key(handle).map_or(TPM_RH_NULL, |k| k.hierarchy),
            _ => TPM_RH_OWNER,
        }
    }
}

/// A TPM_EO.
fn read_operation(r: &mut Reader) -> Result<u16> {
    let op = r.u16()?;
    if op <= 0x000b { Ok(op) } else { Err(Rc::VALUE) }
}

/// PolicySptCheckCondition: `a` (the TPM's data) against `b` (the caller's), by `op`. The
/// signed comparisons look at the first byte's sign bit, then compare unsigned, as the
/// reference does.
fn check_condition(op: u16, a: &[u8], b: &[u8]) -> bool {
    let unsigned = a.cmp(b);
    let signed = match (a.first(), b.first()) {
        (Some(x), Some(y)) if (x ^ y) & 0x80 != 0 => {
            if x & 0x80 != 0 {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        }
        _ => unsigned,
    };
    use std::cmp::Ordering::{Equal, Greater, Less};
    match op {
        0x0000 => unsigned == Equal,
        0x0001 => unsigned != Equal,
        0x0002 => signed == Greater,
        0x0003 => unsigned == Greater,
        0x0004 => signed == Less,
        0x0005 => unsigned == Less,
        0x0006 => signed != Less,
        0x0007 => unsigned != Less,
        0x0008 => signed != Greater,
        0x0009 => unsigned != Greater,
        0x000a => a.iter().zip(b).all(|(x, y)| x & y == *y),
        _ => a.iter().zip(b).all(|(x, y)| x & y == 0),
    }
}

/// The output of TPM2_PolicySigned and TPM2_PolicySecret: a ticket for TPM2_PolicyTicket if
/// the authorization was given an expiration (negative), else a NULL ticket.
fn write_ticket(w: &mut Writer, tag: u16, ticket: Option<(u32, u64, Vec<u8>)>) {
    match ticket {
        Some((hierarchy, timeout, digest)) => {
            w.tpm2b(&timeout.to_be_bytes())
                .u16(tag)
                .u32(hierarchy)
                .tpm2b(&digest);
        }
        None => {
            w.tpm2b(&[]).u16(tag).u32(TPM_RH_NULL).tpm2b(&[]);
        }
    }
}

/// The parameters TPM2_PolicySigned and TPM2_PolicySecret share.
struct Authorization<'a> {
    nonce: &'a [u8],
    cp_hash: &'a [u8],
    policy_ref: &'a [u8],
    expiration: i32,
}

fn read_authorization<'a>(r: &mut Reader<'a>) -> Result<Authorization<'a>> {
    Ok(Authorization {
        nonce: r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(1))?,
        cp_hash: r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(2))?,
        policy_ref: r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(3))?,
        expiration: r.u32().map_err(|rc| rc.param(4))?.cast_signed(),
    })
}

/// What TPM2_PolicySigned and TPM2_PolicySecret do once the authorization is checked: extend
/// the policy, and give a ticket if asked for one.
fn authorized(
    tpm: &mut Tpm,
    code: u32,
    tag: u16,
    entity: u32,
    session_handle: u32,
    (a, timeout): (&Authorization, u64),
    w: &mut Out,
) -> Result<()> {
    let name = tpm.entity_name(entity);
    let trial = tpm.session(session_handle).ok_or(Rc::FAILURE)?.is_trial();
    let ticket = if a.expiration < 0 && !trial && !tpm.nv_is_pin_pass(entity) {
        let expires_on_reset = a.nonce.is_empty();
        let hierarchy = tpm.entity_hierarchy(entity);
        let timeout = timeout & !EXPIRATION_BIT;
        let digest = tpm.auth_ticket(
            tag,
            hierarchy,
            (timeout, expires_on_reset),
            a.cp_hash,
            a.policy_ref,
            &name,
        );
        let marked = if expires_on_reset {
            timeout | EXPIRATION_BIT
        } else {
            timeout
        };
        Some((hierarchy, marked, digest))
    } else {
        None
    };
    let session = tpm.policy_session(session_handle)?;
    session.context_update(code, &name, Some(a.policy_ref), a.cp_hash, timeout);
    write_ticket(w, tag, ticket);
    Ok(())
}

/// TPM2_PolicySigned: an authorization signed by `authObject`'s key, over the session's nonce,
/// an expiration, a cpHash and a policyRef.
pub fn policy_signed(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let a = read_authorization(r)?;
    let signature = signing::read_signature(r).map_err(|rc| rc.param(5))?;
    end(r)?;
    let key_handle = handles.first().copied().ok_or(Rc::FAILURE)?;
    let session_handle = session_handle(handles)?;
    let session = tpm.session(session_handle).ok_or(Rc::FAILURE)?;
    let mut timeout = 0;
    if !session.is_trial() {
        timeout = tpm.auth_timeout(session, a.expiration, a.nonce);
        tpm.policy_parameter_checks(session, timeout, a.cp_hash, Some(a.nonce), (1, 2, 4))?;
        // CryptGetSignHashAlg: ECDAA has no hash to sign with here.
        if signature.alg == crate::public::TPM_ALG_ECDAA {
            return Err(Rc::SCHEME.param(5));
        }
        let hash = signature.hash;
        let expiration = a.expiration.to_be_bytes();
        let digest = hash.digest(&[a.nonce, &expiration, a.cp_hash, a.policy_ref]);
        let key = tpm.key(key_handle).ok_or(Rc::FAILURE)?;
        signing::verify(key, &digest, &signature).map_err(|rc| rc.param(5))?;
    }
    authorized(
        tpm,
        TPM_CC_POLICY_SIGNED,
        TPM_ST_AUTH_SIGNED,
        key_handle,
        session_handle,
        (&a, timeout),
        w,
    )
}

/// TPM2_PolicySecret: the authorization of `authHandle`, given with this command.
pub fn policy_secret(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let a = read_authorization(r)?;
    end(r)?;
    let entity = handles.first().copied().ok_or(Rc::FAILURE)?;
    let session_handle = session_handle(handles)?;
    let session = tpm.session(session_handle).ok_or(Rc::FAILURE)?;
    let mut timeout = 0;
    if !session.is_trial() {
        timeout = tpm.auth_timeout(session, a.expiration, a.nonce);
        tpm.policy_parameter_checks(session, timeout, a.cp_hash, Some(a.nonce), (1, 2, 4))?;
    }
    authorized(
        tpm,
        TPM_CC_POLICY_SECRET,
        TPM_ST_AUTH_SECRET,
        entity,
        session_handle,
        (&a, timeout),
        w,
    )
}

/// A TPMT_TK_AUTH: its tag, hierarchy and digest.
fn read_auth_ticket<'a>(r: &mut Reader<'a>) -> Result<(u16, u32, &'a [u8])> {
    let tag = r.u16()?;
    if !crate::is_structure_tag(tag) {
        return Err(Rc::VALUE);
    }
    if tag != TPM_ST_AUTH_SIGNED && tag != TPM_ST_AUTH_SECRET {
        return Err(Rc::TAG);
    }
    let hierarchy = read_hierarchy(r)?;
    Ok((tag, hierarchy, r.tpm2b(MAX_DIGEST)?))
}

/// TPM2_PolicyTicket: a ticket TPM2_PolicySigned or TPM2_PolicySecret gave, in their stead.
pub fn policy_ticket(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let timeout = r.tpm2b(8).map_err(|rc| rc.param(1))?;
    let cp_hash = r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(2))?;
    let policy_ref = r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(3))?;
    let name = r.tpm2b(MAX_NAME).map_err(|rc| rc.param(4))?;
    let (tag, hierarchy, digest) = read_auth_ticket(r).map_err(|rc| rc.param(5))?;
    end(r)?;
    let session_handle = session_handle(handles)?;
    let session = tpm.session(session_handle).ok_or(Rc::FAILURE)?;
    if session.is_trial() {
        return Err(Rc::ATTRIBUTES.handle(1));
    }
    let timeout: [u8; 8] = timeout.try_into().map_err(|_| Rc::SIZE.param(1))?;
    let timeout = u64::from_be_bytes(timeout);
    let expires_on_reset = timeout & EXPIRATION_BIT != 0;
    let timeout = timeout & !EXPIRATION_BIT;
    tpm.policy_parameter_checks(session, timeout, cp_hash, None, (0, 2, 1))?;
    let expected = tpm.auth_ticket(
        tag,
        hierarchy,
        (timeout, expires_on_reset),
        cp_hash,
        policy_ref,
        name,
    );
    if !bool::from(expected.ct_eq(digest)) {
        return Err(Rc::TICKET.param(5));
    }
    let code = if tag == TPM_ST_AUTH_SIGNED {
        TPM_CC_POLICY_SIGNED
    } else {
        TPM_CC_POLICY_SECRET
    };
    let session = tpm.policy_session(session_handle)?;
    session.context_update(code, name, Some(policy_ref), cp_hash, timeout);
    Ok(())
}

/// TPM2_PolicyOR: the policy so far is one of these branches (any, for a trial).
pub fn policy_or(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let branches = (|| {
        let count = usize::try_from(r.u32()?).map_err(|_| Rc::SIZE)?;
        if !(2..=8).contains(&count) {
            return Err(Rc::SIZE);
        }
        (0..count)
            .map(|_| r.tpm2b(MAX_DIGEST))
            .collect::<Result<Vec<_>>>()
    })()
    .map_err(|rc| rc.param(1))?;
    end(r)?;
    let session = tpm.policy_session(session_handle(handles)?)?;
    let digest = session.policy_digest.clone();
    let matches = branches.iter().any(|b| bool::from(b.ct_eq(&digest)));
    if !session.is_trial() && !matches {
        return Err(Rc::VALUE.param(1));
    }
    session.clear_digest();
    session.extend(TPM_CC_POLICY_OR, &branches);
    Ok(())
}

/// TPM2_PolicyPCR: the selected PCRs have these values (their digest), now and when the session
/// authorizes; a trial takes the digest it is given.
pub fn policy_pcr(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let pcr_digest = r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(1))?;
    let mut selections = pcr::read_selections(r).map_err(|rc| rc.param(2))?;
    end(r)?;
    let handle = session_handle(handles)?;
    let hash = tpm.session(handle).ok_or(Rc::FAILURE)?.hash;
    let current = (tpm.volatile.pcrs).digest(&tpm.volatile.allocation, &mut selections, hash);
    let counter = tpm.volatile.pcrs.counter;
    let session = tpm.policy_session(handle)?;
    let digest = if session.is_trial() {
        if pcr_digest.is_empty() {
            current
        } else {
            pcr_digest.to_vec()
        }
    } else {
        if session.policy.pcr_counter != 0 && session.policy.pcr_counter != counter {
            return Err(Rc::PCR_CHANGED);
        }
        if !pcr_digest.is_empty() && !bool::from(pcr_digest.ct_eq(&current)) {
            return Err(Rc::VALUE.param(1));
        }
        session.policy.pcr_counter = counter;
        current
    };
    let mut w = Writer::new();
    pcr::write_selections(&mut w, &selections);
    session.extend(TPM_CC_POLICY_PCR, &[&w.into_bytes(), &digest]);
    Ok(())
}

/// TPM2_PolicyLocality: the localities the command may come from, narrowed each time.
pub fn policy_locality(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let locality = r.u8().map_err(|rc| rc.param(1))?;
    end(r)?;
    let session = tpm.policy_session(session_handle(handles)?)?;
    let range = Rc::RANGE.param(1);
    if locality == 0 {
        return Err(range);
    }
    let previous = session.policy.locality;
    if previous != 0 && (previous < 32) != (locality < 32) {
        return Err(range);
    }
    let next = if locality < 32 {
        let narrowed = if previous == 0 { 0x1f } else { previous } & locality;
        if narrowed == 0 {
            return Err(range);
        }
        narrowed
    } else {
        if previous != 0 && previous != locality {
            return Err(range);
        }
        locality
    };
    session.extend(TPM_CC_POLICY_LOCALITY, &[&[locality]]);
    session.policy.locality = next;
    Ok(())
}

/// The arguments TPM2_PolicyNV and TPM2_PolicyCounterTimer extend with:
/// H(operandB ‖ offset ‖ operation).
fn arguments(hash: Hash, operand: &[u8], offset: u16, operation: u16) -> Vec<u8> {
    hash.digest(&[operand, &offset.to_be_bytes(), &operation.to_be_bytes()])
}

/// TPM2_PolicyNV: an NV index's data compares with operandB.
pub fn policy_nv(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let operand = r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(1))?;
    let offset = r.u16().map_err(|rc| rc.param(2))?;
    let operation = read_operation(r).map_err(|rc| rc.param(3))?;
    end(r)?;
    let auth = handles.first().copied().ok_or(Rc::FAILURE)?;
    let index = handles.get(1).copied().ok_or(Rc::FAILURE)?;
    let session_handle = session_handle(handles)?;
    let public = tpm.nv_public(index).ok_or(Rc::FAILURE)?;
    let session = tpm.session(session_handle).ok_or(Rc::FAILURE)?;
    if !session.is_trial() {
        nv::read_access(auth, index, &public)?;
        let size = usize::from(public.data_size);
        let start = usize::from(offset);
        if start > size {
            return Err(Rc::VALUE.param(2));
        }
        if size.saturating_sub(start) < operand.len() {
            return Err(Rc::SIZE.param(1));
        }
        let data = tpm.nv_data(index).unwrap_or_default();
        let end = start.saturating_add(operand.len());
        let data = data.get(start..end).ok_or(Rc::FAILURE)?;
        if !check_condition(operation, data, operand) {
            return Err(Rc::POLICY);
        }
    }
    let name = public.name();
    let session = tpm.policy_session(session_handle)?;
    let args = arguments(session.hash, operand, offset, operation);
    session.extend(TPM_CC_POLICY_NV, &[&args, &name]);
    Ok(())
}

/// TPM2_PolicyCounterTimer: TPMS_TIME_INFO (time, Clock, the reset counters) compares with
/// operandB.
pub fn policy_counter_timer(
    tpm: &mut Tpm,
    handles: &[u32],
    r: &mut Reader,
    _: &mut Out,
) -> Result<()> {
    let operand = r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(1))?;
    let offset = r.u16().map_err(|rc| rc.param(2))?;
    let operation = read_operation(r).map_err(|rc| rc.param(3))?;
    end(r)?;
    let start = usize::from(offset);
    if start > TIME_INFO_SIZE {
        return Err(Rc::VALUE.param(2));
    }
    if start.saturating_add(operand.len()) > TIME_INFO_SIZE {
        return Err(Rc::RANGE);
    }
    let session_handle = session_handle(handles)?;
    let trial = tpm.session(session_handle).ok_or(Rc::FAILURE)?.is_trial();
    if !trial {
        let mut info = Writer::new();
        info.u64(tpm.volatile.time);
        tpm.write_clock_info(&mut info);
        let info = info.into_bytes();
        let end = start.saturating_add(operand.len());
        let data = info.get(start..end).ok_or(Rc::FAILURE)?;
        if !check_condition(operation, data, operand) {
            return Err(Rc::POLICY);
        }
    }
    let session = tpm.policy_session(session_handle)?;
    let args = arguments(session.hash, operand, offset, operation);
    session.extend(TPM_CC_POLICY_COUNTER_TIMER, &[&args]);
    Ok(())
}

/// TPM2_PolicyCommandCode: the command the session may authorize, one the TPM implements.
pub fn policy_command_code(
    tpm: &mut Tpm,
    handles: &[u32],
    r: &mut Reader,
    _: &mut Out,
) -> Result<()> {
    let code = r.u32().map_err(|rc| rc.param(1))?;
    end(r)?;
    let session = tpm.policy_session(session_handle(handles)?)?;
    if session.policy.command_code != 0 && session.policy.command_code != code {
        return Err(Rc::VALUE.param(1));
    }
    if find(code).is_none() {
        return Err(Rc::POLICY_CC.param(1));
    }
    session.extend(TPM_CC_POLICY_COMMAND_CODE, &[&code.to_be_bytes()]);
    session.policy.command_code = code;
    Ok(())
}

/// TPM2_PolicyPhysicalPresence: physical presence, which this TPM never has.
pub fn policy_physical_presence(
    tpm: &mut Tpm,
    handles: &[u32],
    r: &mut Reader,
    _: &mut Out,
) -> Result<()> {
    end(r)?;
    let session = tpm.policy_session(session_handle(handles)?)?;
    session.extend(TPM_CC_POLICY_PHYSICAL_PRESENCE, &[]);
    session.policy.pp_required = true;
    Ok(())
}

/// TPM2_PolicyCpHash: the command's cpHash.
pub fn policy_cp_hash(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let cp_hash = r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(1))?;
    end(r)?;
    let session = tpm.policy_session(session_handle(handles)?)?;
    if cp_hash.len() != session.hash.size() {
        return Err(Rc::SIZE.param(1));
    }
    match &session.policy.bound {
        Some((Bound::CpHash, bound)) if bound.as_slice() == cp_hash => {}
        Some(_) => return Err(Rc::CPHASH),
        None => {}
    }
    session.extend(TPM_CC_POLICY_CP_HASH, &[cp_hash]);
    session.policy.bound = Some((Bound::CpHash, cp_hash.to_vec()));
    Ok(())
}

/// TPM2_PolicyNameHash: the hash of the command's handles' Names.
pub fn policy_name_hash(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let name_hash = r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(1))?;
    end(r)?;
    let session = tpm.policy_session(session_handle(handles)?)?;
    if name_hash.len() != session.hash.size() {
        return Err(Rc::SIZE.param(1));
    }
    if session.policy.bound.is_some() {
        return Err(Rc::CPHASH);
    }
    session.extend(TPM_CC_POLICY_NAME_HASH, &[name_hash]);
    session.policy.bound = Some((Bound::Names, name_hash.to_vec()));
    Ok(())
}

/// TPM2_PolicyDuplicationSelect: TPM2_Duplicate of this object to this new parent.
pub fn policy_duplication_select(
    tpm: &mut Tpm,
    handles: &[u32],
    r: &mut Reader,
    _: &mut Out,
) -> Result<()> {
    let object = r.tpm2b(MAX_NAME).map_err(|rc| rc.param(1))?;
    let new_parent = r.tpm2b(MAX_NAME).map_err(|rc| rc.param(2))?;
    let include = read_yes_no(r).map_err(|rc| rc.param(3))?;
    end(r)?;
    let session = tpm.policy_session(session_handle(handles)?)?;
    if session.policy.bound.is_some() {
        return Err(Rc::CPHASH);
    }
    if session.policy.command_code != 0 {
        return Err(Rc::COMMAND_CODE);
    }
    let name_hash = session.hash.digest(&[object, new_parent]);
    let flag = [u8::from(include)];
    let object: &[u8] = if include { object } else { &[] };
    session.extend(
        TPM_CC_POLICY_DUPLICATION_SELECT,
        &[object, new_parent, &flag],
    );
    session.policy.bound = Some((Bound::Names, name_hash));
    session.policy.command_code = TPM_CC_DUPLICATE;
    Ok(())
}

/// TPM2_PolicyAuthorize: the policy so far was approved, with this policyRef, by a key whose
/// signature TPM2_VerifySignature checked (its ticket).
pub fn policy_authorize(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let approved = r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(1))?;
    let policy_ref = r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(2))?;
    let key_sign = r.tpm2b(MAX_NAME).map_err(|rc| rc.param(3))?;
    let (hierarchy, ticket) = (|| {
        let tag = r.u16()?;
        if !crate::is_structure_tag(tag) {
            return Err(Rc::VALUE);
        }
        if tag != TPM_ST_VERIFIED {
            return Err(Rc::TAG);
        }
        Ok((read_hierarchy(r)?, r.tpm2b(MAX_DIGEST)?))
    })()
    .map_err(|rc| rc.param(4))?;
    end(r)?;
    let (alg, digest) = key_sign.split_at_checked(2).ok_or(Rc::SIZE.param(3))?;
    let alg = u16::from_be_bytes(alg.try_into().map_err(|_| Rc::SIZE.param(3))?);
    let hash = Hash::from_id(alg).ok_or(Rc::HASH.param(3))?;
    if digest.len() != hash.size() {
        return Err(Rc::SIZE.param(3));
    }
    let handle = session_handle(handles)?;
    let session = tpm.session(handle).ok_or(Rc::FAILURE)?;
    if !session.is_trial() {
        if !bool::from(session.policy_digest.ct_eq(approved)) {
            return Err(Rc::VALUE.param(1));
        }
        let auth_hash = hash.digest(&[approved, policy_ref]);
        let expected = tpm.verified_ticket(hierarchy, &auth_hash, key_sign);
        if !bool::from(expected.ct_eq(ticket)) {
            return Err(Rc::VALUE.param(4));
        }
    }
    let session = tpm.policy_session(handle)?;
    session.clear_digest();
    session.context_update(TPM_CC_POLICY_AUTHORIZE, key_sign, Some(policy_ref), &[], 0);
    Ok(())
}

/// TPM2_PolicyAuthValue: the HMAC also proves the entity's authValue.
pub fn policy_auth_value(
    tpm: &mut Tpm,
    handles: &[u32],
    r: &mut Reader,
    _: &mut Out,
) -> Result<()> {
    end(r)?;
    let session = tpm.policy_session(session_handle(handles)?)?;
    session.extend(TPM_CC_POLICY_AUTH_VALUE, &[]);
    session.policy.auth_value_needed = true;
    session.policy.password_needed = false;
    Ok(())
}

/// TPM2_PolicyPassword: the entity's authValue, in clear. The policy is the same as
/// TPM2_PolicyAuthValue's (its code is that one's).
pub fn policy_password(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    end(r)?;
    let session = tpm.policy_session(session_handle(handles)?)?;
    session.extend(TPM_CC_POLICY_AUTH_VALUE, &[]);
    session.policy.password_needed = true;
    session.policy.auth_value_needed = false;
    Ok(())
}

/// TPM2_PolicyGetDigest: the policyDigest so far.
pub fn policy_get_digest(
    tpm: &mut Tpm,
    handles: &[u32],
    r: &mut Reader,
    w: &mut Out,
) -> Result<()> {
    end(r)?;
    let session = tpm.session(session_handle(handles)?).ok_or(Rc::FAILURE)?;
    w.tpm2b(&session.policy_digest);
    Ok(())
}

/// TPM2_PolicyNvWritten: the NV index authorized is written, or not.
pub fn policy_nv_written(
    tpm: &mut Tpm,
    handles: &[u32],
    r: &mut Reader,
    _: &mut Out,
) -> Result<()> {
    let written = read_yes_no(r).map_err(|rc| rc.param(1))?;
    end(r)?;
    let session = tpm.policy_session(session_handle(handles)?)?;
    if session.policy.nv_written.is_some_and(|w| w != written) {
        return Err(Rc::VALUE.param(1));
    }
    session.policy.nv_written = Some(written);
    session.extend(TPM_CC_POLICY_NV_WRITTEN, &[&[u8::from(written)]]);
    Ok(())
}

/// TPM2_PolicyTemplate: the template an object is created from.
pub fn policy_template(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let template = r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(1))?;
    end(r)?;
    let session = tpm.policy_session(session_handle(handles)?)?;
    match &session.policy.bound {
        Some((Bound::Template, bound)) if bound.as_slice() == template => {}
        Some(_) => return Err(Rc::CPHASH),
        None => {}
    }
    if template.len() != session.hash.size() {
        return Err(Rc::SIZE.param(1));
    }
    session.extend(TPM_CC_POLICY_TEMPLATE, &[template]);
    session.policy.bound = Some((Bound::Template, template.to_vec()));
    Ok(())
}

/// TPM2_PolicyAuthorizeNV: the policy so far is the one an NV index holds (a TPMT_HA).
pub fn policy_authorize_nv(
    tpm: &mut Tpm,
    handles: &[u32],
    r: &mut Reader,
    _: &mut Out,
) -> Result<()> {
    end(r)?;
    let auth = handles.first().copied().ok_or(Rc::FAILURE)?;
    let index = handles.get(1).copied().ok_or(Rc::FAILURE)?;
    let session_handle = session_handle(handles)?;
    let public = tpm.nv_public(index).ok_or(Rc::FAILURE)?;
    let session = tpm.session(session_handle).ok_or(Rc::FAILURE)?;
    if !session.is_trial() {
        nv::read_access(auth, index, &public)?;
        let data = tpm.nv_data(index).unwrap_or_default();
        let mut r = Reader::new(data.get(..TPMT_HA_SIZE).unwrap_or(data));
        let hash = Hash::read(&mut r)?;
        let digest = r.bytes(hash.size())?;
        if hash != session.hash {
            return Err(Rc::HASH);
        }
        if !bool::from(digest.ct_eq(&session.policy_digest)) {
            return Err(Rc::VALUE);
        }
    }
    let name = public.name();
    let session = tpm.policy_session(session_handle)?;
    session.clear_digest();
    session.context_update(TPM_CC_POLICY_AUTHORIZE_NV, &name, None, &[], 0);
    Ok(())
}

/// TPM2_PolicyRestart: the policy starts over (its expirations still count from the session's
/// start).
pub fn policy_restart(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    end(r)?;
    tpm.policy_session(session_handle(handles)?)?.reset_policy();
    Ok(())
}

impl Tpm {
    /// The index is a PIN pass index: TPM2_PolicySecret gives no ticket for it.
    fn nv_is_pin_pass(&self, handle: u32) -> bool {
        handle_type(handle) == TPM_HT_NV_INDEX
            && self
                .nv_public(handle)
                .and_then(|p| p.kind())
                .is_some_and(|k| k == nv::Kind::PinPass)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditions_compare_as_the_reference_does() {
        assert!(check_condition(0x0000, &[1, 2], &[1, 2]));
        assert!(
            check_condition(0x0003, &[0x80], &[0x7f]),
            "unsigned 0x80 > 0x7f"
        );
        assert!(
            check_condition(0x0004, &[0x80], &[0x7f]),
            "signed 0x80 < 0x7f"
        );
        assert!(check_condition(0x0002, &[0x01, 0x00], &[0x00, 0xff]));
        assert!(check_condition(0x000a, &[0xf3], &[0x03]));
        assert!(!check_condition(0x000a, &[0xf3], &[0x07]));
        assert!(check_condition(0x000b, &[0xf0], &[0x0f]));
        assert!(check_condition(0x0006, &[], &[]), "nothing compares equal");
    }
}
