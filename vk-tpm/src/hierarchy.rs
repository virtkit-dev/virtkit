//! The hierarchies (Part 1, "Hierarchies"), their authorizations, and the dictionary-attack
//! protection (Part 1, "Dictionary Attack Protection"; `DA.c`).
//!
//! What each hierarchy is made of lives in two places, as in the reference implementation:
//! - [`Hierarchies`], in the permanent state: the owner, endorsement and lockout authValues and
//!   authPolicies, the proofs, and disableClear;
//! - [`ClearState`], in the volatile state: the enables and the platform authorization, which
//!   every TPM2_Startup(CLEAR) resets and TPM2_Shutdown(STATE) saves for the resume.

use zeroize::Zeroizing;

use crate::alg::{Hash, MAX_DIGEST};
use crate::commands::{end, first, read_yes_no};
use crate::entity::{
    TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_OWNER, TPM_RH_PLATFORM, TPM_RH_PLATFORM_NV,
    strip_zeros,
};
use crate::marshal::{Reader, Writer};
use crate::rc::{Rc, Result};
use crate::state::{Seed, StateError, new_seed};
use crate::{Out, Tpm};

/// An authValue, without its trailing zeros. Wiped when dropped.
pub type Auth = Zeroizing<Vec<u8>>;

/// An authPolicy: the digest a policy session must reach, and the algorithm it is computed
/// with. `hash` is None (TPM_ALG_NULL) when the entity has none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Policy {
    pub hash: Option<Hash>,
    pub digest: Vec<u8>,
}

impl Policy {
    pub fn write(&self, w: &mut Writer) {
        w.u16(self.hash.map_or(crate::alg::TPM_ALG_NULL, Hash::id))
            .tpm2b(&self.digest);
    }

    pub fn read(r: &mut Reader) -> std::result::Result<Policy, StateError> {
        let hash = Hash::read_or_null(r)?;
        let digest = r.tpm2b(MAX_DIGEST)?.to_vec();
        if digest.len() != hash.map_or(0, Hash::size) {
            return Err(StateError("bad policy"));
        }
        Ok(Policy { hash, digest })
    }
}

/// The permanent part of the hierarchies.
pub struct Hierarchies {
    pub owner_auth: Auth,
    pub endorsement_auth: Auth,
    pub lockout_auth: Auth,
    pub owner_policy: Policy,
    pub endorsement_policy: Policy,
    pub lockout_policy: Policy,
    /// The secret values that prove the TPM made a ticket (or, later, an object) of the
    /// platform, storage (owner) and endorsement hierarchies.
    pub ph_proof: Seed,
    pub sh_proof: Seed,
    pub eh_proof: Seed,
    /// TPM2_Clear is refused (TPM2_ClearControl).
    pub disable_clear: bool,
}

impl Hierarchies {
    pub fn manufacture() -> std::result::Result<Hierarchies, StateError> {
        Ok(Hierarchies {
            owner_auth: Auth::default(),
            endorsement_auth: Auth::default(),
            lockout_auth: Auth::default(),
            owner_policy: Policy::default(),
            endorsement_policy: Policy::default(),
            lockout_policy: Policy::default(),
            ph_proof: new_seed()?,
            sh_proof: new_seed()?,
            eh_proof: new_seed()?,
            disable_clear: false,
        })
    }

    pub fn write(&self, w: &mut Writer) {
        for auth in [&self.owner_auth, &self.endorsement_auth, &self.lockout_auth] {
            w.tpm2b(auth);
        }
        for policy in [
            &self.owner_policy,
            &self.endorsement_policy,
            &self.lockout_policy,
        ] {
            policy.write(w);
        }
        for proof in [&self.ph_proof, &self.sh_proof, &self.eh_proof] {
            w.tpm2b(proof.as_slice());
        }
        w.u8(self.disable_clear.into());
    }

    pub fn read(r: &mut Reader) -> std::result::Result<Hierarchies, StateError> {
        let mut auth = || -> std::result::Result<Auth, StateError> {
            Ok(Zeroizing::new(r.tpm2b(MAX_DIGEST)?.to_vec()))
        };
        let (owner_auth, endorsement_auth, lockout_auth) = (auth()?, auth()?, auth()?);
        let owner_policy = Policy::read(r)?;
        let endorsement_policy = Policy::read(r)?;
        let lockout_policy = Policy::read(r)?;
        let (ph_proof, sh_proof, eh_proof) = (
            crate::state::read_seed(r)?,
            crate::state::read_seed(r)?,
            crate::state::read_seed(r)?,
        );
        Ok(Hierarchies {
            owner_auth,
            endorsement_auth,
            lockout_auth,
            owner_policy,
            endorsement_policy,
            lockout_policy,
            ph_proof,
            sh_proof,
            eh_proof,
            disable_clear: crate::state::read_bool(r)?,
        })
    }
}

/// What TPM2_Startup(CLEAR) resets and TPM2_Shutdown(STATE) saves (STATE_CLEAR_DATA): which
/// hierarchies are enabled, and the platform authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClearState {
    pub sh_enable: bool,
    pub eh_enable: bool,
    pub ph_enable_nv: bool,
    pub platform_auth: Auth,
    pub platform_policy: Policy,
}

impl Default for ClearState {
    fn default() -> ClearState {
        ClearState {
            sh_enable: true,
            eh_enable: true,
            ph_enable_nv: true,
            platform_auth: Auth::default(),
            platform_policy: Policy::default(),
        }
    }
}

impl ClearState {
    pub fn write(&self, w: &mut Writer) {
        w.u8(self.sh_enable.into())
            .u8(self.eh_enable.into())
            .u8(self.ph_enable_nv.into())
            .tpm2b(&self.platform_auth);
        self.platform_policy.write(w);
    }

    pub fn read(r: &mut Reader) -> std::result::Result<ClearState, StateError> {
        use crate::state::read_bool;
        Ok(ClearState {
            sh_enable: read_bool(r)?,
            eh_enable: read_bool(r)?,
            ph_enable_nv: read_bool(r)?,
            platform_auth: Zeroizing::new(r.tpm2b(MAX_DIGEST)?.to_vec()),
            platform_policy: Policy::read(r)?,
        })
    }
}

/// The dictionary-attack parameters and state (TPM2_DictionaryAttackParameters).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DictionaryAttack {
    pub max_tries: u32,
    /// Seconds for one failure to be forgotten; 0 turns the protection off.
    pub recovery_time: u32,
    /// Seconds before lockoutAuth may be tried again after it failed; 0: not until the next
    /// TPM2_Startup.
    pub lockout_recovery: u32,
    pub failed_tries: u32,
    /// lockoutAuth may be used: it did not just fail.
    pub lockout_auth_enabled: bool,
}

impl Default for DictionaryAttack {
    /// The reference implementation's (and libtpms') defaults.
    fn default() -> DictionaryAttack {
        DictionaryAttack {
            max_tries: 3,
            recovery_time: 1000,
            lockout_recovery: 1000,
            failed_tries: 0,
            lockout_auth_enabled: true,
        }
    }
}

impl DictionaryAttack {
    pub fn write(&self, w: &mut Writer) {
        w.u32(self.max_tries)
            .u32(self.recovery_time)
            .u32(self.lockout_recovery)
            .u32(self.failed_tries)
            .u8(self.lockout_auth_enabled.into());
    }

    pub fn read(r: &mut Reader) -> std::result::Result<DictionaryAttack, StateError> {
        Ok(DictionaryAttack {
            max_tries: r.u32()?,
            recovery_time: r.u32()?,
            lockout_recovery: r.u32()?,
            failed_tries: r.u32()?,
            lockout_auth_enabled: crate::state::read_bool(r)?,
        })
    }

    /// TPMA_PERMANENT.inLockout: no DA-protected entity may be authorized with its authValue.
    pub fn in_lockout(&self) -> bool {
        self.failed_tries >= self.max_tries
    }
}

/// The volatile side of the dictionary-attack protection: when the last failures happened, in
/// TPM time (milliseconds), so they can be forgotten as time passes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DaTimers {
    pub self_heal: i64,
    pub lockout: i64,
}

impl Tpm {
    /// DAStartup, the dictionary-attack part of TPM2_Startup. `orderly`: the previous shutdown
    /// was; `time_reset`: TPM time restarted from zero since the last Startup.
    pub fn da_startup(&mut self, orderly: bool, time_reset: bool, da_used: bool) {
        // The timers keep counting across an orderly power cycle (ACCUMULATE_SELF_HEAL_TIMER).
        if time_reset {
            let timers = &mut self.volatile.da_timers;
            if orderly {
                let before = i64::try_from(self.permanent.shutdown_time).unwrap_or(i64::MAX);
                timers.self_heal = timers.self_heal.saturating_sub(before);
                timers.lockout = timers.lockout.saturating_sub(before);
            } else {
                *timers = DaTimers::default();
            }
        }
        let da = &mut self.permanent.dictionary_attack;
        if da.lockout_recovery == 0 {
            da.lockout_auth_enabled = true;
        }
        // A DA-protected authorization may have failed without being recorded before the power
        // was lost: count it.
        if da.recovery_time != 0 && da.failed_tries < da.max_tries && !orderly && da_used {
            da.failed_tries = da.failed_tries.saturating_add(1);
        }
        self.da_self_heal();
    }

    /// DASelfHeal: forget one failure per recoveryTime elapsed, and re-enable lockoutAuth once
    /// lockoutRecovery has.
    pub fn da_self_heal(&mut self) {
        let now = i64::try_from(self.volatile.time).unwrap_or(i64::MAX);
        let da = &mut self.permanent.dictionary_attack;
        let timers = &mut self.volatile.da_timers;
        if da.failed_tries != 0 {
            if da.recovery_time == 0 {
                da.failed_tries = 0;
            } else {
                let elapsed = now.saturating_sub(timers.self_heal) / 1000;
                let healed = elapsed
                    .checked_div(i64::from(da.recovery_time))
                    .unwrap_or(0);
                let healed = u32::try_from(healed.max(0)).unwrap_or(u32::MAX);
                da.failed_tries = da.failed_tries.saturating_sub(healed);
                timers.self_heal = timers.self_heal.saturating_add(
                    i64::from(healed)
                        .saturating_mul(i64::from(da.recovery_time))
                        .saturating_mul(1000),
                );
            }
        }
        if !da.lockout_auth_enabled
            && da.lockout_recovery != 0
            && now.saturating_sub(timers.lockout) / 1000 >= i64::from(da.lockout_recovery)
        {
            da.lockout_auth_enabled = true;
        }
    }

    /// CheckLockedOut: whether a DA-protected authValue may be tried now. `lockout`: the one
    /// tried is lockoutAuth.
    pub fn check_locked_out(&mut self, lockout: bool) -> Result<()> {
        let da = &self.permanent.dictionary_attack;
        if lockout {
            if !da.lockout_auth_enabled {
                return Err(Rc::LOCKOUT);
            }
        } else {
            if da.in_lockout() {
                return Err(Rc::LOCKOUT);
            }
            // The first DA-protected use since Startup is recorded, so that losing power before
            // an orderly shutdown counts as a failure (USE_DA_USED).
            if !self.volatile.da_used {
                self.volatile.da_used = true;
                self.permanent.shutdown = crate::state::Shutdown::DaUsed;
            }
        }
        Ok(())
    }

    /// A failed authorization of a DA-protected entity (`lockout`: lockoutAuth): count it.
    /// The permanent state changes, so the VMM stores it before the guest sees the failure.
    pub fn da_failure(&mut self, lockout: bool) {
        let now = i64::try_from(self.volatile.time).unwrap_or(i64::MAX);
        let da = &mut self.permanent.dictionary_attack;
        if lockout {
            da.lockout_auth_enabled = false;
            self.volatile.da_timers.lockout = now;
        } else {
            if da.recovery_time != 0 {
                da.failed_tries = da.failed_tries.saturating_add(1);
            }
            self.volatile.da_timers.self_heal = now;
        }
    }
}

/// TPM2_HierarchyControl: enable or disable a hierarchy (or the platform's NV).
pub fn hierarchy_control(
    tpm: &mut Tpm,
    handles: &[u32],
    r: &mut Reader,
    _: &mut Out,
) -> Result<()> {
    let enable = r.u32().map_err(|rc| rc.param(1))?;
    if !matches!(
        enable,
        TPM_RH_OWNER | TPM_RH_ENDORSEMENT | TPM_RH_PLATFORM | TPM_RH_PLATFORM_NV
    ) {
        return Err(Rc::VALUE.param(1));
    }
    let state = read_yes_no(r).map_err(|rc| rc.param(2))?;
    end(r)?;
    let auth = first(handles)?;
    let clear = &tpm.volatile.clear;
    let allowed = match enable {
        TPM_RH_OWNER => {
            auth == TPM_RH_PLATFORM || (auth == TPM_RH_OWNER && (clear.sh_enable || !state))
        }
        TPM_RH_ENDORSEMENT => {
            auth == TPM_RH_PLATFORM || (auth == TPM_RH_ENDORSEMENT && (clear.eh_enable || !state))
        }
        _ => auth == TPM_RH_PLATFORM,
    };
    if !allowed {
        return Err(Rc::AUTH_TYPE);
    }
    let selected = match enable {
        TPM_RH_OWNER => &mut tpm.volatile.clear.sh_enable,
        TPM_RH_ENDORSEMENT => &mut tpm.volatile.clear.eh_enable,
        TPM_RH_PLATFORM => &mut tpm.volatile.ph_enable,
        _ => &mut tpm.volatile.clear.ph_enable_nv,
    };
    if *selected != state {
        *selected = state;
        tpm.clear_orderly();
    }
    Ok(())
}

/// TPM2_SetPrimaryPolicy: a hierarchy's (or lockout's) authPolicy.
pub fn set_primary_policy(
    tpm: &mut Tpm,
    handles: &[u32],
    r: &mut Reader,
    _: &mut Out,
) -> Result<()> {
    let digest = r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(1))?.to_vec();
    let hash = Hash::read_or_null(r).map_err(|rc| rc.param(2))?;
    end(r)?;
    if digest.len() != hash.map_or(0, Hash::size) {
        return Err(Rc::SIZE.param(1));
    }
    let policy = Policy { hash, digest };
    let h = &mut tpm.permanent.hierarchies;
    match first(handles)? {
        TPM_RH_OWNER => h.owner_policy = policy,
        TPM_RH_ENDORSEMENT => h.endorsement_policy = policy,
        TPM_RH_LOCKOUT => h.lockout_policy = policy,
        _ => {
            tpm.volatile.clear.platform_policy = policy;
            tpm.clear_orderly();
        }
    }
    Ok(())
}

/// TPM2_HierarchyChangeAuth: a hierarchy's (or lockout's) authValue.
pub fn hierarchy_change_auth(
    tpm: &mut Tpm,
    handles: &[u32],
    r: &mut Reader,
    _: &mut Out,
) -> Result<()> {
    let auth = Zeroizing::new(strip_zeros(r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(1))?).to_vec());
    end(r)?;
    let h = &mut tpm.permanent.hierarchies;
    match first(handles)? {
        TPM_RH_OWNER => h.owner_auth = auth,
        TPM_RH_ENDORSEMENT => h.endorsement_auth = auth,
        TPM_RH_LOCKOUT => h.lockout_auth = auth,
        _ => {
            tpm.volatile.clear.platform_auth = auth;
            tpm.clear_orderly();
        }
    }
    Ok(())
}

/// TPM2_ChangePPS: a new platform seed and proof, and no platform policy.
pub fn change_pps(tpm: &mut Tpm, _: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    end(r)?;
    tpm.permanent.pps = rng_seed()?;
    tpm.permanent.hierarchies.ph_proof = rng_seed()?;
    tpm.volatile.clear.platform_policy = Policy::default();
    tpm.clear_orderly();
    Ok(())
}

/// TPM2_ChangeEPS: a new endorsement seed and proof; the endorsement hierarchy is enabled again,
/// with no authValue or policy.
pub fn change_eps(tpm: &mut Tpm, _: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    end(r)?;
    tpm.permanent.eps = rng_seed()?;
    let h = &mut tpm.permanent.hierarchies;
    h.eh_proof = rng_seed()?;
    h.endorsement_auth = Auth::default();
    h.endorsement_policy = Policy::default();
    tpm.volatile.clear.eh_enable = true;
    tpm.clear_orderly();
    Ok(())
}

/// TPM2_Clear: a new owner: new storage seed, new owner and endorsement proofs, no owner,
/// endorsement or lockout authorization, default dictionary-attack parameters.
pub fn clear(tpm: &mut Tpm, _: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    end(r)?;
    if tpm.permanent.hierarchies.disable_clear {
        return Err(Rc::DISABLED);
    }
    tpm.permanent.sps = rng_seed()?;
    let h = &mut tpm.permanent.hierarchies;
    h.sh_proof = rng_seed()?;
    h.eh_proof = rng_seed()?;
    h.owner_auth = Auth::default();
    h.endorsement_auth = Auth::default();
    h.lockout_auth = Auth::default();
    h.owner_policy = Policy::default();
    h.endorsement_policy = Policy::default();
    h.lockout_policy = Policy::default();
    tpm.volatile.clear.sh_enable = true;
    tpm.volatile.clear.eh_enable = true;
    tpm.permanent.dictionary_attack = DictionaryAttack::default();
    // The reference implementation writes back all of its persistent data here, which drops a
    // pending TPM2_PCR_Allocate; so does this TPM, to answer the same.
    tpm.permanent.allocation = tpm.volatile.allocation.clone();
    // As if PCR 0 changed: a policy session that checked the PCRs must start again.
    tpm.volatile.pcrs.changed(0);
    tpm.clear_orderly();
    Ok(())
}

/// TPM2_ClearControl: refuse (or allow again) TPM2_Clear. Only the platform may allow it.
pub fn clear_control(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let disable = read_yes_no(r).map_err(|rc| rc.param(1))?;
    end(r)?;
    if first(handles)? == TPM_RH_LOCKOUT && !disable {
        return Err(Rc::AUTH_FAIL);
    }
    tpm.permanent.hierarchies.disable_clear = disable;
    Ok(())
}

/// TPM2_DictionaryAttackLockReset: forget every failure.
pub fn dictionary_attack_lock_reset(
    tpm: &mut Tpm,
    _: &[u32],
    r: &mut Reader,
    _: &mut Out,
) -> Result<()> {
    end(r)?;
    tpm.permanent.dictionary_attack.failed_tries = 0;
    Ok(())
}

/// TPM2_DictionaryAttackParameters. The failure count is left as it is, as the reference
/// implementation does.
pub fn dictionary_attack_parameters(
    tpm: &mut Tpm,
    _: &[u32],
    r: &mut Reader,
    _: &mut Out,
) -> Result<()> {
    let max_tries = r.u32().map_err(|rc| rc.param(1))?;
    let recovery_time = r.u32().map_err(|rc| rc.param(2))?;
    let lockout_recovery = r.u32().map_err(|rc| rc.param(3))?;
    end(r)?;
    let da = &mut tpm.permanent.dictionary_attack;
    da.max_tries = max_tries;
    da.recovery_time = recovery_time;
    da.lockout_recovery = lockout_recovery;
    Ok(())
}

fn rng_seed() -> Result<Seed> {
    new_seed().map_err(|_| Rc::FAILURE)
}
