//! The engine end to end: command bytes in, response bytes out.

use super::*;
use crate::commands::*;
use crate::entity::*;

/// A command: no sessions, or one password session with `password`.
fn command(code: u32, handles: &[u32], password: Option<&[u8]>, params: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    let tag = if password.is_some() {
        TPM_ST_SESSIONS
    } else {
        TPM_ST_NO_SESSIONS
    };
    w.u16(tag).u32(0).u32(code);
    for h in handles {
        w.u32(*h);
    }
    if let Some(password) = password {
        let mut area = Writer::new();
        area.u32(TPM_RS_PW).tpm2b(&[]).u8(0).tpm2b(password);
        let area = area.into_bytes();
        w.count(area.len()).bytes(&area);
    }
    w.bytes(params);
    let mut bytes = w.into_bytes();
    let len = bytes.len() as u32;
    bytes[2..6].copy_from_slice(&len.to_be_bytes());
    bytes
}

fn rc(response: &[u8]) -> u32 {
    u32::from_be_bytes(response[6..10].try_into().unwrap())
}

fn started() -> Tpm {
    let mut tpm = Tpm::manufacture().unwrap();
    assert_eq!(
        rc(&tpm.process(&command(TPM_CC_STARTUP, &[], None, &[0, 0]))),
        0
    );
    tpm
}

fn extend(pcr: u32, hash: u16, digest: &[u8]) -> Vec<u8> {
    let mut p = Writer::new();
    p.u32(1).u16(hash).bytes(digest);
    command(TPM_CC_PCR_EXTEND, &[pcr], Some(b""), &p.into_bytes())
}

/// PCR_Read of one PCR of the SHA-256 bank: (update counter, value).
fn read_sha256(tpm: &mut Tpm, pcr: usize) -> (u32, Vec<u8>) {
    let mut select = [0u8; 3];
    select[pcr / 8] = 1 << (pcr % 8);
    let mut p = Writer::new();
    p.u32(1).u16(alg::TPM_ALG_SHA256).u8(3).bytes(&select);
    let response = tpm.process(&command(TPM_CC_PCR_READ, &[], None, &p.into_bytes()));
    assert_eq!(rc(&response), 0);
    let counter = u32::from_be_bytes(response[10..14].try_into().unwrap());
    // Then the selection (4 + 6 bytes), the digest count (4) and the one TPM2B's size (2).
    (counter, response[30..].to_vec())
}

#[test]
fn only_startup_before_startup_and_not_after() {
    let mut tpm = Tpm::manufacture().unwrap();
    let random = command(TPM_CC_GET_RANDOM, &[], None, &[0, 8]);
    assert_eq!(rc(&tpm.process(&random)), Rc::INITIALIZE.0);
    let startup = command(TPM_CC_STARTUP, &[], None, &[0, 0]);
    assert_eq!(tpm.process(&startup), [0x80, 1, 0, 0, 0, 10, 0, 0, 0, 0]);
    assert_eq!(rc(&tpm.process(&startup)), Rc::INITIALIZE.0);
    assert_eq!(rc(&tpm.process(&random)), 0);
}

#[test]
fn malformed_headers_are_refused() {
    let mut tpm = started();
    let mut bad_tag = command(TPM_CC_GET_RANDOM, &[], None, &[0, 8]);
    bad_tag[1] = 0x18;
    assert_eq!(rc(&tpm.process(&bad_tag)), Rc::BAD_TAG.0);
    bad_tag[1] = 0xc1;
    assert_eq!(rc(&tpm.process(&bad_tag)), Rc::VALUE.0);
    let mut short = command(TPM_CC_GET_RANDOM, &[], None, &[0, 8]);
    short.pop();
    assert_eq!(rc(&tpm.process(&short)), Rc::COMMAND_SIZE.0);
    let unknown = command(0x199, &[], None, &[]);
    assert_eq!(rc(&tpm.process(&unknown)), Rc::COMMAND_CODE.0);
    assert_eq!(
        tpm.process(&[0x80]).len(),
        10,
        "even a 1-byte command gets an answer"
    );
    let huge = command(TPM_CC_GET_RANDOM, &[], None, &vec![0; MAX_COMMAND_SIZE]);
    assert_eq!(rc(&tpm.process(&huge)), Rc::COMMAND_SIZE.0);
}

/// A handle of `kind` that is present in a newly started TPM.
fn valid_handle(kind: HandleKind) -> u32 {
    match kind {
        HandleKind::Pcr(_) => 0,
        HandleKind::Hierarchy | HandleKind::HierarchyAuth | HandleKind::HierarchyPolicy => {
            TPM_RH_OWNER
        }
        HandleKind::Platform | HandleKind::Clear => TPM_RH_PLATFORM,
        HandleKind::Lockout => TPM_RH_LOCKOUT,
    }
}

#[test]
fn every_command_refuses_trailing_parameter_bytes() {
    for cmd in COMMANDS {
        let mut tpm = Tpm::manufacture().unwrap();
        if cmd.code != TPM_CC_STARTUP {
            tpm.process(&command(TPM_CC_STARTUP, &[], None, &[0, 0]));
        }
        let params: &[u8] = match cmd.code {
            TPM_CC_GET_CAPABILITY => &[0, 0, 0, 6, 0, 0, 1, 0, 0, 0, 0, 1],
            TPM_CC_GET_RANDOM | TPM_CC_STARTUP | TPM_CC_SHUTDOWN => &[0, 0],
            TPM_CC_SELF_TEST | TPM_CC_CLEAR_CONTROL => &[1],
            TPM_CC_HIERARCHY_CONTROL => &[0x40, 0, 0, 1, 1],
            TPM_CC_HIERARCHY_CHANGE_AUTH => &[0, 0],
            TPM_CC_SET_PRIMARY_POLICY => &[0, 0, 0, 0x10],
            TPM_CC_DICTIONARY_ATTACK_PARAMETERS => &[0; 12],
            TPM_CC_CHANGE_EPS | TPM_CC_CHANGE_PPS | TPM_CC_CLEAR => &[],
            TPM_CC_DICTIONARY_ATTACK_LOCK_RESET => &[],
            _ => &[0, 0, 0, 0],
        };
        let params = [params, &[0xee]].concat();
        let handles: Vec<u32> = cmd.handles.iter().map(|&k| valid_handle(k)).collect();
        let password = (cmd.auth > 0).then_some(&b""[..]);
        let response = tpm.process(&command(cmd.code, &handles, password, &params));
        assert_eq!(rc(&response), Rc::SIZE.0, "command {:#x}", cmd.code);
    }
}

#[test]
fn get_random_returns_at_most_a_digest() {
    let mut tpm = started();
    for (asked, got) in [(0u16, 0usize), (8, 8), (64, 64), (1000, 64)] {
        let r = tpm.process(&command(TPM_CC_GET_RANDOM, &[], None, &asked.to_be_bytes()));
        assert_eq!(rc(&r), 0);
        assert_eq!(r.len(), 12 + got);
        assert_eq!(usize::from(u16::from_be_bytes([r[10], r[11]])), got);
    }
}

#[test]
fn pcr_extend_needs_the_pcr_authorization() {
    let mut tpm = started();
    let digest = [7u8; 32];
    let mut p = Writer::new();
    p.u32(1).u16(alg::TPM_ALG_SHA256).bytes(&digest);
    let p = p.into_bytes();

    let none = command(TPM_CC_PCR_EXTEND, &[7], None, &p);
    assert_eq!(rc(&tpm.process(&none)), Rc::AUTH_MISSING.0);
    let wrong = command(TPM_CC_PCR_EXTEND, &[7], Some(b"x"), &p);
    assert_eq!(
        rc(&tpm.process(&wrong)),
        0x9a2,
        "TPM_RC_BAD_AUTH, session 1"
    );
    // Trailing zeros of a password do not count.
    let zeros = command(TPM_CC_PCR_EXTEND, &[7], Some(&[0, 0]), &p);
    let response = tpm.process(&zeros);
    // Sessions tag, size, success, parameterSize 0, then nonce 0, continueSession, hmac 0.
    assert_eq!(
        response,
        [0x80, 2, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0]
    );
    let (counter, value) = read_sha256(&mut tpm, 7);
    assert_eq!(counter, 21);
    assert_eq!(value, alg::Hash::Sha256.digest(&[&[0; 32], &digest]));
}

#[test]
fn pcr_extend_checks_handle_locality_and_digests() {
    let mut tpm = started();
    assert_eq!(
        rc(&tpm.process(&extend(24, alg::TPM_ALG_SHA256, &[0; 32]))),
        0x184
    );
    assert_eq!(
        rc(&tpm.process(&extend(17, alg::TPM_ALG_SHA256, &[0; 32]))),
        Rc::LOCALITY.0
    );
    assert_eq!(
        rc(&tpm.process(&extend(TPM_RH_NULL, alg::TPM_ALG_SHA256, &[0; 32]))),
        0
    );
    assert_eq!(
        rc(&tpm.process(&extend(7, 0x0010, &[0; 32]))),
        0x1c3,
        "TPM_RC_HASH, param 1"
    );
    assert_eq!(
        rc(&tpm.process(&extend(7, alg::TPM_ALG_SHA256, &[0; 20]))),
        0x1da
    );
    assert_eq!(
        read_sha256(&mut tpm, 7),
        (20, vec![0; 32]),
        "nothing was extended"
    );
}

#[test]
fn sessions_are_checked_before_the_command_runs() {
    let mut tpm = started();
    // A password session where no handle needs one.
    let r = tpm.process(&command(TPM_CC_GET_RANDOM, &[], Some(b""), &[0, 8]));
    assert_eq!(rc(&r), 0x98b, "TPM_RC_HANDLE, session 1");
    // TPM2_Startup takes no sessions at all.
    let mut fresh = Tpm::manufacture().unwrap();
    let r = fresh.process(&command(TPM_CC_STARTUP, &[], Some(b""), &[0, 0]));
    assert_eq!(rc(&r), Rc::AUTH_CONTEXT.0);
    // An HMAC session that was never started.
    let mut c = extend(7, alg::TPM_ALG_SHA256, &[0; 32]);
    c[18..22].copy_from_slice(&0x0200_0000u32.to_be_bytes());
    assert_eq!(rc(&tpm.process(&c)), Rc::REFERENCE_S0.0);
}

#[test]
fn shutdown_state_then_startup_state_resumes_the_saved_pcrs() {
    let mut tpm = started();
    tpm.process(&extend(0, alg::TPM_ALG_SHA256, &[1; 32]));
    tpm.process(&extend(23, alg::TPM_ALG_SHA256, &[1; 32]));
    let (_, pcr0) = read_sha256(&mut tpm, 0);
    assert_eq!(
        rc(&tpm.process(&command(TPM_CC_SHUTDOWN, &[], None, &[0, 1]))),
        0
    );
    assert!(tpm.take_permanent_changed());

    let mut resumed = Tpm::power_on(&tpm.permanent_state()).unwrap();
    assert_eq!(
        rc(&resumed.process(&command(TPM_CC_STARTUP, &[], None, &[0, 1]))),
        0
    );
    assert_eq!(read_sha256(&mut resumed, 0), (21 + 4, pcr0));
    assert_eq!(read_sha256(&mut resumed, 23).1, vec![0; 32]);

    // Without an orderly Shutdown(STATE) since, there is nothing to resume.
    let mut again = Tpm::power_on(&resumed.permanent_state()).unwrap();
    let r = again.process(&command(TPM_CC_STARTUP, &[], None, &[0, 1]));
    assert_eq!(rc(&r), 0x1c4, "TPM_RC_VALUE, param 1");
}

#[test]
fn extending_a_saved_pcr_after_shutdown_voids_the_saved_state() {
    let mut tpm = started();
    tpm.process(&command(TPM_CC_SHUTDOWN, &[], None, &[0, 1]));
    tpm.process(&extend(0, alg::TPM_ALG_SHA256, &[1; 32]));
    let mut next = Tpm::power_on(&tpm.permanent_state()).unwrap();
    assert_eq!(
        rc(&next.process(&command(TPM_CC_STARTUP, &[], None, &[0, 1]))),
        0x1c4
    );
}

#[test]
fn a_snapshot_brings_back_the_running_tpm() {
    let mut tpm = started();
    tpm.process(&extend(4, alg::TPM_ALG_SHA256, &[2; 32]));
    let mut restored = Tpm::restore(&tpm.permanent_state(), &tpm.volatile_state()).unwrap();
    assert_eq!(read_sha256(&mut restored, 4), read_sha256(&mut tpm, 4));
    let startup = command(TPM_CC_STARTUP, &[], None, &[0, 0]);
    assert_eq!(
        rc(&restored.process(&startup)),
        Rc::INITIALIZE.0,
        "it is started"
    );
}

#[test]
fn get_capability_lists_exactly_the_implemented_commands() {
    let mut tpm = started();
    let r = tpm.process(&command(
        TPM_CC_GET_CAPABILITY,
        &[],
        None,
        &[0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 1, 0],
    ));
    assert_eq!(rc(&r), 0);
    let count = u32::from_be_bytes(r[15..19].try_into().unwrap()) as usize;
    assert_eq!(count, COMMANDS.len());
    let listed: Vec<u32> = r[19..]
        .chunks(4)
        .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
        .collect();
    assert_eq!(
        listed[0], 0x02c0_0121,
        "HierarchyControl: nv, extensive, 1 handle"
    );
    assert_eq!(
        *listed.last().unwrap(),
        0x0240_0182,
        "PCR_Extend: nv, 1 handle"
    );
}

/// TPM_PT property `property`, through TPM2_GetCapability.
fn property(tpm: &mut Tpm, property: u32) -> u32 {
    let mut p = Writer::new();
    p.u32(6).u32(property).u32(1);
    let r = tpm.process(&command(TPM_CC_GET_CAPABILITY, &[], None, &p.into_bytes()));
    assert_eq!(rc(&r), 0);
    assert_eq!(u32::from_be_bytes(r[19..23].try_into().unwrap()), property);
    u32::from_be_bytes(r[23..27].try_into().unwrap())
}

const TPM_PT_PERMANENT: u32 = 0x200;
const TPM_PT_STARTUP_CLEAR: u32 = 0x201;

fn change_auth(handle: u32, password: &[u8], new: &[u8]) -> Vec<u8> {
    let mut p = Writer::new();
    p.tpm2b(new);
    command(
        TPM_CC_HIERARCHY_CHANGE_AUTH,
        &[handle],
        Some(password),
        &p.into_bytes(),
    )
}

fn power_cycle(tpm: &Tpm, startup: u8) -> Tpm {
    let mut next = Tpm::power_on(&tpm.permanent_state()).unwrap();
    let r = next.process(&command(TPM_CC_STARTUP, &[], None, &[0, startup]));
    assert_eq!(rc(&r), 0);
    next
}

#[test]
fn hierarchy_auth_values_change_and_authorize() {
    let mut tpm = started();
    assert_eq!(property(&mut tpm, TPM_PT_PERMANENT), 1 << 10);
    assert_eq!(
        rc(&tpm.process(&change_auth(TPM_RH_OWNER, b"", b"owner\0\0"))),
        0
    );
    assert_eq!(property(&mut tpm, TPM_PT_PERMANENT), 1 << 10 | 1);
    // The owner is exempt from dictionary-attack protection: a plain TPM_RC_BAD_AUTH.
    let wrong = change_auth(TPM_RH_OWNER, b"x", b"");
    assert_eq!(rc(&tpm.process(&wrong)), Rc::BAD_AUTH.session(1).0);
    assert!(tpm.take_permanent_changed());
    assert!(!tpm.take_permanent_changed());
    tpm.process(&wrong);
    assert!(!tpm.take_permanent_changed(), "nothing counted");
    let right = change_auth(TPM_RH_OWNER, b"owner", b"");
    assert_eq!(rc(&tpm.process(&right)), 0);
    assert_eq!(property(&mut tpm, TPM_PT_PERMANENT), 1 << 10);
}

#[test]
fn a_failed_lockout_authorization_locks_lockout_out_until_recovery() {
    let mut tpm = started();
    tpm.process(&change_auth(TPM_RH_LOCKOUT, b"", b"lock"));
    let reset = |pw: &[u8]| {
        command(
            TPM_CC_DICTIONARY_ATTACK_LOCK_RESET,
            &[TPM_RH_LOCKOUT],
            Some(pw),
            &[],
        )
    };
    assert_eq!(rc(&tpm.process(&reset(b"lock"))), 0);
    tpm.take_permanent_changed();
    assert_eq!(
        rc(&tpm.process(&reset(b"nope"))),
        Rc::AUTH_FAIL.session(1).0
    );
    assert!(
        tpm.take_permanent_changed(),
        "the failure is stored before the response"
    );
    assert_eq!(rc(&tpm.process(&reset(b"lock"))), Rc::LOCKOUT.0);
    // lockoutRecovery is 1000 s by default.
    tpm.clock.advance(999_000);
    assert_eq!(rc(&tpm.process(&reset(b"lock"))), Rc::LOCKOUT.0);
    tpm.clock.advance(1_000);
    assert_eq!(rc(&tpm.process(&reset(b"lock"))), 0);

    // With lockoutRecovery 0, only the next Startup lets lockout be tried again.
    let mut p = Writer::new();
    p.u32(3).u32(1000).u32(0);
    let params = command(
        TPM_CC_DICTIONARY_ATTACK_PARAMETERS,
        &[TPM_RH_LOCKOUT],
        Some(b"lock"),
        &p.into_bytes(),
    );
    assert_eq!(rc(&tpm.process(&params)), 0);
    tpm.process(&reset(b"nope"));
    tpm.clock.advance(10_000_000);
    assert_eq!(rc(&tpm.process(&reset(b"lock"))), Rc::LOCKOUT.0);
    let mut tpm = power_cycle(&tpm, 0);
    assert_eq!(rc(&tpm.process(&reset(b"lock"))), 0);
}

#[test]
fn hierarchy_control_disables_until_the_next_startup_clear() {
    let mut tpm = started();
    let control = |auth: u32, enable: u32, state: u8| {
        let mut p = Writer::new();
        p.u32(enable).u8(state);
        command(
            TPM_CC_HIERARCHY_CONTROL,
            &[auth],
            Some(b""),
            &p.into_bytes(),
        )
    };
    assert_eq!(property(&mut tpm, TPM_PT_STARTUP_CLEAR), 0x8000_000f);
    assert_eq!(rc(&tpm.process(&control(TPM_RH_OWNER, TPM_RH_OWNER, 0))), 0);
    assert_eq!(property(&mut tpm, TPM_PT_STARTUP_CLEAR), 0x8000_000d);
    // A disabled hierarchy cannot even be named, nor enable itself again.
    assert_eq!(
        rc(&tpm.process(&change_auth(TPM_RH_OWNER, b"", b""))),
        0x185
    );
    let r = tpm.process(&control(TPM_RH_ENDORSEMENT, TPM_RH_OWNER, 1));
    assert_eq!(rc(&r), Rc::AUTH_TYPE.0);
    assert_eq!(
        rc(&tpm.process(&control(TPM_RH_PLATFORM, TPM_RH_OWNER, 1))),
        0
    );
    assert_eq!(
        rc(&tpm.process(&control(TPM_RH_PLATFORM, TPM_RH_PLATFORM, 0))),
        0
    );
    assert_eq!(
        rc(&tpm.process(&control(TPM_RH_PLATFORM, TPM_RH_OWNER, 1))),
        0x185
    );

    // A resume keeps the enables (the platform's excepted); a restart resets them.
    tpm.process(&command(TPM_CC_SHUTDOWN, &[], None, &[0, 1]));
    let mut resumed = power_cycle(&tpm, 1);
    assert_eq!(property(&mut resumed, TPM_PT_STARTUP_CLEAR), 0x8000_000f);
    let mut tpm = started();
    tpm.process(&control(TPM_RH_ENDORSEMENT, TPM_RH_ENDORSEMENT, 0));
    tpm.process(&command(TPM_CC_SHUTDOWN, &[], None, &[0, 1]));
    let mut resumed = power_cycle(&tpm, 1);
    assert_eq!(property(&mut resumed, TPM_PT_STARTUP_CLEAR), 0x8000_000b);
    let mut restarted = power_cycle(&tpm, 0);
    assert_eq!(property(&mut restarted, TPM_PT_STARTUP_CLEAR), 0x8000_000f);
}

#[test]
fn platform_authorization_lasts_until_startup_clear() {
    let mut tpm = started();
    assert_eq!(
        rc(&tpm.process(&change_auth(TPM_RH_PLATFORM, b"", b"pf"))),
        0
    );
    tpm.process(&command(TPM_CC_SHUTDOWN, &[], None, &[0, 1]));
    let mut resumed = power_cycle(&tpm, 1);
    assert_eq!(
        rc(&resumed.process(&change_auth(TPM_RH_PLATFORM, b"pf", b"pf"))),
        0
    );
    let mut restarted = power_cycle(&tpm, 0);
    assert_eq!(
        rc(&restarted.process(&change_auth(TPM_RH_PLATFORM, b"", b""))),
        0
    );

    // Changing it after TPM2_Shutdown(STATE) voids the saved state.
    tpm = started();
    tpm.process(&command(TPM_CC_SHUTDOWN, &[], None, &[0, 1]));
    tpm.process(&change_auth(TPM_RH_PLATFORM, b"", b"x"));
    let mut next = Tpm::power_on(&tpm.permanent_state()).unwrap();
    let r = next.process(&command(TPM_CC_STARTUP, &[], None, &[0, 1]));
    assert_eq!(rc(&r), Rc::VALUE.param(1).0);
}

#[test]
fn clear_resets_the_owner_unless_disabled() {
    let mut tpm = started();
    tpm.process(&change_auth(TPM_RH_OWNER, b"", b"o"));
    tpm.process(&change_auth(TPM_RH_LOCKOUT, b"", b"l"));
    let sps = *tpm.permanent.sps;
    let clear = |auth: u32, pw: &[u8]| command(TPM_CC_CLEAR, &[auth], Some(pw), &[]);
    let control = |auth: u32, pw: &[u8], disable: u8| {
        command(TPM_CC_CLEAR_CONTROL, &[auth], Some(pw), &[disable])
    };
    assert_eq!(rc(&tpm.process(&control(TPM_RH_LOCKOUT, b"l", 1))), 0);
    assert_eq!(
        property(&mut tpm, TPM_PT_PERMANENT),
        1 << 10 | 1 << 8 | 0b101
    );
    assert_eq!(
        rc(&tpm.process(&clear(TPM_RH_LOCKOUT, b"l"))),
        Rc::DISABLED.0
    );
    // Only the platform may allow TPM2_Clear again.
    assert_eq!(
        rc(&tpm.process(&control(TPM_RH_LOCKOUT, b"l", 0))),
        Rc::AUTH_FAIL.0
    );
    assert_eq!(rc(&tpm.process(&control(TPM_RH_PLATFORM, b"", 0))), 0);
    assert_eq!(rc(&tpm.process(&clear(TPM_RH_LOCKOUT, b"l"))), 0);
    assert_eq!(property(&mut tpm, TPM_PT_PERMANENT), 1 << 10);
    assert_ne!(*tpm.permanent.sps, sps);
    assert_eq!(rc(&tpm.process(&change_auth(TPM_RH_OWNER, b"", b""))), 0);
}

#[test]
fn set_primary_policy_checks_the_digest_size() {
    let mut tpm = started();
    let policy = |digest: &[u8], hash: u16| {
        let mut p = Writer::new();
        p.tpm2b(digest).u16(hash);
        command(
            TPM_CC_SET_PRIMARY_POLICY,
            &[TPM_RH_OWNER],
            Some(b""),
            &p.into_bytes(),
        )
    };
    assert_eq!(
        rc(&tpm.process(&policy(&[1; 20], alg::TPM_ALG_SHA256))),
        0x1d5
    );
    assert_eq!(rc(&tpm.process(&policy(&[1; 32], alg::TPM_ALG_SHA256))), 0);
    assert!(tpm.entity_policy(TPM_RH_OWNER).is_some());
    assert_eq!(rc(&tpm.process(&policy(&[], alg::TPM_ALG_NULL))), 0);
    assert!(tpm.entity_policy(TPM_RH_OWNER).is_none());
}
