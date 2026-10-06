//! The engine end to end: command bytes in, response bytes out.

use super::*;
use crate::commands::*;
use crate::entity::*;

/// A command: no sessions, or one password session with `password`.
fn command(code: u32, handles: &[u32], password: Option<&[u8]>, params: &[u8]) -> Vec<u8> {
    let passwords: Vec<&[u8]> = password.into_iter().collect();
    command_with(code, handles, &passwords, params)
}

/// A command with one password session per password.
fn command_with(code: u32, handles: &[u32], passwords: &[&[u8]], params: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    let tag = if passwords.is_empty() {
        TPM_ST_NO_SESSIONS
    } else {
        TPM_ST_SESSIONS
    };
    w.u16(tag).u32(0).u32(code);
    for h in handles {
        w.u32(*h);
    }
    if !passwords.is_empty() {
        let mut area = Writer::new();
        for password in passwords {
            area.u32(TPM_RS_PW).tpm2b(&[]).u8(0).tpm2b(password);
        }
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
        HandleKind::Hierarchy
        | HandleKind::HierarchyOrNull
        | HandleKind::HierarchyAuth
        | HandleKind::HierarchyPolicy
        | HandleKind::Provision => TPM_RH_OWNER,
        HandleKind::Context => 0x8000_0000,
        HandleKind::Platform | HandleKind::Clear => TPM_RH_PLATFORM,
        HandleKind::Lockout => TPM_RH_LOCKOUT,
        // The sequence the test starts first.
        HandleKind::Object(_) => 0x8000_0000,
        HandleKind::Entity(_) => TPM_RH_NULL,
    }
}

#[test]
fn every_command_refuses_trailing_parameter_bytes() {
    for cmd in COMMANDS {
        let mut tpm = Tpm::manufacture().unwrap();
        if cmd.code != TPM_CC_STARTUP {
            tpm.process(&command(TPM_CC_STARTUP, &[], None, &[0, 0]));
        }
        let start_auth_session = [&[0, 16][..], &[0; 16], &[0, 0, 0, 0, 0x10, 0, 0x0b]].concat();
        // A keyed-hash public area, and the parameters that carry one.
        let public: &[u8] = &[0, 14, 0, 8, 0, 0x0b, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0];
        let create = [&[0, 4, 0, 0, 0, 0][..], public, &[0, 0, 0, 0, 0, 0]].concat();
        let load = [&[0, 0][..], public].concat();
        let load_external = [&[0, 0][..], public, &[0x40, 0, 0, 7]].concat();
        let context = [&[0; 8][..], &[0x80, 0, 0, 0, 0x40, 0, 0, 7, 0, 0]].concat();
        // digest, an HMAC signature.
        let verify_signature = [&[0, 0, 0, 5, 0, 0x0b][..], &[0; 32]].concat();
        let params: &[u8] = match cmd.code {
            TPM_CC_EVICT_CONTROL => &[0x81, 0, 0, 1],
            TPM_CC_CREATE_PRIMARY | TPM_CC_CREATE => &create,
            TPM_CC_LOAD => &load,
            TPM_CC_LOAD_EXTERNAL => &load_external,
            TPM_CC_READ_PUBLIC
            | TPM_CC_UNSEAL
            | TPM_CC_CONTEXT_SAVE
            | TPM_CC_ECDH_KEYGEN
            | TPM_CC_GET_TEST_RESULT
            | TPM_CC_READ_CLOCK => &[],
            TPM_CC_OBJECT_CHANGE_AUTH | TPM_CC_STIR_RANDOM => &[0, 0],
            TPM_CC_CONTEXT_LOAD => &context,
            TPM_CC_SIGN => &[0, 0, 0, 0x10, 0x80, 0x24, 0x40, 0, 0, 7, 0, 0],
            TPM_CC_VERIFY_SIGNATURE => &verify_signature,
            TPM_CC_RSA_ENCRYPT | TPM_CC_RSA_DECRYPT => &[0, 0, 0, 0x10, 0, 0],
            TPM_CC_ECDH_ZGEN => &[0, 4, 0, 0, 0, 0],
            TPM_CC_HMAC | TPM_CC_HMAC_START => &[0, 0, 0, 0x10],
            TPM_CC_ECC_PARAMETERS => &[0, 3],
            TPM_CC_TEST_PARMS => &[0, 8, 0, 0x10],
            TPM_CC_GET_CAPABILITY => &[0, 0, 0, 6, 0, 0, 1, 0, 0, 0, 0, 1],
            TPM_CC_GET_RANDOM | TPM_CC_STARTUP | TPM_CC_SHUTDOWN => &[0, 0],
            TPM_CC_SELF_TEST | TPM_CC_CLEAR_CONTROL => &[1],
            TPM_CC_HIERARCHY_CONTROL => &[0x40, 0, 0, 1, 1],
            TPM_CC_HIERARCHY_CHANGE_AUTH | TPM_CC_PCR_EVENT => &[0, 0],
            TPM_CC_PCR_RESET => &[],
            TPM_CC_SET_PRIMARY_POLICY => &[0, 0, 0, 0x10],
            TPM_CC_DICTIONARY_ATTACK_PARAMETERS => &[0; 12],
            TPM_CC_CHANGE_EPS | TPM_CC_CHANGE_PPS | TPM_CC_CLEAR => &[],
            TPM_CC_DICTIONARY_ATTACK_LOCK_RESET => &[],
            TPM_CC_HASH => &[0, 0, 0, 0x0b, 0x40, 0, 0, 7],
            TPM_CC_HASH_SEQUENCE_START => &[0, 0, 0, 0x10],
            TPM_CC_SEQUENCE_UPDATE | TPM_CC_EVENT_SEQUENCE_COMPLETE => &[0, 0],
            TPM_CC_SEQUENCE_COMPLETE => &[0, 0, 0x40, 0, 0, 7],
            TPM_CC_FLUSH_CONTEXT => &[0x80, 0, 0, 0],
            // A 16-byte nonce, no salt, HMAC, TPM_ALG_NULL, SHA-256.
            TPM_CC_START_AUTH_SESSION => &start_auth_session,
            _ => &[0, 0, 0, 0],
        };
        let params = [params, &[0xee]].concat();
        if cmd.code != TPM_CC_STARTUP {
            let start = command(TPM_CC_HASH_SEQUENCE_START, &[], None, &[0, 0, 0, 0x10]);
            assert_eq!(rc(&tpm.process(&start)), 0);
        }
        let handles: Vec<u32> = cmd.handles.iter().map(|&k| valid_handle(k)).collect();
        let passwords = vec![&b""[..]; cmd.auth];
        let response = tpm.process(&command_with(cmd.code, &handles, &passwords, &params));
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
fn malformed_commands_get_a_response_and_no_panic() {
    let read = {
        let mut p = Writer::new();
        p.u32(2).u16(alg::TPM_ALG_SHA1).u8(3).bytes(&[0xff; 3]);
        p.u16(alg::TPM_ALG_SHA256).u8(3).bytes(&[0xff; 3]);
        p.into_bytes()
    };
    let capability = |cap: u32, property: u32| {
        let mut p = Writer::new();
        p.u32(cap).u32(property).u32(1000);
        command(TPM_CC_GET_CAPABILITY, &[], None, &p.into_bytes())
    };
    let corpus = [
        command(TPM_CC_STARTUP, &[], None, &[0, 0]),
        command(TPM_CC_SELF_TEST, &[], None, &[1]),
        command(TPM_CC_GET_RANDOM, &[], None, &[0, 64]),
        capability(0, 0),
        capability(1, 0),
        capability(1, 0x4000_0000),
        capability(2, 0),
        capability(5, 0),
        capability(6, 0x100),
        capability(6, 0x200),
        capability(7, 0),
        command(TPM_CC_PCR_READ, &[], None, &read),
        extend(16, alg::TPM_ALG_SHA256, &[1; 32]),
        command(TPM_CC_SHUTDOWN, &[], None, &[0, 1]),
    ];
    let mut tpm = started();
    let mut fresh = Tpm::manufacture().unwrap();
    let mut check = |cmd: &[u8]| {
        for tpm in [&mut tpm, &mut fresh] {
            let n = tpm.process(cmd).len();
            assert!(
                (10..=MAX_COMMAND_SIZE).contains(&n),
                "{cmd:02x?}: {n} bytes"
            );
        }
    };
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for cmd in &corpus {
        for len in 0..=cmd.len() {
            check(&cmd[..len]);
        }
        for _ in 0..1000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let bit = (x % (cmd.len() as u64 * 8)) as usize;
            let mut mutated = cmd.clone();
            mutated[bit / 8] ^= 1 << (bit % 8);
            check(&mutated);
        }
    }
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
    assert_eq!(listed[0], 0x0440_0120, "EvictControl: nv, 2 handles");
    assert_eq!(
        listed[1], 0x02c0_0121,
        "HierarchyControl: nv, extensive, 1 handle"
    );
    assert_eq!(
        listed[listed.len() - 2],
        0x1000_0186,
        "HashSequenceStart: a response handle"
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

#[test]
fn pcr_event_digests_with_every_bank_and_extends() {
    let mut tpm = started();
    let r = tpm.process(&command(
        TPM_CC_PCR_EVENT,
        &[5],
        Some(b""),
        &[0, 3, b'a', b'b', b'c'],
    ));
    assert_eq!(rc(&r), 0);
    // Sessions header, parameterSize, then TPML_DIGEST_VALUES.
    let mut p = Reader::new(&r[14..]);
    assert_eq!(p.u32(), Ok(4));
    for hash in alg::Hash::ALL {
        assert_eq!(p.u16(), Ok(hash.id()));
        assert_eq!(p.bytes(hash.size()).unwrap(), hash.digest(&[b"abc"]));
    }
    let digest = alg::Hash::Sha256.digest(&[b"abc"]);
    assert_eq!(
        read_sha256(&mut tpm, 5).1,
        alg::Hash::Sha256.digest(&[&[0; 32], &digest])
    );
    let null = command(TPM_CC_PCR_EVENT, &[TPM_RH_NULL], Some(b""), &[0, 1, 0]);
    assert_eq!(rc(&tpm.process(&null)), 0);
    // One change per bank, and none for TPM_RH_NULL.
    assert_eq!(
        read_sha256(&mut tpm, 5).0,
        24,
        "TPM_RH_NULL extends nothing"
    );
}

#[test]
fn pcr_reset_needs_a_resettable_pcr() {
    let mut tpm = started();
    tpm.process(&extend(16, alg::TPM_ALG_SHA256, &[1; 32]));
    tpm.process(&extend(7, alg::TPM_ALG_SHA256, &[1; 32]));
    let reset = |pcr| command(TPM_CC_PCR_RESET, &[pcr], Some(b""), &[]);
    assert_eq!(rc(&tpm.process(&reset(7))), Rc::LOCALITY.0);
    assert_eq!(rc(&tpm.process(&reset(TPM_RH_NULL))), Rc::VALUE.handle(1).0);
    assert_eq!(rc(&tpm.process(&reset(16))), 0);
    assert_eq!(read_sha256(&mut tpm, 16).1, vec![0; 32]);
    assert_ne!(read_sha256(&mut tpm, 7).1, vec![0; 32]);
}

#[test]
fn pcr_allocate_takes_effect_at_the_next_power_on() {
    let mut tpm = started();
    let mut p = Writer::new();
    // SHA-1: nothing; SHA-256: PCR 0 and 17 only.
    p.u32(2).u16(alg::TPM_ALG_SHA1).u8(3).bytes(&[0; 3]);
    p.u16(alg::TPM_ALG_SHA256).u8(3).bytes(&[1, 0, 2]);
    let allocate = command(
        TPM_CC_PCR_ALLOCATE,
        &[TPM_RH_PLATFORM],
        Some(b""),
        &p.into_bytes(),
    );
    let r = tpm.process(&allocate);
    assert_eq!(rc(&r), 0);
    // allocationSuccess, maxPCR, sizeNeeded (2 SHA-256 + 24 SHA-384 + 24 SHA-512), sizeAvailable.
    assert_eq!(r[14], 1);
    assert_eq!(u32::from_be_bytes(r[15..19].try_into().unwrap()), 24);
    assert_eq!(
        u32::from_be_bytes(r[19..23].try_into().unwrap()),
        2 * 32 + 24 * 112
    );
    // Still the old allocation, and no saved state until a TPM Reset.
    assert_eq!(read_sha256(&mut tpm, 7).1, vec![0; 32]);
    let state = command(TPM_CC_SHUTDOWN, &[], None, &[0, 1]);
    assert_eq!(rc(&tpm.process(&state)), Rc::TYPE.param(1).0);
    let mut tpm = power_cycle(&tpm, 0);
    let mut p = Writer::new();
    p.u32(1).u16(alg::TPM_ALG_SHA256).u8(3).bytes(&[0x81, 0, 2]);
    let r = tpm.process(&command(TPM_CC_PCR_READ, &[], None, &p.into_bytes()));
    // The selection comes back trimmed to the allocated PCRs.
    assert_eq!(r[20..24], [3, 1, 0, 2]);

    // Without PCR 0 or 17 in some bank, it is refused.
    let mut p = Writer::new();
    p.u32(4);
    for hash in alg::Hash::ALL {
        p.u16(hash.id()).u8(3).bytes(&[0, 0, 2]);
    }
    let refused = command(
        TPM_CC_PCR_ALLOCATE,
        &[TPM_RH_PLATFORM],
        Some(b""),
        &p.into_bytes(),
    );
    assert_eq!(rc(&tpm.process(&refused)), Rc::PCR.0);
}

fn tpm2b(data: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.tpm2b(data);
    w.into_bytes()
}

#[test]
fn hash_tickets_are_hmacs_with_the_hierarchy_proof() {
    let mut tpm = started();
    let mut p = Writer::new();
    p.tpm2b(b"abc")
        .u16(alg::TPM_ALG_SHA256)
        .u32(TPM_RH_ENDORSEMENT);
    let r = tpm.process(&command(TPM_CC_HASH, &[], None, &p.into_bytes()));
    assert_eq!(rc(&r), 0);
    let digest = alg::Hash::Sha256.digest(&[b"abc"]);
    assert_eq!(r[10..12], [0, 32]);
    assert_eq!(r[12..44], digest[..]);
    // TPMT_TK_HASHCHECK: tag, hierarchy, HMAC-SHA512(ehProof, tag ‖ hashAlg ‖ digest).
    assert_eq!(r[44..50], [0x80, 0x24, 0x40, 0, 0, 0x0b]);
    let proof = tpm.permanent.hierarchies.eh_proof.as_slice();
    let ticket = crypt::hmac(
        alg::Hash::Sha512,
        proof,
        &[&[0x80, 0x24], &[0, 0x0b], &digest],
    );
    assert_eq!(r[50..52], [0, 64]);
    assert_eq!(r[52..], ticket[..]);

    // No ticket for data that starts like a structure the TPM signs.
    let mut p = Writer::new();
    p.tpm2b(b"\xffTCG...")
        .u16(alg::TPM_ALG_SHA256)
        .u32(TPM_RH_OWNER);
    let r = tpm.process(&command(TPM_CC_HASH, &[], None, &p.into_bytes()));
    assert_eq!(r[44..], [0x80, 0x24, 0x40, 0, 0, 7, 0, 0]);
}

#[test]
fn a_sequence_survives_a_snapshot_and_is_flushed_when_complete() {
    let mut tpm = started();
    let r = tpm.process(&command(
        TPM_CC_HASH_SEQUENCE_START,
        &[],
        None,
        &[0, 2, b'p', b'w', 0, 0x0c],
    ));
    assert_eq!(rc(&r), 0);
    assert_eq!(r[10..14], [0x80, 0, 0, 0]);
    let update = command(
        TPM_CC_SEQUENCE_UPDATE,
        &[0x8000_0000],
        Some(b"pw"),
        &tpm2b(&[1; 1000]),
    );
    assert_eq!(rc(&tpm.process(&update)), 0);
    let wrong = command(
        TPM_CC_SEQUENCE_UPDATE,
        &[0x8000_0000],
        Some(b"pv"),
        &tpm2b(b""),
    );
    assert_eq!(
        rc(&tpm.process(&wrong)),
        Rc::BAD_AUTH.session(1).0,
        "sequences are noDA"
    );

    let mut restored = Tpm::restore(&tpm.permanent_state(), &tpm.volatile_state()).unwrap();
    let mut p = Writer::new();
    p.tpm2b(b"end").u32(TPM_RH_NULL);
    let complete = command(
        TPM_CC_SEQUENCE_COMPLETE,
        &[0x8000_0000],
        Some(b"pw"),
        &p.into_bytes(),
    );
    let r = restored.process(&complete);
    assert_eq!(rc(&r), 0);
    let digest = alg::Hash::Sha384.digest(&[&[1; 1000], b"end"]);
    assert_eq!(r[14..16], [0, 48]);
    assert_eq!(r[16..64], digest[..]);
    assert!(restored.loaded_objects().is_empty());
    assert_eq!(rc(&restored.process(&complete)), Rc::REFERENCE_H0.0);
}

#[test]
fn objects_take_the_free_slots() {
    let mut tpm = started();
    let start = command(TPM_CC_HASH_SEQUENCE_START, &[], None, &[0, 0, 0, 0x10]);
    for _ in 0..3 {
        assert_eq!(rc(&tpm.process(&start)), 0);
    }
    assert_eq!(rc(&tpm.process(&start)), Rc::OBJECT_MEMORY.0);
    let flush = command(TPM_CC_FLUSH_CONTEXT, &[], None, &[0x80, 0, 0, 1]);
    assert_eq!(rc(&tpm.process(&flush)), 0);
    assert_eq!(rc(&tpm.process(&flush)), Rc::HANDLE.param(1).0);
    let r = tpm.process(&start);
    assert_eq!(r[10..14], [0x80, 0, 0, 1]);
    let session = command(TPM_CC_FLUSH_CONTEXT, &[], None, &[2, 0, 0, 0]);
    assert_eq!(rc(&tpm.process(&session)), Rc::HANDLE.param(1).0);
    let bad = command(TPM_CC_FLUSH_CONTEXT, &[], None, &[0x80, 0, 0, 3]);
    assert_eq!(rc(&tpm.process(&bad)), Rc::VALUE.param(1).0);
}

#[test]
fn failures_heal_one_per_recovery_time() {
    let mut tpm = started();
    tpm.permanent.dictionary_attack.failed_tries = 3;
    assert_eq!(property(&mut tpm, TPM_PT_PERMANENT), 1 << 10 | 1 << 9);
    // recoveryTime is 1000 s by default.
    tpm.clock.advance(999_000);
    assert_eq!(property(&mut tpm, TPM_PT_PERMANENT), 1 << 10 | 1 << 9);
    tpm.clock.advance(1_001_000);
    assert_eq!(property(&mut tpm, TPM_PT_PERMANENT), 1 << 10);
    assert_eq!(tpm.permanent.dictionary_attack.failed_tries, 1);
}

#[test]
fn the_heal_timer_counts_across_an_orderly_power_cycle_only() {
    let shut_down_after_600s = |orderly: bool| {
        let mut tpm = started();
        tpm.permanent.dictionary_attack.failed_tries = 1;
        tpm.clock.advance(600_000);
        if orderly {
            tpm.process(&command(TPM_CC_SHUTDOWN, &[], None, &[0, 0]));
        }
        let mut next = power_cycle(&tpm, 0);
        next.clock.advance(400_000);
        property(&mut next, TPM_PT_PERMANENT);
        next.permanent.dictionary_attack.failed_tries
    };
    assert_eq!(shut_down_after_600s(true), 0, "600 s before, 400 s after");
    assert_eq!(shut_down_after_600s(false), 1, "only the 400 s after");
}

#[test]
fn power_lost_after_a_da_protected_use_counts_a_failure() {
    let mut tpm = started();
    // No entity is DA-protected but lockout yet, whose use is not marked: mark one directly.
    assert_eq!(tpm.check_locked_out(false), Ok(()), "no TPM_RC_RETRY");
    assert_eq!(tpm.permanent.shutdown, Shutdown::DaUsed);
    let lost = power_cycle(&tpm, 0);
    assert_eq!(lost.permanent.dictionary_attack.failed_tries, 1);
    assert_eq!(lost.permanent.shutdown, Shutdown::None, "counted once");

    tpm.process(&command(TPM_CC_SHUTDOWN, &[], None, &[0, 0]));
    let orderly = power_cycle(&tpm, 0);
    assert_eq!(orderly.permanent.dictionary_attack.failed_tries, 0);
}

#[test]
fn change_eps_and_pps_replace_the_seed_and_proof() {
    let mut tpm = started();
    tpm.process(&change_auth(TPM_RH_ENDORSEMENT, b"", b"e"));
    let (eps, eh_proof) = (*tpm.permanent.eps, *tpm.permanent.hierarchies.eh_proof);
    let (pps, ph_proof) = (*tpm.permanent.pps, *tpm.permanent.hierarchies.ph_proof);
    let change = |code| command(code, &[TPM_RH_PLATFORM], Some(b""), &[]);
    assert_eq!(rc(&tpm.process(&change(TPM_CC_CHANGE_EPS))), 0);
    assert_ne!(*tpm.permanent.eps, eps);
    assert_ne!(*tpm.permanent.hierarchies.eh_proof, eh_proof);
    assert_eq!(*tpm.permanent.pps, pps);
    assert_eq!(
        rc(&tpm.process(&change_auth(TPM_RH_ENDORSEMENT, b"", b""))),
        0,
        "the endorsement authValue is gone"
    );
    assert_eq!(rc(&tpm.process(&change(TPM_CC_CHANGE_PPS))), 0);
    assert_ne!(*tpm.permanent.pps, pps);
    assert_ne!(*tpm.permanent.hierarchies.ph_proof, ph_proof);
}

#[test]
fn an_event_sequence_digests_with_every_bank_and_extends() {
    let mut tpm = started();
    let mut start = |hash: u16| {
        let mut p = Writer::new();
        p.tpm2b(b"").u16(hash);
        let r = tpm.process(&command(
            TPM_CC_HASH_SEQUENCE_START,
            &[],
            None,
            &p.into_bytes(),
        ));
        assert_eq!(rc(&r), 0);
        u32::from_be_bytes(r[10..14].try_into().unwrap())
    };
    let event = start(alg::TPM_ALG_NULL);
    let hash = start(alg::TPM_ALG_SHA256);
    let event_complete = |pcr: u32, sequence: u32| {
        command_with(
            TPM_CC_EVENT_SEQUENCE_COMPLETE,
            &[pcr, sequence],
            &[b"", b""],
            &tpm2b(b"abc"),
        )
    };
    let mut p = Writer::new();
    p.tpm2b(b"").u32(TPM_RH_NULL);
    let complete = command(
        TPM_CC_SEQUENCE_COMPLETE,
        &[event],
        Some(b""),
        &p.into_bytes(),
    );
    assert_eq!(rc(&tpm.process(&complete)), Rc::MODE.handle(1).0);
    let r = tpm.process(&event_complete(5, hash));
    assert_eq!(rc(&r), Rc::MODE.handle(2).0);

    let r = tpm.process(&event_complete(5, event));
    assert_eq!(rc(&r), 0);
    let mut p = Reader::new(&r[14..]);
    assert_eq!(p.u32(), Ok(4));
    for hash in alg::Hash::ALL {
        assert_eq!(p.u16(), Ok(hash.id()));
        assert_eq!(p.bytes(hash.size()).unwrap(), hash.digest(&[b"abc"]));
    }
    let digest = alg::Hash::Sha256.digest(&[b"abc"]);
    assert_eq!(
        read_sha256(&mut tpm, 5).1,
        alg::Hash::Sha256.digest(&[&[0; 32], &digest])
    );
    assert_eq!(
        tpm.loaded_objects(),
        [hash],
        "the event sequence is flushed"
    );
}

#[test]
fn a_hash_sequence_starting_like_a_signed_structure_gets_no_ticket() {
    let mut tpm = started();
    let sequence_ticket = |tpm: &mut Tpm, first: &[u8]| {
        let start = command(TPM_CC_HASH_SEQUENCE_START, &[], None, &[0, 0, 0, 0x0b]);
        let r = tpm.process(&start);
        let handle = u32::from_be_bytes(r[10..14].try_into().unwrap());
        let update = command(TPM_CC_SEQUENCE_UPDATE, &[handle], Some(b""), &tpm2b(first));
        assert_eq!(rc(&tpm.process(&update)), 0);
        let mut p = Writer::new();
        p.tpm2b(b"rest").u32(TPM_RH_OWNER);
        let complete = command(
            TPM_CC_SEQUENCE_COMPLETE,
            &[handle],
            Some(b""),
            &p.into_bytes(),
        );
        let r = tpm.process(&complete);
        assert_eq!(rc(&r), 0);
        // parameterSize, the digest (2 + 32), then the ticket's tag and hierarchy.
        u32::from_be_bytes(r[50..54].try_into().unwrap())
    };
    assert_eq!(sequence_ticket(&mut tpm, b"\xffTCG"), TPM_RH_NULL);
    assert_eq!(
        sequence_ticket(&mut tpm, b"\xffTC"),
        TPM_RH_NULL,
        "too short to tell"
    );
    assert_eq!(sequence_ticket(&mut tpm, b"data"), TPM_RH_OWNER);
}

/// TPM2_StartAuthSession: an HMAC session (SHA-256, `symmetric`) bound to `bind`, with a
/// nonceCaller of 16 bytes of `n`. Returns its handle and nonceTPM.
fn start_session(tpm: &mut Tpm, bind: u32, symmetric: &[u8], n: u8) -> (u32, Vec<u8>) {
    let mut p = Writer::new();
    p.tpm2b(&[n; 16])
        .tpm2b(&[])
        .u8(0)
        .bytes(symmetric)
        .u16(alg::TPM_ALG_SHA256);
    let r = tpm.process(&command(
        TPM_CC_START_AUTH_SESSION,
        &[TPM_RH_NULL, bind],
        None,
        &p.into_bytes(),
    ));
    assert_eq!(rc(&r), 0);
    let handle = u32::from_be_bytes(r[10..14].try_into().unwrap());
    assert_eq!(r[14..16], [0, 16], "nonceTPM is as long as nonceCaller");
    (handle, r[16..32].to_vec())
}

// Client for HMAC, policy and trial sessions. It computes every hash, HMAC, KDFa and cipher
// directly with RustCrypto, independently of `crypt.rs`, to check the engine against Part 1.

// TPMA_SESSION bits.
const CONTINUE: u8 = 0x01;
const AUDIT_EXCLUSIVE: u8 = 0x02;
const AUDIT_RESET: u8 = 0x04;
const DECRYPT: u8 = 0x20;
const ENCRYPT: u8 = 0x40;
const AUDIT: u8 = 0x80;

// TPM_SE.
const HMAC: u8 = 0;
const POLICY: u8 = 1;
const TRIAL: u8 = 3;

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().to_vec()
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    use hmac::{KeyInit, Mac};
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().to_vec()
}

/// KDFa with SHA-256: HMAC(key, counter ‖ label ‖ 0 ‖ contextU ‖ contextV ‖ bits) blocks.
fn kdfa_sha256(key: &[u8], label: &[u8], u: &[u8], v: &[u8], bytes: usize) -> Vec<u8> {
    let bits = (bytes as u32 * 8).to_be_bytes();
    let mut out = Vec::new();
    for counter in 1u32..=(bytes as u32).div_ceil(32) {
        out.extend(hmac_sha256(
            key,
            &[&counter.to_be_bytes(), label, &[0], u, v, &bits],
        ));
    }
    out.truncate(bytes);
    out
}

/// The parameter encryption of a session.
#[derive(Clone, Copy)]
enum Cipher {
    None,
    Xor,
    Aes128,
}

impl Cipher {
    /// Its TPMT_SYM_DEF, as TPM2_StartAuthSession takes it.
    fn definition(self) -> Vec<u8> {
        match self {
            Cipher::None => vec![0, 0x10],
            Cipher::Xor => vec![0, 0x0a, 0, 0x0b],
            Cipher::Aes128 => vec![0, 0x06, 0, 128, 0, 0x43],
        }
    }

    /// Encrypt or decrypt `data` in place, keyed by `key` and the nonces, newer first.
    fn apply(self, key: &[u8], newer: &[u8], older: &[u8], data: &mut [u8], encrypt: bool) {
        use cfb_mode::cipher::KeyIvInit;
        match self {
            Cipher::None => panic!("no parameter encryption"),
            Cipher::Xor => {
                let mask = kdfa_sha256(key, b"XOR", newer, older, data.len());
                data.iter_mut().zip(mask).for_each(|(d, m)| *d ^= m);
            }
            Cipher::Aes128 => {
                let stream = kdfa_sha256(key, b"CFB", newer, older, 32);
                let (key, iv) = stream.split_at(16);
                if encrypt {
                    cfb_mode::Encryptor::<aes::Aes128>::new_from_slices(key, iv)
                        .unwrap()
                        .encrypt(data);
                } else {
                    cfb_mode::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
                        .unwrap()
                        .decrypt(data);
                }
            }
        }
    }
}

/// A caller's side of an unsalted SHA-256 session.
struct Client {
    handle: u32,
    key: Vec<u8>,
    nonce_caller: Vec<u8>,
    nonce_tpm: Vec<u8>,
    cipher: Cipher,
}

impl Client {
    /// TPM2_StartAuthSession of a `kind` session bound to `bind`, whose authValue is
    /// `bind_auth`.
    fn start(tpm: &mut Tpm, kind: u8, bind: u32, bind_auth: &[u8], cipher: Cipher) -> Client {
        let nonce_caller = vec![0x11; 16];
        let mut p = Writer::new();
        p.tpm2b(&nonce_caller)
            .tpm2b(&[])
            .u8(kind)
            .bytes(&cipher.definition())
            .u16(alg::TPM_ALG_SHA256);
        let r = tpm.process(&command(
            TPM_CC_START_AUTH_SESSION,
            &[TPM_RH_NULL, bind],
            None,
            &p.into_bytes(),
        ));
        assert_eq!(rc(&r), 0);
        let handle = u32::from_be_bytes(r[10..14].try_into().unwrap());
        let nonce_tpm = r[16..].to_vec();
        assert_eq!(r[14..16], [0, 16], "nonceTPM is as long as nonceCaller");
        let key = if bind == TPM_RH_NULL {
            Vec::new()
        } else {
            kdfa_sha256(bind_auth, b"ATH", &nonce_tpm, &nonce_caller, 32)
        };
        Client {
            handle,
            key,
            nonce_caller,
            nonce_tpm,
            cipher,
        }
    }
}

/// A session as one command uses it.
struct Turn<'a> {
    client: &'a mut Client,
    attributes: u8,
    /// The authValue of the entity the session authorizes, if it authorizes one: it keys the
    /// parameter encryption, and the HMAC unless `in_hmac` is false.
    auth: Option<&'a [u8]>,
    /// False for a session bound to the entity (its authValue is in the session key already)
    /// and for a policy session.
    in_hmac: bool,
}

impl<'a> Turn<'a> {
    /// The session authorizes an entity whose authValue is `auth`.
    fn authorizing(client: &'a mut Client, attributes: u8, auth: &'a [u8]) -> Turn<'a> {
        Turn {
            client,
            attributes,
            auth: Some(auth),
            in_hmac: true,
        }
    }

    /// The session authorizes the entity it is bound to, or is a policy session.
    fn bound(client: &'a mut Client, attributes: u8, auth: &'a [u8]) -> Turn<'a> {
        Turn {
            in_hmac: false,
            ..Turn::authorizing(client, attributes, auth)
        }
    }

    /// The session authorizes nothing: it only encrypts, decrypts or audits.
    fn alone(client: &'a mut Client, attributes: u8) -> Turn<'a> {
        Turn {
            client,
            attributes,
            auth: None,
            in_hmac: false,
        }
    }

    fn hmac_key(&self) -> Vec<u8> {
        let auth = self.auth.filter(|_| self.in_hmac).unwrap_or_default();
        [&self.client.key[..], auth].concat()
    }

    fn crypt_key(&self) -> Vec<u8> {
        [&self.client.key[..], self.auth.unwrap_or_default()].concat()
    }

    /// The session's HMAC: empty with no key at all, as the engine takes and gives it.
    fn hmac(&self, parts: &[&[u8]]) -> Vec<u8> {
        let key = self.hmac_key();
        if key.is_empty() {
            Vec::new()
        } else {
            hmac_sha256(&key, parts)
        }
    }
}

/// The Name of a handle: the handle, but for a sequence, which has none.
fn name(handle: u32) -> Vec<u8> {
    if handle >> 24 == 0x80 {
        Vec::new()
    } else {
        handle.to_be_bytes().to_vec()
    }
}

/// A command with HMAC or policy sessions, each with a new nonceCaller. The first parameter (a
/// TPM2B) is encrypted for the session that has DECRYPT. Each HMAC covers cpHash; the first
/// session's, when it authorizes, also the nonces of the others that decrypt or encrypt,
/// unless `cover_nonces` is false.
fn session_command(
    code: u32,
    handles: &[u32],
    turns: &mut [Turn],
    params: &[u8],
    cover_nonces: bool,
) -> Vec<u8> {
    let mut params = params.to_vec();
    for t in turns.iter_mut() {
        t.client.nonce_caller.iter_mut().for_each(|b| *b += 1);
    }
    // Parameters too short for it go as they are, for the TPM to refuse.
    if let Some(t) = turns.iter().find(|t| t.attributes & DECRYPT != 0) {
        let size = usize::from(u16::from_be_bytes([params[0], params[1]]));
        let (newer, older) = (&t.client.nonce_caller, &t.client.nonce_tpm);
        if let Some(data) = params.get_mut(2..2 + size) {
            t.client
                .cipher
                .apply(&t.crypt_key(), newer, older, data, true);
        }
    }
    let names: Vec<u8> = handles.iter().flat_map(|&h| name(h)).collect();
    let cp_hash = sha256(&[&code.to_be_bytes(), &names, &params]);
    let mut extra = Vec::new();
    if cover_nonces && turns[0].auth.is_some() {
        for flag in [DECRYPT, ENCRYPT] {
            let other = turns.iter().skip(1).find(|t| t.attributes & flag != 0);
            if let Some(t) = other.filter(|t| !extra.contains(&t.client.nonce_tpm)) {
                extra.push(t.client.nonce_tpm.clone());
            }
        }
    }
    let mut area = Writer::new();
    for (i, t) in turns.iter().enumerate() {
        let c = &t.client;
        let mut parts: Vec<&[u8]> = vec![&cp_hash, &c.nonce_caller, &c.nonce_tpm];
        if i == 0 {
            parts.extend(extra.iter().map(Vec::as_slice));
        }
        parts.push(std::slice::from_ref(&t.attributes));
        area.u32(c.handle)
            .tpm2b(&c.nonce_caller)
            .u8(t.attributes)
            .tpm2b(&t.hmac(&parts));
    }
    let area = area.into_bytes();
    let mut w = Writer::new();
    w.u16(TPM_ST_SESSIONS).u32(0).u32(code);
    for &h in handles {
        w.u32(h);
    }
    w.count(area.len()).bytes(&area).bytes(&params);
    let mut bytes = w.into_bytes();
    let len = bytes.len() as u32;
    bytes[2..6].copy_from_slice(&len.to_be_bytes());
    bytes
}

/// What a successful command with sessions answered.
struct Reply {
    /// The response parameters, the first one decrypted.
    params: Vec<u8>,
    /// Each session's attributes, as the response gives them back.
    attributes: Vec<u8>,
}

/// Send a command with sessions (none with a response handle), and check each response HMAC
/// over rpHash with the session's new nonce. Returns the reply, or the response code.
fn call(
    tpm: &mut Tpm,
    code: u32,
    handles: &[u32],
    turns: &mut [Turn],
    params: &[u8],
) -> std::result::Result<Reply, u32> {
    let r = tpm.process(&session_command(code, handles, turns, params, true));
    if rc(&r) != 0 {
        return Err(rc(&r));
    }
    let mut reader = Reader::new(&r[10..]);
    let size = reader.u32().unwrap() as usize;
    let mut params = reader.bytes(size).unwrap().to_vec();
    let rp_hash = sha256(&[&[0; 4], &code.to_be_bytes(), &params]);
    let mut attributes = Vec::new();
    for t in turns.iter_mut() {
        t.client.nonce_tpm = reader.tpm2b(64).unwrap().to_vec();
        let a = reader.u8().unwrap();
        let c = &t.client;
        let expected = t.hmac(&[&rp_hash, &c.nonce_tpm, &c.nonce_caller, &[a]]);
        assert_eq!(reader.tpm2b(64).unwrap(), expected, "response HMAC");
        attributes.push(a);
    }
    assert!(reader.is_empty());
    if let Some(t) = turns.iter().find(|t| t.attributes & ENCRYPT != 0) {
        let size = usize::from(u16::from_be_bytes([params[0], params[1]]));
        let (newer, older) = (&t.client.nonce_tpm, &t.client.nonce_caller);
        let data = &mut params[2..2 + size];
        t.client
            .cipher
            .apply(&t.crypt_key(), newer, older, data, false);
    }
    Ok(Reply { params, attributes })
}

/// TPM2_Hash parameters: SHA-256 of `data`, no ticket.
fn hash_params(data: &[u8]) -> Vec<u8> {
    let mut p = Writer::new();
    p.tpm2b(data).u16(alg::TPM_ALG_SHA256).u32(TPM_RH_NULL);
    p.into_bytes()
}

#[test]
fn an_hmac_session_authorizes_and_rolls_its_nonce() {
    let mut tpm = started();
    tpm.process(&change_auth(TPM_RH_ENDORSEMENT, b"", b"e"));
    let mut s = Client::start(&mut tpm, HMAC, TPM_RH_ENDORSEMENT, b"e", Cipher::None);
    assert_eq!(s.handle, 0x0200_0000);
    for round in 0..2 {
        let nonce_tpm = s.nonce_tpm.clone();
        // Bound to the endorsement hierarchy: its authValue is in the key already.
        let turns = &mut [Turn::bound(&mut s, CONTINUE, b"e")];
        let params = tpm2b(b"e");
        let c = session_command(
            TPM_CC_HIERARCHY_CHANGE_AUTH,
            &[TPM_RH_ENDORSEMENT],
            turns,
            &params,
            true,
        );
        let r = tpm.process(&c);
        assert_eq!(rc(&r), 0, "round {round}");
        // parameterSize 0, then the new nonce, the attributes and the TPM's HMAC.
        assert_eq!(r[10..16], [0, 0, 0, 0, 0, 16]);
        let new_nonce = &r[16..32];
        assert_ne!(new_nonce, nonce_tpm);
        let code = TPM_CC_HIERARCHY_CHANGE_AUTH.to_be_bytes();
        let rp_hash = sha256(&[&[0; 4], &code]);
        let c_nonce = &turns[0].client.nonce_caller;
        let expected = hmac_sha256(&turns[0].client.key, &[&rp_hash, new_nonce, c_nonce, &[1]]);
        assert_eq!(r[33..35], [0, 32]);
        assert_eq!(r[35..], expected[..]);
        turns[0].client.nonce_tpm = new_nonce.to_vec();
        // The old nonce no longer works.
        assert_eq!(rc(&tpm.process(&c)), Rc::BAD_AUTH.session(1).0);
    }
}

#[test]
fn xor_encryption_and_hmacs_take_the_auth_value_of_an_unbound_session() {
    let mut tpm = started();
    let mut p = Writer::new();
    p.tpm2b(b"s").u16(alg::TPM_ALG_SHA256);
    let r = tpm.process(&command(
        TPM_CC_HASH_SEQUENCE_START,
        &[],
        None,
        &p.into_bytes(),
    ));
    let sequence = u32::from_be_bytes(r[10..14].try_into().unwrap());
    let mut s = Client::start(&mut tpm, HMAC, TPM_RH_NULL, b"", Cipher::Xor);
    let attributes = CONTINUE | DECRYPT | ENCRYPT;
    let mut p = Writer::new();
    p.tpm2b(b"secret data").u32(TPM_RH_NULL);
    let reply = call(
        &mut tpm,
        TPM_CC_SEQUENCE_COMPLETE,
        &[sequence],
        &mut [Turn::authorizing(&mut s, attributes, b"s")],
        &p.into_bytes(),
    )
    .unwrap();
    assert_eq!(reply.params[2..34], sha256(&[b"secret data"]));
    assert!(tpm.object(sequence).is_none(), "the sequence is complete");
    // The wrong authValue keys the wrong HMAC.
    let r = tpm.process(&command(
        TPM_CC_HASH_SEQUENCE_START,
        &[],
        None,
        &[0, 0, 0, 0x0b],
    ));
    let sequence = u32::from_be_bytes(r[10..14].try_into().unwrap());
    let turns = &mut [Turn::authorizing(&mut s, CONTINUE, b"s")];
    let complete = [&tpm2b(b"")[..], &TPM_RH_NULL.to_be_bytes()].concat();
    assert_eq!(
        call(
            &mut tpm,
            TPM_CC_SEQUENCE_COMPLETE,
            &[sequence],
            turns,
            &complete
        )
        .err(),
        Some(Rc::BAD_AUTH.session(1).0)
    );
}

#[test]
fn aes_cfb_encryption_takes_the_auth_value_even_of_the_bound_entity() {
    let mut tpm = started();
    tpm.process(&change_auth(TPM_RH_ENDORSEMENT, b"", b"e"));
    let mut s = Client::start(&mut tpm, HMAC, TPM_RH_ENDORSEMENT, b"e", Cipher::Aes128);
    let turns = &mut [Turn::bound(&mut s, CONTINUE | DECRYPT, b"e")];
    let new_auth = tpm2b(b"a new authValue");
    call(
        &mut tpm,
        TPM_CC_HIERARCHY_CHANGE_AUTH,
        &[TPM_RH_ENDORSEMENT],
        turns,
        &new_auth,
    )
    .unwrap();
    let change = change_auth(TPM_RH_ENDORSEMENT, b"a new authValue", b"");
    assert_eq!(rc(&tpm.process(&change)), 0);
    // Authorizing nothing, the session key alone; the response encrypted with the new nonce.
    let data = [7; 40];
    let turns = &mut [Turn::alone(&mut s, CONTINUE | DECRYPT | ENCRYPT)];
    let reply = call(&mut tpm, TPM_CC_HASH, &[], turns, &hash_params(&data)).unwrap();
    assert_eq!(reply.params[2..34], sha256(&[&data]));
}

#[test]
fn the_first_authorization_covers_the_nonces_of_the_sessions_that_encrypt() {
    let mut tpm = started();
    tpm.process(&change_auth(TPM_RH_ENDORSEMENT, b"", b"e"));
    let mut a = Client::start(&mut tpm, HMAC, TPM_RH_NULL, b"", Cipher::None);
    let mut b = Client::start(&mut tpm, HMAC, TPM_RH_NULL, b"", Cipher::Aes128);
    let turns = &mut [
        Turn::authorizing(&mut a, CONTINUE, b"e"),
        Turn::alone(&mut b, CONTINUE | DECRYPT),
    ];
    // The same authValue again (the response HMAC takes the new one): decrypted wrong, it
    // would be another.
    let code = TPM_CC_HIERARCHY_CHANGE_AUTH;
    let new_auth = tpm2b(b"e");
    let uncovered = session_command(code, &[TPM_RH_ENDORSEMENT], turns, &new_auth, false);
    assert_eq!(rc(&tpm.process(&uncovered)), Rc::BAD_AUTH.session(1).0);
    call(&mut tpm, code, &[TPM_RH_ENDORSEMENT], turns, &new_auth).unwrap();
    assert_eq!(
        rc(&tpm.process(&change_auth(TPM_RH_ENDORSEMENT, b"e", b""))),
        0
    );
}

#[test]
fn a_session_bound_to_lockout_fails_as_lockout() {
    let mut tpm = started();
    let mut unbound = Client::start(&mut tpm, HMAC, TPM_RH_NULL, b"", Cipher::None);
    let mut l = Client::start(&mut tpm, HMAC, TPM_RH_LOCKOUT, b"", Cipher::None);
    let code = TPM_CC_HIERARCHY_CHANGE_AUTH;
    let change_owner = |tpm: &mut Tpm, turn: Turn| {
        call(tpm, code, &[TPM_RH_OWNER], &mut [turn], &tpm2b(b"")).err()
    };
    // The owner's authorization is exempt from the dictionary-attack protection...
    let wrong = Turn::authorizing(&mut unbound, CONTINUE, b"wrong");
    assert_eq!(
        change_owner(&mut tpm, wrong),
        Some(Rc::BAD_AUTH.session(1).0)
    );
    assert!(tpm.permanent.dictionary_attack.lockout_auth_enabled);
    // ...but not through a session bound to lockout, whose key the owner's authValue extends.
    let right = Turn::authorizing(&mut l, CONTINUE, b"");
    assert_eq!(change_owner(&mut tpm, right), None);
    let wrong = Turn::authorizing(&mut l, CONTINUE, b"wrong");
    assert_eq!(
        change_owner(&mut tpm, wrong),
        Some(Rc::AUTH_FAIL.session(1).0)
    );
    assert!(!tpm.permanent.dictionary_attack.lockout_auth_enabled);
    // Lockout is now locked out, and so is the session, before its HMAC is checked.
    let right = Turn::authorizing(&mut l, CONTINUE, b"");
    assert_eq!(change_owner(&mut tpm, right), Some(Rc::LOCKOUT.0));
}

#[test]
fn a_policy_session_authorizes_when_its_digest_and_hash_match_the_policy() {
    let mut tpm = started();
    let mut p = Client::start(&mut tpm, POLICY, TPM_RH_NULL, b"", Cipher::None);
    let set_policy = |tpm: &mut Tpm, digest: &[u8], hash: u16| {
        let mut p = Writer::new();
        p.tpm2b(digest).u16(hash);
        let c = command(
            TPM_CC_SET_PRIMARY_POLICY,
            &[TPM_RH_OWNER],
            Some(b""),
            &p.into_bytes(),
        );
        assert_eq!(rc(&tpm.process(&c)), 0);
    };
    let code = TPM_CC_HIERARCHY_CHANGE_AUTH;
    let change_owner = |tpm: &mut Tpm, p: &mut Client| {
        let turns = &mut [Turn::bound(p, CONTINUE, b"")];
        call(tpm, code, &[TPM_RH_OWNER], turns, &tpm2b(b"")).err()
    };
    // No policy command yet: the session's policyDigest stays all zeros.
    set_policy(&mut tpm, &[0; 32], alg::TPM_ALG_SHA256);
    assert_eq!(change_owner(&mut tpm, &mut p), None);
    set_policy(&mut tpm, &[1; 32], alg::TPM_ALG_SHA256);
    assert_eq!(
        change_owner(&mut tpm, &mut p),
        Some(Rc::POLICY_FAIL.session(1).0)
    );
    set_policy(&mut tpm, &[0; 20], alg::TPM_ALG_SHA1);
    assert_eq!(
        change_owner(&mut tpm, &mut p),
        Some(Rc::POLICY_FAIL.session(1).0)
    );
}

#[test]
fn a_trial_session_authorizes_nothing() {
    let mut tpm = started();
    let mut t = Client::start(&mut tpm, TRIAL, TPM_RH_NULL, b"", Cipher::None);
    let turns = &mut [Turn::bound(&mut t, CONTINUE, b"")];
    let r = call(
        &mut tpm,
        TPM_CC_HIERARCHY_CHANGE_AUTH,
        &[TPM_RH_OWNER],
        turns,
        &tpm2b(b""),
    );
    assert_eq!(r.err(), Some(Rc::ATTRIBUTES.session(1).0));
}

#[test]
fn an_audit_session_digests_each_command_while_it_stays_exclusive() {
    let mut tpm = started();
    let mut s = Client::start(&mut tpm, HMAC, TPM_RH_ENDORSEMENT, b"", Cipher::None);
    let handle = s.handle;
    let code = TPM_CC_GET_RANDOM;
    // Audit GetRandom, and return the digest expected from `from` and the exclusive bit.
    let mut audit = |tpm: &mut Tpm, attributes: u8, from: &[u8]| {
        let turns = &mut [Turn::alone(&mut s, CONTINUE | AUDIT | attributes)];
        let reply = call(tpm, code, &[], turns, &[0, 8])?;
        let cp_hash = sha256(&[&code.to_be_bytes(), &[0, 8]]);
        let rp_hash = sha256(&[&[0; 4], &code.to_be_bytes(), &reply.params]);
        let exclusive = reply.attributes[0] & AUDIT_EXCLUSIVE != 0;
        Ok::<_, u32>((sha256(&[from, &cp_hash, &rp_hash]), exclusive))
    };
    let digest = |tpm: &Tpm| tpm.session(handle).unwrap().audit.clone().unwrap();

    let (expected, exclusive) = audit(&mut tpm, 0, &[0; 32]).unwrap();
    assert_eq!((digest(&tpm), exclusive), (expected.clone(), true));
    assert!(
        tpm.session(handle).unwrap().bound.is_none(),
        "unbound by its first audit"
    );
    let (expected, exclusive) = audit(&mut tpm, AUDIT_EXCLUSIVE, &expected).unwrap();
    assert_eq!((digest(&tpm), exclusive), (expected.clone(), true));
    // A command between ends the exclusivity.
    tpm.process(&command(TPM_CC_GET_RANDOM, &[], None, &[0, 8]));
    assert_eq!(
        audit(&mut tpm, AUDIT_EXCLUSIVE, &expected),
        Err(Rc::EXCLUSIVE.0)
    );
    let (expected, exclusive) = audit(&mut tpm, 0, &expected).unwrap();
    assert_eq!((digest(&tpm), exclusive), (expected, false));
    // auditReset starts the digest over, exclusive again.
    let (expected, exclusive) = audit(&mut tpm, AUDIT_RESET | AUDIT_EXCLUSIVE, &[0; 32]).unwrap();
    assert_eq!((digest(&tpm), exclusive), (expected, true));
}

#[test]
fn a_session_without_continue_session_is_flushed_after_the_command() {
    let mut tpm = started();
    let mut s = Client::start(&mut tpm, HMAC, TPM_RH_NULL, b"", Cipher::None);
    let turns = &mut [Turn::authorizing(&mut s, 0, b"")];
    let reply = call(
        &mut tpm,
        TPM_CC_HIERARCHY_CHANGE_AUTH,
        &[TPM_RH_OWNER],
        turns,
        &tpm2b(b""),
    )
    .unwrap();
    assert_eq!(reply.attributes, [0]);
    assert!(tpm.loaded_sessions(0).is_empty());
}

#[test]
fn session_attributes_must_fit_the_command_and_the_session() {
    let mut tpm = started();
    let mut plain = Client::start(&mut tpm, HMAC, TPM_RH_NULL, b"", Cipher::None);
    let mut x = Client::start(&mut tpm, HMAC, TPM_RH_NULL, b"", Cipher::Xor);
    let mut y = Client::start(&mut tpm, HMAC, TPM_RH_NULL, b"", Cipher::Aes128);
    // GetRandom has no parameter to decrypt.
    let turns = &mut [Turn::alone(&mut x, CONTINUE | DECRYPT)];
    let r = call(&mut tpm, TPM_CC_GET_RANDOM, &[], turns, &[0, 8]);
    assert_eq!(r.err(), Some(Rc::ATTRIBUTES.session(1).0));
    // One session decrypts, one audits.
    let turns = &mut [
        Turn::alone(&mut x, CONTINUE | DECRYPT),
        Turn::alone(&mut y, CONTINUE | DECRYPT),
    ];
    let r = call(&mut tpm, TPM_CC_HASH, &[], turns, &hash_params(b"data"));
    assert_eq!(r.err(), Some(Rc::ATTRIBUTES.session(2).0));
    let turns = &mut [
        Turn::alone(&mut x, CONTINUE | AUDIT),
        Turn::alone(&mut y, CONTINUE | AUDIT),
    ];
    let r = call(&mut tpm, TPM_CC_GET_RANDOM, &[], turns, &[0, 8]);
    assert_eq!(r.err(), Some(Rc::ATTRIBUTES.session(2).0));
    // A session without a symmetric algorithm encrypts nothing.
    let turns = &mut [Turn::alone(&mut plain, CONTINUE | ENCRYPT)];
    let r = call(&mut tpm, TPM_CC_GET_RANDOM, &[], turns, &[0, 8]);
    assert_eq!(r.err(), Some(Rc::SYMMETRIC.session(1).0));
    // Nor does a password session.
    let mut c = command(TPM_CC_GET_RANDOM, &[], Some(b""), &[0, 8]);
    // After the header, the area's size, the session handle and the empty nonce.
    c[10 + 4 + 4 + 2] = ENCRYPT;
    assert_eq!(rc(&tpm.process(&c)), Rc::ATTRIBUTES.session(1).0);
}

#[test]
fn sessions_fill_their_slots_and_survive_a_snapshot() {
    let mut tpm = started();
    let handles: Vec<u32> = (0..3)
        .map(|n| start_session(&mut tpm, TPM_RH_NULL, &[0, 0x0a, 0, 0x0b], n).0)
        .collect();
    assert_eq!(handles, [0x0200_0000, 0x0200_0001, 0x0200_0002]);
    let mut p = Writer::new();
    p.tpm2b(&[9; 16])
        .tpm2b(&[])
        .u8(1)
        .u16(alg::TPM_ALG_NULL)
        .u16(alg::TPM_ALG_SHA1);
    let policy = command(
        TPM_CC_START_AUTH_SESSION,
        &[TPM_RH_NULL, TPM_RH_NULL],
        None,
        &p.into_bytes(),
    );
    assert_eq!(rc(&tpm.process(&policy)), Rc::SESSION_MEMORY.0);
    tpm.process(&command(TPM_CC_FLUSH_CONTEXT, &[], None, &[2, 0, 0, 1]));
    let r = tpm.process(&policy);
    assert_eq!(
        r[10..14],
        [3, 0, 0, 1],
        "a policy session in the freed handle"
    );

    let mut restored = Tpm::restore(&tpm.permanent_state(), &tpm.volatile_state()).unwrap();
    assert_eq!(
        restored.loaded_sessions(0),
        [0x0200_0000, 0x0300_0001, 0x0200_0002]
    );
    // An unbound, unsalted session has no key: the empty HMAC authorizes an empty authValue.
    let mut area = Writer::new();
    area.u32(0x0200_0002).tpm2b(&[1; 16]).u8(1).tpm2b(&[]);
    let area = area.into_bytes();
    let mut c = Writer::new();
    c.u16(TPM_ST_SESSIONS)
        .u32(0)
        .u32(TPM_CC_HIERARCHY_CHANGE_AUTH)
        .u32(TPM_RH_OWNER);
    c.count(area.len()).bytes(&area).u16(0);
    let mut c = c.into_bytes();
    let len = c.len() as u32;
    c[2..6].copy_from_slice(&len.to_be_bytes());
    assert_eq!(rc(&restored.process(&c)), 0);
    // Startup flushes them all.
    restored.process(&command(TPM_CC_SHUTDOWN, &[], None, &[0, 0]));
    let mut next = power_cycle(&restored, 0);
    assert!(next.loaded_sessions(0).is_empty());
    assert_eq!(rc(&next.process(&c)), Rc::REFERENCE_S0.0);
}

// Objects and keys.

/// A TPMT_PUBLIC with SHA-256 as its nameAlg and no authPolicy.
fn public(kind: u16, attributes: u32, params: &[u8], unique: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(kind)
        .u16(alg::TPM_ALG_SHA256)
        .u32(attributes)
        .tpm2b(&[]);
    w.bytes(params).bytes(unique);
    w.into_bytes()
}

use crate::public::attr;

const STORAGE: u32 = attr::FIXED_TPM
    | attr::FIXED_PARENT
    | attr::SENSITIVE_DATA_ORIGIN
    | attr::USER_WITH_AUTH
    | attr::NO_DA
    | attr::RESTRICTED
    | attr::DECRYPT;

/// An ECC P-256 storage key (AES-128-CFB for its children).
fn ecc_srk() -> Vec<u8> {
    let params = [0, 6, 0, 0x80, 0, 0x43, 0, 0x10, 0, 3, 0, 0x10];
    public(0x23, STORAGE, &params, &[0, 0, 0, 0])
}

/// A sealed data object: its secret given at creation.
fn sealed(attributes: u32) -> Vec<u8> {
    public(8, attributes, &[0, 0x10], &[0, 0])
}

/// An HMAC key (SHA-256), noDA.
fn hmac_key() -> Vec<u8> {
    let attributes = attr::FIXED_TPM
        | attr::FIXED_PARENT
        | attr::SENSITIVE_DATA_ORIGIN
        | attr::USER_WITH_AUTH
        | attr::NO_DA
        | attr::SIGN;
    public(8, attributes, &[0, 5, 0, 0x0b], &[0, 0])
}

/// The parameters of TPM2_CreatePrimary and TPM2_Create.
fn create_params(auth: &[u8], data: &[u8], public: &[u8]) -> Vec<u8> {
    let mut sensitive = Writer::new();
    sensitive.tpm2b(auth).tpm2b(data);
    let mut w = Writer::new();
    w.tpm2b(&sensitive.into_bytes())
        .tpm2b(public)
        .tpm2b(&[])
        .u32(0);
    w.into_bytes()
}

/// TPM2_CreatePrimary: the response.
fn create_primary(tpm: &mut Tpm, hierarchy: u32, public: &[u8]) -> Vec<u8> {
    let p = create_params(b"", b"", public);
    tpm.process(&command(TPM_CC_CREATE_PRIMARY, &[hierarchy], Some(b""), &p))
}

fn handle_of(response: &[u8]) -> u32 {
    assert_eq!(rc(response), 0);
    u32::from_be_bytes(response[10..14].try_into().unwrap())
}

/// The first TPM2B in `bytes`, and the rest.
fn split2b(bytes: &[u8]) -> (&[u8], &[u8]) {
    let size = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
    (&bytes[2..2 + size], &bytes[2 + size..])
}

/// A response's parameters (after a handle, with `handle`), for a command with sessions.
fn response_params(r: &[u8], handle: bool) -> &[u8] {
    let at = if handle { 14 } else { 10 };
    let size = u32::from_be_bytes(r[at..at + 4].try_into().unwrap()) as usize;
    &r[at + 4..at + 4 + size]
}

fn read_public_name(tpm: &mut Tpm, handle: u32) -> Vec<u8> {
    let r = tpm.process(&command(TPM_CC_READ_PUBLIC, &[handle], None, &[]));
    assert_eq!(rc(&r), 0);
    let (_, rest) = split2b(&r[10..]);
    split2b(rest).0.to_vec()
}

fn flush(tpm: &mut Tpm, handle: u32) {
    let r = tpm.process(&command(
        TPM_CC_FLUSH_CONTEXT,
        &[],
        None,
        &handle.to_be_bytes(),
    ));
    assert_eq!(rc(&r), 0);
}

#[test]
fn a_primary_key_is_derived_again_from_its_seed() {
    let mut tpm = started();
    let srk = handle_of(&create_primary(&mut tpm, TPM_RH_OWNER, &ecc_srk()));
    let name = read_public_name(&mut tpm, srk);
    flush(&mut tpm, srk);
    let mut tpm = power_cycle(&tpm, 0);
    let again = handle_of(&create_primary(&mut tpm, TPM_RH_OWNER, &ecc_srk()));
    assert_eq!(
        read_public_name(&mut tpm, again),
        name,
        "the same key every time"
    );
    flush(&mut tpm, again);
    let other = handle_of(&create_primary(&mut tpm, TPM_RH_ENDORSEMENT, &ecc_srk()));
    assert_ne!(
        read_public_name(&mut tpm, other),
        name,
        "another hierarchy, another key"
    );
    flush(&mut tpm, other);
    // TPM2_Clear draws a new storage seed.
    let clear = command(TPM_CC_CLEAR, &[TPM_RH_LOCKOUT], Some(b""), &[]);
    assert_eq!(rc(&tpm.process(&clear)), 0);
    let after = handle_of(&create_primary(&mut tpm, TPM_RH_OWNER, &ecc_srk()));
    assert_ne!(read_public_name(&mut tpm, after), name);
}

#[test]
fn a_sealed_object_round_trips_through_its_parent() {
    let mut tpm = started();
    let srk = handle_of(&create_primary(&mut tpm, TPM_RH_OWNER, &ecc_srk()));
    let attributes = attr::FIXED_TPM | attr::FIXED_PARENT | attr::USER_WITH_AUTH;
    let p = create_params(b"pw", b"the secret", &sealed(attributes));
    let r = tpm.process(&command(TPM_CC_CREATE, &[srk], Some(b""), &p));
    assert_eq!(rc(&r), 0);
    let (private, rest) = split2b(response_params(&r, false));
    let (public, _) = split2b(rest);
    let mut load = Writer::new();
    load.tpm2b(private).tpm2b(public);
    let load = command(TPM_CC_LOAD, &[srk], Some(b""), &load.into_bytes());
    let item = handle_of(&tpm.process(&load));
    let unseal = |pw: &[u8]| command(TPM_CC_UNSEAL, &[item], Some(pw), &[]);
    let r = tpm.process(&unseal(b"pw"));
    assert_eq!(split2b(response_params(&r, false)).0, b"the secret");
    // Not noDA: a wrong authValue counts against the dictionary-attack protection.
    assert_eq!(rc(&tpm.process(&unseal(b"no"))), Rc::AUTH_FAIL.session(1).0);
    assert!(tpm.take_permanent_changed());
    // A new authValue: the object wrapped again; the old blob still has the old one.
    let change = command(
        TPM_CC_OBJECT_CHANGE_AUTH,
        &[item, srk],
        Some(b"pw"),
        &tpm2b(b"new"),
    );
    let r = tpm.process(&change);
    assert_eq!(rc(&r), 0);
    let rewrapped = split2b(response_params(&r, false)).0.to_vec();
    flush(&mut tpm, item);
    let mut load = Writer::new();
    load.tpm2b(&rewrapped).tpm2b(public);
    let load = command(TPM_CC_LOAD, &[srk], Some(b""), &load.into_bytes());
    let item = handle_of(&tpm.process(&load));
    let r = tpm.process(&command(TPM_CC_UNSEAL, &[item], Some(b"new"), &[]));
    assert_eq!(rc(&r), 0);
    // Tampered with: refused.
    let mut tampered = private.to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    let mut load = Writer::new();
    load.tpm2b(&tampered).tpm2b(public);
    let load = command(TPM_CC_LOAD, &[srk], Some(b""), &load.into_bytes());
    assert_eq!(rc(&tpm.process(&load)), Rc::INTEGRITY.param(1).0);
}

#[test]
fn hmac_signatures_verify_and_get_a_ticket() {
    let mut tpm = started();
    let key = handle_of(&create_primary(&mut tpm, TPM_RH_OWNER, &hmac_key()));
    let digest = alg::Hash::Sha256.digest(&[b"m"]);
    let mut p = Writer::new();
    p.tpm2b(&digest).u16(alg::TPM_ALG_NULL);
    p.u16(object::TPM_ST_HASHCHECK).u32(TPM_RH_NULL).tpm2b(&[]);
    let r = tpm.process(&command(TPM_CC_SIGN, &[key], Some(b""), &p.into_bytes()));
    let signature = response_params(&r, false).to_vec();
    // TPMT_SIGNATURE: HMAC, SHA-256, the HMAC.
    assert_eq!(signature[..4], [0, 5, 0, 0x0b]);
    let mut p = Writer::new();
    p.tpm2b(&digest).bytes(&signature);
    let r = tpm.process(&command(
        TPM_CC_VERIFY_SIGNATURE,
        &[key],
        None,
        &p.into_bytes(),
    ));
    assert_eq!(rc(&r), 0);
    // TPMT_TK_VERIFIED for the owner.
    assert_eq!(r[10..16], [0x80, 0x22, 0x40, 0, 0, 1]);
    let mut bad = signature.clone();
    bad[10] ^= 1;
    let mut p = Writer::new();
    p.tpm2b(&digest).bytes(&bad);
    let r = tpm.process(&command(
        TPM_CC_VERIFY_SIGNATURE,
        &[key],
        None,
        &p.into_bytes(),
    ));
    assert_eq!(rc(&r), Rc::SIGNATURE.param(2).0);
}

#[test]
fn object_contexts_last_until_a_reset() {
    let mut tpm = started();
    let srk = handle_of(&create_primary(&mut tpm, TPM_RH_OWNER, &ecc_srk()));
    let mut st_clear = ecc_srk();
    st_clear[7] |= attr::ST_CLEAR as u8;
    let volatile = handle_of(&create_primary(&mut tpm, TPM_RH_OWNER, &st_clear));
    let save = |tpm: &mut Tpm, h: u32| {
        let r = tpm.process(&command(TPM_CC_CONTEXT_SAVE, &[h], None, &[]));
        assert_eq!(rc(&r), 0);
        r[10..].to_vec()
    };
    let (srk_context, volatile_context) = (save(&mut tpm, srk), save(&mut tpm, volatile));
    assert_eq!(srk_context[..12], [0, 0, 0, 0, 0, 0, 0, 1, 0x80, 0, 0, 0]);
    assert_eq!(
        volatile_context[..12],
        [0, 0, 0, 0, 0, 0, 0, 2, 0x80, 0, 0, 2]
    );
    let name = read_public_name(&mut tpm, srk);
    flush(&mut tpm, srk);
    flush(&mut tpm, volatile);
    let load = |c: &[u8]| command(TPM_CC_CONTEXT_LOAD, &[], None, c);
    let loaded = handle_of(&tpm.process(&load(&srk_context)));
    assert_eq!(read_public_name(&mut tpm, loaded), name);
    flush(&mut tpm, loaded);
    // A snapshot keeps loaded objects and what makes contexts valid.
    let mut restored = Tpm::restore(&tpm.permanent_state(), &tpm.volatile_state()).unwrap();
    assert_eq!(rc(&restored.process(&load(&srk_context))), 0);
    // A restart: the stClear object's context no longer loads.
    tpm.process(&command(TPM_CC_SHUTDOWN, &[], None, &[0, 1]));
    let mut tpm = power_cycle(&tpm, 0);
    let loaded = handle_of(&tpm.process(&load(&srk_context)));
    flush(&mut tpm, loaded);
    let r = tpm.process(&load(&volatile_context));
    assert_eq!(rc(&r), Rc::INTEGRITY.param(1).0);
    // A reset: none.
    tpm.process(&command(TPM_CC_SHUTDOWN, &[], None, &[0, 0]));
    let mut tpm = power_cycle(&tpm, 0);
    assert_eq!(
        rc(&tpm.process(&load(&srk_context))),
        Rc::INTEGRITY.param(1).0
    );
}

#[test]
fn a_saved_session_holds_back_the_context_counter() {
    let mut tpm = started();
    let (session, _) = start_session(&mut tpm, TPM_RH_NULL, &[0, 0x10], 1);
    let r = tpm.process(&command(TPM_CC_CONTEXT_SAVE, &[session], None, &[]));
    assert_eq!(rc(&r), 0);
    let context = r[10..].to_vec();
    assert_eq!(
        context[..8],
        [0, 0, 0, 0, 0, 0, 0, 4],
        "the first sequence number"
    );
    assert_eq!(tpm.saved_sessions(0), [session]);
    // 2^16 contexts later, the oldest saved session is due: no more until it is loaded.
    tpm.volatile.context_counter += 0xffff;
    let (other, _) = start_session(&mut tpm, TPM_RH_NULL, &[0, 0x10], 2);
    let r = tpm.process(&command(TPM_CC_CONTEXT_SAVE, &[other], None, &[]));
    assert_eq!(rc(&r), Rc::CONTEXT_GAP.0);
    let load = command(TPM_CC_CONTEXT_LOAD, &[], None, &context);
    assert_eq!(handle_of(&tpm.process(&load)), session);
    assert_eq!(
        rc(&tpm.process(&load)),
        Rc::HANDLE.param(1).0,
        "loaded once"
    );
    let r = tpm.process(&command(TPM_CC_CONTEXT_SAVE, &[other], None, &[]));
    assert_eq!(rc(&r), 0);
}

#[test]
fn persistent_objects_are_kept_in_the_permanent_state() {
    let mut tpm = started();
    let srk = handle_of(&create_primary(&mut tpm, TPM_RH_OWNER, &ecc_srk()));
    let name = read_public_name(&mut tpm, srk);
    tpm.take_permanent_changed();
    let evict = |object: u32, persistent: u32| {
        command(
            TPM_CC_EVICT_CONTROL,
            &[TPM_RH_OWNER, object],
            Some(b""),
            &persistent.to_be_bytes(),
        )
    };
    assert_eq!(rc(&tpm.process(&evict(srk, 0x8100_0001))), 0);
    assert!(tpm.take_permanent_changed());
    let mut tpm = power_cycle(&tpm, 0);
    assert_eq!(read_public_name(&mut tpm, 0x8100_0001), name);
    assert!(
        tpm.loaded_objects().is_empty(),
        "its slot is freed after the command"
    );
    // A persistent parent, with every other slot taken: the command has no room for it.
    for _ in 0..3 {
        create_primary(&mut tpm, TPM_RH_OWNER, &hmac_key());
    }
    let r = tpm.process(&command(TPM_CC_READ_PUBLIC, &[0x8100_0001], None, &[]));
    assert_eq!(rc(&r), Rc::OBJECT_MEMORY.0);
    flush(&mut tpm, 0x8000_0000);
    assert_eq!(rc(&tpm.process(&evict(0x8100_0001, 0x8100_0001))), 0);
    let r = tpm.process(&command(TPM_CC_READ_PUBLIC, &[0x8100_0001], None, &[]));
    assert_eq!(rc(&r), Rc::HANDLE.handle(1).0);
}

#[test]
fn clock_goes_on_across_power_cycles() {
    let mut tpm = started();
    tpm.clock.advance(5000);
    let read = |tpm: &mut Tpm| {
        let r = tpm.process(&command(TPM_CC_READ_CLOCK, &[], None, &[]));
        assert_eq!(rc(&r), 0);
        // time, clock, resetCount, restartCount, safe
        let mut p = Reader::new(&r[10..]);
        let v = (p.u64(), p.u64(), p.u32(), p.u32(), p.u8());
        (
            v.0.unwrap(),
            v.1.unwrap(),
            v.2.unwrap(),
            v.3.unwrap(),
            v.4.unwrap(),
        )
    };
    let (time, clock, resets, restarts, safe) = read(&mut tpm);
    assert!(time >= 5000 && clock >= 5000);
    assert_eq!((resets, restarts, safe), (1, 0, 1));
    // Clock alone does not make the permanent state worth storing.
    tpm.take_permanent_changed();
    tpm.clock.advance(1);
    read(&mut tpm);
    assert!(!tpm.take_permanent_changed());
    // An orderly restart: one more restart; a power loss: one more reset, and not safe.
    tpm.process(&command(TPM_CC_SHUTDOWN, &[], None, &[0, 1]));
    let mut tpm = power_cycle(&tpm, 0);
    let (_, after, resets, restarts, safe) = read(&mut tpm);
    assert!(after >= clock);
    assert_eq!((resets, restarts, safe), (1, 1, 1));
    let mut tpm = power_cycle(&tpm, 0);
    let (_, _, resets, restarts, safe) = read(&mut tpm);
    assert_eq!((resets, restarts, safe), (2, 0, 0));
    tpm.clock.advance(1 << 12);
    assert_eq!(read(&mut tpm).4, 1, "safe again once stored");
}

/// The response's outPublic (TPM2_CreatePrimary), and its unique field: the last `unique`
/// bytes.
fn created_unique(response: &[u8], unique: usize) -> Vec<u8> {
    let (public, _) = split2b(response_params(response, true));
    public[public.len() - unique..].to_vec()
}

/// A started TPM with the seeds and proofs the differential tests gave libtpms too (tag
/// `vk-tpm-differential`): EPS, SPS, PPS, phProof, shProof, ehProof of 0x11, 0x22, ... 0x66.
fn seeded() -> Tpm {
    let mut tpm = started();
    let seed = |b: u8| crate::state::Seed::new([b; crate::state::SEED_SIZE]);
    let p = &mut tpm.permanent;
    (p.eps, p.sps, p.pps) = (seed(0x11), seed(0x22), seed(0x33));
    let h = &mut p.hierarchies;
    (h.ph_proof, h.sh_proof, h.eh_proof) = (seed(0x44), seed(0x55), seed(0x66));
    tpm
}

#[test]
fn primaries_are_the_keys_libtpms_derives_from_the_same_seeds() {
    use crate::crypt::tests::unhex;
    // Captured from libtpms (by the differential harness) with the same seeds and templates.
    let mut tpm = seeded();
    let srk = create_primary(&mut tpm, TPM_RH_OWNER, &ecc_srk());
    assert_eq!(
        created_unique(&srk, 68),
        unhex(
            "00200559420e7df88240b263c8140920c1555274fc98c9e9fb9d75e4a78b84049e35\
             00203c1c93c5afe4be521be5346c2b92ca91b5b8a9cbc7b772aa8c58c4abc38bc1b8"
        ),
        "the ECC storage key of the owner"
    );
    let hmac = create_primary(&mut tpm, TPM_RH_ENDORSEMENT, &hmac_key());
    assert_eq!(
        created_unique(&hmac, 34),
        unhex("00204e7548027a56041c80c8fd0ae197b741f1ae847f631695e29e2cfb3c597eb3a1"),
        "an HMAC key of the endorsement hierarchy (the proofs stirred in)"
    );
    // RSA primaries are vk-tpm's own (a prime search of its own): pinned so they never change.
    flush(&mut tpm, handle_of(&srk));
    flush(&mut tpm, handle_of(&hmac));
    let params = [0, 6, 0, 0x80, 0, 0x43, 0, 0x10, 0x08, 0, 0, 0, 0, 0];
    let rsa = create_primary(
        &mut tpm,
        TPM_RH_OWNER,
        &public(1, STORAGE, &params, &[0, 0]),
    );
    let modulus = created_unique(&rsa, 256);
    assert_eq!(
        alg::Hash::Sha256.digest(&[&modulus]),
        unhex("4ed4db532b6ce1d05af2d213919a8ec01c6120ec4a6a29ef30e0e55f70f0980d"),
        "the SHA-256 of the modulus"
    );
}

#[test]
fn a_context_loads_only_as_it_was_saved() {
    let mut tpm = started();
    let srk = handle_of(&create_primary(&mut tpm, TPM_RH_OWNER, &ecc_srk()));
    let r = tpm.process(&command(TPM_CC_CONTEXT_SAVE, &[srk], None, &[]));
    // TPMS_CONTEXT: sequence (8), savedHandle (4), hierarchy (4), the blob.
    let context = r[10..].to_vec();
    let mut flipped = context.clone();
    *flipped.last_mut().unwrap() ^= 1;
    let mut hierarchy = context.clone();
    hierarchy[12..16].copy_from_slice(&TPM_RH_ENDORSEMENT.to_be_bytes());
    let mut st_clear = context.clone();
    st_clear[8..12].copy_from_slice(&0x8000_0002u32.to_be_bytes());
    let load = |c: &[u8]| command(TPM_CC_CONTEXT_LOAD, &[], None, c);
    for tampered in [flipped, hierarchy, st_clear] {
        assert_eq!(rc(&tpm.process(&load(&tampered))), Rc::INTEGRITY.param(1).0);
    }
    assert_eq!(rc(&tpm.process(&load(&context))), 0);
}

/// An ECC P-256 key with these attributes and scheme (no symmetric definition).
fn ecc_key(attributes: u32, scheme: &[u8]) -> Vec<u8> {
    let params = [&[0, 0x10][..], scheme, &[0, 3, 0, 0x10]].concat();
    public(0x23, attributes, &params, &[0, 0, 0, 0])
}

const ORDINARY: u32 =
    attr::FIXED_TPM | attr::FIXED_PARENT | attr::SENSITIVE_DATA_ORIGIN | attr::USER_WITH_AUTH;

#[test]
fn ecdh_z_gen_refuses_a_point_off_the_curve() {
    let mut tpm = started();
    let r = create_primary(
        &mut tpm,
        TPM_RH_OWNER,
        &ecc_key(ORDINARY | attr::DECRYPT, &[0, 0x10]),
    );
    let key = handle_of(&r);
    let point = created_unique(&r, 68);
    let z_gen = |point: &[u8]| command(TPM_CC_ECDH_ZGEN, &[key], Some(b""), &tpm2b(point));
    assert_eq!(rc(&tpm.process(&z_gen(&point))), 0);
    let mut off_curve = point.clone();
    *off_curve.last_mut().unwrap() ^= 1;
    assert_eq!(
        rc(&tpm.process(&z_gen(&off_curve))),
        Rc::ECC_POINT.param(1).0
    );
}

#[test]
fn a_restricted_key_signs_only_with_a_ticket_from_the_tpm() {
    let mut tpm = started();
    let ecdsa_sha256 = [0, 0x18, 0, 0x0b];
    let restricted = ecc_key(ORDINARY | attr::SIGN | attr::RESTRICTED, &ecdsa_sha256);
    let key = handle_of(&create_primary(&mut tpm, TPM_RH_OWNER, &restricted));
    let sign = |digest: &[u8], hierarchy: u32, ticket: &[u8]| {
        let mut p = Writer::new();
        p.tpm2b(digest).u16(alg::TPM_ALG_NULL);
        p.u16(object::TPM_ST_HASHCHECK).u32(hierarchy).tpm2b(ticket);
        command(TPM_CC_SIGN, &[key], Some(b""), &p.into_bytes())
    };
    let digest = alg::Hash::Sha256.digest(&[b"m"]);
    assert_eq!(
        rc(&tpm.process(&sign(&digest, TPM_RH_NULL, &[]))),
        Rc::TICKET.param(3).0,
        "no ticket"
    );
    assert_eq!(
        rc(&tpm.process(&sign(&digest, TPM_RH_OWNER, &[7; 64]))),
        Rc::TICKET.param(3).0,
        "a wrong ticket"
    );
    // TPM2_Hash: the digest, and a ticket that the TPM made it.
    let mut p = Writer::new();
    p.tpm2b(b"m").u16(alg::TPM_ALG_SHA256).u32(TPM_RH_OWNER);
    let r = tpm.process(&command(TPM_CC_HASH, &[], None, &p.into_bytes()));
    let (hashed, ticket) = split2b(&r[10..]);
    assert_eq!(hashed, digest);
    let (ticket, _) = split2b(&ticket[6..]);
    assert_eq!(rc(&tpm.process(&sign(&digest, TPM_RH_OWNER, ticket))), 0);
}

#[test]
fn verify_signature_refuses_a_null_signature() {
    let mut tpm = started();
    let key = handle_of(&create_primary(&mut tpm, TPM_RH_OWNER, &hmac_key()));
    let mut p = Writer::new();
    p.tpm2b(&alg::Hash::Sha256.digest(&[b"m"]))
        .u16(alg::TPM_ALG_NULL);
    let r = tpm.process(&command(
        TPM_CC_VERIFY_SIGNATURE,
        &[key],
        None,
        &p.into_bytes(),
    ));
    assert_eq!(rc(&r), Rc::SCHEME.param(2).0);
}

// A fixed P-256 key: d, and its public point (x, y).
const ECC_D: &str = "af235cdd12ce6ccf8df6cf4e18f15035bbbf6b7dbdbeace49afb951672d886a9";
const ECC_X: &str = "d0d528c1d062530f685a929cb78d81e77b9c2c9f7cce8d53ca0807f0fae8418f";
const ECC_Y: &str = "57b6d63f94e338242c26136f0936f211735396ccdd23ecfc48ffe46edcffbf0c";

/// TPM2_LoadExternal of an ECC key with these attributes, its point (x, y) and its private
/// scalar if any, into `hierarchy`.
fn load_external_ecc(
    attributes: u32,
    (x, y): (&str, &str),
    d: Option<&str>,
    hierarchy: u32,
) -> Vec<u8> {
    use crate::crypt::tests::unhex;
    let unique = [tpm2b(&unhex(x)), tpm2b(&unhex(y))].concat();
    let public = public(
        0x23,
        attributes,
        &[0, 0x10, 0, 0x10, 0, 3, 0, 0x10],
        &unique,
    );
    let sensitive = match d {
        Some(d) => {
            let mut s = Writer::new();
            s.u16(0x23).tpm2b(&[]).tpm2b(&[]).tpm2b(&unhex(d));
            tpm2b(&s.into_bytes())
        }
        None => tpm2b(&[]),
    };
    let mut p = Writer::new();
    p.bytes(&sensitive).tpm2b(&public).u32(hierarchy);
    command(TPM_CC_LOAD_EXTERNAL, &[], None, &p.into_bytes())
}

#[test]
fn load_external_takes_a_private_key_only_into_the_null_hierarchy_and_as_its_own() {
    let mut tpm = started();
    let usage = attr::USER_WITH_AUTH | attr::SIGN | attr::DECRYPT;
    let point = (ECC_X, ECC_Y);
    let mut load = |attributes, point, d, hierarchy| {
        let r = tpm.process(&load_external_ecc(attributes, point, d, hierarchy));
        if rc(&r) == 0 {
            flush(&mut tpm, handle_of(&r));
        }
        rc(&r)
    };
    assert_eq!(load(usage, point, Some(ECC_D), TPM_RH_NULL), 0);
    assert_eq!(
        load(usage, point, None, TPM_RH_OWNER),
        0,
        "a public key anywhere"
    );
    assert_eq!(
        load(usage, point, Some(ECC_D), TPM_RH_OWNER),
        Rc::HIERARCHY.param(3).0
    );
    for fixed in [attr::FIXED_TPM, attr::FIXED_PARENT, attr::RESTRICTED] {
        assert_eq!(
            load(usage | fixed, point, Some(ECC_D), TPM_RH_NULL),
            Rc::ATTRIBUTES.param(2).0
        );
    }
    // Another key's point: the base point, d = 1's.
    let g = (
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    );
    assert_eq!(load(usage, g, Some(ECC_D), TPM_RH_NULL), Rc::BINDING.0);
}

#[test]
fn a_salt_needs_a_decryption_key() {
    let mut tpm = started();
    let ecdsa_sha256 = [0, 0x18, 0, 0x0b];
    let signing = ecc_key(ORDINARY | attr::SIGN, &ecdsa_sha256);
    let key = handle_of(&create_primary(&mut tpm, TPM_RH_OWNER, &signing));
    let mut p = Writer::new();
    p.tpm2b(&[1; 16])
        .tpm2b(&[0, 2, 0, 0])
        .u8(0)
        .u16(alg::TPM_ALG_NULL)
        .u16(alg::TPM_ALG_SHA256);
    let r = tpm.process(&command(
        TPM_CC_START_AUTH_SESSION,
        &[key, TPM_RH_NULL],
        None,
        &p.into_bytes(),
    ));
    assert_eq!(rc(&r), Rc::ATTRIBUTES.handle(1).0);
}
