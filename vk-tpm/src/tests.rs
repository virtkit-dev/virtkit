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
        HandleKind::Entity(_) | HandleKind::Parent => TPM_RH_OWNER,
        // The index and the sessions the test makes first.
        HandleKind::NvAuth | HandleKind::NvIndex => NV_INDEX,
        HandleKind::PolicySession => 0x0300_0000,
        HandleKind::HmacSession => 0x0200_0001,
        HandleKind::Endorsement => TPM_RH_ENDORSEMENT,
    }
}

/// The NV index tests define.
const NV_INDEX: u32 = 0x0100_0001;

/// TPM2_NV_DefineSpace by the owner (or the platform): an index of `size` bytes with
/// SHA-256 as its nameAlg, an empty authValue and no policy.
fn nv_define(tpm: &mut Tpm, index: u32, attributes: u32, size: u16) -> u32 {
    nv_define_with(tpm, index, attributes, size, b"", &[])
}

fn nv_define_with(
    tpm: &mut Tpm,
    index: u32,
    attributes: u32,
    size: u16,
    auth: &[u8],
    policy: &[u8],
) -> u32 {
    let mut public = Writer::new();
    public
        .u32(index)
        .u16(alg::TPM_ALG_SHA256)
        .u32(attributes)
        .tpm2b(policy)
        .u16(size);
    let mut p = Writer::new();
    p.tpm2b(auth).tpm2b(&public.into_bytes());
    let owner = if attributes & nv::attr::PLATFORMCREATE != 0 {
        TPM_RH_PLATFORM
    } else {
        TPM_RH_OWNER
    };
    rc(&tpm.process(&command(
        TPM_CC_NV_DEFINE_SPACE,
        &[owner],
        Some(b""),
        &p.into_bytes(),
    )))
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
        let create_loaded = [&[0, 4, 0, 0, 0, 0][..], public].concat();
        let import = [&[0, 0][..], public, &[0, 0, 0, 0, 0, 0x10]].concat();
        let load_external = [&[0, 0][..], public, &[0x40, 0, 0, 7]].concat();
        let context = [&[0; 8][..], &[0x80, 0, 0, 0, 0x40, 0, 0, 7, 0, 0]].concat();
        // nonceTPM, cpHashA, policyRef, expiration, an HMAC signature.
        let policy_signed = [&[0; 10][..], &[0, 5, 0, 0x0b], &[0; 32]].concat();
        // digest, an HMAC signature.
        let verify_signature = [&[0, 0, 0, 5, 0, 0x0b][..], &[0; 32]].concat();
        // timeout, cpHashA, policyRef, authName, a NULL ticket.
        let policy_ticket = [&[0; 8][..], &[0x80, 0x23, 0x40, 0, 0, 7, 0, 0]].concat();
        // No authValue; an ordinary index of 8 bytes.
        let nv_public = [
            &[0, 0, 0, 14][..],
            &[1, 0, 0, 2, 0, 0x0b, 0, 6, 0, 6, 0, 0, 0, 8],
        ]
        .concat();
        let params: &[u8] = match cmd.code {
            TPM_CC_EVICT_CONTROL => &[0x81, 0, 0, 1],
            TPM_CC_CREATE_PRIMARY | TPM_CC_CREATE => &create,
            TPM_CC_LOAD => &load,
            // qualifyingData, a NULL scheme (and the rest).
            TPM_CC_CERTIFY | TPM_CC_GET_TIME | TPM_CC_GET_SESSION_AUDIT_DIGEST => &[0, 0, 0, 0x10],
            TPM_CC_QUOTE => &[0, 0, 0, 0x10, 0, 0, 0, 0],
            TPM_CC_NV_CERTIFY => &[0, 0, 0, 0x10, 0, 0, 0, 0],
            TPM_CC_CERTIFY_CREATION => &[0, 0, 0, 0, 0, 0x10, 0x80, 0x21, 0x40, 0, 0, 7, 0, 0],
            TPM_CC_MAKE_CREDENTIAL | TPM_CC_ACTIVATE_CREDENTIAL => &[0, 0, 0, 0],
            TPM_CC_CREATE_LOADED => &create_loaded,
            TPM_CC_IMPORT => &import,
            TPM_CC_DUPLICATE => &[0, 0, 0, 0x10],
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
            // No data, TPM_ALG_NULL, no IV.
            TPM_CC_ENCRYPT_DECRYPT => &[0, 0, 0x10, 0, 0, 0, 0],
            TPM_CC_ENCRYPT_DECRYPT_2 => &[0, 0, 0, 0, 0x10, 0, 0],
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
            TPM_CC_POLICY_SIGNED => &policy_signed,
            TPM_CC_POLICY_SECRET => &[0; 12],
            TPM_CC_POLICY_TICKET => &policy_ticket,
            TPM_CC_POLICY_OR => &[0, 0, 0, 2, 0, 0, 0, 0],
            TPM_CC_POLICY_PCR => &[0, 0, 0, 0, 0, 0],
            TPM_CC_POLICY_LOCALITY => &[1],
            TPM_CC_POLICY_NV | TPM_CC_POLICY_COUNTER_TIMER => &[0, 0, 0, 0, 0, 0],
            TPM_CC_POLICY_COMMAND_CODE => &[0, 0, 1, 0x7b],
            TPM_CC_POLICY_CP_HASH | TPM_CC_POLICY_NAME_HASH | TPM_CC_POLICY_TEMPLATE => &[0, 0],
            TPM_CC_POLICY_DUPLICATION_SELECT => &[0, 0, 0, 0, 0],
            TPM_CC_POLICY_AUTHORIZE => &[0, 0, 0, 0, 0, 0, 0x80, 0x22, 0x40, 0, 0, 7, 0, 0],
            TPM_CC_POLICY_NV_WRITTEN => &[0],
            TPM_CC_POLICY_AUTH_VALUE
            | TPM_CC_POLICY_PASSWORD
            | TPM_CC_POLICY_PHYSICAL_PRESENCE
            | TPM_CC_POLICY_GET_DIGEST
            | TPM_CC_POLICY_RESTART
            | TPM_CC_POLICY_AUTHORIZE_NV => &[],
            TPM_CC_NV_DEFINE_SPACE => &nv_public,
            TPM_CC_NV_SET_BITS => &[0; 8],
            TPM_CC_NV_EXTEND | TPM_CC_NV_CHANGE_AUTH => &[0, 0],
            TPM_CC_NV_WRITE | TPM_CC_NV_READ => &[0, 0, 0, 0],
            TPM_CC_NV_UNDEFINE_SPACE
            | TPM_CC_NV_UNDEFINE_SPACE_SPECIAL
            | TPM_CC_NV_GLOBAL_WRITE_LOCK
            | TPM_CC_NV_INCREMENT
            | TPM_CC_NV_WRITE_LOCK
            | TPM_CC_NV_READ_LOCK
            | TPM_CC_NV_READ_PUBLIC => &[],
            // A 16-byte nonce, no salt, HMAC, TPM_ALG_NULL, SHA-256.
            TPM_CC_START_AUTH_SESSION => &start_auth_session,
            _ => &[0, 0, 0, 0],
        };
        let params = [params, &[0xee]].concat();
        if cmd.code != TPM_CC_STARTUP {
            let start = command(TPM_CC_HASH_SEQUENCE_START, &[], None, &[0, 0, 0, 0x10]);
            assert_eq!(rc(&tpm.process(&start)), 0);
            let attributes = nv::attr::OWNERWRITE
                | nv::attr::OWNERREAD
                | nv::attr::AUTHWRITE
                | nv::attr::AUTHREAD;
            assert_eq!(nv_define(&mut tpm, NV_INDEX, attributes, 8), 0);
            // A policy session, then an HMAC session.
            for kind in [1, 0] {
                let p = [&[0, 16][..], &[0; 16], &[0, 0, kind, 0, 0x10, 0, 0x0b]].concat();
                let nulls = [TPM_RH_NULL, TPM_RH_NULL];
                let start = command(TPM_CC_START_AUTH_SESSION, &nulls, None, &p);
                assert_eq!(rc(&tpm.process(&start)), 0);
            }
        }
        let handles: Vec<u32> = cmd.handles.iter().map(|&k| valid_handle(k)).collect();
        let passwords = vec![&b""[..]; cmd.auth];
        let response = tpm.process(&command_with(cmd.code, &handles, &passwords, &params));
        // The ADMIN role of an NV index, and the DUP role, take a policy session: the
        // authorization fails first.
        let nv_admin = cmd.role == Role::Admin && cmd.handles.first() == Some(&HandleKind::NvIndex);
        let expected = if nv_admin || cmd.role == Role::Dup {
            Rc::AUTH_TYPE.session(1)
        } else {
            Rc::SIZE
        };
        assert_eq!(rc(&response), expected.0, "command {:#x}", cmd.code);
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
    assert_eq!(
        listed[0], 0x0440_011f,
        "NV_UndefineSpaceSpecial: nv, 2 handles"
    );
    assert_eq!(listed[1], 0x0440_0120, "EvictControl: nv, 2 handles");
    assert_eq!(
        listed[2], 0x02c0_0121,
        "HierarchyControl: nv, extensive, 1 handle"
    );
    assert!(listed.windows(2).all(|w| (w[0] & 0xffff) < (w[1] & 0xffff)));
    assert!(
        listed.contains(&0x1000_0186),
        "HashSequenceStart: a response handle"
    );
    assert!(listed.contains(&0x0600_0149), "PolicyNV: 3 handles");
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
    assert!(tpm.entity_policy(TPM_RH_OWNER).hash.is_some());
    assert_eq!(rc(&tpm.process(&policy(&[], alg::TPM_ALG_NULL))), 0);
    assert!(tpm.entity_policy(TPM_RH_OWNER).hash.is_none());
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
    /// A policy session after TPM2_PolicyPassword: the authValue in clear in place of an HMAC,
    /// and no HMAC in the response.
    password: bool,
}

impl<'a> Turn<'a> {
    /// The session authorizes an entity whose authValue is `auth`.
    fn authorizing(client: &'a mut Client, attributes: u8, auth: &'a [u8]) -> Turn<'a> {
        Turn {
            client,
            attributes,
            auth: Some(auth),
            in_hmac: true,
            password: false,
        }
    }

    /// A policy session after TPM2_PolicyPassword: it carries `auth` in clear.
    fn password(client: &'a mut Client, attributes: u8, auth: &'a [u8]) -> Turn<'a> {
        Turn {
            password: true,
            ..Turn::authorizing(client, attributes, auth)
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
            password: false,
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
        if self.password {
            return self.auth.unwrap_or_default().to_vec();
        }
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
    let names: Vec<Vec<u8>> = handles.iter().map(|&h| name(h)).collect();
    session_command_named(code, handles, &names, turns, params, cover_nonces)
}

/// [`session_command`] with the handles' Names given (an NV index's is not its handle).
fn session_command_named(
    code: u32,
    handles: &[u32],
    names: &[Vec<u8>],
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
    let cp_hash = sha256(&[&code.to_be_bytes(), &names.concat(), &params]);
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
    let names: Vec<Vec<u8>> = handles.iter().map(|&h| name(h)).collect();
    call_named(tpm, code, handles, &names, turns, params)
}

/// [`call`] with the handles' Names given.
fn call_named(
    tpm: &mut Tpm,
    code: u32,
    handles: &[u32],
    names: &[Vec<u8>],
    turns: &mut [Turn],
    params: &[u8],
) -> std::result::Result<Reply, u32> {
    let r = tpm.process(&session_command_named(
        code, handles, names, turns, params, true,
    ));
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
        let expected = if t.password {
            Vec::new()
        } else {
            t.hmac(&[&rp_hash, &c.nonce_tpm, &c.nonce_caller, &[a]])
        };
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

/// TPM2_NV_Increment by the owner, then the counter's value.
fn nv_increment(tpm: &mut Tpm, index: u32) -> u64 {
    let increment = command(TPM_CC_NV_INCREMENT, &[TPM_RH_OWNER, index], Some(b""), &[]);
    assert_eq!(rc(&tpm.process(&increment)), 0);
    let read = command(
        TPM_CC_NV_READ,
        &[TPM_RH_OWNER, index],
        Some(b""),
        &[0, 8, 0, 0],
    );
    let r = tpm.process(&read);
    assert_eq!(rc(&r), 0);
    // The parameter size, then the TPM2B's.
    u64::from_be_bytes(r[16..24].try_into().unwrap())
}

#[test]
fn nv_writes_are_stored_at_once_but_orderly_ones_at_shutdown() {
    use nv::attr::*;
    let mut tpm = started();
    let rw = OWNERWRITE | OWNERREAD;
    let counter = 1 << TPM_NT_SHIFT;
    assert_eq!(nv_define(&mut tpm, NV_INDEX, rw | counter, 8), 0);
    assert_eq!(
        nv_define(&mut tpm, 0x0100_0002, rw | counter | ORDERLY, 8),
        0
    );
    assert!(tpm.take_permanent_changed(), "defining is stored");
    assert_eq!(nv_increment(&mut tpm, NV_INDEX), 1);
    assert!(tpm.take_permanent_changed());
    // An orderly counter's first value is stored; the next ones are not, until the next
    // TPM2_Shutdown or boundary.
    assert_eq!(nv_increment(&mut tpm, 0x0100_0002), 1);
    assert!(tpm.take_permanent_changed());
    assert_eq!(nv_increment(&mut tpm, 0x0100_0002), 2);
    assert!(!tpm.take_permanent_changed());
    // A snapshot has the RAM copy.
    let mut restored = Tpm::restore(&tpm.permanent_state(), &tpm.volatile_state()).unwrap();
    assert_eq!(nv_increment(&mut restored, 0x0100_0002), 3);
    // Power lost: the orderly counter skips past what it may have reported.
    let mut lost = power_cycle(&restored, 0);
    assert_eq!(nv_increment(&mut lost, 0x0100_0002), 0x100);
    assert_eq!(nv_increment(&mut lost, NV_INDEX), 2);
    // An orderly shutdown stores it.
    assert_eq!(nv_increment(&mut lost, 0x0100_0002), 0x101);
    assert_eq!(
        rc(&lost.process(&command(TPM_CC_SHUTDOWN, &[], None, &[0, 0]))),
        0
    );
    let mut next = power_cycle(&lost, 0);
    assert_eq!(nv_increment(&mut next, 0x0100_0002), 0x102);
}

#[test]
fn nv_memory_is_bounded() {
    use nv::attr::*;
    let mut tpm = started();
    let rw = OWNERWRITE | OWNERREAD;
    let mut defined = 0;
    let last = loop {
        let r = nv_define(&mut tpm, NV_INDEX + defined, rw, 2048);
        if r != 0 {
            break r;
        }
        defined += 1;
    };
    assert_eq!(last, Rc::NV_SPACE.0);
    assert_eq!(defined, 29, "64 KiB of 2 KiB indices");
    // The permanent state holds them all, and reads back.
    let state = tpm.permanent_state();
    let back = Tpm::power_on(&state).unwrap();
    assert_eq!(*back.permanent_state(), *state);
    assert_eq!(back.nv_counts(), (29, 0));
    // The orderly RAM: 512 bytes, 12 for each index's header.
    let mut tpm = started();
    assert_eq!(nv_define(&mut tpm, NV_INDEX, rw | ORDERLY, 500), 0);
    assert_eq!(
        nv_define(&mut tpm, NV_INDEX + 1, rw | ORDERLY, 1),
        Rc::NV_SPACE.0
    );
    assert_eq!(tpm.nv_counters_available(), 0);
}

/// An NV index's Name, as a client computes it: SHA-256 of its TPMS_NV_PUBLIC (SHA-256, no
/// policy), with its attributes as they are now.
fn nv_name(index: u32, attributes: u32, size: u16) -> Vec<u8> {
    let mut public = Writer::new();
    public
        .u32(index)
        .u16(alg::TPM_ALG_SHA256)
        .u32(attributes)
        .tpm2b(&[])
        .u16(size);
    let digest = sha256(&[&public.into_bytes()]);
    [&alg::TPM_ALG_SHA256.to_be_bytes()[..], &digest].concat()
}

/// TPM2_NV_Write of `data` at `offset`, authorized by `auth` (owner or platform).
fn nv_write(tpm: &mut Tpm, auth: u32, index: u32, data: &[u8], offset: u16) -> u32 {
    let mut p = Writer::new();
    p.tpm2b(data).u16(offset);
    let write = command(TPM_CC_NV_WRITE, &[auth, index], Some(b""), &p.into_bytes());
    rc(&tpm.process(&write))
}

/// TPM2_NV_Read of `size` bytes at `offset`, authorized by `auth` (owner or platform).
fn nv_read(
    tpm: &mut Tpm,
    auth: u32,
    index: u32,
    size: u16,
    offset: u16,
) -> std::result::Result<Vec<u8>, u32> {
    let mut p = Writer::new();
    p.u16(size).u16(offset);
    let r = tpm.process(&command(
        TPM_CC_NV_READ,
        &[auth, index],
        Some(b""),
        &p.into_bytes(),
    ));
    match rc(&r) {
        0 => Ok(split2b(response_params(&r, false)).0.to_vec()),
        code => Err(code),
    }
}

/// A command on an index that takes no parameters (a lock, UndefineSpace), authorized by
/// `auth` (owner or platform).
fn nv_command(tpm: &mut Tpm, code: u32, auth: u32, index: u32) -> u32 {
    rc(&tpm.process(&command(code, &[auth, index], Some(b""), &[])))
}

fn nv_read_public(tpm: &mut Tpm, index: u32) -> u32 {
    rc(&tpm.process(&command(TPM_CC_NV_READ_PUBLIC, &[index], None, &[])))
}

fn shutdown(tpm: &mut Tpm, state: u8) {
    let r = tpm.process(&command(TPM_CC_SHUTDOWN, &[], None, &[0, state]));
    assert_eq!(rc(&r), 0);
}

#[test]
fn an_orderly_index_stays_locked_across_a_power_loss() {
    use nv::attr::*;
    // Orderly counters locked for good once written: by NV_WriteLock, and by NV_GlobalWriteLock.
    let counter = OWNERWRITE | OWNERREAD | ORDERLY | WRITEDEFINE | 1 << TPM_NT_SHIFT;
    let (locked, globally) = (NV_INDEX, NV_INDEX + 1);
    let mut tpm = started();
    assert_eq!(nv_define(&mut tpm, locked, counter, 8), 0);
    assert_eq!(nv_define(&mut tpm, globally, counter | GLOBALLOCK, 8), 0);
    nv_increment(&mut tpm, locked);
    nv_increment(&mut tpm, globally);
    tpm.take_permanent_changed();
    let write_lock = TPM_CC_NV_WRITE_LOCK;
    assert_eq!(nv_command(&mut tpm, write_lock, TPM_RH_OWNER, locked), 0);
    let global = command(TPM_CC_NV_GLOBAL_WRITE_LOCK, &[TPM_RH_OWNER], Some(b""), &[]);
    assert_eq!(rc(&tpm.process(&global)), 0);
    assert!(tpm.take_permanent_changed(), "the locks are stored");
    // Power lost without TPM2_Shutdown.
    let mut next = power_cycle(&tpm, 0);
    for index in [locked, globally] {
        let increment = command(TPM_CC_NV_INCREMENT, &[TPM_RH_OWNER, index], Some(b""), &[]);
        assert_eq!(rc(&next.process(&increment)), Rc::NV_LOCKED.0);
    }
}

#[test]
fn nv_locks_last_as_the_index_attributes_say() {
    use nv::attr::*;
    let rw = OWNERWRITE | OWNERREAD;
    let (stclear, define) = (NV_INDEX, NV_INDEX + 1);
    let (read_lock, write_lock) = (TPM_CC_NV_READ_LOCK, TPM_CC_NV_WRITE_LOCK);
    let mut tpm = started();
    let attributes = rw | WRITE_STCLEAR | READ_STCLEAR;
    assert_eq!(nv_define(&mut tpm, stclear, attributes, 8), 0);
    assert_eq!(nv_define(&mut tpm, define, rw | WRITEDEFINE, 8), 0);
    assert_eq!(
        nv_command(&mut tpm, read_lock, TPM_RH_OWNER, define),
        Rc::ATTRIBUTES.handle(2).0,
        "no TPMA_NV_READ_STCLEAR"
    );
    for index in [stclear, define] {
        assert_eq!(nv_write(&mut tpm, TPM_RH_OWNER, index, &[1; 8], 0), 0);
        assert_eq!(nv_command(&mut tpm, write_lock, TPM_RH_OWNER, index), 0);
        let rc = nv_write(&mut tpm, TPM_RH_OWNER, index, &[2; 8], 0);
        assert_eq!(rc, Rc::NV_LOCKED.0);
    }
    assert_eq!(nv_command(&mut tpm, read_lock, TPM_RH_OWNER, stclear), 0);
    let read = nv_read(&mut tpm, TPM_RH_OWNER, stclear, 8, 0);
    assert_eq!(read, Err(Rc::NV_LOCKED.0));

    // A TPM Resume keeps every lock.
    shutdown(&mut tpm, 1);
    let mut resumed = power_cycle(&tpm, 1);
    let read = nv_read(&mut resumed, TPM_RH_OWNER, stclear, 8, 0);
    assert_eq!(read, Err(Rc::NV_LOCKED.0));
    for index in [stclear, define] {
        let rc = nv_write(&mut resumed, TPM_RH_OWNER, index, &[2; 8], 0);
        assert_eq!(rc, Rc::NV_LOCKED.0);
    }
    // A TPM Restart (after Shutdown(STATE)) or Reset (no Shutdown) ends the STCLEAR ones only.
    for mut next in [power_cycle(&tpm, 0), power_cycle(&resumed, 0)] {
        let read = nv_read(&mut next, TPM_RH_OWNER, stclear, 8, 0);
        assert_eq!(read, Ok(vec![1; 8]));
        assert_eq!(nv_write(&mut next, TPM_RH_OWNER, stclear, &[2; 8], 0), 0);
        let rc = nv_write(&mut next, TPM_RH_OWNER, define, &[2; 8], 0);
        assert_eq!(rc, Rc::NV_LOCKED.0);
    }
}

#[test]
fn nv_reads_and_writes_stay_within_the_index() {
    use nv::attr::*;
    let rw = OWNERWRITE | OWNERREAD;
    let owner = TPM_RH_OWNER;
    let mut tpm = started();
    assert_eq!(nv_define(&mut tpm, NV_INDEX, rw, 16), 0);
    let read = nv_read(&mut tpm, owner, NV_INDEX, 1, 0);
    assert_eq!(read, Err(Rc::NV_UNINITIALIZED.0));
    let write = nv_write(&mut tpm, owner, NV_INDEX, &[], 17);
    assert_eq!(write, Rc::VALUE.param(2).0);
    let write = nv_write(&mut tpm, owner, NV_INDEX, &[1; 8], 9);
    assert_eq!(write, Rc::NV_RANGE.0);
    assert_eq!(nv_write(&mut tpm, owner, NV_INDEX, &[1; 8], 8), 0);
    // The first write erased the rest of the index.
    let data = [[0xff; 8], [1; 8]].concat();
    assert_eq!(nv_read(&mut tpm, owner, NV_INDEX, 16, 0), Ok(data));
    let read = nv_read(&mut tpm, owner, NV_INDEX, 1025, 0);
    assert_eq!(read, Err(Rc::VALUE.param(1).0));
    let read = nv_read(&mut tpm, owner, NV_INDEX, 0, 17);
    assert_eq!(read, Err(Rc::VALUE.param(2).0));
    let read = nv_read(&mut tpm, owner, NV_INDEX, 8, 9);
    assert_eq!(read, Err(Rc::NV_RANGE.0));

    // TPMA_NV_WRITEALL: the whole index at once.
    let all = NV_INDEX + 1;
    assert_eq!(nv_define(&mut tpm, all, rw | WRITEALL, 8), 0);
    assert_eq!(nv_write(&mut tpm, owner, all, &[1; 4], 0), Rc::NV_RANGE.0);
    assert_eq!(nv_write(&mut tpm, owner, all, &[1; 8], 0), 0);
    // A counter is written only by TPM2_NV_Increment.
    let counter = NV_INDEX + 2;
    assert_eq!(nv_define(&mut tpm, counter, rw | 1 << TPM_NT_SHIFT, 8), 0);
    assert_eq!(
        nv_write(&mut tpm, owner, counter, &[1; 8], 0),
        Rc::ATTRIBUTES.0
    );
}

#[test]
fn nv_access_takes_the_attribute_of_the_authorizing_entity() {
    use nv::attr::*;
    let attributes = OWNERWRITE | AUTHREAD;
    let mut tpm = started();
    assert_eq!(
        nv_define_with(&mut tpm, NV_INDEX, attributes, 8, b"pw", &[]),
        0
    );
    let write = nv_write(&mut tpm, TPM_RH_PLATFORM, NV_INDEX, &[1; 8], 0);
    assert_eq!(write, Rc::NV_AUTHORIZATION.0, "no TPMA_NV_PPWRITE");
    assert_eq!(nv_write(&mut tpm, TPM_RH_OWNER, NV_INDEX, &[1; 8], 0), 0);
    let read = nv_read(&mut tpm, TPM_RH_OWNER, NV_INDEX, 8, 0);
    assert_eq!(read, Err(Rc::NV_AUTHORIZATION.0), "no TPMA_NV_OWNERREAD");

    // The index's own authValue, in an HMAC session's.
    let name = nv_name(NV_INDEX, attributes | WRITTEN, 8);
    let names = [name.clone(), name];
    let mut s = Client::start(&mut tpm, HMAC, TPM_RH_NULL, b"", Cipher::None);
    let mut as_index = |tpm: &mut Tpm, code: u32, auth: &[u8], params: &[u8]| {
        let turn = Turn::authorizing(&mut s, CONTINUE, auth);
        let handles = [NV_INDEX, NV_INDEX];
        call_named(tpm, code, &handles, &names, &mut [turn], params).map(|r| r.params)
    };
    let read = as_index(&mut tpm, TPM_CC_NV_READ, b"pw", &[0, 8, 0, 0]);
    assert_eq!(read, Ok([&[0, 8][..], &[1; 8]].concat()));
    let read = as_index(&mut tpm, TPM_CC_NV_READ, b"no", &[0, 8, 0, 0]);
    assert_eq!(read, Err(Rc::AUTH_FAIL.session(1).0));
    let write = as_index(&mut tpm, TPM_CC_NV_WRITE, b"pw", &[0, 1, 2, 0, 0]);
    assert_eq!(write, Err(Rc::AUTH_UNAVAILABLE.0), "no TPMA_NV_AUTHWRITE");
}

#[test]
fn pin_indices_count_their_authorizations() {
    use nv::attr::*;
    let (fail, pass) = (NV_INDEX, NV_INDEX + 1);
    let attributes = |kind: u32| OWNERWRITE | OWNERREAD | AUTHREAD | NO_DA | kind << TPM_NT_SHIFT;
    let mut tpm = started();
    for (index, kind) in [(fail, 8), (pass, 9)] {
        let defined = nv_define_with(&mut tpm, index, attributes(kind), 8, b"pin", &[]);
        assert_eq!(defined, 0);
        // pinCount 0, pinLimit 2.
        let write = nv_write(&mut tpm, TPM_RH_OWNER, index, &[0, 0, 0, 0, 0, 0, 0, 2], 0);
        assert_eq!(write, 0);
    }
    // No session may hold a PIN index's authValue.
    let mut p = Writer::new();
    p.tpm2b(&[0; 16]).tpm2b(&[]).u8(HMAC).u16(alg::TPM_ALG_NULL);
    p.u16(alg::TPM_ALG_SHA256);
    let bound = command(
        TPM_CC_START_AUTH_SESSION,
        &[TPM_RH_NULL, fail],
        None,
        &p.into_bytes(),
    );
    assert_eq!(rc(&tpm.process(&bound)), Rc::HANDLE.handle(2).0);

    // TPM2_NV_Read with the index's authorization: its pinCount, or the response code.
    let mut s = Client::start(&mut tpm, HMAC, TPM_RH_NULL, b"", Cipher::None);
    let mut read_count = |tpm: &mut Tpm, index: u32, kind: u32, auth: &[u8]| {
        let name = nv_name(index, attributes(kind) | WRITTEN, 8);
        let turn = Turn::authorizing(&mut s, CONTINUE, auth);
        let params = [0, 4, 0, 0];
        let r = call_named(
            tpm,
            TPM_CC_NV_READ,
            &[index; 2],
            &[name.clone(), name],
            &mut [turn],
            &params,
        );
        r.map(|r| u32::from_be_bytes(r.params[2..6].try_into().unwrap()))
    };
    // TPMA_NV_NO_DA: a bad authValue is TPM_RC_BAD_AUTH, no failure counted against the TPM.
    let failed = Err(Rc::BAD_AUTH.session(1).0);
    let unavailable = Err(Rc::AUTH_UNAVAILABLE.0);
    let owner_count = |tpm: &mut Tpm, index: u32| nv_read(tpm, TPM_RH_OWNER, index, 4, 0);

    // A PIN fail index counts the failures since the last success, up to its limit.
    assert_eq!(read_count(&mut tpm, fail, 8, b"no"), failed);
    assert_eq!(owner_count(&mut tpm, fail), Ok(vec![0, 0, 0, 1]));
    assert_eq!(read_count(&mut tpm, fail, 8, b"pin"), Ok(0));
    assert_eq!(read_count(&mut tpm, fail, 8, b"no"), failed);
    assert_eq!(read_count(&mut tpm, fail, 8, b"no"), failed);
    assert_eq!(read_count(&mut tpm, fail, 8, b"pin"), unavailable);
    // A PIN pass index counts the successes, up to its limit.
    assert_eq!(read_count(&mut tpm, pass, 9, b"no"), failed);
    assert_eq!(read_count(&mut tpm, pass, 9, b"pin"), Ok(1));
    assert_eq!(read_count(&mut tpm, pass, 9, b"pin"), Ok(2));
    assert_eq!(read_count(&mut tpm, pass, 9, b"pin"), unavailable);
    assert_eq!(property(&mut tpm, 0x20e), 0, "TPM_PT_LOCKOUT_COUNTER");
}

#[test]
fn nv_undefine_space_keeps_what_the_caller_may_not_delete() {
    use nv::attr::*;
    let platform = PPWRITE | PPREAD | PLATFORMCREATE;
    let (special, platforms) = (NV_INDEX, NV_INDEX + 1);
    let undefine = TPM_CC_NV_UNDEFINE_SPACE;
    let mut tpm = started();
    let policy_delete = platform | POLICY_DELETE;
    let defined = nv_define_with(&mut tpm, special, policy_delete, 8, b"", &[7; 32]);
    assert_eq!(defined, 0);
    assert_eq!(nv_define(&mut tpm, platforms, platform, 8), 0);
    assert_eq!(
        nv_command(&mut tpm, undefine, TPM_RH_PLATFORM, special),
        Rc::ATTRIBUTES.handle(2).0,
        "TPMA_NV_POLICY_DELETE: TPM2_NV_UndefineSpaceSpecial only"
    );
    assert_eq!(
        nv_command(&mut tpm, undefine, TPM_RH_OWNER, platforms),
        Rc::NV_AUTHORIZATION.0
    );
    assert_eq!(
        nv_command(&mut tpm, undefine, TPM_RH_PLATFORM, platforms),
        0
    );
    assert_eq!(nv_read_public(&mut tpm, platforms), Rc::HANDLE.handle(1).0);
}

#[test]
fn a_counter_starts_above_every_counter_deleted() {
    use nv::attr::*;
    let counter = OWNERWRITE | OWNERREAD | 1 << TPM_NT_SHIFT;
    let mut tpm = started();
    assert_eq!(nv_define(&mut tpm, NV_INDEX, counter, 8), 0);
    for _ in 0..3 {
        nv_increment(&mut tpm, NV_INDEX);
    }
    let undefine = TPM_CC_NV_UNDEFINE_SPACE;
    assert_eq!(nv_command(&mut tpm, undefine, TPM_RH_OWNER, NV_INDEX), 0);
    assert_eq!(nv_define(&mut tpm, NV_INDEX + 1, counter, 8), 0);
    assert_eq!(nv_increment(&mut tpm, NV_INDEX + 1), 4);
}

#[test]
fn clear_deletes_the_owner_indices_only() {
    use nv::attr::*;
    let (owners, platforms) = (NV_INDEX, NV_INDEX + 1);
    let mut tpm = started();
    assert_eq!(nv_define(&mut tpm, owners, OWNERWRITE | OWNERREAD, 8), 0);
    let platform = PPWRITE | PPREAD | PLATFORMCREATE;
    assert_eq!(nv_define(&mut tpm, platforms, platform, 8), 0);
    let clear = command(TPM_CC_CLEAR, &[TPM_RH_LOCKOUT], Some(b""), &[]);
    assert_eq!(rc(&tpm.process(&clear)), 0);
    assert_eq!(nv_read_public(&mut tpm, owners), Rc::HANDLE.handle(1).0);
    assert_eq!(nv_read_public(&mut tpm, platforms), 0);
}

#[test]
fn an_index_is_hidden_while_its_hierarchy_is_disabled() {
    use nv::attr::*;
    let (owners, platforms) = (NV_INDEX, NV_INDEX + 1);
    let platform = PPWRITE | PPREAD | PLATFORMCREATE;
    let mut tpm = started();
    assert_eq!(nv_define(&mut tpm, owners, OWNERWRITE | OWNERREAD, 8), 0);
    assert_eq!(nv_define(&mut tpm, platforms, platform, 8), 0);
    let disable = |enable: u32| {
        let mut p = Writer::new();
        p.u32(enable).u8(0);
        let control = TPM_CC_HIERARCHY_CONTROL;
        command(control, &[TPM_RH_PLATFORM], Some(b""), &p.into_bytes())
    };
    assert_eq!(rc(&tpm.process(&disable(TPM_RH_OWNER))), 0);
    assert_eq!(nv_read_public(&mut tpm, owners), Rc::HANDLE.handle(1).0);
    assert_eq!(nv_read_public(&mut tpm, platforms), 0);
    assert_eq!(rc(&tpm.process(&disable(TPM_RH_PLATFORM_NV))), 0);
    assert_eq!(nv_read_public(&mut tpm, platforms), Rc::HANDLE.handle(1).0);
    assert_eq!(
        nv_define(&mut tpm, platforms + 1, platform, 8),
        Rc::HIERARCHY.handle(1).0
    );
    // Both come back at the next TPM2_Startup(CLEAR).
    let mut next = power_cycle(&tpm, 0);
    assert_eq!(nv_read_public(&mut next, owners), 0);
    assert_eq!(nv_read_public(&mut next, platforms), 0);
}

#[test]
fn a_restored_nv_state_is_checked() {
    use nv::attr::*;
    let mut tpm = started();
    let orderly = OWNERWRITE | OWNERREAD | ORDERLY;
    assert_eq!(nv_define(&mut tpm, NV_INDEX, orderly, 8), 0);
    let permanent = tpm.permanent_state();
    let volatile = tpm.volatile_state();
    assert!(Tpm::restore(&permanent, &volatile).is_ok());
    // Orderly RAM that is not the orderly indices' copies.
    let other = started().volatile_state();
    assert!(Tpm::restore(&permanent, &other).is_err(), "no copy");
    tpm.volatile.nv_orderly[0].data.push(0);
    assert!(
        Tpm::restore(&permanent, &tpm.volatile_state()).is_err(),
        "not its size"
    );
    tpm.volatile.nv_orderly[0].data.pop();
    tpm.volatile.nv_orderly[0].attributes &= !ORDERLY;
    assert!(
        Tpm::restore(&permanent, &tpm.volatile_state()).is_err(),
        "other attributes"
    );
    tpm.volatile.nv_orderly[0].attributes |= ORDERLY;
    let copy = tpm.volatile.nv_orderly[0].clone();
    tpm.volatile.nv_orderly.push(copy);
    assert!(
        Tpm::restore(&permanent, &tpm.volatile_state()).is_err(),
        "two copies"
    );

    // A counter of other than 8 bytes.
    let mut tpm = started();
    assert_eq!(nv_define(&mut tpm, NV_INDEX, OWNERWRITE | OWNERREAD, 2), 0);
    tpm.permanent.nv[0].public.attributes |= 1 << TPM_NT_SHIFT;
    assert!(
        Tpm::power_on(&tpm.permanent_state()).is_err(),
        "a 2-byte counter"
    );
    // Indices over their memory: 29 of 2 KiB fit, not 30.
    let mut tpm = started();
    for n in 0..29 {
        assert_eq!(
            nv_define(&mut tpm, NV_INDEX + n, OWNERWRITE | OWNERREAD, 2048),
            0
        );
    }
    let mut extra = tpm.permanent.nv[0].clone();
    extra.public.index = NV_INDEX + 29;
    tpm.permanent.nv.push(extra);
    assert!(
        Tpm::power_on(&tpm.permanent_state()).is_err(),
        "over 64 KiB"
    );
}

// Policy sessions. Expected policyDigests are computed here from Part 3's formulas with
// RustCrypto, or are values published elsewhere.

/// A SHA-256 policy (or trial) session, unbound and unsalted.
fn policy_session(tpm: &mut Tpm, kind: u8) -> Client {
    Client::start(tpm, kind, TPM_RH_NULL, b"", Cipher::None)
}

/// A policy command on `handles` (the session last) that needs no authorization.
fn policy_command(tpm: &mut Tpm, code: u32, handles: &[u32], params: &[u8]) -> u32 {
    rc(&tpm.process(&command(code, handles, None, params)))
}

/// A policy command whose first handle the owner (or the entity, with an empty authValue)
/// authorizes with a password: its response parameters, or the response code.
fn policy_command_authorized(
    tpm: &mut Tpm,
    code: u32,
    handles: &[u32],
    params: &[u8],
) -> std::result::Result<Vec<u8>, u32> {
    let r = tpm.process(&command(code, handles, Some(b""), params));
    match rc(&r) {
        0 => Ok(response_params(&r, false).to_vec()),
        code => Err(code),
    }
}

/// TPM2_PolicyRestart: a failed authorization leaves the session's policy as it was.
fn policy_restart(tpm: &mut Tpm, session: u32) {
    assert_eq!(
        policy_command(tpm, TPM_CC_POLICY_RESTART, &[session], &[]),
        0
    );
}

/// TPM2_PolicyGetDigest.
fn policy_digest(tpm: &mut Tpm, session: u32) -> Vec<u8> {
    let r = tpm.process(&command(TPM_CC_POLICY_GET_DIGEST, &[session], None, &[]));
    assert_eq!(rc(&r), 0);
    split2b(&r[10..]).0.to_vec()
}

/// Part 1's PolicyUpdate without a policyRef: H(policyDigest ‖ commandCode ‖ parts).
fn policy_extend(digest: &[u8], code: u32, parts: &[&[u8]]) -> Vec<u8> {
    sha256(&[digest, &code.to_be_bytes(), &parts.concat()])
}

/// PolicyUpdate with a policyRef (TPM2_PolicySigned, TPM2_PolicySecret, TPM2_PolicyAuthorize):
/// H(H(policyDigest ‖ commandCode ‖ name) ‖ policyRef).
fn policy_update(digest: &[u8], code: u32, name: &[u8], policy_ref: &[u8]) -> Vec<u8> {
    sha256(&[&policy_extend(digest, code, &[name]), policy_ref])
}

/// TPML_PCR_SELECTION of one PCR of the SHA-256 bank.
fn pcr_selection(pcr: usize) -> Vec<u8> {
    let mut select = [0u8; 3];
    select[pcr / 8] = 1 << (pcr % 8);
    let mut w = Writer::new();
    w.u32(1).u16(alg::TPM_ALG_SHA256).u8(3).bytes(&select);
    w.into_bytes()
}

/// An NV index's Name with an authPolicy (see [`nv_name`]).
fn nv_policy_name(index: u32, attributes: u32, policy: &[u8], size: u16) -> Vec<u8> {
    let mut public = Writer::new();
    public
        .u32(index)
        .u16(alg::TPM_ALG_SHA256)
        .u32(attributes)
        .tpm2b(policy)
        .u16(size);
    let digest = sha256(&[&public.into_bytes()]);
    [&alg::TPM_ALG_SHA256.to_be_bytes()[..], &digest].concat()
}

/// An index of 8 bytes the owner writes (pinCount 0, pinLimit 2 for a PIN index) and a policy
/// session reaching `policy` reads, with `auth` as its authValue: its Name.
fn policy_index(tpm: &mut Tpm, index: u32, attributes: u32, auth: &[u8], policy: &[u8]) -> Vec<u8> {
    use nv::attr::*;
    let attributes = attributes | OWNERWRITE | OWNERREAD | POLICYREAD;
    assert_eq!(nv_define_with(tpm, index, attributes, 8, auth, policy), 0);
    let data = [0, 0, 0, 0, 0, 0, 0, 2];
    assert_eq!(nv_write(tpm, TPM_RH_OWNER, index, &data, 0), 0);
    nv_policy_name(index, attributes | WRITTEN, policy, 8)
}

/// TPM2_NV_Read of `params` (size, offset) authorized by the index itself through `turn`.
fn nv_read_as(
    tpm: &mut Tpm,
    (index, name): (u32, &[u8]),
    turn: Turn,
    params: &[u8],
) -> std::result::Result<Vec<u8>, u32> {
    let names = [name.to_vec(), name.to_vec()];
    let reply = call_named(
        tpm,
        TPM_CC_NV_READ,
        &[index; 2],
        &names,
        &mut [turn],
        params,
    )?;
    Ok(split2b(&reply.params).0.to_vec())
}

/// A trial session's policyDigest after `commands` (code, parameters).
fn trial_digest(tpm: &mut Tpm, commands: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let t = policy_session(tpm, TRIAL);
    for (code, params) in commands {
        assert_eq!(policy_command(tpm, *code, &[t.handle], params), 0);
    }
    let digest = policy_digest(tpm, t.handle);
    flush(tpm, t.handle);
    digest
}

/// TPM2_PolicySecret's parameters: nonceTPM, cpHashA, policyRef, expiration.
fn secret_params(nonce: &[u8], cp_hash: &[u8], policy_ref: &[u8], expiration: i32) -> Vec<u8> {
    let mut w = Writer::new();
    w.tpm2b(nonce)
        .tpm2b(cp_hash)
        .tpm2b(policy_ref)
        .u32(expiration as u32);
    w.into_bytes()
}

#[test]
fn policy_digests_are_the_published_ones() {
    use crate::crypt::tests::unhex;
    // tpm2-tss's FAPI policy tests: the policies of test/data/fapi/policy/pol_<name>.json and
    // their SHA-256 digests in test/data/test-fapi-policies.h (tpm2-tss commit d50e55b13a96).
    let auth_value = "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e";
    // TPMT_PUBLIC of pol_template: ECC P-256 storage key, AES-128-CFB, no unique.
    let template = unhex("0023000b00030072000000060080004300100003001000000000");
    let cases = [
        (
            "auth_value",
            vec![(TPM_CC_POLICY_AUTH_VALUE, vec![])],
            auth_value,
        ),
        (
            "password",
            vec![(TPM_CC_POLICY_PASSWORD, vec![])],
            auth_value,
        ),
        (
            "locality",
            vec![(TPM_CC_POLICY_LOCALITY, vec![1])],
            "ddee6af14bf3c4e8127ced87bcf9a57e1c0c8ddb5e67735c8505f96f07b8dbb8",
        ),
        (
            "physical_presence",
            vec![(TPM_CC_POLICY_PHYSICAL_PRESENCE, vec![])],
            "0d7c6747b1b9facbba03492097aa9d5af792e5efc07346e05f9daa8b3d9e13b5",
        ),
        (
            "command_code (349, TPM_CC_Sign)",
            vec![(TPM_CC_POLICY_COMMAND_CODE, 349u32.to_be_bytes().to_vec())],
            "cc6918b226273b08f5bd406d7f10cf160f0a7d13dfd83b7770ccbcd1aa80d811",
        ),
        (
            "countertimer (operandB ff, offset 0, UNSIGNED_LT)",
            vec![(TPM_CC_POLICY_COUNTER_TIMER, vec![0, 1, 0xff, 0, 0, 0, 5])],
            "7c67802209683d17c1d94f3fc9df7afb2a0d7955c3c5d0fa3f602d58ffdaf984",
        ),
        (
            "nv_written (NO)",
            vec![(TPM_CC_POLICY_NV_WRITTEN, vec![0])],
            "3c326323670e28ad37bd57f63b4cc34d26ab205ef22f275c58d47fab2485466e",
        ),
        (
            "pcr16_0",
            vec![(
                TPM_CC_POLICY_PCR,
                [tpm2b(&sha256(&[&[0; 32]])), pcr_selection(16)].concat(),
            )],
            "bff2d58e9813f97cefc14f72ad8133bc7092d652b7c877959254af140c841f36",
        ),
        (
            "pcr8_0",
            vec![(
                TPM_CC_POLICY_PCR,
                [tpm2b(&sha256(&[&[0; 32]])), pcr_selection(8)].concat(),
            )],
            "2a90ac03196573f129e70a9e04485bff581d2890fe5882d3c2667290d84b497b",
        ),
        (
            "nv_change_auth (auth value, then command code 315)",
            vec![
                (TPM_CC_POLICY_AUTH_VALUE, vec![]),
                (TPM_CC_POLICY_COMMAND_CODE, 315u32.to_be_bytes().to_vec()),
            ],
            "363ac945b6457c47c31f3355dba0db27de8db213d6250c6bf79685003f9fe7ab",
        ),
        (
            "template",
            vec![(TPM_CC_POLICY_TEMPLATE, tpm2b(&sha256(&[&template])))],
            "8beacb2d1cb3318856f9a51bbdede1499892b5bbe7fc491f37cf5c6ed56c7d73",
        ),
    ];
    let mut tpm = started();
    for (name, commands, expected) in cases {
        assert_eq!(trial_digest(&mut tpm, &commands), unhex(expected), "{name}");
    }

    // A policy session takes the PCR's value itself: PCR 16 is all zeros after Startup.
    let p = policy_session(&mut tpm, POLICY);
    let pcr_16 = [tpm2b(&[]), pcr_selection(16)].concat();
    assert_eq!(
        policy_command(&mut tpm, TPM_CC_POLICY_PCR, &[p.handle], &pcr_16),
        0
    );
    assert_eq!(
        policy_digest(&mut tpm, p.handle),
        unhex("bff2d58e9813f97cefc14f72ad8133bc7092d652b7c877959254af140c841f36")
    );
    flush(&mut tpm, p.handle);

    // The EK policies (pol_ek_high_range_sha256; the TCG EK Credential Profile's PolicyA and
    // PolicyB for SHA-256): TPM2_PolicySecret(TPM_RH_ENDORSEMENT), then TPM2_PolicyOR of it and
    // of TPM2_PolicyAuthorizeNV of the profile's index 0x01c07f01.
    let policy_a = unhex("837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa");
    let ek_index_attributes = 0x220f_1008; // POLICYWRITE, WRITEALL, *READ, NO_DA, WRITTEN
    let ek_index = nv_policy_name(0x01c0_7f01, ek_index_attributes, &policy_a, 34);
    let policy_c = policy_extend(&[0; 32], TPM_CC_POLICY_AUTHORIZE_NV, &[&ek_index]);
    for kind in [TRIAL, POLICY] {
        let p = policy_session(&mut tpm, kind);
        let secret = secret_params(&[], &[], &[], 0);
        let handles = [TPM_RH_ENDORSEMENT, p.handle];
        let r = policy_command_authorized(&mut tpm, TPM_CC_POLICY_SECRET, &handles, &secret);
        assert!(r.is_ok());
        assert_eq!(policy_digest(&mut tpm, p.handle), policy_a);
        let branches = [&[0, 0, 0, 2][..], &tpm2b(&policy_a), &tpm2b(&policy_c)].concat();
        assert_eq!(
            policy_command(&mut tpm, TPM_CC_POLICY_OR, &[p.handle], &branches),
            0
        );
        assert_eq!(
            policy_digest(&mut tpm, p.handle),
            unhex("ca3d0a99a2b93906f7a3342414efcfb3a385d44cd1fd459089d19b5071c0b7a0")
        );
        flush(&mut tpm, p.handle);
    }
}

#[test]
fn policy_digests_extend_as_part_3_says() {
    use nv::attr::*;
    let mut tpm = started();
    let zeros = [0u8; 32];
    let (x, y) = (sha256(&[b"x"]), sha256(&[b"y"]));
    let key_sign = [&[0, 0x0b][..], &y].concat();
    let null_verified_ticket = [0x80, 0x22, 0x40, 0, 0, 7, 0, 0];
    // Each from a new trial session.
    let cases: [(u32, Vec<u8>, Vec<u8>); 6] = [
        (
            TPM_CC_POLICY_CP_HASH,
            tpm2b(&x),
            policy_extend(&zeros, TPM_CC_POLICY_CP_HASH, &[&x]),
        ),
        (
            TPM_CC_POLICY_NAME_HASH,
            tpm2b(&x),
            policy_extend(&zeros, TPM_CC_POLICY_NAME_HASH, &[&x]),
        ),
        (
            TPM_CC_POLICY_DUPLICATION_SELECT,
            [tpm2b(&x), tpm2b(&y), vec![1]].concat(),
            policy_extend(&zeros, TPM_CC_POLICY_DUPLICATION_SELECT, &[&x, &y, &[1]]),
        ),
        (
            // Without includeObject, the object's Name is left out.
            TPM_CC_POLICY_DUPLICATION_SELECT,
            [tpm2b(&x), tpm2b(&y), vec![0]].concat(),
            policy_extend(&zeros, TPM_CC_POLICY_DUPLICATION_SELECT, &[&y, &[0]]),
        ),
        (
            // A trial takes any branches.
            TPM_CC_POLICY_OR,
            [&[0, 0, 0, 2][..], &tpm2b(&x), &tpm2b(&y)].concat(),
            policy_extend(&zeros, TPM_CC_POLICY_OR, &[&x, &y]),
        ),
        (
            // A trial takes any ticket.
            TPM_CC_POLICY_AUTHORIZE,
            [
                tpm2b(&x),
                tpm2b(b"r"),
                tpm2b(&key_sign),
                null_verified_ticket.to_vec(),
            ]
            .concat(),
            policy_update(&zeros, TPM_CC_POLICY_AUTHORIZE, &key_sign, b"r"),
        ),
    ];
    for (code, params, expected) in cases {
        let digest = trial_digest(&mut tpm, &[(code, params.clone())]);
        assert_eq!(digest, expected, "{code:#x}");
        // TPM2_PolicyOR and TPM2_PolicyAuthorize start over from what they approve.
        if matches!(code, TPM_CC_POLICY_OR | TPM_CC_POLICY_AUTHORIZE) {
            let after = [(TPM_CC_POLICY_AUTH_VALUE, vec![]), (code, params)];
            assert_eq!(trial_digest(&mut tpm, &after), expected, "{code:#x}");
        }
    }

    // Those that name an entity: a key (TPM2_PolicySigned), the owner (TPM2_PolicySecret), an
    // index (TPM2_PolicyNV, TPM2_PolicyAuthorizeNV).
    let key = handle_of(&create_primary(&mut tpm, TPM_RH_OWNER, &hmac_key()));
    let key_name = read_public_name(&mut tpm, key);
    let attributes = OWNERWRITE | OWNERREAD;
    assert_eq!(nv_define(&mut tpm, NV_INDEX, attributes, 34), 0);
    assert_eq!(nv_write(&mut tpm, TPM_RH_OWNER, NV_INDEX, &[0; 34], 0), 0);
    let index_name = nv_name(NV_INDEX, attributes | WRITTEN, 34);
    let t = policy_session(&mut tpm, TRIAL);
    let hmac_signature = [&[0, 5, 0, 0x0b][..], &[0; 32]].concat();
    let signed = [secret_params(&[], &x, b"r", 0), hmac_signature].concat();
    let handles = [key, t.handle];
    assert_eq!(
        policy_command(&mut tpm, TPM_CC_POLICY_SIGNED, &handles, &signed),
        0
    );
    let mut expected = policy_update(&zeros, TPM_CC_POLICY_SIGNED, &key_name, b"r");
    assert_eq!(policy_digest(&mut tpm, t.handle), expected, "PolicySigned");

    let secret = secret_params(&[], &[], b"s", 0);
    let handles = [TPM_RH_OWNER, t.handle];
    assert!(policy_command_authorized(&mut tpm, TPM_CC_POLICY_SECRET, &handles, &secret).is_ok());
    let owner_name = TPM_RH_OWNER.to_be_bytes();
    expected = policy_update(&expected, TPM_CC_POLICY_SECRET, &owner_name, b"s");
    assert_eq!(policy_digest(&mut tpm, t.handle), expected, "PolicySecret");

    // operandB 01 02, offset 3, UNSIGNED_GE: H(operandB ‖ offset ‖ operation), then the Name.
    let nv_params = [&tpm2b(&[1, 2])[..], &[0, 3, 0, 7]].concat();
    let handles = [TPM_RH_OWNER, NV_INDEX, t.handle];
    let r = policy_command_authorized(&mut tpm, TPM_CC_POLICY_NV, &handles, &nv_params);
    assert!(r.is_ok());
    let args = sha256(&[&[1, 2], &[0, 3], &[0, 7]]);
    expected = policy_extend(&expected, TPM_CC_POLICY_NV, &[&args, &index_name]);
    assert_eq!(policy_digest(&mut tpm, t.handle), expected, "PolicyNV");

    let r = policy_command_authorized(&mut tpm, TPM_CC_POLICY_AUTHORIZE_NV, &handles, &[]);
    assert!(r.is_ok());
    expected = policy_extend(&zeros, TPM_CC_POLICY_AUTHORIZE_NV, &[&index_name]);
    assert_eq!(
        policy_digest(&mut tpm, t.handle),
        expected,
        "PolicyAuthorizeNV"
    );

    assert_eq!(
        policy_command(&mut tpm, TPM_CC_POLICY_RESTART, &[t.handle], &[]),
        0
    );
    assert_eq!(policy_digest(&mut tpm, t.handle), zeros);
}

/// An HMAC (SHA-256) signing key of the owner's whose secret the test knows.
fn signing_key(tpm: &mut Tpm, secret: &[u8]) -> u32 {
    let attributes = attr::FIXED_TPM | attr::FIXED_PARENT | attr::USER_WITH_AUTH | attr::SIGN;
    let template = public(8, attributes, &[0, 5, 0, 0x0b], &[0, 0]);
    let p = create_params(b"", secret, &template);
    handle_of(&tpm.process(&command(
        TPM_CC_CREATE_PRIMARY,
        &[TPM_RH_OWNER],
        Some(b""),
        &p,
    )))
}

/// TPM2_PolicySigned with `secret`'s HMAC over aHash = H(nonceTPM ‖ expiration ‖ cpHashA ‖
/// policyRef): its response parameters (timeout, ticket), or the response code.
fn policy_signed(
    tpm: &mut Tpm,
    (key, secret): (u32, &[u8]),
    session: u32,
    nonce: &[u8],
    policy_ref: &[u8],
    expiration: i32,
) -> std::result::Result<Vec<u8>, u32> {
    let a_hash = sha256(&[nonce, &expiration.to_be_bytes(), &[], policy_ref]);
    let signature = [&[0, 5, 0, 0x0b][..], &hmac_sha256(secret, &[&a_hash])].concat();
    let params = [secret_params(nonce, &[], policy_ref, expiration), signature].concat();
    let r = tpm.process(&command(
        TPM_CC_POLICY_SIGNED,
        &[key, session],
        None,
        &params,
    ));
    match rc(&r) {
        0 => Ok(r[10..].to_vec()),
        code => Err(code),
    }
}

#[test]
fn policy_signed_checks_the_signature_nonce_and_expiration() {
    let mut tpm = started();
    let key = signing_key(&mut tpm, b"k");
    let key_name = read_public_name(&mut tpm, key);
    let policy = policy_update(&[0; 32], TPM_CC_POLICY_SIGNED, &key_name, b"");
    let name = policy_index(&mut tpm, NV_INDEX, 0, b"", &policy);
    let index = (NV_INDEX, &name[..]);
    let mut p = policy_session(&mut tpm, POLICY);
    let other = policy_session(&mut tpm, POLICY);

    let nonce = p.nonce_tpm.clone();
    let signed = policy_signed(&mut tpm, (key, b"not k"), p.handle, &nonce, b"", 1);
    assert_eq!(signed, Err(Rc::SIGNATURE.param(5).0));
    let signed = policy_signed(&mut tpm, (key, b"k"), p.handle, &other.nonce_tpm, b"", 1);
    assert_eq!(signed, Err(Rc::NONCE.param(1).0), "another session's nonce");
    // A sequence object signs nothing (CryptValidateSignature: no scheme for TPM_ALG_NULL).
    let r = tpm.process(&command(
        TPM_CC_HASH_SEQUENCE_START,
        &[],
        None,
        &[0, 0, 0, 0x0b],
    ));
    let sequence = handle_of(&r);
    let signed = policy_signed(&mut tpm, (sequence, b""), p.handle, &nonce, b"", 1);
    assert_eq!(signed, Err(Rc::SCHEME.param(5).0));
    assert_eq!(
        policy_digest(&mut tpm, p.handle),
        [0; 32],
        "nothing failed extends"
    );

    // Valid one second from the session's start (bound to its nonce), across a snapshot.
    assert!(policy_signed(&mut tpm, (key, b"k"), p.handle, &nonce, b"", 1).is_ok());
    let mut tpm = Tpm::restore(&tpm.permanent_state(), &tpm.volatile_state()).unwrap();
    let read = nv_read_as(
        &mut tpm,
        index,
        Turn::bound(&mut p, CONTINUE, b""),
        &[0, 8, 0, 0],
    );
    assert!(read.is_ok());
    // The use restarted the session's clock; one second later, the authorization has expired.
    let nonce = p.nonce_tpm.clone();
    assert!(policy_signed(&mut tpm, (key, b"k"), p.handle, &nonce, b"", 1).is_ok());
    tpm.clock.advance(1001);
    let read = nv_read_as(
        &mut tpm,
        index,
        Turn::bound(&mut p, CONTINUE, b""),
        &[0, 8, 0, 0],
    );
    assert_eq!(read, Err(Rc::EXPIRED.session(1).0));
    let signed = policy_signed(&mut tpm, (key, b"k"), p.handle, &nonce, b"", 1);
    assert_eq!(signed, Err(Rc::EXPIRED.param(4).0));
}

/// TPM2_PolicyTicket's parameters, from TPM2_PolicySigned's or TPM2_PolicySecret's response:
/// timeout, cpHashA, policyRef, authName, the ticket.
fn ticket_params(response: &[u8], policy_ref: &[u8], name: &[u8]) -> Vec<u8> {
    let (timeout, ticket) = split2b(response);
    let mut w = Writer::new();
    w.tpm2b(timeout)
        .tpm2b(&[])
        .tpm2b(policy_ref)
        .tpm2b(name)
        .bytes(ticket);
    w.into_bytes()
}

#[test]
fn a_policy_ticket_stands_for_its_authorization_while_it_is_valid() {
    let mut tpm = started();
    let key = signing_key(&mut tpm, b"k");
    let key_name = read_public_name(&mut tpm, key);
    let policy = policy_update(&[0; 32], TPM_CC_POLICY_SIGNED, &key_name, b"r");
    let name = policy_index(&mut tpm, NV_INDEX, 0, b"", &policy);
    let p = policy_session(&mut tpm, POLICY);
    // A negative expiration asks for a ticket; bound to the nonce, it lasts across a TPM Reset
    // (a minute from the session's start); unbound, it expires at the next one.
    let bound = policy_signed(&mut tpm, (key, b"k"), p.handle, &p.nonce_tpm, b"r", -60).unwrap();
    let unbound = policy_signed(&mut tpm, (key, b"k"), p.handle, &[], b"r", -60).unwrap();
    // TPMT_TK_AUTH: TPM_ST_AUTH_SIGNED for the owner.
    let (timeout, ticket) = split2b(&unbound);
    assert_eq!(ticket[..6], [0x80, 0x25, 0x40, 0, 0, 1]);
    assert!(timeout[0] & 0x80 != 0, "expires at the next TPM Reset");
    let bound = ticket_params(&bound, b"r", &key_name);
    let unbound = ticket_params(&unbound, b"r", &key_name);

    let mut q = policy_session(&mut tpm, POLICY);
    let use_ticket = |tpm: &mut Tpm, session: u32, params: &[u8]| {
        policy_command(tpm, TPM_CC_POLICY_TICKET, &[session], params)
    };
    for params in [&bound, &unbound] {
        assert_eq!(use_ticket(&mut tpm, q.handle, params), 0);
        assert_eq!(policy_digest(&mut tpm, q.handle), policy);
        let turn = Turn::bound(&mut q, CONTINUE, b"");
        assert!(nv_read_as(&mut tpm, (NV_INDEX, &name), turn, &[0, 8, 0, 0]).is_ok());
    }
    // Tampered with: its digest, its hierarchy, the expiration bit stripped, another policyRef.
    let ticket_error = Rc::TICKET.param(5).0;
    let mut digest = bound.clone();
    *digest.last_mut().unwrap() ^= 1;
    let mut hierarchy = bound.clone();
    let at = hierarchy.len() - 2 - 64 - 4;
    hierarchy[at..at + 4].copy_from_slice(&TPM_RH_ENDORSEMENT.to_be_bytes());
    let mut no_expiration = unbound.clone();
    no_expiration[2] &= 0x7f;
    let other_ref = ticket_params(
        &policy_signed(&mut tpm, (key, b"k"), p.handle, &p.nonce_tpm, b"x", -60).unwrap(),
        b"r",
        &key_name,
    );
    for params in [&digest, &hierarchy, &no_expiration, &other_ref] {
        assert_eq!(use_ticket(&mut tpm, q.handle, params), ticket_error);
    }
    // A trial session takes no ticket.
    let t = policy_session(&mut tpm, TRIAL);
    assert_eq!(
        use_ticket(&mut tpm, t.handle, &bound),
        Rc::ATTRIBUTES.handle(1).0
    );

    // After a TPM Reset, no ticket from before is valid: TPM time started over.
    let mut tpm = power_cycle(&tpm, 0);
    let q = policy_session(&mut tpm, POLICY);
    for params in [&bound, &unbound] {
        assert_eq!(use_ticket(&mut tpm, q.handle, params), ticket_error);
    }
}

#[test]
fn policy_or_needs_a_branch_that_matches() {
    let mut tpm = started();
    let p = policy_session(&mut tpm, POLICY);
    let or = |branches: &[&[u8]]| {
        let mut w = Writer::new();
        w.u32(branches.len() as u32);
        branches.iter().for_each(|b| {
            w.tpm2b(b);
        });
        w.into_bytes()
    };
    let (zeros, other) = ([0; 32], sha256(&[b"x"]));
    let refused = policy_command(
        &mut tpm,
        TPM_CC_POLICY_OR,
        &[p.handle],
        &or(&[&other, &other]),
    );
    assert_eq!(refused, Rc::VALUE.param(1).0);
    assert_eq!(
        policy_command(&mut tpm, TPM_CC_POLICY_OR, &[p.handle], &or(&[&other])),
        Rc::SIZE.param(1).0,
        "one branch"
    );
    assert_eq!(
        policy_command(
            &mut tpm,
            TPM_CC_POLICY_OR,
            &[p.handle],
            &or(&[&other, &zeros])
        ),
        0
    );
}

#[test]
fn the_admin_role_needs_a_policy_bound_to_the_command() {
    use nv::attr::*;
    let mut tpm = started();
    // Owner-readable indices whose authPolicy is: the empty policy; PolicyCommandCode of
    // TPM2_NV_ChangeAuth; and of TPM2_NV_Read.
    let code = |cc: u32| policy_extend(&[0; 32], TPM_CC_POLICY_COMMAND_CODE, &[&cc.to_be_bytes()]);
    let policies = [
        vec![0; 32],
        code(TPM_CC_NV_CHANGE_AUTH),
        code(TPM_CC_NV_READ),
    ];
    let names: Vec<Vec<u8>> = (0..3)
        .map(|i| {
            let attributes = OWNERWRITE | OWNERREAD;
            assert_eq!(
                nv_define_with(
                    &mut tpm,
                    NV_INDEX + i,
                    attributes,
                    8,
                    b"",
                    &policies[i as usize]
                ),
                0
            );
            nv_policy_name(NV_INDEX + i, attributes, &policies[i as usize], 8)
        })
        .collect();
    let mut p = policy_session(&mut tpm, POLICY);
    let mut change_auth = |tpm: &mut Tpm, i: u32, command_code: Option<u32>| {
        if let Some(cc) = command_code {
            let params = cc.to_be_bytes();
            assert_eq!(
                policy_command(tpm, TPM_CC_POLICY_COMMAND_CODE, &[p.handle], &params),
                0
            );
        }
        let turns = &mut [Turn::bound(&mut p, CONTINUE, b"")];
        let names = [names[i as usize].clone()];
        let r = call_named(
            tpm,
            TPM_CC_NV_CHANGE_AUTH,
            &[NV_INDEX + i],
            &names,
            turns,
            &tpm2b(b""),
        );
        r.err()
    };
    let policy_fail = Some(Rc::POLICY_FAIL.session(1).0);
    assert_eq!(
        change_auth(&mut tpm, 0, None),
        policy_fail,
        "not bound to a command"
    );
    assert_eq!(change_auth(&mut tpm, 1, Some(TPM_CC_NV_CHANGE_AUTH)), None);
    let wrong = change_auth(&mut tpm, 2, Some(TPM_CC_NV_READ));
    assert_eq!(
        wrong,
        Some(Rc::POLICY_CC.session(1).0),
        "bound to another command"
    );

    // One command only, one the TPM implements.
    let q = policy_session(&mut tpm, POLICY);
    let command_code = |tpm: &mut Tpm, cc: u32| {
        policy_command(
            tpm,
            TPM_CC_POLICY_COMMAND_CODE,
            &[q.handle],
            &cc.to_be_bytes(),
        )
    };
    assert_eq!(command_code(&mut tpm, 0x1ff), Rc::POLICY_CC.param(1).0);
    assert_eq!(command_code(&mut tpm, TPM_CC_NV_READ), 0);
    assert_eq!(command_code(&mut tpm, TPM_CC_NV_READ), 0);
    assert_eq!(
        command_code(&mut tpm, TPM_CC_NV_WRITE),
        Rc::VALUE.param(1).0
    );
}

/// TPM2_SetPrimaryPolicy of the owner: a SHA-256 `policy`.
fn set_owner_policy(tpm: &mut Tpm, policy: &[u8]) {
    let params = [tpm2b(policy), alg::TPM_ALG_SHA256.to_be_bytes().to_vec()].concat();
    let c = command(
        TPM_CC_SET_PRIMARY_POLICY,
        &[TPM_RH_OWNER],
        Some(b""),
        &params,
    );
    assert_eq!(rc(&tpm.process(&c)), 0);
}

#[test]
fn a_cp_hash_or_name_hash_binds_the_policy_to_the_command() {
    use nv::attr::*;
    let mut tpm = started();
    // Two indices the owner reads, through its policy (its Name is not its policy's).
    let attributes = OWNERWRITE | OWNERREAD;
    let names: Vec<Vec<u8>> = [NV_INDEX, NV_INDEX + 1]
        .into_iter()
        .map(|index| {
            assert_eq!(nv_define(&mut tpm, index, attributes, 8), 0);
            assert_eq!(nv_write(&mut tpm, TPM_RH_OWNER, index, &[1; 8], 0), 0);
            nv_name(index, attributes | WRITTEN, 8)
        })
        .collect();
    let owner = TPM_RH_OWNER.to_be_bytes().to_vec();
    let mut p = policy_session(&mut tpm, POLICY);
    // A policy command, then TPM2_NV_Read of index `i` authorized by the owner's policy.
    let mut read = |tpm: &mut Tpm, (code, bound): (u32, &[u8]), i: usize, params: &[u8]| {
        policy_restart(tpm, p.handle);
        assert_eq!(policy_command(tpm, code, &[p.handle], &tpm2b(bound)), 0);
        let handles = [TPM_RH_OWNER, NV_INDEX + i as u32];
        let names = [owner.clone(), names[i].clone()];
        let turns = &mut [Turn::bound(&mut p, CONTINUE, b"")];
        call_named(tpm, TPM_CC_NV_READ, &handles, &names, turns, params).err()
    };
    let policy_fail = Some(Rc::POLICY_FAIL.session(1).0);

    // PolicyCpHash: the command, its handles' Names and its parameters.
    let cp_hash = sha256(&[
        &TPM_CC_NV_READ.to_be_bytes(),
        &owner,
        &names[0],
        &[0, 8, 0, 0],
    ]);
    let cp = (TPM_CC_POLICY_CP_HASH, &cp_hash[..]);
    set_owner_policy(&mut tpm, &policy_extend(&[0; 32], cp.0, &[&cp_hash]));
    assert_eq!(read(&mut tpm, cp, 0, &[0, 8, 0, 0]), None);
    assert_eq!(
        read(&mut tpm, cp, 0, &[0, 4, 0, 0]),
        policy_fail,
        "other parameters"
    );
    assert_eq!(
        read(&mut tpm, cp, 1, &[0, 8, 0, 0]),
        policy_fail,
        "another index"
    );

    // PolicyNameHash: the handles' Names only.
    let name_hash = sha256(&[&owner, &names[0]]);
    let nh = (TPM_CC_POLICY_NAME_HASH, &name_hash[..]);
    set_owner_policy(&mut tpm, &policy_extend(&[0; 32], nh.0, &[&name_hash]));
    assert_eq!(read(&mut tpm, nh, 0, &[0, 4, 0, 0]), None);
    assert_eq!(
        read(&mut tpm, nh, 1, &[0, 8, 0, 0]),
        policy_fail,
        "another index"
    );

    // A session binds to one cpHash, or one Names hash, of the session's digest size.
    let q = policy_session(&mut tpm, POLICY);
    let bind = |tpm: &mut Tpm, code: u32, digest: &[u8]| {
        policy_command(tpm, code, &[q.handle], &tpm2b(digest))
    };
    assert_eq!(bind(&mut tpm, cp.0, &[0; 20]), Rc::SIZE.param(1).0);
    assert_eq!(bind(&mut tpm, cp.0, &cp_hash), 0);
    assert_eq!(bind(&mut tpm, cp.0, &cp_hash), 0, "the same again");
    assert_eq!(bind(&mut tpm, cp.0, &name_hash), Rc::CPHASH.0);
    assert_eq!(bind(&mut tpm, nh.0, &name_hash), Rc::CPHASH.0);
    let template = TPM_CC_POLICY_TEMPLATE;
    assert_eq!(bind(&mut tpm, template, &name_hash), Rc::CPHASH.0);
    // Reject a template that differs from the existing binding.
    let r = policy_session(&mut tpm, POLICY);
    let bind = |tpm: &mut Tpm, code: u32, digest: &[u8]| {
        policy_command(tpm, code, &[r.handle], &tpm2b(digest))
    };
    assert_eq!(bind(&mut tpm, template, &cp_hash), 0);
    assert_eq!(bind(&mut tpm, template, &name_hash), Rc::VALUE.param(1).0);
    assert_eq!(bind(&mut tpm, cp.0, &cp_hash), Rc::CPHASH.0);
}

#[test]
fn policy_pcr_fails_once_a_pcr_changes() {
    let mut tpm = started();
    // PCR 0 (a change to PCR 16, in the TCB group, is not counted). An update counter of 0
    // records nothing in the session (PolicyPCR, CheckPolicyAuthSession): count one first.
    let pcr_0 = [tpm2b(&[]), pcr_selection(0)].concat();
    assert_eq!(
        rc(&tpm.process(&extend(1, alg::TPM_ALG_SHA256, &[1; 32]))),
        0
    );
    let zero_pcr = sha256(&[&[0; 32]]);
    let policy = policy_extend(&[0; 32], TPM_CC_POLICY_PCR, &[&pcr_selection(0), &zero_pcr]);
    let name = policy_index(&mut tpm, NV_INDEX, 0, b"", &policy);
    let mut p = policy_session(&mut tpm, POLICY);
    let pcr = |tpm: &mut Tpm, session: u32, params: &[u8]| {
        policy_command(tpm, TPM_CC_POLICY_PCR, &[session], params)
    };
    let wrong = [tpm2b(&sha256(&[b"x"])), pcr_selection(0)].concat();
    assert_eq!(pcr(&mut tpm, p.handle, &wrong), Rc::VALUE.param(1).0);
    assert_eq!(pcr(&mut tpm, p.handle, &pcr_0), 0);
    assert_eq!(
        rc(&tpm.process(&extend(0, alg::TPM_ALG_SHA256, &[1; 32]))),
        0
    );
    let turn = Turn::bound(&mut p, CONTINUE, b"");
    let read = nv_read_as(&mut tpm, (NV_INDEX, &name), turn, &[0, 8, 0, 0]);
    assert_eq!(read, Err(Rc::PCR_CHANGED.0));
    // Nor may the session assert the PCRs again.
    assert_eq!(pcr(&mut tpm, p.handle, &pcr_0), Rc::PCR_CHANGED.0);
}

#[test]
fn locality_physical_presence_and_policy_secret_are_enforced() {
    let mut tpm = started();
    let mut p = policy_session(&mut tpm, POLICY);
    // An index for each policy: TPM2_PolicyLocality(locality 0), (locality 1), and
    // TPM2_PolicyPhysicalPresence.
    let steps = [
        (TPM_CC_POLICY_LOCALITY, vec![1]),
        (TPM_CC_POLICY_LOCALITY, vec![2]),
        (TPM_CC_POLICY_PHYSICAL_PRESENCE, vec![]),
    ];
    let expected = [None, Some(Rc::LOCALITY.0), Some(Rc::PP.0)];
    for (i, ((code, params), expected)) in steps.into_iter().zip(expected).enumerate() {
        let index = NV_INDEX + i as u32;
        let policy = policy_extend(&[0; 32], code, &[&params]);
        let name = policy_index(&mut tpm, index, 0, b"", &policy);
        policy_restart(&mut tpm, p.handle);
        assert_eq!(policy_command(&mut tpm, code, &[p.handle], &params), 0);
        let turn = Turn::bound(&mut p, CONTINUE, b"");
        let read = nv_read_as(&mut tpm, (index, &name), turn, &[0, 8, 0, 0]);
        assert_eq!(read.err(), expected, "{code:#x} {params:?}");
    }
    // Localities narrow, and do not mix TPMA_LOCALITY bits with an extended locality.
    let q = policy_session(&mut tpm, POLICY);
    let locality =
        |tpm: &mut Tpm, l: u8| policy_command(tpm, TPM_CC_POLICY_LOCALITY, &[q.handle], &[l]);
    let range = Rc::RANGE.param(1).0;
    assert_eq!(locality(&mut tpm, 0), range);
    assert_eq!(locality(&mut tpm, 0b011), 0);
    assert_eq!(locality(&mut tpm, 0b100), range, "nothing left");
    assert_eq!(locality(&mut tpm, 0x40), range, "an extended locality");
    flush(&mut tpm, q.handle);

    // A policy session authorizing TPM2_PolicySecret must prove the authValue (TPM_RC_MODE).
    let policy = policy_extend(&[0; 32], TPM_CC_POLICY_AUTH_VALUE, &[]);
    let index = NV_INDEX + 3;
    let name = policy_index(&mut tpm, index, 0, b"pw", &policy);
    let target = policy_session(&mut tpm, POLICY);
    let handles = [index, target.handle];
    let names = [name.clone(), name_of(target.handle)];
    let secret = secret_params(&[], &[], &[], 0);
    let mut s = policy_session(&mut tpm, POLICY);
    let turns = &mut [Turn::bound(&mut s, CONTINUE, b"pw")];
    let r = call_named(
        &mut tpm,
        TPM_CC_POLICY_SECRET,
        &handles,
        &names,
        turns,
        &secret,
    );
    assert_eq!(r.err(), Some(Rc::MODE.session(1).0));
    assert_eq!(
        policy_command(&mut tpm, TPM_CC_POLICY_AUTH_VALUE, &[s.handle], &[]),
        0
    );
    let turns = &mut [Turn::authorizing(&mut s, CONTINUE, b"pw")];
    assert!(
        call_named(
            &mut tpm,
            TPM_CC_POLICY_SECRET,
            &handles,
            &names,
            turns,
            &secret
        )
        .is_ok()
    );
    let expected = policy_update(&[0; 32], TPM_CC_POLICY_SECRET, &name, b"");
    assert_eq!(policy_digest(&mut tpm, target.handle), expected);
}

/// The Name of a session's handle: the handle.
fn name_of(handle: u32) -> Vec<u8> {
    handle.to_be_bytes().to_vec()
}

#[test]
fn policy_auth_value_and_password_prove_the_auth_value() {
    use nv::attr::*;
    let mut tpm = started();
    let policy = policy_extend(&[0; 32], TPM_CC_POLICY_AUTH_VALUE, &[]);
    // Not noDA: a wrong authValue counts against the dictionary-attack protection.
    let name = policy_index(&mut tpm, NV_INDEX, 0, b"pw", &policy);
    let index = (NV_INDEX, &name[..]);
    let mut p = policy_session(&mut tpm, POLICY);
    let read_8 = [0, 8, 0, 0];
    let auth_fail = Err(Rc::AUTH_FAIL.session(1).0);
    let failures = |tpm: &mut Tpm| property(tpm, 0x20e); // TPM_PT_LOCKOUT_COUNTER

    // TPM2_PolicyAuthValue: the HMAC keyed with the authValue.
    for (auth, expected) in [(&b"pw"[..], Ok(())), (b"no", auth_fail)] {
        let code = TPM_CC_POLICY_AUTH_VALUE;
        policy_restart(&mut tpm, p.handle);
        assert_eq!(policy_command(&mut tpm, code, &[p.handle], &[]), 0);
        let turn = Turn::authorizing(&mut p, CONTINUE, auth);
        let read = nv_read_as(&mut tpm, index, turn, &read_8);
        assert_eq!(read.map(|_| ()), expected);
    }
    assert_eq!(failures(&mut tpm), 1);
    // TPM2_PolicyPassword: the authValue in clear, and no HMAC in the response.
    for (auth, expected) in [(&b"pw"[..], Ok(())), (b"no", auth_fail)] {
        let code = TPM_CC_POLICY_PASSWORD;
        policy_restart(&mut tpm, p.handle);
        assert_eq!(policy_command(&mut tpm, code, &[p.handle], &[]), 0);
        let turn = Turn::password(&mut p, CONTINUE, auth);
        let read = nv_read_as(&mut tpm, index, turn, &read_8);
        assert_eq!(read.map(|_| ()), expected);
    }
    assert_eq!(failures(&mut tpm), 2);
    // Without either, the policy's digest does not match.
    policy_restart(&mut tpm, p.handle);
    let turn = Turn::bound(&mut p, CONTINUE, b"pw");
    let read = nv_read_as(&mut tpm, index, turn, &read_8);
    assert_eq!(read, Err(Rc::POLICY_FAIL.session(1).0));

    // A PIN pass index counts the successes through a policy session too (noDA: a failure is
    // TPM_RC_BAD_AUTH, and not counted).
    let pass = NV_INDEX + 1;
    let pin_pass = NO_DA | 9 << TPM_NT_SHIFT;
    let name = policy_index(&mut tpm, pass, pin_pass, b"pin", &policy);
    let mut pin_read = |tpm: &mut Tpm, auth: &[u8]| {
        let code = TPM_CC_POLICY_PASSWORD;
        policy_restart(tpm, p.handle);
        assert_eq!(policy_command(tpm, code, &[p.handle], &[]), 0);
        let turn = Turn::password(&mut p, CONTINUE, auth);
        nv_read_as(tpm, (pass, &name), turn, &[0, 4, 0, 0])
    };
    assert_eq!(pin_read(&mut tpm, b"pin"), Ok(vec![0, 0, 0, 1]));
    assert_eq!(pin_read(&mut tpm, b"no"), Err(Rc::BAD_AUTH.session(1).0));
    assert_eq!(pin_read(&mut tpm, b"pin"), Ok(vec![0, 0, 0, 2]));
    assert_eq!(failures(&mut tpm), 2);
}

// Attestation, credentials, duplication and symmetric encryption.

/// An unrestricted ECDSA (SHA-256) signing key, primary in `hierarchy`.
fn ecdsa_key(tpm: &mut Tpm, hierarchy: u32) -> u32 {
    let template = ecc_key(ORDINARY | attr::SIGN, &[0, 0x18, 0, 0x0b]);
    handle_of(&create_primary(tpm, hierarchy, &template))
}

/// The TPM2B_ATTEST of an attestation's response, once TPM2_VerifySignature has checked the
/// TPMT_SIGNATURE that follows it with `key`.
fn signed_attest(tpm: &mut Tpm, response: &[u8], key: u32) -> Vec<u8> {
    assert_eq!(rc(response), 0);
    let (attest, signature) = split2b(response_params(response, false));
    let mut p = Writer::new();
    p.tpm2b(&sha256(&[attest])).bytes(signature);
    let verify = command(TPM_CC_VERIFY_SIGNATURE, &[key], None, &p.into_bytes());
    assert_eq!(rc(&tpm.process(&verify)), 0, "the signature verifies");
    attest.to_vec()
}

/// The fields of a TPMS_ATTEST.
struct Attest {
    kind: u16,
    signer: Vec<u8>,
    extra: Vec<u8>,
    reset_count: u32,
    restart_count: u32,
    firmware: u64,
    attested: Vec<u8>,
}

fn parse_attest(attest: &[u8]) -> Attest {
    let mut r = Reader::new(attest);
    assert_eq!(r.u32().unwrap(), 0xff54_4347, "TPM_GENERATED_VALUE");
    let kind = r.u16().unwrap();
    let signer = r.tpm2b(MAX_NAME).unwrap().to_vec();
    let extra = r.tpm2b(64).unwrap().to_vec();
    let _clock = r.u64().unwrap();
    let reset_count = r.u32().unwrap();
    let restart_count = r.u32().unwrap();
    let _safe = r.u8().unwrap();
    let firmware = r.u64().unwrap();
    Attest {
        kind,
        signer,
        extra,
        reset_count,
        restart_count,
        firmware,
        attested: r.rest().to_vec(),
    }
}

#[test]
fn quotes_and_certifications_are_signed_and_identify_endorsement_keys_only() {
    use crate::capability::FIRMWARE_VERSION;
    let mut tpm = started();
    let pcr0 = read_sha256(&mut tpm, 0).1;
    let quote = |key: u32| {
        let mut p = Writer::new();
        p.tpm2b(b"nonce")
            .u16(alg::TPM_ALG_NULL)
            .bytes(&pcr_selection(0));
        command(TPM_CC_QUOTE, &[key], Some(b""), &p.into_bytes())
    };
    for hierarchy in [TPM_RH_ENDORSEMENT, TPM_RH_OWNER] {
        let key = ecdsa_key(&mut tpm, hierarchy);
        let r = tpm.process(&quote(key));
        let quoted = parse_attest(&signed_attest(&mut tpm, &r, key));
        assert_eq!(quoted.kind, 0x8018);
        assert_eq!(quoted.extra, b"nonce");
        let digest = sha256(&[&pcr0]);
        assert_eq!(quoted.attested, [pcr_selection(0), tpm2b(&digest)].concat());
        // TPM2_Certify of the key, by itself (its ADMIN role takes its authValue).
        let mut p = Writer::new();
        p.tpm2b(b"").u16(alg::TPM_ALG_NULL);
        let certify = command_with(TPM_CC_CERTIFY, &[key, key], &[b"", b""], &p.into_bytes());
        let r = tpm.process(&certify);
        let certified = parse_attest(&signed_attest(&mut tpm, &r, key));
        assert_eq!(certified.kind, 0x8017);
        let (name, qualified_name) = split2b(&certified.attested);
        assert_eq!(name, read_public_name(&mut tpm, key));
        assert_eq!(split2b(qualified_name).0, quoted.signer);
        // Outside the endorsement and platform hierarchies, the counters and the firmware
        // version are offset by KDFa(SHA-512, shProof, "OBFUSCATE", qualifiedSigner).
        let (reset, restart) = (tpm.permanent.reset_count, tpm.volatile.restart_count);
        let (mut firmware, mut reset_count, mut restart_count) = (FIRMWARE_VERSION, reset, restart);
        if hierarchy == TPM_RH_OWNER {
            let proof = tpm.permanent.hierarchies.sh_proof.as_slice();
            let mask = crate::crypt::kdfa(
                alg::Hash::Sha512,
                proof,
                b"OBFUSCATE",
                &quoted.signer,
                &[],
                16,
            );
            let low = u64::from_le_bytes(mask[..8].try_into().unwrap());
            let high = u64::from_le_bytes(mask[8..].try_into().unwrap());
            firmware = firmware.wrapping_add(low);
            reset_count = reset_count.wrapping_add((high >> 32) as u32);
            restart_count = restart_count.wrapping_add(high as u32);
        }
        for attest in [&quoted, &certified] {
            assert_eq!(
                (attest.firmware, attest.reset_count, attest.restart_count),
                (firmware, reset_count, restart_count),
                "hierarchy {hierarchy:#x}"
            );
        }
        assert_eq!(hierarchy == TPM_RH_OWNER, firmware != FIRMWARE_VERSION);
        flush(&mut tpm, key);
    }
    // TPM_RH_NULL signs with no scheme, so has no hash to quote with (as libtpms answers).
    assert_eq!(rc(&tpm.process(&quote(TPM_RH_NULL))), Rc::SCHEME.param(2).0);
}

#[test]
fn certify_creation_takes_only_the_ticket_of_the_object() {
    let mut tpm = started();
    let key = ecdsa_key(&mut tpm, TPM_RH_OWNER);
    // TPM2_CreatePrimary: the object, its creationHash and its TPMT_TK_CREATION.
    let mut create = |template: &[u8]| {
        let r = create_primary(&mut tpm, TPM_RH_OWNER, template);
        let (_public, rest) = split2b(response_params(&r, true));
        let (_creation_data, rest) = split2b(rest);
        let (creation_hash, rest) = split2b(rest);
        let ticket_size = 6 + 2 + split2b(&rest[6..]).0.len();
        let ticket = rest[..ticket_size].to_vec();
        (handle_of(&r), creation_hash.to_vec(), ticket)
    };
    let (object, creation_hash, ticket) = create(&ecc_srk());
    let (other, _, _) = create(&hmac_key());
    let certify_creation = |object: u32| {
        let mut p = Writer::new();
        p.tpm2b(b"")
            .tpm2b(&creation_hash)
            .u16(alg::TPM_ALG_NULL)
            .bytes(&ticket);
        let handles = [key, object];
        command(
            TPM_CC_CERTIFY_CREATION,
            &handles,
            Some(b""),
            &p.into_bytes(),
        )
    };
    let r = tpm.process(&certify_creation(object));
    let attest = parse_attest(&signed_attest(&mut tpm, &r, key));
    assert_eq!(attest.kind, 0x801a);
    let name = read_public_name(&mut tpm, object);
    assert_eq!(
        attest.attested,
        [tpm2b(&name), tpm2b(&creation_hash)].concat()
    );
    assert_eq!(
        rc(&tpm.process(&certify_creation(other))),
        Rc::TICKET.param(4).0
    );
}

#[test]
fn a_credential_activates_only_for_the_object_it_names() {
    let mut tpm = started();
    let ek = handle_of(&create_primary(&mut tpm, TPM_RH_ENDORSEMENT, &ecc_srk()));
    let object = ecdsa_key(&mut tpm, TPM_RH_OWNER);
    let other = handle_of(&create_primary(&mut tpm, TPM_RH_OWNER, &hmac_key()));
    let mut p = Writer::new();
    p.tpm2b(b"the credential")
        .tpm2b(&read_public_name(&mut tpm, object));
    let make = command(TPM_CC_MAKE_CREDENTIAL, &[ek], None, &p.into_bytes());
    let r = tpm.process(&make);
    assert_eq!(rc(&r), 0);
    let (blob, rest) = split2b(&r[10..]);
    let (secret, _) = split2b(rest);
    let mut activate = |object: u32| {
        let mut p = Writer::new();
        p.tpm2b(blob).tpm2b(secret);
        let handles = [object, ek];
        let c = command_with(
            TPM_CC_ACTIVATE_CREDENTIAL,
            &handles,
            &[b"", b""],
            &p.into_bytes(),
        );
        tpm.process(&c)
    };
    let r = activate(object);
    assert_eq!(rc(&r), 0);
    assert_eq!(split2b(response_params(&r, false)).0, b"the credential");
    assert_eq!(rc(&activate(other)), Rc::INTEGRITY.param(1).0);
}

/// TPMT_SYM_DEF_OBJECT: AES-128-CFB, and TPM_ALG_NULL.
const AES128_CFB: &[u8] = &[0, 6, 0, 0x80, 0, 0x43];
const NO_SYMMETRIC: &[u8] = &[0, 0x10];

/// A sealed data object (with `attributes` too) whose policy lets a policy session duplicate
/// it: TPM2_PolicyCommandCode(TPM2_Duplicate).
fn duplicable(attributes: u32) -> Vec<u8> {
    let code = TPM_CC_DUPLICATE.to_be_bytes();
    let policy = policy_extend(&[0; 32], TPM_CC_POLICY_COMMAND_CODE, &[&code]);
    let mut w = Writer::new();
    w.u16(8)
        .u16(alg::TPM_ALG_SHA256)
        .u32(attr::USER_WITH_AUTH | attributes)
        .tpm2b(&policy)
        .u16(alg::TPM_ALG_NULL)
        .u16(0);
    w.into_bytes()
}

/// TPM2_Load of a child of `parent`.
fn load_child(tpm: &mut Tpm, parent: u32, private: &[u8], public: &[u8]) -> u32 {
    let mut p = Writer::new();
    p.tpm2b(private).tpm2b(public);
    handle_of(&tpm.process(&command(TPM_CC_LOAD, &[parent], Some(b""), &p.into_bytes())))
}

/// TPM2_Create of `template` under `parent` with `data`, then TPM2_Load: the object's handle
/// and its TPMT_PUBLIC.
fn create_loaded_child(tpm: &mut Tpm, parent: u32, template: &[u8], data: &[u8]) -> (u32, Vec<u8>) {
    let p = create_params(b"", data, template);
    let r = tpm.process(&command(TPM_CC_CREATE, &[parent], Some(b""), &p));
    assert_eq!(rc(&r), 0);
    let (private, rest) = split2b(response_params(&r, false));
    let public = split2b(rest).0.to_vec();
    (load_child(tpm, parent, private, &public), public)
}

/// TPM2_Unseal of `object`: the data.
fn unseal(tpm: &mut Tpm, object: u32) -> Vec<u8> {
    let r = tpm.process(&command(TPM_CC_UNSEAL, &[object], Some(b""), &[]));
    assert_eq!(rc(&r), 0);
    split2b(response_params(&r, false)).0.to_vec()
}

/// What TPM2_Duplicate answers: encryptionKeyOut, duplicate, outSymSeed.
type Duplicate = (Vec<u8>, Vec<u8>, Vec<u8>);

/// TPM2_Duplicate of `object` for `new_parent`, its policy satisfied, with a key the TPM
/// picks if `symmetric` is not TPM_ALG_NULL.
fn duplicate(
    tpm: &mut Tpm,
    object: u32,
    new_parent: u32,
    symmetric: &[u8],
) -> std::result::Result<Duplicate, u32> {
    let mut s = policy_session(tpm, POLICY);
    let code = TPM_CC_DUPLICATE.to_be_bytes();
    assert_eq!(
        policy_command(tpm, TPM_CC_POLICY_COMMAND_CODE, &[s.handle], &code),
        0
    );
    let mut p = Writer::new();
    p.tpm2b(&[]).bytes(symmetric);
    let turns = &mut [Turn::bound(&mut s, CONTINUE, b"")];
    let reply = call(
        tpm,
        TPM_CC_DUPLICATE,
        &[object, new_parent],
        turns,
        &p.into_bytes(),
    );
    flush(tpm, s.handle);
    let reply = reply?;
    let (key, rest) = split2b(&reply.params);
    let (duplicate, rest) = split2b(rest);
    Ok((key.to_vec(), duplicate.to_vec(), split2b(rest).0.to_vec()))
}

/// TPM2_Import of `duplicate` (an object whose public area is `public`) under `parent`: the
/// TPM2B_PRIVATE TPM2_Load takes.
fn import(
    tpm: &mut Tpm,
    parent: u32,
    public: &[u8],
    (key, duplicate, seed): &Duplicate,
    symmetric: &[u8],
) -> std::result::Result<Vec<u8>, u32> {
    let mut p = Writer::new();
    p.tpm2b(key)
        .tpm2b(public)
        .tpm2b(duplicate)
        .tpm2b(seed)
        .bytes(symmetric);
    let r = tpm.process(&command(
        TPM_CC_IMPORT,
        &[parent],
        Some(b""),
        &p.into_bytes(),
    ));
    match rc(&r) {
        0 => Ok(split2b(response_params(&r, false)).0.to_vec()),
        code => Err(code),
    }
}

#[test]
fn a_duplicate_imports_and_loads_under_its_new_parent() {
    let mut tpm = started();
    let srk = handle_of(&create_primary(&mut tpm, TPM_RH_OWNER, &ecc_srk()));
    let new_parent = handle_of(&create_primary(&mut tpm, TPM_RH_ENDORSEMENT, &ecc_srk()));
    let (object, public) = create_loaded_child(&mut tpm, srk, &duplicable(0), b"moved");
    // Wrapped inside (with a key the TPM picks) and outside (for the new parent), or neither.
    let wrapped = duplicate(&mut tpm, object, new_parent, AES128_CFB).unwrap();
    assert_eq!(wrapped.0.len(), 16);
    let bare = duplicate(&mut tpm, object, TPM_RH_NULL, NO_SYMMETRIC).unwrap();
    assert!(bare.0.is_empty() && bare.2.is_empty());
    // Only a storage key is a new parent: not the sealed object itself.
    assert_eq!(
        duplicate(&mut tpm, object, object, NO_SYMMETRIC),
        Err(Rc::TYPE.handle(2).0)
    );
    flush(&mut tpm, object);
    for (dup, symmetric) in [(&wrapped, AES128_CFB), (&bare, NO_SYMMETRIC)] {
        let private = import(&mut tpm, new_parent, &public, dup, symmetric).unwrap();
        let copy = load_child(&mut tpm, new_parent, &private, &public);
        assert_eq!(unseal(&mut tpm, copy), b"moved");
        flush(&mut tpm, copy);
    }
    // Wrapped for the new parent: the old one cannot unwrap it.
    assert_eq!(
        import(&mut tpm, srk, &public, &wrapped, AES128_CFB),
        Err(Rc::INTEGRITY.param(3).0)
    );
    // An object that may not leave its TPM, or its parent, is never imported.
    for fixed in [attr::FIXED_TPM, attr::FIXED_PARENT] {
        assert_eq!(
            import(&mut tpm, srk, &duplicable(fixed), &bare, NO_SYMMETRIC),
            Err(Rc::ATTRIBUTES.param(2).0)
        );
    }
    // Its public area alone: no policy for the DUP role.
    let mut p = Writer::new();
    p.tpm2b(&[]).tpm2b(&public).u32(TPM_RH_OWNER);
    let load = command(TPM_CC_LOAD_EXTERNAL, &[], None, &p.into_bytes());
    let external = handle_of(&tpm.process(&load));
    assert_eq!(
        duplicate(&mut tpm, external, new_parent, AES128_CFB),
        Err(Rc::AUTH_UNAVAILABLE.0)
    );
}

#[test]
fn encrypted_duplication_takes_both_wraps() {
    let mut tpm = started();
    let srk = handle_of(&create_primary(&mut tpm, TPM_RH_OWNER, &ecc_srk()));
    let new_parent = handle_of(&create_primary(&mut tpm, TPM_RH_ENDORSEMENT, &ecc_srk()));
    let template = duplicable(attr::ENCRYPTED_DUPLICATION);
    let (object, public) = create_loaded_child(&mut tpm, srk, &template, b"moved");
    assert_eq!(
        duplicate(&mut tpm, object, new_parent, NO_SYMMETRIC),
        Err(Rc::SYMMETRIC.param(2).0)
    );
    assert_eq!(
        duplicate(&mut tpm, object, TPM_RH_NULL, AES128_CFB),
        Err(Rc::HIERARCHY.handle(2).0)
    );
    let wrapped = duplicate(&mut tpm, object, new_parent, AES128_CFB).unwrap();
    let (key, dup, seed) = &wrapped;
    let no_inner = (Vec::new(), dup.clone(), seed.clone());
    assert_eq!(
        import(&mut tpm, new_parent, &public, &no_inner, NO_SYMMETRIC),
        Err(Rc::ATTRIBUTES.param(1).0)
    );
    let no_outer = (key.clone(), dup.clone(), Vec::new());
    assert_eq!(
        import(&mut tpm, new_parent, &public, &no_outer, AES128_CFB),
        Err(Rc::ATTRIBUTES.param(4).0)
    );
    assert!(import(&mut tpm, new_parent, &public, &wrapped, AES128_CFB).is_ok());
}

/// TPM2_CreateLoaded of `template` under `parent` with `data`: the object's handle, and its
/// TPM2B_PRIVATE, TPMT_PUBLIC and Name.
fn create_loaded(
    tpm: &mut Tpm,
    parent: u32,
    template: &[u8],
    data: &[u8],
) -> (u32, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut sensitive = Writer::new();
    sensitive.tpm2b(b"").tpm2b(data);
    let mut p = Writer::new();
    p.tpm2b(&sensitive.into_bytes()).tpm2b(template);
    let r = tpm.process(&command(
        TPM_CC_CREATE_LOADED,
        &[parent],
        Some(b""),
        &p.into_bytes(),
    ));
    let handle = handle_of(&r);
    let (private, rest) = split2b(response_params(&r, true));
    let (public, rest) = split2b(rest);
    let name = split2b(rest).0;
    (handle, private.to_vec(), public.to_vec(), name.to_vec())
}

#[test]
fn create_loaded_makes_a_primary_or_a_child() {
    let mut tpm = started();
    // Under a hierarchy: the primary TPM2_CreatePrimary derives, and no TPM2B_PRIVATE.
    let (srk, private, _, name) = create_loaded(&mut tpm, TPM_RH_OWNER, &ecc_srk(), b"");
    assert!(private.is_empty());
    let primary = handle_of(&create_primary(&mut tpm, TPM_RH_OWNER, &ecc_srk()));
    assert_eq!(read_public_name(&mut tpm, primary), name);
    flush(&mut tpm, primary);
    // Under a parent: the child, loaded, and wrapped for a later TPM2_Load.
    let attributes = attr::FIXED_TPM | attr::FIXED_PARENT | attr::USER_WITH_AUTH;
    let (child, private, public, name) =
        create_loaded(&mut tpm, srk, &sealed(attributes), b"inside");
    assert_eq!(unseal(&mut tpm, child), b"inside");
    flush(&mut tpm, child);
    let child = load_child(&mut tpm, srk, &private, &public);
    assert_eq!(read_public_name(&mut tpm, child), name);
    assert_eq!(unseal(&mut tpm, child), b"inside");
}

/// TPM2_EncryptDecrypt2 with `key`: outData and ivOut, or the response code.
fn encrypt_decrypt2(
    tpm: &mut Tpm,
    key: u32,
    decrypt: bool,
    mode: u16,
    (iv, data): (&[u8], &[u8]),
) -> std::result::Result<(Vec<u8>, Vec<u8>), u32> {
    let mut p = Writer::new();
    p.tpm2b(data).u8(decrypt.into()).u16(mode).tpm2b(iv);
    let c = command(TPM_CC_ENCRYPT_DECRYPT_2, &[key], Some(b""), &p.into_bytes());
    let r = tpm.process(&c);
    if rc(&r) != 0 {
        return Err(rc(&r));
    }
    let (out, rest) = split2b(response_params(&r, false));
    Ok((out.to_vec(), split2b(rest).0.to_vec()))
}

#[test]
fn encrypt_decrypt_continues_from_the_iv_it_returns() {
    use crate::public::{TPM_ALG_CBC, TPM_ALG_CFB, TPM_ALG_CTR, TPM_ALG_ECB, TPM_ALG_OFB};
    let mut tpm = started();
    // An AES-128 key with no mode of its own: the caller picks.
    let attributes = ORDINARY | attr::SIGN | attr::DECRYPT;
    let template = public(0x25, attributes, &[0, 6, 0, 0x80, 0, 0x10], &[0, 0]);
    let key = handle_of(&create_primary(&mut tpm, TPM_RH_OWNER, &template));
    let data: Vec<u8> = (0..32).collect();
    let iv = [7u8; 16];
    for mode in [TPM_ALG_CBC, TPM_ALG_CFB, TPM_ALG_OFB, TPM_ALG_CTR] {
        let mut run = |decrypt, iv: &[u8], data: &[u8]| {
            encrypt_decrypt2(&mut tpm, key, decrypt, mode, (iv, data)).unwrap()
        };
        let (whole, iv_out) = run(false, &iv, &data);
        let (first, iv1) = run(false, &iv, &data[..16]);
        let (second, iv2) = run(false, &iv1, &data[16..]);
        assert_eq!([first, second].concat(), whole, "mode {mode:#x}");
        assert_eq!(iv2, iv_out, "mode {mode:#x}");
        assert_eq!(run(true, &iv, &whole).0, data, "mode {mode:#x}");
    }
    // TPM2_EncryptDecrypt: the same, its parameters in another order.
    let mut p = Writer::new();
    p.u8(0).u16(TPM_ALG_CBC).tpm2b(&iv).tpm2b(&data);
    let r = tpm.process(&command(
        TPM_CC_ENCRYPT_DECRYPT,
        &[key],
        Some(b""),
        &p.into_bytes(),
    ));
    let (whole, iv_out) =
        encrypt_decrypt2(&mut tpm, key, false, TPM_ALG_CBC, (&iv, &data)).unwrap();
    assert_eq!(
        response_params(&r, false),
        [tpm2b(&whole), tpm2b(&iv_out)].concat()
    );
    // No mode at all; an IV ECB does not take; a partial block for CBC.
    let mut refused = |mode, iv: &[u8], data: &[u8]| {
        encrypt_decrypt2(&mut tpm, key, false, mode, (iv, data)).unwrap_err()
    };
    assert_eq!(refused(alg::TPM_ALG_NULL, &iv, &data), Rc::MODE.param(3).0);
    assert_eq!(refused(TPM_ALG_ECB, &iv, &data), Rc::SIZE.param(4).0);
    assert_eq!(refused(TPM_ALG_CBC, &iv, &data[..15]), Rc::SIZE.param(1).0);
}

/// The outPublic from TPM2_CreatePrimary with `kind`'s EK template in the endorsement hierarchy.
fn create_ek(tpm: &mut Tpm, kind: EkKind) -> Vec<u8> {
    let template = kind_template(kind);
    let mut p = Writer::new();
    p.u16(4).u16(0).u16(0).tpm2b(&template).tpm2b(&[]).u32(0);
    let r = tpm.process(&command(
        TPM_CC_CREATE_PRIMARY,
        &[TPM_RH_ENDORSEMENT],
        Some(b""),
        &p.into_bytes(),
    ));
    assert_eq!(rc(&r), 0);
    let mut reader = Reader::new(&r[18..]);
    reader.tpm2b(4096).unwrap().to_vec()
}

/// The profile's default template for `kind`, as a guest sends it.
fn kind_template(kind: EkKind) -> Vec<u8> {
    let policy: [u8; 32] = [
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7,
        0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14,
        0x69, 0xaa,
    ];
    let mut w = Writer::new();
    match kind {
        EkKind::Rsa2048 => {
            w.u16(1).u16(0x0b).u32(0x0003_00b2).tpm2b(&policy);
            w.u16(6).u16(128).u16(0x43).u16(0x10).u16(2048).u32(0);
            w.tpm2b(&[0; 256]);
        }
        EkKind::EccNistP256 => {
            w.u16(0x23).u16(0x0b).u32(0x0003_00b2).tpm2b(&policy);
            w.u16(6).u16(128).u16(0x43).u16(0x10).u16(3).u16(0x10);
            w.tpm2b(&[0; 32]).tpm2b(&[0; 32]);
        }
    }
    w.into_bytes()
}

#[test]
fn the_endorsement_key_is_the_one_a_guest_creates() {
    let mut tpm = started();
    for kind in [EkKind::EccNistP256, EkKind::Rsa2048] {
        let ek = tpm.endorsement_key(kind).unwrap();
        assert_eq!(create_ek(&mut tpm, kind), ek);
        tpm.process(&command(TPM_CC_FLUSH_CONTEXT, &[], None, &[0x80, 0, 0, 0]));
    }
}

#[test]
fn a_provisioned_endorsement_key_and_its_certificate_persist() {
    let mut tpm = Tpm::manufacture().unwrap();
    tpm.take_permanent_changed();
    let kind = EkKind::EccNistP256;
    let certificate: Vec<u8> = (0..1500).map(|i| i as u8).collect();
    tpm.provision_endorsement_key(kind, Some(&certificate))
        .unwrap();
    assert!(tpm.take_permanent_changed());
    let mut tpm = Tpm::power_on(&tpm.permanent_state()).unwrap();
    tpm.process(&command(TPM_CC_STARTUP, &[], None, &[0, 0]));
    // The EK at its handle, the one TPM2_CreatePrimary makes.
    let r = tpm.process(&command(TPM_CC_READ_PUBLIC, &[kind.handle()], None, &[]));
    assert_eq!(rc(&r), 0);
    let public = Reader::new(&r[10..]).tpm2b(4096).unwrap().to_vec();
    assert_eq!(public, tpm.endorsement_key(kind).unwrap());
    // The certificate, read by the owner in two parts; nobody may write it.
    let index = kind.certificate_index();
    let mut read = Vec::new();
    for (size, offset) in [(1024u16, 0u16), (476, 1024)] {
        let p = [size.to_be_bytes(), offset.to_be_bytes()].concat();
        let r = tpm.process(&command(
            TPM_CC_NV_READ,
            &[TPM_RH_OWNER, index],
            Some(b""),
            &p,
        ));
        assert_eq!(rc(&r), 0);
        read.extend_from_slice(Reader::new(&r[14..]).tpm2b(1024).unwrap());
    }
    assert_eq!(read, certificate);
    let write = [&tpm2b(b"x")[..], &[0, 0]].concat();
    let r = tpm.process(&command(
        TPM_CC_NV_WRITE,
        &[TPM_RH_PLATFORM, index],
        Some(b""),
        &write,
    ));
    assert_eq!(rc(&r), Rc::NV_LOCKED.0);
    let r = tpm.process(&command(
        TPM_CC_NV_UNDEFINE_SPACE,
        &[TPM_RH_OWNER, index],
        Some(b""),
        &[],
    ));
    assert_eq!(rc(&r), Rc::NV_AUTHORIZATION.0);
    // Provisioning again replaces both; a certificate too large is refused.
    tpm.provision_endorsement_key(kind, Some(b"new")).unwrap();
    assert_eq!(tpm.nv_data(index).unwrap(), b"new");
    assert_eq!(
        tpm.provision_endorsement_key(kind, Some(&[0; 2049])),
        Err(Rc::SIZE)
    );
}

#[test]
fn provisioning_without_a_certificate_removes_the_old_one() {
    let mut tpm = started();
    let kind = EkKind::Rsa2048;
    tpm.provision_endorsement_key(kind, Some(b"old")).unwrap();
    tpm.provision_endorsement_key(kind, None).unwrap();
    assert_eq!(tpm.nv_data(kind.certificate_index()), None);
    let r = tpm.process(&command(TPM_CC_READ_PUBLIC, &[kind.handle()], None, &[]));
    assert_eq!(rc(&r), 0);
    let public = Reader::new(&r[10..]).tpm2b(4096).unwrap().to_vec();
    assert_eq!(public, tpm.endorsement_key(kind).unwrap());
}

#[test]
fn an_endorsement_key_needs_a_free_persistent_handle() {
    let mut tpm = started();
    let kind = EkKind::EccNistP256;
    tpm.provision_endorsement_key(kind, None).unwrap();
    let key = tpm.permanent.persistent[0].1.clone();
    for handle in (0x8100_0000..).take(crate::key::MAX_PERSISTENT - 1) {
        tpm.permanent.persistent.push((handle, key.clone()));
    }
    // Replace its own occupied handle; fail if every handle is occupied by others.
    assert_eq!(tpm.provision_endorsement_key(kind, None), Ok(()));
    tpm.take_permanent_changed();
    assert_eq!(
        tpm.provision_endorsement_key(EkKind::Rsa2048, Some(b"cert")),
        Err(Rc::NV_SPACE)
    );
    assert!(!tpm.take_permanent_changed());
    assert_eq!(tpm.nv_data(EkKind::Rsa2048.certificate_index()), None);
}
