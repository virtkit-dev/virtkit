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

#[test]
fn an_hmac_session_authorizes_and_rolls_its_nonce() {
    let mut tpm = started();
    tpm.process(&change_auth(TPM_RH_ENDORSEMENT, b"", b"e"));
    let (handle, mut nonce_tpm) = start_session(&mut tpm, TPM_RH_ENDORSEMENT, &[0, 0x10], 1);
    assert_eq!(handle, 0x0200_0000);
    let hash = alg::Hash::Sha256;
    let key = crypt::kdfa(hash, b"e", b"ATH", &nonce_tpm, &[1; 16], 32);
    let params = tpm2b(b"e");
    for (round, nonce_caller) in [[2u8; 16], [3; 16]].iter().enumerate() {
        // Bound to the endorsement hierarchy: its authValue is in the key already.
        let code = TPM_CC_HIERARCHY_CHANGE_AUTH.to_be_bytes();
        let name = TPM_RH_ENDORSEMENT.to_be_bytes();
        let cp_hash = hash.digest(&[&code, &name, &params]);
        let hmac = crypt::hmac(hash, &key, &[&cp_hash, nonce_caller, &nonce_tpm, &[1]]);
        let mut area = Writer::new();
        area.u32(handle).tpm2b(nonce_caller).u8(1).tpm2b(&hmac);
        let area = area.into_bytes();
        let mut c = Writer::new();
        c.u16(TPM_ST_SESSIONS)
            .u32(0)
            .u32(TPM_CC_HIERARCHY_CHANGE_AUTH)
            .u32(TPM_RH_ENDORSEMENT);
        c.count(area.len()).bytes(&area).bytes(&params);
        let mut c = c.into_bytes();
        let len = c.len() as u32;
        c[2..6].copy_from_slice(&len.to_be_bytes());
        let r = tpm.process(&c);
        assert_eq!(rc(&r), 0, "round {round}");
        // parameterSize 0, then the new nonce, the attributes and the TPM's HMAC.
        assert_eq!(r[10..16], [0, 0, 0, 0, 0, 16]);
        let new_nonce = r[16..32].to_vec();
        assert_ne!(new_nonce, nonce_tpm);
        let code = TPM_CC_HIERARCHY_CHANGE_AUTH.to_be_bytes();
        let rp_hash = hash.digest(&[&[0; 4], &code]);
        let expected = crypt::hmac(hash, &key, &[&rp_hash, &new_nonce, nonce_caller, &[1]]);
        assert_eq!(r[33..35], [0, 32]);
        assert_eq!(r[35..], expected[..]);
        nonce_tpm = new_nonce;
        // The old nonce no longer works.
        assert_eq!(rc(&tpm.process(&c)), Rc::BAD_AUTH.session(1).0);
    }
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

/// TPM2_CreatePrimary of the EK template `kind` has, under the endorsement hierarchy: its
/// outPublic.
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
fn commands_that_change_nothing_lasting_ask_for_no_store() {
    let mut tpm = started();
    tpm.take_permanent_changed();
    let pcr_read = [&[0, 0, 0, 1, 0, 0x0b, 3][..], &[0xff; 3]].concat();
    let hash = [&tpm2b(b"data")[..], &[0, 0x0b, 0x40, 0, 0, 7]].concat();
    for c in [
        command(
            TPM_CC_GET_CAPABILITY,
            &[],
            None,
            &[0, 0, 0, 6, 0, 0, 1, 0, 0, 0, 0, 8],
        ),
        command(TPM_CC_GET_RANDOM, &[], None, &[0, 8]),
        command(TPM_CC_READ_CLOCK, &[], None, &[]),
        command(TPM_CC_PCR_READ, &[], None, &pcr_read),
        extend(0, 0x0b, &[1; 32]),
        command(TPM_CC_HASH, &[], None, &hash),
    ] {
        assert_eq!(rc(&tpm.process(&c)), 0);
        assert!(!tpm.take_permanent_changed(), "command {:x?}", &c[6..10]);
    }
}
