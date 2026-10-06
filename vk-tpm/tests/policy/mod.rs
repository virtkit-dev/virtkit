//! Differential tests of the policy commands: the digests trial sessions compute, each
//! assertion checked by real policy sessions, and the authorizations they give (sealed data,
//! NV indices, the ADMIN role), with their tickets. Policy digests are deterministic, and so are
//! responses of unsalted, unbound policy sessions but for the TPM's nonces.

use super::nv::{self, INDEX, RW};
use super::objects::{
    ADMIN_WITH_POLICY, ALG_KEYEDHASH, CREATE, CREATE_PRIMARY, FIXED_PARENT, FIXED_TPM, LOAD, NULL,
    OBJECT_CHANGE_AUTH, READ_PUBLIC, SIGN_ATTR, UNSEAL, USER_WITH_AUTH, create_params,
    create_primary, ecc_srk, handle, hmac_key, no_pcrs, ok, params, public, split2b,
};
use super::*;

pub const POLICY_NV: u32 = 0x149;
pub const POLICY_SECRET: u32 = 0x151;
pub const POLICY_SIGNED: u32 = 0x160;
pub const POLICY_AUTHORIZE: u32 = 0x16a;
pub const POLICY_AUTH_VALUE: u32 = 0x16b;
pub const POLICY_COMMAND_CODE: u32 = 0x16c;
pub const POLICY_COUNTER_TIMER: u32 = 0x16d;
pub const POLICY_CP_HASH: u32 = 0x16e;
pub const POLICY_LOCALITY: u32 = 0x16f;
pub const POLICY_NAME_HASH: u32 = 0x170;
pub const POLICY_OR: u32 = 0x171;
pub const POLICY_TICKET: u32 = 0x172;
pub const POLICY_PCR: u32 = 0x17f;
pub const POLICY_RESTART: u32 = 0x180;
pub const POLICY_PHYSICAL_PRESENCE: u32 = 0x187;
pub const POLICY_DUPLICATION_SELECT: u32 = 0x188;
pub const POLICY_GET_DIGEST: u32 = 0x189;
pub const POLICY_PASSWORD: u32 = 0x18c;
pub const POLICY_NV_WRITTEN: u32 = 0x18f;
pub const POLICY_TEMPLATE: u32 = 0x190;
pub const POLICY_AUTHORIZE_NV: u32 = 0x192;
const VERIFY_SIGNATURE: u32 = 0x177;

const POLICY_SESSION: u32 = 0x0300_0000;

/// A policy command on `session`, no authorization.
pub fn policy(code: u32, session: u32, params: &[u8]) -> Vec<u8> {
    command(code, &[session], None, params)
}

/// TPM2_StartAuthSession of a policy (or trial) session of `hash`, unbound and unsalted.
fn start(kind: u8, hash: u16) -> Vec<u8> {
    let p = [
        tpm2b(&[7; 16]),
        tpm2b(b""),
        vec![kind],
        NULL.to_vec(),
        hash.to_be_bytes().to_vec(),
    ]
    .concat();
    command(START_AUTH_SESSION, &[RH_NULL, RH_NULL], None, &p)
}

/// Start a session on both (their nonces differ, not their handles); its handle.
fn begin(both: &mut Both, kind: u8, hash: u16) -> u32 {
    let (ours, theirs) = both.both(&start(kind, hash));
    assert_eq!(hex(&ours[..14]), hex(&theirs[..14]));
    handle(&ours)
}

fn get_digest(both: &mut Both, session: u32) -> Vec<u8> {
    let r = both.same(&policy(POLICY_GET_DIGEST, session, &[]));
    split2b(&ok(&r)[10..]).0
}

fn flush(both: &mut Both, handle: u32) {
    both.same(&command(FLUSH_CONTEXT, &[], None, &handle.to_be_bytes()));
}

/// TPM2_PolicyPCR of PCR 16 (and 0) of the SHA-256 bank.
fn policy_pcr(session: u32, digest: &[u8]) -> Vec<u8> {
    let p = [tpm2b(digest), selection(&[(0x0b, &[1, 0, 1])])].concat();
    policy(POLICY_PCR, session, &p)
}

/// The policy commands taking no authorization, with arguments trial and real sessions
/// both take.
fn assertions(session: u32) -> Vec<Vec<u8>> {
    let cc = |code: u32| code.to_be_bytes().to_vec();
    let eo = |operand: &[u8], offset: u16, op: u16| {
        [
            tpm2b(operand),
            offset.to_be_bytes().to_vec(),
            op.to_be_bytes().to_vec(),
        ]
        .concat()
    };
    vec![
        policy_pcr(session, b""),
        policy(POLICY_AUTH_VALUE, session, &[]),
        policy(POLICY_PASSWORD, session, &[]),
        policy(POLICY_COMMAND_CODE, session, &cc(UNSEAL)),
        policy(POLICY_COMMAND_CODE, session, &cc(0x199)),
        policy(POLICY_COMMAND_CODE, session, &cc(0x2000_0000)),
        policy(POLICY_LOCALITY, session, &[0x03]),
        policy(POLICY_LOCALITY, session, &[0x06]),
        policy(POLICY_LOCALITY, session, &[0x08]),
        policy(POLICY_LOCALITY, session, &[0x00]),
        policy(POLICY_LOCALITY, session, &[0x40]),
        policy(POLICY_NV_WRITTEN, session, &[1]),
        policy(POLICY_NV_WRITTEN, session, &[0]),
        policy(POLICY_NV_WRITTEN, session, &[2]),
        policy(POLICY_PHYSICAL_PRESENCE, session, &[]),
        // resetCount (offset 16) is 1, Clock (offset 8) is not 0.
        policy(POLICY_COUNTER_TIMER, session, &eo(&[0, 0, 0, 1], 16, 0)),
        policy(POLICY_COUNTER_TIMER, session, &eo(&[0; 8], 8, 3)),
        policy(POLICY_COUNTER_TIMER, session, &eo(&[0; 8], 8, 5)),
        policy(POLICY_COUNTER_TIMER, session, &eo(&[1], 25, 0)),
        policy(POLICY_COUNTER_TIMER, session, &eo(&[], 26, 0)),
        policy(POLICY_COUNTER_TIMER, session, &eo(&[1], 1, 12)),
        policy(POLICY_RESTART, session, &[]),
    ]
}

/// The commands that bind a session to a cpHash, Names or a template, which each exclude the
/// others.
fn bindings(session: u32, size: usize) -> Vec<Vec<u8>> {
    vec![
        policy(POLICY_CP_HASH, session, &tpm2b(&vec![1; size])),
        policy(POLICY_CP_HASH, session, &tpm2b(&vec![1; size])),
        policy(POLICY_CP_HASH, session, &tpm2b(&vec![2; size])),
        policy(POLICY_NAME_HASH, session, &tpm2b(&vec![3; size])),
        policy(POLICY_TEMPLATE, session, &tpm2b(&vec![4; size])),
        policy(POLICY_RESTART, session, &[]),
        policy(POLICY_CP_HASH, session, &tpm2b(&[1; 3])),
        policy(POLICY_NAME_HASH, session, &tpm2b(&vec![3; size])),
        policy(POLICY_CP_HASH, session, &tpm2b(&vec![3; size])),
        policy(POLICY_RESTART, session, &[]),
        policy(POLICY_TEMPLATE, session, &tpm2b(&vec![4; size])),
        policy(POLICY_TEMPLATE, session, &tpm2b(&vec![4; size])),
        policy(POLICY_TEMPLATE, session, &tpm2b(&[4; 3])),
        policy(POLICY_RESTART, session, &[]),
        policy(
            POLICY_DUPLICATION_SELECT,
            session,
            &[tpm2b(b"object"), tpm2b(b"parent"), vec![1]].concat(),
        ),
        policy(
            POLICY_DUPLICATION_SELECT,
            session,
            &[tpm2b(b""), tpm2b(b""), vec![0]].concat(),
        ),
        policy(POLICY_RESTART, session, &[]),
        policy(POLICY_COMMAND_CODE, session, &UNSEAL.to_be_bytes()),
        policy(
            POLICY_DUPLICATION_SELECT,
            session,
            &[tpm2b(b"o"), tpm2b(b"p"), vec![0]].concat(),
        ),
        policy(POLICY_RESTART, session, &[]),
        policy(
            POLICY_OR,
            session,
            &[vec![0, 0, 0, 2], tpm2b(&[0; 32]), tpm2b(&[1; 32])].concat(),
        ),
        policy(
            POLICY_OR,
            session,
            &[vec![0, 0, 0, 1], tpm2b(&[0; 32])].concat(),
        ),
        policy(POLICY_OR, session, &[vec![0, 0, 0, 9]].concat()),
    ]
}

#[test]
fn trial_and_real_policy_digests_match() {
    let mut both = Both::started();
    both.same(&extend(16, &[(0x0b, vec![9; 32])]));
    for kind in [SE_TRIAL, SE_POLICY] {
        for (hash, size) in [
            (client::SHA256, 32),
            (client::SHA1, 20),
            (client::SHA384, 48),
        ] {
            begin(&mut both, kind, hash);
            for c in assertions(POLICY_SESSION)
                .into_iter()
                .chain(bindings(POLICY_SESSION, size))
            {
                both.same(&c);
                both.same(&policy(POLICY_GET_DIGEST, POLICY_SESSION, &[]));
            }
            flush(&mut both, POLICY_SESSION);
        }
    }
    // A policy command on an HMAC session, or a session not loaded.
    begin(&mut both, SE_HMAC, client::SHA256);
    both.same(&policy(POLICY_AUTH_VALUE, 0x0200_0000, &[]));
    both.same(&policy(POLICY_AUTH_VALUE, 0x0300_0000, &[]));
    both.same(&policy(POLICY_AUTH_VALUE, 0x0300_0001, &[]));
}

#[test]
fn policy_pcr_and_or_match() {
    let mut both = Both::started();
    both.same(&extend(16, &[(0x0b, vec![9; 32])]));
    begin(&mut both, SE_TRIAL, client::SHA256);
    both.same(&policy_pcr(POLICY_SESSION, b""));
    let branch_a = get_digest(&mut both, POLICY_SESSION);
    both.same(&policy(POLICY_RESTART, POLICY_SESSION, &[]));
    both.same(&policy_pcr(POLICY_SESSION, &[5; 32]));
    let branch_b = get_digest(&mut both, POLICY_SESSION);
    let or = [vec![0, 0, 0, 2], tpm2b(&branch_a), tpm2b(&branch_b)].concat();
    both.same(&policy(POLICY_OR, POLICY_SESSION, &or));
    flush(&mut both, POLICY_SESSION);
    // A real session: the PCRs as they are, then as a digest says they are.
    begin(&mut both, SE_POLICY, client::SHA256);
    both.same(&policy_pcr(POLICY_SESSION, b""));
    assert_eq!(get_digest(&mut both, POLICY_SESSION), branch_a);
    both.same(&policy(POLICY_OR, POLICY_SESSION, &or));
    both.same(&policy(POLICY_OR, POLICY_SESSION, &or));
    both.same(&policy(POLICY_RESTART, POLICY_SESSION, &[]));
    both.same(&policy_pcr(POLICY_SESSION, &[5; 32]));
    // The PCRs change between two assertions.
    both.same(&policy_pcr(POLICY_SESSION, b""));
    both.same(&extend(16, &[(0x0b, vec![1; 32])]));
    both.same(&policy_pcr(POLICY_SESSION, b""));
}

/// A sealed object whose authPolicy is `policy`, created under the owner; its handle.
fn sealed_with_policy(both: &mut Both, policy_digest: &[u8], admin: bool) -> u32 {
    let mut attributes = FIXED_TPM | FIXED_PARENT;
    if admin {
        attributes |= ADMIN_WITH_POLICY | USER_WITH_AUTH;
    }
    let mut template = public(ALG_KEYEDHASH, attributes, NULL, &tpm2b(b""));
    // The authPolicy, after type, nameAlg and attributes.
    template.splice(8..10, tpm2b(policy_digest));
    let p = create_params(b"pw", b"the secret", &template, b"", &no_pcrs());
    handle(&both.same(&with_password(CREATE_PRIMARY, RH_OWNER, b"", &p)))
}

/// The Name of an object.
fn object_name(both: &mut Both, handle: u32) -> Vec<u8> {
    let r = both.same(&command(READ_PUBLIC, &[handle], None, &[]));
    let p = params(ok(&r), false);
    split2b(split2b(&p).1).0
}

/// The policy digest a trial session computes from `commands` (each built for its handle).
fn trial(both: &mut Both, hash: u16, commands: &[fn(u32) -> Vec<u8>]) -> Vec<u8> {
    let session = begin(both, SE_TRIAL, hash);
    for c in commands {
        ok(&both.same(&c(session)));
    }
    let digest = get_digest(both, session);
    flush(both, session);
    digest
}

/// One policy session, authorizing the first handle of the command.
fn policy_auth(index: usize, entity: Option<&[u8]>, auth_value: bool) -> Auth {
    Auth::Session {
        index,
        attributes: client::CONTINUE,
        entity: Some(entity.unwrap_or_default().to_vec()),
        // Without TPM2_PolicyAuthValue the authValue keys nothing: as for a bound session.
        bound: !auth_value,
        after: None,
        hmac: None,
    }
}

#[test]
fn policy_sessions_authorize_alike() {
    let mut both = Both::seeded();
    both.same(&extend(16, &[(0x0b, vec![9; 32])]));
    let pcr_and_value = trial(
        &mut both,
        client::SHA256,
        &[
            |s| policy_pcr(s, b""),
            |s| policy(POLICY_AUTH_VALUE, s, &[]),
            |s| policy(POLICY_COMMAND_CODE, s, &UNSEAL.to_be_bytes()),
        ],
    );
    let sealed = sealed_with_policy(&mut both, &pcr_and_value, false);
    let name = object_name(&mut both, sealed);
    let mut sessions = Sessions::default();
    let unseal = |entity: &[u8], auth_value: bool| {
        let mut cmd = client::Command::new(
            UNSEAL,
            &[sealed],
            &[],
            vec![policy_auth(0, Some(entity), auth_value)],
        );
        cmd.names = vec![name.clone()];
        cmd
    };
    for (pcr, value, code, entity) in [
        (true, true, true, &b"pw"[..]), // the policy, its authValue: the secret
        (true, true, true, b"bad"),     // a wrong authValue
        (true, false, true, b"pw"),     // no PolicyAuthValue: another digest
        (true, true, false, b"pw"),     // no PolicyCommandCode
        (false, true, true, b"pw"),     // no PolicyPCR
    ] {
        let start = both.start_session(
            &mut sessions,
            SE_POLICY,
            client::SHA256,
            Sym::Null,
            (RH_NULL, None),
            &[1; 16],
        );
        assert_eq!(start, 0);
        let session = POLICY_SESSION + sessions.ours.len() as u32 - 1;
        if pcr {
            ok(&both.same(&policy_pcr(session, b"")));
        }
        if value {
            ok(&both.same(&policy(POLICY_AUTH_VALUE, session, &[])));
        }
        if code {
            ok(&both.same(&policy(POLICY_COMMAND_CODE, session, &UNSEAL.to_be_bytes())));
        }
        let index = sessions.ours.len() - 1;
        let mut cmd = unseal(entity, value);
        if let Auth::Session { index: i, .. } = &mut cmd.auths[0] {
            *i = index;
        }
        let response = both.run(&mut sessions, &cmd);
        // Used, the session starts over.
        let digest = get_digest(&mut both, session);
        if response.rc == 0 {
            assert_eq!(digest, vec![0; 32]);
        }
        flush(&mut both, session);
        sessions.ours.pop();
        sessions.theirs.pop();
        read_hierarchy_state(&mut both);
    }
    // The PCRs changed since the assertion.
    both.start_session(
        &mut sessions,
        SE_POLICY,
        client::SHA256,
        Sym::Null,
        (RH_NULL, None),
        &[2; 16],
    );
    ok(&both.same(&policy_pcr(POLICY_SESSION, b"")));
    ok(&both.same(&policy(POLICY_AUTH_VALUE, POLICY_SESSION, &[])));
    ok(&both.same(&policy(
        POLICY_COMMAND_CODE,
        POLICY_SESSION,
        &UNSEAL.to_be_bytes(),
    )));
    both.same(&extend(16, &[(0x0b, vec![9; 32])]));
    both.run(&mut sessions, &unseal(b"pw", true));
    // PolicyPassword: the authValue in clear, and an empty HMAC in the response.
    let password = trial(
        &mut both,
        client::SHA256,
        &[|s| policy(POLICY_PASSWORD, s, &[])],
    );
    let sealed = sealed_with_policy(&mut both, &password, false);
    for pw in [&b"pw"[..], b"no"] {
        begin(&mut both, SE_POLICY, client::SHA256);
        let session = 0x0300_0001;
        ok(&both.same(&policy(POLICY_PASSWORD, session, &[])));
        let area = super::session(session, &[3; 16], 1, pw);
        let (ours, theirs) = both.both(&command(UNSEAL, &[sealed], Some(&area), &[]));
        assert_eq!(ours.len(), theirs.len());
        assert_eq!(hex(&ours[..10]), hex(&theirs[..10]));
        if rc(&ours) == 0 {
            // Parameters, then nonceTPM (16 bytes), attributes and an empty HMAC.
            assert_eq!(ours[ours.len() - 3..], [1, 0, 0]);
        }
        flush(&mut both, session);
    }
    read_hierarchy_state(&mut both);
}

/// The policy that lets a policy session take the ADMIN role for `code`.
fn admin_for(both: &mut Both, code: u32) -> Vec<u8> {
    begin(both, SE_TRIAL, client::SHA256);
    let session = 0x0300_0000;
    ok(&both.same(&policy(POLICY_COMMAND_CODE, session, &code.to_be_bytes())));
    let digest = get_digest(both, session);
    flush(both, session);
    digest
}

#[test]
fn policy_command_code_gives_the_admin_role() {
    let mut both = Both::seeded();
    // An NV index's authValue changes only by its policy, bound to TPM2_NV_ChangeAuth.
    let change_auth = admin_for(&mut both, nv::NV_CHANGE_AUTH);
    both.same(&nv::define(
        RH_OWNER,
        b"old",
        &nv::nv_public(INDEX, RW, &change_auth, 8),
    ));
    let name = |both: &mut Both| {
        let p = params(ok(&both.same(&nv::read_public(INDEX))), false);
        split2b(split2b(&p).1).0
    };
    let mut sessions = Sessions::default();
    for code in [nv::NV_CHANGE_AUTH, 0, nv::NV_WRITE] {
        both.start_session(
            &mut sessions,
            SE_POLICY,
            client::SHA256,
            Sym::Null,
            (RH_NULL, None),
            &[1; 16],
        );
        if code != 0 {
            ok(&both.same(&policy(
                POLICY_COMMAND_CODE,
                POLICY_SESSION,
                &code.to_be_bytes(),
            )));
        }
        let mut cmd = client::Command::new(
            nv::NV_CHANGE_AUTH,
            &[INDEX],
            &tpm2b(b"new"),
            vec![policy_auth(0, Some(b"old"), false)],
        );
        cmd.names = vec![name(&mut both)];
        both.run(&mut sessions, &cmd);
        flush(&mut both, POLICY_SESSION);
        sessions.ours.clear();
        sessions.theirs.clear();
    }
    // The new authValue works.
    both.same(&nv::nv_command(
        nv::NV_WRITE,
        INDEX,
        INDEX,
        b"new",
        &[tpm2b(b"x"), vec![0, 0]].concat(),
    ));
    // An object with adminWithPolicy: TPM2_ObjectChangeAuth by its policy only. The child
    // libtpms wraps under the storage key both derive loads in both.
    let object_change_auth = admin_for(&mut both, OBJECT_CHANGE_AUTH);
    let srk = handle(&both.same(&create_primary(RH_OWNER, &ecc_srk())));
    let mut template = public(
        ALG_KEYEDHASH,
        FIXED_TPM | FIXED_PARENT | USER_WITH_AUTH | ADMIN_WITH_POLICY,
        NULL,
        &tpm2b(b""),
    );
    template.splice(8..10, tpm2b(&object_change_auth));
    let p = create_params(b"pw", b"data", &template, b"", &no_pcrs());
    let created = params(
        ok(&both.theirs.process(&with_password(CREATE, srk, b"", &p))),
        false,
    );
    let (private, rest) = split2b(&created);
    let load = [tpm2b(&private), tpm2b(&split2b(rest).0)].concat();
    let child = handle(&both.same(&with_password(LOAD, srk, b"", &load)));
    // Its authValue does not serve the ADMIN role.
    let (ours, theirs) = both.both(&command(
        OBJECT_CHANGE_AUTH,
        &[child, srk],
        Some(&password(b"pw")),
        &tpm2b(b"x"),
    ));
    assert_eq!(hex(&ours), hex(&theirs));
    both.start_session(
        &mut sessions,
        SE_POLICY,
        client::SHA256,
        Sym::Null,
        (RH_NULL, None),
        &[2; 16],
    );
    ok(&both.same(&policy(
        POLICY_COMMAND_CODE,
        POLICY_SESSION,
        &OBJECT_CHANGE_AUTH.to_be_bytes(),
    )));
    let mut cmd = client::Command::new(
        OBJECT_CHANGE_AUTH,
        &[child, srk],
        &tpm2b(b"x"),
        vec![policy_auth(0, Some(b"pw"), false)],
    );
    cmd.names[0] = object_name(&mut both, child);
    cmd.names[1] = object_name(&mut both, srk);
    // The new private area is wrapped with a random IV: compare the response codes.
    sessions.calls += 1;
    let nonce = [5u8; 20];
    let ours = both
        .ours
        .process(&client::build(&cmd, &sessions.ours, &nonce));
    let theirs = both
        .theirs
        .process(&client::build(&cmd, &sessions.theirs, &nonce));
    assert_eq!(rc(&ours), 0);
    assert_eq!(rc(&theirs), 0);
    client::check(&cmd, &mut sessions.ours, &nonce, &ours);
    client::check(&cmd, &mut sessions.theirs, &nonce, &theirs);
    // TPM2_NV_UndefineSpaceSpecial: the index's policy, and the platform's authorization.
    let delete = admin_for(&mut both, nv::NV_UNDEFINE_SPACE_SPECIAL);
    both.same(&nv::define(
        RH_PLATFORM,
        b"",
        &nv::nv_public(
            0x0100_0002,
            RW | nv::PLATFORMCREATE | nv::POLICY_DELETE,
            &delete,
            8,
        ),
    ));
    let p = params(ok(&both.same(&nv::read_public(0x0100_0002))), false);
    let index_name = split2b(split2b(&p).1).0;
    flush(&mut both, POLICY_SESSION);
    sessions.ours.clear();
    sessions.theirs.clear();
    both.start_session(
        &mut sessions,
        SE_POLICY,
        client::SHA256,
        Sym::Null,
        (RH_NULL, None),
        &[3; 16],
    );
    ok(&both.same(&policy(
        POLICY_COMMAND_CODE,
        POLICY_SESSION,
        &nv::NV_UNDEFINE_SPACE_SPECIAL.to_be_bytes(),
    )));
    let mut cmd = client::Command::new(
        nv::NV_UNDEFINE_SPACE_SPECIAL,
        &[0x0100_0002, RH_PLATFORM],
        &[],
        vec![policy_auth(0, Some(b""), false), Auth::Password(Vec::new())],
    );
    cmd.names[0] = index_name;
    both.run(&mut sessions, &cmd);
    both.same(&nv::read_public(0x0100_0002));
}

#[test]
fn policy_secret_signed_and_tickets_match() {
    let mut both = Both::seeded();
    let session = POLICY_SESSION;
    let secret = |session: u32, expiration: i32, nonce: &[u8], cp_hash: &[u8]| {
        let p = [
            tpm2b(nonce),
            tpm2b(cp_hash),
            tpm2b(b"ref"),
            expiration.to_be_bytes().to_vec(),
        ]
        .concat();
        command(
            POLICY_SECRET,
            &[RH_OWNER, session],
            Some(&password(b"")),
            &p,
        )
    };
    // Trial and real, without an expiration: the same digest, a NULL ticket.
    begin(&mut both, SE_TRIAL, client::SHA256);
    both.same(&secret(session, 0, b"", b""));
    let expected = get_digest(&mut both, session);
    flush(&mut both, session);
    begin(&mut both, SE_POLICY, client::SHA256);
    both.same(&secret(session, 0, b"", b""));
    assert_eq!(get_digest(&mut both, session), expected);
    both.same(&secret(session, 0, b"", &[1; 31]));
    both.same(&secret(session, 0, b"", &[1; 32]));
    both.same(&secret(session, 0, b"", &[2; 32]));
    both.same(&secret(session, 0, &[9; 16], b""));
    // A wrong authorization of the entity.
    both.same(&command(
        POLICY_SECRET,
        &[RH_OWNER, session],
        Some(&password(b"bad")),
        &[tpm2b(b""), tpm2b(b""), tpm2b(b""), vec![0; 4]].concat(),
    ));
    // An expiration in the past; a ticket (its timeout depends on each TPM's time).
    both.same(&secret(session, 1, b"", b""));
    let (ours, theirs) = both.both(&secret(session, -100, b"", b""));
    assert_eq!(rc(&ours), 0);
    assert_eq!(ours.len(), theirs.len());
    // Each TPM takes its own ticket back, in another session; not the other's.
    for (r, which) in [(ours, true), (theirs, false)] {
        let out = params(&r, false);
        let (timeout, rest) = split2b(&out);
        let ticket = rest.to_vec();
        let p = [
            tpm2b(&timeout),
            tpm2b(b""),
            tpm2b(b"ref"),
            tpm2b(&RH_OWNER.to_be_bytes()),
            ticket,
        ]
        .concat();
        begin(&mut both, SE_POLICY, client::SHA256);
        let c = policy(POLICY_TICKET, 0x0300_0001, &p);
        let (mine, other) = if which {
            (both.ours.process(&c), both.theirs.process(&c))
        } else {
            (both.theirs.process(&c), both.ours.process(&c))
        };
        assert_eq!(rc(&mine), 0, "a TPM takes its own ticket");
        drop(other);
        flush(&mut both, 0x0300_0001);
    }
    // PolicyTicket's own checks.
    begin(&mut both, SE_TRIAL, client::SHA256);
    let bad = [
        tpm2b(&[0; 7]),
        tpm2b(b""),
        tpm2b(b""),
        tpm2b(b""),
        vec![0x80, 0x23, 0x40, 0, 0, 1, 0, 0],
    ]
    .concat();
    both.same(&policy(POLICY_TICKET, 0x0300_0001, &bad));
    flush(&mut both, 0x0300_0001);
    begin(&mut both, SE_POLICY, client::SHA256);
    for ticket_tag in [
        &[0x80, 0x23][..],
        &[0x80, 0x25],
        &[0x80, 0x24],
        &[0x12, 0x34],
    ] {
        let p = [
            tpm2b(&[0; 8]),
            tpm2b(b""),
            tpm2b(b""),
            tpm2b(b""),
            ticket_tag.to_vec(),
            vec![0x40, 0, 0, 1, 0, 0],
        ]
        .concat();
        both.same(&policy(POLICY_TICKET, 0x0300_0001, &p));
    }
    for size in [7usize, 8] {
        let p = [
            tpm2b(&vec![0; size]),
            tpm2b(b""),
            tpm2b(b""),
            tpm2b(b""),
            vec![0x80, 0x23, 0x40, 0, 0, 1, 0, 0],
        ]
        .concat();
        both.same(&policy(POLICY_TICKET, 0x0300_0001, &p));
    }

    // PolicySigned with an HMAC key the caller holds (its signature is deterministic), loaded
    // in the null hierarchy: no nonce, so the same signature serves both TPMs.
    let key_secret = [6u8; 32];
    let sensitive = tpm2b(
        &[
            &ALG_KEYEDHASH.to_be_bytes()[..],
            &tpm2b(b""),
            &tpm2b(&[0; 32]),
            &tpm2b(&key_secret),
        ]
        .concat(),
    );
    let template = public(
        ALG_KEYEDHASH,
        SIGN_ATTR | USER_WITH_AUTH,
        &[0, 5, 0, 0x0b],
        &tpm2b(&[0; 32]),
    );
    let mut template = template;
    // Its unique: H(seed ‖ secret), as the TPM checks.
    let unique = client::digest(client::SHA256, &[&[0; 32], &key_secret]);
    let at = template.len() - 32;
    template[at..].copy_from_slice(&unique);
    let load = [sensitive, tpm2b(&template), RH_NULL.to_be_bytes().to_vec()].concat();
    let key = handle(&both.same(&command(super::objects::LOAD_EXTERNAL, &[], None, &load)));
    let signed = |session: u32, expiration: i32, signature: &[u8]| {
        let p = [
            tpm2b(b""),
            tpm2b(b""),
            tpm2b(b"ref"),
            expiration.to_be_bytes().to_vec(),
            signature.to_vec(),
        ]
        .concat();
        command(POLICY_SIGNED, &[key, session], None, &p)
    };
    for expiration in [0i32, -60, 60] {
        let a_hash = client::digest(client::SHA256, &[&expiration.to_be_bytes(), b"ref"]);
        let mac = client::hmac(client::SHA256, &key_secret, &[&a_hash]);
        let signature = [&[0, 5, 0, 0x0b][..], &mac].concat();
        let (ours, theirs) = both.both(&signed(0x0300_0001, expiration, &signature));
        assert_eq!(rc(&ours), 0);
        assert_eq!(rc(&theirs), 0);
        assert_eq!(ours.len(), theirs.len());
        if expiration >= 0 {
            assert_eq!(hex(&ours), hex(&theirs));
        }
        let mut wrong = signature.clone();
        *wrong.last_mut().unwrap() ^= 1;
        both.same(&signed(0x0300_0001, expiration, &wrong));
        both.same(&policy(POLICY_GET_DIGEST, 0x0300_0001, &[]));
    }
    for signature in [
        &[0, 0x10][..],
        &[0, 0x14, 0, 0x0b, 0, 0],
        &[0, 0x1a, 0, 0x0b, 0, 0, 0, 0],
        &[0, 5, 0, 4],
    ] {
        both.same(&signed(0x0300_0001, 0, signature));
        both.same(&command(
            VERIFY_SIGNATURE,
            &[key],
            None,
            &[tpm2b(&[0; 32]), signature.to_vec()].concat(),
        ));
    }
    both.same(&signed(0x0300_0001, 0, &[0, 5, 0, 0x0b]));
}

#[test]
fn policy_authorize_and_authorize_nv_match() {
    let mut both = Both::seeded();
    // An HMAC key in the owner hierarchy, the same on both: its tickets are the same too.
    let key = handle(&both.same(&with_password(
        CREATE_PRIMARY,
        RH_OWNER,
        b"",
        &create_params(b"", b"", &hmac_key(), b"", &no_pcrs()),
    )));
    let key_name = object_name(&mut both, key);
    let approved = trial(
        &mut both,
        client::SHA256,
        &[|s| policy(POLICY_AUTH_VALUE, s, &[])],
    );
    let a_hash = client::digest(client::SHA256, &[&approved, b"ref"]);
    let signature = params(
        ok(&both.same(&with_password(
            0x15d,
            key,
            b"",
            &[
                tpm2b(&a_hash),
                vec![0, 0x10],
                vec![0x80, 0x24, 0x40, 0, 0, 7, 0, 0],
            ]
            .concat(),
        ))),
        false,
    );
    let ticket = params(
        ok(&both.same(&command(
            VERIFY_SIGNATURE,
            &[key],
            None,
            &[tpm2b(&a_hash), signature].concat(),
        ))),
        false,
    );
    let authorize = |session: u32, approved: &[u8], ticket: &[u8]| {
        let p = [
            tpm2b(approved),
            tpm2b(b"ref"),
            tpm2b(&key_name),
            ticket.to_vec(),
        ]
        .concat();
        policy(POLICY_AUTHORIZE, session, &p)
    };
    for kind in [SE_TRIAL, SE_POLICY] {
        begin(&mut both, kind, client::SHA256);
        let s = 0x0300_0000;
        both.same(&authorize(s, &approved, &ticket));
        both.same(&policy(POLICY_AUTH_VALUE, s, &[]));
        both.same(&authorize(s, &approved, &ticket));
        both.same(&policy(POLICY_GET_DIGEST, s, &[]));
        both.same(&authorize(s, &[0; 32], &ticket));
        let mut bad = ticket.clone();
        *bad.last_mut().unwrap() ^= 1;
        both.same(&authorize(s, &approved, &bad));
        for name in [&b""[..], &[0, 0x0b], &[0, 0x0b, 1], &[0x12, 0x34, 1]] {
            let p = [tpm2b(&approved), tpm2b(b""), tpm2b(name), ticket.clone()].concat();
            both.same(&policy(POLICY_AUTHORIZE, s, &p));
        }
        flush(&mut both, s);
    }
    // PolicyAuthorizeNV: the policy an index holds.
    both.same(&nv::define_owner(INDEX, RW, 34));
    let authorize_nv = |s: u32| {
        command(
            POLICY_AUTHORIZE_NV,
            &[RH_OWNER, INDEX, s],
            Some(&password(b"")),
            &[],
        )
    };
    for kind in [SE_TRIAL, SE_POLICY] {
        begin(&mut both, kind, client::SHA256);
        let s = 0x0300_0000;
        both.same(&authorize_nv(s));
        both.same(&policy(POLICY_AUTH_VALUE, s, &[]));
        for stored in [
            [&[0, 0x0b][..], &approved].concat(),
            [&[0, 0x04][..], &approved].concat(),
            [&[0, 0x0b][..], &[1; 32]].concat(),
            [&[0x12, 0x34][..], &[1; 32]].concat(),
            [&[0, 0x0b][..], &approved].concat(),
        ] {
            both.same(&nv::nv_write(RH_OWNER, INDEX, &stored, 0));
            both.same(&authorize_nv(s));
            both.same(&policy(POLICY_GET_DIGEST, s, &[]));
            both.same(&policy(POLICY_AUTH_VALUE, s, &[]));
        }
        flush(&mut both, s);
    }
}

#[test]
fn policy_nv_and_nv_written_match() {
    let mut both = Both::started();
    both.same(&nv::define_owner(INDEX, RW, 8));
    let policy_nv = |s: u32, operand: &[u8], offset: u16, op: u16| {
        let p = [
            tpm2b(operand),
            offset.to_be_bytes().to_vec(),
            op.to_be_bytes().to_vec(),
        ]
        .concat();
        command(POLICY_NV, &[RH_OWNER, INDEX, s], Some(&password(b"")), &p)
    };
    for kind in [SE_TRIAL, SE_POLICY] {
        begin(&mut both, kind, client::SHA256);
        let s = 0x0300_0000;
        both.same(&policy_nv(s, &[1], 0, 0));
        both.same(&nv::nv_write(
            RH_OWNER,
            INDEX,
            &[0x80, 1, 2, 3, 4, 5, 6, 7],
            0,
        ));
        for (operand, offset, op) in [
            (&[0x80u8, 1][..], 0, 0),
            (&[0x80, 2], 0, 0),
            (&[0x80, 2], 0, 1),
            (&[0x7f], 0, 2),
            (&[0x7f], 0, 3),
            (&[0x7f], 0, 4),
            (&[0x7f], 0, 5),
            (&[0x80], 0, 6),
            (&[0x81], 0, 7),
            (&[0x80], 0, 8),
            (&[0x79], 0, 9),
            (&[0x01, 0x02], 1, 10),
            (&[0x01, 0x04], 1, 10),
            (&[0x02], 1, 11),
            (&[0x01], 1, 11),
            (&[7], 7, 0),
            (&[7, 8], 7, 0),
            (&[], 9, 0),
            (&[], 8, 0),
            (&[1], 0, 12),
        ] {
            both.same(&policy_nv(s, operand, offset, op));
        }
        both.same(&policy(POLICY_GET_DIGEST, s, &[]));
        flush(&mut both, s);
        both.same(&nv::undefine(RH_OWNER, INDEX));
        both.same(&nv::define_owner(INDEX, RW, 8));
    }
    // PolicyNvWritten: an index that may be written once, by its policy only.
    let once = trial(
        &mut both,
        client::SHA256,
        &[
            |s| policy(POLICY_NV_WRITTEN, s, &[0]),
            |s| policy(POLICY_COMMAND_CODE, s, &nv::NV_WRITE.to_be_bytes()),
        ],
    );
    let attributes = nv::POLICYWRITE | nv::OWNERREAD | nv::AUTHREAD;
    both.same(&nv::define(
        RH_OWNER,
        b"",
        &nv::nv_public(0x0100_0002, attributes, &once, 4),
    ));
    let mut sessions = Sessions::default();
    for _ in 0..2 {
        both.start_session(
            &mut sessions,
            SE_POLICY,
            client::SHA256,
            Sym::Null,
            (RH_NULL, None),
            &[1; 16],
        );
        ok(&both.same(&policy(POLICY_NV_WRITTEN, POLICY_SESSION, &[0])));
        ok(&both.same(&policy(
            POLICY_COMMAND_CODE,
            POLICY_SESSION,
            &nv::NV_WRITE.to_be_bytes(),
        )));
        let p = params(ok(&both.same(&nv::read_public(0x0100_0002))), false);
        let name = split2b(split2b(&p).1).0;
        let mut cmd = client::Command::new(
            nv::NV_WRITE,
            &[0x0100_0002, 0x0100_0002],
            &[tpm2b(b"once"), vec![0, 0]].concat(),
            vec![policy_auth(0, Some(b""), false)],
        );
        cmd.names = vec![name.clone(), name];
        both.run(&mut sessions, &cmd);
        flush(&mut both, POLICY_SESSION);
        sessions.ours.clear();
        sessions.theirs.clear();
    }
    both.same(&nv::nv_read(0x0100_0002, 0x0100_0002, 4, 0));
}

/// The policy commands the mutation pass starts from: on a policy session (0x03000000) the
/// corpus' StartAuthSession makes, and the NV index of the NV corpus.
pub fn mutation_corpus() -> Vec<Vec<u8>> {
    let s = POLICY_SESSION;
    let mut corpus = assertions(s);
    corpus.extend(bindings(s, 32));
    corpus.extend([
        start(SE_POLICY, client::SHA256),
        start(SE_TRIAL, client::SHA1),
        command(
            POLICY_SECRET,
            &[RH_OWNER, s],
            Some(&password(b"")),
            &[
                tpm2b(b""),
                tpm2b(b""),
                tpm2b(b"r"),
                vec![0xff, 0xff, 0xff, 0xf0],
            ]
            .concat(),
        ),
        command(
            POLICY_NV,
            &[RH_OWNER, INDEX, s],
            Some(&password(b"")),
            &[tpm2b(&[0]), vec![0, 0, 0, 0]].concat(),
        ),
        command(
            POLICY_AUTHORIZE_NV,
            &[RH_OWNER, INDEX, s],
            Some(&password(b"")),
            &[],
        ),
        policy(
            POLICY_TICKET,
            s,
            &[
                tpm2b(&[0; 8]),
                tpm2b(b""),
                tpm2b(b""),
                tpm2b(b""),
                vec![0x80, 0x23, 0x40, 0, 0, 1, 0, 0],
            ]
            .concat(),
        ),
        policy(
            POLICY_AUTHORIZE,
            s,
            &[
                tpm2b(&[0; 32]),
                tpm2b(b""),
                tpm2b(&[0, 0x0b, 0, 0]),
                vec![0x80, 0x22, 0x40, 0, 0, 7, 0, 0],
            ]
            .concat(),
        ),
        policy(POLICY_GET_DIGEST, s, &[]),
    ]);
    corpus
}
