//! Differential tests of attestation and credentials: each TPMS_ATTEST compared byte for byte,
//! Clock, TPM time and the firmware version aside (each engine's own); each signature verified
//! by the other engine; credentials made by one engine activated by the other.

use super::nv::{READ_STCLEAR, RW, define_owner, nv_command, nv_write};
use super::objects::*;
use super::*;

pub const ACTIVATE_CREDENTIAL: u32 = 0x147;
pub const CERTIFY: u32 = 0x148;
pub const CERTIFY_CREATION: u32 = 0x14a;
pub const GET_TIME: u32 = 0x14c;
pub const GET_SESSION_AUDIT_DIGEST: u32 = 0x14d;
pub const QUOTE: u32 = 0x158;
pub const MAKE_CREDENTIAL: u32 = 0x168;
pub const NV_CERTIFY: u32 = 0x184;

const TPM_ST_ATTEST_TIME: u16 = 0x8019;

fn passwords(n: usize) -> Vec<u8> {
    (0..n).flat_map(|_| password(b"")).collect()
}

/// qualifyingData and inScheme.
fn common(extra: &[u8], scheme: &[u8]) -> Vec<u8> {
    [tpm2b(extra), scheme.to_vec()].concat()
}

pub fn quote(key: u32, extra: &[u8], scheme: &[u8], pcrs: &[u8]) -> Vec<u8> {
    let p = [common(extra, scheme), pcrs.to_vec()].concat();
    command(QUOTE, &[key], Some(&passwords(1)), &p)
}

pub fn certify(object: u32, key: u32, extra: &[u8], scheme: &[u8]) -> Vec<u8> {
    command(
        CERTIFY,
        &[object, key],
        Some(&passwords(2)),
        &common(extra, scheme),
    )
}

pub fn get_time(key: u32, scheme: &[u8]) -> Vec<u8> {
    let p = common(b"time", scheme);
    command(GET_TIME, &[RH_ENDORSEMENT, key], Some(&passwords(2)), &p)
}

pub fn nv_certify(key: u32, auth: u32, index: u32, size: u16, offset: u16) -> Vec<u8> {
    let p = [
        common(b"nv", NULL),
        size.to_be_bytes().to_vec(),
        offset.to_be_bytes().to_vec(),
    ]
    .concat();
    command(NV_CERTIFY, &[key, auth, index], Some(&passwords(2)), &p)
}

/// A TPMS_ATTEST with what each engine fills in its own way zeroed: Clock, the firmware
/// version, and in a TPMS_TIME_ATTEST_INFO TPM time and Clock again (and that firmware version).
fn masked(attest: &[u8]) -> Vec<u8> {
    let mut a = attest.to_vec();
    let kind = u16::from_be_bytes([a[4], a[5]]);
    let mut at = 6;
    for _ in 0..2 {
        at += 2 + u16::from_be_bytes([a[at], a[at + 1]]) as usize;
    }
    a[at..at + 8].fill(0);
    let firmware = at + 8 + 4 + 4 + 1;
    a[firmware..firmware + 8].fill(0);
    if kind == TPM_ST_ATTEST_TIME {
        let time = firmware + 8;
        a[time..time + 16].fill(0);
        let firmware = time + 8 + 8 + 4 + 4 + 1;
        a[firmware..firmware + 8].fill(0);
    }
    a
}

/// An attestation both engines answer: the same code, the same TPMS_ATTEST but for what
/// [`masked`] zeroes, and each signature (by `key`, a key both have, unless TPM_RH_NULL)
/// verified by the other engine. The response code.
#[track_caller]
fn attested(both: &mut Both, cmd: &[u8], key: u32) -> u32 {
    let (ours, theirs) = both.both(cmd);
    assert_eq!(rc(&ours), rc(&theirs), "command {}", hex(cmd));
    if rc(&ours) != 0 {
        assert_eq!(hex(&ours), hex(&theirs), "command {}", hex(cmd));
        return rc(&ours);
    }
    let (ours, theirs) = (params(&ours, false), params(&theirs, false));
    let (our_attest, our_signature) = split2b(&ours);
    let (their_attest, their_signature) = split2b(&theirs);
    assert_eq!(
        hex(&masked(&our_attest)),
        hex(&masked(&their_attest)),
        "command {}",
        hex(cmd)
    );
    assert_eq!(our_signature.len(), their_signature.len());
    if key == RH_NULL {
        assert_eq!(our_signature, [0, 0x10]);
        assert_eq!(their_signature, [0, 0x10]);
        return 0;
    }
    let hash = u16::from_be_bytes([our_signature[2], our_signature[3]]);
    let digest = client::digest(hash, &[&our_attest]);
    ok(&both.theirs.process(&verify(key, &digest, our_signature)));
    let digest = client::digest(hash, &[&their_attest]);
    ok(&both.ours.process(&verify(key, &digest, their_signature)));
    0
}

/// An ECDSA key that signs anything (not restricted) and one restricted (an attestation key),
/// and an HMAC key, in `hierarchy`; their handles.
fn signing_keys(both: &mut Both, hierarchy: u32) -> [u32; 3] {
    let restricted = public(
        ALG_ECC,
        SIGNING | RESTRICTED,
        &ecc(NULL, ECDSA_SHA256),
        ECC_UNIQUE,
    );
    [ecdsa_key(), restricted, hmac_key()]
        .map(|template| handle(&both.same(&create_primary(hierarchy, &template))))
}

fn flush_all(both: &mut Both, handles: &[u32]) {
    for h in handles {
        both.same(&command(FLUSH_CONTEXT, &[], None, &h.to_be_bytes()));
    }
}

#[test]
fn quotes_match() {
    let mut both = Both::seeded();
    both.same(&extend(16, &[(0x0b, vec![5; 32]), (0x04, vec![6; 20])]));
    let pcrs = [
        selection(&[(0x0b, &[0x01, 0, 1])]),
        selection(&[(0x0b, &[0xff, 0xff, 0xff]), (0x04, &[0, 0, 1])]),
        selection(&[(0x0c, &[1, 2, 3, 4])]),
        selection(&[]),
    ];
    // Endorsement keys report the reset counters as they are; owner and null keys obfuscated.
    for hierarchy in [RH_ENDORSEMENT, RH_OWNER, RH_PLATFORM] {
        let keys = signing_keys(&mut both, hierarchy);
        for key in keys {
            for scheme in [NULL, ECDSA_SHA256, &[0, 0x18, 0, 0x04], &[0, 5, 0, 0x0b]] {
                for pcrs in &pcrs {
                    attested(&mut both, &quote(key, b"nonce", scheme, pcrs), key);
                }
            }
        }
        flush_all(&mut both, &keys);
    }
    // No key: no scheme, so no hash to quote with.
    attested(&mut both, &quote(RH_NULL, b"", NULL, &pcrs[0]), RH_NULL);
    // Not a signing key; a scheme the key does not have; qualifying data too long.
    let srk = handle(&both.same(&create_primary(RH_OWNER, &ecc_srk())));
    both.same(&quote(srk, b"", NULL, &pcrs[0]));
    flush_all(&mut both, &[srk]);
    let [key, ..] = signing_keys(&mut both, RH_OWNER);
    both.same(&quote(key, b"", &[0, 0x14, 0, 0x0b], &pcrs[0]));
    both.same(&quote(key, &[1; 67], NULL, &pcrs[0]));
    // After a Restart, the counters moved.
    both.same(&command(SHUTDOWN, &[], None, &[0, 1]));
    both.power_cycle();
    both.same(&command(STARTUP, &[], None, &[0, 1]));
    let [key, ..] = signing_keys(&mut both, RH_OWNER);
    attested(&mut both, &quote(key, b"", ECDSA_SHA256, &pcrs[1]), key);
}

#[test]
fn certify_and_get_time_match() {
    let mut both = Both::seeded();
    let keys = signing_keys(&mut both, RH_ENDORSEMENT);
    let [ecdsa, restricted, hmac] = keys;
    for key in [ecdsa, restricted, hmac, RH_NULL] {
        for object in [ecdsa, hmac] {
            attested(&mut both, &certify(object, key, b"q", NULL), key);
        }
        attested(&mut both, &get_time(key, NULL), key);
    }
    // A scheme mismatch, a sequence that is not a key, the ADMIN role of a key that needs its
    // policy for it.
    both.same(&certify(ecdsa, hmac, b"", ECDSA_SHA256));
    flush_all(&mut both, &[restricted, hmac]);
    let seq = handle(&both.same(&command(HASH_SEQUENCE_START, &[], None, &[0, 0, 0, 0x0b])));
    both.same(&certify(ecdsa, seq, b"", NULL));
    both.same(&get_time(seq, NULL));
    flush_all(&mut both, &[seq]);
    let admin = public(
        ALG_ECC,
        SIGNING | ADMIN_WITH_POLICY,
        &ecc(NULL, ECDSA_SHA256),
        ECC_UNIQUE,
    );
    let admin = handle(&both.same(&create_primary(RH_OWNER, &admin)));
    both.same(&certify(admin, ecdsa, b"", NULL));
    // The endorsement hierarchy disabled: no privacy administrator.
    both.same(&hierarchy_control(RH_PLATFORM, RH_ENDORSEMENT, 0));
    both.same(&get_time(RH_NULL, NULL));
}

#[test]
fn certify_creation_matches() {
    let mut both = Both::seeded();
    let key = handle(&both.same(&create_primary(RH_ENDORSEMENT, &ecdsa_key())));
    let p = create_params(b"", b"", &ecc_srk(), b"outside", &no_pcrs());
    let created = both.same(&with_password(CREATE_PRIMARY, RH_OWNER, b"", &p));
    let object = handle(&created);
    let out = params(&created, true);
    let (_, rest) = split2b(&out);
    let (_, rest) = split2b(rest);
    let (creation_hash, ticket) = split2b(rest);
    let ticket = ticket[..ticket.len() - 36].to_vec();
    let certify_creation = |key: u32, hash: &[u8], ticket: &[u8]| {
        let p = [tpm2b(b"q"), tpm2b(hash), NULL.to_vec(), ticket.to_vec()].concat();
        command(CERTIFY_CREATION, &[key, object], Some(&passwords(1)), &p)
    };
    for key in [key, RH_NULL] {
        attested(
            &mut both,
            &certify_creation(key, &creation_hash, &ticket),
            key,
        );
    }
    // Another creation hash, a tampered ticket, a ticket of another kind.
    both.same(&certify_creation(key, &[0; 32], &ticket));
    let mut tampered = ticket.clone();
    *tampered.last_mut().unwrap() ^= 1;
    both.same(&certify_creation(key, &creation_hash, &tampered));
    let mut other = ticket.clone();
    other[1] = 0x24;
    both.same(&certify_creation(key, &creation_hash, &other));
}

#[test]
fn nv_certify_matches() {
    let mut both = Both::seeded();
    let [key, _, hmac] = signing_keys(&mut both, RH_OWNER);
    let index = 0x0100_0010;
    ok(&both.same(&define_owner(index, RW, 40)));
    // Not written yet.
    both.same(&nv_certify(key, RH_OWNER, index, 4, 0));
    ok(&both.same(&nv_write(RH_OWNER, index, &[7; 40], 0)));
    for signer in [key, hmac, RH_NULL] {
        for (size, offset) in [(4, 0), (8, 32), (0, 0), (0, 3), (40, 0)] {
            attested(
                &mut both,
                &nv_certify(signer, RH_OWNER, index, size, offset),
                signer,
            );
        }
        attested(&mut both, &nv_certify(signer, index, index, 1, 1), signer);
    }
    // Out of range, too large, read-locked.
    both.same(&nv_certify(key, RH_OWNER, index, 8, 33));
    both.same(&nv_certify(key, RH_OWNER, index, 41, 0));
    both.same(&nv_certify(key, RH_PLATFORM, index, 1, 0));
    let big = 0x0100_0011;
    both.same(&define_owner(big, RW | READ_STCLEAR, 1100));
    both.same(&nv_write(RH_OWNER, big, &[1; 1024], 0));
    both.same(&nv_certify(key, RH_OWNER, big, 1025, 0));
    both.same(&nv_command(nv::NV_READ_LOCK, RH_OWNER, big, b"", &[]));
    both.same(&nv_certify(key, RH_OWNER, big, 1, 0));
}

#[test]
fn session_audit_digests_match() {
    let mut both = Both::seeded();
    let mut s = Sessions::default();
    let bind = (RH_NULL, None);
    let sha256 = client::SHA256;
    assert_eq!(
        both.start_session(&mut s, SE_HMAC, sha256, Sym::Null, bind, &[5; 16]),
        0
    );
    let audit = Auth::session(0, client::CONTINUE | client::AUDIT, None);
    let p = [tpm2b(b"audited"), vec![0, 0x0b, 0x40, 0, 0, 7]].concat();
    let get = |key: u32, session: u32| {
        command(
            GET_SESSION_AUDIT_DIGEST,
            &[RH_ENDORSEMENT, key, session],
            Some(&passwords(2)),
            &common(b"audit", NULL),
        )
    };
    let session = 0x0200_0000;
    // Not auditing yet: TPM_RC_TYPE.
    both.same(&get(RH_NULL, session));
    for _ in 0..3 {
        both.run(
            &mut s,
            &client::Command::new(HASH, &[], &p, vec![audit.clone()]),
        );
        attested(&mut both, &get(RH_NULL, session), RH_NULL);
    }
    let key = handle(&both.same(&create_primary(RH_ENDORSEMENT, &ecdsa_key())));
    attested(&mut both, &get(key, session), key);
    // A policy session is no HMAC session; a session that is not loaded.
    both.same(&get(RH_NULL, 0x0300_0000));
    both.same(&get(RH_NULL, 0x0200_0001));
}

#[test]
fn credentials_activate_on_the_other_engine() {
    let mut both = Both::seeded();
    // The EK: an ECC storage key of the endorsement hierarchy, the same on both; the object
    // the credential is for, the same on both too.
    let ek = handle(&both.same(&create_primary(RH_ENDORSEMENT, &ecc_srk())));
    let object = handle(&both.same(&create_primary(RH_OWNER, &ecdsa_key())));
    let name = split2b(&params(
        &both.same(&command(READ_PUBLIC, &[object], None, &[])),
        false,
    ))
    .1
    .to_vec();
    let name = split2b(&name).0;
    let make = |key: u32, credential: &[u8], name: &[u8]| {
        command(
            MAKE_CREDENTIAL,
            &[key],
            None,
            &[tpm2b(credential), tpm2b(name)].concat(),
        )
    };
    let activate = |blob: &[u8], secret: &[u8]| {
        let p = [tpm2b(blob), tpm2b(secret)].concat();
        command(ACTIVATE_CREDENTIAL, &[object, ek], Some(&passwords(2)), &p)
    };
    for credential in [&b"the credential"[..], &[9; 32], b""] {
        let (ours, theirs) = both.both(&make(ek, credential, &name));
        assert_eq!((rc(&ours), ours.len()), (0, theirs.len()));
        for (made, by_ours) in [(ours, true), (theirs, false)] {
            let p = params(&made, false);
            let (blob, rest) = split2b(&p);
            let (secret, _) = split2b(rest);
            let cmd = activate(&blob, &secret);
            let r = if by_ours {
                both.theirs.process(&cmd)
            } else {
                both.ours.process(&cmd)
            };
            assert_eq!(split2b(&params(ok(&r), false)).0, credential);
            // Both refuse it alike once tampered with.
            for at in [0, 3, blob.len() - 1] {
                let mut tampered = blob.clone();
                tampered[at] ^= 1;
                both.same(&activate(&tampered, &secret));
            }
            both.same(&activate(&blob[..2], &secret));
            both.same(&activate(&blob, &secret[..10]));
        }
    }
    // A credential too long for the EK's nameAlg; a key that is no EK.
    both.same(&make(ek, &[1; 33], &name));
    both.same(&make(object, b"c", &name));
    both.same(&activate(b"", b""));
    let unrestricted = handle(&both.same(&load_external(
        &external_ecc_public(),
        ALG_ECC,
        None,
        RH_NULL,
    )));
    both.same(&make(unrestricted, b"c", &name));
    // An RSA EK (each engine's own): its public half, loaded on the other engine, makes
    // credentials for it.
    let rsa_ek = public(ALG_RSA, STORAGE, &rsa(AES128_CFB, NULL, 2048), &tpm2b(b""));
    flush_all(&mut both, &[unrestricted, ek]);
    let mut rsa_handle = 0;
    let mut publics = Vec::new();
    for ours in [true, false] {
        let r = on(&mut both, ours, &create_primary(RH_ENDORSEMENT, &rsa_ek));
        rsa_handle = handle(&r);
        publics.push(out_public(&params(&r, true), 0));
    }
    for (maker, public) in [(true, &publics[1]), (false, &publics[0])] {
        let load = load_external(public, ALG_RSA, None, RH_OWNER);
        let external = handle(&on(&mut both, maker, &load));
        let made = on(&mut both, maker, &make(external, b"rsa credential", &name));
        let p = params(ok(&made), false);
        let (blob, rest) = split2b(&p);
        let (secret, _) = split2b(rest);
        let p = [tpm2b(&blob), tpm2b(&secret)].concat();
        let cmd = command(
            ACTIVATE_CREDENTIAL,
            &[object, rsa_handle],
            Some(&passwords(2)),
            &p,
        );
        let r = on(&mut both, !maker, &cmd);
        assert_eq!(split2b(&params(ok(&r), false)).0, b"rsa credential");
        on(
            &mut both,
            maker,
            &command(FLUSH_CONTEXT, &[], None, &external.to_be_bytes()),
        );
    }
}

/// `cmd` on one engine only: ours, or libtpms.
fn on(both: &mut Both, ours: bool, cmd: &[u8]) -> Vec<u8> {
    if ours {
        both.ours.process(cmd)
    } else {
        both.theirs.process(cmd)
    }
}

/// The commands whose answers hold each engine's own values: Clock and the firmware version in
/// an attestation, a random seed in a credential.
pub fn answers_randomly(code: u32) -> bool {
    matches!(
        code,
        QUOTE
            | CERTIFY
            | CERTIFY_CREATION
            | GET_TIME
            | GET_SESSION_AUDIT_DIGEST
            | NV_CERTIFY
            | MAKE_CREDENTIAL
    )
}

/// The attestation commands the mutation pass starts from: keys at the handles the objects
/// corpus loads (an HMAC key at 0x80000001, ECC keys at 0x80000002), the index of the NV
/// corpus, the HMAC session its StartAuthSession makes.
pub fn mutation_corpus() -> Vec<Vec<u8>> {
    let pcrs = selection(&[(0x0b, &[0x01, 0, 1])]);
    let ticket = [&[0x80, 0x21][..], &RH_OWNER.to_be_bytes(), &tpm2b(&[0; 64])].concat();
    let creation = [tpm2b(b"q"), tpm2b(&[0; 32]), NULL.to_vec(), ticket].concat();
    let credential = [tpm2b(b"credential"), tpm2b(&[0, 0x0b, 1, 2])].concat();
    let activation = [tpm2b(&[0; 70]), tpm2b(&[0; 68])].concat();
    vec![
        quote(0x8000_0001, b"nonce", NULL, &pcrs),
        quote(0x8000_0002, b"", ECDSA_SHA256, &pcrs),
        quote(RH_NULL, b"", NULL, &pcrs),
        certify(0x8000_0001, 0x8000_0001, b"q", NULL),
        get_time(0x8000_0001, NULL),
        command(
            CERTIFY_CREATION,
            &[RH_NULL, 0x8000_0000],
            Some(&passwords(1)),
            &creation,
        ),
        nv_certify(RH_NULL, RH_OWNER, nv::INDEX, 4, 0),
        command(
            GET_SESSION_AUDIT_DIGEST,
            &[RH_ENDORSEMENT, RH_NULL, 0x0200_0000],
            Some(&passwords(2)),
            &common(b"", NULL),
        ),
        command(MAKE_CREDENTIAL, &[0x8000_0000], None, &credential),
        command(
            ACTIVATE_CREDENTIAL,
            &[0x8000_0001, 0x8000_0000],
            Some(&passwords(2)),
            &activation,
        ),
    ]
}
