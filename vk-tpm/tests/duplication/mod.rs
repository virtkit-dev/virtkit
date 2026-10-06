//! Differential tests of duplication: what one engine duplicates (TPM2_Duplicate, behind a
//! policy that allows it) both import (TPM2_Import), load and unseal; duplicates the test makes
//! itself, plain or inside-wrapped, likewise; and both refuse broken ones alike.

use super::objects::*;
use super::policy::{POLICY_COMMAND_CODE, policy};
use super::*;

pub const DUPLICATE: u32 = 0x14b;
pub const IMPORT: u32 = 0x156;

const POLICY_SESSION: u32 = 0x0300_0000;
/// TPMA_OBJECT_ENCRYPTEDDUPLICATION.
const ENCRYPTED_DUPLICATION: u32 = 1 << 11;
/// AES-128 (CFB) as a duplicate's inner wrap.
const AES128: &[u8] = &[0, 6, 0, 0x80, 0, 0x43];

/// The policy that lets a policy session take the DUP role: TPM2_PolicyCommandCode of
/// TPM2_Duplicate.
fn dup_policy() -> Vec<u8> {
    let code = POLICY_COMMAND_CODE.to_be_bytes();
    client::digest(client::SHA256, &[&[0; 32], &code, &DUPLICATE.to_be_bytes()])
}

/// A sealed object that may be duplicated (neither fixedTPM nor fixedParent), with the
/// duplication policy and `extra` attributes.
fn movable(extra: u32) -> Vec<u8> {
    let mut template = public(ALG_KEYEDHASH, USER_WITH_AUTH | extra, NULL, &tpm2b(b""));
    template.splice(8..10, tpm2b(&dup_policy()));
    template
}

/// A TPM2B_SENSITIVE of a keyed-hash object: authValue `auth` (padded to SHA-256), a seed, the
/// secret.
fn sensitive_area(auth: &[u8], secret: &[u8]) -> Vec<u8> {
    let mut auth = auth.to_vec();
    auth.resize(32, 0);
    let s = [
        &ALG_KEYEDHASH.to_be_bytes()[..],
        &tpm2b(&auth),
        &tpm2b(&[4; 32]),
        &tpm2b(secret),
    ]
    .concat();
    tpm2b(&s)
}

/// The template `movable` makes, with its unique digest for that sensitive area: H(seed ‖
/// secret).
fn movable_public(extra: u32, secret: &[u8]) -> Vec<u8> {
    let mut p = movable(extra);
    let unique = client::digest(client::SHA256, &[&[4; 32], secret]);
    p.truncate(p.len() - 2);
    p.extend_from_slice(&tpm2b(&unique));
    p
}

pub fn import(
    parent: u32,
    key: &[u8],
    public: &[u8],
    duplicate: &[u8],
    seed: &[u8],
    sym: &[u8],
) -> Vec<u8> {
    let p = [
        tpm2b(key),
        tpm2b(public),
        tpm2b(duplicate),
        tpm2b(seed),
        sym.to_vec(),
    ]
    .concat();
    with_password(IMPORT, parent, b"", &p)
}

/// Import on both: the same code and size (the result is wrapped with a random IV); then each
/// engine's blob loads on both, and unseals `secret`.
#[track_caller]
fn import_on_both(both: &mut Both, parent: u32, public: &[u8], cmd: &[u8], secret: &[u8]) {
    let (ours, theirs) = both.both(cmd);
    assert_eq!(
        (rc(&ours), ours.len()),
        (0, theirs.len()),
        "command {}",
        hex(cmd)
    );
    for made in [ours, theirs] {
        let private = split2b(&params(&made, false)).0;
        let load = with_password(
            LOAD,
            parent,
            b"",
            &[tpm2b(&private), tpm2b(public)].concat(),
        );
        let loaded = handle(&both.same(&load));
        let unseal = command(UNSEAL, &[loaded], Some(&password(b"pw")), &[]);
        assert_eq!(split2b(&params(ok(&both.same(&unseal)), false)).0, secret);
        both.same(&command(FLUSH_CONTEXT, &[], None, &loaded.to_be_bytes()));
    }
}

/// The inner wrap: H(data ‖ Name) and the data, AES-128-CFB with a zero IV.
fn inner_wrap(key: &[u8], name: &[u8], data: &[u8]) -> Vec<u8> {
    let integrity = client::digest(client::SHA256, &[data, name]);
    let mut wrapped = [tpm2b(&integrity), data.to_vec()].concat();
    client::aes_cfb(key, &[0; 16], &mut wrapped, true);
    wrapped
}

fn name_of(public: &[u8]) -> Vec<u8> {
    [&[0, 0x0b][..], &client::digest(client::SHA256, &[public])].concat()
}

#[test]
fn imports_of_test_made_duplicates_match() {
    let mut both = Both::seeded();
    let srk = handle(&both.same(&create_primary(RH_OWNER, &ecc_srk())));
    let public = movable_public(0, b"imported");
    let name = name_of(&public);
    let data = sensitive_area(b"pw", b"imported");
    // Plain, and inside-wrapped.
    import_on_both(
        &mut both,
        srk,
        &public,
        &import(srk, b"", &public, &data, b"", NULL),
        b"imported",
    );
    let key = [3u8; 16];
    let wrapped = inner_wrap(&key, &name, &data);
    let cmd = import(srk, &key, &public, &wrapped, b"", AES128);
    import_on_both(&mut both, srk, &public, &cmd, b"imported");
    // Refused alike: the wrong inner key, a tampered duplicate, sizes that do not add up,
    // attributes a duplicate cannot have, a key of the wrong size, an inner key without inner
    // wrap, encryptedDuplication without either wrap, no parent.
    both.same(&import(srk, &[4; 16], &public, &wrapped, b"", AES128));
    for at in [0, 5, wrapped.len() - 1] {
        let mut tampered = wrapped.clone();
        tampered[at] ^= 1;
        both.same(&import(srk, &key, &public, &tampered, b"", AES128));
    }
    let mut short = data.clone();
    short.pop();
    both.same(&import(srk, b"", &public, &short, b"", NULL));
    both.same(&import(
        srk,
        b"",
        &public,
        &[data.clone(), vec![0]].concat(),
        b"",
        NULL,
    ));
    both.same(&import(srk, b"", &public, &data[..1], b"", NULL));
    both.same(&import(srk, b"", &public, b"", b"", NULL));
    for attributes in [FIXED_TPM | FIXED_PARENT, FIXED_PARENT] {
        let fixed = movable_public(attributes, b"imported");
        both.same(&import(srk, b"", &fixed, &data, b"", NULL));
    }
    both.same(&import(srk, &[1; 15], &public, &wrapped, b"", AES128));
    both.same(&import(srk, &key, &public, &data, b"", NULL));
    let encrypted = movable_public(ENCRYPTED_DUPLICATION, b"imported");
    both.same(&import(srk, b"", &encrypted, &data, b"", NULL));
    let wrapped = inner_wrap(&key, &name_of(&encrypted), &data);
    both.same(&import(srk, &key, &encrypted, &wrapped, b"", AES128));
    both.same(&import(srk, &key, &public, &wrapped, &[1; 10], AES128));
    let signer = handle(&both.same(&create_primary(RH_OWNER, &ecdsa_key())));
    both.same(&import(signer, b"", &public, &data, b"", NULL));
    // Another public area than the duplicate's: its unique digest does not bind.
    let other = movable_public(0, b"other");
    both.same(&import(srk, b"", &other, &data, b"", NULL));
}

#[test]
fn duplicates_import_on_both() {
    let mut both = Both::seeded();
    let srk = handle(&both.same(&create_primary(RH_OWNER, &ecc_srk())));
    let mut imported = 0;
    // The object: made by libtpms under the shared storage key, loaded on both.
    for extra in [0, ENCRYPTED_DUPLICATION] {
        let template = movable(extra);
        let p = create_params(b"pw", b"moved", &template, b"", &no_pcrs());
        let created = params(
            ok(&both.theirs.process(&with_password(CREATE, srk, b"", &p))),
            false,
        );
        let (private, rest) = split2b(&created);
        let public = split2b(rest).0;
        let load = with_password(LOAD, srk, b"", &[tpm2b(&private), tpm2b(&public)].concat());
        let object = handle(&both.same(&load));
        let name = name_of(&public);
        let mut sessions = Sessions::default();
        for (new_parent, key_in, sym) in [
            (srk, &b""[..], AES128),
            (srk, &[5; 16], AES128),
            (srk, b"", NULL),
            (RH_NULL, b"", AES128),
            (RH_NULL, b"", NULL),
        ] {
            both.start_session(
                &mut sessions,
                SE_POLICY,
                client::SHA256,
                Sym::Null,
                (RH_NULL, None),
                &[1; 16],
            );
            let index = sessions.ours.len() - 1;
            ok(&both.same(&policy(
                POLICY_COMMAND_CODE,
                POLICY_SESSION,
                &DUPLICATE.to_be_bytes(),
            )));
            let auth = Auth::Session {
                index,
                attributes: client::CONTINUE,
                entity: Some(b"pw".to_vec()),
                bound: true,
                after: None,
                hmac: None,
            };
            let p = [tpm2b(key_in), sym.to_vec()].concat();
            let mut cmd = client::Command::new(DUPLICATE, &[object, new_parent], &p, vec![auth]);
            cmd.names = vec![
                name.clone(),
                if new_parent == RH_NULL {
                    new_parent.to_be_bytes().to_vec()
                } else {
                    object_name(&mut both, srk)
                },
            ];
            let (ours, theirs) = both.run_apart(&mut sessions, &cmd);
            assert_eq!(ours.rc, theirs.rc);
            assert_eq!(ours.params.len(), theirs.params.len());
            both.same(&command(
                FLUSH_CONTEXT,
                &[],
                None,
                &POLICY_SESSION.to_be_bytes(),
            ));
            sessions.ours.pop();
            sessions.theirs.pop();
            if ours.rc != 0 {
                continue;
            }
            for made in [ours.params, theirs.params] {
                let (key_out, rest) = split2b(&made);
                let (duplicate, rest) = split2b(rest);
                let (seed, _) = split2b(rest);
                assert_eq!(
                    key_out.len(),
                    if key_in.is_empty() && sym != NULL {
                        16
                    } else {
                        0
                    }
                );
                let key = if key_out.is_empty() {
                    key_in.to_vec()
                } else {
                    key_out
                };
                let cmd = import(srk, &key, &public, &duplicate, &seed, sym);
                import_on_both(&mut both, srk, &public, &cmd, b"moved");
                imported += 1;
            }
        }
        both.same(&command(FLUSH_CONTEXT, &[], None, &object.to_be_bytes()));
    }
    // Each engine's duplicates, for both parents, with and without wraps; encryptedDuplication
    // takes both.
    assert_eq!(imported, 14);
    // Refused alike: a fixedParent object (its policy aside), the DUP role by authValue.
    let fixed = create_params(b"pw", b"x", &sealed(), b"", &no_pcrs());
    let fixed = handle(&both.same(&with_password(CREATE_PRIMARY, RH_OWNER, b"", &fixed)));
    both.same(&with_password(DUPLICATE, fixed, b"pw", &[0, 0, 0, 0x10]));
}

/// The Name of a loaded object.
fn object_name(both: &mut Both, handle: u32) -> Vec<u8> {
    let p = params(
        ok(&both.same(&command(READ_PUBLIC, &[handle], None, &[]))),
        false,
    );
    split2b(split2b(&p).1).0
}

/// TPM2_Import commands the mutation pass starts from: a plain duplicate under the ECC storage
/// key the objects corpus makes at 0x80000000.
pub fn mutation_corpus() -> Vec<Vec<u8>> {
    let public = movable_public(0, b"imported");
    let data = sensitive_area(b"pw", b"imported");
    let wrapped = inner_wrap(&[3; 16], &name_of(&public), &data);
    vec![
        import(0x8000_0000, b"", &public, &data, b"", NULL),
        import(0x8000_0000, &[3; 16], &public, &wrapped, b"", AES128),
        with_password(DUPLICATE, 0x8000_0001, b"", &[0, 0, 0, 0x10]),
    ]
}
