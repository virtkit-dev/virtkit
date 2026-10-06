//! Differential tests of objects and keys: primaries derived from the same seeds, wrapped
//! objects loaded across engines, signatures and ciphertexts checked by the other engine,
//! contexts, persistent objects.

use super::*;

pub const CREATE_PRIMARY: u32 = 0x131;
pub const EVICT_CONTROL: u32 = 0x120;
pub const CREATE: u32 = 0x153;
pub const LOAD: u32 = 0x157;
pub const LOAD_EXTERNAL: u32 = 0x167;
pub const READ_PUBLIC: u32 = 0x173;
pub const OBJECT_CHANGE_AUTH: u32 = 0x150;
pub const UNSEAL: u32 = 0x15e;
pub const CONTEXT_SAVE: u32 = 0x162;
pub const CONTEXT_LOAD: u32 = 0x161;
pub const SIGN: u32 = 0x15d;
pub const VERIFY_SIGNATURE: u32 = 0x177;
pub const RSA_ENCRYPT: u32 = 0x174;
pub const RSA_DECRYPT: u32 = 0x159;
pub const ECDH_KEYGEN: u32 = 0x163;
pub const ECDH_ZGEN: u32 = 0x154;
pub const ECC_PARAMETERS: u32 = 0x178;
pub const HMAC: u32 = 0x155;
pub const HMAC_START: u32 = 0x15b;
pub const TEST_PARMS: u32 = 0x18a;
pub const STIR_RANDOM: u32 = 0x146;
pub const GET_TEST_RESULT: u32 = 0x17c;
pub const READ_CLOCK: u32 = 0x181;

// TPMA_OBJECT.
pub const FIXED_TPM: u32 = 1 << 1;
pub const ST_CLEAR: u32 = 1 << 2;
pub const FIXED_PARENT: u32 = 1 << 4;
pub const ORIGIN: u32 = 1 << 5;
pub const USER_WITH_AUTH: u32 = 1 << 6;
pub const ADMIN_WITH_POLICY: u32 = 1 << 7;
pub const NO_DA: u32 = 1 << 10;
pub const RESTRICTED: u32 = 1 << 16;
pub const DECRYPT: u32 = 1 << 17;
pub const SIGN_ATTR: u32 = 1 << 18;

pub const STORAGE: u32 =
    FIXED_TPM | FIXED_PARENT | ORIGIN | USER_WITH_AUTH | NO_DA | RESTRICTED | DECRYPT;
pub const SIGNING: u32 = FIXED_TPM | FIXED_PARENT | ORIGIN | USER_WITH_AUTH | SIGN_ATTR;

pub const ALG_RSA: u16 = 0x01;
pub const ALG_KEYEDHASH: u16 = 0x08;
pub const ALG_ECC: u16 = 0x23;
pub const ALG_SYMCIPHER: u16 = 0x25;

/// AES-128 in CFB mode (TPMT_SYM_DEF_OBJECT).
pub const AES128_CFB: &[u8] = &[0, 6, 0, 0x80, 0, 0x43];
pub const NULL: &[u8] = &[0, 0x10];

/// A TPMT_PUBLIC.
pub fn public(kind: u16, attributes: u32, params: &[u8], unique: &[u8]) -> Vec<u8> {
    [
        &kind.to_be_bytes()[..],
        &client::SHA256.to_be_bytes(),
        &attributes.to_be_bytes(),
        &tpm2b(b""),
        params,
        unique,
    ]
    .concat()
}

/// ECC P-256 parameters: symmetric definition, scheme.
pub fn ecc(symmetric: &[u8], scheme: &[u8]) -> Vec<u8> {
    [symmetric, scheme, &[0, 3], NULL].concat()
}

pub const ECC_UNIQUE: &[u8] = &[0, 0, 0, 0];

/// RSA parameters: symmetric definition, scheme, key bits.
pub fn rsa(symmetric: &[u8], scheme: &[u8], bits: u16) -> Vec<u8> {
    [symmetric, scheme, &bits.to_be_bytes(), &[0, 0, 0, 0]].concat()
}

pub fn ecc_srk() -> Vec<u8> {
    public(ALG_ECC, STORAGE, &ecc(AES128_CFB, NULL), ECC_UNIQUE)
}

pub fn ecdsa_key() -> Vec<u8> {
    public(
        ALG_ECC,
        SIGNING,
        &ecc(NULL, &[0, 0x18, 0, 0x0b]),
        ECC_UNIQUE,
    )
}

pub fn hmac_key() -> Vec<u8> {
    public(ALG_KEYEDHASH, SIGNING, &[0, 5, 0, 0x0b], &tpm2b(b""))
}

/// A sealed data object (the caller gives its secret).
pub fn sealed() -> Vec<u8> {
    let attributes = FIXED_TPM | FIXED_PARENT | USER_WITH_AUTH;
    public(ALG_KEYEDHASH, attributes, NULL, &tpm2b(b""))
}

/// TPM2B_SENSITIVE_CREATE.
pub fn sensitive(auth: &[u8], data: &[u8]) -> Vec<u8> {
    tpm2b(&[tpm2b(auth), tpm2b(data)].concat())
}

/// The parameters of TPM2_CreatePrimary and TPM2_Create.
pub fn create_params(
    auth: &[u8],
    data: &[u8],
    public: &[u8],
    outside: &[u8],
    pcrs: &[u8],
) -> Vec<u8> {
    [
        sensitive(auth, data),
        tpm2b(public),
        tpm2b(outside),
        pcrs.to_vec(),
    ]
    .concat()
}

pub fn no_pcrs() -> Vec<u8> {
    vec![0, 0, 0, 0]
}

pub fn create_primary(hierarchy: u32, public: &[u8]) -> Vec<u8> {
    let p = create_params(b"", b"", public, b"", &no_pcrs());
    with_password(CREATE_PRIMARY, hierarchy, b"", &p)
}

#[test]
fn primaries_are_derived_as_libtpms_derives_them() {
    let mut both = Both::seeded();
    let mut rsa_srk = public(ALG_RSA, STORAGE, &rsa(AES128_CFB, NULL, 2048), &tpm2b(b""));
    rsa_srk.truncate(rsa_srk.len());
    for hierarchy in [RH_OWNER, RH_ENDORSEMENT, RH_PLATFORM] {
        for template in [
            ecc_srk(),
            ecdsa_key(),
            hmac_key(),
            public(ALG_SYMCIPHER, STORAGE, AES128_CFB, &tpm2b(b"")),
            public(
                ALG_SYMCIPHER,
                STORAGE & !RESTRICTED,
                &[0, 6, 1, 0, 0, 0x43],
                &tpm2b(b""),
            ),
        ] {
            both.same(&create_primary(hierarchy, &template));
            both.same(&command(READ_PUBLIC, &[0x8000_0000], None, &[]));
            both.same(&command(
                FLUSH_CONTEXT,
                &[],
                None,
                &0x8000_0000u32.to_be_bytes(),
            ));
        }
    }
    // Sealed data, an authValue, outside data and PCRs in the creation data.
    both.same(&extend(16, &[(0x0b, vec![5; 32])]));
    let pcrs = selection(&[(0x0b, &[0x01, 0, 1]), (0x04, &[0xff, 0xff, 0xff])]);
    let p = create_params(b"pw\0\0", b"the secret", &sealed(), b"outside", &pcrs);
    both.same(&with_password(CREATE_PRIMARY, RH_OWNER, b"", &p));
    both.same(&command(
        UNSEAL,
        &[0x8000_0000],
        Some(&password(b"pw")),
        &[],
    ));
}

/// The response code is success.
#[track_caller]
pub fn ok(r: &[u8]) -> &[u8] {
    assert_eq!(rc(r), 0, "response {}", hex(r));
    r
}

/// A response's parameters: after the header, the response handle (`handle`), and, for a
/// command with sessions, the parameter size; the sessions are left out.
pub fn params(r: &[u8], handle: bool) -> Vec<u8> {
    let mut at = 10 + if handle { 4 } else { 0 };
    if r[0..2] == [0x80, 0x02] {
        let size = u32::from_be_bytes(r[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        r[at..at + size].to_vec()
    } else {
        r[at..].to_vec()
    }
}

/// The response handle.
pub fn handle(r: &[u8]) -> u32 {
    u32::from_be_bytes(ok(r)[10..14].try_into().unwrap())
}

/// The first TPM2B of `bytes`, and the rest.
pub fn split2b(bytes: &[u8]) -> (Vec<u8>, &[u8]) {
    let size = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    (bytes[2..2 + size].to_vec(), &bytes[2 + size..])
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// A fixed RSA-2048 key (n and the prime p) and a fixed P-256 key (d, x, y).
pub const RSA_N: &str = "e27d4c39369bf37ac6d7d4c7f05c8ac4eddf943a726a2de1a0302c5a946f10c0facbceaf4b5815ca40d661b21fcacde5ebd1b8336a6014cc338275608b0f0ae2eca68bc74b1ffee1b6adc4d7fe169b69fc7e240a5eefef8b0f4c6ef372889bc3f91511b200a9c1bf8a5308a43b04d38aff3b22abe710b2ef5b4beeb70e48433370375358ce3505eb0878847fb107fe7e3010d7d363c6b12d6104b6d340776f299e7676afe2441c49528fe573e6e1b0b007b85ff514c6ff09959bce18c6f361fc20e5dc57da4608a56a7c3242a7280dbf49e08539b2a2a13ae5d4a7622b2fce901e4e6a532bea8452a6f7e56e46ada0d3b9f8300a29e216d6b72b3d5572733cd9";
pub const RSA_P: &str = "fb4fe6639d7b897c4c5159fe7a3e3414fab8d64dfd13e551472d941a3174b495610c25e5758d323ebf97318f30c5b835651f8dd16f2ea26e958a11f83c4224e065bc323dfcf31b0dc033ba7d629d72290e82bdec0a43d12df81861e009a9ce04eeb8736fa1ff111104a81dcd8848165fa03cb88c114fb6f5813e39bd6bf0f5f9";
pub const ECC_D: &str = "af235cdd12ce6ccf8df6cf4e18f15035bbbf6b7dbdbeace49afb951672d886a9";
pub const ECC_X: &str = "d0d528c1d062530f685a929cb78d81e77b9c2c9f7cce8d53ca0807f0fae8418f";
pub const ECC_Y: &str = "57b6d63f94e338242c26136f0936f211735396ccdd23ecfc48ffe46edcffbf0c";

/// A key that signs and decrypts, with no scheme of its own: each command picks one.
const SIGN_DECRYPT: u32 = USER_WITH_AUTH | SIGN_ATTR | DECRYPT;

pub fn external_rsa_public() -> Vec<u8> {
    public(
        ALG_RSA,
        SIGN_DECRYPT,
        &rsa(NULL, NULL, 2048),
        &tpm2b(&unhex(RSA_N)),
    )
}

pub fn external_ecc_public() -> Vec<u8> {
    let unique = [tpm2b(&unhex(ECC_X)), tpm2b(&unhex(ECC_Y))].concat();
    public(ALG_ECC, SIGN_DECRYPT, &ecc(NULL, NULL), &unique)
}

/// TPM2_LoadExternal of a key whose secret is `secret` (a TPMT_SENSITIVE), or of its public
/// area alone.
pub fn load_external(public: &[u8], kind: u16, secret: Option<&[u8]>, hierarchy: u32) -> Vec<u8> {
    let sensitive = match secret {
        Some(s) => tpm2b(&[&kind.to_be_bytes()[..], &tpm2b(b""), &tpm2b(b""), &tpm2b(s)].concat()),
        None => tpm2b(b""),
    };
    let p = [sensitive, tpm2b(public), hierarchy.to_be_bytes().to_vec()].concat();
    command(LOAD_EXTERNAL, &[], None, &p)
}

/// TPM2_Sign with a scheme and no ticket.
pub fn sign(key: u32, digest: &[u8], scheme: &[u8]) -> Vec<u8> {
    let ticket = [&[0x80, 0x24][..], &RH_NULL.to_be_bytes(), &[0, 0]].concat();
    let p = [tpm2b(digest), scheme.to_vec(), ticket].concat();
    with_password(SIGN, key, b"", &p)
}

/// TPM2_VerifySignature of a TPMT_SIGNATURE.
pub fn verify(key: u32, digest: &[u8], signature: &[u8]) -> Vec<u8> {
    command(
        VERIFY_SIGNATURE,
        &[key],
        None,
        &[&tpm2b(digest), signature].concat(),
    )
}

pub fn rsa_encrypt(key: u32, message: &[u8], scheme: &[u8], label: &[u8]) -> Vec<u8> {
    let p = [tpm2b(message), scheme.to_vec(), tpm2b(label)].concat();
    command(RSA_ENCRYPT, &[key], None, &p)
}

pub fn rsa_decrypt(key: u32, ciphertext: &[u8], scheme: &[u8], label: &[u8]) -> Vec<u8> {
    let p = [tpm2b(ciphertext), scheme.to_vec(), tpm2b(label)].concat();
    with_password(RSA_DECRYPT, key, b"", &p)
}

const RSASSA_SHA256: &[u8] = &[0, 0x14, 0, 0x0b];
const RSAPSS_SHA384: &[u8] = &[0, 0x16, 0, 0x0c];
const ECDSA_SHA256: &[u8] = &[0, 0x18, 0, 0x0b];
const OAEP_SHA256: &[u8] = &[0, 0x17, 0, 0x0b];
const RSAES: &[u8] = &[0, 0x15];

#[test]
fn rsa_signatures_and_ciphertexts_cross_check() {
    let mut both = Both::seeded();
    let p = unhex(RSA_P);
    let key = handle(&both.same(&load_external(
        &external_rsa_public(),
        ALG_RSA,
        Some(&p),
        RH_NULL,
    )));
    let digest = client::digest(client::SHA256, &[b"message"]);
    // PKCS#1 v1.5 signatures are deterministic.
    let signature = params(ok(&both.same(&sign(key, &digest, RSASSA_SHA256))), false);
    ok(&both.same(&verify(key, &digest, &signature)));
    // PSS: each one's signature verifies on both.
    let digest384 = client::digest(client::SHA384, &[b"message"]);
    let (ours, theirs) = both.both(&sign(key, &digest384, RSAPSS_SHA384));
    assert_ne!(
        params(ok(&ours), false),
        params(ok(&theirs), false),
        "PSS is salted"
    );
    for signature in [params(&ours, false), params(&theirs, false)] {
        ok(&both.same(&verify(key, &digest384, &signature)));
        let mut bad = signature.clone();
        bad[20] ^= 1;
        both.same(&verify(key, &digest384, &bad));
        both.same(&verify(key, &digest, &signature));
    }
    // Encryption: what one encrypts, the other decrypts.
    let label = b"label\0";
    for scheme in [OAEP_SHA256, RSAES] {
        let (ours, theirs) = both.both(&rsa_encrypt(key, b"secret", scheme, label));
        for ciphertext in [params(ok(&ours), false), params(ok(&theirs), false)] {
            let (c, _) = split2b(&ciphertext);
            let m = both.same(&rsa_decrypt(key, &c, scheme, label));
            assert_eq!(split2b(&params(ok(&m), false)).0, b"secret");
            let mut bad = c.clone();
            bad[100] ^= 4;
            both.same(&rsa_decrypt(key, &bad, scheme, label));
            both.same(&rsa_decrypt(key, &c[1..], scheme, label));
        }
        both.same(&rsa_decrypt(key, &[0; 256], scheme, label));
        both.same(&rsa_encrypt(key, &[1; 250], scheme, label));
    }
    // Raw RSA is deterministic.
    let c = both.same(&rsa_encrypt(key, &[0, 0, 7, 8, 9], NULL, b""));
    let (c, _) = split2b(&params(ok(&c), false));
    ok(&both.same(&rsa_decrypt(key, &c, NULL, b"")));
    both.same(&rsa_encrypt(key, &[0xff; 256], NULL, b""));
    both.same(&rsa_decrypt(key, &[0xff; 256], NULL, b""));
    // Labels end with their zero; schemes must agree with the key's.
    both.same(&rsa_encrypt(key, b"x", OAEP_SHA256, b"label"));
    both.same(&rsa_decrypt(key, &c, OAEP_SHA256, b"label"));
    both.same(&rsa_encrypt(key, b"x", &[0, 0x14, 0, 0x0b], b""));
    // A public key alone verifies and encrypts, but has nothing to sign or decrypt with.
    let public = handle(&both.same(&load_external(
        &external_rsa_public(),
        ALG_RSA,
        None,
        RH_OWNER,
    )));
    ok(&both.same(&verify(public, &digest, &signature)));
    both.same(&rsa_encrypt(public, &[0, 0, 7, 8, 9], NULL, b""));
    both.same(&sign(public, &digest, RSASSA_SHA256));
    both.same(&rsa_decrypt(public, &c, NULL, b""));
}

#[test]
fn ecc_signatures_and_ecdh_cross_check() {
    let mut both = Both::seeded();
    let d = unhex(ECC_D);
    let key = handle(&both.same(&load_external(
        &external_ecc_public(),
        ALG_ECC,
        Some(&d),
        RH_NULL,
    )));
    for digest in [
        client::digest(client::SHA256, &[b"m"]),
        client::digest(client::SHA1, &[b"m"]),
        client::digest(client::SHA512, &[b"m"]),
    ] {
        let alg = match digest.len() {
            20 => client::SHA1,
            32 => client::SHA256,
            _ => client::SHA512,
        };
        let scheme = [&[0, 0x18][..], &alg.to_be_bytes()].concat();
        let (ours, theirs) = both.both(&sign(key, &digest, &scheme));
        for signature in [params(ok(&ours), false), params(ok(&theirs), false)] {
            ok(&both.same(&verify(key, &digest, &signature)));
            let mut bad = signature.clone();
            bad[10] ^= 1;
            both.same(&verify(key, &digest, &bad));
        }
    }
    // [d]P is deterministic; an ephemeral key's Z is checked by the other engine.
    let point = |x: &[u8], y: &[u8]| tpm2b(&[tpm2b(x), tpm2b(y)].concat());
    let zgen = |p: &[u8]| with_password(ECDH_ZGEN, key, b"", p);
    ok(&both.same(&zgen(&point(&unhex(ECC_X), &unhex(ECC_Y)))));
    both.same(&zgen(&point(&unhex(ECC_X), &unhex(ECC_X))));
    both.same(&zgen(&point(&[], &[])));
    let (ours, theirs) = both.both(&command(ECDH_KEYGEN, &[key], None, &[]));
    for response in [ours, theirs] {
        let p = params(ok(&response), false);
        let (z, rest) = split2b(&p);
        let (public, _) = split2b(rest);
        let z_again = params(ok(&both.same(&zgen(&tpm2b(&public)))), false);
        assert_eq!(split2b(&z_again).0, z);
    }
    ok(&both.same(&command(ECC_PARAMETERS, &[], None, &[0, 3])));
    both.same(&command(ECC_PARAMETERS, &[], None, &[0, 0]));
}

#[test]
fn hmac_keys_and_sequences_match() {
    let mut both = Both::seeded();
    let key = handle(&both.same(&create_primary(RH_OWNER, &hmac_key())));
    for scheme in [
        &[0, 0x10][..],
        &[0, 0x0b],
        &[0, 0x04],
        &[0, 0x3f],
        &[0, 0x99],
    ] {
        let p = [tpm2b(b"data"), scheme.to_vec()].concat();
        both.same(&with_password(HMAC, key, b"", &p));
    }
    let digest = client::digest(client::SHA256, &[b"m"]);
    let signature = params(ok(&both.same(&sign(key, &digest, &[0, 0x10]))), false);
    ok(&both.same(&verify(key, &digest, &signature)));
    let start = [tpm2b(b"seq"), vec![0, 0x0b]].concat();
    let seq = handle(&both.same(&with_password(HMAC_START, key, b"", &start)));
    ok(&both.same(&sequence_update(seq, b"seq", b"some ")));
    ok(&both.same(&sequence_complete(seq, b"seq", b"data", RH_OWNER)));
    // Only a keyed hash that signs, and not restricted, starts one.
    let ecc = handle(&both.same(&create_primary(RH_OWNER, &ecdsa_key())));
    both.same(&with_password(HMAC_START, ecc, b"", &start));
    both.same(&command(FLUSH_CONTEXT, &[], None, &ecc.to_be_bytes()));
    let sealed_key = create_params(b"", b"x", &sealed(), b"", &no_pcrs());
    let sealed = handle(&both.same(&with_password(CREATE_PRIMARY, RH_OWNER, b"", &sealed_key)));
    both.same(&with_password(HMAC_START, sealed, b"", &start));
}

/// A CreatePrimary or Create response's outPublic (after `skip` leading TPM2Bs).
pub fn out_public(params: &[u8], skip: usize) -> Vec<u8> {
    let mut rest = params;
    for _ in 0..skip {
        rest = split2b(rest).1;
    }
    split2b(rest).0
}

#[test]
fn rsa_primaries_work_with_libtpms() {
    // vk-tpm's prime search is its own: same template, same seeds, another key. Each engine's
    // key verifies on the other.
    let mut both = Both::seeded();
    let signing = public(
        ALG_RSA,
        SIGNING,
        &rsa(NULL, RSASSA_SHA256, 2048),
        &tpm2b(b""),
    );
    let storage = public(ALG_RSA, STORAGE, &rsa(AES128_CFB, NULL, 2048), &tpm2b(b""));
    let (ours, theirs) = both.both(&create_primary(RH_ENDORSEMENT, &storage));
    assert_eq!(ours.len(), theirs.len());
    assert_eq!(ours[..14], theirs[..14]);
    both.same(&command(
        FLUSH_CONTEXT,
        &[],
        None,
        &0x8000_0000u32.to_be_bytes(),
    ));
    let (ours, theirs) = both.both(&create_primary(RH_OWNER, &signing));
    assert_eq!(ours.len(), theirs.len());
    // The same template and seeds give the same key, every time.
    assert_eq!(
        both.ours.process(&create_primary(RH_OWNER, &signing))[14..],
        ours[14..],
        "deterministic"
    );
    let digest = client::digest(client::SHA256, &[b"m"]);
    let ticket = [&[0x80, 0x24][..], &RH_NULL.to_be_bytes(), &[0, 0]].concat();
    let sign_params = [tpm2b(&digest), NULL.to_vec(), ticket].concat();
    let sign = with_password(SIGN, 0x8000_0000, b"", &sign_params);
    for (signer, verifier) in [(true, false), (false, true)] {
        let public = out_public(&params(if signer { &ours } else { &theirs }, true), 0);
        let signature = if signer {
            params(ok(&both.ours.process(&sign)), false)
        } else {
            params(ok(&both.theirs.process(&sign)), false)
        };
        let load = load_external(&public, ALG_RSA, None, RH_OWNER);
        let (verify_with, response) = if verifier {
            let h = handle(&both.ours.process(&load));
            (h, both.ours.process(&verify(h, &digest, &signature)))
        } else {
            let h = handle(&both.theirs.process(&load));
            (h, both.theirs.process(&verify(h, &digest, &signature)))
        };
        ok(&response);
        assert_ne!(verify_with, 0);
    }
}

#[test]
fn objects_created_by_one_load_in_the_other() {
    let mut both = Both::seeded();
    // The same ECC storage key on both: its seed protects the children.
    let srk = handle(&both.same(&create_primary(RH_OWNER, &ecc_srk())));
    let child_storage = ecc_srk();
    let templates: [(Vec<u8>, &[u8]); 5] = [
        (sealed(), b"sealed secret"),
        (hmac_key(), b""),
        (ecdsa_key(), b""),
        (child_storage, b""),
        (
            public(
                ALG_RSA,
                SIGNING,
                &rsa(NULL, RSASSA_SHA256, 1024),
                &tpm2b(b""),
            ),
            b"",
        ),
    ];
    for (template, data) in templates {
        for creator in [true, false] {
            let p = create_params(b"child", data, &template, b"info", &no_pcrs());
            let create = with_password(CREATE, srk, b"", &p);
            let (ours, theirs) = both.both(&create);
            assert_eq!(ours.len(), theirs.len(), "the same shape");
            let response = if creator { ours } else { theirs };
            let created = params(ok(&response), false);
            let (private, rest) = split2b(&created);
            let (public, _) = split2b(rest);
            let load = with_password(LOAD, srk, b"", &[tpm2b(&private), tpm2b(&public)].concat());
            let child = handle(&both.same(&load));
            both.same(&command(READ_PUBLIC, &[child], None, &[]));
            both.same(&command(UNSEAL, &[child], Some(&password(b"child")), &[]));
            // Not noDA: the failure counts.
            both.same(&command(UNSEAL, &[child], Some(&password(b"wrong")), &[]));
            read_hierarchy_state(&mut both);
            ok(&both.same(&with_password(DA_LOCK_RESET, RH_LOCKOUT, b"", &[])));
            // A new authValue: the object wrapped again, loadable on both.
            let change = command(
                OBJECT_CHANGE_AUTH,
                &[child, srk],
                Some(&password(b"child")),
                &tpm2b(b"new"),
            );
            let (ours, theirs) = both.both(&change);
            assert_eq!(ours.len(), theirs.len());
            let rewrapped = split2b(&params(ok(&ours), false)).0;
            both.same(&command(FLUSH_CONTEXT, &[], None, &child.to_be_bytes()));
            let load = with_password(
                LOAD,
                srk,
                b"",
                &[tpm2b(&rewrapped), tpm2b(&public)].concat(),
            );
            let child = handle(&both.same(&load));
            both.same(&command(UNSEAL, &[child], Some(&password(b"new")), &[]));
            both.same(&command(FLUSH_CONTEXT, &[], None, &child.to_be_bytes()));
            // Tampered, or under another name: refused alike.
            let mut tampered = private.clone();
            let last = tampered.len() - 1;
            tampered[last] ^= 1;
            both.same(&with_password(
                LOAD,
                srk,
                b"",
                &[tpm2b(&tampered), tpm2b(&public)].concat(),
            ));
            let mut other = public.clone();
            other[5] ^= 0x40;
            both.same(&with_password(
                LOAD,
                srk,
                b"",
                &[tpm2b(&private), tpm2b(&other)].concat(),
            ));
        }
    }
    // Every slot taken: Create answers TPM_RC_OBJECT_MEMORY too.
    let hmac = handle(&both.same(&create_primary(RH_OWNER, &hmac_key())));
    handle(&both.same(&create_primary(RH_OWNER, &hmac_key())));
    let p = create_params(b"", b"x", &sealed(), b"", &no_pcrs());
    both.same(&with_password(CREATE, srk, b"", &p));
    both.same(&command(FLUSH_CONTEXT, &[], None, &hmac.to_be_bytes()));
    // Not a parent.
    let p = create_params(b"", b"x", &sealed(), b"", &no_pcrs());
    let ecdsa = handle(&both.same(&create_primary(RH_OWNER, &ecdsa_key())));
    both.same(&with_password(CREATE, ecdsa, b"", &p));
}

/// A TPMS_CONTEXT's header: sequence, savedHandle, hierarchy (the blob is each engine's own).
fn context_header(response: &[u8]) -> Vec<u8> {
    params(ok(response), false)[..16].to_vec()
}

/// ContextSave on both: the headers match; each engine's own context.
fn save(both: &mut Both, handle: u32) -> (Vec<u8>, Vec<u8>) {
    let (ours, theirs) = both.both(&command(CONTEXT_SAVE, &[handle], None, &[]));
    assert_eq!(
        context_header(&ours),
        context_header(&theirs),
        "context of {handle:#x}"
    );
    (params(&ours, false), params(&theirs, false))
}

/// ContextLoad of each engine's own context: the same answer.
fn load_context(both: &mut Both, (ours, theirs): &(Vec<u8>, Vec<u8>)) -> Vec<u8> {
    let o = both.ours.process(&command(CONTEXT_LOAD, &[], None, ours));
    let t = both
        .theirs
        .process(&command(CONTEXT_LOAD, &[], None, theirs));
    assert_eq!(hex(&o), hex(&t), "context load");
    o
}

#[test]
fn contexts_match() {
    let mut both = Both::seeded();
    let srk = handle(&both.same(&create_primary(RH_OWNER, &ecc_srk())));
    let mut st_clear = ecdsa_key();
    st_clear[7] |= ST_CLEAR as u8;
    let volatile = handle(&both.same(&create_primary(RH_ENDORSEMENT, &st_clear)));
    let seq = handle(&both.same(&sequence_start(b"", 0x0b)));
    let saved_srk = save(&mut both, srk);
    let saved_volatile = save(&mut both, volatile);
    let saved_seq = save(&mut both, seq);
    for h in [srk, volatile, seq] {
        both.same(&command(FLUSH_CONTEXT, &[], None, &h.to_be_bytes()));
    }
    // Back into the first free slots, and again (an object context loads any number of times).
    for saved in [&saved_volatile, &saved_srk, &saved_seq] {
        ok(&load_context(&mut both, saved));
    }
    load_context(&mut both, &saved_srk);
    both.same(&get_capability(1, 0x8000_0000, 8));
    for h in [0x8000_0000u32, 0x8000_0001, 0x8000_0002] {
        both.same(&command(FLUSH_CONTEXT, &[], None, &h.to_be_bytes()));
    }
    // Damaged contexts.
    let mut bad = saved_srk.clone();
    for c in [&mut bad.0, &mut bad.1] {
        let last = c.len() - 1;
        c[last] ^= 1;
    }
    load_context(&mut both, &bad);
    let mut wrong_handle = saved_srk.clone();
    for c in [&mut wrong_handle.0, &mut wrong_handle.1] {
        c[11] = 2;
    }
    load_context(&mut both, &wrong_handle);
    for c in [&mut wrong_handle.0, &mut wrong_handle.1] {
        c[11] = 9;
    }
    load_context(&mut both, &wrong_handle);

    // Sessions: saved, they keep their handle; only the last context loads, once.
    let mut s = Sessions::default();
    let unbound = (RH_NULL, None);
    for n in 0..3u8 {
        assert_eq!(
            both.start_session(
                &mut s,
                SE_HMAC,
                client::SHA256,
                Sym::Null,
                unbound,
                &[n; 16]
            ),
            0
        );
    }
    let first = save(&mut both, HMAC_SESSION);
    both.same(&get_capability(1, 0x0200_0000, 8));
    both.same(&get_capability(1, 0x0300_0000, 8));
    both.same(&get_capability(6, 0x203, 4));
    // A saved session cannot be used, nor saved again.
    both.same(&command(CONTEXT_SAVE, &[HMAC_SESSION], None, &[]));
    assert_eq!(handle(&load_context(&mut both, &first)), HMAC_SESSION);
    load_context(&mut both, &first);
    let second = save(&mut both, HMAC_SESSION);
    load_context(&mut both, &first);
    // A saved session is flushed as it is.
    both.same(&command(
        FLUSH_CONTEXT,
        &[],
        None,
        &HMAC_SESSION.to_be_bytes(),
    ));
    load_context(&mut both, &second);
    let third = save(&mut both, HMAC_SESSION + 1);
    // Every slot loaded: no room to load one.
    assert_eq!(
        both.start_session(
            &mut s,
            SE_POLICY,
            client::SHA1,
            Sym::Null,
            unbound,
            &[7; 16]
        ),
        0
    );
    both.start_session(&mut s, SE_HMAC, client::SHA1, Sym::Null, unbound, &[8; 16]);
    load_context(&mut both, &third);
    // A restart keeps saved sessions and the contexts of what is not stClear; a reset does not.
    both.same(&command(SHUTDOWN, &[], None, &[0, 1]));
    both.power_cycle();
    both.same(&command(STARTUP, &[], None, &[0, 0]));
    both.same(&get_capability(1, 0x0300_0000, 8));
    ok(&load_context(&mut both, &third));
    ok(&load_context(&mut both, &saved_srk));
    load_context(&mut both, &saved_volatile);
    let fourth = save(&mut both, HMAC_SESSION + 1);
    both.same(&command(SHUTDOWN, &[], None, &[0, 0]));
    both.power_cycle();
    both.same(&command(STARTUP, &[], None, &[0, 0]));
    both.same(&get_capability(1, 0x0300_0000, 8));
    load_context(&mut both, &fourth);
    load_context(&mut both, &saved_srk);
}

#[test]
fn persistent_objects_match() {
    let mut both = Both::seeded();
    let srk = handle(&both.same(&create_primary(RH_OWNER, &ecc_srk())));
    let evict = |object: u32, persistent: u32, auth: u32| {
        command(
            EVICT_CONTROL,
            &[auth, object],
            Some(&password(b"")),
            &persistent.to_be_bytes(),
        )
    };
    ok(&both.same(&evict(srk, 0x8100_0001, RH_OWNER)));
    both.same(&evict(srk, 0x8100_0001, RH_OWNER));
    both.same(&evict(srk, 0x8180_0001, RH_OWNER));
    both.same(&evict(srk, 0x8100_0002, RH_PLATFORM));
    both.same(&evict(srk, 0x8000_0002, RH_OWNER));
    both.same(&get_capability(1, 0x8100_0000, 8));
    both.same(&get_capability(6, 0x208, 1));
    both.same(&command(FLUSH_CONTEXT, &[], None, &srk.to_be_bytes()));
    both.same(&command(READ_PUBLIC, &[0x8100_0001], None, &[]));
    both.same(&command(READ_PUBLIC, &[0x8100_0003], None, &[]));
    // A persistent parent takes a slot for the command: the child goes in the next one.
    let p = create_params(b"", b"x", &sealed(), b"", &no_pcrs());
    let created = params(
        ok(&both.both(&with_password(CREATE, 0x8100_0001, b"", &p)).0),
        false,
    );
    let (private, rest) = split2b(&created);
    let load = [tpm2b(&private), tpm2b(&split2b(rest).0)].concat();
    assert_eq!(
        handle(&both.same(&with_password(LOAD, 0x8100_0001, b"", &load))),
        0x8000_0001
    );
    handle(&both.same(&create_primary(RH_OWNER, &hmac_key())));
    handle(&both.same(&create_primary(RH_OWNER, &hmac_key())));
    both.same(&command(READ_PUBLIC, &[0x8100_0001], None, &[]));
    both.same(&command(
        FLUSH_CONTEXT,
        &[],
        None,
        &0x8000_0000u32.to_be_bytes(),
    ));
    // A persistent key in a session, as tpmKey and bind.
    let mut s = Sessions::default();
    let bind = (0x8100_0001, Some(&b""[..]));
    both.start_session(&mut s, SE_HMAC, client::SHA256, Sym::Null, bind, &[3; 16]);
    // Removed from where it is, by the owner or the platform.
    both.same(&evict(0x8100_0001, 0x8100_0002, RH_OWNER));
    ok(&both.same(&evict(0x8100_0001, 0x8100_0001, RH_PLATFORM)));
    both.same(&evict(0x8100_0001, 0x8100_0001, RH_OWNER));
    both.same(&get_capability(1, 0x8100_0000, 8));
    for h in [0x8000_0001u32, 0x8000_0002] {
        both.same(&command(FLUSH_CONTEXT, &[], None, &h.to_be_bytes()));
    }
    // A platform key under the platform's handles; TPM2_Clear leaves it.
    let pk = handle(&both.same(&create_primary(RH_PLATFORM, &ecc_srk())));
    ok(&both.same(&evict(pk, 0x8180_0000, RH_PLATFORM)));
    let ok_owner = handle(&both.same(&create_primary(RH_OWNER, &ecdsa_key())));
    ok(&both.same(&evict(ok_owner, 0x8100_0000, RH_OWNER)));
    both.same(&get_capability(1, 0x8100_0000, 8));
    // TPM2_Clear deletes the owner's and the endorsement's persistent objects (Part 3); libtpms
    // keeps them (a deviation).
    both.same(&with_password(CLEAR, RH_LOCKOUT, b"", &[]));
    let listed = both.ours.process(&get_capability(1, 0x8100_0000, 8));
    assert_eq!(hex(&listed[15..]), "0000000181800000");
    both.same(&get_capability(1, 0x8000_0000, 8));
    // Disabling the platform hierarchy hides its persistent objects and flushes its keys.
    both.same(&hierarchy_control(RH_PLATFORM, RH_PLATFORM, 0));
    both.same(&command(READ_PUBLIC, &[0x8180_0000], None, &[]));
}

#[test]
fn salted_sessions_match() {
    let mut both = Both::seeded();
    let p = unhex(RSA_P);
    let rsa_key = handle(&both.same(&load_external(
        &external_rsa_public(),
        ALG_RSA,
        Some(&p),
        RH_NULL,
    )));
    let d = unhex(ECC_D);
    let ecc_key = handle(&both.same(&load_external(
        &external_ecc_public(),
        ALG_ECC,
        Some(&d),
        RH_NULL,
    )));
    let mut s = Sessions::default();
    // RSA: the salt OAEP-encrypted (SHA-256, the key's nameAlg) with the label "SECRET".
    let salt = [9u8; 32];
    let encrypted = both
        .theirs
        .process(&rsa_encrypt(rsa_key, &salt, OAEP_SHA256, b"SECRET\0"));
    let (encrypted, _) = split2b(&params(ok(&encrypted), false));
    assert_eq!(
        both.start_salted_session(&mut s, rsa_key, &encrypted, &salt, &[1; 16]),
        0
    );
    // ECC: an ephemeral key's point; the salt is KDFe of the shared x-coordinate.
    let keygen = params(
        ok(&both
            .theirs
            .process(&command(ECDH_KEYGEN, &[ecc_key], None, &[]))),
        false,
    );
    let (z, rest) = split2b(&keygen);
    let (ephemeral, _) = split2b(rest);
    let zx = split2b(&z).0;
    let ex = split2b(&ephemeral).0;
    let ecc_salt = client::kdfe(client::SHA256, &zx, b"SECRET\0", &ex, &unhex(ECC_X), 32);
    assert_eq!(
        both.start_salted_session(&mut s, ecc_key, &ephemeral, &ecc_salt, &[2; 20]),
        0
    );
    // Both sessions authorize, and encrypt parameters with salt-derived keys.
    both.same(&change_auth(RH_OWNER, b"", b"owner"));
    for index in [0, 1] {
        let auth = Auth::Session {
            index,
            attributes: client::CONTINUE | client::DECRYPT,
            entity: Some(b"owner".to_vec()),
            bound: false,
            after: None,
            hmac: None,
        };
        let r = both.run(&mut s, &change_auth_command(RH_OWNER, b"owner", vec![auth]));
        assert_eq!(r.rc, 0);
    }
    // Wrong salts, wrong keys.
    let mut bad = encrypted.clone();
    bad[7] ^= 1;
    both.start_salted_session(&mut s, rsa_key, &bad, &salt, &[3; 16]);
    both.start_salted_session(&mut s, rsa_key, &[], &salt, &[3; 16]);
    both.start_salted_session(&mut s, ecc_key, &[0, 1, 0, 0, 1, 0], &salt, &[3; 16]);
    let public_only = handle(&both.same(&load_external(
        &external_rsa_public(),
        ALG_RSA,
        None,
        RH_NULL,
    )));
    both.start_salted_session(&mut s, public_only, &encrypted, &salt, &[3; 16]);
    both.same(&command(
        FLUSH_CONTEXT,
        &[],
        None,
        &public_only.to_be_bytes(),
    ));
    let p = create_params(b"", b"", &hmac_key(), b"", &no_pcrs());
    let hmac = handle(&both.same(&with_password(CREATE_PRIMARY, RH_OWNER, b"owner", &p)));
    both.start_salted_session(&mut s, hmac, &encrypted, &salt, &[3; 16]);
}

#[test]
fn object_authorization_matches() {
    let mut both = Both::seeded();
    let srk = handle(&both.same(&create_primary(RH_OWNER, &ecc_srk())));
    // A key whose authValue does not serve the USER role (userWithAuth clear), one that takes
    // a policy for the ADMIN role, and one subject to dictionary-attack protection. HMAC keys:
    // their signatures compare.
    let mut policy_only = hmac_key();
    policy_only[7] &= !(USER_WITH_AUTH as u8);
    let mut admin_policy = hmac_key();
    admin_policy[7] |= ADMIN_WITH_POLICY as u8;
    let digest = client::digest(client::SHA256, &[b"m"]);
    let ticket = [&[0x80, 0x24][..], &RH_NULL.to_be_bytes(), &[0, 0]].concat();
    let sign_params = [tpm2b(&digest), NULL.to_vec(), ticket].concat();
    for template in [policy_only, admin_policy, hmac_key()] {
        let p = create_params(b"pw", b"", &template, b"", &no_pcrs());
        let created = params(
            ok(&both.both(&with_password(CREATE, srk, b"", &p)).0),
            false,
        );
        let (private, rest) = split2b(&created);
        let load = [tpm2b(&private), tpm2b(&split2b(rest).0)].concat();
        let key = handle(&both.same(&with_password(LOAD, srk, b"", &load)));
        let sign = |pw: &[u8]| command(SIGN, &[key], Some(&password(pw)), &sign_params);
        both.same(&sign(b"pw"));
        both.same(&sign(b"no"));
        read_hierarchy_state(&mut both);
        // ObjectChangeAuth wraps with a random IV: only its response code compares.
        let change = |pw: &[u8]| {
            command(
                OBJECT_CHANGE_AUTH,
                &[key, srk],
                Some(&password(pw)),
                &tpm2b(b"x"),
            )
        };
        let (ours, theirs) = both.both(&change(b"pw"));
        assert_eq!(rc(&ours), rc(&theirs));
        // HMAC sessions, bound to the key or not, and a policy session.
        let mut s = Sessions::default();
        let unbound = (RH_NULL, None);
        both.start_session(
            &mut s,
            SE_HMAC,
            client::SHA256,
            Sym::Null,
            unbound,
            &[1; 16],
        );
        both.start_session(
            &mut s,
            SE_HMAC,
            client::SHA256,
            Sym::Null,
            (key, Some(b"pw")),
            &[2; 16],
        );
        both.start_session(
            &mut s,
            SE_POLICY,
            client::SHA256,
            Sym::Null,
            unbound,
            &[3; 16],
        );
        for (index, bound) in [(0, false), (1, true), (2, false)] {
            let auth = Auth::Session {
                index,
                attributes: client::CONTINUE,
                entity: Some(b"pw".to_vec()),
                bound,
                after: None,
                hmac: None,
            };
            let mut cmd = client::Command::new(SIGN, &[key], &sign_params, vec![auth]);
            cmd.names[0] = name(&mut both, key);
            both.run(&mut s, &cmd);
        }
        for h in [key, HMAC_SESSION, HMAC_SESSION + 1, 0x0300_0002] {
            both.same(&command(FLUSH_CONTEXT, &[], None, &h.to_be_bytes()));
        }
        ok(&both.same(&with_password(DA_LOCK_RESET, RH_LOCKOUT, b"", &[])));
    }
}

/// An object's Name, from TPM2_ReadPublic.
fn name(both: &mut Both, handle: u32) -> Vec<u8> {
    let r = both.same(&command(READ_PUBLIC, &[handle], None, &[]));
    let p = params(ok(&r), false);
    split2b(split2b(&p).1).0
}

#[test]
fn templates_are_checked_alike() {
    let mut both = Both::seeded();
    let srk = handle(&both.same(&create_primary(RH_OWNER, &ecc_srk())));
    let with = |template: &[u8], attributes: u32| {
        let mut t = template.to_vec();
        t[4..8].copy_from_slice(&attributes.to_be_bytes());
        t
    };
    let ecc_signing = ecdsa_key();
    let storage = ecc_srk();
    let rsa_storage = public(ALG_RSA, STORAGE, &rsa(AES128_CFB, NULL, 2048), &tpm2b(b""));
    let mut templates = vec![
        with(&storage, STORAGE & !FIXED_PARENT),
        with(&storage, STORAGE | SIGN_ATTR),
        with(&storage, STORAGE & !DECRYPT),
        with(&storage, STORAGE | 1),
        with(&storage, STORAGE | 1 << 8),
        with(&storage, STORAGE | 1 << 11),
        with(&storage, STORAGE & !ORIGIN),
        with(&ecc_signing, SIGNING | RESTRICTED),
        with(&ecc_signing, SIGNING | DECRYPT),
        with(&ecc_signing, SIGNING & !SIGN_ATTR),
        with(&hmac_key(), SIGNING | DECRYPT),
        with(&hmac_key(), SIGNING | RESTRICTED),
        with(&sealed(), FIXED_TPM | FIXED_PARENT | ORIGIN),
        public(ALG_ECC, STORAGE, &ecc(NULL, NULL), ECC_UNIQUE),
        public(ALG_ECC, SIGNING, &ecc(AES128_CFB, ECDSA_SHA256), ECC_UNIQUE),
        public(
            ALG_ECC,
            SIGNING,
            &[NULL, &[0, 0x18, 0, 0x0b], &[0, 3], &[0, 0x20, 0, 0x0b]].concat(),
            ECC_UNIQUE,
        ),
        public(
            ALG_ECC,
            SIGNING,
            &ecc(NULL, &[0, 0x19, 0, 0x0b]),
            ECC_UNIQUE,
        ),
        public(ALG_ECC, SIGNING, &ecc(NULL, NULL), ECC_UNIQUE),
        public(
            ALG_ECC,
            SIGNING,
            &[NULL, NULL, &[0, 0][..], NULL].concat(),
            ECC_UNIQUE,
        ),
        public(
            ALG_RSA,
            STORAGE,
            &rsa(AES128_CFB, &[0, 0x17, 0, 0x0b], 2048),
            &tpm2b(b""),
        ),
        public(ALG_RSA, STORAGE, &rsa(AES128_CFB, NULL, 4096), &tpm2b(b"")),
        public(ALG_RSA, STORAGE, &rsa(AES128_CFB, NULL, 1000), &tpm2b(b"")),
        public(
            ALG_RSA,
            SIGNING,
            &[NULL, &[0, 0x14, 0, 0x10], &[8, 0, 0, 0, 0, 0]].concat(),
            &tpm2b(b""),
        ),
        public(
            ALG_RSA,
            SIGNING,
            &[NULL, &[0, 0x14, 0, 0x0b], &[8, 0, 0, 0, 0, 3]].concat(),
            &tpm2b(b""),
        ),
        public(
            ALG_SYMCIPHER,
            STORAGE,
            &[0, 6, 0, 0x80, 0, 0x3f],
            &tpm2b(b""),
        ),
        public(
            ALG_SYMCIPHER,
            STORAGE,
            &[0, 6, 0, 0x81, 0, 0x43],
            &tpm2b(b""),
        ),
        public(ALG_SYMCIPHER, STORAGE, &[0, 0x10], &tpm2b(b"")),
        public(ALG_SYMCIPHER, SIGNING, AES128_CFB, &tpm2b(b"")),
        public(
            ALG_KEYEDHASH,
            STORAGE,
            &[0, 0x0a, 0, 0x0b, 0, 0x21],
            &tpm2b(b""),
        ),
        public(
            ALG_KEYEDHASH,
            STORAGE,
            &[0, 0x0a, 0, 0x0b, 0, 0x22],
            &tpm2b(b""),
        ),
        public(
            ALG_KEYEDHASH,
            SIGNING,
            &[0, 0x0a, 0, 0x0b, 0, 0x22],
            &tpm2b(b""),
        ),
        public(0x99, SIGNING, NULL, &tpm2b(b"")),
    ];
    let mut no_name = rsa_storage.clone();
    no_name[2..4].copy_from_slice(&[0, 0x10]);
    templates.push(no_name);
    let mut policy = rsa_storage.clone();
    policy[8..10].copy_from_slice(&[0, 1]);
    policy.insert(10, 7);
    templates.push(policy);
    for template in &templates {
        for (auth, data) in [(&b""[..], &b""[..]), (b"x", b"data"), (&[1; 33], b"")] {
            let p = create_params(auth, data, template, b"", &no_pcrs());
            let primary = both.same(&with_password(CREATE_PRIMARY, RH_OWNER, b"", &p));
            if rc(&primary) == 0 {
                both.same(&command(
                    FLUSH_CONTEXT,
                    &[],
                    None,
                    &handle(&primary).to_be_bytes(),
                ));
            }
            let (ours, theirs) = both.both(&with_password(CREATE, srk, b"", &p));
            assert_eq!(rc(&ours), rc(&theirs), "Create of {}", hex(template));
        }
    }
    // The TPM2B around the public area, and the one around the sensitive area.
    let p = [
        sensitive(b"", b""),
        vec![0, 3],
        storage.clone(),
        tpm2b(b""),
        no_pcrs(),
    ]
    .concat();
    both.same(&with_password(CREATE_PRIMARY, RH_OWNER, b"", &p));
    let p = [
        vec![0, 9, 0, 0, 0, 0],
        tpm2b(&storage),
        tpm2b(b""),
        no_pcrs(),
    ]
    .concat();
    both.same(&with_password(CREATE_PRIMARY, RH_OWNER, b"", &p));
    let p = [vec![0, 0], tpm2b(&storage), tpm2b(b""), no_pcrs()].concat();
    both.same(&with_password(CREATE_PRIMARY, RH_OWNER, b"", &p));
    let p = create_params(b"", b"", &storage, &[0; 67], &no_pcrs());
    both.same(&with_password(CREATE_PRIMARY, RH_OWNER, b"", &p));
    // RSA keys: the exponent is checked when the key is generated.
    for exponent in [3u32, 65535, 65539, 0x1_0002] {
        let params = [AES128_CFB, NULL, &[8, 0], &exponent.to_be_bytes()].concat();
        let p = create_params(
            b"",
            b"",
            &public(ALG_RSA, STORAGE, &params, &tpm2b(b"")),
            b"",
            &no_pcrs(),
        );
        let (ours, theirs) = both.both(&with_password(CREATE_PRIMARY, RH_OWNER, b"", &p));
        assert_eq!(rc(&ours), rc(&theirs), "exponent {exponent}");
        if rc(&ours) == 0 {
            both.same(&command(
                FLUSH_CONTEXT,
                &[],
                None,
                &handle(&ours).to_be_bytes(),
            ));
        }
    }
}

#[test]
fn load_external_is_checked_alike() {
    let mut both = Both::seeded();
    let rsa_public = external_rsa_public();
    let ecc_public = external_ecc_public();
    let (p, d) = (unhex(RSA_P), unhex(ECC_D));
    let restricted = public(
        ALG_ECC,
        SIGN_DECRYPT | RESTRICTED,
        &ecc(NULL, NULL),
        &ecc_public[18..],
    );
    let off_curve = public(
        ALG_ECC,
        SIGN_DECRYPT,
        &ecc(NULL, NULL),
        &[tpm2b(&[1; 32]), tpm2b(&[2; 32])].concat(),
    );
    let mut no_name = off_curve.clone();
    no_name[2..4].copy_from_slice(&[0, 0x10]);
    let short = public(
        ALG_RSA,
        SIGN_DECRYPT,
        &rsa(NULL, NULL, 2048),
        &tpm2b(&[0x80; 200]),
    );
    // (public area, sensitive type, secret, hierarchy)
    type Case = (Vec<u8>, u16, Option<Vec<u8>>, u32);
    let cases: Vec<Case> = vec![
        (rsa_public.clone(), ALG_RSA, Some(p.clone()), RH_OWNER),
        (rsa_public.clone(), ALG_RSA, Some(p[1..].to_vec()), RH_NULL),
        (rsa_public.clone(), ALG_RSA, Some(vec![0xc1; 128]), RH_NULL),
        (rsa_public.clone(), ALG_RSA, None, RH_ENDORSEMENT),
        (rsa_public.clone(), ALG_ECC, Some(d.clone()), RH_NULL),
        (ecc_public.clone(), ALG_ECC, Some(vec![1; 32]), RH_NULL),
        (ecc_public.clone(), ALG_ECC, Some(vec![0; 32]), RH_NULL),
        (ecc_public.clone(), ALG_ECC, Some(vec![0xff; 32]), RH_NULL),
        (ecc_public.clone(), ALG_ECC, None, RH_PLATFORM),
        (restricted, ALG_ECC, Some(d.clone()), RH_NULL),
        (off_curve.clone(), ALG_ECC, None, RH_NULL),
        (no_name, ALG_ECC, None, RH_NULL),
        (short, ALG_RSA, None, RH_NULL),
        (hmac_key(), ALG_KEYEDHASH, None, RH_NULL),
        (hmac_key(), ALG_KEYEDHASH, Some(b"key".to_vec()), RH_NULL),
    ];
    for (public, kind, secret, hierarchy) in cases {
        let r = both.same(&load_external(&public, kind, secret.as_deref(), hierarchy));
        if rc(&r) == 0 {
            both.same(&command(READ_PUBLIC, &[handle(&r)], None, &[]));
            both.same(&command(
                FLUSH_CONTEXT,
                &[],
                None,
                &handle(&r).to_be_bytes(),
            ));
        }
    }
}

#[test]
fn testing_random_and_clock_commands_match() {
    let mut both = Both::seeded();
    for parms in [
        &[0, 1, 0, 0x10, 0, 0x10, 8, 0, 0, 0, 0, 0][..],
        &[0, 1, 0, 0x10, 0, 0x10, 0x10, 0, 0, 0, 0, 0],
        &[0, 0x23, 0, 0x10, 0, 0x18, 0, 0x0b, 0, 3, 0, 0x10],
        &[0, 0x23, 0, 0x10, 0, 0x1a, 0, 0x0b, 0, 1, 0, 3, 0, 0x10],
        &[0, 0x23, 0, 0x10, 0, 0x10, 0, 3, 0, 0x21, 0, 0x0b],
        &[0, 0x25, 0, 6, 0, 0xc0, 0, 0x42],
        &[0, 0x25, 0, 6, 0, 0xc1, 0, 0x42],
        &[0, 0x25, 0, 0x10],
        &[0, 8, 0, 5, 0, 0x0b],
        &[0, 8, 0, 0x0a, 0, 0x0b, 0, 0x99],
        &[0, 0x99],
        &[0, 1],
    ] {
        both.same(&command(TEST_PARMS, &[], None, parms));
    }
    both.same(&command(GET_TEST_RESULT, &[], None, &[]));
    both.same(&command(STIR_RANDOM, &[], None, &tpm2b(&[7; 128])));
    both.same(&command(STIR_RANDOM, &[], None, &tpm2b(&[7; 129])));
    // The clock: the same shape, and the same counters.
    let (ours, theirs) = both.both(&command(READ_CLOCK, &[], None, &[]));
    assert_eq!(ours.len(), theirs.len());
    assert_eq!(ours[..10], theirs[..10]);
    assert_eq!(ours[26..], theirs[26..], "resetCount, restartCount, safe");
    both.same(&command(SHUTDOWN, &[], None, &[0, 1]));
    both.power_cycle();
    both.same(&command(STARTUP, &[], None, &[0, 0]));
    let (ours, theirs) = both.both(&command(READ_CLOCK, &[], None, &[]));
    assert_eq!(ours[26..], theirs[26..], "a restart");
    both.power_cycle();
    both.same(&command(STARTUP, &[], None, &[0, 0]));
    let (ours, theirs) = both.both(&command(READ_CLOCK, &[], None, &[]));
    assert_eq!(ours[26..], theirs[26..], "a reset, not orderly");
}
