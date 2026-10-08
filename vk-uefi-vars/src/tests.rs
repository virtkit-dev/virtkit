//! The service on a synthetic store: variable semantics, persistence, the MM encoding, and
//! Secure Boot's authenticated writes with keys and signatures made here.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use crypto_bigint::BoxedUint;
use getrandom::rand_core::UnwrapErr;
use rsa::traits::{PublicKeyParts, SignatureScheme};
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use sha2::{Digest, Sha256};

use super::*;

const NV_BS_RT: u32 = NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS;
const AUTH: u32 = NV_BS_RT | TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
const VENDOR: Guid = Guid::new(0x11111111, 0x2222, 0x3333, [4, 4, 5, 5, 6, 6, 7, 7]);

/// An empty 528 KiB store image: firmware volume header, authenticated store header, erased.
fn image() -> Vec<u8> {
    let total: usize = 0x84000;
    let mut b = vec![0xffu8; total];
    b[..16].fill(0);
    b[16..32].copy_from_slice(&guid::SYSTEM_NV_DATA_FV.0);
    b[32..40].copy_from_slice(&(total as u64).to_le_bytes());
    b[40..44].copy_from_slice(&0x4856_465fu32.to_le_bytes());
    b[44..48].copy_from_slice(&0u32.to_le_bytes());
    b[48..50].copy_from_slice(&0x48u16.to_le_bytes());
    let st = 0x48;
    b[st..st + 16].copy_from_slice(&guid::AUTHENTICATED_VARIABLE.0);
    b[st + 16..st + 20].copy_from_slice(&(0x40000u32 - 0x48).to_le_bytes());
    b[st + 20] = 0x5a;
    b[st + 21] = 0xfe;
    b[st + 22..st + 28].fill(0);
    b
}

fn name(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn get(svc: &Service, guid: &Guid, n: &str) -> Option<(u32, Vec<u8>)> {
    let (status, attrs, data) = svc.get_variable(guid, &name(n), 1 << 20);
    (status == Status::SUCCESS).then(|| (attrs.unwrap(), data.unwrap()))
}

#[test]
fn set_get_append_and_delete() {
    let mut svc = Service::new(image()).unwrap();
    assert_eq!(
        svc.set_variable(&VENDOR, &name("Boot0001"), NV_BS_RT, b"abc"),
        Status::SUCCESS
    );
    assert_eq!(
        get(&svc, &VENDOR, "Boot0001"),
        Some((NV_BS_RT, b"abc".to_vec()))
    );
    assert_eq!(
        svc.set_variable(&VENDOR, &name("Boot0001"), NV_BS_RT | APPEND_WRITE, b"de"),
        Status::SUCCESS
    );
    assert_eq!(get(&svc, &VENDOR, "Boot0001").unwrap().1, b"abcde");
    // Other attributes on an existing variable are refused; attributes 0 deletes.
    assert_eq!(
        svc.set_variable(&VENDOR, &name("Boot0001"), BOOTSERVICE_ACCESS, b"x"),
        Status::INVALID_PARAMETER
    );
    assert_eq!(
        svc.set_variable(&VENDOR, &name("Boot0001"), 0, b""),
        Status::SUCCESS
    );
    assert_eq!(get(&svc, &VENDOR, "Boot0001"), None);
    assert_eq!(
        svc.set_variable(&VENDOR, &name("Boot0001"), 0, b""),
        Status::NOT_FOUND
    );
    // Runtime without boot services, and non-volatile alone, are invalid.
    assert_eq!(
        svc.set_variable(&VENDOR, &name("X"), RUNTIME_ACCESS, b"x"),
        Status::INVALID_PARAMETER
    );
    assert_eq!(
        svc.set_variable(&VENDOR, &name("X"), NON_VOLATILE, b"x"),
        Status::INVALID_PARAMETER
    );
}

#[test]
fn buffer_too_small_says_the_size_and_attributes() {
    let mut svc = Service::new(image()).unwrap();
    svc.set_variable(&VENDOR, &name("V"), NV_BS_RT, b"hello");
    let (status, attrs, data) = svc.get_variable(&VENDOR, &name("V"), 2);
    assert_eq!(status, Status::BUFFER_TOO_SMALL);
    assert_eq!(attrs, Some(NV_BS_RT));
    assert_eq!(data.unwrap().len(), 5);
}

#[test]
fn after_exit_boot_services_only_runtime_variables_show_and_change() {
    let mut svc = Service::new(image()).unwrap();
    let bs = NON_VOLATILE | BOOTSERVICE_ACCESS;
    svc.set_variable(&VENDOR, &name("BootOnly"), bs, b"1");
    svc.set_variable(
        &VENDOR,
        &name("Volatile"),
        BOOTSERVICE_ACCESS | RUNTIME_ACCESS,
        b"1",
    );
    svc.runtime = true;
    assert_eq!(get(&svc, &VENDOR, "BootOnly"), None);
    assert_eq!(
        svc.set_variable(&VENDOR, &name("BootOnly"), bs, b"2"),
        Status::WRITE_PROTECTED
    );
    assert_eq!(
        svc.set_variable(
            &VENDOR,
            &name("Volatile"),
            BOOTSERVICE_ACCESS | RUNTIME_ACCESS,
            b"2"
        ),
        Status::WRITE_PROTECTED
    );
    assert_eq!(
        svc.set_variable(&VENDOR, &name("New"), bs, b"2"),
        Status::INVALID_PARAMETER
    );
    assert_eq!(
        svc.set_variable(&VENDOR, &name("New"), NV_BS_RT, b"2"),
        Status::SUCCESS
    );
    let mut seen = Vec::new();
    let mut cur = (Guid::default(), Vec::new());
    while let Ok(v) = svc.next_variable(&cur.0, &cur.1) {
        seen.push(String::from_utf16_lossy(&v.name));
        cur = (v.guid, v.name.clone());
    }
    assert!(seen.contains(&"New".to_string()) && !seen.contains(&"BootOnly".to_string()));
}

#[test]
fn non_volatile_variables_persist_in_the_store_image() {
    let mut svc = Service::new(image()).unwrap();
    svc.set_variable(&VENDOR, &name("Keep"), NV_BS_RT, b"kept");
    svc.set_variable(&VENDOR, &name("Lose"), BOOTSERVICE_ACCESS, b"lost");
    let bytes = svc.take_image().unwrap().unwrap().to_vec();
    // Not yet in the file (its write failed, say): offered again.
    assert_eq!(svc.take_image().unwrap().unwrap(), bytes.as_slice());
    svc.mark_written();
    assert!(svc.take_image().unwrap().is_none(), "nothing changed since");
    let again = Service::new(bytes).unwrap();
    assert_eq!(get(&again, &VENDOR, "Keep").unwrap().1, b"kept");
    assert_eq!(get(&again, &VENDOR, "Lose"), None);
}

#[test]
fn the_mm_encoding_sets_and_gets() {
    let mut svc = Service::new(image()).unwrap();
    let n = codec::ucs2_bytes(&name("Mm"));
    let msg = |function: u64, attrs: u32, data: &[u8], data_size: usize| {
        let mut m = Vec::new();
        m.extend_from_slice(&guid::SMM_VARIABLE_PROTOCOL.0);
        let body = VAR_HEADER + ACCESS_NAME + n.len() + data_size;
        m.extend_from_slice(&(body as u64).to_le_bytes());
        m.extend_from_slice(&function.to_le_bytes());
        m.extend_from_slice(&u64::MAX.to_le_bytes());
        m.extend_from_slice(&VENDOR.0);
        m.extend_from_slice(&(data_size as u64).to_le_bytes());
        m.extend_from_slice(&(n.len() as u64).to_le_bytes());
        m.extend_from_slice(&attrs.to_le_bytes());
        m.extend_from_slice(&n);
        m.extend_from_slice(data);
        m.resize(MM_HEADER + body, 0);
        m
    };
    let mut set = msg(3, NV_BS_RT, b"value", 5);
    svc.communicate(&mut set).unwrap();
    assert_eq!(get_u64(&set, MM_HEADER + 8).unwrap(), 0);
    let mut got = msg(1, 0, b"", 16);
    svc.communicate(&mut got).unwrap();
    let p = MM_HEADER + VAR_HEADER;
    assert_eq!(get_u64(&got, MM_HEADER + 8).unwrap(), 0);
    assert_eq!(get_u64(&got, p + 16).unwrap(), 5);
    assert_eq!(codec::get_u32(&got, p + 32).unwrap(), NV_BS_RT);
    assert_eq!(&got[p + ACCESS_NAME + n.len()..][..5], b"value");
}

// --- Secure Boot, with a key and certificate made here ---

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(der::SEQUENCE, &parts.concat())
}

fn integer(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    if v.first().is_some_and(|b| b & 0x80 != 0) {
        v.insert(0, 0);
    }
    tlv(der::INTEGER, &v)
}

fn alg(oid: &[u8]) -> Vec<u8> {
    seq(&[tlv(der::OID, oid), vec![0x05, 0x00]])
}

fn cn(name: &str) -> Vec<u8> {
    seq(&[tlv(
        der::SET,
        &seq(&[
            tlv(der::OID, &[0x55, 0x04, 0x03]),
            tlv(0x0c, name.as_bytes()),
        ]),
    )])
}

/// A key and its self-signed certificate.
struct Signer {
    key: RsaPrivateKey,
    cert: Vec<u8>,
    name: Vec<u8>,
}

fn signer(common_name: &str) -> Signer {
    signer_from(common_name, &mut UnwrapErr(getrandom::SysRng))
}

/// A key `rng` makes, and its self-signed certificate: the same ones for the same `rng` state.
fn signer_from(common_name: &str, rng: &mut impl getrandom::rand_core::CryptoRng) -> Signer {
    let key = RsaPrivateKey::new(rng, 1024).unwrap();
    let name = cn(common_name);
    let n = key.n().to_be_bytes();
    let e = BoxedUint::from(65537u32).to_be_bytes();
    let rsa_key = seq(&[integer(der::unsigned(&n)), integer(der::unsigned(&e))]);
    let spki = seq(&[
        alg(der::oids::RSA_ENCRYPTION),
        tlv(der::BIT_STRING, &[&[0][..], &rsa_key].concat()),
    ]);
    let time = tlv(0x17, b"250101000000Z");
    let tbs = seq(&[
        tlv(der::CTX0, &integer(&[2])),
        integer(&[1]),
        alg(der::oids::SHA256_WITH_RSA),
        name.clone(),
        seq(&[time.clone(), time]),
        name.clone(),
        spki,
    ]);
    let sig = Pkcs1v15Sign::new::<Sha256>()
        .sign(Some(rng), &key, &Sha256::digest(&tbs))
        .unwrap();
    let cert = seq(&[
        tbs,
        alg(der::oids::SHA256_WITH_RSA),
        tlv(der::BIT_STRING, &[&[0][..], &sig].concat()),
    ]);
    Signer { key, cert, name }
}

impl Signer {
    /// A bare SignedData over `content`, without signed attributes.
    fn sign(&self, content: &[u8]) -> Vec<u8> {
        let mut rng = getrandom::SysRng;
        let sig = Pkcs1v15Sign::new::<Sha256>()
            .sign(Some(&mut rng), &self.key, &Sha256::digest(content))
            .unwrap();
        let signer_info = seq(&[
            integer(&[1]),
            seq(&[self.name.clone(), integer(&[1])]),
            alg(der::oids::SHA256),
            alg(der::oids::RSA_ENCRYPTION),
            tlv(der::OCTET_STRING, &sig),
        ]);
        seq(&[
            integer(&[1]),
            tlv(der::SET, &alg(der::oids::SHA256)),
            seq(&[tlv(
                der::OID,
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01],
            )]),
            tlv(der::CTX0, &self.cert),
            tlv(der::SET, &signer_info),
        ])
    }

    /// An X.509 signature list with this signer's certificate.
    fn siglist(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&guid::CERT_X509.0);
        out.extend_from_slice(&((28 + 16 + self.cert.len()) as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&((16 + self.cert.len()) as u32).to_le_bytes());
        out.extend_from_slice(&VENDOR.0);
        out.extend_from_slice(&self.cert);
        out
    }
}

fn time(second: u8) -> [u8; 16] {
    let mut t = [0u8; 16];
    t[..2].copy_from_slice(&2026u16.to_le_bytes());
    t[2] = 10;
    t[3] = 7;
    t[6] = second;
    t
}

/// EFI_VARIABLE_AUTHENTICATION_2 + payload, signed by `by` (None: an empty signature).
fn authenticated(
    n: &str,
    g: &Guid,
    attrs: u32,
    second: u8,
    payload: &[u8],
    by: Option<&Signer>,
) -> Vec<u8> {
    let ts = time(second);
    let content = {
        let mut c = codec::ucs2_bytes(&name(n));
        c.truncate(c.len() - 2);
        c.extend_from_slice(&g.0);
        c.extend_from_slice(&attrs.to_le_bytes());
        c.extend_from_slice(&ts);
        c.extend_from_slice(payload);
        c
    };
    let sig = by.map(|s| s.sign(&content)).unwrap_or_default();
    let mut out = ts.to_vec();
    out.extend_from_slice(&((8 + 16 + sig.len()) as u32).to_le_bytes());
    out.extend_from_slice(&0x0200u16.to_le_bytes());
    out.extend_from_slice(&0x0ef1u16.to_le_bytes());
    out.extend_from_slice(&guid::CERT_PKCS7.0);
    out.extend_from_slice(&sig);
    out.extend_from_slice(payload);
    out
}

#[test]
fn secure_boot_keys_are_enrolled_then_only_signed_writes_go() {
    let pk = signer("PK");
    let kek = signer("KEK");
    let mut svc = Service::new(image()).unwrap();
    assert_eq!(get(&svc, &GLOBAL_VARIABLE, "SetupMode").unwrap().1, [1]);
    let g = GLOBAL_VARIABLE;
    // Setup mode: the PK goes in without a signature check.
    let data = authenticated("PK", &g, AUTH, 1, &pk.siglist(), None);
    assert_eq!(
        svc.set_variable(&g, &name("PK"), AUTH, &data),
        Status::SUCCESS
    );
    assert_eq!(get(&svc, &g, "SetupMode").unwrap().1, [0]);
    assert_eq!(get(&svc, &g, "SecureBoot").unwrap().1, [1]);
    // User mode: KEK unsigned, or signed by the wrong key, is refused; by the PK it goes.
    let unsigned = authenticated("KEK", &g, AUTH, 2, &kek.siglist(), None);
    assert_eq!(
        svc.set_variable(&g, &name("KEK"), AUTH, &unsigned),
        Status::SECURITY_VIOLATION
    );
    let wrong = authenticated("KEK", &g, AUTH, 2, &kek.siglist(), Some(&kek));
    assert_eq!(
        svc.set_variable(&g, &name("KEK"), AUTH, &wrong),
        Status::SECURITY_VIOLATION
    );
    let good = authenticated("KEK", &g, AUTH, 2, &kek.siglist(), Some(&pk));
    assert_eq!(
        svc.set_variable(&g, &name("KEK"), AUTH, &good),
        Status::SUCCESS
    );
    // db by the KEK; an append may carry an older timestamp, a replace may not.
    let db = IMAGE_SECURITY_DATABASE;
    let hash_list = {
        let mut l = Vec::new();
        l.extend_from_slice(&guid::CERT_SHA256.0);
        l.extend_from_slice(&(28u32 + 48).to_le_bytes());
        l.extend_from_slice(&0u32.to_le_bytes());
        l.extend_from_slice(&48u32.to_le_bytes());
        l.extend_from_slice(&VENDOR.0);
        l.extend_from_slice(&[0xab; 32]);
        l
    };
    let write = authenticated("db", &db, AUTH, 5, &hash_list, Some(&kek));
    assert_eq!(
        svc.set_variable(&db, &name("db"), AUTH, &write),
        Status::SUCCESS
    );
    let append = authenticated(
        "db",
        &db,
        AUTH | APPEND_WRITE,
        3,
        &kek.siglist(),
        Some(&kek),
    );
    assert_eq!(
        svc.set_variable(&db, &name("db"), AUTH | APPEND_WRITE, &append),
        Status::SUCCESS
    );
    let stored = get(&svc, &db, "db").unwrap().1;
    assert_eq!(siglist::parse(&stored).unwrap().len(), 2);
    // Appending the same certificate again adds nothing.
    let again = authenticated(
        "db",
        &db,
        AUTH | APPEND_WRITE,
        4,
        &kek.siglist(),
        Some(&kek),
    );
    assert_eq!(
        svc.set_variable(&db, &name("db"), AUTH | APPEND_WRITE, &again),
        Status::SUCCESS
    );
    let stored = get(&svc, &db, "db").unwrap().1;
    assert_eq!(siglist::parse(&stored).unwrap().len(), 2);
    let stale = authenticated("db", &db, AUTH, 4, &hash_list, Some(&kek));
    assert_eq!(
        svc.set_variable(&db, &name("db"), AUTH, &stale),
        Status::SECURITY_VIOLATION
    );
    // The modes are the service's: the guest cannot write them.
    assert_eq!(
        svc.set_variable(
            &g,
            &name("SetupMode"),
            BOOTSERVICE_ACCESS | RUNTIME_ACCESS,
            &[1]
        ),
        Status::WRITE_PROTECTED
    );
    // Deleting the PK, signed by it, goes back to setup mode.
    let delete = authenticated("PK", &g, AUTH, 9, &[], Some(&pk));
    assert_eq!(
        svc.set_variable(&g, &name("PK"), AUTH, &delete),
        Status::SUCCESS
    );
    assert_eq!(get(&svc, &g, "SetupMode").unwrap().1, [1]);
}

#[test]
fn a_private_authenticated_variable_keeps_its_signer() {
    let owner = signer("owner");
    let other = signer("other");
    let mut svc = Service::new(image()).unwrap();
    let first = authenticated("Mine", &VENDOR, AUTH, 1, b"one", Some(&owner));
    assert_eq!(
        svc.set_variable(&VENDOR, &name("Mine"), AUTH, &first),
        Status::SUCCESS
    );
    let hijack = authenticated("Mine", &VENDOR, AUTH, 2, b"two", Some(&other));
    assert_eq!(
        svc.set_variable(&VENDOR, &name("Mine"), AUTH, &hijack),
        Status::SECURITY_VIOLATION
    );
    let update = authenticated("Mine", &VENDOR, AUTH, 3, b"three", Some(&owner));
    assert_eq!(
        svc.set_variable(&VENDOR, &name("Mine"), AUTH, &update),
        Status::SUCCESS
    );
    assert_eq!(get(&svc, &VENDOR, "Mine").unwrap().1, b"three");
    // A delete is a write: no signature, no delete.
    assert_eq!(
        svc.set_variable(&VENDOR, &name("Mine"), 0, &[]),
        Status::WRITE_PROTECTED
    );
    assert_eq!(get(&svc, &VENDOR, "Mine").unwrap().1, b"three");
}

#[test]
fn the_secure_boot_keys_are_not_deleted_without_a_signature() {
    let pk = signer("PK");
    let kek = signer("KEK");
    let mut svc = Service::new(image()).unwrap();
    let g = GLOBAL_VARIABLE;
    let db = IMAGE_SECURITY_DATABASE;
    let data = authenticated("PK", &g, AUTH, 1, &pk.siglist(), None);
    assert_eq!(
        svc.set_variable(&g, &name("PK"), AUTH, &data),
        Status::SUCCESS
    );
    let data = authenticated("KEK", &g, AUTH, 2, &kek.siglist(), Some(&pk));
    assert_eq!(
        svc.set_variable(&g, &name("KEK"), AUTH, &data),
        Status::SUCCESS
    );
    let data = authenticated("db", &db, AUTH, 3, &kek.siglist(), Some(&kek));
    assert_eq!(
        svc.set_variable(&db, &name("db"), AUTH, &data),
        Status::SUCCESS
    );
    // Attributes 0 (a delete), or a plain write without time-based authentication: refused,
    // the keys stay, and so does user mode.
    for (guid, n) in [(g, "PK"), (g, "KEK"), (db, "db")] {
        assert_eq!(
            svc.set_variable(&guid, &name(n), 0, &[]),
            Status::INVALID_PARAMETER,
            "{n}"
        );
        assert_eq!(
            svc.set_variable(&guid, &name(n), NV_BS_RT, b"junk"),
            Status::INVALID_PARAMETER,
            "{n}"
        );
        assert!(get(&svc, &guid, n).is_some(), "{n} is gone");
    }
    // Nor is an absent database created or deleted without one.
    for attributes in [0, NV_BS_RT] {
        assert_eq!(
            svc.set_variable(&db, &name("dbx"), attributes, b"junk"),
            Status::INVALID_PARAMETER
        );
    }
    assert!(get(&svc, &db, "dbx").is_none());
    assert_eq!(get(&svc, &g, "SetupMode").unwrap().1, [0]);
    assert_eq!(get(&svc, &g, "SecureBoot").unwrap().1, [1]);
    // The PK deletes itself only by a PK-signed empty write.
    let unsigned = authenticated("PK", &g, AUTH, 4, &[], None);
    assert_eq!(
        svc.set_variable(&g, &name("PK"), AUTH, &unsigned),
        Status::SECURITY_VIOLATION
    );
    let signed = authenticated("PK", &g, AUTH, 4, &[], Some(&pk));
    assert_eq!(
        svc.set_variable(&g, &name("PK"), AUTH, &signed),
        Status::SUCCESS
    );
    assert_eq!(get(&svc, &g, "SetupMode").unwrap().1, [1]);
}

#[test]
fn a_snapshot_keeps_the_phase_and_the_volatile_variables() {
    let mut svc = Service::new(image()).unwrap();
    svc.set_variable(
        &VENDOR,
        &name("BootCurrent"),
        BOOTSERVICE_ACCESS | RUNTIME_ACCESS,
        &[1, 0],
    );
    svc.set_variable(&VENDOR, &name("Nv"), NV_BS_RT, b"nv");
    svc.runtime = true;
    let state = svc.save_transient();
    let bytes = svc.take_image().unwrap().unwrap().to_vec();
    let mut restored = Service::new(bytes).unwrap();
    restored.restore_transient(&state).unwrap();
    assert!(restored.runtime);
    assert_eq!(get(&restored, &VENDOR, "BootCurrent").unwrap().1, [1, 0]);
    assert_eq!(get(&restored, &VENDOR, "Nv").unwrap().1, b"nv");
    assert_eq!(
        get(&restored, &GLOBAL_VARIABLE, "SetupMode").unwrap().1,
        [1]
    );
}

/// Delete a private authenticated variable, signed by `by`.
fn delete_private(svc: &mut Service, n: &str, second: u8, by: &Signer) -> Status {
    let delete = authenticated(n, &VENDOR, AUTH, second, &[], Some(by));
    svc.set_variable(&VENDOR, &name(n), AUTH, &delete)
}

#[test]
fn a_deleted_private_variable_takes_its_signer_record_with_it() {
    let owner = signer("owner");
    let mut svc = Service::new(image()).unwrap();
    for n in ["A", "B"] {
        let write = authenticated(n, &VENDOR, AUTH, 1, b"x", Some(&owner));
        assert_eq!(
            svc.set_variable(&VENDOR, &name(n), AUTH, &write),
            Status::SUCCESS
        );
    }
    assert_eq!(svc.signer_records().len(), 2);
    assert_eq!(delete_private(&mut svc, "A", 2, &owner), Status::SUCCESS);
    let records = svc.signer_records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].1, name("B"));
    assert_eq!(delete_private(&mut svc, "B", 2, &owner), Status::SUCCESS);
    assert_eq!(
        svc.data(&CERT_DB, SIGNERS),
        None,
        "no records left, no variable"
    );
}

#[test]
fn an_existing_private_variable_without_a_recorded_signer_is_nobodys_to_take() {
    let owner = signer("owner");
    let mut svc = Service::new(image()).unwrap();
    let first = authenticated("Mine", &VENDOR, AUTH, 1, b"one", Some(&owner));
    assert_eq!(
        svc.set_variable(&VENDOR, &name("Mine"), AUTH, &first),
        Status::SUCCESS
    );
    // As a variable carried over from the firmware's own store, whose certdb is not read.
    let i = svc.store.position(&CERT_DB, &name(SIGNERS)).unwrap();
    svc.store.remove(i);
    let takeover = authenticated("Mine", &VENDOR, AUTH, 2, b"two", Some(&signer("other")));
    assert_eq!(
        svc.set_variable(&VENDOR, &name("Mine"), AUTH, &takeover),
        Status::SECURITY_VIOLATION
    );
    assert_eq!(get(&svc, &VENDOR, "Mine").unwrap().1, b"one");
}

#[test]
fn a_signer_record_that_does_not_fit_refuses_the_write_and_stores_nothing() {
    let owner = signer("owner");
    let mut svc = Service::new(image()).unwrap();
    // Records as many as a variable holds: one more the size of "Mine"'s cannot join them.
    let room = MAX_VARIABLE_SIZE - 2 * (SIGNERS.len() + 1);
    let mut records = Vec::new();
    for i in 0.. {
        records.push((VENDOR, name(&format!("{i:04}")), [0u8; 32]));
        if encode_signer_records(&records).len() > room {
            records.pop();
            break;
        }
    }
    let full = encode_signer_records(&records);
    svc.put_internal(
        CERT_DB,
        SIGNERS,
        NON_VOLATILE | BOOTSERVICE_ACCESS,
        full.clone(),
    );
    let write = authenticated("Mine", &VENDOR, AUTH, 1, b"one", Some(&owner));
    assert_eq!(
        svc.set_variable(&VENDOR, &name("Mine"), AUTH, &write),
        Status::OUT_OF_RESOURCES
    );
    assert_eq!(get(&svc, &VENDOR, "Mine"), None);
    assert_eq!(svc.data(&CERT_DB, SIGNERS), Some(full));
}

#[test]
fn a_private_variable_the_budget_cannot_hold_records_no_signer() {
    let owner = signer("owner");
    let mut svc = Service::new(image()).unwrap();
    // Fill the non-volatile budget with plain variables, then ask for one more.
    let chunk = vec![0u8; MAX_VARIABLE_SIZE / 2];
    let mut i = 0;
    while svc.set_variable(&VENDOR, &name(&format!("Fill{i}")), NV_BS_RT, &chunk) == Status::SUCCESS
    {
        i += 1;
    }
    // Larger than the last one refused, so no smaller name lets it in.
    let mine = vec![0u8; chunk.len() + 64];
    let write = authenticated("Mine", &VENDOR, AUTH, 1, &mine, Some(&owner));
    assert_eq!(
        svc.set_variable(&VENDOR, &name("Mine"), AUTH, &write),
        Status::OUT_OF_RESOURCES
    );
    assert!(svc.signer_records().is_empty());
}

/// An rsaEncryption SubjectPublicKeyInfo's content for modulus `n` and exponent `e`.
fn spki(n: &[u8], e: &[u8]) -> Vec<u8> {
    let key = seq(&[integer(n), integer(e)]);
    [
        alg(der::oids::RSA_ENCRYPTION),
        tlv(der::BIT_STRING, &[&[0][..], &key].concat()),
    ]
    .concat()
}

#[test]
fn rsa_keys_are_bounded_in_size_and_exponent() {
    // All ones: the top bit set, and odd.
    let odd = |bits: usize| vec![0xffu8; bits / 8];
    let e = [1, 0, 1];
    assert!(pkcs7::rsa_key(&spki(&odd(2048), &e)).is_some());
    assert!(pkcs7::rsa_key(&spki(&odd(1024), &e)).is_some());
    assert!(pkcs7::rsa_key(&spki(&odd(512), &e)).is_none(), "too small");
    assert!(
        pkcs7::rsa_key(&spki(&odd(16384 + 8), &e)).is_none(),
        "too large"
    );
    let huge_e = [0x7f; 64];
    assert!(
        pkcs7::rsa_key(&spki(&odd(2048), &huge_e)).is_none(),
        "exponent too large"
    );
    let mut even = odd(2048);
    *even.last_mut().unwrap() = 0xfe;
    assert!(pkcs7::rsa_key(&spki(&even, &e)).is_none(), "even modulus");
}

#[test]
fn appended_entries_the_new_data_repeats_go_in_once() {
    let kek = signer("KEK");
    let twice = [kek.siglist(), kek.siglist()].concat();
    let merged = siglist::append(&[], &twice).unwrap();
    assert_eq!(merged, kek.siglist());
}

#[test]
fn a_policy_message_without_room_for_its_status_changes_nothing() {
    let mut svc = Service::new(image()).unwrap();
    // DISABLE, its header cut short of the result field.
    let mut msg = guid::VAR_CHECK_POLICY_MMI.0.to_vec();
    msg.extend_from_slice(&16u64.to_le_bytes());
    msg.extend_from_slice(&POLICY_SIGNATURE.to_le_bytes());
    msg.extend_from_slice(&POLICY_REVISION.to_le_bytes());
    msg.extend_from_slice(&1u32.to_le_bytes());
    msg.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(svc.communicate(&mut msg), Err(MmError::Malformed));
    assert!(svc.policies.enabled());
}

#[test]
fn the_secure_boot_switch_is_boot_service_only_and_one_byte() {
    let mut svc = Service::new(image()).unwrap();
    let g = SECURE_BOOT_ENABLE_DISABLE;
    let bs = NON_VOLATILE | BOOTSERVICE_ACCESS;
    assert_eq!(
        svc.set_variable(&g, &name("SecureBootEnable"), NV_BS_RT, &[0]),
        Status::INVALID_PARAMETER,
        "the OS would reach it at run time"
    );
    assert_eq!(
        svc.set_variable(&g, &name("SecureBootEnable"), bs, &[0, 0]),
        Status::INVALID_PARAMETER
    );
    assert_eq!(
        svc.set_variable(&g, &name("SecureBootEnable"), bs, &[1]),
        Status::SUCCESS
    );
    svc.runtime = true;
    assert_eq!(
        svc.set_variable(&g, &name("SecureBootEnable"), bs, &[0]),
        Status::WRITE_PROTECTED
    );
}

#[test]
fn appending_nothing_to_no_variable_creates_none() {
    let mut svc = Service::new(image()).unwrap();
    assert_eq!(
        svc.set_variable(&VENDOR, &name("None"), NV_BS_RT | APPEND_WRITE, b""),
        Status::SUCCESS
    );
    assert_eq!(get(&svc, &VENDOR, "None"), None);
}

#[test]
fn a_volatile_private_variable_leaves_no_record_past_its_boot() {
    let owner = signer("owner");
    let mut svc = Service::new(image()).unwrap();
    let attrs = BOOTSERVICE_ACCESS | RUNTIME_ACCESS | TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
    let write = authenticated("Gone", &VENDOR, attrs, 1, b"x", Some(&owner));
    assert_eq!(
        svc.set_variable(&VENDOR, &name("Gone"), attrs, &write),
        Status::SUCCESS
    );
    assert_eq!(svc.signer_records().len(), 1);
    let next_boot = Service::new(svc.take_image().unwrap().unwrap().to_vec()).unwrap();
    assert!(next_boot.signer_records().is_empty());
    assert_eq!(next_boot.data(&CERT_DB, SIGNERS), None);
}

#[test]
fn the_os_cannot_create_morlock() {
    let mut svc = Service::new(image()).unwrap();
    assert_eq!(
        svc.set_variable(
            &guid::MEMORY_OVERWRITE_REQUEST_CONTROL_LOCK,
            &name("MemoryOverwriteRequestControlLock"),
            NV_BS_RT,
            &[1]
        ),
        Status::WRITE_PROTECTED
    );
}

// --- Malformed messages: the guest writes the buffer, and a panic would end its VM ---

/// xorshift64*, so that a failing iteration replays from its seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// Also the fuzz's key generator, so that its signers, and the seeds they sign, are the same
/// on every run (not a cryptographic generator, which a test key does not need).
impl getrandom::rand_core::TryRng for Rng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.next() as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.next())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let bytes = self.next().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

impl getrandom::rand_core::TryCryptoRng for Rng {}

/// An MM message for `handler`: its header, then `body`.
fn mm(handler: &Guid, body: &[u8]) -> Vec<u8> {
    let mut m = handler.0.to_vec();
    m.extend_from_slice(&(body.len() as u64).to_le_bytes());
    m.extend_from_slice(body);
    m
}

/// A variable protocol message: function, status, then `payload`.
fn var_mm(function: u64, payload: &[u8]) -> Vec<u8> {
    let mut body = function.to_le_bytes().to_vec();
    body.extend_from_slice(&u64::MAX.to_le_bytes());
    body.extend_from_slice(payload);
    mm(&guid::SMM_VARIABLE_PROTOCOL, &body)
}

/// ACCESS_VARIABLE: guid, data size, name size, attributes, name, data.
fn access(g: &Guid, n: &str, attrs: u32, data: &[u8], room: usize) -> Vec<u8> {
    let name = codec::ucs2_bytes(&name(n));
    let mut p = g.0.to_vec();
    p.extend_from_slice(&(data.len().max(room) as u64).to_le_bytes());
    p.extend_from_slice(&(name.len() as u64).to_le_bytes());
    p.extend_from_slice(&attrs.to_le_bytes());
    p.extend_from_slice(&name);
    p.extend_from_slice(data);
    p.resize(ACCESS_NAME + name.len() + data.len().max(room), 0);
    p
}

/// Well-formed messages of every kind the service handles, to mutate.
fn seed_messages(pk: &Signer, kek: &Signer) -> Vec<Vec<u8>> {
    let g = GLOBAL_VARIABLE;
    let db = IMAGE_SECURITY_DATABASE;
    let mut seeds = vec![
        var_mm(3, &access(&VENDOR, "Fuzz", NV_BS_RT, b"value", 0)),
        var_mm(1, &access(&VENDOR, "Fuzz", 0, b"", 64)),
        var_mm(1, &access(&g, "SecureBoot", 0, b"", 1)),
        // QUERY_VARIABLE_INFO: three sizes out, then the attributes asked about.
        var_mm(
            4,
            &[&[0u8; 24][..], &NV_BS_RT.to_le_bytes(), &[0u8; 4]].concat(),
        ),
        var_mm(5, &[]),
        var_mm(6, &[]),
        var_mm(9, &[]),
        var_mm(10, &[]),
        var_mm(11, &[0u8; 8]),
    ];
    let mut next = VENDOR.0.to_vec();
    next.extend_from_slice(&64u64.to_le_bytes());
    next.extend_from_slice(&[0u8; 64]);
    seeds.push(var_mm(2, &next));
    // VARIABLE_LOCK: vendor, name size, name.
    let lock_name = codec::ucs2_bytes(&name("Fuzz"));
    let mut lock = VENDOR.0.to_vec();
    lock.extend_from_slice(&(lock_name.len() as u64).to_le_bytes());
    lock.extend_from_slice(&lock_name);
    seeds.push(var_mm(8, &lock));
    for (n, guid, by, payload) in [
        ("PK", g, None, pk.siglist()),
        ("KEK", g, Some(pk), kek.siglist()),
        ("db", db, Some(kek), kek.siglist()),
        ("dbx", db, Some(kek), kek.siglist()),
    ] {
        let data = authenticated(n, &guid, AUTH, 1, &payload, by);
        seeds.push(var_mm(3, &access(&guid, n, AUTH, &data, 0)));
    }
    for command in 1..=5u32 {
        let mut body = POLICY_SIGNATURE.to_le_bytes().to_vec();
        body.extend_from_slice(&POLICY_REVISION.to_le_bytes());
        body.extend_from_slice(&command.to_le_bytes());
        body.extend_from_slice(&[0u8; 12]);
        if command == 3 {
            let name = codec::ucs2_bytes(&name("Fuzz"));
            body.extend_from_slice(&0x0001_0000u32.to_le_bytes()); // revision
            // VARIABLE_POLICY_ENTRY, 44 bytes, then the name.
            body.extend_from_slice(&((44 + name.len()) as u16).to_le_bytes());
            body.extend_from_slice(&44u16.to_le_bytes()); // name offset
            body.extend_from_slice(&VENDOR.0);
            for v in [0, u32::MAX, 0, 0] {
                body.extend_from_slice(&v.to_le_bytes()); // sizes, attributes
            }
            body.extend_from_slice(&[0u8; 4]); // no lock, padding
            body.extend_from_slice(&name);
        } else {
            body.extend_from_slice(&[0u8; 16]);
        }
        seeds.push(mm(&guid::VAR_CHECK_POLICY_MMI, &body));
    }
    seeds
}

/// Flip bytes, set 4- or 8-byte fields to edge values, cut or extend the message.
fn mutate(m: &mut Vec<u8>, rng: &mut Rng) {
    const EDGES: [u64; 8] = [0, 1, 2, 0x7f, 0xffff, 0xffff_ffff, u64::MAX, 0x8400];
    for _ in 0..1 + rng.below(4) {
        match rng.below(6) {
            0 | 1 if !m.is_empty() => {
                let i = rng.below(m.len());
                m[i] ^= 1 << rng.below(8);
            }
            2 if m.len() >= 8 => {
                let i = rng.below(m.len() - 7);
                let v = EDGES[rng.below(EDGES.len())];
                m[i..i + 8].copy_from_slice(&v.to_le_bytes());
            }
            3 if m.len() >= 4 => {
                let i = rng.below(m.len() - 3);
                let v = EDGES[rng.below(EDGES.len())] as u32;
                m[i..i + 4].copy_from_slice(&v.to_le_bytes());
            }
            4 => m.truncate(rng.below(m.len() + 1)),
            _ => m.resize(m.len() + rng.below(64), rng.next() as u8),
        }
    }
}

/// A seed mutated: mostly its body, under a header that says its new length, so that a
/// handler gets the short or long payload; now and then the whole message, header included.
fn mutate_seed(seed: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut m = seed.to_vec();
    if rng.below(8) == 0 {
        mutate(&mut m, rng);
        return m;
    }
    let mut body = m.split_off(MM_HEADER);
    mutate(&mut body, rng);
    m[16..MM_HEADER].copy_from_slice(&(body.len() as u64).to_le_bytes());
    m.extend_from_slice(&body);
    m
}

/// Mutated and random messages never panic the service, nor does writing its store after
/// them. Every input derives from `UEFI_VARS_FUZZ_SEED` (the signers' keys too), so a failing
/// iteration replays; `UEFI_VARS_FUZZ=<iterations>` runs it longer.
#[test]
fn malformed_messages_never_panic_the_service() {
    let env = |key: &str, default: u64| {
        std::env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    };
    let iterations = env("UEFI_VARS_FUZZ", 20_000);
    let seed = env("UEFI_VARS_FUZZ_SEED", 0x5eed);
    let mut rng = Rng(seed | 1);
    let (pk, kek) = (signer_from("PK", &mut rng), signer_from("KEK", &mut rng));
    let seeds = seed_messages(&pk, &kek);
    let mut svc = Service::new(image()).unwrap();
    for i in 0..iterations {
        // Often a fresh service, in setup mode and before the end of DXE again: a message that
        // ends boot services comes up about one time in twenty.
        if i % 200 == 0 {
            svc = Service::new(image()).unwrap();
        }
        let mut m = if rng.below(10) == 0 {
            let mut m: Vec<u8> = (0..rng.below(512)).map(|_| rng.next() as u8).collect();
            mutate(&mut m, &mut rng);
            m
        } else {
            mutate_seed(&seeds[rng.below(seeds.len())], &mut rng)
        };
        let message = m.clone();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // Only a panic counts: a refusal, of the message or of the store, is the point.
            let _ = svc.communicate(&mut m);
            let _ = svc.take_image();
        }));
        assert!(
            outcome.is_ok(),
            "iteration {i} (seed {seed:#x}) panicked the service on {message:02x?}"
        );
    }
}
