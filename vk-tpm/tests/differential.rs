//! Differential tests: the same commands to vk-tpm and to libtpms (the engine it replaces),
//! compared byte for byte where the TPM is deterministic, and by shape where it is not (random
//! bytes) or where vk-tpm deliberately differs (its identity, what it does not implement yet).
//!
//! Needs libtpms: `cargo test -p vk-tpm --features libtpms --test differential` with VK_LIBTPMS_DIR set (the build
//! image has it at /opt/tpm).

#![cfg(feature = "libtpms")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod client;
mod libtpms;

use client::{Auth, Sym};
use libtpms::LibTpms;
use vk_tpm::Tpm;

const SELF_TEST: u32 = 0x143;
const STARTUP: u32 = 0x144;
const SHUTDOWN: u32 = 0x145;
const GET_CAPABILITY: u32 = 0x17a;
const GET_RANDOM: u32 = 0x17b;
const PCR_READ: u32 = 0x17e;
const PCR_EXTEND: u32 = 0x182;
const PCR_ALLOCATE: u32 = 0x12b;
const SEQUENCE_COMPLETE: u32 = 0x13e;
const SEQUENCE_UPDATE: u32 = 0x15c;
const FLUSH_CONTEXT: u32 = 0x165;
const HASH: u32 = 0x17d;
const EVENT_SEQUENCE_COMPLETE: u32 = 0x185;
const HASH_SEQUENCE_START: u32 = 0x186;
const START_AUTH_SESSION: u32 = 0x176;
const PCR_EVENT: u32 = 0x13c;
const PCR_RESET: u32 = 0x13d;

const HIERARCHY_CONTROL: u32 = 0x121;
const CHANGE_EPS: u32 = 0x124;
const CHANGE_PPS: u32 = 0x125;
const CLEAR: u32 = 0x126;
const CLEAR_CONTROL: u32 = 0x127;
const HIERARCHY_CHANGE_AUTH: u32 = 0x129;
const SET_PRIMARY_POLICY: u32 = 0x12e;
const DA_LOCK_RESET: u32 = 0x139;
const DA_PARAMETERS: u32 = 0x13a;

const RH_OWNER: u32 = 0x4000_0001;
const RS_PW: u32 = 0x4000_0009;
const RH_NULL: u32 = 0x4000_0007;
const RH_LOCKOUT: u32 = 0x4000_000a;
const RH_ENDORSEMENT: u32 = 0x4000_000b;
const RH_PLATFORM: u32 = 0x4000_000c;
const RH_PLATFORM_NV: u32 = 0x4000_000d;
const HIERARCHIES: [u32; 4] = [RH_OWNER, RH_ENDORSEMENT, RH_PLATFORM, RH_LOCKOUT];
const BANKS: [(u16, usize); 4] = [(0x04, 20), (0x0b, 32), (0x0c, 48), (0x0d, 64)];

/// Both TPMs, fed the same commands.
struct Both {
    ours: Tpm,
    theirs: LibTpms,
}

impl Both {
    fn new() -> Both {
        Both {
            theirs: LibTpms::manufacture(),
            ours: Tpm::manufacture().unwrap(),
        }
    }

    fn started() -> Both {
        let mut both = Both::new();
        both.same(&command(STARTUP, &[], None, &[0, 0]));
        both
    }

    /// Started, with the same seeds and proofs: what derives from them (tickets, primary
    /// keys) is the same on both.
    fn seeded() -> Both {
        let mut both = Both::new();
        let secrets: [[u8; 64]; 6] = std::array::from_fn(|i| [0x11 * (i as u8 + 1); 64]);
        both.theirs.set_secrets(&secrets);
        both.ours.set_secrets_for_tests(&secrets);
        both.same(&command(STARTUP, &[], None, &[0, 0]));
        both
    }

    fn both(&mut self, command: &[u8]) -> (Vec<u8>, Vec<u8>) {
        (self.ours.process(command), self.theirs.process(command))
    }

    /// Send `command` to both; the responses must be the same bytes.
    #[track_caller]
    fn same(&mut self, command: &[u8]) -> Vec<u8> {
        let (ours, theirs) = self.both(command);
        assert_eq!(hex(&ours), hex(&theirs), "command {}", hex(command));
        ours
    }

    /// TPM2_StartAuthSession on both (a session of `kind`, bound to `bind` whose authValue is
    /// `bind_auth`); on success, each TPM's session joins `sessions`. Returns the response
    /// code.
    fn start_session(
        &mut self,
        sessions: &mut Sessions,
        kind: u8,
        hash: u16,
        sym: Sym,
        (bind, bind_auth): (u32, Option<&[u8]>),
        nonce: &[u8],
    ) -> u32 {
        let params = [
            tpm2b(nonce),
            tpm2b(b""),
            vec![kind],
            sym.marshal(hash),
            hash.to_be_bytes().to_vec(),
        ]
        .concat();
        let c = command(START_AUTH_SESSION, &[RH_NULL, bind], None, &params);
        let (ours, theirs) = self.both(&c);
        assert_eq!(ours.len(), theirs.len(), "command {}", hex(&c));
        // The header and the session handle: the nonce is random.
        assert_eq!(
            hex(&ours[..14.min(ours.len())]),
            hex(&theirs[..14.min(theirs.len())])
        );
        if rc(&ours) == 0 {
            let bind = (bind != RH_NULL).then_some(bind_auth.unwrap_or_default());
            sessions
                .ours
                .push(client::Session::started(&ours, hash, nonce, sym, bind));
            sessions
                .theirs
                .push(client::Session::started(&theirs, hash, nonce, sym, bind));
        }
        rc(&ours)
    }

    /// `cmd`, authorized by each TPM's sessions: both must say the same once decrypted, and
    /// each its response HMACs right.
    #[track_caller]
    fn run(&mut self, sessions: &mut Sessions, cmd: &client::Command) -> client::Response {
        sessions.calls += 1;
        let nonce: Vec<u8> = (0..20).map(|i| (sessions.calls * 7 + i) as u8).collect();
        let ours = client::build(cmd, &sessions.ours, &nonce);
        let theirs = client::build(cmd, &sessions.theirs, &nonce);
        let ours = self.ours.process(&ours);
        let theirs = self.theirs.process(&theirs);
        let ours = client::check(cmd, &mut sessions.ours, &nonce, &ours);
        let theirs = client::check(cmd, &mut sessions.theirs, &nonce, &theirs);
        assert_eq!(ours, theirs, "command {:#x}", cmd.code);
        ours
    }

    /// Power off and on: both start again from their permanent state.
    fn power_cycle(&mut self) {
        self.theirs.power_cycle();
        self.ours = Tpm::power_on(&self.ours.permanent_state()).unwrap();
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn rc(response: &[u8]) -> u32 {
    u32::from_be_bytes(response[6..10].try_into().unwrap())
}

/// A command with these handles, then (with `sessions`) that authorization area, then `params`.
fn command(code: u32, handles: &[u32], sessions: Option<&[u8]>, params: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(
        &(if sessions.is_some() {
            0x8002u16
        } else {
            0x8001
        })
        .to_be_bytes(),
    );
    c.extend_from_slice(&[0; 4]);
    c.extend_from_slice(&code.to_be_bytes());
    for h in handles {
        c.extend_from_slice(&h.to_be_bytes());
    }
    if let Some(area) = sessions {
        c.extend_from_slice(&(area.len() as u32).to_be_bytes());
        c.extend_from_slice(area);
    }
    c.extend_from_slice(params);
    let len = c.len() as u32;
    c[2..6].copy_from_slice(&len.to_be_bytes());
    c
}

/// One session in an authorization area.
fn session(handle: u32, nonce: &[u8], attributes: u8, hmac: &[u8]) -> Vec<u8> {
    let mut s = handle.to_be_bytes().to_vec();
    s.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    s.extend_from_slice(nonce);
    s.push(attributes);
    s.extend_from_slice(&(hmac.len() as u16).to_be_bytes());
    s.extend_from_slice(hmac);
    s
}

fn password(pw: &[u8]) -> Vec<u8> {
    session(RS_PW, &[], 0, pw)
}

/// TPML_DIGEST_VALUES with these (algorithm, digest) pairs.
fn digests(values: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut p = (values.len() as u32).to_be_bytes().to_vec();
    for (alg, d) in values {
        p.extend_from_slice(&alg.to_be_bytes());
        p.extend_from_slice(d);
    }
    p
}

fn extend(pcr: u32, values: &[(u16, Vec<u8>)]) -> Vec<u8> {
    command(PCR_EXTEND, &[pcr], Some(&password(b"")), &digests(values))
}

/// TPML_PCR_SELECTION with these (algorithm, bitmap) pairs.
fn selection(selections: &[(u16, &[u8])]) -> Vec<u8> {
    let mut p = (selections.len() as u32).to_be_bytes().to_vec();
    for (alg, bitmap) in selections {
        p.extend_from_slice(&alg.to_be_bytes());
        p.push(bitmap.len() as u8);
        p.extend_from_slice(bitmap);
    }
    p
}

fn get_capability(capability: u32, property: u32, count: u32) -> Vec<u8> {
    let mut p = capability.to_be_bytes().to_vec();
    p.extend_from_slice(&property.to_be_bytes());
    p.extend_from_slice(&count.to_be_bytes());
    command(GET_CAPABILITY, &[], None, &p)
}

/// Read every PCR of every bank, eight at a time, as the response says what it returned.
fn read_all_pcrs(both: &mut Both) {
    for (alg, _) in BANKS {
        let mut left = [0xff, 0xff, 0xff];
        while left != [0, 0, 0] {
            let response = both.same(&command(PCR_READ, &[], None, &selection(&[(alg, &left)])));
            // Header, update counter, count, algorithm, sizeofSelect: then the bitmap.
            let returned = &response[21..24];
            assert_ne!(returned, [0, 0, 0]);
            for (l, r) in left.iter_mut().zip(returned) {
                *l &= !r;
            }
        }
    }
}

#[test]
fn startup_and_shutdown_sequences_match() {
    let mut both = Both::new();
    // Nothing before Startup; Startup(STATE) with nothing saved; then Startup(CLEAR) once.
    both.same(&command(GET_RANDOM, &[], None, &[0, 8]));
    both.same(&command(STARTUP, &[], None, &[0, 1]));
    both.same(&command(STARTUP, &[], None, &[0, 2]));
    both.same(&command(STARTUP, &[], None, &[0, 0]));
    both.same(&command(STARTUP, &[], None, &[0, 0]));
    read_all_pcrs(&mut both);
    for full in [0, 1, 2] {
        both.same(&command(SELF_TEST, &[], None, &[full]));
    }

    let sha256 = |b: u8| (0x0b, vec![b; 32]);
    // (shutdown, startup) after a few extends; None: power lost without a shutdown.
    for (shutdown, startup) in [
        (Some(1u8), 1u8), // resume
        (Some(1), 0),     // restart
        (Some(0), 0),     // reset
        (None, 0),
        (None, 1),
        (Some(0), 1),
        (Some(2), 0),
    ] {
        both.same(&extend(0, &[sha256(1)]));
        both.same(&extend(16, &[sha256(2)]));
        both.same(&extend(23, &[sha256(3)]));
        if let Some(su) = shutdown {
            both.same(&command(SHUTDOWN, &[], None, &[0, su]));
        }
        both.power_cycle();
        both.same(&command(
            PCR_READ,
            &[],
            None,
            &selection(&[(0x0b, &[1, 0, 0x81])]),
        ));
        if rc(&both.same(&command(STARTUP, &[], None, &[0, startup]))) != 0 {
            both.same(&command(STARTUP, &[], None, &[0, 0]));
        }
        both.same(&get_capability(6, 0x201, 1)); // TPM_PT_STARTUP_CLEAR: orderly or not
        read_all_pcrs(&mut both);
    }

    // A state-saved PCR extended after Shutdown(STATE) voids the saved state; others do not.
    for pcr in [23, 0] {
        both.same(&command(SHUTDOWN, &[], None, &[0, 1]));
        both.same(&extend(pcr, &[sha256(4)]));
        both.power_cycle();
        both.same(&command(STARTUP, &[], None, &[0, 1]));
        both.same(&command(STARTUP, &[], None, &[0, 0]));
        read_all_pcrs(&mut both);
    }
}

#[test]
fn pcr_extend_and_read_match() {
    let mut both = Both::started();
    let every_bank: Vec<_> = BANKS
        .iter()
        .map(|&(alg, size)| (alg, vec![0x5a; size]))
        .collect();
    for pcr in (0..26).chain([RH_NULL, 0x4000_0001, 0x0100_0000]) {
        both.same(&extend(pcr, &every_bank));
    }
    // One bank twice, one bank alone, no digest at all.
    both.same(&extend(5, &[(0x0b, vec![1; 32]), (0x0b, vec![2; 32])]));
    both.same(&extend(6, &[(0x04, vec![3; 20])]));
    both.same(&extend(7, &[]));
    read_all_pcrs(&mut both);

    // Malformed digests: unknown or NULL algorithm, short digest, too many, trailing bytes.
    both.same(&extend(8, &[(0x0010, vec![0; 32])]));
    both.same(&extend(8, &[(0x0012, vec![0; 32])]));
    both.same(&extend(8, &[(0x0b, vec![0; 31])]));
    let five: Vec<_> = (0..5).map(|_| (0x04, vec![0; 20])).collect();
    both.same(&extend(8, &five));
    let mut trailing = digests(&[(0x04, vec![0; 20])]);
    trailing.push(0);
    both.same(&command(PCR_EXTEND, &[8], Some(&password(b"")), &trailing));

    // Malformed selections.
    let all: &[u8] = &[0xff, 0xff, 0xff];
    for bad in [
        selection(&[(0x0b, &all[..2])]),
        selection(&[(0x0b, &[0xff, 0xff, 0xff, 0xff])]),
        selection(&[(0x0b, &[])]),
        selection(&[(0x0010, all)]),
        selection(&[(0x0b, all); 5]),
        selection(&[(0x0b, all); 4]),
        selection(&[(0x04, &[1, 0, 0]), (0x0b, &[2, 0, 0]), (0x04, &[1, 0, 0])]),
        selection(&[]),
        vec![0, 0, 0, 1, 0],
    ] {
        both.same(&command(PCR_READ, &[], None, &bad));
    }
}

#[test]
fn authorization_areas_match() {
    let mut both = Both::started();
    let params = digests(&[(0x0b, vec![9; 32])]);
    let pw = password(b"");
    let extend_with = |area: &[u8]| command(PCR_EXTEND, &[3], Some(area), &params);
    for area in [
        pw.clone(),
        password(b"wrong"),
        password(&[0, 0, 0]),
        session(RS_PW, &[1], 0, b""),
        session(RS_PW, &[], 0x01, b""),
        session(RS_PW, &[], 0x02, b""),
        session(RS_PW, &[], 0x08, b""),
        session(RS_PW, &[], 0x20, b""),
        session(RS_PW, &[], 0x40, b""),
        session(RS_PW, &[], 0x80, b""),
        session(RS_PW, &[0; 65], 0, b""),
        session(RS_PW, &[], 0, &[0; 65]),
        session(0x0200_0000, &[0; 16], 0x01, &[0; 32]),
        session(0x0300_0001, &[0; 16], 0x01, &[0; 32]),
        session(0x0100_0000, &[], 0, b""),
        [pw.clone(), pw.clone()].concat(),
        [pw.clone(), pw.clone(), pw.clone(), pw.clone()].concat(),
        pw[..8].to_vec(),
        [pw.clone(), vec![0]].concat(),
    ] {
        both.same(&extend_with(&area));
    }
    // An authorization area whose size is wrong, or that is missing.
    let mut c = extend_with(&pw);
    c[14..18].copy_from_slice(&100u32.to_be_bytes());
    both.same(&c);
    c[14..18].copy_from_slice(&8u32.to_be_bytes());
    both.same(&c);
    both.same(&command(PCR_EXTEND, &[3], None, &params));
    // Sessions where no handle needs one.
    both.same(&command(GET_RANDOM, &[], Some(&pw), &[0, 0]));
    both.same(&command(
        PCR_READ,
        &[],
        Some(&pw),
        &selection(&[(0x0b, &[1, 0, 0])]),
    ));
    read_all_pcrs(&mut both);
}

#[test]
fn malformed_commands_match() {
    let mut both = Both::started();
    let good = command(PCR_READ, &[], None, &selection(&[(0x0b, &[1, 0, 0])]));
    for len in 0..good.len() {
        // Truncated, with the size field left as is, then fixed to match.
        both.same(&good[..len]);
        let mut fixed = good[..len].to_vec();
        if len >= 6 {
            fixed[2..6].copy_from_slice(&(len as u32).to_be_bytes());
            both.same(&fixed);
        }
    }
    for tag in [
        0x0000u16, 0x00c1, 0x00c4, 0x8000, 0x8003, 0x8018, 0x801c, 0x8029, 0xffff,
    ] {
        let mut bad_tag = good.clone();
        bad_tag[..2].copy_from_slice(&tag.to_be_bytes());
        both.same(&bad_tag);
    }
    for code in [0, 0x11f - 1, 0x200, 0x2000_0000, 0xffff_ffff] {
        both.same(&command(code, &[], None, &[]));
    }
    let huge = command(GET_RANDOM, &[], None, &vec![0; vk_tpm::MAX_COMMAND_SIZE]);
    both.same(&huge);
    both.same(&command(SHUTDOWN, &[], None, &[0, 2]));
    both.same(&command(SHUTDOWN, &[], None, &[0]));
}

#[test]
fn get_random_matches_in_shape() {
    let mut both = Both::started();
    for n in [0u16, 1, 32, 48, 64, 65, 1024, 0xffff] {
        let (ours, theirs) = both.both(&command(GET_RANDOM, &[], None, &n.to_be_bytes()));
        assert_eq!(ours.len(), theirs.len(), "{n} random bytes");
        assert_eq!(ours[..12], theirs[..12], "{n} random bytes");
    }
}

/// The entries of a TPM_CAP_* response: (more, capability, count, entries).
fn capability_entries(response: &[u8], entry_size: usize) -> Vec<Vec<u8>> {
    assert_eq!(rc(response), 0);
    let count = u32::from_be_bytes(response[15..19].try_into().unwrap()) as usize;
    let entries = &response[19..];
    assert_eq!(entries.len(), count * entry_size);
    entries.chunks(entry_size).map(<[u8]>::to_vec).collect()
}

#[test]
fn capabilities_match() {
    let mut both = Both::started();
    let counts = [0, 1, 2, 7, 8, 100, 0xffff_ffff];

    // What both report identically: PCR banks and properties, handles.
    for count in counts {
        both.same(&get_capability(5, 0, count));
        for property in [0, 1, 0x0a, 0x0b, 0x11, 0x14, 0x15, 0xffff_ffff] {
            both.same(&get_capability(7, property, count));
        }
        for property in [
            0,
            5,
            23,
            24,
            0x00ff_ffff,
            0x4000_0000,
            0x4000_0007,
            0x4000_000e,
            0x4000_ffff,
            0x0100_0000,
            0x0200_0000,
            0x0300_0000,
            0x8000_0000,
            0x8100_0000,
        ] {
            both.same(&get_capability(1, property, count));
        }
    }
    both.same(&get_capability(5, 1, 8));
    for capability in [0x0b, 0x0100, 0x1_0000, 0xffff_ffff] {
        both.same(&get_capability(capability, 0, 8));
    }
    for property in [0x0400_0000, 0x0500_0000, 0x4100_0000, 0xff00_0000] {
        both.same(&get_capability(1, property, 8));
    }

    // Algorithms and commands: vk-tpm implements a subset, with the same attributes.
    for (capability, size) in [(0u32, 6usize), (2, 4)] {
        let (ours, theirs) = both.both(&get_capability(capability, 0, 1000));
        let theirs = capability_entries(&theirs, size);
        let ours = capability_entries(&ours, size);
        assert!(!ours.is_empty());
        for entry in &ours {
            assert!(
                theirs.contains(entry),
                "cap {capability}: {} not libtpms'",
                hex(entry)
            );
        }
    }

    // TPM properties: the same set, the same values but for vk-tpm's identity and what it
    // does not implement yet.
    let differ = [
        0x105, 0x106, 0x107, 0x108, 0x109, // manufacturer, vendor strings
        0x10b, 0x10c, // firmware version
        0x128, // SPLIT_MAX: no TPM2_Commit
        0x129, 0x12a, // implemented commands
        0x12f, 0x130, // firmware SVN
        0x20d, // LOADED_CURVES: no ECC yet
    ];
    for start in [0x100, 0x200] {
        let (ours, theirs) = both.both(&get_capability(6, start, 1000));
        let ours = capability_entries(&ours, 8);
        let theirs = capability_entries(&theirs, 8);
        assert_eq!(ours.len(), theirs.len(), "properties from {start:#x}");
        for (o, t) in ours.iter().zip(&theirs) {
            let property = u32::from_be_bytes(o[..4].try_into().unwrap());
            if !differ.contains(&property) {
                assert_eq!(hex(o), hex(t), "property {property:#x}");
            } else {
                assert_eq!(o[..4], t[..4]);
            }
        }
    }
    // Paging through the properties gives the same shape on both.
    for (property, count) in [
        (0, 1),
        (0x100, 0),
        (0x101, 3),
        (0x1ff, 9),
        (0x200, 1),
        (0x2ff, 2),
        (0x300, 4),
        (0xffff_ffff, 1),
    ] {
        let (ours, theirs) = both.both(&get_capability(6, property, count));
        assert_eq!(ours.len(), theirs.len(), "{property:#x} {count}");
        assert_eq!(ours[..19], theirs[..19], "{property:#x} {count}");
    }
}

/// A command authorized by one password session.
fn with_password(code: u32, handle: u32, pw: &[u8], params: &[u8]) -> Vec<u8> {
    command(code, &[handle], Some(&password(pw)), params)
}

fn change_auth(handle: u32, pw: &[u8], new: &[u8]) -> Vec<u8> {
    let mut p = (new.len() as u16).to_be_bytes().to_vec();
    p.extend_from_slice(new);
    with_password(HIERARCHY_CHANGE_AUTH, handle, pw, &p)
}

fn hierarchy_control(auth: u32, enable: u32, state: u8) -> Vec<u8> {
    let mut p = enable.to_be_bytes().to_vec();
    p.push(state);
    with_password(HIERARCHY_CONTROL, auth, b"", &p)
}

/// The TPM properties that describe the hierarchies and the dictionary-attack state.
fn read_hierarchy_state(both: &mut Both) {
    both.same(&get_capability(6, 0x200, 2)); // TPMA_PERMANENT, TPMA_STARTUP_CLEAR
    both.same(&get_capability(6, 0x20e, 4)); // lockout counter and parameters
}

#[test]
fn hierarchy_authorizations_match() {
    let mut both = Both::started();
    read_hierarchy_state(&mut both);
    for (i, &h) in HIERARCHIES.iter().enumerate() {
        let auth = vec![b'a' + i as u8; 4 + i];
        both.same(&change_auth(h, b"", &[&auth[..], &[0, 0]].concat()));
        both.same(&change_auth(h, b"", b""));
        both.same(&change_auth(h, &auth, b"x"));
        both.same(&change_auth(h, b"x\0\0", &auth));
        read_hierarchy_state(&mut both);
    }
    // Every handle a TPMI_RH_HIERARCHY_AUTH may not be, and auth values of every size.
    for h in [
        RH_NULL,
        RH_PLATFORM_NV,
        RS_PW,
        0,
        0x4000_0010,
        0x4000_0110,
        0x8000_0000,
    ] {
        both.same(&change_auth(h, b"", b""));
    }
    for len in [32, 48, 64, 65] {
        both.same(&change_auth(RH_OWNER, b"a\0\0\0\0\0", &vec![1; len]));
    }
    // TPM2_SetPrimaryPolicy: digest sizes, algorithms, then the lockout and platform ones.
    for (digest, alg) in [
        (vec![1; 32], 0x0bu16),
        (vec![1; 20], 0x0b),
        (vec![], 0x10),
        (vec![1; 20], 0x10),
        (vec![1; 64], 0x0d),
        (vec![1; 32], 0x12),
    ] {
        let mut p = (digest.len() as u16).to_be_bytes().to_vec();
        p.extend_from_slice(&digest);
        p.extend_from_slice(&alg.to_be_bytes());
        for h in HIERARCHIES {
            let pw: &[u8] = match h {
                RH_OWNER => &[1; 64],
                RH_LOCKOUT => b"dddddddd",
                _ => b"x",
            };
            both.same(&with_password(SET_PRIMARY_POLICY, h, pw, &p));
        }
    }
}

#[test]
fn hierarchy_control_and_clear_match() {
    let mut both = Both::started();
    let enables = [
        RH_OWNER,
        RH_ENDORSEMENT,
        RH_PLATFORM_NV,
        RH_PLATFORM,
        RH_NULL,
        RH_LOCKOUT,
    ];
    for auth in [RH_OWNER, RH_ENDORSEMENT, RH_PLATFORM] {
        for enable in enables {
            for state in [0, 1, 2] {
                both.same(&hierarchy_control(auth, enable, state));
                read_hierarchy_state(&mut both);
                both.same(&hierarchy_control(RH_PLATFORM, enable, 1));
            }
        }
    }
    // Disabled hierarchies, through a resume and a restart.
    both.same(&hierarchy_control(RH_OWNER, RH_OWNER, 0));
    both.same(&hierarchy_control(RH_PLATFORM, RH_PLATFORM_NV, 0));
    both.same(&change_auth(RH_PLATFORM, b"", b"pf"));
    both.same(&change_auth(RH_OWNER, b"", b""));
    both.same(&command(SHUTDOWN, &[], None, &[0, 1]));
    both.power_cycle();
    both.same(&command(STARTUP, &[], None, &[0, 1]));
    read_hierarchy_state(&mut both);
    both.same(&change_auth(RH_PLATFORM, b"pf", b"pf"));
    both.same(&hierarchy_control(RH_PLATFORM, RH_PLATFORM, 0));
    both.same(&change_auth(RH_PLATFORM, b"pf", b""));
    both.same(&command(SHUTDOWN, &[], None, &[0, 1]));
    // A command that changes what Shutdown(STATE) saved voids it.
    both.same(&hierarchy_control(RH_ENDORSEMENT, RH_ENDORSEMENT, 0));
    both.power_cycle();
    both.same(&command(STARTUP, &[], None, &[0, 1]));
    both.same(&command(STARTUP, &[], None, &[0, 0]));
    read_hierarchy_state(&mut both);

    // TPM2_ClearControl and TPM2_Clear, from lockout and from the platform.
    both.same(&change_auth(RH_OWNER, b"", b"owner"));
    both.same(&change_auth(RH_LOCKOUT, b"", b"lock"));
    let clear = |h: u32, pw: &[u8]| with_password(CLEAR, h, pw, &[]);
    let control = |h: u32, pw: &[u8], disable: u8| with_password(CLEAR_CONTROL, h, pw, &[disable]);
    for c in [
        control(RH_LOCKOUT, b"lock", 1),
        clear(RH_LOCKOUT, b"lock"),
        clear(RH_PLATFORM, b""),
        control(RH_LOCKOUT, b"lock", 0),
        control(RH_LOCKOUT, b"lock", 2),
        control(RH_OWNER, b"owner", 0),
        control(RH_PLATFORM, b"", 0),
        clear(RH_OWNER, b"owner"),
        clear(RH_LOCKOUT, b"lock"),
        change_auth(RH_OWNER, b"owner", b""),
        change_auth(RH_OWNER, b"", b""),
        with_password(CHANGE_EPS, RH_PLATFORM, b"", &[]),
        with_password(CHANGE_PPS, RH_PLATFORM, b"", &[]),
        with_password(CHANGE_PPS, RH_OWNER, b"", &[]),
        with_password(CHANGE_EPS, RH_PLATFORM, b"", &[0]),
    ] {
        both.same(&c);
        read_hierarchy_state(&mut both);
        both.same(&command(
            PCR_READ,
            &[],
            None,
            &selection(&[(0x0b, &[1, 0, 0])]),
        ));
    }
}

#[test]
fn dictionary_attack_protection_matches() {
    let mut both = Both::started();
    let reset = |pw: &[u8]| with_password(DA_LOCK_RESET, RH_LOCKOUT, pw, &[]);
    let parameters = |pw: &[u8], max: u32, recovery: u32, lockout: u32| {
        let p = [
            max.to_be_bytes(),
            recovery.to_be_bytes(),
            lockout.to_be_bytes(),
        ]
        .concat();
        with_password(DA_PARAMETERS, RH_LOCKOUT, pw, &p)
    };
    both.same(&change_auth(RH_LOCKOUT, b"", b"lock"));
    both.same(&reset(b"lock"));
    both.same(&reset(b"wrong"));
    read_hierarchy_state(&mut both);
    both.same(&reset(b"lock"));
    both.same(&parameters(b"lock", 5, 10, 0));
    // Through a power cycle, lockout is still locked out (lockoutRecovery was 1000 s).
    both.power_cycle();
    both.same(&command(STARTUP, &[], None, &[0, 0]));
    both.same(&reset(b"lock"));
    both.same(&change_auth(RH_LOCKOUT, b"lock", b"lock"));
    read_hierarchy_state(&mut both);

    // With lockoutRecovery 0, the next Startup lets it be tried again.
    drop(both); // libtpms is one TPM per process
    let mut both = Both::started();
    both.same(&parameters(b"", 5, 10, 0));
    both.same(
        &parameters(b"", 5, 10, 0)
            .iter()
            .copied()
            .chain([0])
            .collect::<Vec<_>>(),
    );
    read_hierarchy_state(&mut both);
    both.same(&reset(b"x"));
    both.same(&reset(b""));
    both.same(&command(SHUTDOWN, &[], None, &[0, 0]));
    both.power_cycle();
    both.same(&command(STARTUP, &[], None, &[0, 0]));
    both.same(&reset(b""));
    both.same(&parameters(b"", 0, 0, 0));
    read_hierarchy_state(&mut both);
    both.same(&clear(RH_LOCKOUT));
    read_hierarchy_state(&mut both);
}

fn clear(h: u32) -> Vec<u8> {
    with_password(CLEAR, h, b"", &[])
}

#[test]
fn pcr_event_and_reset_match() {
    let mut both = Both::started();
    for pcr in (0..25).chain([RH_NULL, RH_OWNER]) {
        let mut event = vec![0, 5];
        event.extend_from_slice(b"event");
        both.same(&command(PCR_EVENT, &[pcr], Some(&password(b"")), &event));
        both.same(&command(PCR_RESET, &[pcr], Some(&password(b"")), &[]));
    }
    for len in [0usize, 1, 1024, 1025] {
        let mut event = (len as u16).to_be_bytes().to_vec();
        event.extend(std::iter::repeat_n(7, len));
        both.same(&command(PCR_EVENT, &[16], Some(&password(b"")), &event));
    }
    both.same(&command(PCR_EVENT, &[16], None, &[0, 0]));
    both.same(&command(PCR_RESET, &[16], Some(&password(b"")), &[0]));
    read_all_pcrs(&mut both);
    // Resetting or extending a state-saved PCR after Shutdown(STATE) voids it; others do not.
    for (code, pcr) in [(PCR_RESET, 16), (PCR_EVENT, 23), (PCR_EVENT, 7)] {
        both.same(&command(SHUTDOWN, &[], None, &[0, 1]));
        let params: &[u8] = if code == PCR_EVENT { &[0, 1, 9] } else { &[] };
        both.same(&command(code, &[pcr], Some(&password(b"")), params));
        both.power_cycle();
        both.same(&command(STARTUP, &[], None, &[0, 1]));
        both.same(&command(STARTUP, &[], None, &[0, 0]));
        read_all_pcrs(&mut both);
    }
}

#[test]
fn pcr_allocate_matches() {
    let mut both = Both::started();
    let allocate = |selections: &[(u16, &[u8])]| {
        with_password(PCR_ALLOCATE, RH_PLATFORM, b"", &selection(selections))
    };
    let none: &[u8] = &[0, 0, 0];
    let all: &[u8] = &[0xff, 0xff, 0xff];
    for request in [
        allocate(&[(0x04, none)]),
        allocate(&[(0x04, none), (0x0b, none), (0x0c, none), (0x0d, none)]),
        allocate(&[(0x04, &[1, 0, 0]), (0x0b, &[0, 0, 2])]),
        allocate(&[(0x04, &[0, 0, 2])]),
        allocate(&[
            (0x04, &[0x81, 0, 2]),
            (0x0b, none),
            (0x0c, none),
            (0x0d, none),
        ]),
        allocate(&[(0x0b, all), (0x0b, none)]),
        allocate(&[(0x0b, &[0xff, 0xff])]),
        allocate(&[(0x12, all)]),
        allocate(&[]),
        with_password(PCR_ALLOCATE, RH_OWNER, b"", &selection(&[])),
    ] {
        both.same(&request);
        both.same(&get_capability(5, 0, 8));
        read_all_pcrs(&mut both);
        both.same(&extend(1, &[(0x04, vec![1; 20]), (0x0b, vec![2; 32])]));
        both.same(&command(PCR_RESET, &[16], Some(&password(b"")), &[]));
    }
    // The new allocation takes effect at the next TPM Reset; Shutdown(STATE) is refused
    // until then.
    both.same(&command(SHUTDOWN, &[], None, &[0, 1]));
    both.same(&command(SHUTDOWN, &[], None, &[0, 0]));
    both.power_cycle();
    both.same(&command(STARTUP, &[], None, &[0, 0]));
    read_all_pcrs(&mut both);
    both.same(&command(SHUTDOWN, &[], None, &[0, 1]));
    both.power_cycle();
    both.same(&command(STARTUP, &[], None, &[0, 1]));
    read_all_pcrs(&mut both);
    // TPM2_Clear drops a pending allocation (the reference implementation rewrites all of its
    // persistent data).
    both.same(&allocate(&[(0x04, none)]));
    both.same(&clear(RH_PLATFORM));
    both.power_cycle();
    both.same(&command(STARTUP, &[], None, &[0, 0]));
    both.same(&get_capability(5, 0, 8));
    both.same(&allocate(&[
        (0x04, all),
        (0x0b, all),
        (0x0c, all),
        (0x0d, all),
    ]));
    read_all_pcrs(&mut both);
    both.same(&command(SHUTDOWN, &[], None, &[0, 0]));
    both.power_cycle();
    both.same(&command(STARTUP, &[], None, &[0, 0]));
    read_all_pcrs(&mut both);
}

/// A TPM2B.
fn tpm2b(data: &[u8]) -> Vec<u8> {
    [&(data.len() as u16).to_be_bytes()[..], data].concat()
}

fn hash(data: &[u8], alg: u16, hierarchy: u32) -> Vec<u8> {
    let p = [
        tpm2b(data),
        alg.to_be_bytes().to_vec(),
        hierarchy.to_be_bytes().to_vec(),
    ]
    .concat();
    command(HASH, &[], None, &p)
}

fn sequence_start(auth: &[u8], alg: u16) -> Vec<u8> {
    let p = [tpm2b(auth), alg.to_be_bytes().to_vec()].concat();
    command(HASH_SEQUENCE_START, &[], None, &p)
}

fn sequence_update(handle: u32, pw: &[u8], data: &[u8]) -> Vec<u8> {
    with_password(SEQUENCE_UPDATE, handle, pw, &tpm2b(data))
}

fn sequence_complete(handle: u32, pw: &[u8], data: &[u8], hierarchy: u32) -> Vec<u8> {
    let p = [tpm2b(data), hierarchy.to_be_bytes().to_vec()].concat();
    with_password(SEQUENCE_COMPLETE, handle, pw, &p)
}

fn event_sequence_complete(pcr: u32, handle: u32, pw: &[u8], data: &[u8]) -> Vec<u8> {
    let area = [password(b""), password(pw)].concat();
    command(
        EVENT_SEQUENCE_COMPLETE,
        &[pcr, handle],
        Some(&area),
        &tpm2b(data),
    )
}

const GENERATED: &[u8] = b"\xffTCG";

#[test]
fn hash_and_its_tickets_match() {
    let mut both = Both::seeded();
    let data = [
        b"",
        &b"abc"[..],
        b"\xffTC",
        GENERATED,
        b"\xffTCGdata",
        &[9; 1024],
    ];
    for data in data {
        for alg in [0x04, 0x0b, 0x0c, 0x0d, 0x10, 0x12] {
            for hierarchy in [
                RH_OWNER,
                RH_ENDORSEMENT,
                RH_PLATFORM,
                RH_NULL,
                RH_LOCKOUT,
                0,
            ] {
                both.same(&hash(data, alg, hierarchy));
            }
        }
    }
    both.same(&hash(&[0; 1025], 0x0b, RH_OWNER));
    both.same(&command(HASH, &[], None, &[0, 1, 0, 0, 0x0b]));
    // A disabled hierarchy still gets its ticket.
    both.same(&hierarchy_control(RH_OWNER, RH_OWNER, 0));
    both.same(&hash(b"abc", 0x0b, RH_OWNER));
}

#[test]
fn hash_sequences_match() {
    let mut both = Both::seeded();
    // Hash sequences: tickets depend on the first block, wherever it comes from.
    for (first, rest) in [
        (Some(&b"abc"[..]), &b"def"[..]),
        (Some(b"ab"), b"cdef"),
        (Some(GENERATED), b"x"),
        (Some(b""), GENERATED),
        (None, GENERATED),
        (None, b"abcd"),
        (None, b""),
    ] {
        for alg in [0x04, 0x0b, 0x0d] {
            for hierarchy in [RH_OWNER, RH_PLATFORM, RH_NULL] {
                let r = both.same(&sequence_start(b"seq\0", alg));
                let handle = u32::from_be_bytes(r[10..14].try_into().unwrap());
                if let Some(first) = first {
                    both.same(&sequence_update(handle, b"seq", first));
                    both.same(&sequence_update(handle, b"seq", &[5; 1024]));
                }
                both.same(&sequence_complete(handle, b"seq", rest, hierarchy));
                both.same(&sequence_complete(handle, b"seq", rest, hierarchy));
            }
        }
    }
    // Event sequences, into a PCR or none.
    for pcr in [RH_NULL, 10, 17, 24] {
        let r = both.same(&sequence_start(b"", 0x10));
        let handle = u32::from_be_bytes(r[10..14].try_into().unwrap());
        both.same(&sequence_update(handle, b"", b"event"));
        both.same(&sequence_complete(handle, b"", b"", RH_OWNER));
        both.same(&event_sequence_complete(pcr, handle, b"", b"data"));
        both.same(&command(FLUSH_CONTEXT, &[], None, &handle.to_be_bytes()));
    }
    read_all_pcrs(&mut both);
}

#[test]
fn object_slots_match() {
    let mut both = Both::started();
    for _ in 0..4 {
        both.same(&sequence_start(b"pw", 0x0b));
        both.same(&get_capability(1, 0x8000_0000, 8));
        both.same(&get_capability(6, 0x207, 1));
    }
    // Wrong and missing handles and passwords, sequences of the wrong kind.
    for handle in [
        0x8000_0000,
        0x8000_0002,
        0x8000_0003,
        0x80ff_ffff,
        0x8100_0000,
        0x8180_0001,
    ] {
        both.same(&sequence_update(handle, b"pw", b"x"));
        both.same(&sequence_update(handle, b"wrong", b"x"));
        both.same(&event_sequence_complete(RH_NULL, handle, b"pw", b""));
        both.same(&command(SEQUENCE_UPDATE, &[handle], None, &tpm2b(b"")));
    }
    for handle in [
        0x8000_0001u32,
        0x8000_0001,
        0x8000_0000,
        0x8000_0003,
        0x0200_0000,
        0x0300_003f,
        0x4000_0001,
        0x8100_0000,
    ] {
        both.same(&command(FLUSH_CONTEXT, &[], None, &handle.to_be_bytes()));
        both.same(&get_capability(1, 0x8000_0000, 8));
    }
    both.same(&command(
        FLUSH_CONTEXT,
        &[],
        Some(&password(b"")),
        &[0x80, 0, 0, 2],
    ));
    both.same(&sequence_start(b"", 0x10));
    both.same(&sequence_start(b"", 0x10));
    both.same(&sequence_start(&[1; 65], 0x0b));
    both.same(&sequence_complete(0x8000_0000, b"", b"", RH_OWNER));
    both.same(&get_capability(1, 0x8000_0001, 1));
    // Persistent handles take a slot to look the object up: with all of them taken,
    // TPM_RC_OBJECT_MEMORY.
    both.same(&sequence_update(0x8100_0000, b"", b""));
    both.same(&hierarchy_control(RH_OWNER, RH_OWNER, 0));
    both.same(&sequence_update(0x8100_0000, b"", b""));
    both.same(&sequence_update(0x8180_0000, b"", b""));
    // A sequence does not outlive Startup.
    both.same(&command(SHUTDOWN, &[], None, &[0, 1]));
    both.power_cycle();
    both.same(&command(STARTUP, &[], None, &[0, 1]));
    both.same(&get_capability(1, 0x8000_0000, 8));
}

/// Each TPM's sessions, as the caller tracks them.
#[derive(Default)]
struct Sessions {
    ours: Vec<client::Session>,
    theirs: Vec<client::Session>,
    calls: usize,
}

const SE_HMAC: u8 = 0;
const SE_POLICY: u8 = 1;
const SE_TRIAL: u8 = 3;
const HMAC_SESSION: u32 = 0x0200_0000;

fn change_auth_command(handle: u32, new: &[u8], auths: Vec<Auth>) -> client::Command {
    client::Command::new(HIERARCHY_CHANGE_AUTH, &[handle], &tpm2b(new), auths)
}

#[test]
fn hmac_sessions_match() {
    let mut both = Both::seeded();
    let mut s = Sessions::default();
    let unbound = (RH_NULL, None);
    assert_eq!(
        both.start_session(
            &mut s,
            SE_HMAC,
            client::SHA256,
            Sym::Null,
            unbound,
            &[1; 16]
        ),
        0
    );
    both.same(&change_auth(RH_OWNER, b"", b"owner"));
    let session = |entity: &[u8], after: Option<&[u8]>| Auth::Session {
        index: 0,
        attributes: client::CONTINUE,
        entity: Some(entity.to_vec()),
        bound: false,
        after: after.map(<[u8]>::to_vec),
        hmac: None,
    };
    // The response HMAC is keyed with the new authValue.
    both.run(
        &mut s,
        &change_auth_command(RH_OWNER, b"new\0", vec![session(b"owner", Some(b"new"))]),
    );
    both.run(
        &mut s,
        &change_auth_command(RH_OWNER, b"", vec![session(b"owner", None)]),
    );
    let mut wrong = session(b"new", None);
    if let Auth::Session { hmac, .. } = &mut wrong {
        *hmac = Some(vec![0; 32]);
    }
    let r = both.run(&mut s, &change_auth_command(RH_OWNER, b"", vec![wrong]));
    assert_eq!(r.rc, 0x9a2, "TPM_RC_BAD_AUTH");
    both.run(
        &mut s,
        &change_auth_command(RH_OWNER, b"", vec![session(b"new", Some(b""))]),
    );
    // The same session for two handles, and a session where none is needed.
    both.run(
        &mut s,
        &change_auth_command(RH_OWNER, b"", vec![session(b"", None), session(b"", None)]),
    );
    let get_random = client::Command::new(GET_RANDOM, &[], &[0, 8], vec![session(b"", None)]);
    both.run(&mut s, &get_random);
    read_hierarchy_state(&mut both);

    // Bound sessions: the bind authValue is in the key, so not added again for the entity it
    // is bound to; once that authValue changes, it is.
    both.same(&change_auth(RH_OWNER, b"", b"owner"));
    both.same(&change_auth(RH_ENDORSEMENT, b"", b"endorsement"));
    let bind = (RH_OWNER, Some(&b"owner"[..]));
    assert_eq!(
        both.start_session(&mut s, SE_HMAC, client::SHA1, Sym::Null, bind, &[2; 20]),
        0
    );
    let bound = |entity: &[u8], bound: bool, after: Option<&[u8]>| Auth::Session {
        index: 1,
        attributes: client::CONTINUE,
        entity: Some(entity.to_vec()),
        bound,
        after: after.map(<[u8]>::to_vec),
        hmac: None,
    };
    both.run(
        &mut s,
        &change_auth_command(RH_OWNER, b"owner", vec![bound(b"owner", true, None)]),
    );
    both.run(
        &mut s,
        &change_auth_command(
            RH_ENDORSEMENT,
            b"endorsement",
            vec![bound(b"endorsement", false, None)],
        ),
    );
    both.run(
        &mut s,
        &change_auth_command(RH_OWNER, b"owner", vec![bound(b"owner", false, None)]),
    );
    both.run(
        &mut s,
        &change_auth_command(RH_OWNER, b"o2", vec![bound(b"owner", true, Some(b"o2"))]),
    );
    both.run(
        &mut s,
        &change_auth_command(RH_OWNER, b"", vec![bound(b"o2", false, Some(b""))]),
    );

    // A session bound to lockout is subject to its dictionary-attack protection: a failure
    // through it disables lockout, whatever the session authorized.
    both.same(&change_auth(RH_LOCKOUT, b"", b"lock"));
    let lockout = (RH_LOCKOUT, Some(&b"lock"[..]));
    assert_eq!(
        both.start_session(
            &mut s,
            SE_HMAC,
            client::SHA384,
            Sym::Null,
            lockout,
            &[3; 48]
        ),
        0
    );
    let via_lockout = |hmac: Option<Vec<u8>>| Auth::Session {
        index: 2,
        attributes: client::CONTINUE,
        entity: Some(Vec::new()),
        bound: false,
        after: None,
        hmac,
    };
    both.run(
        &mut s,
        &change_auth_command(RH_OWNER, b"", vec![via_lockout(None)]),
    );
    both.run(
        &mut s,
        &change_auth_command(RH_OWNER, b"", vec![via_lockout(Some(vec![1; 48]))]),
    );
    read_hierarchy_state(&mut both);
    let r = both.run(
        &mut s,
        &change_auth_command(RH_OWNER, b"", vec![via_lockout(None)]),
    );
    assert_eq!(r.rc, 0x921, "TPM_RC_LOCKOUT");
    both.run(
        &mut s,
        &change_auth_command(RH_OWNER, b"", vec![via_lockout(None)]),
    );
    both.run(
        &mut s,
        &change_auth_command(RH_OWNER, b"", vec![session(b"", None)]),
    );

    // A session that does not continue is flushed.
    let mut last = session(b"", None);
    if let Auth::Session { attributes, .. } = &mut last {
        *attributes = 0;
    }
    both.run(
        &mut s,
        &change_auth_command(RH_OWNER, b"", vec![last.clone()]),
    );
    both.same(&get_capability(1, HMAC_SESSION, 8));
    both.same(&get_capability(6, 0x203, 4));
    both.run(&mut s, &change_auth_command(RH_OWNER, b"", vec![last]));
}

#[test]
fn policy_and_trial_sessions_match() {
    let mut both = Both::seeded();
    let mut s = Sessions::default();
    // Without policy commands, a policy session's digest stays all zeros: an authPolicy of
    // zeros is one it satisfies.
    let mut p = tpm2b(&[0; 32]);
    p.extend_from_slice(&client::SHA256.to_be_bytes());
    both.same(&with_password(SET_PRIMARY_POLICY, RH_OWNER, b"", &p));
    let unbound = (RH_NULL, None);
    for (kind, hash) in [
        (SE_POLICY, client::SHA256),
        (SE_POLICY, client::SHA1),
        (SE_TRIAL, client::SHA256),
    ] {
        assert_eq!(
            both.start_session(&mut s, kind, hash, Sym::Null, unbound, &[4; 20]),
            0
        );
    }
    let policy = |index: usize, attributes: u8| Auth::Session {
        index,
        attributes,
        entity: Some(Vec::new()),
        // A policy session never adds the authValue.
        bound: true,
        after: None,
        hmac: None,
    };
    // Satisfied, SHA-1 instead of SHA-256 (TPM_RC_POLICY_FAIL), no authPolicy
    // (TPM_RC_AUTH_UNAVAILABLE); a trial session authorizes nothing (TPM_RC_ATTRIBUTES).
    let expected = [
        [0, 0x12f, 0x12f],
        [0x99d, 0x12f, 0x12f],
        [0x982, 0x982, 0x982],
    ];
    for (index, expected) in expected.iter().enumerate() {
        for (h, rc) in [RH_OWNER, RH_ENDORSEMENT, RH_PLATFORM]
            .into_iter()
            .zip(expected)
        {
            let cmd = change_auth_command(h, b"", vec![policy(index, client::CONTINUE)]);
            assert_eq!(both.run(&mut s, &cmd).rc, *rc);
        }
    }
    // As an audit or encryption session, a policy session is refused.
    let get_random = |auth| client::Command::new(GET_RANDOM, &[], &[0, 8], vec![auth]);
    both.run(
        &mut s,
        &get_random(policy(0, client::CONTINUE | client::AUDIT)),
    );
    both.run(
        &mut s,
        &get_random(policy(0, client::CONTINUE | client::ENCRYPT)),
    );
    both.run(&mut s, &get_random(policy(2, client::CONTINUE)));
    both.same(&get_capability(1, HMAC_SESSION, 8));
    both.same(&get_capability(1, HMAC_SESSION + 1, 8));
    both.same(&get_capability(1, 0x0300_0000, 8));
}

#[test]
fn parameter_encryption_matches() {
    let mut both = Both::seeded();
    let mut s = Sessions::default();
    let unbound = (RH_NULL, None);
    let mut index = 0;
    for sym in [Sym::Xor, Sym::Aes(128), Sym::Aes(192), Sym::Aes(256)] {
        for hash in [client::SHA1, client::SHA256, client::SHA512] {
            let nonce = vec![index as u8 + 1; 16];
            assert_eq!(
                both.start_session(&mut s, SE_HMAC, hash, sym, unbound, &nonce),
                0
            );
            let crypt = |attributes: u8| Auth::Session {
                index,
                attributes: client::CONTINUE | attributes,
                entity: None,
                bound: false,
                after: None,
                hmac: None,
            };
            // TPM2_Hash: the data in, the digest out; the ticket shows the TPM hashed the
            // plaintext.
            let p = [tpm2b(b"some secret data"), vec![0, 0x0b, 0x40, 0, 0, 1]].concat();
            for attributes in [
                client::DECRYPT,
                client::ENCRYPT,
                client::DECRYPT | client::ENCRYPT,
            ] {
                let cmd = client::Command::new(HASH, &[], &p, vec![crypt(attributes)]);
                assert_eq!(both.run(&mut s, &cmd).rc, 0);
            }
            // A new authValue, encrypted, with a password session authorizing.
            let cmd = change_auth_command(
                RH_OWNER,
                b"encrypted",
                vec![Auth::Password(Vec::new()), crypt(client::DECRYPT)],
            );
            both.run(&mut s, &cmd);
            both.same(&change_auth(RH_OWNER, b"encrypted", b""));
            // Sessions that cannot: no symmetric algorithm, or a command without the parameter.
            let cmd =
                client::Command::new(GET_CAPABILITY, &[], &[0; 12], vec![crypt(client::DECRYPT)]);
            both.run(&mut s, &cmd);
            let cmd = client::Command::new(PCR_READ, &[], &[0; 4], vec![crypt(client::ENCRYPT)]);
            both.run(&mut s, &cmd);
            index += 1;
            let r = both.same(&command(
                FLUSH_CONTEXT,
                &[],
                None,
                &(HMAC_SESSION + 1).to_be_bytes(),
            ));
            if rc(&r) == 0 {
                s.ours.remove(1);
                s.theirs.remove(1);
                index -= 1;
            }
            if s.ours.len() == 3 {
                both.same(&command(
                    FLUSH_CONTEXT,
                    &[],
                    None,
                    &HMAC_SESSION.to_be_bytes(),
                ));
                s.ours.remove(0);
                s.theirs.remove(0);
                index -= 1;
            }
        }
    }

    // An HMAC session that authorizes, with another that encrypts both ways: the first one's
    // HMAC covers the other's nonce. The sequence's Name is empty.
    both.same(&command(
        FLUSH_CONTEXT,
        &[],
        None,
        &HMAC_SESSION.to_be_bytes(),
    ));
    s.ours.clear();
    s.theirs.clear();
    assert_eq!(
        both.start_session(
            &mut s,
            SE_HMAC,
            client::SHA256,
            Sym::Null,
            unbound,
            &[7; 32]
        ),
        0
    );
    assert_eq!(
        both.start_session(
            &mut s,
            SE_HMAC,
            client::SHA1,
            Sym::Aes(128),
            unbound,
            &[8; 16]
        ),
        0
    );
    let r = both.same(&sequence_start(b"seq", client::SHA256));
    let handle = u32::from_be_bytes(r[10..14].try_into().unwrap());
    let handles = [handle];
    let p = [tpm2b(b"the end"), RH_ENDORSEMENT.to_be_bytes().to_vec()].concat();
    let auths = vec![
        Auth::session(0, client::CONTINUE, Some(b"seq")),
        Auth::session(
            1,
            client::CONTINUE | client::DECRYPT | client::ENCRYPT,
            None,
        ),
    ];
    let mut cmd = client::Command::new(SEQUENCE_COMPLETE, &handles, &p, auths);
    cmd.names = vec![Vec::new()];
    both.run(&mut s, &cmd);
    // Both ways round, and the decrypting session first.
    let r = both.same(&sequence_start(b"seq", client::SHA256));
    let handle = u32::from_be_bytes(r[10..14].try_into().unwrap());
    let handles = [handle];
    let auths = vec![
        Auth::session(1, client::CONTINUE | client::DECRYPT, Some(b"seq")),
        Auth::session(0, client::CONTINUE, None),
    ];
    let mut cmd = client::Command::new(SEQUENCE_COMPLETE, &handles, &p, auths);
    cmd.names = vec![Vec::new()];
    both.run(&mut s, &cmd);
}

#[test]
fn audit_sessions_match() {
    let mut both = Both::seeded();
    let mut s = Sessions::default();
    let bind = (RH_OWNER, Some(&b""[..]));
    assert_eq!(
        both.start_session(&mut s, SE_HMAC, client::SHA256, Sym::Null, bind, &[5; 16]),
        0
    );
    let audit = |attributes: u8| Auth::Session {
        index: 0,
        attributes: client::CONTINUE | client::AUDIT | attributes,
        entity: None,
        bound: false,
        after: None,
        hmac: None,
    };
    let hash_cmd = |auths| {
        let p = [tpm2b(b"audited"), vec![0, 0x0b, 0x40, 0, 0, 7]].concat();
        client::Command::new(HASH, &[], &p, auths)
    };
    // The first audit makes the session exclusive; it stays so while only it audits.
    let r = both.run(&mut s, &hash_cmd(vec![audit(0)]));
    assert_eq!(
        r.attributes,
        [client::CONTINUE | client::AUDIT | client::AUDIT_EXCLUSIVE]
    );
    both.run(&mut s, &hash_cmd(vec![audit(client::AUDIT_EXCLUSIVE)]));
    // Any command that could have had a session ends the exclusivity.
    both.same(&get_capability(6, 0x100, 1));
    let r = both.run(&mut s, &hash_cmd(vec![audit(0)]));
    assert_eq!(r.attributes, [client::CONTINUE | client::AUDIT]);
    both.same(&get_capability(6, 0x100, 1));
    let r = both.run(&mut s, &hash_cmd(vec![audit(client::AUDIT_EXCLUSIVE)]));
    assert_eq!(r.rc, 0x121, "TPM_RC_EXCLUSIVE");
    both.run(&mut s, &hash_cmd(vec![audit(client::AUDIT_RESET)]));
    both.run(&mut s, &hash_cmd(vec![audit(client::AUDIT_EXCLUSIVE)]));
    // TPM2_Startup and TPM2_FlushContext take no session: they leave it exclusive.
    both.same(&command(
        FLUSH_CONTEXT,
        &[],
        None,
        &0x8000_0000u32.to_be_bytes(),
    ));
    both.run(&mut s, &hash_cmd(vec![audit(client::AUDIT_EXCLUSIVE)]));
    // Auditing an authorization: an audit session is no longer bound.
    let auth = Auth::Session {
        index: 0,
        attributes: client::CONTINUE | client::AUDIT,
        entity: Some(Vec::new()),
        bound: false,
        after: None,
        hmac: None,
    };
    both.run(&mut s, &change_auth_command(RH_OWNER, b"", vec![auth]));
    // Two audit sessions, or one with a password session.
    assert_eq!(
        both.start_session(
            &mut s,
            SE_HMAC,
            client::SHA1,
            Sym::Null,
            (RH_NULL, None),
            &[6; 16]
        ),
        0
    );
    let second = Auth::session(1, client::CONTINUE | client::AUDIT, None);
    both.run(&mut s, &hash_cmd(vec![audit(0), second]));
    both.run(
        &mut s,
        &change_auth_command(RH_OWNER, b"", vec![Auth::Password(vec![]), audit(0)]),
    );
}

#[test]
fn session_handles_and_errors_match() {
    let mut both = Both::started();
    let mut s = Sessions::default();
    let start = |both: &mut Both, s: &mut Sessions, kind, hash, sym, bind, nonce: &[u8]| {
        both.start_session(s, kind, hash, sym, bind, nonce)
    };
    let unbound = (RH_NULL, None);
    // Nonce sizes, session types, hashes, symmetric definitions.
    for (nonce, hash) in [
        (15, client::SHA256),
        (16, client::SHA1),
        (20, client::SHA1),
        (21, client::SHA1),
        (32, client::SHA256),
        (33, client::SHA256),
        (64, client::SHA512),
        (65, client::SHA512),
    ] {
        start(
            &mut both,
            &mut s,
            SE_HMAC,
            hash,
            Sym::Null,
            unbound,
            &vec![9; nonce],
        );
        while s.ours.len() > 1 {
            let h = s.ours.pop().unwrap().handle;
            s.theirs.pop();
            both.same(&command(FLUSH_CONTEXT, &[], None, &h.to_be_bytes()));
        }
    }
    let raw = |kind: u8, sym: &[u8], hash: u16, salt: &[u8], handles: [u32; 2]| {
        let p = [
            tpm2b(&[1; 16]),
            tpm2b(salt),
            vec![kind],
            sym.to_vec(),
            hash.to_be_bytes().to_vec(),
        ]
        .concat();
        command(START_AUTH_SESSION, &handles, None, &p)
    };
    let null = [RH_NULL, RH_NULL];
    for bad in [
        raw(2, &[0, 0x10], 0x0b, b"", null),
        raw(4, &[0, 0x10], 0x0b, b"", null),
        raw(0, &[0, 0x10], 0x10, b"", null),
        raw(0, &[0, 0x10], 0x12, b"", null),
        raw(0, &[0, 0x06, 0, 128, 0, 0x40], 0x0b, b"", null),
        raw(0, &[0, 0x06, 0, 128, 0, 0x10], 0x0b, b"", null),
        raw(0, &[0, 0x06, 0, 128, 0, 0x45], 0x0b, b"", null),
        raw(0, &[0, 0x06, 0, 129, 0, 0x43], 0x0b, b"", null),
        raw(0, &[0, 0x0a, 0, 0x10], 0x0b, b"", null),
        raw(0, &[0, 0x0a, 0, 0x0d], 0x0b, b"", null),
        raw(0, &[0, 0x25], 0x0b, b"", null),
        raw(0, &[0, 0x10], 0x0b, b"salt", null),
        raw(0, &[0, 0x10], 0x0b, &[1; 512], null),
        raw(0, &[0, 0x10], 0x0b, &[1; 513], null),
        raw(0, &[0, 0x10], 0x0b, b"", [0x8000_0000, RH_NULL]),
        raw(0, &[0, 0x10], 0x0b, b"", [0x8100_0000, RH_NULL]),
        raw(0, &[0, 0x10], 0x0b, b"", [RH_OWNER, RH_NULL]),
        raw(0, &[0, 0x10], 0x0b, b"", [RH_NULL, 0x0100_0000]),
        raw(0, &[0, 0x10], 0x0b, b"", [RH_NULL, 0x8100_0000]),
        raw(0, &[0, 0x10], 0x0b, b"", [RH_NULL, 0x4000_0010]),
        raw(0, &[0, 0x10], 0x0b, b"", [RH_NULL, 0x8000_0000]),
        raw(0, &[0, 0x10], 0x0b, b"", [RH_NULL, 24]),
        raw(0, &[0, 0x10], 0x0b, b"", [RH_NULL, RS_PW]),
        command(START_AUTH_SESSION, &null, Some(&password(b"")), &[0; 9]),
    ] {
        let (ours, theirs) = both.both(&bad);
        assert_eq!(ours.len(), theirs.len(), "{}", hex(&bad));
        assert_eq!(ours[..10], theirs[..10], "{}", hex(&bad));
        if rc(&ours) == 0 {
            let h = u32::from_be_bytes(ours[10..14].try_into().unwrap());
            both.same(&command(FLUSH_CONTEXT, &[], None, &h.to_be_bytes()));
        }
    }
    // Bound to a sequence (empty Name) and to a PCR.
    let r = both.same(&sequence_start(b"sq", client::SHA1));
    let seq = u32::from_be_bytes(r[10..14].try_into().unwrap());
    start(
        &mut both,
        &mut s,
        SE_HMAC,
        client::SHA256,
        Sym::Null,
        (seq, Some(b"sq")),
        &[1; 16],
    );
    start(
        &mut both,
        &mut s,
        SE_HMAC,
        client::SHA256,
        Sym::Xor,
        (7, Some(b"")),
        &[1; 16],
    );
    let handles = [seq];
    let mut cmd = client::Command::new(
        SEQUENCE_UPDATE,
        &handles,
        &tpm2b(b"x"),
        vec![Auth::Session {
            index: 1,
            attributes: client::CONTINUE | client::DECRYPT,
            entity: Some(b"sq".to_vec()),
            bound: true,
            after: None,
            hmac: None,
        }],
    );
    cmd.names = vec![Vec::new()];
    both.run(&mut s, &cmd);
    let pcr = [7u32];
    let extend = [1u32.to_be_bytes().to_vec(), vec![0, 4], vec![1; 20]].concat();
    for (index, bound) in [(2, true), (1, false)] {
        let auth = Auth::Session {
            index,
            attributes: client::CONTINUE,
            entity: Some(Vec::new()),
            bound,
            after: None,
            hmac: None,
        };
        both.run(
            &mut s,
            &client::Command::new(PCR_EXTEND, &pcr, &extend, vec![auth]),
        );
    }
    // Every slot taken: TPM_RC_SESSION_MEMORY.
    assert_eq!(
        start(
            &mut both,
            &mut s,
            SE_HMAC,
            client::SHA256,
            Sym::Null,
            unbound,
            &[1; 16]
        ),
        0x903
    );
    both.same(&get_capability(1, HMAC_SESSION, 64));
    both.same(&get_capability(6, 0x203, 4));
    // Sessions misused in an authorization area.
    let session = |index: usize, attributes: u8| Auth::Session {
        index,
        attributes,
        entity: Some(Vec::new()),
        bound: false,
        after: None,
        hmac: None,
    };
    let p = [tpm2b(b"x"), vec![0, 0x0b, 0x40, 0, 0, 7]].concat();
    for auths in [
        vec![session(0, client::CONTINUE | client::DECRYPT)],
        vec![session(0, client::CONTINUE)],
        vec![
            session(2, client::CONTINUE | client::DECRYPT),
            session(2, client::CONTINUE | client::ENCRYPT),
        ],
        vec![
            session(2, client::CONTINUE | client::DECRYPT),
            session(1, client::CONTINUE | client::DECRYPT),
        ],
        vec![
            session(2, client::CONTINUE | client::ENCRYPT),
            session(1, client::CONTINUE | client::ENCRYPT),
        ],
        vec![
            session(2, client::CONTINUE | client::AUDIT),
            session(1, client::CONTINUE | client::AUDIT),
        ],
        vec![Auth::Password(Vec::new())],
    ] {
        let cmd = client::Command::new(HASH, &[], &p, auths);
        both.run(&mut s, &cmd);
    }
    // Policy handles for HMAC sessions, sessions that are not loaded, in the handle area too.
    for handle in [0x0300_0000, 0x0200_0003, 0x0200_0040] {
        let area = session_entry(handle);
        both.same(&command(HASH, &[], Some(&area), &p));
        both.same(&command(FLUSH_CONTEXT, &[], None, &handle.to_be_bytes()));
    }
    // A Startup flushes every session.
    both.same(&command(SHUTDOWN, &[], None, &[0, 1]));
    both.power_cycle();
    both.same(&command(STARTUP, &[], None, &[0, 1]));
    both.same(&get_capability(1, HMAC_SESSION, 64));
    both.same(&get_capability(6, 0x203, 4));
}

/// An authorization-area entry for `handle`, its HMAC empty.
fn session_entry(handle: u32) -> Vec<u8> {
    session(handle, &[0; 16], 1, &[])
}

/// Deterministic mutations of well-formed commands: both must answer the same, wherever the
/// answer does not depend on what vk-tpm does not implement yet.
#[test]
fn mutated_commands_match() {
    let mut both = Both::started();
    let corpus = [
        extend(4, &[(0x04, vec![1; 20]), (0x0b, vec![2; 32])]),
        command(
            PCR_READ,
            &[],
            None,
            &selection(&[(0x04, &[0xff, 0, 0]), (0x0b, &[0, 1, 0x80])]),
        ),
        get_capability(5, 0, 1),
        get_capability(7, 0, 4),
        get_capability(1, 0x4000_0000, 3),
        command(SELF_TEST, &[], None, &[1]),
        command(SHUTDOWN, &[], None, &[0, 0]),
    ];
    // xorshift: a fixed seed, so a failure reproduces.
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut compared = 0;
    for _ in 0..50_000 {
        let mut c = corpus[(next() % corpus.len() as u64) as usize].clone();
        for _ in 0..1 + next() % 3 {
            let at = (next() % c.len() as u64) as usize;
            c[at] ^= 1 << (next() % 8);
        }
        let (ours, theirs) = both.both(&c);
        let code = c
            .get(6..10)
            .map(|b| u32::from_be_bytes(b.try_into().unwrap()));
        // A command code libtpms implements and vk-tpm does not yet: a different answer.
        let ours_unknown = rc(&ours) == 0x143 && rc(&theirs) != 0x143;
        // GetCapability for a capability vk-tpm reports differently (or not yet).
        let capability = c.get(c.len().saturating_sub(12)..c.len().saturating_sub(8));
        let other_capability =
            code == Some(GET_CAPABILITY) && !matches!(capability, Some([0, 0, 0, 1 | 5 | 7]));
        if ours_unknown || other_capability {
            continue;
        }
        assert_eq!(hex(&ours), hex(&theirs), "command {}", hex(&c));
        compared += 1;
    }
    assert!(compared > 25_000, "only {compared} compared");
}
