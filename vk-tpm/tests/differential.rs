//! Differential tests: the same commands to vk-tpm and to libtpms (the engine it replaces),
//! compared byte for byte where the TPM is deterministic, and by shape where it is not (random
//! bytes) or where vk-tpm deliberately differs (its identity, what it does not implement yet).
//!
//! Needs libtpms: `cargo test -p vk-tpm --features libtpms --test differential` with VK_LIBTPMS_DIR set (the build
//! image has it at /opt/tpm).

#![cfg(feature = "libtpms")]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod libtpms;

use libtpms::LibTpms;
use vk_tpm::Tpm;

const SELF_TEST: u32 = 0x143;
const STARTUP: u32 = 0x144;
const SHUTDOWN: u32 = 0x145;
const GET_CAPABILITY: u32 = 0x17a;
const GET_RANDOM: u32 = 0x17b;
const PCR_READ: u32 = 0x17e;
const PCR_EXTEND: u32 = 0x182;

const RS_PW: u32 = 0x4000_0009;
const RH_NULL: u32 = 0x4000_0007;
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
