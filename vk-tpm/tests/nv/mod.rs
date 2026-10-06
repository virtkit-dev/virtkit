//! Differential tests of NV indices: every type and attribute, their locks and what each kind
//! of Startup does to them, orderly indices across orderly and disorderly power cycles, PIN
//! indices, and the hierarchies they belong to. NV is deterministic: everything compares byte
//! for byte.

use super::*;

pub const NV_UNDEFINE_SPACE_SPECIAL: u32 = 0x11f;
pub const NV_UNDEFINE_SPACE: u32 = 0x122;
pub const NV_DEFINE_SPACE: u32 = 0x12a;
pub const NV_GLOBAL_WRITE_LOCK: u32 = 0x132;
pub const NV_INCREMENT: u32 = 0x134;
pub const NV_SET_BITS: u32 = 0x135;
pub const NV_EXTEND: u32 = 0x136;
pub const NV_WRITE: u32 = 0x137;
pub const NV_WRITE_LOCK: u32 = 0x138;
pub const NV_CHANGE_AUTH: u32 = 0x13b;
pub const NV_READ: u32 = 0x14e;
pub const NV_READ_LOCK: u32 = 0x14f;
pub const NV_READ_PUBLIC: u32 = 0x169;

// TPMA_NV.
pub const PPWRITE: u32 = 1 << 0;
pub const OWNERWRITE: u32 = 1 << 1;
pub const AUTHWRITE: u32 = 1 << 2;
pub const COUNTER: u32 = 1 << 4;
pub const BITS: u32 = 2 << 4;
pub const EXTEND: u32 = 4 << 4;
pub const PIN_FAIL: u32 = 8 << 4;
pub const PIN_PASS: u32 = 9 << 4;
pub const POLICY_DELETE: u32 = 1 << 10;
pub const WRITELOCKED: u32 = 1 << 11;
pub const WRITEALL: u32 = 1 << 12;
pub const WRITEDEFINE: u32 = 1 << 13;
pub const WRITE_STCLEAR: u32 = 1 << 14;
pub const GLOBALLOCK: u32 = 1 << 15;
pub const PPREAD: u32 = 1 << 16;
pub const OWNERREAD: u32 = 1 << 17;
pub const AUTHREAD: u32 = 1 << 18;
pub const NO_DA: u32 = 1 << 25;
pub const ORDERLY: u32 = 1 << 26;
pub const CLEAR_STCLEAR: u32 = 1 << 27;
pub const READLOCKED: u32 = 1 << 28;
pub const WRITTEN: u32 = 1 << 29;
pub const PLATFORMCREATE: u32 = 1 << 30;
pub const READ_STCLEAR: u32 = 1 << 31;

/// Owner and authValue may read and write.
pub const RW: u32 = OWNERWRITE | AUTHWRITE | OWNERREAD | AUTHREAD;

pub const INDEX: u32 = 0x0100_0001;

/// A TPMS_NV_PUBLIC with SHA-256 as its nameAlg.
pub fn nv_public(index: u32, attributes: u32, policy: &[u8], size: u16) -> Vec<u8> {
    nv_public_with(index, client::SHA256, attributes, policy, size)
}

pub fn nv_public_with(index: u32, alg: u16, attributes: u32, policy: &[u8], size: u16) -> Vec<u8> {
    [
        &index.to_be_bytes()[..],
        &alg.to_be_bytes(),
        &attributes.to_be_bytes(),
        &tpm2b(policy),
        &size.to_be_bytes(),
    ]
    .concat()
}

/// TPM2_NV_DefineSpace by `auth` (owner or platform) of `public`, with authValue `pw`.
pub fn define(auth: u32, pw: &[u8], public: &[u8]) -> Vec<u8> {
    with_password(
        NV_DEFINE_SPACE,
        auth,
        b"",
        &[tpm2b(pw), tpm2b(public)].concat(),
    )
}

/// The owner defines an index of `size` bytes, empty authValue, no policy.
pub fn define_owner(index: u32, attributes: u32, size: u16) -> Vec<u8> {
    define(RH_OWNER, b"", &nv_public(index, attributes, b"", size))
}

/// A command on an index, authorized by `auth` (owner, platform or the index) with `pw`.
pub fn nv_command(code: u32, auth: u32, index: u32, pw: &[u8], params: &[u8]) -> Vec<u8> {
    command(code, &[auth, index], Some(&password(pw)), params)
}

pub fn nv_write(auth: u32, index: u32, data: &[u8], offset: u16) -> Vec<u8> {
    let p = [tpm2b(data), offset.to_be_bytes().to_vec()].concat();
    nv_command(NV_WRITE, auth, index, b"", &p)
}

pub fn nv_read(auth: u32, index: u32, size: u16, offset: u16) -> Vec<u8> {
    let p = [size.to_be_bytes(), offset.to_be_bytes()].concat();
    nv_command(NV_READ, auth, index, b"", &p)
}

pub fn read_public(index: u32) -> Vec<u8> {
    command(NV_READ_PUBLIC, &[index], None, &[])
}

pub fn undefine(auth: u32, index: u32) -> Vec<u8> {
    nv_command(NV_UNDEFINE_SPACE, auth, index, b"", &[])
}

/// The NV properties: indices, counters, counters still available.
fn nv_properties(both: &mut Both) {
    both.same(&get_capability(6, 0x202, 1));
    both.same(&get_capability(6, 0x20a, 2));
    both.same(&get_capability(1, 0x0100_0000, 100));
}

#[test]
fn ordinary_indices_match() {
    let mut both = Both::started();
    both.same(&define_owner(INDEX, RW, 32));
    both.same(&read_public(INDEX));
    // Not written yet; then written in part, which zeroes the rest.
    both.same(&nv_read(RH_OWNER, INDEX, 4, 0));
    both.same(&nv_write(INDEX, INDEX, b"hello", 3));
    both.same(&read_public(INDEX));
    both.same(&nv_read(RH_OWNER, INDEX, 32, 0));
    both.same(&nv_read(INDEX, INDEX, 8, 24));
    for (size, offset) in [(1, 32), (0, 32), (2, 31), (1025, 0), (0, 33), (32, 1)] {
        both.same(&nv_read(RH_OWNER, INDEX, size, offset));
        both.same(&nv_write(RH_OWNER, INDEX, &vec![7; size as usize], offset));
    }
    // Who may write and read.
    both.same(&nv_write(RH_PLATFORM, INDEX, b"x", 0));
    both.same(&nv_read(RH_PLATFORM, INDEX, 1, 0));
    both.same(&define_owner(0x0100_0002, OWNERWRITE | OWNERREAD, 4));
    both.same(&nv_write(0x0100_0002, 0x0100_0002, b"x", 0));
    both.same(&nv_read(0x0100_0002, 0x0100_0002, 1, 0));
    both.same(&nv_write(INDEX, 0x0100_0002, b"x", 0));
    // WRITEALL; types that NV_Write does not take.
    both.same(&define_owner(0x0100_0003, RW | WRITEALL, 4));
    both.same(&nv_write(RH_OWNER, 0x0100_0003, b"abc", 0));
    both.same(&nv_write(RH_OWNER, 0x0100_0003, b"abcd", 0));
    both.same(&define_owner(0x0100_0004, RW | COUNTER, 8));
    both.same(&nv_write(RH_OWNER, 0x0100_0004, &[0; 8], 0));
    // Its authValue changes only with the ADMIN role (a policy).
    both.same(&command(
        NV_CHANGE_AUTH,
        &[INDEX],
        Some(&password(b"")),
        &tpm2b(b"new"),
    ));
    nv_properties(&mut both);
    // Delete: the owner may not delete the platform's.
    both.same(&define(
        RH_PLATFORM,
        b"",
        &nv_public(
            0x01c0_0002,
            PLATFORMCREATE | PPWRITE | PPREAD | OWNERREAD,
            b"",
            16,
        ),
    ));
    both.same(&undefine(RH_OWNER, 0x01c0_0002));
    both.same(&undefine(RH_PLATFORM, INDEX));
    both.same(&undefine(RH_PLATFORM, INDEX));
    both.same(&read_public(INDEX));
    both.same(&undefine(RH_PLATFORM, 0x01c0_0002));
    nv_properties(&mut both);
}

#[test]
fn define_space_is_checked_alike() {
    let mut both = Both::started();
    let digest = [5u8; 32];
    for (auth, pw, public) in [
        (RH_OWNER, &b""[..], nv_public(INDEX, RW, &digest[..31], 8)),
        (RH_OWNER, &[1; 33][..], nv_public(INDEX, RW, b"", 8)),
        (RH_OWNER, &[1; 32][..], nv_public(INDEX, RW, b"", 8)),
        (RH_OWNER, b"", nv_public(INDEX, RW | (3 << 4), b"", 8)),
        (RH_OWNER, b"", nv_public(INDEX, RW | (0xf << 4), b"", 8)),
        (RH_OWNER, b"", nv_public(INDEX, RW, b"", 2049)),
        (RH_OWNER, b"", nv_public(INDEX, RW, b"", 2048)),
        (RH_OWNER, b"", nv_public(INDEX, RW | COUNTER, b"", 4)),
        (RH_OWNER, b"", nv_public(INDEX, RW | BITS, b"", 8)),
        (RH_OWNER, b"", nv_public(INDEX, RW | EXTEND, b"", 20)),
        (RH_OWNER, b"", nv_public(INDEX, RW | EXTEND, b"", 32)),
        (
            RH_OWNER,
            b"",
            nv_public(INDEX, RW | COUNTER | CLEAR_STCLEAR, b"", 8),
        ),
        (RH_OWNER, b"", nv_public(INDEX, RW | PIN_FAIL, b"", 8)),
        (
            RH_OWNER,
            b"",
            nv_public(INDEX, OWNERWRITE | AUTHREAD | PIN_FAIL | NO_DA, b"", 8),
        ),
        (RH_OWNER, b"", nv_public(INDEX, RW | PIN_PASS, b"", 8)),
        (
            RH_OWNER,
            b"",
            nv_public(
                INDEX,
                OWNERWRITE | OWNERREAD | PIN_PASS | WRITEDEFINE,
                b"",
                8,
            ),
        ),
        (RH_OWNER, b"", nv_public(INDEX, RW | WRITTEN, b"", 8)),
        (RH_OWNER, b"", nv_public(INDEX, RW | WRITELOCKED, b"", 8)),
        (RH_OWNER, b"", nv_public(INDEX, RW | READLOCKED, b"", 8)),
        (RH_OWNER, b"", nv_public(INDEX, OWNERWRITE, b"", 8)),
        (RH_OWNER, b"", nv_public(INDEX, OWNERREAD, b"", 8)),
        (
            RH_OWNER,
            b"",
            nv_public(INDEX, RW | CLEAR_STCLEAR | WRITEDEFINE, b"", 8),
        ),
        (RH_OWNER, b"", nv_public(INDEX, RW | PLATFORMCREATE, b"", 8)),
        (RH_PLATFORM, b"", nv_public(INDEX, RW, b"", 8)),
        (RH_OWNER, b"", nv_public(INDEX, RW | POLICY_DELETE, b"", 8)),
        (
            RH_PLATFORM,
            b"",
            nv_public(INDEX, RW | POLICY_DELETE | PLATFORMCREATE, &digest, 8),
        ),
        (RH_OWNER, b"", nv_public(INDEX, RW | WRITEALL, b"", 1025)),
        (RH_OWNER, b"", nv_public(INDEX, RW | (1 << 8), b"", 8)),
        (RH_OWNER, b"", nv_public(INDEX, RW | (1 << 20), b"", 8)),
        (RH_OWNER, b"", nv_public(0x0200_0000, RW, b"", 8)),
        (RH_OWNER, b"", nv_public_with(INDEX, 0x10, RW, b"", 8)),
        (
            RH_OWNER,
            b"",
            nv_public_with(INDEX, client::SHA1, RW | EXTEND, b"", 20),
        ),
        (RH_OWNER, b"", nv_public(INDEX, RW, b"", 8)),
    ] {
        both.same(&define(auth, pw, &public));
    }
    // A TPM2B_NV_PUBLIC of the wrong size; an index defined twice; the platform's NV disabled.
    let public = nv_public(0x0100_0005, RW, b"", 8);
    let mut long = tpm2b(&public);
    long[1] += 1;
    long.push(0);
    both.same(&with_password(
        NV_DEFINE_SPACE,
        RH_OWNER,
        b"",
        &[tpm2b(b""), long].concat(),
    ));
    both.same(&define(RH_OWNER, b"", &nv_public(INDEX, RW, b"", 8)));
    both.same(&hierarchy_control(RH_PLATFORM, RH_PLATFORM_NV, 0));
    both.same(&define(
        RH_PLATFORM,
        b"",
        &nv_public(0x0100_0006, RW | PLATFORMCREATE, b"", 8),
    ));
    nv_properties(&mut both);
}

#[test]
fn counters_bits_and_extend_indices_match() {
    let mut both = Both::started();
    both.same(&define_owner(INDEX, RW | COUNTER, 8));
    both.same(&nv_read(RH_OWNER, INDEX, 8, 0));
    for _ in 0..3 {
        both.same(&nv_command(NV_INCREMENT, INDEX, INDEX, b"", &[]));
        both.same(&nv_read(RH_OWNER, INDEX, 8, 0));
    }
    // A new counter starts above every counter deleted.
    both.same(&undefine(RH_OWNER, INDEX));
    both.same(&define_owner(INDEX, RW | COUNTER, 8));
    both.same(&nv_command(NV_INCREMENT, RH_OWNER, INDEX, b"", &[]));
    both.same(&nv_read(RH_OWNER, INDEX, 8, 0));
    both.same(&nv_command(NV_SET_BITS, RH_OWNER, INDEX, b"", &[0; 8]));

    both.same(&define_owner(0x0100_0002, RW | BITS, 8));
    for bits in [0x0100u64, 0x8000_0000_0000_0001, 0] {
        both.same(&nv_command(
            NV_SET_BITS,
            RH_OWNER,
            0x0100_0002,
            b"",
            &bits.to_be_bytes(),
        ));
        both.same(&nv_read(RH_OWNER, 0x0100_0002, 8, 0));
    }
    both.same(&nv_command(NV_INCREMENT, RH_OWNER, 0x0100_0002, b"", &[]));

    for (index, alg, size) in [
        (0x0100_0003, client::SHA256, 32),
        (0x0100_0004, client::SHA1, 20),
        (0x0100_0005, client::SHA384, 48),
    ] {
        both.same(&define(
            RH_OWNER,
            b"",
            &nv_public_with(index, alg, RW | EXTEND, b"", size),
        ));
        for data in [&b"one"[..], b"", &[9; 1024]] {
            both.same(&nv_command(NV_EXTEND, RH_OWNER, index, b"", &tpm2b(data)));
            both.same(&nv_read(RH_OWNER, index, size, 0));
        }
        both.same(&read_public(index));
    }
    both.same(&nv_command(
        NV_EXTEND,
        RH_OWNER,
        0x0100_0002,
        b"",
        &tpm2b(b"x"),
    ));
    nv_properties(&mut both);
}

#[test]
fn locks_match() {
    let mut both = Both::started();
    both.same(&define_owner(INDEX, RW | WRITEDEFINE, 4));
    both.same(&define_owner(
        0x0100_0002,
        RW | WRITE_STCLEAR | READ_STCLEAR,
        4,
    ));
    both.same(&define_owner(0x0100_0003, RW | GLOBALLOCK, 4));
    both.same(&define_owner(0x0100_0004, RW, 4));
    let lock = |code: u32, index: u32| nv_command(code, RH_OWNER, index, b"", &[]);
    // Locking what cannot be; a WRITEDEFINE index not yet written.
    both.same(&lock(NV_WRITE_LOCK, 0x0100_0004));
    both.same(&lock(NV_READ_LOCK, 0x0100_0004));
    both.same(&lock(NV_WRITE_LOCK, INDEX));
    both.same(&nv_write(RH_OWNER, INDEX, b"abcd", 0));
    for index in [INDEX, 0x0100_0002] {
        both.same(&nv_write(RH_OWNER, index, b"abcd", 0));
        both.same(&lock(NV_WRITE_LOCK, index));
        both.same(&lock(NV_WRITE_LOCK, index));
        both.same(&nv_write(RH_OWNER, index, b"efgh", 0));
        both.same(&read_public(index));
    }
    both.same(&lock(NV_READ_LOCK, 0x0100_0002));
    both.same(&lock(NV_READ_LOCK, 0x0100_0002));
    both.same(&nv_read(RH_OWNER, 0x0100_0002, 4, 0));
    both.same(&nv_command(NV_WRITE_LOCK, RH_PLATFORM, INDEX, b"", &[]));
    both.same(&with_password(NV_GLOBAL_WRITE_LOCK, RH_OWNER, b"", &[]));
    both.same(&nv_write(RH_OWNER, 0x0100_0003, b"abcd", 0));
    both.same(&read_public(0x0100_0003));
    // Startup(CLEAR) unlocks all but a written WRITEDEFINE index.
    both.same(&command(SHUTDOWN, &[], None, &[0, 0]));
    both.power_cycle();
    both.same(&command(STARTUP, &[], None, &[0, 0]));
    for index in [INDEX, 0x0100_0002, 0x0100_0003] {
        both.same(&read_public(index));
        both.same(&nv_write(RH_OWNER, index, b"ijkl", 0));
        both.same(&nv_read(RH_OWNER, index, 4, 0));
    }
}

/// Every kind of Startup, after the state it follows: CLEAR_STCLEAR and orderly indices.
#[test]
fn startup_and_orderly_indices_match() {
    let mut both = Both::started();
    let indices = [
        (INDEX, RW | CLEAR_STCLEAR, 4),
        (0x0100_0002, RW | ORDERLY, 4),
        (0x0100_0003, RW | ORDERLY | COUNTER, 8),
        (0x0100_0004, RW | ORDERLY | CLEAR_STCLEAR | WRITE_STCLEAR, 4),
        (0x0100_0005, RW | ORDERLY | BITS, 8),
        (0x0100_0006, RW | COUNTER, 8),
    ];
    for (index, attributes, size) in indices {
        both.same(&define_owner(index, attributes, size));
    }
    let write_all = |both: &mut Both| {
        for (index, attributes, _) in indices {
            if attributes & COUNTER != 0 {
                both.same(&nv_command(NV_INCREMENT, RH_OWNER, index, b"", &[]));
            } else if attributes & BITS != 0 {
                both.same(&nv_command(NV_SET_BITS, RH_OWNER, index, b"", &[1; 8]));
            } else {
                both.same(&nv_write(RH_OWNER, index, b"data", 0));
            }
        }
    };
    let read_all = |both: &mut Both| {
        for (index, _, size) in indices {
            both.same(&read_public(index));
            both.same(&nv_read(RH_OWNER, index, size, 0));
        }
        both.same(&get_capability(6, 0x200, 2));
    };
    write_all(&mut both);
    both.same(&nv_command(NV_WRITE_LOCK, RH_OWNER, 0x0100_0004, b"", &[]));
    for (shutdown, startup) in [
        (Some(1), 1), // resume
        (Some(1), 0), // restart
        (Some(0), 0), // reset
        (None, 0),    // power lost
    ] {
        write_all(&mut both);
        if let Some(kind) = shutdown {
            both.same(&command(SHUTDOWN, &[], None, &[0, kind]));
        }
        both.power_cycle();
        both.same(&command(STARTUP, &[], None, &[0, startup]));
        read_all(&mut both);
    }
    // An orderly counter goes past what it may have reported before power was lost, even many
    // times; and it is stored as it crosses each boundary.
    for _ in 0..300 {
        both.same(&nv_command(NV_INCREMENT, RH_OWNER, 0x0100_0003, b"", &[]));
    }
    both.power_cycle();
    both.same(&command(STARTUP, &[], None, &[0, 0]));
    read_all(&mut both);
    // Writing an orderly index voids an orderly shutdown recorded since.
    both.same(&command(SHUTDOWN, &[], None, &[0, 1]));
    both.same(&nv_write(RH_OWNER, 0x0100_0002, b"late", 0));
    both.power_cycle();
    both.same(&command(STARTUP, &[], None, &[0, 1]));
    both.same(&command(STARTUP, &[], None, &[0, 0]));
    read_all(&mut both);
}

#[test]
fn orderly_ram_runs_out_alike() {
    let mut both = Both::started();
    // 512 bytes of RAM, a 12-byte header each.
    for (i, size) in [100u16, 200, 150, 14, 1].into_iter().enumerate() {
        both.same(&define_owner(0x0100_0010 + i as u32, RW | ORDERLY, size));
        nv_properties(&mut both);
    }
    both.same(&define_owner(0x0100_0020, RW | ORDERLY | COUNTER, 8));
    both.same(&undefine(RH_OWNER, 0x0100_0011));
    both.same(&define_owner(0x0100_0020, RW | ORDERLY | COUNTER, 8));
    both.same(&define_owner(0x0100_0021, RW | ORDERLY, 180));
    nv_properties(&mut both);
}

#[test]
fn pin_indices_match() {
    let mut both = Both::started();
    let pin = |count: u32, limit: u32| [count.to_be_bytes(), limit.to_be_bytes()].concat();
    both.same(&define(
        RH_OWNER,
        b"pin",
        &nv_public(
            INDEX,
            OWNERWRITE | OWNERREAD | AUTHREAD | PIN_FAIL | NO_DA,
            b"",
            8,
        ),
    ));
    both.same(&define(
        RH_OWNER,
        b"pass",
        &nv_public(
            0x0100_0002,
            OWNERWRITE | OWNERREAD | AUTHREAD | PIN_PASS,
            b"",
            8,
        ),
    ));
    let read_with = |index: u32, pw: &[u8]| nv_command(NV_READ, index, index, pw, &[0, 8, 0, 0]);
    // Not written: no authValue.
    both.same(&read_with(INDEX, b"pin"));
    both.same(&nv_write(RH_OWNER, INDEX, &pin(0, 2), 0));
    both.same(&nv_write(RH_OWNER, 0x0100_0002, &pin(0, 2), 0));
    for pw in [
        &b"pin"[..],
        b"bad",
        b"bad",
        b"pin",
        b"bad",
        b"bad",
        b"bad",
        b"pin",
    ] {
        both.same(&read_with(INDEX, pw));
        both.same(&nv_read(RH_OWNER, INDEX, 8, 0));
    }
    for pw in [&b"pass"[..], b"bad", b"pass", b"pass"] {
        both.same(&read_with(0x0100_0002, pw));
        both.same(&nv_read(RH_OWNER, 0x0100_0002, 8, 0));
    }
    // No session may bind to a PIN index.
    let p = [tpm2b(&[1; 16]), tpm2b(b""), vec![0, 0, 0x10, 0, 0x0b]].concat();
    both.same(&command(START_AUTH_SESSION, &[RH_NULL, INDEX], None, &p));
    read_hierarchy_state(&mut both);
}

#[test]
fn authorization_and_dictionary_attacks_on_indices_match() {
    let mut both = Both::started();
    both.same(&define(RH_OWNER, b"pw", &nv_public(INDEX, RW, b"", 8)));
    both.same(&define(
        RH_OWNER,
        b"pw",
        &nv_public(0x0100_0002, RW | NO_DA, b"", 8),
    ));
    for index in [INDEX, 0x0100_0002] {
        both.same(&nv_command(
            NV_WRITE,
            index,
            index,
            b"bad",
            &[tpm2b(b"x"), vec![0, 0]].concat(),
        ));
        both.same(&nv_command(
            NV_WRITE,
            index,
            index,
            b"pw\0",
            &[tpm2b(b"x"), vec![0, 0]].concat(),
        ));
        read_hierarchy_state(&mut both);
    }
    // An HMAC session: the index's Name, as it is now, is in the cpHash.
    let mut sessions = Sessions::default();
    let start = both.start_session(
        &mut sessions,
        SE_HMAC,
        client::SHA256,
        Sym::Aes(128),
        (RH_NULL, None),
        &[3; 16],
    );
    assert_eq!(start, 0);
    let name = objects::params(&both.same(&read_public(INDEX)), false);
    let (_, rest) = objects::split2b(&name);
    let name = objects::split2b(rest).0;
    let mut cmd = client::Command::new(
        NV_WRITE,
        &[INDEX, INDEX],
        &[tpm2b(b"secret"), vec![0, 0]].concat(),
        vec![Auth::session(
            0,
            client::CONTINUE | client::DECRYPT,
            Some(b"pw"),
        )],
    );
    cmd.names = vec![name.clone(), name];
    both.run(&mut sessions, &cmd);
    both.same(&nv_read(RH_OWNER, INDEX, 6, 0));
    // A session bound to the index.
    let start = both.start_session(
        &mut sessions,
        SE_HMAC,
        client::SHA256,
        Sym::Null,
        (INDEX, Some(b"pw")),
        &[4; 16],
    );
    assert_eq!(start, 0);
    let name = objects::params(&both.same(&read_public(INDEX)), false);
    let (_, rest) = objects::split2b(&name);
    let name = objects::split2b(rest).0;
    let mut cmd = client::Command::new(
        NV_READ,
        &[INDEX, INDEX],
        &[0, 6, 0, 0],
        vec![Auth::Session {
            index: 1,
            attributes: client::CONTINUE,
            entity: Some(b"pw".to_vec()),
            bound: true,
            after: None,
            hmac: None,
        }],
    );
    cmd.names = vec![name.clone(), name];
    both.run(&mut sessions, &cmd);
}

#[test]
fn hierarchies_and_clear_affect_indices_alike() {
    let mut both = Both::started();
    both.same(&define_owner(INDEX, RW, 4));
    both.same(&define_owner(0x0100_0002, RW | COUNTER, 8));
    both.same(&nv_command(NV_INCREMENT, RH_OWNER, 0x0100_0002, b"", &[]));
    both.same(&define(
        RH_PLATFORM,
        b"",
        &nv_public(
            0x01c0_0002,
            PLATFORMCREATE | PPWRITE | PPREAD | OWNERREAD | AUTHREAD,
            b"",
            4,
        ),
    ));
    both.same(&nv_write(RH_PLATFORM, 0x01c0_0002, b"cert", 0));
    // The owner's hierarchy disabled: its indices are not there.
    both.same(&hierarchy_control(RH_OWNER, RH_OWNER, 0));
    both.same(&read_public(INDEX));
    both.same(&read_public(0x01c0_0002));
    both.same(&nv_read(RH_PLATFORM, 0x01c0_0002, 4, 0));
    both.same(&hierarchy_control(RH_PLATFORM, RH_OWNER, 1));
    both.same(&hierarchy_control(RH_PLATFORM, RH_PLATFORM_NV, 0));
    both.same(&read_public(INDEX));
    both.same(&read_public(0x01c0_0002));
    both.same(&hierarchy_control(RH_PLATFORM, RH_PLATFORM_NV, 1));
    // TPM2_Clear deletes the owner's; the next counter starts above the one deleted.
    both.same(&clear(RH_PLATFORM));
    nv_properties(&mut both);
    both.same(&read_public(0x01c0_0002));
    both.same(&define_owner(0x0100_0002, RW | COUNTER, 8));
    both.same(&nv_command(NV_INCREMENT, RH_OWNER, 0x0100_0002, b"", &[]));
    both.same(&nv_read(RH_OWNER, 0x0100_0002, 8, 0));
}

/// The NV commands the mutation pass starts from.
pub fn mutation_corpus() -> Vec<Vec<u8>> {
    vec![
        define_owner(INDEX, RW, 16),
        define_owner(0x0100_0002, RW | COUNTER | ORDERLY, 8),
        define_owner(0x0100_0003, RW | EXTEND | WRITE_STCLEAR, 32),
        define(
            RH_PLATFORM,
            b"pw",
            &nv_public(
                0x0100_0004,
                RW | PLATFORMCREATE | POLICY_DELETE,
                &[1; 32],
                8,
            ),
        ),
        nv_write(INDEX, INDEX, b"data", 2),
        nv_read(RH_OWNER, INDEX, 4, 2),
        read_public(INDEX),
        nv_command(NV_INCREMENT, RH_OWNER, 0x0100_0002, b"", &[]),
        nv_command(NV_EXTEND, RH_OWNER, 0x0100_0003, b"", &tpm2b(b"x")),
        nv_command(
            NV_SET_BITS,
            RH_OWNER,
            0x0100_0002,
            b"",
            &[0, 0, 0, 0, 0, 0, 1, 0],
        ),
        nv_command(NV_WRITE_LOCK, RH_OWNER, 0x0100_0003, b"", &[]),
        nv_command(NV_READ_LOCK, INDEX, INDEX, b"", &[]),
        with_password(NV_GLOBAL_WRITE_LOCK, RH_OWNER, b"", &[]),
        command(NV_CHANGE_AUTH, &[INDEX], Some(&password(b"")), &tpm2b(b"a")),
        undefine(RH_OWNER, INDEX),
        command(
            NV_UNDEFINE_SPACE_SPECIAL,
            &[0x0100_0004, RH_PLATFORM],
            Some(&[password(b""), password(b"")].concat()),
            &[],
        ),
        get_capability(1, 0x0100_0000, 8),
    ]
}
