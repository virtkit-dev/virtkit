//! Platform Configuration Registers: 24 per bank, one bank per hash algorithm, with the PC
//! Client attributes (which PCR a locality may extend or reset, which survive a resume).

use crate::alg::Hash;
use crate::marshal::{Reader, Writer};
use crate::rc::{Rc, Result};

pub const PCR_COUNT: usize = 24;
/// Bytes in a PCR bitmap (TPMS_PCR_SELECTION.sizeofSelect): both its minimum and maximum.
pub const PCR_SELECT: usize = PCR_COUNT / 8;
/// TPM_RH_NULL, which TPM2_PCR_Extend takes as "extend nothing".
pub const TPM_RH_NULL: u32 = 0x4000_0007;
/// A PCR read returns at most this many digests (TPML_DIGEST); the selection says which.
const MAX_READ: usize = 8;

/// What the PC Client profile says of one PCR.
struct Attributes {
    /// Saved by TPM2_Shutdown(STATE) and restored by the TPM2_Startup(STATE) after it.
    state_save: bool,
    /// Changes to it leave the PCR update counter alone (the "TCB group").
    no_increment: bool,
    /// The localities (bit n: locality n) that may reset it; locality 4 marks a DRTM PCR.
    reset: u8,
    /// The localities that may extend it.
    extend: u8,
}

const fn static_rtm() -> Attributes {
    Attributes {
        state_save: true,
        no_increment: false,
        reset: 0,
        extend: 0x1f,
    }
}

const fn dynamic(no_increment: bool, reset: u8, extend: u8) -> Attributes {
    Attributes {
        state_save: false,
        no_increment,
        reset,
        extend,
    }
}

/// Exactly libtpms' table (and so swtpm's, which Windows guests know): PCRs 0-15 for the static
/// root of trust, 16 debug, 17-22 DRTM, 23 application.
const ATTRIBUTES: [Attributes; PCR_COUNT] = [
    static_rtm(),
    static_rtm(),
    static_rtm(),
    static_rtm(),
    static_rtm(),
    static_rtm(),
    static_rtm(),
    static_rtm(),
    static_rtm(),
    static_rtm(),
    static_rtm(),
    static_rtm(),
    static_rtm(),
    static_rtm(),
    static_rtm(),
    static_rtm(),
    dynamic(true, 0x0f, 0x1f),
    dynamic(false, 0x10, 0x1c),
    dynamic(false, 0x10, 0x1c),
    dynamic(false, 0x10, 0x0c),
    dynamic(false, 0x1c, 0x0e),
    dynamic(true, 0x1c, 0x04),
    dynamic(true, 0x1c, 0x04),
    dynamic(true, 0x0f, 0x1f),
];

fn attributes(pcr: usize) -> Option<&'static Attributes> {
    ATTRIBUTES.get(pcr)
}

/// A TPMS_PCR_SELECTION: some PCRs of one bank.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    pub hash: Hash,
    pub select: [u8; PCR_SELECT],
}

impl Selection {
    pub fn read(r: &mut Reader) -> Result<Selection> {
        let hash = Hash::read(r)?;
        if usize::from(r.u8()?) != PCR_SELECT {
            return Err(Rc::VALUE);
        }
        let mut select = [0; PCR_SELECT];
        select.copy_from_slice(r.bytes(PCR_SELECT)?);
        Ok(Selection { hash, select })
    }

    pub fn write(&self, w: &mut Writer) {
        w.u16(self.hash.id())
            .u8(PCR_SELECT as u8)
            .bytes(&self.select);
    }

    /// Every PCR of the bank, or none.
    pub fn all(hash: Hash, on: bool) -> Selection {
        let byte = if on { 0xff } else { 0 };
        Selection {
            hash,
            select: [byte; PCR_SELECT],
        }
    }

    pub fn has(&self, pcr: usize) -> bool {
        self.select
            .get(pcr / 8)
            .is_some_and(|byte| byte & (1 << (pcr % 8)) != 0)
    }

    fn set(&mut self, pcr: usize, on: bool) {
        if let Some(byte) = self.select.get_mut(pcr / 8) {
            let bit = 1 << (pcr % 8);
            if on {
                *byte |= bit;
            } else {
                *byte &= !bit;
            }
        }
    }
}

/// A TPML_PCR_SELECTION: one selection per bank at most.
pub fn read_selections(r: &mut Reader) -> Result<Vec<Selection>> {
    let count = r.count(Hash::ALL.len())?;
    (0..count).map(|_| Selection::read(r)).collect()
}

pub fn write_selections(w: &mut Writer, selections: &[Selection]) {
    w.count(selections.len());
    for s in selections {
        s.write(w);
    }
}

/// Which of the PCRs Startup brings back.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Startup {
    /// TPM Reset: every PCR to its initial value, the update counter to zero.
    Reset,
    /// TPM Restart (Shutdown(STATE), then Startup(CLEAR)): as a reset, but the counter goes on.
    Restart,
    /// TPM Resume (Shutdown(STATE), then Startup(STATE)): the saved PCRs come back.
    Resume,
}

/// PCR values per bank.
pub type Banks = Vec<(Hash, Vec<Vec<u8>>)>;

/// The PCRs TPM2_Shutdown(STATE) saved, for the next Startup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Saved {
    pub counter: u32,
    /// Per bank, the values of the state-saved PCRs.
    pub banks: Banks,
}

/// One bank's PCRs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bank {
    pub hash: Hash,
    pub values: Vec<Vec<u8>>,
}

/// Every bank's PCRs, and the update counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pcrs {
    pub banks: Vec<Bank>,
    pub counter: u32,
}

impl Pcrs {
    /// The PCRs before a Startup: every bank the TPM implements, zeroed.
    pub fn new() -> Pcrs {
        let banks = Hash::ALL
            .into_iter()
            .map(|hash| Bank {
                hash,
                values: vec![vec![0; hash.size()]; PCR_COUNT],
            })
            .collect();
        Pcrs { banks, counter: 0 }
    }

    /// Initialize the PCRs for `kind` of startup, from `saved` for a restart or resume.
    pub fn startup(&mut self, kind: Startup, saved: Option<&Saved>) {
        self.counter = match (kind, saved) {
            (Startup::Restart | Startup::Resume, Some(saved)) => saved.counter,
            _ => 0,
        };
        for bank in &mut self.banks {
            let saved = saved
                .filter(|_| kind == Startup::Resume)
                .and_then(|s| s.banks.iter().find(|(h, _)| *h == bank.hash))
                .map(|(_, values)| values);
            let mut saved = saved.into_iter().flatten();
            for (pcr, value) in bank.values.iter_mut().enumerate() {
                let Some(attributes) = attributes(pcr) else {
                    continue;
                };
                if attributes.state_save
                    && let Some(old) = saved.next()
                {
                    value.clone_from(old);
                    continue;
                }
                // A DRTM PCR (resettable from locality 4) starts as all ones, others as zeros;
                // PCR 0 would end in the startup locality, always 0 here.
                let initial = if attributes.reset & 0x10 != 0 {
                    0xff
                } else {
                    0
                };
                value.fill(initial);
            }
        }
        // Each PCR that was not restored counts as a change, once (not once per bank).
        for (pcr, attributes) in ATTRIBUTES.iter().enumerate() {
            let restored = kind == Startup::Resume && attributes.state_save;
            if !restored {
                self.changed(pcr);
            }
        }
    }

    /// What TPM2_Shutdown(STATE) keeps: the state-saved PCRs of every bank, and the counter.
    pub fn save(&self) -> Saved {
        let banks = self
            .banks
            .iter()
            .map(|bank| {
                let values = bank
                    .values
                    .iter()
                    .zip(&ATTRIBUTES)
                    .filter(|(_, a)| a.state_save)
                    .map(|(v, _)| v.clone())
                    .collect();
                (bank.hash, values)
            })
            .collect();
        Saved {
            counter: self.counter,
            banks,
        }
    }

    fn changed(&mut self, pcr: usize) {
        let no_increment = attributes(pcr).is_some_and(|a| a.no_increment);
        // PCR 0 always counts (TPM2_Clear signals a change through it).
        if pcr == 0 || !no_increment {
            self.counter = self.counter.wrapping_add(1);
        }
    }

    /// PCR `pcr` of bank `hash` := H(PCR || digest), if `allocation` has it.
    pub fn extend(&mut self, allocation: &[Selection], pcr: usize, hash: Hash, digest: &[u8]) {
        if !is_allocated(allocation, hash, pcr) {
            return;
        }
        let Some(value) = self
            .banks
            .iter_mut()
            .find(|b| b.hash == hash)
            .and_then(|b| b.values.get_mut(pcr))
        else {
            return;
        };
        *value = hash.digest(&[value, digest]);
        self.changed(pcr);
    }

    /// TPM2_PCR_Read: the selected PCRs that are allocated, up to [`MAX_READ`] of them, and the
    /// selection trimmed to the ones returned.
    pub fn read(
        &self,
        allocation: &[Selection],
        selections: &[Selection],
    ) -> (Vec<Selection>, Vec<Vec<u8>>) {
        let mut digests = Vec::new();
        let mut out = Vec::with_capacity(selections.len());
        for selection in selections {
            let mut returned = Selection::all(selection.hash, false);
            for pcr in 0..PCR_COUNT {
                if !selection.has(pcr) || !is_allocated(allocation, selection.hash, pcr) {
                    continue;
                }
                let value = self
                    .banks
                    .iter()
                    .find(|b| b.hash == selection.hash)
                    .and_then(|b| b.values.get(pcr));
                if let Some(value) = value
                    && digests.len() < MAX_READ
                {
                    digests.push(value.clone());
                    returned.set(pcr, true);
                }
            }
            out.push(returned);
        }
        (out, digests)
    }
}

fn is_allocated(allocation: &[Selection], hash: Hash, pcr: usize) -> bool {
    allocation
        .iter()
        .find(|s| s.hash == hash)
        .is_some_and(|s| s.has(pcr))
}

/// The PCR (as a handle number) is extendable from `locality`.
pub fn may_extend(pcr: usize, locality: u8) -> bool {
    attributes(pcr).is_some_and(|a| a.extend & (1 << locality) != 0)
}

/// The PCR is saved by TPM2_Shutdown(STATE).
pub fn is_state_saved(pcr: usize) -> bool {
    attributes(pcr).is_some_and(|a| a.state_save)
}

/// TPM_PT_PCR: the properties TPM_CAP_PCR_PROPERTIES reports, in order, each with the PCRs
/// that have it.
pub fn properties() -> Vec<(u32, [u8; PCR_SELECT])> {
    let has = |f: &dyn Fn(&Attributes) -> bool| {
        let mut s = Selection::all(Hash::Sha1, false);
        for (pcr, a) in ATTRIBUTES.iter().enumerate() {
            s.set(pcr, f(a));
        }
        s.select
    };
    let extend = |l: u8| has(&|a| a.extend & (1 << l) != 0);
    let reset = |l: u8| has(&|a| a.reset & (1 << l) != 0);
    vec![
        (0x00, has(&|a| a.state_save)), // TPM_PT_PCR_SAVE
        (0x01, extend(0)),              // TPM_PT_PCR_EXTEND_L0
        (0x02, reset(0)),               // TPM_PT_PCR_RESET_L0
        (0x03, extend(1)),
        (0x04, reset(1)),
        (0x05, extend(2)),
        (0x06, reset(2)),
        (0x07, extend(3)),
        (0x08, reset(3)),
        (0x09, extend(4)),
        (0x0a, reset(4)),
        (0x11, has(&|a| a.no_increment)), // TPM_PT_PCR_NO_INCREMENT
        (0x12, reset(4)),                 // TPM_PT_PCR_DRTM_RESET
        // TPM_PT_PCR_POLICY, TPM_PT_PCR_AUTH: no PCR has a policy or authValue of its own.
        (0x13, has(&|_| false)),
        (0x14, has(&|_| false)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_bank() -> Vec<Selection> {
        Hash::ALL
            .into_iter()
            .map(|h| Selection::all(h, true))
            .collect()
    }

    #[test]
    fn startup_initializes_and_counts_like_the_pc_client_profile() {
        let mut pcrs = Pcrs::new();
        pcrs.startup(Startup::Reset, None);
        // PCRs 0-15 and 17-20 count; the TCB group (16, 21-23) does not.
        assert_eq!(pcrs.counter, 20);
        let sha256 = &pcrs.banks[1];
        assert_eq!(sha256.values[0], vec![0; 32]);
        assert_eq!(sha256.values[17], vec![0xff; 32]);
        assert_eq!(sha256.values[23], vec![0; 32]);
    }

    #[test]
    fn extend_hashes_into_allocated_pcrs_only() {
        let all = every_bank();
        let mut pcrs = Pcrs::new();
        pcrs.startup(Startup::Reset, None);
        let digest = Hash::Sha256.digest(&[b"x"]);
        pcrs.extend(&all, 7, Hash::Sha256, &digest);
        assert_eq!(
            pcrs.banks[1].values[7],
            Hash::Sha256.digest(&[&[0; 32], &digest])
        );
        assert_eq!(pcrs.counter, 21);
        pcrs.extend(&all, 16, Hash::Sha256, &digest);
        assert_eq!(pcrs.counter, 21, "PCR 16 is in the TCB group");

        let none = vec![Selection::all(Hash::Sha256, false)];
        let before = pcrs.clone();
        pcrs.extend(&none, 7, Hash::Sha256, &digest);
        assert_eq!(pcrs, before);
    }

    #[test]
    fn resume_restores_saved_pcrs_and_restart_does_not() {
        let all = every_bank();
        let mut pcrs = Pcrs::new();
        pcrs.startup(Startup::Reset, None);
        pcrs.extend(&all, 0, Hash::Sha1, &[1; 20]);
        pcrs.extend(&all, 23, Hash::Sha1, &[1; 20]);
        let extended = pcrs.banks[0].values[0].clone();
        let saved = pcrs.save();

        let mut resumed = Pcrs::new();
        resumed.startup(Startup::Resume, Some(&saved));
        assert_eq!(resumed.banks[0].values[0], extended);
        assert_eq!(resumed.banks[0].values[23], vec![0; 20], "23 is not saved");
        assert_eq!(resumed.counter, saved.counter + 4);

        let mut restarted = Pcrs::new();
        restarted.startup(Startup::Restart, Some(&saved));
        assert_eq!(restarted.banks[0].values[0], vec![0; 20]);
        assert_eq!(restarted.counter, saved.counter + 20);
    }

    #[test]
    fn read_returns_at_most_eight_and_says_which() {
        let mut pcrs = Pcrs::new();
        pcrs.startup(Startup::Reset, None);
        let all = every_bank();
        let ask = vec![
            Selection::all(Hash::Sha1, true),
            Selection::all(Hash::Sha256, true),
        ];
        let (out, digests) = pcrs.read(&all, &ask);
        assert_eq!(digests.len(), 8);
        assert_eq!(out[0].select, [0xff, 0, 0]);
        assert_eq!(out[1].select, [0, 0, 0]);

        let only_sha1 = vec![Selection::all(Hash::Sha1, true)];
        let (out, digests) = pcrs.read(&only_sha1, &ask[1..]);
        assert!(digests.is_empty(), "an unallocated bank reads as nothing");
        assert_eq!(out[0].select, [0, 0, 0]);
    }

    #[test]
    fn properties_match_libtpms() {
        let p = properties();
        let get = |tag| p.iter().find(|(t, _)| *t == tag).unwrap().1;
        assert_eq!(p.len(), 15);
        assert_eq!(get(0x00), [0xff, 0xff, 0x00]);
        assert_eq!(get(0x01), [0xff, 0xff, 0x81]);
        assert_eq!(get(0x02), [0x00, 0x00, 0x81]);
        assert_eq!(get(0x0a), [0x00, 0x00, 0x7e]);
        assert_eq!(get(0x11), [0x00, 0x00, 0xe1]);
    }
}
