// SPDX-License-Identifier: Apache-2.0
//
// Minimal ACPI fixed-hardware register block for x86_64 guests, served on the
// PIO bus at `ACPI_PM_BASE`. It implements just enough of the ACPI PM model for:
//   - power-off: a guest write of SLP_TYP=S5 | SLP_EN to PM1a_CNT fires the Vmm
//     exit event (clean exit, code 0);
//   - reset: a guest write of the reset value to the FADT reset register sets the
//     shared reset flag and fires the exit event (reported as a guest reset);
//   - power button: the host writes `shutdown_efd`, which latches PWRBTN_STS and,
//     if the guest enabled it, raises the SCI so the guest's fixed-feature power
//     button driver runs an orderly shutdown.
//
// It also serves the ACPI PM timer: a free-running 32-bit counter at 3.579545 MHz, which
// UEFI firmware and Windows use for their delays and calibration. And a GPE0 block, whose only
// event is the host's: a new VM generation ID after a restore (`raise_gpe`), as QEMU's vmgenid.
// SCI_EN reads back as 1 (the system is always in ACPI mode: FADT SMI_CMD is 0), so the
// guest never tries to enable it.

use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};
use utils::eventfd::EventFd;

use arch::x86_64::layout::{
    ACPI_GPE0_BLK, ACPI_GPE0_BLK_LEN, ACPI_PM_BASE, ACPI_RESET_REG, ACPI_RESET_VALUE,
};

use crate::bus::BusDevice;

// Register offsets from the device base (ACPI_PM_BASE). PM1a_EVT (STS at +0, EN at
// +2) and PM1a_CNT (+4) decompose the PM block whose base and reset register live in
// arch::x86_64::layout and feed the FADT, so the reset offset/value are taken from
// there rather than re-hardcoded (so a layout change cannot desync the FADT from
// this device).
const PM1_STS: u64 = 0x00; // 2 bytes
const PM1_EN: u64 = 0x02; // 2 bytes
const PM1_CNT: u64 = 0x04; // 2 bytes
const PM_TMR: u64 = 0x08; // 4 bytes, read-only
/// The ACPI PM timer's fixed frequency (ACPI 6.x § 4.8.3.3).
const PM_TIMER_HZ: u128 = 3_579_545;
const RESET_REG: u64 = (ACPI_RESET_REG - ACPI_PM_BASE) as u64; // 1 byte
/// GPE0_STS then GPE0_EN, each half the block; byte-addressable, as GPE registers are.
const GPE0_STS: u64 = (ACPI_GPE0_BLK - ACPI_PM_BASE) as u64;
const GPE0_EN: u64 = GPE0_STS + ACPI_GPE0_BLK_LEN as u64 / 2;
const GPE0_END: u64 = GPE0_STS + ACPI_GPE0_BLK_LEN as u64;

// PM1 status/enable: only the power-button bit is modelled.
const PWRBTN: u16 = 1 << 8;
// PM1 control.
const SCI_EN: u16 = 1 << 0;
const SLP_EN: u16 = 1 << 13;
const SLP_TYP_SHIFT: u16 = 10;
const SLP_TYP_MASK: u16 = 0x7;
const S5_SLP_TYP: u16 = 5;

/// Value the guest writes to the reset register (matches FADT `reset_value`).
const RESET_VALUE: u8 = ACPI_RESET_VALUE;

pub struct AcpiPm {
    pm1_sts: u16,
    pm1_en: u16,
    gpe0_sts: u16,
    gpe0_en: u16,
    /// The Vmm exit event: written to end the VM (power-off or reset).
    exit_evt: EventFd,
    /// Set (before firing `exit_evt`) when the exit is a reset, so the Vmm reports
    /// a guest reset rather than a clean power-off.
    reset_flag: Arc<AtomicBool>,
    /// Raises the ACPI SCI (registered as an irqfd on `SCI_GSI`).
    sci_evt: EventFd,
    /// Host-side power-button trigger. `None` when the host exposes no button.
    shutdown_efd: Option<EventFd>,
    /// The PM timer counts from here.
    timer_start: Instant,
}

/// [`AcpiPm::save_state`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "snapshot", derive(serde::Serialize, serde::Deserialize))]
pub struct AcpiPmState {
    pub pm1_sts: u16,
    pub pm1_en: u16,
    pub gpe0_sts: u16,
    pub gpe0_en: u16,
    pub timer_ns: u64,
}

impl AcpiPm {
    /// What a snapshot keeps: the PM1 and GPE0 status and enable registers (the power
    /// button's and the VM generation ID's enables among them) and how far the PM timer had
    /// counted (local patch).
    pub fn save_state(&self) -> AcpiPmState {
        AcpiPmState {
            pm1_sts: self.pm1_sts,
            pm1_en: self.pm1_en,
            gpe0_sts: self.gpe0_sts,
            gpe0_en: self.gpe0_en,
            timer_ns: self.timer_start.elapsed().as_nanos() as u64,
        }
    }

    /// Put back what [`AcpiPm::save_state`] returned: the timer carries on from its count.
    pub fn restore_state(&mut self, state: &AcpiPmState) {
        self.pm1_sts = state.pm1_sts;
        self.pm1_en = state.pm1_en;
        self.gpe0_sts = state.gpe0_sts;
        self.gpe0_en = state.gpe0_en;
        self.timer_start = Instant::now()
            .checked_sub(std::time::Duration::from_nanos(state.timer_ns))
            .unwrap_or_else(Instant::now);
    }

    pub fn new(
        exit_evt: EventFd,
        reset_flag: Arc<AtomicBool>,
        sci_evt: EventFd,
        shutdown_efd: Option<EventFd>,
    ) -> Self {
        AcpiPm {
            pm1_sts: 0,
            pm1_en: 0,
            gpe0_sts: 0,
            gpe0_en: 0,
            exit_evt,
            reset_flag,
            sci_evt,
            shutdown_efd,
            timer_start: Instant::now(),
        }
    }

    /// The PM timer's current value: ticks of 3.579545 MHz since the device was created,
    /// wrapping at 32 bits (the FADT sets TMR_VAL_EXT).
    fn pm_timer(&self) -> u32 {
        (self.timer_start.elapsed().as_nanos() * PM_TIMER_HZ / 1_000_000_000) as u32
    }

    /// Latch general-purpose event `gpe` and raise the SCI if the guest enabled it.
    pub fn raise_gpe(&mut self, gpe: u8) {
        self.gpe0_sts |= 1 << gpe;
        self.raise_sci_if_pending();
    }

    fn raise_sci_if_pending(&self) {
        let pending = self.pm1_sts & self.pm1_en & PWRBTN != 0 || self.gpe0_sts & self.gpe0_en != 0;
        if pending && let Err(e) = self.sci_evt.write(1) {
            error!("acpi_pm: failed to raise SCI: {e:?}");
        }
    }

    fn fire_exit(&self, reset: bool) {
        if reset {
            self.reset_flag.store(true, Ordering::SeqCst);
        }
        if let Err(e) = self.exit_evt.write(1) {
            error!("acpi_pm: failed to fire exit event: {e:?}");
        }
    }
}

impl BusDevice for AcpiPm {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        if (PM_TMR..PM_TMR + 4).contains(&offset) {
            let bytes = self.pm_timer().to_le_bytes();
            let start = (offset - PM_TMR) as usize;
            for (i, b) in data.iter_mut().enumerate() {
                *b = bytes.get(start + i).copied().unwrap_or(0);
            }
            return;
        }
        if (GPE0_STS..GPE0_END).contains(&offset) {
            let [s0, s1] = self.gpe0_sts.to_le_bytes();
            let [e0, e1] = self.gpe0_en.to_le_bytes();
            let block = [s0, s1, e0, e1];
            let start = (offset - GPE0_STS) as usize;
            for (i, b) in data.iter_mut().enumerate() {
                *b = block.get(start + i).copied().unwrap_or(0);
            }
            return;
        }
        let val: u16 = match offset {
            PM1_STS => self.pm1_sts,
            PM1_EN => self.pm1_en,
            // SCI_EN always reads 1: the system is permanently in ACPI mode.
            PM1_CNT => SCI_EN,
            _ => 0,
        };
        let bytes = val.to_le_bytes();
        for (i, b) in data.iter_mut().enumerate() {
            *b = bytes.get(i).copied().unwrap_or(0);
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        // Reset register is a single byte.
        if offset == RESET_REG {
            if data.first().copied() == Some(RESET_VALUE) {
                self.fire_exit(true);
            }
            return;
        }

        if (GPE0_STS..GPE0_END).contains(&offset) {
            for (i, &b) in data.iter().enumerate() {
                let at = offset + i as u64;
                if at < GPE0_EN {
                    // Status bits are write-1-to-clear.
                    self.gpe0_sts &= !(u16::from(b) << (8 * (at - GPE0_STS)));
                } else if at < GPE0_END {
                    let shift = 8 * (at - GPE0_EN);
                    self.gpe0_en = (self.gpe0_en & !(0xff << shift)) | (u16::from(b) << shift);
                }
            }
            self.raise_sci_if_pending();
            return;
        }

        // The PM1 registers are word-wide.
        if data.len() < 2 {
            return;
        }
        let val = u16::from_le_bytes([data[0], data[1]]);
        match offset {
            // Status bits are write-1-to-clear.
            PM1_STS => self.pm1_sts &= !val,
            PM1_EN => {
                self.pm1_en = val;
                self.raise_sci_if_pending();
            }
            PM1_CNT if val & SLP_EN != 0 => {
                let slp_typ = (val >> SLP_TYP_SHIFT) & SLP_TYP_MASK;
                if slp_typ == S5_SLP_TYP {
                    self.fire_exit(false);
                }
            }
            _ => {}
        }
    }
}

impl Subscriber for AcpiPm {
    fn process(&mut self, event: &EpollEvent, _event_manager: &mut EventManager) {
        let source = event.fd();
        let is_button = self
            .shutdown_efd
            .as_ref()
            .is_some_and(|efd| source == efd.as_raw_fd());
        if is_button {
            if let Some(efd) = self.shutdown_efd.as_ref() {
                let _ = efd.read();
            }
            self.pm1_sts |= PWRBTN;
            self.raise_sci_if_pending();
        } else {
            warn!("acpi_pm: unexpected event on fd {source:?}");
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        match self.shutdown_efd.as_ref() {
            Some(efd) => vec![EpollEvent::new(EventSet::IN, efd.as_raw_fd() as u64)],
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::eventfd::EFD_NONBLOCK;

    fn pm() -> AcpiPm {
        AcpiPm::new(
            EventFd::new(EFD_NONBLOCK).unwrap(),
            Arc::new(AtomicBool::new(false)),
            EventFd::new(EFD_NONBLOCK).unwrap(),
            None,
        )
    }

    fn fired(efd: &EventFd) -> bool {
        efd.read().is_ok()
    }

    fn word(pm: &mut AcpiPm, offset: u64, val: u16) {
        pm.write(0, offset, &val.to_le_bytes());
    }

    #[test]
    fn s5_powers_off_and_other_sleep_types_do_nothing() {
        let mut pm = pm();
        word(&mut pm, PM1_CNT, (3 << SLP_TYP_SHIFT) | SLP_EN);
        word(&mut pm, PM1_CNT, S5_SLP_TYP << SLP_TYP_SHIFT);
        assert!(!fired(&pm.exit_evt));
        word(&mut pm, PM1_CNT, (S5_SLP_TYP << SLP_TYP_SHIFT) | SLP_EN);
        assert!(fired(&pm.exit_evt));
        assert!(!pm.reset_flag.load(Ordering::SeqCst));
    }

    #[test]
    fn only_the_reset_value_resets() {
        let mut pm = pm();
        pm.write(0, RESET_REG, &[RESET_VALUE.wrapping_add(1)]);
        assert!(!fired(&pm.exit_evt));
        pm.write(0, RESET_REG, &[RESET_VALUE]);
        assert!(fired(&pm.exit_evt));
        assert!(pm.reset_flag.load(Ordering::SeqCst));
    }

    #[test]
    fn the_power_button_raises_the_sci_once_enabled_and_clears_by_write() {
        let mut pm = pm();
        // Latched before the guest enabled it: no SCI until PWRBTN_EN is set.
        pm.pm1_sts |= PWRBTN;
        pm.raise_sci_if_pending();
        assert!(!fired(&pm.sci_evt));
        word(&mut pm, PM1_EN, PWRBTN);
        assert!(fired(&pm.sci_evt));
        // Status is write-1-to-clear: writing 0 keeps it, writing the bit clears it.
        word(&mut pm, PM1_STS, 0);
        let mut buf = [0u8; 2];
        pm.read(0, PM1_STS, &mut buf);
        assert_eq!(u16::from_le_bytes(buf), PWRBTN);
        word(&mut pm, PM1_STS, PWRBTN);
        pm.read(0, PM1_STS, &mut buf);
        assert_eq!(u16::from_le_bytes(buf), 0);
    }

    #[test]
    fn pm1_cnt_reads_sci_enabled() {
        let mut pm = pm();
        let mut buf = [0u8; 2];
        pm.read(0, PM1_CNT, &mut buf);
        assert_eq!(u16::from_le_bytes(buf), SCI_EN);
    }

    fn gpe0(pm: &mut AcpiPm) -> [u8; 4] {
        let mut block = [0u8; 4];
        pm.read(0, GPE0_STS, &mut block);
        block
    }

    #[test]
    fn the_gpe0_block_sits_where_the_fadt_says() {
        assert_eq!(ACPI_PM_BASE as u64 + GPE0_STS, 0x610);
        assert_eq!(GPE0_EN - GPE0_STS, 2);
        assert_eq!(GPE0_END, arch::x86_64::layout::ACPI_PM_LEN);
    }

    #[test]
    fn a_gpe_raises_the_sci_once_enabled_and_clears_by_writing_one() {
        let mut pm = pm();
        // Latched before the guest enabled it: no SCI until its enable bit is set.
        pm.raise_gpe(5);
        assert!(!fired(&pm.sci_evt));
        assert_eq!(gpe0(&mut pm), [0x20, 0, 0, 0]);
        // GPE registers are byte-wide: GPE0_EN's first byte.
        pm.write(0, GPE0_EN, &[0x20]);
        assert!(fired(&pm.sci_evt));
        assert_eq!(gpe0(&mut pm), [0x20, 0, 0x20, 0]);
        // Write-1-to-clear: a zero, or another bit, keeps it.
        pm.write(0, GPE0_STS, &[0x00]);
        pm.write(0, GPE0_STS, &[0x01]);
        pm.write(0, GPE0_STS + 1, &[0x20]);
        assert_eq!(gpe0(&mut pm), [0x20, 0, 0x20, 0]);
        // (Those writes raised the still-pending SCI again.)
        let _ = fired(&pm.sci_evt);
        pm.write(0, GPE0_STS, &[0x20]);
        assert_eq!(gpe0(&mut pm), [0, 0, 0x20, 0]);
        assert!(!fired(&pm.sci_evt));
        // Enabled, a GPE raises the SCI at once; a GPE in the second byte too.
        pm.raise_gpe(5);
        assert!(fired(&pm.sci_evt));
        pm.write(0, GPE0_EN + 1, &[0x01]);
        pm.raise_gpe(8);
        assert!(fired(&pm.sci_evt));
        assert_eq!(gpe0(&mut pm), [0x20, 0x01, 0x20, 0x01]);
        // A word access covers both bytes.
        pm.write(0, GPE0_STS, &0x0120u16.to_le_bytes());
        assert_eq!(gpe0(&mut pm), [0, 0, 0x20, 0x01]);
    }

    #[test]
    fn the_registers_survive_save_and_restore() {
        let mut live = pm();
        word(&mut live, PM1_EN, PWRBTN);
        live.pm1_sts |= PWRBTN;
        live.write(0, GPE0_EN, &[0x20]);
        live.raise_gpe(5);
        std::thread::sleep(std::time::Duration::from_millis(5));
        let saved = live.save_state();
        assert_eq!(
            (saved.pm1_sts, saved.pm1_en, saved.gpe0_sts, saved.gpe0_en),
            (PWRBTN, PWRBTN, 0x20, 0x20)
        );
        let mut back = pm();
        back.restore_state(&saved);
        assert_eq!(gpe0(&mut back), [0x20, 0, 0x20, 0]);
        let mut buf = [0u8; 2];
        back.read(0, PM1_EN, &mut buf);
        assert_eq!(u16::from_le_bytes(buf), PWRBTN);
        // The timer carries on from its count, not from zero.
        let ticks_5ms = (PM_TIMER_HZ / 200) as u32;
        assert!(read_timer(&mut back) >= ticks_5ms);
        let again = back.save_state();
        assert_eq!(
            (again.pm1_sts, again.gpe0_en),
            (saved.pm1_sts, saved.gpe0_en)
        );
    }

    fn read_timer(pm: &mut AcpiPm) -> u32 {
        let mut data = [0u8; 4];
        pm.read(0, PM_TMR, &mut data);
        u32::from_le_bytes(data)
    }

    #[test]
    fn the_pm_timer_counts_at_3_58_mhz() {
        let mut pm = pm();
        let before = read_timer(&mut pm);
        std::thread::sleep(std::time::Duration::from_millis(20));
        let ticks = read_timer(&mut pm).wrapping_sub(before);
        // 20 ms is about 71,600 ticks; allow for a slow scheduler, never for a stopped clock.
        assert!(
            (70_000..1_000_000).contains(&ticks),
            "{ticks} ticks in 20 ms"
        );
    }
}
