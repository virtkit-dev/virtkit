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
// There is no PM timer and no GPE block. SCI_EN reads back as 1 (the system is
// always in ACPI mode: FADT SMI_CMD is 0), so the guest never tries to enable it.

use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};
use utils::eventfd::EventFd;

use arch::x86_64::layout::{ACPI_PM_BASE, ACPI_RESET_REG, ACPI_RESET_VALUE};

use crate::bus::BusDevice;

// Register offsets from the device base (ACPI_PM_BASE). PM1a_EVT (STS at +0, EN at
// +2) and PM1a_CNT (+4) decompose the PM block whose base and reset register live in
// arch::x86_64::layout and feed the FADT, so the reset offset/value are taken from
// there rather than re-hardcoded (so a layout change cannot desync the FADT from
// this device).
const PM1_STS: u64 = 0x00; // 2 bytes
const PM1_EN: u64 = 0x02; // 2 bytes
const PM1_CNT: u64 = 0x04; // 2 bytes
const RESET_REG: u64 = (ACPI_RESET_REG - ACPI_PM_BASE) as u64; // 1 byte

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
    /// The Vmm exit event: written to end the VM (power-off or reset).
    exit_evt: EventFd,
    /// Set (before firing `exit_evt`) when the exit is a reset, so the Vmm reports
    /// a guest reset rather than a clean power-off.
    reset_flag: Arc<AtomicBool>,
    /// Raises the ACPI SCI (registered as an irqfd on `SCI_GSI`).
    sci_evt: EventFd,
    /// Host-side power-button trigger. `None` when the host exposes no button.
    shutdown_efd: Option<EventFd>,
}

impl AcpiPm {
    pub fn new(
        exit_evt: EventFd,
        reset_flag: Arc<AtomicBool>,
        sci_evt: EventFd,
        shutdown_efd: Option<EventFd>,
    ) -> Self {
        AcpiPm {
            pm1_sts: 0,
            pm1_en: 0,
            exit_evt,
            reset_flag,
            sci_evt,
            shutdown_efd,
        }
    }

    fn raise_sci_if_pending(&self) {
        if self.pm1_sts & self.pm1_en & PWRBTN != 0 {
            if let Err(e) = self.sci_evt.write(1) {
                error!("acpi_pm: failed to raise SCI: {e:?}");
            }
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
