// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
#![cfg(target_arch = "x86_64")]

use std::fmt;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use arch::x86_64::layout::{ACPI_PM_BASE, ACPI_PM_LEN};
use devices;
use utils::eventfd::EventFd;

/// Errors corresponding to the `PortIODeviceManager`.
#[derive(Debug)]
pub enum Error {
    /// Cannot add legacy device to Bus.
    BusError(devices::BusError),
    /// Cannot create EventFd.
    EventFd(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        match *self {
            BusError(ref err) => write!(f, "Failed to add legacy device to Bus: {err}"),
            EventFd(ref err) => write!(f, "Failed to create EventFd: {err}"),
        }
    }
}

type Result<T> = ::std::result::Result<T, Error>;

/// The `PortIODeviceManager` is a wrapper that is used for registering legacy devices
/// on an I/O Bus. It currently manages the uart and i8042 devices.
/// The `LegacyDeviceManger` should be initialized only by using the constructor.
pub struct PortIODeviceManager {
    pub io_bus: devices::Bus,
    pub cmos: Arc<Mutex<devices::legacy::Cmos>>,
    pub stdio_serial: Vec<Arc<Mutex<devices::legacy::Serial>>>,
    pub i8042: Arc<Mutex<devices::legacy::I8042Device>>,
    pub acpi_pm: Arc<Mutex<devices::legacy::AcpiPm>>,
    pub pci_config_io: Arc<Mutex<devices::legacy::PciConfigIo>>,

    pub com_evt_1: EventFd,
    pub com_evt_2: EventFd,
    pub com_evt_3: EventFd,
    pub com_evt_4: EventFd,
    pub kbd_evt: EventFd,
}

impl PortIODeviceManager {
    /// Create a new DeviceManager handling legacy devices (uart, i8042, ACPI PM).
    ///
    /// `exit_evt` is the Vmm exit event, fired by the i8042 CPU-reset command and
    /// by the ACPI power-off / reset registers. `reset_flag` is shared with those
    /// devices and the Vmm so a reset is distinguished from a clean power-off.
    /// `sci_evt` raises the ACPI SCI, and `shutdown_efd` is the host power button.
    pub fn new(
        cmos: Arc<Mutex<devices::legacy::Cmos>>,
        stdio_serial: Vec<Arc<Mutex<devices::legacy::Serial>>>,
        exit_evt: EventFd,
        reset_flag: Arc<AtomicBool>,
        sci_evt: EventFd,
        shutdown_efd: Option<EventFd>,
    ) -> Result<Self> {
        let io_bus = devices::Bus::new();
        let mut evts: Vec<EventFd> = Vec::new();
        for i in 0..4 {
            let com_evt = match stdio_serial.get(i) {
                Some(s) => s
                    .lock()
                    .unwrap()
                    .interrupt_evt()
                    .try_clone()
                    .map_err(Error::EventFd)?,
                None => EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(Error::EventFd)?,
            };
            evts.push(com_evt);
        }

        let kbd_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(Error::EventFd)?;

        let i8042 = Arc::new(Mutex::new(devices::legacy::I8042Device::new(
            exit_evt.try_clone().map_err(Error::EventFd)?,
            reset_flag.clone(),
            kbd_evt.try_clone().map_err(Error::EventFd)?,
        )));

        let acpi_pm = Arc::new(Mutex::new(devices::legacy::AcpiPm::new(
            exit_evt,
            reset_flag,
            sci_evt,
            shutdown_efd,
        )));

        // Legacy PCI: a single host bridge at 00:00.0 reachable via the type-1
        // 0xCF8/0xCFC config mechanism. No devices hang off it yet.
        let mut pci_bus = devices::legacy::PciBus::new();
        pci_bus.add_device(
            0,
            Arc::new(Mutex::new(devices::legacy::PciDevice::new_host_bridge(
                0x1b36, 0x0008,
            ))),
        );
        let pci_config_io = Arc::new(Mutex::new(devices::legacy::PciConfigIo::new(Arc::new(
            Mutex::new(pci_bus),
        ))));

        Ok(PortIODeviceManager {
            io_bus,
            cmos,
            stdio_serial,
            i8042,
            acpi_pm,
            pci_config_io,
            com_evt_1: evts[0].try_clone().map_err(Error::EventFd)?,
            com_evt_2: evts[1].try_clone().map_err(Error::EventFd)?,
            com_evt_3: evts[2].try_clone().map_err(Error::EventFd)?,
            com_evt_4: evts[3].try_clone().map_err(Error::EventFd)?,
            kbd_evt,
        })
    }

    /// Register supported legacy devices.
    pub fn register_devices(&mut self) -> Result<()> {
        self.io_bus
            .insert(self.cmos.clone(), 0x70, 0x8)
            .map_err(Error::BusError)?;

        if let Some(serial) = self.stdio_serial.first() {
            self.io_bus
                .insert(serial.clone(), 0x3f8, 0x8)
                .map_err(Error::BusError)?;
        }
        self.io_bus
            .insert(
                self.stdio_serial
                    .get(1)
                    .unwrap_or(&Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                        self.com_evt_2.try_clone().map_err(Error::EventFd)?,
                    ))))
                    .clone(),
                0x2f8,
                0x8,
            )
            .map_err(Error::BusError)?;
        self.io_bus
            .insert(
                self.stdio_serial
                    .get(2)
                    .unwrap_or(&Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                        self.com_evt_3.try_clone().map_err(Error::EventFd)?,
                    ))))
                    .clone(),
                0x3e8,
                0x8,
            )
            .map_err(Error::BusError)?;
        self.io_bus
            .insert(
                self.stdio_serial
                    .get(3)
                    .unwrap_or(&Arc::new(Mutex::new(devices::legacy::Serial::new_sink(
                        self.com_evt_4.try_clone().map_err(Error::EventFd)?,
                    ))))
                    .clone(),
                0x2e8,
                0x8,
            )
            .map_err(Error::BusError)?;
        self.io_bus
            .insert(self.i8042.clone(), 0x060, 0x5)
            .map_err(Error::BusError)?;
        // ACPI PM1 block and reset register.
        self.io_bus
            .insert(self.acpi_pm.clone(), u64::from(ACPI_PM_BASE), ACPI_PM_LEN)
            .map_err(Error::BusError)?;
        // Type-1 PCI config: CONFIG_ADDRESS at 0xcf8, CONFIG_DATA at 0xcfc.
        self.io_bus
            .insert(self.pci_config_io.clone(), 0xcf8, 0x8)
            .map_err(Error::BusError)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_legacy_devices() {
        let serial =
            devices::legacy::Serial::new_sink(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap());
        let cmos = devices::legacy::Cmos::new(0, 0);
        let ldm = PortIODeviceManager::new(
            Arc::new(Mutex::new(cmos)),
            vec![Arc::new(Mutex::new(serial))],
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
            Arc::new(AtomicBool::new(false)),
            EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
            None,
        );
        assert!(ldm.is_ok());
        assert!(&ldm.unwrap().register_devices().is_ok());
    }

    #[test]
    fn test_debug_error() {
        assert_eq!(
            format!("{}", Error::BusError(devices::BusError::Overlap)),
            format!(
                "Failed to add legacy device to Bus: {}",
                devices::BusError::Overlap
            )
        );
        assert_eq!(
            format!("{}", Error::EventFd(std::io::Error::from_raw_os_error(1))),
            format!(
                "Failed to create EventFd: {}",
                std::io::Error::from_raw_os_error(1)
            )
        );
    }
}
