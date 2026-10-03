// The pvpanic ISA device (local patch, see VENDOR.md): QEMU's I/O port 0x505, declared in the
// DSDT as QEMU0001, which a crashing guest writes. The event is logged; the guest reboots itself.

use log::error;

use crate::bus::BusDevice;

/// The guest crashed.
pub const PVPANIC_PANICKED: u8 = 1 << 0;
/// The guest crashed and its crash kernel (or dump writer) took over.
pub const PVPANIC_CRASH_LOADED: u8 = 1 << 1;

pub struct PvPanic;

impl BusDevice for PvPanic {
    fn read(&mut self, _vcpuid: u64, _offset: u64, data: &mut [u8]) {
        // A read lists the events this device accepts.
        if let Some(b) = data.first_mut() {
            *b = PVPANIC_PANICKED | PVPANIC_CRASH_LOADED;
        }
    }

    fn write(&mut self, _vcpuid: u64, _offset: u64, data: &[u8]) {
        let Some(&event) = data.first() else {
            return;
        };
        if event & PVPANIC_PANICKED != 0 {
            error!("pvpanic: the guest crashed (bug check / kernel panic)");
        }
        if event & PVPANIC_CRASH_LOADED != 0 {
            error!("pvpanic: the guest crashed and is writing a crash dump");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_lists_the_events_it_accepts() {
        let mut data = [0u8];
        PvPanic.read(0, 0, &mut data);
        assert_eq!(data[0], PVPANIC_PANICKED | PVPANIC_CRASH_LOADED);
    }

    #[test]
    fn any_write_is_taken() {
        for data in [
            &[][..],
            &[0],
            &[PVPANIC_PANICKED],
            &[PVPANIC_CRASH_LOADED],
            &[0xff],
        ] {
            PvPanic.write(0, 0, data);
        }
    }
}
