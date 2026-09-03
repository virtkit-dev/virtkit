//! Watch the guest's ACPI power button. A host power-button press (SIGTERM to the VMM, which
//! its libkrun boot child turns into an ACPI SCI) surfaces in the guest as a KEY_POWER input
//! event. When `vk-agent init` is PID 1 nothing else consumes it, so this catches it and asks
//! PID 1 (this agent) to power off cleanly — the same path as a host `vk-agent poweroff`. It
//! is the fallback for when the exec channel is gone (a hung or shell-less guest).
//!
//! With a systemd entrypoint running as a child under `vk-agent init`, both this watcher and
//! systemd's logind see the event; PID 1's `STOP_REQUESTED` guard makes the double request
//! harmless.

use std::io::Read;
use std::mem::size_of;
use std::path::{Path, PathBuf};

const EV_KEY: u16 = 1;
const KEY_POWER: u16 = 116;

/// Spawn a reader thread per `/dev/input/event*` device. The one the ACPI button registers
/// carries KEY_POWER; the rest simply never see it. A no-op when there are no input devices.
pub fn watch_power_button() {
    for path in event_devices() {
        std::thread::spawn(move || read_events(&path));
    }
}

fn event_devices() -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir("/dev/input") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("event"))
        })
        .map(|e| e.path())
        .collect()
}

fn read_events(path: &Path) {
    let Ok(mut f) = std::fs::File::open(path) else {
        return;
    };
    // struct input_event = { struct timeval time; __u16 type; __u16 code; __s32 value; }.
    // Parse the trailing fields by offset so the timeval width is whatever this libc uses.
    let ts = size_of::<libc::timeval>();
    let mut buf = vec![0u8; ts + 8];
    while f.read_exact(&mut buf).is_ok() {
        let Some(fields) = buf.get(ts..).and_then(|t| <[u8; 8]>::try_from(t).ok()) else {
            return;
        };
        if is_power_press(fields) {
            // SAFETY: kill(2). PID 1 is this agent; its SIG_POWEROFF handler shuts down.
            unsafe { libc::kill(1, crate::poweroff::SIG_POWEROFF) };
            return;
        }
    }
}

/// True when the `type`, `code` and `value` fields trailing an `input_event`'s timeval are a
/// KEY_POWER press: value 1 is a press (0 = release, 2 = autorepeat).
fn is_power_press(fields: [u8; 8]) -> bool {
    let type_ = u16::from_ne_bytes([fields[0], fields[1]]);
    let code = u16::from_ne_bytes([fields[2], fields[3]]);
    let value = i32::from_ne_bytes([fields[4], fields[5], fields[6], fields[7]]);
    type_ == EV_KEY && code == KEY_POWER && value == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the 8 trailing bytes of an `input_event` in this machine's byte order.
    fn fields(type_: u16, code: u16, value: i32) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0..2].copy_from_slice(&type_.to_ne_bytes());
        b[2..4].copy_from_slice(&code.to_ne_bytes());
        b[4..8].copy_from_slice(&value.to_ne_bytes());
        b
    }

    #[test]
    fn power_key_press_is_recognized() {
        assert!(is_power_press(fields(EV_KEY, KEY_POWER, 1)));
    }

    #[test]
    fn release_and_autorepeat_are_ignored() {
        assert!(!is_power_press(fields(EV_KEY, KEY_POWER, 0)));
        assert!(!is_power_press(fields(EV_KEY, KEY_POWER, 2)));
    }

    #[test]
    fn other_keys_and_types_are_ignored() {
        assert!(!is_power_press(fields(EV_KEY, KEY_POWER + 1, 1)));
        assert!(!is_power_press(fields(EV_KEY + 1, KEY_POWER, 1)));
    }
}
