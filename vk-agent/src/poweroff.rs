//! Select the shutdown request for each VMM. libkrun has no ACPI, so power-off only halts
//! its vCPUs and leaves the VMM running; reset exits the VMM. With ACPI (cloud-hypervisor),
//! power-off exits and reset reboots the VM.

use std::path::Path;

/// Whether this machine has ACPI and therefore supports power-off. In libkrun guests the
/// firmware directory contains only the memory map.
pub(crate) fn machine_has_acpi() -> bool {
    Path::new("/sys/firmware/acpi").is_dir()
}

/// End the VM with its supported `reboot(2)` request: power-off with ACPI, reset otherwise.
/// The caller samples [`machine_has_acpi`] beforehand so this remains safe for
/// `init::poweroff`'s signal-handler path. Never returns.
pub(crate) fn power_off_machine(acpi: bool) -> ! {
    let cmd = if acpi {
        libc::LINUX_REBOOT_CMD_POWER_OFF
    } else {
        libc::LINUX_REBOOT_CMD_RESTART
    };
    // SAFETY: reboot(2) has no memory-safety preconditions.
    unsafe { libc::reboot(cmd) };
    // An accepted request never returns. Exit on failure so PID 1 triggers a visible kernel
    // panic rather than hanging.
    std::process::exit(1)
}
