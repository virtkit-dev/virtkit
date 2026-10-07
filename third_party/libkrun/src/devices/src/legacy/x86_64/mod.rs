pub mod cmos;
#[cfg(target_os = "linux")]
pub mod flash;
#[cfg(all(target_os = "linux", feature = "uefi-vars"))]
pub mod fw_cfg;
#[cfg(target_os = "linux")]
pub mod pvpanic;
pub mod serial;
#[cfg(all(target_os = "linux", feature = "tpm"))]
pub mod tpm;
#[cfg(all(target_os = "linux", feature = "uefi-vars"))]
pub mod uefi_vars;
