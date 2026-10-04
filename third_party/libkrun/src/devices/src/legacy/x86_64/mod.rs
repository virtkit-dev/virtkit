pub mod cmos;
#[cfg(target_os = "linux")]
pub mod flash;
#[cfg(target_os = "linux")]
pub mod pvpanic;
pub mod serial;
