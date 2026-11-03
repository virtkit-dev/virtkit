#[cfg(feature = "tee")]
pub mod tee;

pub mod vstate;

#[cfg(target_arch = "x86_64")]
mod virtiofs_test;
