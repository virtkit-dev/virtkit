//! Guest-only agent code: PID 1 bring-up (`init`), the block-device mount syscalls
//! (`diskmount`), fs freeze/thaw (`fsfreeze`), the writable layer's high-water mark
//! (`fsmark`), the guest's peak memory demand (`memmark`), the line both publish (`mark`),
//! guest statistics in atop's parseable format (`atop`, with the exited tasks `taskstats`
//! reports), networking (`tap`, `netcfg`) and the embedded SSH server
//! (`ssh`/`sftp`, feature `ssh`). The shared host↔guest protocol and runtime helpers live in
//! the `vk-core` crate.

pub mod atop;
pub mod ctlfs;
pub mod diskmount;
pub mod fsfreeze;
pub mod fsmark;
pub mod init;
pub(crate) mod mark;
pub mod memmark;
pub mod netcfg;
#[cfg(feature = "ssh")]
pub mod sftp;
#[cfg(feature = "ssh")]
pub mod ssh;
pub mod tap;
pub mod taskstats;
