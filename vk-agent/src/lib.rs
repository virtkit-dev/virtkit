//! Guest-only agent code: PID 1 bring-up (`init`), the block-device mount syscalls
//! (`diskmount`), fs freeze/thaw (`fsfreeze`), networking (`tap`, `netcfg`) and the
//! embedded SSH server (`ssh`/`sftp`, feature `ssh`). The shared host↔guest protocol
//! and runtime helpers live in the `vk-core` crate.

pub mod diskmount;
pub mod fsfreeze;
pub mod init;
pub mod netcfg;
#[cfg(feature = "ssh")]
pub mod sftp;
#[cfg(feature = "ssh")]
pub mod ssh;
pub mod tap;
