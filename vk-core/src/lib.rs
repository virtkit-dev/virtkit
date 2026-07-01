//! Shared host↔guest library: the wire protocol (`messages`, `framing`, `addr`, `net`,
//! `status`, `fleetctl`) and the runtime helpers both the driver (`vk`) and the guest
//! agent (`vk-agent`) build on (`exec`, `forward`, `pty`, `dockerignore`). Deliberately
//! free of guest-only concerns (init/ssh/tap/…) so the host links none of that.

pub mod addr;
pub mod dockerignore;
pub mod exec;
pub mod fleetctl;
pub mod forward;
pub mod framing;
pub mod messages;
pub mod net;
pub mod pty;
pub mod status;
