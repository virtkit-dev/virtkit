#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{Backend, NetWorker};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::NetWorker;
