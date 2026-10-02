use std::io;

#[cfg(unix)]
use std::os::fd::RawFd;
#[cfg(windows)]
use std::os::windows::io::RawSocket;

#[cfg(windows)]
use vm_memory::GuestMemoryMmap;

#[cfg(unix)]
pub type SysError = nix::Error;
#[cfg(windows)]
pub type SysError = io::Error;

#[allow(dead_code)]
#[derive(Debug)]
pub enum ConnectError {
    InvalidAddress(SysError),
    CreateSocket(SysError),
    Binding(SysError),
    #[cfg(windows)]
    Worker(SysError),
    #[cfg(not(target_os = "windows"))]
    SendingMagic(nix::Error),
    // Tap backend errors.
    #[cfg(not(target_os = "windows"))]
    OpenNetTun(nix::Error),
    #[cfg(not(target_os = "windows"))]
    TunSetIff(io::Error),
    #[cfg(not(target_os = "windows"))]
    TunSetVnetHdrSz(io::Error),
    #[cfg(not(target_os = "windows"))]
    TunSetOffload(io::Error),
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum ReadError {
    /// Nothing was written
    NothingRead,
    /// The guest queue ran out of available descriptors
    #[cfg(windows)]
    DescriptorStarvation,
    #[cfg(windows)]
    ProcessNotRunning,
    #[cfg(windows)]
    Queue(crate::virtio::queue::Error),
    /// Another internal error occurred
    Internal(SysError),
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum WriteError {
    /// `write_frame` refused the offered frame; `flush_frames` made no progress and
    /// retains all pending bytes for a later retry.
    NothingWritten,
    /// Part of what was pending was written, the rest is held for the next flush_frames
    PartialWrite,
    /// Passt doesnt seem to be running (received EPIPE)
    ProcessNotRunning,
    /// Another internal error occurred
    Internal(SysError),
}

#[cfg(unix)]
pub trait NetBackend {
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError>;
    /// Take one frame. A backend may hold it back to send it with the frames that follow,
    /// so a frame is only known to have left once `flush_frames` reports it. `NothingWritten`
    /// means the frame was not taken at all and the caller keeps it. Accepted frames
    /// return `Ok(())`, even if bytes remain pending; `PartialWrite` is only for flushing.
    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError>;
    fn has_unfinished_write(&self) -> bool;
    /// Push out everything `write_frame` left pending: frames held back for batching, and
    /// the tail of a send the socket could not take whole. What does not go out now is kept
    /// for the next call, so a blocked socket costs nothing but a retry on the next writable
    /// event. Backends that complete every frame in `write_frame` have nothing to do.
    fn flush_frames(&mut self) -> Result<(), WriteError>;
    fn raw_socket_fd(&self) -> RawFd;

    /// Delay in microseconds before retrying after NothingWritten.
    /// Returns 0 if no delay-based retry is needed (e.g. on Linux where
    /// EAGAIN + EPOLLET handles retries via writable events).
    #[allow(dead_code)]
    fn write_retry_delay_us(&self) -> u64 {
        0
    }
}

#[cfg(windows)]
#[derive(Debug, PartialEq, Eq)]
pub enum WriteStatus {
    Complete,
    Pending,
}

#[cfg(windows)]
pub trait NetBackend {
    fn prepare_tx_buffer(&mut self) -> &mut [u8];

    fn start_tx(&mut self, total_bytes: usize) -> Result<WriteStatus, WriteError>;

    fn resume_tx(&mut self) -> Result<WriteStatus, WriteError>;

    fn read_frames_to_guest(
        &mut self,
        mem: &GuestMemoryMmap,
        rx_queue: &mut crate::virtio::queue::Queue,
    ) -> Result<u32, ReadError>;

    fn raw_socket_fd(&self) -> RawSocket;
}
