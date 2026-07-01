pub mod client;
pub mod server;

/// Capacity of the bounded stdin/stdout/stderr data channels (messages of up to
/// 4 KiB): bounds the buffering at ~1 MiB per stream so a fast producer feeding a
/// slow consumer backpressures down to the pipe instead of buffering in memory.
pub(crate) const DATA_CHANNEL_CAPACITY: usize = 256;
