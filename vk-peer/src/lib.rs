//! What a peer of `vk-hub` needs to join it and hold a session with it: an ed25519 identity,
//! enrollment with a single-use token, the TLS connection and the handshake every peer opens
//! its session with, release keys, and the pieces of a self-update on trial. `vk node` and
//! `vk-registry` are such peers; each brings its own messages after the handshake and its own
//! state.

pub mod identity;
pub mod net;
pub mod release_key;
pub mod session;
pub mod update;

use std::time::Duration;

use anyhow::{Result, anyhow};

/// Seconds since the Unix epoch, which command expiries count in.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    use ring::rand::SecureRandom;
    ring::rand::SystemRandom::new()
        .fill(buf)
        .map_err(|_| anyhow!("the system random number generator failed"))
}

/// `d` plus up to a quarter more, so a fleet that lost its hub together does not redial it
/// in lockstep.
pub fn jittered(d: Duration) -> Duration {
    let mut b = [0u8; 2];
    let spread = fill_random(&mut b)
        .map(|()| u32::from(u16::from_le_bytes(b)))
        .unwrap_or(0);
    d + d / 4 * spread / u32::from(u16::MAX)
}
