//! Exponential backoff with the semantics of `github.com/jpillora/backoff`, which
//! gitlab-runner uses for request retries, final job updates and unhealthy runners, plus the
//! OS randomness the crate needs.

use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};

/// `n` random bytes from the OS. A failing OS RNG is not recoverable for a process that
/// mints tokens and IDs, but none of the callers needs cryptographic strength, so it
/// degrades to zeros rather than panicking.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    if SystemRandom::new().fill(&mut buf).is_err() {
        log::warn!("OS random number generator failed");
    }
    buf
}

/// A uniformly distributed value in `[0, 1)`.
fn random_unit() -> f64 {
    let bits = u64::from_le_bytes(random_bytes::<8>()) >> 11;
    // 53 random bits over 2^53: exact in an f64.
    bits as f64 / (1u64 << 53) as f64
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[derive(Debug, Clone)]
pub struct Backoff {
    pub min: Duration,
    pub max: Duration,
    pub factor: f64,
    pub jitter: bool,
    attempt: u32,
}

impl Backoff {
    pub fn new(min: Duration, max: Duration, factor: f64, jitter: bool) -> Self {
        Self {
            min,
            max,
            factor,
            jitter,
            attempt: 0,
        }
    }

    /// The next wait: `min * factor^attempt`, capped at `max`; with jitter, uniform between
    /// `min` and that.
    pub fn next_delay(&mut self) -> Duration {
        let d = self.for_attempt(self.attempt);
        self.attempt = self.attempt.saturating_add(1);
        d
    }

    pub fn attempt(&self) -> u32 {
        self.attempt
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    fn for_attempt(&self, attempt: u32) -> Duration {
        let min = self.min.as_secs_f64();
        let max = self.max.as_secs_f64();
        if min >= max {
            return self.max;
        }
        let exp = i32::try_from(attempt).unwrap_or(i32::MAX);
        let mut d = min * self.factor.powi(exp);
        if self.jitter {
            d = random_unit() * (d - min) + min;
        }
        if !d.is_finite() || d > max {
            return self.max;
        }
        if d < min {
            return self.min;
        }
        Duration::from_secs_f64(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doubles_and_caps() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(5), 2.0, false);
        let got: Vec<u64> = (0..5).map(|_| b.next_delay().as_secs()).collect();
        assert_eq!(got, [1, 2, 4, 5, 5]);
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_secs(1));
    }

    #[test]
    fn jitter_stays_in_range() {
        let mut b = Backoff::new(
            Duration::from_millis(100),
            Duration::from_secs(60),
            2.0,
            true,
        );
        for attempt in 0..20 {
            let d = b.next_delay();
            let ceiling = (0.1 * 2f64.powi(attempt)).min(60.0);
            assert!(d >= Duration::from_millis(100), "{d:?}");
            assert!(d.as_secs_f64() <= ceiling + 1e-9, "{d:?} > {ceiling}");
        }
    }

    #[test]
    fn hex_encodes() {
        assert_eq!(hex(&[0x00, 0xab, 0x10]), "00ab10");
    }
}
