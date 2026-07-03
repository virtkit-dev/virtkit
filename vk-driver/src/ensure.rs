//! Content fingerprints for image staleness: an ext4's UUID is a fingerprint of
//! what it was built from, so a staleness check is just a UUID compare. `vk
//! fingerprint` exposes the recipe so build scripts compute the same value.

use sha2::{Digest, Sha256};

fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    let d = Sha256::digest(data);
    let mut s = String::with_capacity(64);
    for b in d {
        use std::fmt::Write;
        write!(s, "{b:02x}").unwrap();
    }
    s
}

/// Content fingerprint as a canonical UUID: sha256 of the parts joined by '\n', the
/// first 16 bytes formatted 8-4-4-4-12. Called by the `vk fingerprint` subcommand
/// so build scripts can compute the same value without reimplementing the algorithm.
pub fn fingerprint(parts: &[&str]) -> String {
    let hex = sha256_hex(parts.join("\n"));
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_a_canonical_uuid_and_stable() {
        let fp = fingerprint(&["myservice:tag", "abc123"]);
        // 8-4-4-4-12 lowercase hex
        let parts: Vec<&str> = fp.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(fp.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));
        // deterministic + order-sensitive
        assert_eq!(fp, fingerprint(&["myservice:tag", "abc123"]));
        assert_ne!(fp, fingerprint(&["abc123", "myservice:tag"]));
    }
}
