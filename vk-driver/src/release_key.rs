//! Release keys: the ed25519 keys whose signatures a fleet node requires of the `vk` its hub
//! sends it (`[node] release_keys`). `vk release-key generate` makes one and `vk release-key
//! sign` signs a binary with it, on whatever machine holds the key — deliberately not the
//! hub, whose compromise a signature is there to survive: a hub can hand a node any bytes,
//! but not a signature it has no key for.
//!
//! A signature covers [`vk_fleet_proto::release_message`] — the binary's sha256 and the version
//! it is released as — and is written as base64, as the public keys are.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use sha2::{Digest, Sha256};

/// A PKCS#8 ed25519 key is under 100 bytes; this bounds what a wrong file costs to read.
const MAX_KEY_FILE: u64 = 4096;

/// `vk release-key generate`: a new key at `path`, `0600` and never over an existing file.
/// Returns its public half, base64, for `[node] release_keys`.
pub fn generate(path: &Path) -> Result<String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 =
        Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| anyhow!("generating an ed25519 key"))?;
    let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| anyhow!("reading back the generated key"))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| {
            format!(
                "creating {} (an existing key is never replaced)",
                path.display()
            )
        })?;
    file.write_all(pkcs8.as_ref())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(vk_fleet_proto::to_base64(key.public_key().as_ref()))
}

/// `vk release-key sign`: the signature of `binary` as `version` under the key at `key`,
/// base64.
pub fn sign(key: &Path, binary: &Path, version: &str) -> Result<String> {
    let key = load(key)?;
    let sha256 = sha256_of(binary)?;
    let signature = key.sign(&vk_fleet_proto::release_message(&sha256, version));
    Ok(vk_fleet_proto::to_base64(signature.as_ref()))
}

fn load(path: &Path) -> Result<Ed25519KeyPair> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = std::fs::File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let mode = file
        .metadata()
        .with_context(|| format!("statting {}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        bail!(
            "{} has mode {:o}: a release key must be readable by its owner only (chmod 600)",
            path.display(),
            mode & 0o7777
        );
    }
    let mut pkcs8 = Vec::new();
    (&mut file)
        .take(MAX_KEY_FILE)
        .read_to_end(&mut pkcs8)
        .with_context(|| format!("reading {}", path.display()))?;
    Ed25519KeyPair::from_pkcs8(&pkcs8)
        .map_err(|_| anyhow!("{} is not an ed25519 key in PKCS#8", path.display()))
}

fn sha256_of(path: &Path) -> Result<[u8; 32]> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("reading {}", path.display()))?;
        match buf.get(..n) {
            Some(chunk) if !chunk.is_empty() => hasher.update(chunk),
            _ => break,
        }
    }
    Ok(hasher.finalize().into())
}

/// What a node requires of a release's signature: `[node] release_keys` and
/// `require_signed`, read once.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    keys: Vec<Vec<u8>>,
    required: bool,
}

impl Policy {
    /// The policy `[node]` sets. A signature is required when any key is configured, unless
    /// `require_signed = false`; requiring one with no key to check it against is an error,
    /// as is a key that is not 32 bytes of base64.
    pub fn from_config(keys: &[String], require_signed: Option<bool>) -> Result<Self> {
        let keys = keys
            .iter()
            .map(|k| {
                vk_fleet_proto::from_base64(k)
                    .filter(|k| k.len() == vk_fleet_proto::PUBLIC_KEY_LEN)
                    .ok_or_else(|| {
                        anyhow!(
                            "[node] release_keys: {k:?} is not an ed25519 public key in base64, \
                             as `vk release-key generate` prints one"
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let required = require_signed.unwrap_or(!keys.is_empty());
        if required && keys.is_empty() {
            bail!("[node] require_signed = true needs release_keys to check signatures against");
        }
        Ok(Policy { keys, required })
    }

    /// Whether release `sha256` (hex) as `version`, with `signature`, may be installed: a
    /// signature is checked whenever there is one and a key to check it against — one that
    /// fails is refused even where none is required — and must be there when one is.
    pub fn check(
        &self,
        sha256: &str,
        version: &str,
        signature: Option<&str>,
    ) -> Result<(), String> {
        let Some(signature) = signature else {
            return if self.required {
                Err(
                    "the release is unsigned, and this node requires a signature by one of its \
                     [node] release_keys"
                        .to_string(),
                )
            } else {
                Ok(())
            };
        };
        if self.keys.is_empty() {
            return Ok(());
        }
        let digest = vk_fleet_proto::from_hex(sha256)
            .filter(|d| d.len() == vk_fleet_proto::SHA256_LEN)
            .ok_or_else(|| format!("{sha256:?} is not a sha256"))?;
        let signature = vk_fleet_proto::from_base64(signature)
            .filter(|s| s.len() == vk_fleet_proto::SIGNATURE_LEN)
            .ok_or_else(|| "the release's signature is not an ed25519 signature".to_string())?;
        let message = vk_fleet_proto::release_message(&digest, version);
        if self.keys.iter().any(|k| {
            UnparsedPublicKey::new(&ED25519, k)
                .verify(&message, &signature)
                .is_ok()
        }) {
            Ok(())
        } else {
            Err(format!(
                "the release's signature does not verify as vk {version} against any of this \
                 node's [node] release_keys"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signed_release_verifies_only_as_what_was_signed() {
        let dir = std::env::temp_dir().join(format!("vk-release-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("release.pk8");
        let public = generate(&key).unwrap();
        // Never over an existing key.
        assert!(generate(&key).is_err());
        let binary = dir.join("vk");
        std::fs::write(&binary, b"a vk").unwrap();
        let signature = sign(&key, &binary, "0.81.0").unwrap();
        let sha = vk_fleet_proto::to_hex(&sha256_of(&binary).unwrap());

        let policy = Policy::from_config(std::slice::from_ref(&public), None).unwrap();
        policy.check(&sha, "0.81.0", Some(&signature)).unwrap();
        // Another version, other bytes, no signature: refused.
        assert!(policy.check(&sha, "0.81.1", Some(&signature)).is_err());
        assert!(
            policy
                .check(&"00".repeat(32), "0.81.0", Some(&signature))
                .is_err()
        );
        assert!(policy.check(&sha, "0.81.0", None).is_err());

        // Another key's signature does not do, even where none is required.
        let other = dir.join("other.pk8");
        let other_public = generate(&other).unwrap();
        let optional =
            Policy::from_config(std::slice::from_ref(&other_public), Some(false)).unwrap();
        optional.check(&sha, "0.81.0", None).unwrap();
        assert!(optional.check(&sha, "0.81.0", Some(&signature)).is_err());

        // No keys: nothing is required or checked.
        let none = Policy::from_config(&[], None).unwrap();
        none.check(&sha, "0.81.0", None).unwrap();
        assert!(Policy::from_config(&[], Some(true)).is_err());
        assert!(Policy::from_config(&["not a key".into()], None).is_err());

        // A key others can read is refused.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(sign(&key, &binary, "0.81.0").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
