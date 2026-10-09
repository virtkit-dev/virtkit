//! Ed25519 release keys for fleet nodes (`[node] release_keys`). `vk release-key generate`
//! creates a key; `vk release-key sign` signs a binary on the machine holding it. Keep the
//! key off the hub so a compromised hub can send arbitrary bytes but cannot sign them.
//!
//! A signature covers [`vk_hub_proto::release_message`] — the binary's sha256 and the version
//! it is released as — and is written as base64, as the public keys are.

use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use sha2::{Digest, Sha256};

/// A PKCS#8 ed25519 key is under 100 bytes; this bounds what a wrong file costs to read.
const MAX_KEY_FILE: u64 = 4096;

/// `vk release-key generate`: a new key at `path`, `0600` from the moment it exists, published
/// whole and never over an existing file. Returns its public half, base64, for `[node]
/// release_keys`.
pub fn generate(path: &Path) -> Result<String> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 =
        Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| anyhow!("generating an ed25519 key"))?;
    let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| anyhow!("reading back the generated key"))?;
    vk_fs::write_new(path, pkcs8.as_ref(), 0o600).with_context(|| {
        format!(
            "writing {} (an existing file is never replaced)",
            path.display()
        )
    })?;
    Ok(vk_hub_proto::to_base64(key.public_key().as_ref()))
}

/// `vk release-key sign`: the signature of `binary` as `version` under the key at `key`,
/// base64.
pub fn sign(key: &Path, binary: &Path, version: &str) -> Result<String> {
    let key = load(key)?;
    let sha256 = sha256_of(binary)?;
    let signature = key.sign(&vk_hub_proto::release_message(&sha256, version));
    Ok(vk_hub_proto::to_base64(signature.as_ref()))
}

fn load(path: &Path) -> Result<Ed25519KeyPair> {
    // `O_NOFOLLOW` and the mode judged off the descriptor, as for the node's own key;
    // `O_NONBLOCK` so a FIFO there is refused rather than waited on.
    let mut file = std::fs::File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("statting {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    let mode = metadata.permissions().mode();
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
    Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|_| {
        anyhow!(
            "{} is not an ed25519 key as `vk release-key generate` writes one (PKCS#8 v2)",
            path.display()
        )
    })
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

/// The node's signature policy, read once from `[node] release_keys` and `require_signed`.
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
                vk_hub_proto::from_base64(k)
                    .filter(|k| k.len() == vk_hub_proto::PUBLIC_KEY_LEN)
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

    /// Whether every release must carry a signature by one of the node's keys: the node does
    /// not take its hub's word for what runs on it.
    pub fn required(&self) -> bool {
        self.required
    }

    /// Check whether release `sha256` (hex) as `version` may be installed. A signature must
    /// be present when required. With keys configured, any supplied signature must verify,
    /// even when signatures are optional.
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
        let digest = vk_hub_proto::from_hex_lower::<{ vk_hub_proto::SHA256_LEN }>(sha256)
            .ok_or_else(|| format!("{sha256:?} is not a sha256"))?;
        let signature = vk_hub_proto::from_base64(signature)
            .filter(|s| s.len() == vk_hub_proto::SIGNATURE_LEN)
            .ok_or_else(|| "the release's signature is not an ed25519 signature".to_string())?;
        let message = vk_hub_proto::release_message(&digest, version);
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
        assert_eq!(
            std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // Never over an existing key.
        let before = std::fs::read(&key).unwrap();
        assert!(generate(&key).is_err());
        assert_eq!(std::fs::read(&key).unwrap(), before);
        let binary = dir.join("vk");
        std::fs::write(&binary, b"a vk").unwrap();
        let signature = sign(&key, &binary, "0.84.0").unwrap();
        let sha = vk_hub_proto::to_hex(&sha256_of(&binary).unwrap());

        let policy = Policy::from_config(std::slice::from_ref(&public), None).unwrap();
        policy.check(&sha, "0.84.0", Some(&signature)).unwrap();
        // Another version, other bytes, no signature: refused.
        assert!(policy.check(&sha, "0.84.1", Some(&signature)).is_err());
        assert!(
            policy
                .check(&"00".repeat(32), "0.84.0", Some(&signature))
                .is_err()
        );
        assert!(policy.check(&sha, "0.84.0", None).is_err());
        // A signature that is not one at all: refused as such.
        for malformed in ["abc!".to_string(), vk_hub_proto::to_base64(&[0; 63])] {
            let err = policy.check(&sha, "0.84.0", Some(&malformed)).unwrap_err();
            assert!(err.contains("not an ed25519 signature"), "{err}");
        }

        // Another key's signature does not do, even where none is required.
        let other = dir.join("other.pk8");
        let other_public = generate(&other).unwrap();
        let optional =
            Policy::from_config(std::slice::from_ref(&other_public), Some(false)).unwrap();
        optional.check(&sha, "0.84.0", None).unwrap();
        assert!(optional.check(&sha, "0.84.0", Some(&signature)).is_err());
        // Either of two keys does.
        let both = Policy::from_config(&[other_public, public], None).unwrap();
        both.check(&sha, "0.84.0", Some(&signature)).unwrap();

        // No keys: nothing is required or checked.
        let none = Policy::from_config(&[], None).unwrap();
        none.check(&sha, "0.84.0", None).unwrap();
        none.check(&sha, "0.84.0", Some("not checked")).unwrap();
        assert!(Policy::from_config(&[], Some(true)).is_err());
        assert!(Policy::from_config(&["not a key".into()], None).is_err());

        // A key others can read, or a link to one, is refused.
        let link = dir.join("link.pk8");
        std::os::unix::fs::symlink(&key, &link).unwrap();
        assert!(sign(&link, &binary, "0.84.0").is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = sign(&key, &binary, "0.84.0").unwrap_err();
        assert!(format!("{err:#}").contains("chmod 600"), "{err:#}");
        // A FIFO is refused, not waited on.
        let fifo = dir.join("fifo.pk8");
        let c_fifo = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: the path is NUL-terminated and outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);
        let err = sign(&fifo, &binary, "0.84.0").unwrap_err();
        assert!(format!("{err:#}").contains("not a regular file"), "{err:#}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
