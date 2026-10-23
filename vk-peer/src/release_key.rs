//! Ed25519 release keys for the hub's peers (`[node] release_keys` for `vk node`, `[hub]
//! release_keys` for `vk-registry`). `vk release-key generate`
//! creates a key; `vk release-key sign` signs a binary on the machine holding it. Keep the
//! key off the hub so a compromised hub can send arbitrary bytes but cannot sign them.
//!
//! A signature covers the binary's sha256 and the version it is released as, under a label
//! naming its [`Program`] — so a `vk` release never verifies as a `vk-registry` one, nor the
//! reverse — and is written as base64, as the public keys are.

use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use sha2::{Digest, Sha256};

/// A PKCS#8 ed25519 key is under 100 bytes; this bounds what a wrong file costs to read.
const MAX_KEY_FILE: u64 = 4096;

/// `vk release-key generate`: a new key at `path`, `0600` from the moment it exists, published
/// whole and never over an existing file. Returns its public half, base64, for a peer's
/// `release_keys`.
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

/// The release's program determines the signed message.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Program {
    /// `vk`, which nodes run: [`vk_hub_proto::release_message`].
    #[default]
    Vk,
    /// `vk-registry`: [`vk_hub_proto::registry::release_message`].
    Registry,
}

impl Program {
    fn release_message(self, sha256: &[u8; vk_hub_proto::SHA256_LEN], version: &str) -> Vec<u8> {
        match self {
            Program::Vk => vk_hub_proto::release_message(sha256, version),
            Program::Registry => vk_hub_proto::registry::release_message(sha256, version),
        }
    }
}

/// `vk release-key sign`: the signature of `binary` as `version` of `program` under the key
/// at `key`, base64.
pub fn sign(key: &Path, binary: &Path, version: &str, program: Program) -> Result<String> {
    let key = load(key)?;
    let sha256 = sha256_of(binary)?;
    let signature = key.sign(&program.release_message(&sha256, version));
    Ok(vk_hub_proto::to_base64(signature.as_ref()))
}

/// The ed25519 key at `path`: a regular file, readable by its owner only, PKCS#8 v2.
pub(crate) fn load(path: &Path) -> Result<Ed25519KeyPair> {
    // `O_NOFOLLOW` and the mode judged off the descriptor, as for the peer's own key;
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
            "{} has mode {:o}: a signing key must be readable by its owner only (chmod 600)",
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
            "{} is not an ed25519 key in PKCS#8 v2, as `vk release-key generate` and the hub \
             write one",
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

/// A peer's signature policy, read once from its config's `release_keys` and
/// `require_signed`.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    keys: Vec<Vec<u8>>,
    required: bool,
    /// The config table the keys come from, `[node]` or `[hub]`, to say so.
    section: &'static str,
    /// The program of the releases it checks.
    program: Program,
}

impl Policy {
    /// The policy `[node]` sets for `vk` releases. A signature is required when any key is
    /// configured, unless `require_signed = false`; requiring one with no key to check it
    /// against is an error, as is a key that is not 32 bytes of base64.
    pub fn from_config(keys: &[String], require_signed: Option<bool>) -> Result<Self> {
        Self::from_config_in("[node]", Program::Vk, keys, require_signed)
    }

    /// [`Policy::from_config`] for the keys of the config table `section`, checking releases
    /// of `program`.
    pub fn from_config_in(
        section: &'static str,
        program: Program,
        keys: &[String],
        require_signed: Option<bool>,
    ) -> Result<Self> {
        let keys = keys
            .iter()
            .map(|k| {
                vk_hub_proto::from_base64(k)
                    .filter(|k| k.len() == vk_hub_proto::PUBLIC_KEY_LEN)
                    .ok_or_else(|| {
                        anyhow!(
                            "{section} release_keys: {k:?} is not an ed25519 public key in \
                             base64, as `vk release-key generate` prints one"
                        )
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let required = require_signed.unwrap_or(!keys.is_empty());
        if required && keys.is_empty() {
            bail!("{section} require_signed = true needs release_keys to check signatures against");
        }
        Ok(Policy {
            keys,
            required,
            section,
            program,
        })
    }

    /// Whether every release must carry a signature by one of the peer's keys: the peer does
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
                Err(format!(
                    "the release is unsigned, and this host requires a signature by one of its \
                     {} release_keys",
                    self.section
                ))
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
        let message = self.program.release_message(&digest, version);
        if self.keys.iter().any(|k| {
            UnparsedPublicKey::new(&ED25519, k)
                .verify(&message, &signature)
                .is_ok()
        }) {
            Ok(())
        } else {
            Err(format!(
                "the release's signature does not verify as {version} against any of this \
                 host's {} release_keys",
                self.section
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
        let signature = sign(&key, &binary, "0.84.0", Program::Vk).unwrap();
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
        assert!(sign(&link, &binary, "0.84.0", Program::Vk).is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = sign(&key, &binary, "0.84.0", Program::Vk).unwrap_err();
        assert!(format!("{err:#}").contains("chmod 600"), "{err:#}");
        // A FIFO is refused, not waited on.
        let fifo = dir.join("fifo.pk8");
        let c_fifo = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: the path is NUL-terminated and outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) }, 0);
        let err = sign(&fifo, &binary, "0.84.0", Program::Vk).unwrap_err();
        assert!(format!("{err:#}").contains("not a regular file"), "{err:#}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_registry_release_verifies_only_as_a_registrys() {
        let dir = std::env::temp_dir().join(format!("vk-release-key-reg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("release.pk8");
        let public = generate(&key).unwrap();
        let binary = dir.join("vk-registry");
        std::fs::write(&binary, b"a vk-registry").unwrap();
        let sha = vk_hub_proto::to_hex(&sha256_of(&binary).unwrap());
        let keys = std::slice::from_ref(&public);
        let registry = Policy::from_config_in("[hub]", Program::Registry, keys, None).unwrap();
        let node = Policy::from_config(keys, None).unwrap();

        let signed = sign(&key, &binary, "0.89.0", Program::Registry).unwrap();
        registry.check(&sha, "0.89.0", Some(&signed)).unwrap();
        assert!(node.check(&sha, "0.89.0", Some(&signed)).is_err());
        let as_vk = sign(&key, &binary, "0.89.0", Program::Vk).unwrap();
        assert!(registry.check(&sha, "0.89.0", Some(&as_vk)).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
