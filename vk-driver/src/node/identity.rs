//! The node's ed25519 identity: a PKCS#8 key under `<state_dir>/node/`, created `0600` and
//! never replaced. The hub pins its public half at enrollment, so losing or replacing the
//! file means enrolling again as a new node.

use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use ring::signature::{Ed25519KeyPair, KeyPair};

const KEY_FILE: &str = "key.pk8";

/// A PKCS#8 ed25519 key is under 100 bytes; this only bounds what a wrong file costs to read.
const MAX_KEY_FILE: u64 = 4096;

pub struct Identity {
    key: Ed25519KeyPair,
}

impl Identity {
    /// The identity in `dir`, generated there first if there is none.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        let path = dir.join(KEY_FILE);
        match Self::load(dir) {
            Ok(identity) => return Ok(identity),
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
            Err(e) => return Err(e),
        }
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| anyhow!("generating the node's ed25519 key"))?;
        // Private from the moment it exists, and published whole by `rename`.
        vk_fs::write_atomic(&path, pkcs8.as_ref(), 0o600)
            .with_context(|| format!("writing {}", path.display()))?;
        Self::load(dir)
    }

    /// The identity in `dir`. A missing key is an `io::Error` of kind `NotFound` at the root
    /// of the chain, so a caller can tell "not enrolled" from "unreadable".
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(KEY_FILE);
        // `O_NOFOLLOW` and the mode judged off the descriptor: a key file swapped for a link,
        // or one others can read, is not this node's secret any more. Its owner is left to
        // the directory, which `vk node` requires be this user's alone.
        let mut file = std::fs::File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| anyhow::Error::new(e).context(format!("opening {}", path.display())))?;
        let mode = file
            .metadata()
            .with_context(|| format!("statting {}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            bail!(
                "{} has mode {:o}: the node's private key must be readable by its owner only \
                 (chmod 600)",
                path.display(),
                mode & 0o7777
            );
        }
        let mut pkcs8 = Vec::new();
        (&mut file)
            .take(MAX_KEY_FILE)
            .read_to_end(&mut pkcs8)
            .with_context(|| format!("reading {}", path.display()))?;
        let key = Ed25519KeyPair::from_pkcs8(&pkcs8)
            .map_err(|e| anyhow!("{} is not an ed25519 PKCS#8 key: {e}", path.display()))?;
        Ok(Identity { key })
    }

    pub fn public_key(&self) -> &[u8] {
        self.key.public_key().as_ref()
    }

    /// `message` signed, as hex.
    pub fn sign(&self, message: &[u8]) -> String {
        vk_hub_proto::to_hex(self.key.sign(message).as_ref())
    }
}

/// Where the key lives, for messages that name it.
pub fn key_path(dir: &Path) -> PathBuf {
    dir.join(KEY_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-node-id-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_key_is_created_private_once_and_then_reused() {
        let dir = scratch("create");
        assert!(Identity::load(&dir).is_err());
        let first = Identity::load_or_create(&dir).unwrap();
        let mode = std::fs::metadata(key_path(&dir))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let again = Identity::load_or_create(&dir).unwrap();
        assert_eq!(first.public_key(), again.public_key());
        // What it signs verifies against its public half.
        let signature = vk_hub_proto::from_hex(&first.sign(b"m")).unwrap();
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, first.public_key())
            .verify(b"m", &signature)
            .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_key_others_can_read_or_a_symlink_is_refused() {
        let dir = scratch("refuse");
        Identity::load_or_create(&dir).unwrap();
        let path = key_path(&dir);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let Err(err) = Identity::load(&dir) else {
            panic!("a group-readable key was loaded");
        };
        assert!(format!("{err:#}").contains("owner only"), "{err:#}");
        // Not regenerated over either: the pinned identity is the operator's to fix.
        assert!(Identity::load_or_create(&dir).is_err());
        std::fs::rename(&path, dir.join("real")).unwrap();
        std::os::unix::fs::symlink(dir.join("real"), &path).unwrap();
        assert!(Identity::load(&dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
