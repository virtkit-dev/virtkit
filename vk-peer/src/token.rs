//! Signing and checking registry tokens ([`vk_hub_proto::token`]): the hub signs with a key
//! of its own, and a registry checks against the public keys the hub sent it.

use std::path::Path;

use anyhow::{Result, bail};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use sha2::{Digest, Sha256};
use vk_hub_proto::token::{self, Claims, TokenKey};

/// A token-signing key, held by the hub: its own key, never a release key, which stays off
/// the hub. It is stored as a release key is, PKCS#8 v2 in a `0600` file.
pub struct Signer {
    key: Ed25519KeyPair,
    public: TokenKey,
}

impl Signer {
    /// A new key at `path`, `0600`, never over an existing file.
    pub fn generate(path: &Path) -> Result<Self> {
        crate::release_key::generate(path)?;
        Self::load(path)
    }

    /// The key at `path`, as [`Signer::generate`] writes it.
    pub fn load(path: &Path) -> Result<Self> {
        Ok(Self::from_key(crate::release_key::load(path)?))
    }

    fn from_key(key: Ed25519KeyPair) -> Self {
        let public = public_key(key.public_key().as_ref());
        Self { key, public }
    }

    /// The key's public half, as registries get it.
    pub fn public(&self) -> &TokenKey {
        &self.public
    }

    /// A token for `claims`, with this key's `kid`. Reject malformed claims here
    /// rather than minting a token a registry would refuse.
    pub fn sign(&self, mut claims: Claims) -> Result<String> {
        claims.kid.clone_from(&self.public.kid);
        if !claims.well_formed() {
            bail!("refusing to sign malformed token claims for {}", claims.sub);
        }
        let part = token::claims_part(&claims);
        let signature = self.key.sign(&token::signed_message(&part));
        let token = token::assemble(&part, signature.as_ref());
        if token.len() > token::MAX_TOKEN_LEN {
            bail!(
                "a token for {} would be {} bytes, over {}",
                claims.sub,
                token.len(),
                token::MAX_TOKEN_LEN
            );
        }
        Ok(token)
    }
}

/// The [`TokenKey`] for a raw ed25519 public key.
pub fn public_key(raw: &[u8]) -> TokenKey {
    TokenKey {
        kid: token::key_id(&Sha256::digest(raw).into()),
        public_key: vk_hub_proto::to_base64(raw),
    }
}

/// Why a token was refused. The registry answers each the same way; the reason is for its
/// log.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    Malformed,
    UnknownKey,
    BadSignature,
    WrongAudience,
    Expired,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Refused::Malformed => "malformed",
            Refused::UnknownKey => "signed by an unknown key",
            Refused::BadSignature => "bad signature",
            Refused::WrongAudience => "for another registry",
            Refused::Expired => "expired",
        })
    }
}

impl std::error::Error for Refused {}

/// The claims of `token` if it is signed by one of `keys`, for the registry `aud`, and live
/// at `now`. `keys` must have unique kids, which their consumer enforces when it applies them:
/// only the first with the token's kid is tried.
pub fn verify(token: &str, keys: &[TokenKey], aud: &str, now: u64) -> Result<Claims, Refused> {
    let parsed = token::parse(token).ok_or(Refused::Malformed)?;
    let key = keys
        .iter()
        .find(|k| k.kid == parsed.claims.kid)
        .ok_or(Refused::UnknownKey)?;
    // Treat an undecodable key as unknown: it cannot verify a token.
    let raw = vk_hub_proto::from_base64(&key.public_key)
        .filter(|raw| raw.len() == 32)
        .ok_or(Refused::UnknownKey)?;
    UnparsedPublicKey::new(&ED25519, raw)
        .verify(
            &token::signed_message(&parsed.claims_part),
            &parsed.signature,
        )
        .map_err(|_| Refused::BadSignature)?;
    if parsed.claims.aud != aud {
        return Err(Refused::WrongAudience);
    }
    if !parsed.claims.live_at(now) {
        return Err(Refused::Expired);
    }
    Ok(parsed.claims)
}

/// A fresh token ID.
pub fn new_jti() -> Result<String> {
    let mut b = [0u8; vk_hub_proto::ID_BYTES];
    crate::fill_random(&mut b)?;
    Ok(vk_hub_proto::to_hex(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vk_hub_proto::token::Grant;

    const AUD: &str = "9c2f4e1a7b3d5e60f1a2b3c4d5e6f708";

    fn claims() -> Claims {
        Claims {
            kid: String::new(),
            aud: AUD.into(),
            sub: "job:j1".into(),
            jti: new_jti().unwrap(),
            pipeline: None,
            iat: 1000,
            exp: 2000,
            grants: vec![Grant {
                prefix: "p/gl/42".into(),
                read: true,
                ..Grant::default()
            }],
        }
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-token-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir); // a leftover of an earlier run, if any
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn signer(dir: &Path, name: &str) -> Signer {
        Signer::generate(&dir.join(name)).unwrap()
    }

    #[test]
    fn a_signed_token_verifies_against_its_key_only() {
        let dir = scratch("keys");
        let a = signer(&dir, "a");
        let b = signer(&dir, "b");
        let token = a.sign(claims()).unwrap();
        let got = verify(&token, &[b.public().clone(), a.public().clone()], AUD, 1500);
        assert_eq!(got.unwrap().kid, a.public().kid);
        assert_eq!(
            verify(&token, &[b.public().clone()], AUD, 1500),
            Err(Refused::UnknownKey)
        );
        let forged = TokenKey {
            kid: a.public().kid.clone(),
            public_key: b.public().public_key.clone(),
        };
        assert_eq!(
            verify(&token, &[forged], AUD, 1500),
            Err(Refused::BadSignature)
        );
    }

    #[test]
    fn a_token_from_a_fixed_key_is_pinned() {
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let signer = Signer::from_key(key);
        let claims = Claims {
            jti: "a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4".into(),
            ..claims()
        };
        let token = signer.sign(claims).unwrap();
        assert_eq!(
            token,
            concat!(
                "vkt_eyJraWQiOiJmZTgxMmMxMmYzYWI0Y2U2YWM1ZGI2OWFjMzUyZjkwNiIsImF1ZCI6IjljMmY0ZTFh",
                "N2IzZDVlNjBmMWEyYjNjNGQ1ZTZmNzA4Iiwic3ViIjoiam9iOmoxIiwianRpIjoiYTFiMmMzZDRhMWIy",
                "YzNkNGExYjJjM2Q0YTFiMmMzZDQiLCJpYXQiOjEwMDAsImV4cCI6MjAwMCwiZ3JhbnRzIjpbeyJwcmVm",
                "aXgiOiJwL2dsLzQyIiwicmVhZCI6dHJ1ZX1dfQ",
                ".YO73aTvDxyyy8ZM_XABVh30D9_qlaeODClCXjQUagUoqqp9q_zwmxb5GR07-wen1HtFTVKAO9IpBgAWIbL8dBg",
            )
        );
        assert_eq!(signer.public().kid, "fe812c12f3ab4ce6ac5db69ac352f906");
        assert!(verify(&token, &[signer.public().clone()], AUD, 1500).is_ok());
    }

    #[test]
    fn a_future_iat_is_accepted() {
        let dir = scratch("iat");
        let a = signer(&dir, "a");
        // A registry clock behind the hub's sees `iat` in the future: accepted, since `exp`
        // alone bounds the token's life.
        let token = a.sign(claims()).unwrap();
        assert!(verify(&token, &[a.public().clone()], AUD, 500).is_ok());
    }

    #[test]
    fn audience_expiry_and_tampering_are_refused() {
        let dir = scratch("claims");
        let a = signer(&dir, "a");
        let keys = [a.public().clone()];
        let token = a.sign(claims()).unwrap();
        assert_eq!(
            verify(&token, &keys, "00000000000000000000000000000000", 1500),
            Err(Refused::WrongAudience)
        );
        assert_eq!(
            verify(&token, &keys, AUD, 2000 + token::SKEW_SECS + 1),
            Err(Refused::Expired)
        );
        let mut wider = claims();
        wider.grants[0].write = true;
        let (_, sig) = token.split_once('.').unwrap();
        let tampered = format!(
            "{}{}.{sig}",
            token::TOKEN_PREFIX,
            token::claims_part(&Claims {
                kid: a.public().kid.clone(),
                ..wider
            })
        );
        assert_eq!(
            verify(&tampered, &keys, AUD, 1500),
            Err(Refused::BadSignature)
        );
        assert_eq!(verify("vkt_x.y", &keys, AUD, 1500), Err(Refused::Malformed));
    }
}
