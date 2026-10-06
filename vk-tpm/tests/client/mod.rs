//! The caller's side of authorization sessions (what a TSS does), written from Part 1 apart
//! from vk-tpm's own code: it computes the command HMACs and parameter encryption, and checks
//! the TPM's response HMACs. Each TPM has its own session (its own nonces and key), so the
//! differential tests drive one per engine and compare what the responses say.

use aes::cipher::KeyIvInit;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

pub const SHA1: u16 = 0x04;
pub const SHA256: u16 = 0x0b;
pub const SHA384: u16 = 0x0c;
pub const SHA512: u16 = 0x0d;

pub const CONTINUE: u8 = 0x01;
pub const AUDIT_EXCLUSIVE: u8 = 0x02;
pub const AUDIT_RESET: u8 = 0x04;
pub const DECRYPT: u8 = 0x20;
pub const ENCRYPT: u8 = 0x40;
pub const AUDIT: u8 = 0x80;

const RS_PW: u32 = 0x4000_0009;

pub fn digest(alg: u16, parts: &[&[u8]]) -> Vec<u8> {
    fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
        let mut d = D::new();
        parts.iter().for_each(|p| d.update(p));
        d.finalize().to_vec()
    }
    match alg {
        SHA1 => run::<Sha1>(parts),
        SHA256 => run::<Sha256>(parts),
        SHA384 => run::<Sha384>(parts),
        SHA512 => run::<Sha512>(parts),
        _ => panic!("hash {alg:#x}"),
    }
}

pub fn hmac(alg: u16, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    macro_rules! run {
        ($d:ty) => {{
            let mut m = <Hmac<$d> as KeyInit>::new_from_slice(key).unwrap();
            parts.iter().for_each(|p| m.update(p));
            m.finalize().into_bytes().to_vec()
        }};
    }
    match alg {
        SHA1 => run!(Sha1),
        SHA256 => run!(Sha256),
        SHA384 => run!(Sha384),
        SHA512 => run!(Sha512),
        _ => panic!("hash {alg:#x}"),
    }
}

/// KDFa (Part 1, 11.4.10.2), `bytes` long, `label` without its terminating zero.
pub fn kdfa(alg: u16, key: &[u8], label: &str, u: &[u8], v: &[u8], bytes: usize) -> Vec<u8> {
    let bits = (bytes as u32 * 8).to_be_bytes();
    let mut out = Vec::new();
    let mut counter = 0u32;
    while out.len() < bytes {
        counter += 1;
        let block = hmac(
            alg,
            key,
            &[&counter.to_be_bytes(), label.as_bytes(), &[0], u, v, &bits],
        );
        out.extend_from_slice(&block);
    }
    out.truncate(bytes);
    out
}

/// KDFe (SP 800-56A, Part 1 11.4.10.3): `bytes` of H(counter ‖ Z ‖ label ‖ U ‖ V), `label` with
/// its terminating zero.
pub fn kdfe(alg: u16, z: &[u8], label: &[u8], u: &[u8], v: &[u8], bytes: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter = 0u32;
    while out.len() < bytes {
        counter += 1;
        out.extend_from_slice(&digest(alg, &[&counter.to_be_bytes(), z, label, u, v]));
    }
    out.truncate(bytes);
    out
}

/// A session's parameter encryption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sym {
    Null,
    Xor,
    /// AES-CFB with this many key bits.
    Aes(u16),
}

impl Sym {
    /// Its TPMT_SYM_DEF, as TPM2_StartAuthSession takes it.
    pub fn marshal(self, xor_hash: u16) -> Vec<u8> {
        match self {
            Sym::Null => vec![0, 0x10],
            Sym::Xor => [&[0, 0x0a][..], &xor_hash.to_be_bytes()].concat(),
            Sym::Aes(bits) => [&[0, 0x06][..], &bits.to_be_bytes(), &[0, 0x43]].concat(),
        }
    }
}

/// One TPM's session, as the caller tracks it.
#[derive(Clone, Debug)]
pub struct Session {
    pub handle: u32,
    pub hash: u16,
    pub key: Vec<u8>,
    pub nonce_tpm: Vec<u8>,
    pub sym: Sym,
}

impl Session {
    /// From TPM2_StartAuthSession's response (handle, nonceTPM), with the authValue of the bind
    /// entity (None: unbound) and no salt.
    pub fn started(
        response: &[u8],
        hash: u16,
        nonce_caller: &[u8],
        sym: Sym,
        bind: Option<&[u8]>,
    ) -> Session {
        Session::salted(response, hash, nonce_caller, sym, bind, &[])
    }

    /// As [`Session::started`], with a salt: the session key is KDFa of the bind authValue ‖
    /// the salt.
    pub fn salted(
        response: &[u8],
        hash: u16,
        nonce_caller: &[u8],
        sym: Sym,
        bind: Option<&[u8]>,
        salt: &[u8],
    ) -> Session {
        let handle = u32::from_be_bytes(response[10..14].try_into().unwrap());
        let size = u16::from_be_bytes([response[14], response[15]]) as usize;
        let nonce_tpm = response[16..16 + size].to_vec();
        let key = if bind.is_none() && salt.is_empty() {
            Vec::new()
        } else {
            let secret = [strip(bind.unwrap_or_default()), salt].concat();
            let size = digest(hash, &[]).len();
            kdfa(hash, &secret, "ATH", &nonce_tpm, nonce_caller, size)
        };
        Session {
            handle,
            hash,
            key,
            nonce_tpm,
            sym,
        }
    }

    /// Encrypt (or decrypt) a parameter's contents; `extra` is the authValue of the entity the
    /// session authorizes, the nonces newer first.
    fn crypt(&self, extra: &[u8], newer: &[u8], older: &[u8], data: &mut [u8], encrypt: bool) {
        let key = [&self.key[..], strip(extra)].concat();
        match self.sym {
            // The TPM refuses it (TPM_RC_SYMMETRIC): send the parameter as it is.
            Sym::Null => {}
            Sym::Xor => {
                let mask = kdfa(self.hash, &key, "XOR", newer, older, data.len());
                data.iter_mut().zip(mask).for_each(|(d, m)| *d ^= m);
            }
            Sym::Aes(bits) => {
                let n = bits as usize / 8;
                let stream = kdfa(self.hash, &key, "CFB", newer, older, n + 16);
                let (k, iv) = stream.split_at(n);
                aes_cfb(k, iv, data, encrypt);
            }
        }
    }
}

/// AES-CFB, in place; the key's length picks AES-128, -192 or -256.
pub fn aes_cfb(key: &[u8], iv: &[u8], data: &mut [u8], encrypt: bool) {
    macro_rules! cfb {
        ($aes:ty) => {
            if encrypt {
                cfb_mode::Encryptor::<$aes>::new_from_slices(key, iv)
                    .unwrap()
                    .encrypt(data)
            } else {
                cfb_mode::Decryptor::<$aes>::new_from_slices(key, iv)
                    .unwrap()
                    .decrypt(data)
            }
        };
    }
    match key.len() {
        16 => cfb!(aes::Aes128),
        24 => cfb!(aes::Aes192),
        _ => cfb!(aes::Aes256),
    }
}

/// A password's or an authValue's significant bytes.
pub fn strip(auth: &[u8]) -> &[u8] {
    let end = auth.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &auth[..end]
}

/// One entry of a command's authorization area.
#[derive(Clone)]
pub enum Auth {
    Password(Vec<u8>),
    /// Session `index` (in the caller's list), with these attributes. `entity` is the authValue
    /// of the entity it authorizes (None if it authorizes nothing), `bound` that the session is
    /// bound to it, `after` the authValue the entity has once the command ran (it changed).
    Session {
        index: usize,
        attributes: u8,
        entity: Option<Vec<u8>>,
        bound: bool,
        after: Option<Vec<u8>>,
        /// Send this HMAC instead of the right one.
        hmac: Option<Vec<u8>>,
    },
}

impl Auth {
    pub fn session(index: usize, attributes: u8, entity: Option<&[u8]>) -> Auth {
        Auth::Session {
            index,
            attributes,
            entity: entity.map(<[u8]>::to_vec),
            bound: false,
            after: None,
            hmac: None,
        }
    }
}

/// A command, before authorization.
pub struct Command {
    pub code: u32,
    pub handles: Vec<u32>,
    /// The Names of the handles (a sequence's is empty).
    pub names: Vec<Vec<u8>>,
    pub params: Vec<u8>,
    pub auths: Vec<Auth>,
    /// The command returns a handle.
    pub response_handle: bool,
}

impl Command {
    pub fn new(code: u32, handles: &[u32], params: &[u8], auths: Vec<Auth>) -> Command {
        Command {
            code,
            handles: handles.to_vec(),
            names: handles.iter().map(|h| h.to_be_bytes().to_vec()).collect(),
            params: params.to_vec(),
            auths,
            response_handle: false,
        }
    }
}

/// What a response says, its first parameter decrypted.
#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    pub rc: u32,
    pub handle: Option<u32>,
    pub params: Vec<u8>,
    pub attributes: Vec<u8>,
}

/// Build `cmd` for one TPM, whose sessions are `sessions`, with `nonce_caller` for each.
/// Returns the command bytes, and what checking the response needs.
pub fn build(cmd: &Command, sessions: &[Session], nonce_caller: &[u8]) -> Vec<u8> {
    let mut params = cmd.params.clone();
    // The first parameter, encrypted by the session that decrypts.
    for auth in &cmd.auths {
        if let Auth::Session {
            index,
            attributes,
            entity,
            ..
        } = auth
            && attributes & DECRYPT != 0
        {
            let s = &sessions[*index];
            let size = u16::from_be_bytes([params[0], params[1]]) as usize;
            let extra = entity.as_deref().unwrap_or_default();
            s.crypt(
                extra,
                nonce_caller,
                &s.nonce_tpm,
                &mut params[2..2 + size],
                true,
            );
        }
    }
    let mut parts: Vec<&[u8]> = Vec::new();
    let code = cmd.code.to_be_bytes();
    parts.push(&code);
    for name in &cmd.names {
        parts.push(name);
    }
    parts.push(&params);
    // The nonces the first session's HMAC adds: those of the decrypt and encrypt sessions.
    let nonce_of = |flag: u8| {
        cmd.auths.iter().enumerate().find_map(|(i, a)| match a {
            Auth::Session {
                index, attributes, ..
            } if attributes & flag != 0 => Some((i, sessions[*index].nonce_tpm.clone())),
            _ => None,
        })
    };
    let (decrypt, encrypt) = (nonce_of(DECRYPT), nonce_of(ENCRYPT));
    let mut area = Vec::new();
    for (i, auth) in cmd.auths.iter().enumerate() {
        match auth {
            Auth::Password(pw) => {
                area.extend_from_slice(&RS_PW.to_be_bytes());
                area.extend_from_slice(&[0, 0, 0]);
                area.extend_from_slice(&(pw.len() as u16).to_be_bytes());
                area.extend_from_slice(pw);
            }
            Auth::Session {
                index,
                attributes,
                entity,
                bound,
                hmac: forced,
                ..
            } => {
                let s = &sessions[*index];
                let cp_hash = digest(s.hash, &parts);
                let mut extra: Vec<Vec<u8>> = Vec::new();
                if i == 0 && entity.is_some() {
                    if let Some((j, nonce)) = &decrypt
                        && *j != 0
                    {
                        extra.push(nonce.clone());
                    }
                    if let Some((j, nonce)) = &encrypt
                        && *j != 0
                        && decrypt.as_ref().map(|d| d.0) != Some(*j)
                    {
                        extra.push(nonce.clone());
                    }
                }
                let key = [
                    &s.key[..],
                    if *bound {
                        &[]
                    } else {
                        strip(entity.as_deref().unwrap_or_default())
                    },
                ]
                .concat();
                let mut hmac_parts: Vec<&[u8]> = vec![&cp_hash, nonce_caller, &s.nonce_tpm];
                extra.iter().for_each(|e| hmac_parts.push(e));
                let attrs = [*attributes];
                hmac_parts.push(&attrs);
                let mac = match forced {
                    Some(mac) => mac.clone(),
                    None if key.is_empty() => Vec::new(),
                    None => hmac(s.hash, &key, &hmac_parts),
                };
                area.extend_from_slice(&s.handle.to_be_bytes());
                area.extend_from_slice(&(nonce_caller.len() as u16).to_be_bytes());
                area.extend_from_slice(nonce_caller);
                area.push(*attributes);
                area.extend_from_slice(&(mac.len() as u16).to_be_bytes());
                area.extend_from_slice(&mac);
            }
        }
    }
    let mut c = Vec::new();
    c.extend_from_slice(&0x8002u16.to_be_bytes());
    c.extend_from_slice(&[0; 4]);
    c.extend_from_slice(&code);
    for h in &cmd.handles {
        c.extend_from_slice(&h.to_be_bytes());
    }
    c.extend_from_slice(&(area.len() as u32).to_be_bytes());
    c.extend_from_slice(&area);
    c.extend_from_slice(&params);
    let len = c.len() as u32;
    c[2..6].copy_from_slice(&len.to_be_bytes());
    c
}

/// Check `response` to `cmd`: each session's HMAC, the new nonces (kept in `sessions`), and
/// the first parameter decrypted. Sessions that did not continue are removed from nothing:
/// the caller knows.
pub fn check(
    cmd: &Command,
    sessions: &mut [Session],
    nonce_caller: &[u8],
    response: &[u8],
) -> Response {
    let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
    if rc != 0 {
        assert_eq!(response.len(), 10);
        return Response {
            rc,
            handle: None,
            params: Vec::new(),
            attributes: Vec::new(),
        };
    }
    let mut at = 10;
    let handle = cmd.response_handle.then(|| {
        at += 4;
        u32::from_be_bytes(response[10..14].try_into().unwrap())
    });
    let size = u32::from_be_bytes(response[at..at + 4].try_into().unwrap()) as usize;
    at += 4;
    let mut params = response[at..at + size].to_vec();
    at += size;
    let mut attributes = Vec::new();
    for auth in &cmd.auths {
        let nonce_size = u16::from_be_bytes([response[at], response[at + 1]]) as usize;
        let nonce = response[at + 2..at + 2 + nonce_size].to_vec();
        at += 2 + nonce_size;
        let attrs = response[at];
        attributes.push(attrs);
        at += 1;
        let mac_size = u16::from_be_bytes([response[at], response[at + 1]]) as usize;
        let mac = &response[at + 2..at + 2 + mac_size];
        at += 2 + mac_size;
        match auth {
            Auth::Password(_) => assert!(nonce.is_empty() && mac.is_empty()),
            Auth::Session {
                index,
                entity,
                bound,
                after,
                hmac: forced,
                ..
            } => {
                let s = &mut sessions[*index];
                // Whether the command's HMAC was empty: the response's is then empty too
                // if its key is.
                let command_key = !s.key.is_empty()
                    || (!*bound && !strip(entity.as_deref().unwrap_or_default()).is_empty());
                let sent_empty = forced.as_ref().map_or(!command_key, Vec::is_empty);
                assert_eq!(nonce.len(), s.nonce_tpm.len(), "nonceTPM keeps its size");
                assert_ne!(nonce, s.nonce_tpm, "a new nonceTPM");
                s.nonce_tpm = nonce;
                let entity = after.as_ref().or(entity.as_ref());
                let auth = if *bound {
                    &[][..]
                } else {
                    strip(entity.map(Vec::as_slice).unwrap_or_default())
                };
                let key = [&s.key[..], auth].concat();
                let rp_hash = digest(s.hash, &[&[0; 4], &cmd.code.to_be_bytes(), &params]);
                let expected = if key.is_empty() && sent_empty {
                    Vec::new()
                } else {
                    hmac(
                        s.hash,
                        &key,
                        &[&rp_hash, &s.nonce_tpm, nonce_caller, &[attrs]],
                    )
                };
                assert_eq!(mac, &expected[..], "the response HMAC");
            }
        }
    }
    assert_eq!(at, response.len());
    for auth in &cmd.auths {
        if let Auth::Session {
            index,
            attributes,
            entity,
            after,
            ..
        } = auth
            && attributes & ENCRYPT != 0
        {
            let s = &sessions[*index];
            let size = u16::from_be_bytes([params[0], params[1]]) as usize;
            let extra = after.as_ref().or(entity.as_ref()).map(Vec::as_slice);
            let nonce_tpm = s.nonce_tpm.clone();
            s.crypt(
                extra.unwrap_or_default(),
                &nonce_tpm,
                nonce_caller,
                &mut params[2..2 + size],
                false,
            );
        }
    }
    Response {
        rc,
        handle,
        params,
        attributes,
    }
}
