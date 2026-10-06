//! An object's public and sensitive areas (Part 2: TPMT_PUBLIC, TPMT_SENSITIVE): their wire
//! format, the Name, and the rules on attributes and schemes every object follows
//! (`Object_spt.c`: CreateChecks, PublicAttributesValidation, SchemeChecks).
//!
//! Unmarshalling answers as the reference implementation does, code for code, for everything
//! libtpms' `default-v1` profile accepts, with these exceptions, refused where the reference
//! would accept them: curves other than NIST P-256 (TPM_RC_CURVE), and TDES, Camellia and SM4
//! (TPM_RC_SYMMETRIC). Schemes vk-tpm cannot run (ECDAA, SM2, EC-Schnorr, ECMQV, KDF2, CMAC...)
//! are only identifiers here, accepted as the reference does; using one fails where it is used.

use zeroize::Zeroizing;

use crate::alg::{Hash, MAX_DIGEST, TPM_ALG_NULL};
use crate::marshal::{Reader, Writer};
use crate::rc::{Rc, Result};

pub const TPM_ALG_RSA: u16 = 0x0001;
pub const TPM_ALG_HMAC: u16 = 0x0005;
pub const TPM_ALG_AES: u16 = 0x0006;
pub const TPM_ALG_MGF1: u16 = 0x0007;
pub const TPM_ALG_KEYEDHASH: u16 = 0x0008;
pub const TPM_ALG_XOR: u16 = 0x000a;
pub const TPM_ALG_RSASSA: u16 = 0x0014;
pub const TPM_ALG_RSAES: u16 = 0x0015;
pub const TPM_ALG_RSAPSS: u16 = 0x0016;
pub const TPM_ALG_OAEP: u16 = 0x0017;
pub const TPM_ALG_ECDSA: u16 = 0x0018;
pub const TPM_ALG_ECDH: u16 = 0x0019;
pub const TPM_ALG_ECDAA: u16 = 0x001a;
pub const TPM_ALG_SM2: u16 = 0x001b;
pub const TPM_ALG_ECSCHNORR: u16 = 0x001c;
pub const TPM_ALG_ECMQV: u16 = 0x001d;
pub const TPM_ALG_KDF1_SP800_56A: u16 = 0x0020;
pub const TPM_ALG_KDF2: u16 = 0x0021;
pub const TPM_ALG_KDF1_SP800_108: u16 = 0x0022;
pub const TPM_ALG_ECC: u16 = 0x0023;
pub const TPM_ALG_SYMCIPHER: u16 = 0x0025;
pub const TPM_ALG_CMAC: u16 = 0x003f;
pub const TPM_ALG_CTR: u16 = 0x0040;
pub const TPM_ALG_OFB: u16 = 0x0041;
pub const TPM_ALG_CBC: u16 = 0x0042;
pub const TPM_ALG_CFB: u16 = 0x0043;
pub const TPM_ALG_ECB: u16 = 0x0044;

pub const TPM_ECC_NIST_P256: u16 = 0x0003;

/// TPMA_OBJECT bits.
pub mod attr {
    pub const FIXED_TPM: u32 = 1 << 1;
    pub const ST_CLEAR: u32 = 1 << 2;
    pub const FIXED_PARENT: u32 = 1 << 4;
    pub const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
    pub const USER_WITH_AUTH: u32 = 1 << 6;
    pub const ADMIN_WITH_POLICY: u32 = 1 << 7;
    pub const FIRMWARE_LIMITED: u32 = 1 << 8;
    pub const SVN_LIMITED: u32 = 1 << 9;
    pub const NO_DA: u32 = 1 << 10;
    pub const ENCRYPTED_DUPLICATION: u32 = 1 << 11;
    pub const RESTRICTED: u32 = 1 << 16;
    pub const DECRYPT: u32 = 1 << 17;
    pub const SIGN: u32 = 1 << 18;
    pub const X509_SIGN: u32 = 1 << 19;
    /// The bits the reference refuses with TPM_RC_RESERVED_BITS.
    pub const RESERVED: u32 = 0xfff0_f009;
}

/// TPM2B_PUBLIC_KEY_RSA: an RSA-4096 modulus (MAX_RSA_KEY_BYTES), though RSA-3072 is the largest
/// key the TPM takes.
pub const MAX_RSA_KEY_BYTES: usize = 512;
/// TPM2B_PRIVATE_KEY_RSA (RSA_PRIVATE_SIZE: five half-size values).
const MAX_RSA_PRIVATE: usize = MAX_RSA_KEY_BYTES / 2 * 5;
/// TPM2B_ECC_PARAMETER: sized for the reference's largest curve (BN P638).
pub const MAX_ECC_KEY_BYTES: usize = 80;
/// TPM2B_SENSITIVE_DATA (MAX_SYM_DATA).
pub const MAX_SYM_DATA: usize = 128;
/// TPM2B_SYM_KEY (MAX_SYM_KEY_BYTES).
const MAX_SYM_KEY: usize = 32;

/// An object's type (TPMI_ALG_PUBLIC).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    Rsa,
    KeyedHash,
    Ecc,
    SymCipher,
}

impl Type {
    pub fn id(self) -> u16 {
        match self {
            Type::Rsa => TPM_ALG_RSA,
            Type::KeyedHash => TPM_ALG_KEYEDHASH,
            Type::Ecc => TPM_ALG_ECC,
            Type::SymCipher => TPM_ALG_SYMCIPHER,
        }
    }

    pub fn read(r: &mut Reader) -> Result<Type> {
        match r.u16()? {
            TPM_ALG_RSA => Ok(Type::Rsa),
            TPM_ALG_KEYEDHASH => Ok(Type::KeyedHash),
            TPM_ALG_ECC => Ok(Type::Ecc),
            TPM_ALG_SYMCIPHER => Ok(Type::SymCipher),
            _ => Err(Rc::TYPE),
        }
    }

    pub fn is_asymmetric(self) -> bool {
        matches!(self, Type::Rsa | Type::Ecc)
    }
}

/// A TPMT_SYM_DEF_OBJECT that is not TPM_ALG_NULL: AES, the only block cipher implemented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SymDef {
    pub bits: u16,
    /// A TPMI_ALG_SYM_MODE+ (TPM_ALG_NULL allowed).
    pub mode: u16,
}

impl SymDef {
    /// A TPMT_SYM_DEF_OBJECT; with `allow_null`, TPM_ALG_NULL is None.
    pub fn read(r: &mut Reader, allow_null: bool) -> Result<Option<SymDef>> {
        match r.u16()? {
            TPM_ALG_AES => {}
            TPM_ALG_NULL if allow_null => return Ok(None),
            _ => return Err(Rc::SYMMETRIC),
        }
        let bits = match r.u16()? {
            bits @ (128 | 192 | 256) => bits,
            _ => return Err(Rc::VALUE),
        };
        let mode = r.u16()?;
        if !(mode == TPM_ALG_NULL || mode == TPM_ALG_CMAC || is_block_mode(mode)) {
            return Err(Rc::MODE);
        }
        Ok(Some(SymDef { bits, mode }))
    }

    pub fn write(def: Option<SymDef>, w: &mut Writer) {
        match def {
            Some(d) => w.u16(TPM_ALG_AES).u16(d.bits).u16(d.mode),
            None => w.u16(TPM_ALG_NULL),
        };
    }

    pub fn key_bytes(self) -> usize {
        usize::from(self.bits / 8)
    }
}

/// CryptSymModeIsValid: a block cipher mode (not a MAC).
pub fn is_block_mode(mode: u16) -> bool {
    matches!(
        mode,
        TPM_ALG_CTR | TPM_ALG_OFB | TPM_ALG_CBC | TPM_ALG_CFB | TPM_ALG_ECB
    )
}

/// A scheme: TPMT_KEYEDHASH_SCHEME, TPMT_RSA_SCHEME, TPMT_ECC_SCHEME, TPMT_KDF_SCHEME,
/// TPMT_SIG_SCHEME or TPMT_RSA_DECRYPT. `hash` is the details' hash algorithm, None where the
/// scheme has none (TPM_ALG_NULL, RSAES); `extra` is ECDAA's count or the XOR scheme's KDF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scheme {
    pub alg: u16,
    pub hash: Option<Hash>,
    pub extra: u16,
}

impl Scheme {
    pub const NULL: Scheme = Scheme {
        alg: TPM_ALG_NULL,
        hash: None,
        extra: 0,
    };

    pub fn is_null(&self) -> bool {
        self.alg == TPM_ALG_NULL
    }

    /// The scheme of an algorithm ID the caller validated: its details (TPMU_ASYM_SCHEME,
    /// TPMU_SIG_SCHEME, TPMU_KDF_SCHEME...) follow.
    fn read_details(alg: u16, r: &mut Reader) -> Result<Scheme> {
        let (hash, extra) = match alg {
            TPM_ALG_NULL | TPM_ALG_RSAES => (None, 0),
            TPM_ALG_ECDAA => (Some(Hash::read(r)?), r.u16()?),
            TPM_ALG_XOR => (Some(Hash::read(r)?), read_kdf_alg(r, true)?),
            _ => (Some(Hash::read(r)?), 0),
        };
        Ok(Scheme { alg, hash, extra })
    }

    pub fn write(&self, w: &mut Writer) {
        w.u16(self.alg);
        if let Some(hash) = self.hash {
            w.u16(hash.id());
        }
        match self.alg {
            TPM_ALG_ECDAA | TPM_ALG_XOR => {
                w.u16(self.extra);
            }
            _ => {}
        }
    }

    /// A TPMT_KEYEDHASH_SCHEME+ (HMAC or XOR).
    pub fn read_keyed_hash(r: &mut Reader) -> Result<Scheme> {
        let alg = r.u16()?;
        if !matches!(alg, TPM_ALG_HMAC | TPM_ALG_XOR | TPM_ALG_NULL) {
            return Err(Rc::VALUE);
        }
        Scheme::read_details(alg, r)
    }

    /// A TPMT_RSA_SCHEME+.
    pub fn read_rsa(r: &mut Reader) -> Result<Scheme> {
        let alg = r.u16()?;
        if !matches!(
            alg,
            TPM_ALG_RSASSA | TPM_ALG_RSAPSS | TPM_ALG_RSAES | TPM_ALG_OAEP | TPM_ALG_NULL
        ) {
            return Err(Rc::VALUE);
        }
        Scheme::read_details(alg, r)
    }

    /// A TPMT_RSA_DECRYPT+ (RSAES or OAEP).
    pub fn read_rsa_decrypt(r: &mut Reader) -> Result<Scheme> {
        let alg = r.u16()?;
        if !matches!(alg, TPM_ALG_RSAES | TPM_ALG_OAEP | TPM_ALG_NULL) {
            return Err(Rc::VALUE);
        }
        Scheme::read_details(alg, r)
    }

    /// A TPMT_ECC_SCHEME+.
    pub fn read_ecc(r: &mut Reader) -> Result<Scheme> {
        let alg = r.u16()?;
        if !(alg == TPM_ALG_NULL || is_ecc_scheme(alg)) {
            return Err(Rc::SCHEME);
        }
        Scheme::read_details(alg, r)
    }

    /// A TPMT_SIG_SCHEME, with `allow_null` TPMT_SIG_SCHEME+.
    pub fn read_sig(r: &mut Reader, allow_null: bool) -> Result<Scheme> {
        let alg = r.u16()?;
        if !(is_sig_scheme(alg) || (allow_null && alg == TPM_ALG_NULL)) {
            return Err(Rc::SCHEME);
        }
        Scheme::read_details(alg, r)
    }

    /// A TPMT_KDF_SCHEME+.
    pub fn read_kdf(r: &mut Reader) -> Result<Scheme> {
        let alg = read_kdf_alg(r, true)?;
        Scheme::read_details(alg, r)
    }
}

fn is_ecc_scheme(alg: u16) -> bool {
    matches!(
        alg,
        TPM_ALG_ECDSA
            | TPM_ALG_SM2
            | TPM_ALG_ECDAA
            | TPM_ALG_ECSCHNORR
            | TPM_ALG_ECDH
            | TPM_ALG_ECMQV
    )
}

/// TPMI_ALG_SIG_SCHEME.
pub fn is_sig_scheme(alg: u16) -> bool {
    matches!(
        alg,
        TPM_ALG_HMAC
            | TPM_ALG_RSASSA
            | TPM_ALG_RSAPSS
            | TPM_ALG_ECDSA
            | TPM_ALG_ECDAA
            | TPM_ALG_SM2
            | TPM_ALG_ECSCHNORR
    )
}

/// A TPMI_ALG_KDF.
fn read_kdf_alg(r: &mut Reader, allow_null: bool) -> Result<u16> {
    match r.u16()? {
        alg @ (TPM_ALG_MGF1 | TPM_ALG_KDF1_SP800_56A | TPM_ALG_KDF2 | TPM_ALG_KDF1_SP800_108) => {
            Ok(alg)
        }
        TPM_ALG_NULL if allow_null => Ok(TPM_ALG_NULL),
        _ => Err(Rc::KDF),
    }
}

/// A TPMI_ECC_CURVE: only NIST P-256 is implemented.
pub fn read_curve(r: &mut Reader) -> Result<u16> {
    match r.u16()? {
        TPM_ECC_NIST_P256 => Ok(TPM_ECC_NIST_P256),
        _ => Err(Rc::CURVE),
    }
}

/// What an object's type adds to its public area (TPMU_PUBLIC_PARMS).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Params {
    KeyedHash(Scheme),
    SymCipher(SymDef),
    Rsa {
        symmetric: Option<SymDef>,
        scheme: Scheme,
        bits: u16,
        /// 0 for the default, 65537.
        exponent: u32,
    },
    Ecc {
        symmetric: Option<SymDef>,
        scheme: Scheme,
        curve: u16,
        kdf: Scheme,
    },
}

impl Params {
    pub fn kind(&self) -> Type {
        match self {
            Params::KeyedHash(_) => Type::KeyedHash,
            Params::SymCipher(_) => Type::SymCipher,
            Params::Rsa { .. } => Type::Rsa,
            Params::Ecc { .. } => Type::Ecc,
        }
    }

    /// TPMU_PUBLIC_PARMS for `kind`.
    pub fn read(kind: Type, r: &mut Reader) -> Result<Params> {
        Ok(match kind {
            Type::KeyedHash => Params::KeyedHash(Scheme::read_keyed_hash(r)?),
            Type::SymCipher => Params::SymCipher(SymDef::read(r, false)?.ok_or(Rc::SYMMETRIC)?),
            Type::Rsa => Params::Rsa {
                symmetric: SymDef::read(r, true)?,
                scheme: Scheme::read_rsa(r)?,
                bits: match r.u16()? {
                    bits @ (1024 | 2048 | 3072) => bits,
                    _ => return Err(Rc::VALUE),
                },
                exponent: r.u32()?,
            },
            Type::Ecc => Params::Ecc {
                symmetric: SymDef::read(r, true)?,
                scheme: Scheme::read_ecc(r)?,
                curve: read_curve(r)?,
                kdf: Scheme::read_kdf(r)?,
            },
        })
    }

    pub fn write(&self, w: &mut Writer) {
        match self {
            Params::KeyedHash(scheme) => scheme.write(w),
            Params::SymCipher(def) => SymDef::write(Some(*def), w),
            Params::Rsa {
                symmetric,
                scheme,
                bits,
                exponent,
            } => {
                SymDef::write(*symmetric, w);
                scheme.write(w);
                w.u16(*bits).u32(*exponent);
            }
            Params::Ecc {
                symmetric,
                scheme,
                curve,
                kdf,
            } => {
                SymDef::write(*symmetric, w);
                scheme.write(w);
                w.u16(*curve);
                kdf.write(w);
            }
        }
    }

    /// An asymmetric key's symmetric algorithm (a storage parent's), or a symmetric key's.
    pub fn symmetric(&self) -> Option<SymDef> {
        match self {
            Params::Rsa { symmetric, .. } | Params::Ecc { symmetric, .. } => *symmetric,
            Params::SymCipher(def) => Some(*def),
            Params::KeyedHash(_) => None,
        }
    }

    /// The key's scheme (an asymmetric key's, or a keyed hash's).
    pub fn scheme(&self) -> Scheme {
        match self {
            Params::Rsa { scheme, .. } | Params::Ecc { scheme, .. } => *scheme,
            Params::KeyedHash(scheme) => *scheme,
            Params::SymCipher(_) => Scheme::NULL,
        }
    }
}

/// The public key or the digest that makes an object unique (TPMU_PUBLIC_ID).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unique {
    /// A keyed hash's or a symmetric key's: a digest of its seed and secret.
    Digest(Vec<u8>),
    /// An RSA modulus.
    Rsa(Vec<u8>),
    /// An ECC point.
    Ecc { x: Vec<u8>, y: Vec<u8> },
}

impl Unique {
    fn read(kind: Type, r: &mut Reader) -> Result<Unique> {
        Ok(match kind {
            Type::KeyedHash | Type::SymCipher => Unique::Digest(r.tpm2b(MAX_DIGEST)?.to_vec()),
            Type::Rsa => Unique::Rsa(r.tpm2b(MAX_RSA_KEY_BYTES)?.to_vec()),
            Type::Ecc => {
                let (x, y) = read_point(r)?;
                Unique::Ecc { x, y }
            }
        })
    }

    fn write(&self, w: &mut Writer) {
        match self {
            Unique::Digest(d) | Unique::Rsa(d) => {
                w.tpm2b(d);
            }
            Unique::Ecc { x, y } => {
                w.tpm2b(x).tpm2b(y);
            }
        }
    }
}

/// A TPMS_ECC_POINT.
pub fn read_point(r: &mut Reader) -> Result<(Vec<u8>, Vec<u8>)> {
    let x = r.tpm2b(MAX_ECC_KEY_BYTES)?.to_vec();
    let y = r.tpm2b(MAX_ECC_KEY_BYTES)?.to_vec();
    Ok((x, y))
}

/// A TPMT_PUBLIC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Public {
    /// None (TPM_ALG_NULL) only for an external key: it then has no Name.
    pub name_alg: Option<Hash>,
    pub attributes: u32,
    pub auth_policy: Vec<u8>,
    pub params: Params,
    pub unique: Unique,
}

impl Public {
    pub fn kind(&self) -> Type {
        self.params.kind()
    }

    pub fn has(&self, attribute: u32) -> bool {
        self.attributes & attribute != 0
    }

    /// A TPMT_PUBLIC; `allow_null_name`: its nameAlg may be TPM_ALG_NULL (TPM2_LoadExternal).
    pub fn read(r: &mut Reader, allow_null_name: bool) -> Result<Public> {
        let kind = Type::read(r)?;
        let name_alg = if allow_null_name {
            Hash::read_or_null(r)?
        } else {
            Some(Hash::read(r)?)
        };
        let attributes = r.u32()?;
        if attributes & attr::RESERVED != 0 {
            return Err(Rc::RESERVED_BITS);
        }
        let auth_policy = r.tpm2b(MAX_DIGEST)?.to_vec();
        let params = Params::read(kind, r)?;
        let unique = Unique::read(kind, r)?;
        Ok(Public {
            name_alg,
            attributes,
            auth_policy,
            params,
            unique,
        })
    }

    /// A TPM2B_PUBLIC. Its size must be exactly what the TPMT_PUBLIC takes, counted as the
    /// reference counts it: an error inside the structure comes first.
    pub fn read_sized(r: &mut Reader, allow_null_name: bool) -> Result<Public> {
        let size = usize::from(r.u16()?);
        if size == 0 {
            return Err(Rc::SIZE);
        }
        let before = r.len();
        let public = Public::read(r, allow_null_name)?;
        if before.saturating_sub(r.len()) != size {
            return Err(Rc::SIZE);
        }
        Ok(public)
    }

    pub fn write(&self, w: &mut Writer) {
        w.u16(self.kind().id())
            .u16(self.name_alg.map_or(TPM_ALG_NULL, Hash::id))
            .u32(self.attributes)
            .tpm2b(&self.auth_policy);
        self.params.write(w);
        self.unique.write(w);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.write(&mut w);
        w.into_bytes()
    }

    /// As a TPM2B_PUBLIC.
    pub fn write_sized(&self, w: &mut Writer) {
        w.tpm2b(&self.to_bytes());
    }

    /// The Name: nameAlg ‖ H(TPMT_PUBLIC); empty without a nameAlg.
    pub fn name(&self) -> Vec<u8> {
        match self.name_alg {
            Some(hash) => [
                &hash.id().to_be_bytes()[..],
                &hash.digest(&[&self.to_bytes()]),
            ]
            .concat(),
            None => Vec::new(),
        }
    }

    /// The digest size of the nameAlg (0 without one).
    pub fn digest_size(&self) -> usize {
        self.name_alg.map_or(0, Hash::size)
    }

    /// A storage parent: restricted decryption, not signing (an asymmetric or symmetric key).
    pub fn is_storage_parent(&self) -> bool {
        self.has(attr::RESTRICTED)
            && self.has(attr::DECRYPT)
            && self.kind() != Type::KeyedHash
            && self.name_alg.is_some()
    }
}

/// The parent of an object being checked: what CreateChecks and PublicAttributesValidation
/// look at.
pub struct Parent<'a> {
    pub public: &'a Public,
}

/// CreateChecks: what is special about creating an object. `parent` is None for a primary key.
pub fn create_checks(parent: Option<&Parent>, public: &Public, data_len: usize) -> Result<()> {
    let origin = public.has(attr::SENSITIVE_DATA_ORIGIN);
    // The caller says they provide the secret: they must.
    if !origin && data_len == 0 {
        return Err(Rc::ATTRIBUTES);
    }
    // An ordinary object takes data only if the TPM does not generate it.
    if parent.is_some() && origin && data_len != 0 {
        return Err(Rc::ATTRIBUTES);
    }
    match public.kind() {
        Type::KeyedHash | Type::SymCipher => {
            // A data object (neither sign nor decrypt) is the caller's.
            if public.kind() == Type::KeyedHash
                && !public.has(attr::SIGN)
                && !public.has(attr::DECRYPT)
                && origin
            {
                return Err(Rc::ATTRIBUTES);
            }
            // A restricted symmetric key the caller provides cannot be fixed to its parent.
            if public.has(attr::RESTRICTED)
                && !origin
                && (public.has(attr::FIXED_PARENT) || public.has(attr::FIXED_TPM))
            {
                return Err(Rc::ATTRIBUTES);
            }
        }
        // An asymmetric key's secret always comes from the TPM.
        Type::Rsa | Type::Ecc => {
            if !origin {
                return Err(Rc::ATTRIBUTES);
            }
        }
    }
    attributes_validation(parent, public)
}

/// PublicAttributesValidation: the attributes agree with each other and with the parent's.
pub fn attributes_validation(parent: Option<&Parent>, public: &Public) -> Result<()> {
    let has = |a| public.has(a);
    let Some(hash) = public.name_alg else {
        return Err(Rc::HASH);
    };
    if !public.auth_policy.is_empty() && public.auth_policy.len() != hash.size() {
        return Err(Rc::SIZE);
    }
    let parent_fixed_tpm = parent.is_none_or(|p| p.public.has(attr::FIXED_TPM));
    // Under a fixedTPM parent (a primary seed included), fixedParent and fixedTPM go together.
    if parent_fixed_tpm {
        if has(attr::FIXED_PARENT) != has(attr::FIXED_TPM) {
            return Err(Rc::ATTRIBUTES);
        }
    } else if has(attr::FIXED_TPM) {
        return Err(Rc::ATTRIBUTES);
    }
    if has(attr::SIGN) == has(attr::DECRYPT) {
        // Only an unrestricted data object may be neither; nothing restricted may be both.
        if has(attr::RESTRICTED) {
            return Err(Rc::ATTRIBUTES);
        }
        if public.kind() != Type::KeyedHash && !has(attr::SIGN) {
            return Err(Rc::ATTRIBUTES);
        }
    }
    if has(attr::FIXED_TPM) && has(attr::ENCRYPTED_DUPLICATION) {
        return Err(Rc::ATTRIBUTES);
    }
    if let Some(p) = parent
        && !p.public.has(attr::FIXED_TPM)
        && has(attr::ENCRYPTED_DUPLICATION) != p.public.has(attr::ENCRYPTED_DUPLICATION)
    {
        return Err(Rc::ATTRIBUTES);
    }
    // Firmware- and SVN-limited hierarchies are not implemented (as in libtpms).
    if has(attr::FIRMWARE_LIMITED) || has(attr::SVN_LIMITED) {
        return Err(Rc::ATTRIBUTES);
    }
    scheme_checks(parent, public)
}

/// SchemeChecks: the schemes fit the key's type and use.
pub fn scheme_checks(parent: Option<&Parent>, public: &Public) -> Result<()> {
    let has = |a| public.has(a);
    let (sign, decrypt, restricted) = (has(attr::SIGN), has(attr::DECRYPT), has(attr::RESTRICTED));
    let symmetric = match &public.params {
        Params::SymCipher(def) => {
            if decrypt && !(def.mode == TPM_ALG_NULL || is_block_mode(def.mode)) {
                return Err(Rc::SCHEME);
            }
            Some(Some(*def))
        }
        Params::KeyedHash(scheme) => {
            if sign == decrypt {
                if !scheme.is_null() {
                    return Err(Rc::SCHEME);
                }
            } else if sign && scheme.alg != TPM_ALG_HMAC {
                return Err(Rc::SCHEME);
            } else if decrypt {
                if scheme.alg != TPM_ALG_XOR {
                    return Err(Rc::SCHEME);
                }
                // A derivation parent derives with SP 800-108.
                if restricted && scheme.extra != TPM_ALG_KDF1_SP800_108 {
                    return Err(Rc::SCHEME);
                }
            }
            None
        }
        Params::Rsa {
            symmetric, scheme, ..
        }
        | Params::Ecc {
            symmetric, scheme, ..
        } => {
            let kind = public.kind();
            if sign == decrypt {
                if !scheme.is_null() {
                    return Err(Rc::SCHEME);
                }
            } else if sign {
                if is_asym_sign_scheme(kind, scheme.alg) {
                    if scheme.hash.is_none() {
                        return Err(Rc::SCHEME);
                    }
                } else if restricted || !scheme.is_null() {
                    return Err(Rc::SCHEME);
                }
            } else if restricted {
                // A storage parent has no scheme of its own.
                if !scheme.is_null() {
                    return Err(Rc::SCHEME);
                }
            } else if !scheme.is_null() && !is_asym_decrypt_scheme(kind, scheme.alg) {
                return Err(Rc::SCHEME);
            }
            if (!restricted || !decrypt) && symmetric.is_some() {
                return Err(Rc::SYMMETRIC);
            }
            if let Params::Ecc { kdf, .. } = &public.params
                && !kdf.is_null()
            {
                return Err(Rc::KDF);
            }
            Some(*symmetric)
        }
    };
    // An ordinary parent: a symmetric algorithm for its children's protection; one that
    // cannot be duplicated has its parent's algorithms.
    if let Some(symmetric) = symmetric
        && restricted
        && decrypt
    {
        let Some(def) = symmetric else {
            return Err(Rc::SYMMETRIC);
        };
        if has(attr::FIXED_PARENT)
            && let Some(p) = parent
        {
            if public.name_alg != p.public.name_alg {
                return Err(Rc::HASH);
            }
            if p.public.params.symmetric() != Some(def) {
                return Err(Rc::SYMMETRIC);
            }
        }
    }
    Ok(())
}

/// CryptIsAsymSignScheme.
pub fn is_asym_sign_scheme(kind: Type, alg: u16) -> bool {
    match kind {
        Type::Rsa => matches!(alg, TPM_ALG_RSASSA | TPM_ALG_RSAPSS),
        Type::Ecc => matches!(
            alg,
            TPM_ALG_ECDSA | TPM_ALG_ECDAA | TPM_ALG_ECSCHNORR | TPM_ALG_SM2
        ),
        _ => false,
    }
}

/// CryptIsAsymDecryptScheme.
fn is_asym_decrypt_scheme(kind: Type, alg: u16) -> bool {
    match kind {
        Type::Rsa => matches!(alg, TPM_ALG_RSAES | TPM_ALG_OAEP),
        Type::Ecc => matches!(alg, TPM_ALG_ECDH | TPM_ALG_SM2 | TPM_ALG_ECMQV),
        _ => false,
    }
}

/// A TPMT_SENSITIVE: the authValue, the seed that protects the children (or makes a symmetric
/// object's unique digest), and the secret (TPMU_SENSITIVE_COMPOSITE: an RSA prime, an ECC
/// scalar, a keyed hash's or a symmetric key's bits). All of it is wiped when dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sensitive {
    pub kind: Type,
    pub auth: Zeroizing<Vec<u8>>,
    pub seed: Zeroizing<Vec<u8>>,
    pub secret: Zeroizing<Vec<u8>>,
}

impl Sensitive {
    pub fn read(r: &mut Reader) -> Result<Sensitive> {
        let kind = Type::read(r)?;
        let auth = Zeroizing::new(r.tpm2b(MAX_DIGEST)?.to_vec());
        let seed = Zeroizing::new(r.tpm2b(MAX_DIGEST)?.to_vec());
        let max = match kind {
            Type::Rsa => MAX_RSA_PRIVATE,
            Type::Ecc => MAX_ECC_KEY_BYTES,
            Type::KeyedHash => MAX_SYM_DATA,
            Type::SymCipher => MAX_SYM_KEY,
        };
        let secret = Zeroizing::new(r.tpm2b(max)?.to_vec());
        Ok(Sensitive {
            kind,
            auth,
            seed,
            secret,
        })
    }

    /// A TPM2B_SENSITIVE: None for an empty one.
    pub fn read_sized(r: &mut Reader) -> Result<Option<Sensitive>> {
        let size = usize::from(r.u16()?);
        if size == 0 {
            return Ok(None);
        }
        let before = r.len();
        let sensitive = Sensitive::read(r)?;
        if before.saturating_sub(r.len()) != size {
            return Err(Rc::SIZE);
        }
        Ok(Some(sensitive))
    }

    /// Marshalled, the authValue padded with zeros to `auth_size` (MarshalSensitive).
    pub fn to_bytes(&self, auth_size: usize) -> Zeroizing<Vec<u8>> {
        let mut auth = self.auth.clone();
        if auth.len() < auth_size {
            auth.resize(auth_size, 0);
        }
        let size = [auth.len(), self.seed.len(), self.secret.len(), 8];
        let mut w = Writer::with_capacity(size.iter().fold(0, |a, b| a.saturating_add(*b)));
        w.u16(self.kind.id())
            .tpm2b(&auth)
            .tpm2b(&self.seed)
            .tpm2b(&self.secret);
        Zeroizing::new(w.into_bytes())
    }
}

/// TPMS_SENSITIVE_CREATE (in a TPM2B_SENSITIVE_CREATE): the new object's authValue, and the
/// secret if the caller provides it.
pub struct SensitiveCreate {
    pub auth: Zeroizing<Vec<u8>>,
    pub data: Zeroizing<Vec<u8>>,
}

impl SensitiveCreate {
    pub fn read_sized(r: &mut Reader) -> Result<SensitiveCreate> {
        let size = usize::from(r.u16()?);
        if size == 0 {
            return Err(Rc::SIZE);
        }
        let before = r.len();
        let auth = Zeroizing::new(r.tpm2b(MAX_DIGEST)?.to_vec());
        let data = Zeroizing::new(r.tpm2b(MAX_SYM_DATA)?.to_vec());
        if before.saturating_sub(r.len()) != size {
            return Err(Rc::SIZE);
        }
        Ok(SensitiveCreate { auth, data })
    }
}

/// AdjustAuthSize: an authValue no longer than `max` once its trailing zeros are dropped,
/// kept without them (they never count).
pub fn adjust_auth(auth: &[u8], max: usize) -> Result<Zeroizing<Vec<u8>>> {
    let auth = crate::entity::strip_zeros(auth);
    if auth.len() > max {
        return Err(Rc::SIZE);
    }
    Ok(Zeroizing::new(auth.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The TCG EK Credential Profile's RSA 2048 EK template (template L-1).
    pub fn rsa_ek_template() -> Public {
        Public {
            name_alg: Some(Hash::Sha256),
            attributes: attr::FIXED_TPM
                | attr::FIXED_PARENT
                | attr::SENSITIVE_DATA_ORIGIN
                | attr::ADMIN_WITH_POLICY
                | attr::RESTRICTED
                | attr::DECRYPT,
            auth_policy: vec![
                0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5,
                0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b,
                0x33, 0x14, 0x69, 0xaa,
            ],
            params: Params::Rsa {
                symmetric: Some(SymDef {
                    bits: 128,
                    mode: TPM_ALG_CFB,
                }),
                scheme: Scheme::NULL,
                bits: 2048,
                exponent: 0,
            },
            unique: Unique::Rsa(vec![0; 256]),
        }
    }

    #[test]
    fn a_public_area_round_trips_and_is_checked_whole() {
        let ek = rsa_ek_template();
        let bytes = ek.to_bytes();
        assert_eq!(bytes[..10], [0, 1, 0, 0x0b, 0, 0x03, 0x00, 0xb2, 0, 32]);
        let mut r = Reader::new(&bytes);
        assert_eq!(Public::read(&mut r, false).unwrap(), ek);
        assert!(r.is_empty());
        assert_eq!(ek.name()[..2], [0, 0x0b]);
        assert_eq!(ek.name().len(), 34);
        assert_eq!(create_checks(None, &ek, 0), Ok(()));

        let mut sized = Writer::new();
        sized.u16(bytes.len() as u16 + 1).bytes(&bytes).u8(0);
        let sized = sized.into_bytes();
        assert_eq!(
            Public::read_sized(&mut Reader::new(&sized), false),
            Err(Rc::SIZE)
        );

        // Reserved attribute bits, a missing nameAlg, an unimplemented curve.
        let mut reserved = bytes.clone();
        reserved[7] |= 1;
        assert_eq!(
            Public::read(&mut Reader::new(&reserved), false),
            Err(Rc::RESERVED_BITS)
        );
        let mut null = bytes.clone();
        null[2..4].copy_from_slice(&[0, 0x10]);
        assert_eq!(Public::read(&mut Reader::new(&null), false), Err(Rc::HASH));
        assert!(Public::read(&mut Reader::new(&null), true).is_ok());
    }

    #[test]
    fn attributes_must_agree() {
        let ek = rsa_ek_template();
        let with = |f: &dyn Fn(&mut Public)| {
            let mut p = ek.clone();
            f(&mut p);
            create_checks(None, &p, 0)
        };
        assert_eq!(
            with(&|p| p.attributes &= !attr::FIXED_PARENT),
            Err(Rc::ATTRIBUTES)
        );
        assert_eq!(with(&|p| p.attributes |= attr::SIGN), Err(Rc::ATTRIBUTES));
        assert_eq!(
            with(&|p| p.attributes &= !attr::SENSITIVE_DATA_ORIGIN),
            Err(Rc::ATTRIBUTES)
        );
        assert_eq!(
            with(&|p| p.auth_policy.pop().map(drop).unwrap_or(())),
            Err(Rc::SIZE)
        );
        assert_eq!(
            with(&|p| {
                if let Params::Rsa { symmetric, .. } = &mut p.params {
                    *symmetric = None;
                }
            }),
            Err(Rc::SYMMETRIC)
        );
        assert_eq!(
            with(&|p| {
                if let Params::Rsa { scheme, .. } = &mut p.params {
                    *scheme = Scheme {
                        alg: TPM_ALG_OAEP,
                        hash: Some(Hash::Sha256),
                        extra: 0,
                    };
                }
            }),
            Err(Rc::SCHEME)
        );
        // A child that cannot be duplicated has its parent's algorithms.
        let parent = Parent { public: &ek };
        let mut child = ek.clone();
        child.name_alg = Some(Hash::Sha384);
        child.auth_policy.clear();
        assert_eq!(create_checks(Some(&parent), &child, 0), Err(Rc::HASH));
    }

    #[test]
    fn sensitive_areas_round_trip_with_their_auth_padded() {
        let s = Sensitive {
            kind: Type::KeyedHash,
            auth: Zeroizing::new(b"pw".to_vec()),
            seed: Zeroizing::new(vec![1; 32]),
            secret: Zeroizing::new(b"secret".to_vec()),
        };
        let bytes = s.to_bytes(32);
        assert_eq!(bytes[..4], [0, 8, 0, 32]);
        let back = Sensitive::read(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(back.auth.len(), 32);
        assert_eq!(*back.secret, b"secret");
        assert_eq!(adjust_auth(&back.auth, 32).unwrap().as_slice(), b"pw");
        assert_eq!(adjust_auth(&[1; 33], 32), Err(Rc::SIZE));
    }
}
