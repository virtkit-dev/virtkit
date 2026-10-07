//! PKCS#7 signatures of authenticated variable writes, checked as edk2's Pkcs7Verify checks
//! them: one or more signers, each found among the signature's certificates and its signature
//! good (over the signed attributes, whose messageDigest must match the content, or over the
//! content itself), and each signer chaining, through the signature's certificates, to the
//! trusted certificate. No validity periods and no key usages are checked, as edk2 checks none:
//! the certificates that sign Secure Boot updates have long expired.

use crypto_bigint::BoxedUint;
use rsa::traits::{PublicKeyParts, SignatureScheme};
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::der::{self, Tlv, oids};

/// How deep a chain may run from a signer to the trusted certificate.
const MAX_CHAIN: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn from_digest_oid(oid: &[u8]) -> Option<Hash> {
        match oid {
            oids::SHA1 => Some(Hash::Sha1),
            oids::SHA256 => Some(Hash::Sha256),
            oids::SHA384 => Some(Hash::Sha384),
            oids::SHA512 => Some(Hash::Sha512),
            _ => None,
        }
    }

    fn from_signature_oid(oid: &[u8]) -> Option<Hash> {
        match oid {
            oids::SHA1_WITH_RSA => Some(Hash::Sha1),
            oids::SHA256_WITH_RSA => Some(Hash::Sha256),
            oids::SHA384_WITH_RSA => Some(Hash::Sha384),
            oids::SHA512_WITH_RSA => Some(Hash::Sha512),
            _ => None,
        }
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha1 => Sha1::digest(data).to_vec(),
            Hash::Sha256 => Sha256::digest(data).to_vec(),
            Hash::Sha384 => Sha384::digest(data).to_vec(),
            Hash::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    fn verify(self, key: &RsaPublicKey, digest: &[u8], signature: &[u8]) -> bool {
        let scheme = match self {
            Hash::Sha1 => Pkcs1v15Sign::new::<Sha1>(),
            Hash::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
            Hash::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
            Hash::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
        };
        signature.len() == key.size() && scheme.verify(key, digest, signature).is_ok()
    }
}

/// An X.509 certificate, with the parts a chain check reads.
#[derive(Clone, Debug)]
pub struct Certificate<'a> {
    pub raw: &'a [u8],
    tbs: &'a [u8],
    signature_hash: Option<Hash>,
    signature: &'a [u8],
    serial: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    key: Option<RsaPublicKey>,
    subject_key_id: Option<&'a [u8]>,
}

impl<'a> Certificate<'a> {
    /// Parse a DER certificate; None if it is not one this module can use.
    pub fn parse(raw: &'a [u8]) -> Option<Certificate<'a>> {
        let (cert, _) = der::expect(raw, der::SEQUENCE)?;
        let parts = der::children(cert.value)?;
        let (tbs, alg, sig) = match parts.as_slice() {
            [tbs, alg, sig] => (tbs, alg, sig),
            _ => return None,
        };
        let signature_hash = algorithm_oid(alg.value).and_then(Hash::from_signature_oid);
        let signature = bit_string(sig)?;
        let mut fields = der::children(tbs.value)?.into_iter().peekable();
        if fields.peek().is_some_and(|t| t.tag == der::CTX0) {
            fields.next(); // version
        }
        let serial = fields.next().filter(|t| t.tag == der::INTEGER)?;
        fields.next()?; // signature algorithm
        let issuer = fields.next().filter(|t| t.tag == der::SEQUENCE)?;
        fields.next()?; // validity
        let subject = fields.next().filter(|t| t.tag == der::SEQUENCE)?;
        let spki = fields.next().filter(|t| t.tag == der::SEQUENCE)?;
        let mut subject_key_id = None;
        for field in fields {
            if field.tag == der::CTX3 {
                subject_key_id = extension_ski(field.value);
            }
        }
        Some(Certificate {
            raw: cert.raw,
            tbs: tbs.raw,
            signature_hash,
            signature,
            serial: der::unsigned(serial.value),
            issuer: issuer.raw,
            subject: subject.raw,
            key: rsa_key(spki.value),
            subject_key_id,
        })
    }

    /// Whether `issuer`'s key signed this certificate.
    fn signed_by(&self, issuer: &Certificate<'_>) -> bool {
        let (Some(hash), Some(key)) = (self.signature_hash, issuer.key.as_ref()) else {
            return false;
        };
        hash.verify(key, &hash.digest(self.tbs), self.signature)
    }

    /// The SHA-256 of the to-be-signed part, which names a signer across re-signed copies.
    pub fn tbs_sha256(&self) -> [u8; 32] {
        Sha256::digest(self.tbs).into()
    }
}

/// A BIT STRING's bits, which must be whole bytes.
fn bit_string<'a>(tlv: &Tlv<'a>) -> Option<&'a [u8]> {
    if tlv.tag != der::BIT_STRING {
        return None;
    }
    match tlv.value.split_first() {
        Some((0, bits)) => Some(bits),
        _ => None,
    }
}

/// An AlgorithmIdentifier's OID.
fn algorithm_oid(value: &[u8]) -> Option<&[u8]> {
    der::expect(value, der::OID).map(|(oid, _)| oid.value)
}

/// An rsaEncryption SubjectPublicKeyInfo's key.
fn rsa_key(spki: &[u8]) -> Option<RsaPublicKey> {
    let (alg, rest) = der::expect(spki, der::SEQUENCE)?;
    if algorithm_oid(alg.value)? != oids::RSA_ENCRYPTION {
        return None;
    }
    let (bits, _) = read_tlv(rest)?;
    let (key, _) = der::expect(bit_string(&bits)?, der::SEQUENCE)?;
    let (n, rest) = der::expect(key.value, der::INTEGER)?;
    let (e, _) = der::expect(rest, der::INTEGER)?;
    let n = der::unsigned(n.value);
    let e = der::unsigned(e.value);
    let n_bits = u32::try_from(n.len().checked_mul(8)?).ok()?;
    let e_bits = u32::try_from(e.len().checked_mul(8)?).ok()?;
    let n = BoxedUint::from_be_slice(n, n_bits).ok()?;
    let e = BoxedUint::from_be_slice(e, e_bits).ok()?;
    if n.bits() < 512 || n.as_limbs().first().is_none_or(|l| l.0 & 1 == 0) {
        return None;
    }
    Some(RsaPublicKey::new_unchecked(n, e))
}

fn read_tlv(input: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    der::read(input)
}

/// The subjectKeyIdentifier in an [3] extensions element.
fn extension_ski(value: &[u8]) -> Option<&[u8]> {
    let (exts, _) = der::expect(value, der::SEQUENCE)?;
    for ext in der::children(exts.value)? {
        let parts = der::children(ext.value)?;
        let oid = parts.first().filter(|t| t.tag == der::OID)?;
        if oid.value != oids::SUBJECT_KEY_IDENTIFIER {
            continue;
        }
        let octets = parts.last().filter(|t| t.tag == der::OCTET_STRING)?;
        let (ski, _) = der::expect(octets.value, der::OCTET_STRING)?;
        return Some(ski.value);
    }
    None
}

/// Who a SignerInfo says signed.
enum SignerId<'a> {
    IssuerSerial { issuer: &'a [u8], serial: &'a [u8] },
    KeyId(&'a [u8]),
}

struct SignerInfo<'a> {
    id: SignerId<'a>,
    digest: Hash,
    /// The signed attributes as their [0] element encodes them.
    signed_attrs: Option<Tlv<'a>>,
    signature: &'a [u8],
}

/// A PKCS#7 SignedData: its certificates and signers.
pub struct SignedData<'a> {
    pub certificates: Vec<Certificate<'a>>,
    signers: Vec<SignerInfo<'a>>,
}

impl<'a> SignedData<'a> {
    /// Parse a SignedData, bare (as UEFI authenticated variables carry it) or in a ContentInfo.
    pub fn parse(bytes: &'a [u8]) -> Option<SignedData<'a>> {
        let (outer, _) = der::expect(bytes, der::SEQUENCE)?;
        let mut parts = der::children(outer.value)?;
        if parts.first().is_some_and(|t| t.tag == der::OID) {
            // ContentInfo { contentType signedData, [0] EXPLICIT SignedData }
            if parts.first()?.value != oids::SIGNED_DATA {
                return None;
            }
            let content = parts.get(1).filter(|t| t.tag == der::CTX0)?;
            let (inner, _) = der::expect(content.value, der::SEQUENCE)?;
            parts = der::children(inner.value)?;
        }
        let mut it = parts.into_iter();
        it.next().filter(|t| t.tag == der::INTEGER)?; // version
        it.next().filter(|t| t.tag == der::SET)?; // digestAlgorithms
        it.next().filter(|t| t.tag == der::SEQUENCE)?; // encapContentInfo
        let mut certificates = Vec::new();
        let mut signer_infos = None;
        for part in it {
            match part.tag {
                der::CTX0 => {
                    for cert in der::children(part.value)? {
                        if let Some(cert) = Certificate::parse(cert.raw) {
                            certificates.push(cert);
                        }
                    }
                }
                der::CTX1 => {} // crls
                der::SET => signer_infos = Some(part),
                _ => return None,
            }
        }
        let mut signers = Vec::new();
        for info in der::children(signer_infos?.value)? {
            signers.push(signer_info(info.value)?);
        }
        if signers.is_empty() {
            return None;
        }
        Some(SignedData {
            certificates,
            signers,
        })
    }

    /// Whether every signer signed `content` and chains to `trusted` (a DER certificate).
    pub fn verify(&self, content: &[u8], trusted: &Certificate<'_>) -> bool {
        self.signers.iter().all(|signer| {
            self.signer_certificate(signer)
                .is_some_and(|cert| signed(signer, cert, content) && self.chains(cert, trusted))
        })
    }

    /// The certificate at the top of the first signer's chain within this signature: the one
    /// the chain stops at for want of its issuer here (edk2's "top-level certificate").
    pub fn top_level(&self) -> Option<&Certificate<'a>> {
        let signer = self.signers.first()?;
        let mut cert = self.signer_certificate(signer)?;
        for _ in 0..MAX_CHAIN {
            match self
                .certificates
                .iter()
                .find(|c| c.subject == cert.issuer && c.raw != cert.raw && cert.signed_by(c))
            {
                Some(issuer) => cert = issuer,
                None => return Some(cert),
            }
        }
        Some(cert)
    }

    fn signer_certificate(&self, signer: &SignerInfo<'_>) -> Option<&Certificate<'a>> {
        self.certificates.iter().find(|c| match signer.id {
            SignerId::IssuerSerial { issuer, serial } => c.issuer == issuer && c.serial == serial,
            SignerId::KeyId(id) => c.subject_key_id == Some(id),
        })
    }

    /// Whether `cert` is `trusted`, or was signed by it, possibly through certificates of
    /// this signature.
    fn chains(&self, cert: &Certificate<'_>, trusted: &Certificate<'_>) -> bool {
        let mut current = cert;
        for _ in 0..MAX_CHAIN {
            if current.raw == trusted.raw {
                return true;
            }
            if current.issuer == trusted.subject && current.signed_by(trusted) {
                return true;
            }
            match self.certificates.iter().find(|c| {
                c.subject == current.issuer && c.raw != current.raw && current.signed_by(c)
            }) {
                Some(issuer) => current = issuer,
                None => return false,
            }
        }
        false
    }
}

fn signer_info(value: &[u8]) -> Option<SignerInfo<'_>> {
    let mut it = der::children(value)?.into_iter();
    it.next().filter(|t| t.tag == der::INTEGER)?; // version
    let sid = it.next()?;
    let id = match sid.tag {
        der::SEQUENCE => {
            let (issuer, rest) = der::expect(sid.value, der::SEQUENCE)?;
            let (serial, _) = der::expect(rest, der::INTEGER)?;
            SignerId::IssuerSerial {
                issuer: issuer.raw,
                serial: der::unsigned(serial.value),
            }
        }
        der::CTX0_PRIMITIVE => SignerId::KeyId(sid.value),
        _ => return None,
    };
    let digest_alg = it.next().filter(|t| t.tag == der::SEQUENCE)?;
    let digest = Hash::from_digest_oid(algorithm_oid(digest_alg.value)?)?;
    let mut next = it.next()?;
    let mut signed_attrs = None;
    if next.tag == der::CTX0 {
        signed_attrs = Some(next);
        next = it.next()?;
    }
    if next.tag != der::SEQUENCE {
        return None; // signatureAlgorithm
    }
    let signature = it.next().filter(|t| t.tag == der::OCTET_STRING)?.value;
    Some(SignerInfo {
        id,
        digest,
        signed_attrs,
        signature,
    })
}

/// Whether `signer`'s signature, by `cert`'s key, covers `content`.
fn signed(signer: &SignerInfo<'_>, cert: &Certificate<'_>, content: &[u8]) -> bool {
    let Some(key) = cert.key.as_ref() else {
        return false;
    };
    let content_digest = signer.digest.digest(content);
    match signer.signed_attrs {
        None => signer.digest.verify(key, &content_digest, signer.signature),
        Some(attrs) => {
            if message_digest(attrs.value) != Some(content_digest.as_slice()) {
                return false;
            }
            // The signature covers the attributes as a SET, not as the [0] they are carried in.
            let mut set = attrs.raw.to_vec();
            if let Some(tag) = set.first_mut() {
                *tag = der::SET;
            }
            signer
                .digest
                .verify(key, &signer.digest.digest(&set), signer.signature)
        }
    }
}

/// The messageDigest signed attribute's value.
fn message_digest(attrs: &[u8]) -> Option<&[u8]> {
    for attr in der::children(attrs)? {
        let (oid, rest) = der::expect(attr.value, der::OID)?;
        if oid.value != oids::MESSAGE_DIGEST {
            continue;
        }
        let (values, _) = der::expect(rest, der::SET)?;
        let (digest, _) = der::expect(values.value, der::OCTET_STRING)?;
        return Some(digest.value);
    }
    None
}
