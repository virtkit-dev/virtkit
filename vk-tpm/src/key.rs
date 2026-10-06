//! Keys, and every object with a public area (Part 1, "Object Structure Elements"): what a loaded
//! one is, how one is created (a primary key from its hierarchy's seed, an ordinary one under a
//! parent), and the object commands (Part 3, "Object Commands": CreatePrimary, Create, Load,
//! LoadExternal, ReadPublic, ObjectChangeAuth, Unseal; and EvictControl). How an object is
//! wrapped under its parent and checked before it loads is `protection.rs`.

use rsa::RsaPrivateKey;
use zeroize::Zeroizing;

use crate::alg::{Hash, MAX_DIGEST, TPM_ALG_NULL};
use crate::asym;
use crate::commands::{end, first};
use crate::crypt;
use crate::drbg::{Drbg, PRIMARY_OBJECT_CREATION};
use crate::entity::{
    TPM_HT_PERMANENT, TPM_RH_ENDORSEMENT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM, handle_type,
};
use crate::marshal::{Reader, Writer};
use crate::pcr;
use crate::protection::{load_checked, unwrap, wrap};
use crate::public::{self, Params, Parent, Public, Sensitive, SensitiveCreate, Type, Unique, attr};
use crate::rc::{Rc, Result};
use crate::state::{Seed, StateError, read_bool};
use crate::{LOCALITY, Out, Tpm};

/// TPM_ST_CREATION, the tag of a TPMT_TK_CREATION.
const TPM_ST_CREATION: u16 = 0x8021;
/// TPM2B_DATA: sizeof(TPMT_HA).
pub const MAX_DATA: usize = 2 + MAX_DIGEST;
/// TPM2B_PRIVATE: sizeof(_PRIVATE), two TPM2B_DIGESTs and a TPM2B_SENSITIVE as the reference
/// lays them out.
pub const MAX_PRIVATE: usize = 2 * (2 + MAX_DIGEST) + 2 + 2 + 2 * (2 + MAX_DIGEST) + 2 + 1280;
/// Persistent handles from here on belong to the platform (PLATFORM_PERSISTENT).
pub const PLATFORM_PERSISTENT: u32 = 0x8180_0000;
const PERSISTENT_FIRST: u32 = 0x8100_0000;
const PERSISTENT_LAST: u32 = 0x81ff_ffff;
/// How many persistent objects the TPM keeps (EvictControl answers TPM_RC_NV_SPACE beyond).
pub const MAX_PERSISTENT: usize = 16;

/// An object with a public area: a key, a sealed data object, or a public key alone.
#[derive(Clone)]
pub struct Key {
    pub public: Public,
    /// None for a public key loaded alone (TPM2_LoadExternal).
    pub sensitive: Option<Sensitive>,
    pub name: Vec<u8>,
    pub qualified_name: Vec<u8>,
    /// TPM_RH_OWNER, _ENDORSEMENT, _PLATFORM, or TPM_RH_NULL (a temporary object).
    pub hierarchy: u32,
    pub primary: bool,
    /// Loaded from outside the TPM (TPM2_LoadExternal): its qualified name is its Name, and it
    /// cannot be a parent.
    pub external: bool,
    /// Under the null hierarchy or external: it never becomes persistent.
    pub temporary: bool,
    /// stClear, its own or inherited: a context of it does not survive a TPM Restart.
    pub st_clear: bool,
    /// The persistent handle a copy was loaded from, for one command.
    pub evict: Option<u32>,
    /// Its RSA private key, rebuilt whenever the sensitive area is loaded; never stored.
    rsa: Option<Box<RsaPrivateKey>>,
}

impl Key {
    /// A loaded object: its RSA private key (if any) rebuilt from the prime, TPM_RC_BINDING if
    /// the prime does not divide the modulus.
    pub fn new(public: Public, sensitive: Option<Sensitive>) -> Result<Key> {
        let rsa = match (&public.params, &public.unique, &sensitive) {
            (Params::Rsa { exponent, .. }, Unique::Rsa(n), Some(s)) => {
                Some(Box::new(asym::rsa_private(n, &s.secret, *exponent)?))
            }
            _ => None,
        };
        let name = public.name();
        Ok(Key {
            qualified_name: name.clone(),
            name,
            public,
            sensitive,
            hierarchy: TPM_RH_NULL,
            primary: false,
            external: false,
            temporary: false,
            st_clear: false,
            evict: None,
            rsa,
        })
    }

    /// The authValue (without trailing zeros); a public key alone has none.
    pub fn auth(&self) -> &[u8] {
        self.sensitive
            .as_ref()
            .map_or(&[][..], |s| crate::entity::strip_zeros(&s.auth))
    }

    pub fn public_only(&self) -> bool {
        self.sensitive.is_none()
    }

    /// isParent: a storage key with its sensitive area, not external.
    pub fn is_parent(&self) -> bool {
        !self.external && !self.public_only() && self.public.is_storage_parent()
    }

    pub fn rsa(&self) -> Result<&RsaPrivateKey> {
        self.rsa.as_deref().ok_or(Rc::FAILURE)
    }

    /// The private scalar of an ECC key.
    pub fn ecc_secret(&self) -> Result<&[u8]> {
        match (&self.public.params, &self.sensitive) {
            (Params::Ecc { .. }, Some(s)) => Ok(&s.secret),
            _ => Err(Rc::FAILURE),
        }
    }

    /// CryptSecretDecrypt for an asymmetric key: a secret encrypted to it, as a salt or a
    /// credential seed is, with `label` (its terminating zero included). RSA: OAEP with the
    /// key's scheme hash, its nameAlg if it has none; at most a digest long. ECC: the TPMS_ECC_POINT
    /// of an ephemeral key, Z = [d]Q, and KDFe over Z's x-coordinate.
    pub fn decrypt_secret(&self, label: &[u8], secret: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let name_alg = self.public.name_alg.ok_or(Rc::SCHEME)?;
        match (&self.public.params, &self.public.unique) {
            (Params::Rsa { scheme, .. }, _) => {
                let (alg, hash) = if scheme.is_null() {
                    (public::TPM_ALG_OAEP, name_alg)
                } else {
                    (scheme.alg, scheme.hash.ok_or(Rc::SCHEME)?)
                };
                if alg != public::TPM_ALG_OAEP {
                    return Err(Rc::SCHEME);
                }
                let data = asym::rsa_decrypt(self.rsa()?, alg, Some(hash), label, secret)?;
                if data.len() > hash.size() {
                    return Err(Rc::VALUE);
                }
                Ok(data)
            }
            (Params::Ecc { .. }, Unique::Ecc { x: own_x, .. }) => {
                let (x, y) = public::read_point(&mut Reader::new(secret))?;
                let (zx, _) = asym::ecc_multiply(self.ecc_secret()?, &x, &y)?;
                Ok(crypt::kdfe(
                    name_alg,
                    &zx,
                    label,
                    &x,
                    own_x,
                    name_alg.size(),
                ))
            }
            _ => Err(Rc::FAILURE),
        }
    }

    /// The seed that protects its children (a parent's seedValue).
    pub fn seed(&self) -> &[u8] {
        self.sensitive.as_ref().map_or(&[][..], |s| &s.seed)
    }

    /// Finish loading under `parent` (or as a primary or external object of `hierarchy`):
    /// ObjectSetLoadedAttributes.
    fn set_loaded(&mut self, parent: Option<&Key>, parent_handle: u32) {
        let st_clear = self.public.has(attr::ST_CLEAR);
        match parent {
            None => {
                self.hierarchy = parent_handle;
                self.primary = parent_handle != TPM_RH_NULL;
                self.temporary = parent_handle == TPM_RH_NULL;
                self.st_clear = st_clear;
            }
            Some(p) => {
                self.hierarchy = p.hierarchy;
                self.temporary = p.temporary || self.external;
                self.st_clear = st_clear || p.st_clear;
            }
        }
        self.qualified_name = if self.external {
            self.name.clone()
        } else {
            let parent_qn = parent.map_or_else(
                || parent_handle.to_be_bytes().to_vec(),
                |p| p.qualified_name.clone(),
            );
            qualified_name(self.public.name_alg, &parent_qn, &self.name)
        };
    }

    pub fn write(&self, w: &mut Writer) {
        w.tpm2b(&self.public.to_bytes());
        match &self.sensitive {
            Some(s) => w.u8(1).tpm2b(&s.to_bytes(0)),
            None => w.u8(0),
        };
        w.tpm2b(&self.name)
            .tpm2b(&self.qualified_name)
            .u32(self.hierarchy)
            .u8(self.primary.into())
            .u8(self.external.into())
            .u8(self.temporary.into())
            .u8(self.st_clear.into())
            .u32(self.evict.unwrap_or(0));
    }

    pub fn read(r: &mut Reader) -> std::result::Result<Key, StateError> {
        let public = Public::read(&mut Reader::new(r.tpm2b(usize::from(u16::MAX))?), true)?;
        let sensitive = if read_bool(r)? {
            let bytes = r.tpm2b(usize::from(u16::MAX))?;
            Some(Sensitive::read(&mut Reader::new(bytes))?)
        } else {
            None
        };
        let mut key = Key::new(public, sensitive).map_err(|_| StateError("bad key"))?;
        key.name = r.tpm2b(2 + MAX_DIGEST)?.to_vec();
        key.qualified_name = r.tpm2b(2 + MAX_DIGEST)?.to_vec();
        key.hierarchy = r.u32()?;
        key.primary = read_bool(r)?;
        key.external = read_bool(r)?;
        key.temporary = read_bool(r)?;
        key.st_clear = read_bool(r)?;
        key.evict = Some(r.u32()?).filter(|&h| h != 0);
        Ok(key)
    }
}

/// ComputeQualifiedName: QN = nameAlg ‖ H(parent's QN ‖ Name).
fn qualified_name(name_alg: Option<Hash>, parent_qn: &[u8], name: &[u8]) -> Vec<u8> {
    match name_alg {
        Some(hash) => [
            &hash.id().to_be_bytes()[..],
            &hash.digest(&[parent_qn, name]),
        ]
        .concat(),
        None => name.to_vec(),
    }
}

/// The object a template creates, its secrets drawn from `drbg` (CryptCreateObject). A primary
/// key of the endorsement hierarchy also mixes the proofs `eps_stir` into it before the seed.
fn create_object(
    public: &mut Public,
    create: &SensitiveCreate,
    drbg: &mut Drbg,
    eps_stir: Option<(&Seed, &Seed)>,
) -> Result<Sensitive> {
    let kind = public.kind();
    // Data the caller provides counts only if the TPM does not generate the secret.
    let data: &[u8] = if public.has(attr::SENSITIVE_DATA_ORIGIN) {
        &[]
    } else {
        &create.data
    };
    let secret = match &public.params {
        Params::Rsa { bits, exponent, .. } => {
            let (n, p, _) = asym::rsa_generate(*bits, *exponent, drbg)?;
            public.unique = Unique::Rsa(n);
            p
        }
        Params::Ecc { .. } => {
            let d = asym::ecc_derive(drbg);
            let (x, y) = asym::ecc_public(d.as_slice())?;
            public.unique = Unique::Ecc { x, y };
            Zeroizing::new(d.to_vec())
        }
        Params::SymCipher(def) => {
            if def.bits % 64 != 0 {
                return Err(Rc::KEY_SIZE);
            }
            if data.is_empty() {
                drbg.bytes(def.key_bytes())
            } else if data.len() != def.key_bytes() {
                return Err(Rc::KEY_SIZE);
            } else {
                Zeroizing::new(data.to_vec())
            }
        }
        Params::KeyedHash(scheme) => {
            let hash = match scheme.hash {
                Some(hash) => hash,
                None => public.name_alg.ok_or(Rc::HASH)?,
            };
            if data.is_empty() {
                drbg.bytes(hash.size())
            } else {
                let keyed = public.has(attr::SIGN) || public.has(attr::DECRYPT);
                if keyed && data.len() > hash_block_size(hash) {
                    return Err(Rc::SIZE);
                }
                Zeroizing::new(data.to_vec())
            }
        }
    };
    if let Some((sh_proof, eh_proof)) = eps_stir {
        drbg.additional_data(sh_proof.as_slice());
        drbg.additional_data(eh_proof.as_slice());
    }
    let mut seed = drbg.bytes(public.digest_size());
    match kind {
        Type::SymCipher | Type::KeyedHash => {
            public.unique = Unique::Digest(symmetric_unique(public, &seed, &secret));
        }
        // Only a parent keeps its seed.
        Type::Rsa | Type::Ecc => {
            if public.has(attr::SIGN) || !public.has(attr::RESTRICTED) {
                seed = Zeroizing::new(Vec::new());
            }
        }
    }
    Ok(Sensitive {
        kind,
        auth: create.auth.clone(),
        seed,
        secret,
    })
}

/// CryptComputeSymmetricUnique: a parent's HMAC(seed, secret), anything else's H(seed ‖ secret).
pub fn symmetric_unique(public: &Public, seed: &[u8], secret: &[u8]) -> Vec<u8> {
    let Some(hash) = public.name_alg else {
        return Vec::new();
    };
    if public.has(attr::RESTRICTED) && public.has(attr::DECRYPT) {
        crypt::hmac(hash, seed, &[secret])
    } else {
        hash.digest(&[seed, secret])
    }
}

/// The block size of a hash: the most key HMAC takes without hashing it first.
pub fn hash_block_size(hash: Hash) -> usize {
    match hash {
        Hash::Sha1 | Hash::Sha256 => 64,
        Hash::Sha384 | Hash::Sha512 => 128,
    }
}

impl Tpm {
    /// A hierarchy's proof (TPM_RH_NULL's changes at every TPM Reset).
    pub fn proof(&self, hierarchy: u32) -> &Seed {
        let h = &self.permanent.hierarchies;
        match hierarchy {
            TPM_RH_PLATFORM => &h.ph_proof,
            TPM_RH_ENDORSEMENT => &h.eh_proof,
            TPM_RH_OWNER => &h.sh_proof,
            _ => &self.volatile.null_proof,
        }
    }

    /// A hierarchy's primary seed.
    fn primary_seed(&self, hierarchy: u32) -> &Seed {
        match hierarchy {
            TPM_RH_PLATFORM => &self.permanent.pps,
            TPM_RH_ENDORSEMENT => &self.permanent.eps,
            TPM_RH_OWNER => &self.permanent.sps,
            _ => &self.volatile.null_seed,
        }
    }

    /// A primary key of `hierarchy`, derived from the hierarchy's seed and `template`
    /// (DRBG_InstantiateSeeded, then CryptCreateObject): the same key every time, until the seed
    /// changes. The template's unique field becomes the key's.
    pub fn derive_primary(
        &self,
        hierarchy: u32,
        template: &mut Public,
        sensitive: &SensitiveCreate,
    ) -> Result<Sensitive> {
        let mut drbg = Drbg::seeded(
            self.primary_seed(hierarchy).as_slice(),
            PRIMARY_OBJECT_CREATION,
            &template.name(),
            &sensitive.data,
        );
        let h = &self.permanent.hierarchies;
        let eps_stir = (hierarchy == TPM_RH_ENDORSEMENT).then_some((&h.sh_proof, &h.eh_proof));
        create_object(template, sensitive, &mut drbg, eps_stir)
    }

    /// The primary key `template` makes in `hierarchy`, as TPM2_CreatePrimary loads it.
    pub fn primary_key(
        &self,
        hierarchy: u32,
        mut template: Public,
        sensitive: &SensitiveCreate,
    ) -> Result<Key> {
        let secrets = self.derive_primary(hierarchy, &mut template, sensitive)?;
        let mut key = Key::new(template, Some(secrets))?;
        key.set_loaded(None, hierarchy);
        Ok(key)
    }

    /// The object (with a public area) a handle names: a transient one, or a persistent one
    /// loaded for the command.
    pub fn key(&self, handle: u32) -> Option<&Key> {
        match self.object(handle)? {
            crate::object::Object::Key(key) => Some(key),
            crate::object::Object::Sequence(_) => None,
        }
    }

    /// FillInCreationData: TPMS_CREATION_DATA, and its digest with `name_alg`.
    fn creation_data(
        &self,
        parent_handle: u32,
        name_alg: Hash,
        selections: &mut [pcr::Selection],
        outside: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let pcr_digest =
            (self.volatile.pcrs).digest(&self.permanent.allocation, selections, name_alg);
        let mut w = Writer::new();
        pcr::write_selections(&mut w, selections);
        w.tpm2b(&pcr_digest).u8(1 << LOCALITY);
        match self.key(parent_handle) {
            Some(parent) if handle_type(parent_handle) != TPM_HT_PERMANENT => {
                w.u16(parent.public.name_alg.map_or(TPM_ALG_NULL, Hash::id))
                    .tpm2b(&parent.name)
                    .tpm2b(&parent.qualified_name);
            }
            _ => {
                let handle = parent_handle.to_be_bytes();
                w.u16(TPM_ALG_NULL).tpm2b(&handle).tpm2b(&handle);
            }
        }
        w.tpm2b(outside);
        let data = w.into_bytes();
        let digest = name_alg.digest(&[&data]);
        (data, digest)
    }

    /// TicketComputeCreation: TPMT_TK_CREATION, an HMAC with the hierarchy's proof over the
    /// Name and the creation digest.
    fn creation_ticket(&self, hierarchy: u32, name: &[u8], creation_hash: &[u8], w: &mut Writer) {
        let tag = TPM_ST_CREATION.to_be_bytes();
        let proof = self.proof(hierarchy);
        let ticket = crypt::hmac(Hash::Sha512, proof.as_slice(), &[&tag, name, creation_hash]);
        w.u16(TPM_ST_CREATION).u32(hierarchy).tpm2b(&ticket);
    }

    /// Flush the objects of a hierarchy being disabled or cleared (ObjectFlushHierarchy).
    pub fn flush_hierarchy(&mut self, hierarchy: u32) {
        for slot in &mut self.volatile.objects {
            if let Some(crate::object::Object::Key(k)) = slot
                && k.hierarchy == hierarchy
            {
                *slot = None;
            }
        }
    }

    /// Delete the persistent objects of a hierarchy (NvFlushHierarchy).
    pub fn flush_persistent(&mut self, hierarchy: u32) {
        self.permanent
            .persistent
            .retain(|(_, k)| k.hierarchy != hierarchy);
    }
}

/// The parameters TPM2_Create and TPM2_CreatePrimary take.
struct CreateIn {
    sensitive: SensitiveCreate,
    public: Public,
    outside: Vec<u8>,
    pcrs: Vec<pcr::Selection>,
}

fn read_create(r: &mut Reader) -> Result<CreateIn> {
    let sensitive = SensitiveCreate::read_sized(r).map_err(|rc| rc.param(1))?;
    let public = Public::read_sized(r, false).map_err(|rc| rc.param(2))?;
    let outside = r.tpm2b(MAX_DATA).map_err(|rc| rc.param(3))?.to_vec();
    let pcrs = pcr::read_selections(r).map_err(|rc| rc.param(4))?;
    end(r)?;
    Ok(CreateIn {
        sensitive,
        public,
        outside,
        pcrs,
    })
}

/// TPM2_CreatePrimary: a key derived from its hierarchy's seed and the template, the same one
/// every time.
pub fn create_primary(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let mut input = read_create(r)?;
    let hierarchy = first(handles)?;
    tpm.free_slot()?;
    let data_len = input.sensitive.data.len();
    public::create_checks(None, &input.public, data_len).map_err(|rc| rc.param(2))?;
    let digest_size = input.public.digest_size();
    let auth = public::adjust_auth(&input.sensitive.auth, digest_size).map_err(|rc| rc.param(1))?;
    input.sensitive.auth = auth;
    let key = tpm.primary_key(hierarchy, input.public, &input.sensitive)?;
    let name_alg = key.public.name_alg.ok_or(Rc::FAILURE)?;
    let (creation, creation_hash) =
        tpm.creation_data(hierarchy, name_alg, &mut input.pcrs, &input.outside);
    key.public.write_sized(w);
    w.tpm2b(&creation).tpm2b(&creation_hash);
    tpm.creation_ticket(hierarchy, &key.name, &creation_hash, w);
    w.tpm2b(&key.name);
    w.handle = Some(tpm.load_object(crate::object::Object::Key(Box::new(key)))?);
    Ok(())
}

/// TPM2_Create: an ordinary object under a loaded parent, returned wrapped (not loaded).
pub fn create(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let mut input = read_create(r)?;
    let parent_handle = first(handles)?;
    let parent = tpm.key(parent_handle).filter(|p| p.is_parent());
    let parent = parent.ok_or(Rc::TYPE.handle(1))?;
    tpm.free_slot()?;
    let data_len = input.sensitive.data.len();
    let checked = Parent {
        public: &parent.public,
    };
    public::create_checks(Some(&checked), &input.public, data_len).map_err(|rc| rc.param(2))?;
    let digest_size = input.public.digest_size();
    input.sensitive.auth =
        public::adjust_auth(&input.sensitive.auth, digest_size).map_err(|rc| rc.param(1))?;
    let mut drbg = Drbg::random()?;
    let mut public = input.public;
    let sensitive = create_object(&mut public, &input.sensitive, &mut drbg, None)?;
    let name = public.name();
    let name_alg = public.name_alg.ok_or(Rc::FAILURE)?;
    let hierarchy = parent.hierarchy;
    let (creation, creation_hash) =
        tpm.creation_data(parent_handle, name_alg, &mut input.pcrs, &input.outside);
    let parent = tpm.key(parent_handle).ok_or(Rc::FAILURE)?;
    let private = wrap(parent, &name, public.name_alg, &sensitive)?;
    w.tpm2b(&private);
    public.write_sized(w);
    w.tpm2b(&creation).tpm2b(&creation_hash);
    tpm.creation_ticket(hierarchy, &name, &creation_hash, w);
    Ok(())
}

/// TPM2_Load: an object Create (or ObjectChangeAuth) wrapped, back under its parent.
pub fn load(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let private = r.tpm2b(MAX_PRIVATE).map_err(|rc| rc.param(1))?.to_vec();
    let public = Public::read_sized(r, false).map_err(|rc| rc.param(2))?;
    end(r)?;
    tpm.free_slot()?;
    if private.is_empty() {
        return Err(Rc::SIZE.param(1));
    }
    let parent_handle = first(handles)?;
    let parent = tpm.key(parent_handle).filter(|p| p.is_parent());
    let parent = parent.ok_or(Rc::TYPE.handle(1))?;
    let name = public.name();
    let sensitive = unwrap(parent, &name, &private).map_err(|rc| rc.param(1))?;
    let mut key = load_checked(Some(parent), public, Some(sensitive), (2, 1))?;
    key.set_loaded(Some(parent), parent_handle);
    let name = key.name.clone();
    w.handle = Some(tpm.load_object(crate::object::Object::Key(Box::new(key)))?);
    w.tpm2b(&name);
    Ok(())
}

/// TPM2_LoadExternal: a public key, or (in the null hierarchy) a key the caller has in clear.
pub fn load_external(tpm: &mut Tpm, _: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let sensitive = Sensitive::read_sized(r).map_err(|rc| rc.param(1))?;
    let public = Public::read_sized(r, true).map_err(|rc| rc.param(2))?;
    let hierarchy = crate::object::read_hierarchy(r).map_err(|rc| rc.param(3))?;
    end(r)?;
    tpm.free_slot()?;
    tpm.hierarchy_enabled(hierarchy)
        .map_err(|_| Rc::HIERARCHY.param(3))?;
    if sensitive.is_some() {
        if hierarchy != TPM_RH_NULL {
            return Err(Rc::HIERARCHY.param(3));
        }
        if public.has(attr::FIXED_TPM)
            || public.has(attr::FIXED_PARENT)
            || public.has(attr::RESTRICTED)
        {
            return Err(Rc::ATTRIBUTES.param(2));
        }
    }
    let mut key = load_checked(None, public, sensitive, (2, 1))?;
    key.external = true;
    key.set_loaded(None, hierarchy);
    let name = key.name.clone();
    w.handle = Some(tpm.load_object(crate::object::Object::Key(Box::new(key)))?);
    w.tpm2b(&name);
    Ok(())
}

/// TPM2_ReadPublic: an object's public area, Name and qualified name.
pub fn read_public(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    end(r)?;
    let key = tpm.key(first(handles)?).ok_or(Rc::SEQUENCE)?;
    key.public.write_sized(w);
    w.tpm2b(&key.name).tpm2b(&key.qualified_name);
    Ok(())
}

/// TPM2_ObjectChangeAuth: the object wrapped again under its parent with a new authValue.
pub fn object_change_auth(
    tpm: &mut Tpm,
    handles: &[u32],
    r: &mut Reader,
    w: &mut Out,
) -> Result<()> {
    let new_auth = r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(1))?.to_vec();
    end(r)?;
    let (handle, parent_handle) = (first(handles)?, handles.get(1).copied().ok_or(Rc::FAILURE)?);
    let key = tpm.key(handle).ok_or(Rc::TYPE.handle(1))?;
    let auth =
        public::adjust_auth(&new_auth, key.public.digest_size()).map_err(|rc| rc.param(1))?;
    let parent = tpm.key(parent_handle);
    let parent_qn = parent.map_or_else(
        || parent_handle.to_be_bytes().to_vec(),
        |p| p.qualified_name.clone(),
    );
    if qualified_name(key.public.name_alg, &parent_qn, &key.name) != key.qualified_name {
        return Err(Rc::TYPE.handle(2));
    }
    let parent = parent.ok_or(Rc::TYPE.handle(2))?;
    let mut sensitive = key.sensitive.clone().ok_or(Rc::FAILURE)?;
    sensitive.auth = auth;
    let private = wrap(parent, &key.name, key.public.name_alg, &sensitive)?;
    w.tpm2b(&private);
    Ok(())
}

/// TPM2_Unseal: a sealed data object's secret.
pub fn unseal(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    end(r)?;
    let key = tpm.key(first(handles)?).ok_or(Rc::TYPE.handle(1))?;
    if key.public.kind() != Type::KeyedHash {
        return Err(Rc::TYPE.handle(1));
    }
    if key.public.has(attr::DECRYPT)
        || key.public.has(attr::SIGN)
        || key.public.has(attr::RESTRICTED)
    {
        return Err(Rc::ATTRIBUTES.handle(1));
    }
    let secret = key.sensitive.as_ref().map_or(&[][..], |s| &s.secret);
    w.tpm2b(secret);
    Ok(())
}

/// A TPMI_DH_PERSISTENT.
fn read_persistent(r: &mut Reader) -> Result<u32> {
    let h = r.u32()?;
    if (PERSISTENT_FIRST..=PERSISTENT_LAST).contains(&h) {
        Ok(h)
    } else {
        Err(Rc::VALUE)
    }
}

/// TPM2_EvictControl: make a loaded object persistent, or remove a persistent object.
pub fn evict_control(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let persistent = read_persistent(r).map_err(|rc| rc.param(1))?;
    end(r)?;
    let auth = first(handles)?;
    let object = handles.get(1).copied().ok_or(Rc::FAILURE)?;
    // A sequence is temporary.
    let key = tpm.key(object).ok_or(Rc::ATTRIBUTES.handle(2))?;
    if key.temporary || key.st_clear || key.public_only() {
        return Err(Rc::ATTRIBUTES.handle(2));
    }
    if key.evict.is_some_and(|h| h != persistent) {
        return Err(Rc::HANDLE.handle(2));
    }
    let platform_object = key.hierarchy == TPM_RH_PLATFORM;
    if auth == TPM_RH_PLATFORM {
        if key.evict.is_none() {
            if !platform_object {
                return Err(Rc::HIERARCHY.handle(2));
            }
            if persistent < PLATFORM_PERSISTENT {
                return Err(Rc::RANGE.param(1));
            }
        }
    } else {
        if platform_object {
            return Err(Rc::HIERARCHY.handle(2));
        }
        if key.evict.is_none() && persistent >= PLATFORM_PERSISTENT {
            return Err(Rc::RANGE.param(1));
        }
    }
    match key.evict {
        None => {
            if tpm.persistent(persistent).is_some() {
                return Err(Rc::NV_DEFINED);
            }
            if tpm.permanent.persistent.len() >= MAX_PERSISTENT {
                return Err(Rc::NV_SPACE);
            }
            let mut stored = key.clone();
            stored.evict = None;
            let list = &mut tpm.permanent.persistent;
            let at = list.partition_point(|(h, _)| *h < persistent);
            list.insert(at, (persistent, stored));
        }
        Some(_) => {
            tpm.permanent.persistent.retain(|(h, _)| *h != persistent);
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An RSA storage key of `bits`, with the longest authValue and seed.
    pub fn rsa_storage_key(bits: u16) -> Key {
        let mut public = storage_template(Params::Rsa {
            symmetric: Some(SymDef {
                bits: 256,
                mode: TPM_ALG_CFB,
            }),
            scheme: Scheme::NULL,
            bits,
            exponent: 0,
        });
        public.name_alg = Some(Hash::Sha512);
        public.auth_policy = vec![1; 64];
        let create = SensitiveCreate {
            auth: Zeroizing::new(vec![2; 64]),
            data: Zeroizing::new(Vec::new()),
        };
        let mut drbg = Drbg::seeded(&[3; 64], PRIMARY_OBJECT_CREATION, b"big", b"");
        let sensitive = create_object(&mut public, &create, &mut drbg, None).unwrap();
        let mut key = Key::new(public, Some(sensitive)).unwrap();
        key.set_loaded(None, TPM_RH_OWNER);
        key
    }
    use crate::public::{Scheme, SymDef, TPM_ALG_CFB};

    fn storage_template(params: Params) -> Public {
        Public {
            name_alg: Some(Hash::Sha256),
            attributes: attr::FIXED_TPM
                | attr::FIXED_PARENT
                | attr::SENSITIVE_DATA_ORIGIN
                | attr::USER_WITH_AUTH
                | attr::RESTRICTED
                | attr::DECRYPT,
            auth_policy: Vec::new(),
            unique: match params {
                Params::Ecc { .. } => Unique::Ecc {
                    x: Vec::new(),
                    y: Vec::new(),
                },
                Params::Rsa { .. } => Unique::Rsa(Vec::new()),
                _ => Unique::Digest(Vec::new()),
            },
            params,
        }
    }

    pub fn ecc_srk() -> Key {
        let mut public = storage_template(Params::Ecc {
            symmetric: Some(SymDef {
                bits: 128,
                mode: TPM_ALG_CFB,
            }),
            scheme: Scheme::NULL,
            curve: public::TPM_ECC_NIST_P256,
            kdf: Scheme::NULL,
        });
        let create = SensitiveCreate {
            auth: Zeroizing::new(Vec::new()),
            data: Zeroizing::new(Vec::new()),
        };
        let mut drbg = Drbg::seeded(&[7; 64], PRIMARY_OBJECT_CREATION, b"srk", b"");
        let sensitive = create_object(&mut public, &create, &mut drbg, None).unwrap();
        assert_eq!(sensitive.seed.len(), 32, "a parent keeps its seed");
        let mut key = Key::new(public, Some(sensitive)).unwrap();
        key.set_loaded(None, TPM_RH_OWNER);
        key
    }

    #[test]
    fn salts_decrypt_with_oaep_or_ecdh() {
        // RSA: OAEP with the nameAlg, "SECRET".
        let rsa = rsa_storage_key(2048);
        let Unique::Rsa(n) = &rsa.public.unique else {
            panic!("an RSA key");
        };
        let public = asym::rsa_public(n, 0).unwrap();
        let salt = [5u8; 64];
        let c = asym::rsa_encrypt(
            &public,
            public::TPM_ALG_OAEP,
            Some(Hash::Sha512),
            b"SECRET\0",
            &salt,
        )
        .unwrap();
        assert_eq!(*rsa.decrypt_secret(b"SECRET\0", &c).unwrap(), salt);
        assert_eq!(rsa.decrypt_secret(b"OTHER\0", &c), Err(Rc::VALUE));
        // ECC: an ephemeral point; Z's x-coordinate through KDFe.
        let srk = ecc_srk();
        let Unique::Ecc { x, y } = &srk.public.unique else {
            panic!("an ECC key");
        };
        let e = asym::ecc_random().unwrap();
        let (ex, ey) = asym::ecc_public(e.as_slice()).unwrap();
        let (zx, _) = asym::ecc_multiply(e.as_slice(), x, y).unwrap();
        let expected = crypt::kdfe(Hash::Sha256, &zx, b"SECRET\0", &ex, x, 32);
        let mut point = Writer::new();
        point.tpm2b(&ex).tpm2b(&ey);
        let point = point.into_bytes();
        assert_eq!(*srk.decrypt_secret(b"SECRET\0", &point).unwrap(), *expected);
        assert_eq!(
            srk.decrypt_secret(b"SECRET\0", &point[..10]),
            Err(Rc::INSUFFICIENT)
        );
    }

    #[test]
    fn keys_round_trip_through_the_state() {
        let srk = ecc_srk();
        let mut w = Writer::new();
        srk.write(&mut w);
        let bytes = w.into_bytes();
        let back = Key::read(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(back.public, srk.public);
        assert_eq!(back.qualified_name, srk.qualified_name);
        assert_eq!(back.sensitive, srk.sensitive);
    }
}
