//! EFI GUIDs, in their in-memory byte order, and the ones the variable service names.

/// An EFI_GUID as it lies in memory: the first three fields little-endian.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    pub const fn new(a: u32, b: u16, c: u16, d: [u8; 8]) -> Guid {
        let a = a.to_le_bytes();
        let b = b.to_le_bytes();
        let c = c.to_le_bytes();
        Guid([
            a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5],
            d[6], d[7],
        ])
    }
}

impl std::fmt::Debug for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = &self.0;
        let a = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let m = u16::from_le_bytes([b[4], b[5]]);
        let n = u16::from_le_bytes([b[6], b[7]]);
        write!(f, "{a:08x}-{m:04x}-{n:04x}-{:02x}{:02x}-", b[8], b[9])?;
        for x in &b[10..] {
            write!(f, "{x:02x}")?;
        }
        Ok(())
    }
}

impl std::fmt::Display for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// EFI_GLOBAL_VARIABLE: PK, KEK, Boot####, SecureBoot, SetupMode, ...
pub const GLOBAL_VARIABLE: Guid = Guid::new(
    0x8be4df61,
    0x93ca,
    0x11d2,
    [0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
);
/// EFI_IMAGE_SECURITY_DATABASE_GUID: db, dbx, dbt, dbr.
pub const IMAGE_SECURITY_DATABASE: Guid = Guid::new(
    0xd719b2cb,
    0x3d3a,
    0x4596,
    [0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f],
);
/// The MM handler of the variable protocol (gEfiSmmVariableProtocolGuid).
pub const SMM_VARIABLE_PROTOCOL: Guid = Guid::new(
    0xed32d533,
    0x99e6,
    0x4209,
    [0x9c, 0xc0, 0x2d, 0x72, 0xcd, 0xd9, 0x98, 0xa7],
);
/// The MM handler of variable policies (gVarCheckPolicyLibMmiHandlerGuid).
pub const VAR_CHECK_POLICY_MMI: Guid = Guid::new(
    0xda1b0d11,
    0xd1a7,
    0x46c4,
    [0x9d, 0xc9, 0xf3, 0x71, 0x48, 0x75, 0xc6, 0xeb],
);
/// WIN_CERTIFICATE_UEFI_GUID's CertType for PKCS#7 signed data.
pub const CERT_PKCS7: Guid = Guid::new(
    0x4aafd29d,
    0x68df,
    0x49ee,
    [0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7],
);
/// EFI_CERT_X509_GUID: a signature list of DER certificates.
pub const CERT_X509: Guid = Guid::new(
    0xa5c059a1,
    0x94e4,
    0x4aa7,
    [0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72],
);
pub const CERT_SHA1: Guid = Guid::new(
    0x826ca512,
    0xcf10,
    0x4ac9,
    [0xb1, 0x87, 0xbe, 0x01, 0x49, 0x66, 0x31, 0xbd],
);
pub const CERT_SHA256: Guid = Guid::new(
    0xc1c41626,
    0x504c,
    0x4092,
    [0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28],
);
pub const CERT_SHA384: Guid = Guid::new(
    0xff3e5307,
    0x9fd0,
    0x48c9,
    [0x85, 0xf1, 0x8a, 0xd5, 0x6c, 0x70, 0x1e, 0x01],
);
pub const CERT_SHA512: Guid = Guid::new(
    0x093e0fae,
    0xa6c4,
    0x4f50,
    [0x9f, 0x1b, 0xd4, 0x1e, 0x2b, 0x89, 0xc1, 0x9a],
);
pub const CERT_RSA2048: Guid = Guid::new(
    0x3c5766e8,
    0x269c,
    0x4e34,
    [0xaa, 0x14, 0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6],
);
pub const CERT_X509_SHA256: Guid = Guid::new(
    0x3bd2a492,
    0x96c0,
    0x4079,
    [0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed],
);
pub const CERT_X509_SHA384: Guid = Guid::new(
    0x7076876e,
    0x80c2,
    0x4ee6,
    [0xaa, 0xd2, 0x28, 0xb3, 0x49, 0xa6, 0x86, 0x5b],
);
pub const CERT_X509_SHA512: Guid = Guid::new(
    0x446dbf63,
    0x2502,
    0x4cda,
    [0xbc, 0xfa, 0x24, 0x65, 0xd2, 0xb0, 0xfe, 0x9d],
);
/// edk2's record of the signers of private authenticated variables (certdb, certdbv).
pub const CERT_DB: Guid = Guid::new(
    0xd9bee56e,
    0x75dc,
    0x49d9,
    [0xb4, 0xd7, 0xb5, 0x34, 0x21, 0x0f, 0x63, 0x7a],
);
/// edk2's SecureBootEnable (the user's switch, honoured by edk2 alone).
pub const SECURE_BOOT_ENABLE_DISABLE: Guid = Guid::new(
    0xf0a30bc7,
    0xaf08,
    0x4556,
    [0x99, 0xc4, 0x00, 0x10, 0x09, 0xc9, 0x3a, 0x44],
);
/// edk2's VendorKeysNv.
pub const VENDOR_KEYS_NV: Guid = Guid::new(
    0x9073e4e0,
    0x60ec,
    0x4b6e,
    [0x99, 0x03, 0x4c, 0x22, 0x3c, 0x26, 0x0f, 0x3c],
);
/// The variable store signature of edk2's authenticated variable format.
pub const AUTHENTICATED_VARIABLE: Guid = Guid::new(
    0xaaf32c78,
    0x947b,
    0x439a,
    [0xa1, 0x80, 0x2e, 0x14, 0x4e, 0xc3, 0x77, 0x92],
);
/// EFI_SYSTEM_NV_DATA_FV_GUID: the firmware volume holding the variable store.
pub const SYSTEM_NV_DATA_FV: Guid = Guid::new(
    0xfff12b8d,
    0x7696,
    0x4c8b,
    [0xa9, 0x85, 0x27, 0x47, 0x07, 0x5b, 0x4f, 0x50],
);
