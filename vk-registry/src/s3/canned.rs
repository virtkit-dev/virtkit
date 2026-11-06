//! The configuration a bucket or an object is asked for, answered as S3 answers for one
//! with nothing configured: tools probe versioning, tagging, ACLs, lifecycle and the rest
//! before they use a bucket, and go on when they hear there is none. Nothing of it can be
//! set here: a `PUT` or `DELETE` of any of them is `NotImplemented`, and so is a request
//! whose headers ask for one on the object or bucket it writes ([`asked`]).

use hyper::Response;
use hyper::header::HeaderMap;

use super::bucket::{OWNER, owner};
use super::error::{Code, Refusal};
use super::xml;

/// What a configuration read answers.
pub(super) enum Canned {
    /// a 200 document: its root element and what it holds
    Document(&'static str, String),
    /// a 404: S3's code for "none configured"
    Missing(Code),
}

impl Canned {
    /// The answer, at `ctx`'s path, for `bucket`.
    pub(super) fn answer(self, bucket: &str, ctx: &super::Ctx) -> Response<crate::Body> {
        match self {
            Canned::Document(root, inner) => xml::document(root, &inner),
            Canned::Missing(code) => ctx.error(Refusal::new(code).with("BucketName", bucket)),
        }
    }
}

/// The ACL every bucket and object has: the owner [`OWNER`], who may do anything.
fn acl() -> Canned {
    let grantee = format!(
        "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \
         xsi:type=\"CanonicalUser\">{}{}</Grantee>",
        xml::element("ID", OWNER),
        xml::element("DisplayName", OWNER)
    );
    Canned::Document(
        "AccessControlPolicy",
        format!(
            "{}<AccessControlList><Grant>{grantee}{}</Grant></AccessControlList>",
            owner(),
            xml::element("Permission", "FULL_CONTROL")
        ),
    )
}

fn empty(root: &'static str) -> Canned {
    Canned::Document(root, String::new())
}

/// What a `GET /s3/<bucket>?<sub>` answers, when `sub` is a configuration S3 has.
pub(super) fn bucket(sub: &str) -> Option<Canned> {
    Some(match sub {
        "versioning" => empty("VersioningConfiguration"),
        "tagging" => Canned::Document("Tagging", "<TagSet/>".to_string()),
        "acl" => acl(),
        "logging" => empty("BucketLoggingStatus"),
        "notification" => empty("NotificationConfiguration"),
        "requestPayment" => Canned::Document(
            "RequestPaymentConfiguration",
            xml::element("Payer", "BucketOwner"),
        ),
        "accelerate" => empty("AccelerateConfiguration"),
        "lifecycle" => Canned::Missing(Code::NoSuchLifecycleConfiguration),
        "policy" | "policyStatus" => Canned::Missing(Code::NoSuchBucketPolicy),
        "cors" => Canned::Missing(Code::NoSuchCORSConfiguration),
        "encryption" => Canned::Missing(Code::ServerSideEncryptionConfigurationNotFoundError),
        "object-lock" => Canned::Missing(Code::ObjectLockConfigurationNotFoundError),
        "replication" => Canned::Missing(Code::ReplicationConfigurationNotFoundError),
        "website" => Canned::Missing(Code::NoSuchWebsiteConfiguration),
        "publicAccessBlock" => Canned::Missing(Code::NoSuchPublicAccessBlockConfiguration),
        "ownershipControls" => Canned::Missing(Code::OwnershipControlsNotFoundError),
        _ => return None,
    })
}

/// What a `GET /s3/<bucket>/<key>?<sub>` answers, when `sub` is a configuration S3 has.
pub(super) fn object(sub: &str) -> Option<Canned> {
    Some(match sub {
        "tagging" => Canned::Document("Tagging", "<TagSet/>".to_string()),
        "acl" => acl(),
        _ => return None,
    })
}

/// The storage classes S3 has: `STANDARD` is the one here, the others are not served, and
/// anything else is no class at all.
const STORAGE_CLASSES: [&str; 10] = [
    "STANDARD",
    "REDUCED_REDUNDANCY",
    "STANDARD_IA",
    "ONEZONE_IA",
    "INTELLIGENT_TIERING",
    "GLACIER",
    "DEEP_ARCHIVE",
    "OUTPOSTS",
    "GLACIER_IR",
    "EXPRESS_ONEZONE",
];

/// What a request's headers ask for that this registry keeps nothing of, refused as the
/// `PUT` of that configuration is rather than taken and dropped: a client that asked for its
/// object to be encrypted under its own key would otherwise be told it was, and the bytes
/// stored and served plain. Encryption of any kind (SSE-S3, SSE-KMS, SSE-C, on a read or a
/// copy's source too), object tags, an ACL other than the one every object has, a grant, a
/// storage class other than `STANDARD`, a website redirect and object lock are
/// `NotImplemented`; a storage class S3 does not have is `InvalidStorageClass`.
pub(super) fn asked(headers: &HeaderMap) -> Option<Refusal> {
    // AWS names the header a NotImplemented is about.
    let not_implemented = |header: &str| Refusal::new(Code::NotImplemented).with("Header", header);
    for name in headers.keys() {
        let name = name.as_str();
        // No tags at all is what every object has.
        if name.contains("server-side-encryption")
            || (name == "x-amz-tagging" && headers.get_all(name).iter().any(|v| !v.is_empty()))
            || name.starts_with("x-amz-grant-")
            || name.starts_with("x-amz-object-lock-")
            || name == "x-amz-website-redirect-location"
        {
            return Some(not_implemented(name));
        }
    }
    // The ACL every object and bucket has, by either of its names, asks for nothing new.
    if headers
        .get_all("x-amz-acl")
        .iter()
        .any(|v| !matches!(v.as_bytes(), b"private" | b"bucket-owner-full-control"))
    {
        return Some(not_implemented("x-amz-acl"));
    }
    for value in headers.get_all("x-amz-storage-class") {
        let class = value.to_str().unwrap_or_default();
        if class == "STANDARD" {
            continue;
        }
        if STORAGE_CLASSES.contains(&class) {
            return Some(not_implemented("x-amz-storage-class"));
        }
        return Some(Refusal::new(Code::InvalidStorageClass).with("StorageClassRequested", class));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_bucket_configuration_has_an_answer_and_nothing_else_does() {
        for sub in [
            "versioning",
            "tagging",
            "acl",
            "logging",
            "notification",
            "requestPayment",
            "accelerate",
            "lifecycle",
            "policy",
            "policyStatus",
            "cors",
            "encryption",
            "object-lock",
            "replication",
            "website",
            "publicAccessBlock",
            "ownershipControls",
        ] {
            assert!(bucket(sub).is_some(), "{sub}");
        }
        for sub in [
            "",
            "uploads",
            "delete",
            "location",
            "Versioning",
            "intelligent-tiering",
        ] {
            assert!(bucket(sub).is_none(), "{sub}");
        }
        assert!(object("tagging").is_some() && object("acl").is_some());
        assert!(object("versioning").is_none() && object("retention").is_none());
    }

    #[test]
    fn headers_asking_for_what_is_not_kept_are_refused() {
        let of = |pairs: &[(&str, &str)]| {
            let mut h = HeaderMap::new();
            for (n, v) in pairs {
                h.append(
                    hyper::header::HeaderName::from_bytes(n.as_bytes()).unwrap(),
                    hyper::header::HeaderValue::from_str(v).unwrap(),
                );
            }
            asked(&h).map(|r| (r.code.status().as_u16(), r.code.name()))
        };
        assert_eq!(of(&[]), None);
        assert_eq!(
            of(&[
                ("x-amz-acl", "private"),
                ("x-amz-storage-class", "STANDARD"),
                ("x-amz-meta-x", "1"),
                ("x-amz-tagging-directive", "COPY"),
                ("content-type", "text/plain"),
            ]),
            None
        );
        assert_eq!(of(&[("x-amz-acl", "bucket-owner-full-control")]), None);
        assert_eq!(of(&[("x-amz-tagging", "")]), None);
        let refused = Some((501, "NotImplemented"));
        for (name, value) in [
            ("x-amz-server-side-encryption", "AES256"),
            ("x-amz-server-side-encryption", "aws:kms"),
            ("x-amz-server-side-encryption-aws-kms-key-id", "k"),
            ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
            ("x-amz-server-side-encryption-customer-key", "a2V5"),
            ("x-amz-server-side-encryption-customer-key-md5", "bWQ1"),
            ("x-amz-server-side-encryption-bucket-key-enabled", "true"),
            (
                "x-amz-copy-source-server-side-encryption-customer-algorithm",
                "AES256",
            ),
            ("x-amz-tagging", "a=b"),
            ("x-amz-acl", "public-read"),
            ("x-amz-acl", "PRIVATE"),
            ("x-amz-grant-read", "id=x"),
            ("x-amz-grant-full-control", "id=x"),
            ("x-amz-storage-class", "GLACIER"),
            ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
            ("x-amz-website-redirect-location", "/x"),
            ("x-amz-object-lock-mode", "GOVERNANCE"),
            (
                "x-amz-object-lock-retain-until-date",
                "2030-01-01T00:00:00Z",
            ),
            ("x-amz-object-lock-legal-hold", "ON"),
        ] {
            assert_eq!(of(&[(name, value)]), refused, "{name}: {value}");
        }
        for bad in ["INVALID_CLASS", "standard", ""] {
            assert_eq!(
                of(&[("x-amz-storage-class", bad)]),
                Some((400, "InvalidStorageClass")),
                "{bad:?}"
            );
        }
        // A refusal names the header, and says what AWS says.
        let mut h = HeaderMap::new();
        h.insert(
            "x-amz-grant-read",
            hyper::header::HeaderValue::from_static("id=x"),
        );
        let r = asked(&h).unwrap();
        assert_eq!(r.element("Header"), Some("x-amz-grant-read"));
        assert_eq!(
            r.message(),
            "A header you provided implies functionality that is not implemented"
        );
        // Checked in that order: a refusal names the first thing asked for.
        assert_eq!(
            of(&[("x-amz-acl", "public-read"), ("x-amz-storage-class", "x")]),
            refused
        );
    }

    #[test]
    fn the_acl_grants_the_owner_everything() {
        let Some(Canned::Document(root, inner)) = bucket("acl") else {
            panic!("a document");
        };
        assert_eq!(root, "AccessControlPolicy");
        assert_eq!(
            inner,
            "<Owner><ID>vk-registry</ID><DisplayName>vk-registry</DisplayName></Owner>\
             <AccessControlList><Grant><Grantee \
             xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \
             xsi:type=\"CanonicalUser\"><ID>vk-registry</ID>\
             <DisplayName>vk-registry</DisplayName></Grantee>\
             <Permission>FULL_CONTROL</Permission></Grant></AccessControlList>"
        );
    }
}
