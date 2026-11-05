//! The configuration a bucket or an object is asked for, answered as S3 answers for one
//! with nothing configured: tools probe versioning, tagging, ACLs, lifecycle and the rest
//! before they use a bucket, and go on when they hear there is none. Nothing of it can be
//! set here; a `PUT` or `DELETE` of any of them is `NotImplemented`.

use hyper::{Response, StatusCode};

use super::bucket::{OWNER, owner};
use super::xml;

/// What a configuration read answers.
pub(super) enum Canned {
    /// a 200 document: its root element and what it holds
    Document(&'static str, String),
    /// a 404: S3's code for "none configured"
    Missing(&'static str),
}

impl Canned {
    /// The answer, at `ctx`'s path.
    pub(super) fn answer(self, ctx: &super::Ctx) -> Response<crate::Body> {
        match self {
            Canned::Document(root, inner) => xml::document(root, &inner),
            Canned::Missing(code) => ctx.error(
                StatusCode::NOT_FOUND,
                code,
                "this registry keeps no such configuration",
            ),
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
        "lifecycle" => Canned::Missing("NoSuchLifecycleConfiguration"),
        "policy" | "policyStatus" => Canned::Missing("NoSuchBucketPolicy"),
        "cors" => Canned::Missing("NoSuchCORSConfiguration"),
        "encryption" => Canned::Missing("ServerSideEncryptionConfigurationNotFoundError"),
        "object-lock" => Canned::Missing("ObjectLockConfigurationNotFoundError"),
        "replication" => Canned::Missing("ReplicationConfigurationNotFoundError"),
        "website" => Canned::Missing("NoSuchWebsiteConfiguration"),
        "publicAccessBlock" => Canned::Missing("NoSuchPublicAccessBlockConfiguration"),
        "ownershipControls" => Canned::Missing("OwnershipControlsNotFoundError"),
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
