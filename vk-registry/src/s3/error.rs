//! S3's errors as AWS answers them: each code this view refuses with, the status that goes
//! with it and AWS's own message for it, in one table ([`Code`]), so a handler names a code
//! and the words are S3's. A refusal ([`Refusal`]) carries the code's message unless AWS has
//! a more specific one for the case (`InvalidArgument` and `InvalidRequest` always do), and
//! the elements AWS adds to its `Error` document for it — `BucketName`, `Key`, `UploadId`,
//! `ArgumentName` and `ArgumentValue`, `Condition`, `Header` and the like — which is where
//! the detail of a refusal goes.

use std::borrow::Cow;

use hyper::{Response, StatusCode};

use super::xml;
use crate::Body;

/// An S3 error code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Code {
    AccessDenied,
    AuthorizationHeaderMalformed,
    AuthorizationQueryParametersError,
    BadDigest,
    BucketAlreadyOwnedByYou,
    BucketNotEmpty,
    EntityTooLarge,
    IncompleteBody,
    InternalError,
    InvalidAccessKeyId,
    InvalidArgument,
    InvalidBucketName,
    InvalidChunkSizeError,
    InvalidDigest,
    InvalidPart,
    InvalidPartNumber,
    InvalidPartOrder,
    InvalidRange,
    InvalidRequest,
    InvalidStorageClass,
    InvalidToken,
    InvalidURI,
    KeyTooLongError,
    MalformedTrailerError,
    MalformedXML,
    MetadataTooLarge,
    NoSuchBucket,
    NoSuchBucketPolicy,
    NoSuchCORSConfiguration,
    NoSuchKey,
    NoSuchLifecycleConfiguration,
    NoSuchPublicAccessBlockConfiguration,
    NoSuchUpload,
    NoSuchWebsiteConfiguration,
    NotImplemented,
    ObjectLockConfigurationNotFoundError,
    OperationAborted,
    OwnershipControlsNotFoundError,
    PreconditionFailed,
    ReplicationConfigurationNotFoundError,
    RequestTimeTooSkewed,
    ServerSideEncryptionConfigurationNotFoundError,
    ServiceUnavailable,
    SignatureDoesNotMatch,
    XAmzContentSHA256Mismatch,
}

impl Code {
    /// The code's name, its status and AWS's message for it.
    const fn spec(self) -> (&'static str, StatusCode, &'static str) {
        use Code::*;
        const BAD: StatusCode = StatusCode::BAD_REQUEST;
        const GONE: StatusCode = StatusCode::NOT_FOUND;
        match self {
            AccessDenied => ("AccessDenied", StatusCode::FORBIDDEN, "Access Denied"),
            AuthorizationHeaderMalformed => (
                "AuthorizationHeaderMalformed",
                BAD,
                "The authorization header is malformed.",
            ),
            AuthorizationQueryParametersError => (
                "AuthorizationQueryParametersError",
                BAD,
                "Query-string authentication version 4 requires the X-Amz-Algorithm, \
                 X-Amz-Credential, X-Amz-Signature, X-Amz-Date, X-Amz-SignedHeaders, and \
                 X-Amz-Expires parameters.",
            ),
            BadDigest => (
                "BadDigest",
                BAD,
                "The Content-MD5 you specified did not match what we received.",
            ),
            BucketAlreadyOwnedByYou => (
                "BucketAlreadyOwnedByYou",
                StatusCode::CONFLICT,
                "Your previous request to create the named bucket succeeded and you already \
                 own it.",
            ),
            BucketNotEmpty => (
                "BucketNotEmpty",
                StatusCode::CONFLICT,
                "The bucket you tried to delete is not empty.",
            ),
            EntityTooLarge => (
                "EntityTooLarge",
                BAD,
                "Your proposed upload exceeds the maximum allowed object size.",
            ),
            IncompleteBody => (
                "IncompleteBody",
                BAD,
                "You did not provide the number of bytes specified by the Content-Length HTTP \
                 header",
            ),
            InternalError => (
                "InternalError",
                StatusCode::INTERNAL_SERVER_ERROR,
                "We encountered an internal error. Please try again.",
            ),
            InvalidAccessKeyId => (
                "InvalidAccessKeyId",
                StatusCode::FORBIDDEN,
                "The AWS Access Key Id you provided does not exist in our records.",
            ),
            InvalidArgument => ("InvalidArgument", BAD, "Invalid Argument"),
            InvalidBucketName => (
                "InvalidBucketName",
                BAD,
                "The specified bucket is not valid.",
            ),
            InvalidChunkSizeError => (
                "InvalidChunkSizeError",
                BAD,
                "Only the last chunk is allowed to have a size less than 8192 bytes",
            ),
            InvalidDigest => (
                "InvalidDigest",
                BAD,
                "The Content-Md5 you specified is not valid.",
            ),
            InvalidPart => (
                "InvalidPart",
                BAD,
                "One or more of the specified parts could not be found.  The part may not have \
                 been uploaded, or the specified entity tag may not match the part's entity \
                 tag.",
            ),
            InvalidPartNumber => (
                "InvalidPartNumber",
                StatusCode::RANGE_NOT_SATISFIABLE,
                "The requested partnumber is not satisfiable.",
            ),
            InvalidPartOrder => (
                "InvalidPartOrder",
                BAD,
                "The list of parts was not in ascending order. Parts must be ordered by part \
                 number.",
            ),
            InvalidRange => (
                "InvalidRange",
                StatusCode::RANGE_NOT_SATISFIABLE,
                "The requested range is not satisfiable",
            ),
            InvalidRequest => ("InvalidRequest", BAD, "Invalid Request"),
            InvalidStorageClass => (
                "InvalidStorageClass",
                BAD,
                "The storage class you specified is not valid",
            ),
            InvalidToken => (
                "InvalidToken",
                BAD,
                "The provided token is malformed or otherwise invalid.",
            ),
            InvalidURI => ("InvalidURI", BAD, "Couldn't parse the specified URI."),
            KeyTooLongError => ("KeyTooLongError", BAD, "Your key is too long."),
            MalformedTrailerError => (
                "MalformedTrailerError",
                BAD,
                "The request contained trailing data that was not well-formed or did not \
                 conform to our published schema.",
            ),
            MalformedXML => (
                "MalformedXML",
                BAD,
                "The XML you provided was not well-formed or did not validate against our \
                 published schema.",
            ),
            MetadataTooLarge => (
                "MetadataTooLarge",
                BAD,
                "Your metadata headers exceed the maximum allowed metadata size",
            ),
            NoSuchBucket => ("NoSuchBucket", GONE, "The specified bucket does not exist."),
            NoSuchBucketPolicy => (
                "NoSuchBucketPolicy",
                GONE,
                "The bucket policy does not exist.",
            ),
            NoSuchCORSConfiguration => (
                "NoSuchCORSConfiguration",
                GONE,
                "The CORS configuration does not exist",
            ),
            NoSuchKey => ("NoSuchKey", GONE, "The specified key does not exist."),
            NoSuchLifecycleConfiguration => (
                "NoSuchLifecycleConfiguration",
                GONE,
                "The lifecycle configuration does not exist",
            ),
            NoSuchPublicAccessBlockConfiguration => (
                "NoSuchPublicAccessBlockConfiguration",
                GONE,
                "The public access block configuration was not found",
            ),
            NoSuchUpload => (
                "NoSuchUpload",
                GONE,
                "The specified multipart upload does not exist. The upload ID may be invalid, \
                 or the upload may have been aborted or completed.",
            ),
            NoSuchWebsiteConfiguration => (
                "NoSuchWebsiteConfiguration",
                GONE,
                "The specified bucket does not have a website configuration",
            ),
            NotImplemented => (
                "NotImplemented",
                StatusCode::NOT_IMPLEMENTED,
                "A header you provided implies functionality that is not implemented",
            ),
            ObjectLockConfigurationNotFoundError => (
                "ObjectLockConfigurationNotFoundError",
                GONE,
                "Object Lock configuration does not exist for this bucket.",
            ),
            OperationAborted => (
                "OperationAborted",
                StatusCode::CONFLICT,
                "A conflicting conditional operation is currently in progress against this \
                 resource. Try again.",
            ),
            OwnershipControlsNotFoundError => (
                "OwnershipControlsNotFoundError",
                GONE,
                "The bucket ownership controls were not found.",
            ),
            PreconditionFailed => (
                "PreconditionFailed",
                StatusCode::PRECONDITION_FAILED,
                "At least one of the pre-conditions you specified did not hold",
            ),
            ReplicationConfigurationNotFoundError => (
                "ReplicationConfigurationNotFoundError",
                GONE,
                "The replication configuration was not found",
            ),
            RequestTimeTooSkewed => (
                "RequestTimeTooSkewed",
                StatusCode::FORBIDDEN,
                "The difference between the request time and the current time is too large.",
            ),
            ServerSideEncryptionConfigurationNotFoundError => (
                "ServerSideEncryptionConfigurationNotFoundError",
                GONE,
                "The server side encryption configuration was not found",
            ),
            ServiceUnavailable => (
                "ServiceUnavailable",
                StatusCode::SERVICE_UNAVAILABLE,
                "Please reduce your request rate.",
            ),
            SignatureDoesNotMatch => (
                "SignatureDoesNotMatch",
                StatusCode::FORBIDDEN,
                "The request signature we calculated does not match the signature you \
                 provided. Check your key and signing method.",
            ),
            XAmzContentSHA256Mismatch => (
                "XAmzContentSHA256Mismatch",
                BAD,
                "The provided 'x-amz-content-sha256' header does not match what was computed.",
            ),
        }
    }

    /// S3's name of the code.
    pub(crate) const fn name(self) -> &'static str {
        self.spec().0
    }

    /// The status S3 answers the code with.
    pub(crate) const fn status(self) -> StatusCode {
        self.spec().1
    }

    /// AWS's message for the code.
    pub(crate) const fn message(self) -> &'static str {
        self.spec().2
    }
}

/// A refusal: its code, the message (the code's, or AWS's own for the case), and the
/// elements AWS adds to the `Error` document, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub(crate) code: Code,
    message: Cow<'static, str>,
    extra: Vec<(&'static str, String)>,
}

impl From<Code> for Refusal {
    fn from(code: Code) -> Self {
        Refusal::new(code)
    }
}

impl Refusal {
    /// `code`, with its message.
    pub(crate) const fn new(code: Code) -> Self {
        Refusal {
            code,
            message: Cow::Borrowed(code.message()),
            extra: Vec::new(),
        }
    }

    /// `code`, with the message AWS gives this case of it.
    pub(crate) const fn said(code: Code, message: &'static str) -> Self {
        Refusal {
            code,
            message: Cow::Borrowed(message),
            extra: Vec::new(),
        }
    }

    /// [`said`](Self::said), the message made for this request.
    pub(crate) fn saying(code: Code, message: String) -> Self {
        Refusal {
            code,
            message: Cow::Owned(message),
            extra: Vec::new(),
        }
    }

    /// `InvalidArgument`, as AWS answers it: what is wrong with the argument `name`, which
    /// was sent as `value`.
    pub(crate) fn argument(
        message: impl Into<Cow<'static, str>>,
        name: &str,
        value: impl Into<String>,
    ) -> Self {
        Refusal {
            code: Code::InvalidArgument,
            message: message.into(),
            extra: Vec::new(),
        }
        .with("ArgumentName", name)
        .with("ArgumentValue", value)
    }

    /// The refusal with element `name` added, holding `value`.
    pub(crate) fn with(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.extra.push((name, value.into()));
        self
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    /// The value of element `name`, when the refusal carries it.
    #[cfg(test)]
    pub(crate) fn element(&self, name: &str) -> Option<&str> {
        self.extra
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }

    /// The `Error` document, for the request `request_id` naming `resource`.
    pub(crate) fn answer(&self, resource: &str, request_id: &str) -> Response<Body> {
        let extra: Vec<(&str, &str)> = self.extra.iter().map(|(n, v)| (*n, v.as_str())).collect();
        xml::error(
            self.code.status(),
            self.code.name(),
            &self.message,
            &extra,
            resource,
            request_id,
        )
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.name(), self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_carries_its_code_s_message_unless_given_one() {
        let r = Refusal::new(Code::NoSuchBucket).with("BucketName", "b");
        assert_eq!(r.code.status(), StatusCode::NOT_FOUND);
        assert_eq!(r.message(), "The specified bucket does not exist.");
        assert_eq!(r.element("BucketName"), Some("b"));
        let r = Refusal::argument("Invalid uploadId marker", "upload-id-marker", "x");
        assert_eq!(r.code, Code::InvalidArgument);
        assert_eq!(r.message(), "Invalid uploadId marker");
        assert_eq!(r.element("ArgumentName"), Some("upload-id-marker"));
        assert_eq!(r.element("ArgumentValue"), Some("x"));
    }

    #[test]
    fn every_code_is_named_as_s3_names_it() {
        for code in [
            Code::AccessDenied,
            Code::NoSuchUpload,
            Code::XAmzContentSHA256Mismatch,
            Code::ServerSideEncryptionConfigurationNotFoundError,
        ] {
            assert_eq!(code.name(), format!("{code:?}"));
            assert!(!code.message().is_empty());
        }
    }
}
