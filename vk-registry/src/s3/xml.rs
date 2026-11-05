//! The XML S3 answers in: the `Error` document every refusal carries, and the documents of
//! the operations that answer with one.

use bytes::Bytes;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::{Response, StatusCode};

use crate::{Body, body_of};

/// The namespace of S3's documents.
pub(crate) const NS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// The XML declaration every document starts with.
const DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";

/// A 200 answer whose document is `root`, in S3's namespace, holding `inner`: elements
/// already built, every caller string in them escaped.
pub(crate) fn document(root: &str, inner: &str) -> Response<Body> {
    let body = if inner.is_empty() {
        format!("{DECLARATION}<{root} xmlns=\"{NS}\"/>")
    } else {
        format!("{DECLARATION}<{root} xmlns=\"{NS}\">{inner}</{root}>")
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/xml")
        .header(CONTENT_LENGTH, body.len().to_string())
        .body(body_of(Bytes::from(body)))
        .expect("building an S3 document")
}

/// `<name>text</name>`, the text escaped.
pub(crate) fn element(name: &str, text: &str) -> String {
    format!("<{name}>{}</{name}>", escape(text))
}

/// Escape a string for XML text: [`crate::html_escape`]'s five characters are XML's too.
/// What reaches it is a request path, a header value or a message of ours, none of which
/// can hold a control character XML 1.0 has no way to write.
pub(crate) fn escape(s: &str) -> String {
    crate::html_escape(s)
}

/// An S3 `Error` document: `code`, `message`, then each of `extra` as an element of its
/// own (`ServerTime` and the like), the `resource` the request named and its `request_id`.
/// Every string is escaped.
pub(crate) fn error(
    status: StatusCode,
    code: &str,
    message: &str,
    extra: &[(&str, &str)],
    resource: &str,
    request_id: &str,
) -> Response<Body> {
    let mut body = format!(
        "{DECLARATION}<Error><Code>{}</Code><Message>{}</Message>",
        escape(code),
        escape(message)
    );
    for (name, value) in extra {
        body.push_str(&element(name, value));
    }
    body.push_str(&format!(
        "<Resource>{}</Resource><RequestId>{}</RequestId></Error>",
        escape(resource),
        escape(request_id)
    ));
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/xml")
        .body(body_of(Bytes::from(body)))
        .expect("building an S3 error")
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt as _;

    #[tokio::test]
    async fn every_caller_string_is_escaped() {
        let resp = error(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "a <b> & 'c' \"d\"",
            &[("RequestTime", "<t>")],
            "/s3/</Resource><x>",
            "0123456789abcdef",
        );
        assert_eq!(resp.status(), 403);
        assert_eq!(resp.headers()[CONTENT_TYPE], "application/xml");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>AccessDenied</Code>\
             <Message>a &lt;b&gt; &amp; &#39;c&#39; &quot;d&quot;</Message>\
             <RequestTime>&lt;t&gt;</RequestTime>\
             <Resource>/s3/&lt;/Resource&gt;&lt;x&gt;</Resource>\
             <RequestId>0123456789abcdef</RequestId></Error>"
        );
    }

    #[tokio::test]
    async fn a_document_is_in_s3_s_namespace() {
        let body = async |resp: Response<Body>| {
            assert_eq!(resp.status(), 200);
            assert_eq!(resp.headers()[CONTENT_TYPE], "application/xml");
            let len: usize = resp.headers()[CONTENT_LENGTH]
                .to_str()
                .unwrap()
                .parse()
                .unwrap();
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body.len(), len);
            String::from_utf8(body.to_vec()).unwrap()
        };
        assert_eq!(
            body(document("LocationConstraint", "")).await,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>"
        );
        assert_eq!(
            body(document("R", &element("Name", "a<b"))).await,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <R xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>a&lt;b</Name></R>"
        );
    }
}
