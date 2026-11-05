//! The XML S3 answers in: the `Error` document every refusal carries.

use bytes::Bytes;
use hyper::header::CONTENT_TYPE;
use hyper::{Response, StatusCode};

use crate::{Body, body_of};

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
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{}</Code><Message>{}</Message>",
        escape(code),
        escape(message)
    );
    for (name, value) in extra {
        body.push_str(&format!("<{name}>{}</{name}>", escape(value)));
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
}
