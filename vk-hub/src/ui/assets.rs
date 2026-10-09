//! The files pages load, embedded in the binary and served under a path carrying a hash of
//! their content, so a browser may keep each for good: a new build that changes one changes
//! its path. `assets/VENDOR.md` says where the vendored ones come from; `ui.css`, `time.js`
//! and `favicon.svg` (virtkit's mark, `docs/assets/logo-mark.svg`) are the UI's own.

use std::sync::LazyLock;

use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Response, StatusCode};
use sha2::{Digest, Sha256};

use super::Body;

pub struct Asset {
    pub name: &'static str,
    content_type: &'static str,
    bytes: &'static [u8],
}

pub const CSS: &str = "ui.css";
pub const HTMX: &str = "htmx.min.js";
pub const SSE: &str = "sse.min.js";
pub const TIME: &str = "time.js";
pub const ICON: &str = "favicon.svg";

static FILES: [Asset; 5] = [
    Asset {
        name: CSS,
        content_type: "text/css; charset=utf-8",
        bytes: include_bytes!("../../assets/ui.css"),
    },
    Asset {
        name: HTMX,
        content_type: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../../assets/htmx.min.js"),
    },
    Asset {
        name: SSE,
        content_type: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../../assets/sse.min.js"),
    },
    Asset {
        name: TIME,
        content_type: "text/javascript; charset=utf-8",
        bytes: include_bytes!("../../assets/time.js"),
    },
    Asset {
        name: ICON,
        content_type: "image/svg+xml",
        bytes: include_bytes!("../../assets/favicon.svg"),
    },
];

/// Each file with its path, `/assets/<hash>/<name>`, and its quoted ETag.
static SERVED: LazyLock<Vec<(String, String, &'static Asset)>> = LazyLock::new(|| {
    FILES
        .iter()
        .map(|asset| {
            let hash = vk_hub_proto::to_hex(&Sha256::digest(asset.bytes));
            let hash = hash.get(..16).unwrap_or(&hash).to_string();
            (
                format!("/assets/{hash}/{}", asset.name),
                format!("\"{hash}\""),
                asset,
            )
        })
        .collect()
});

/// The path asset `name` is served at.
pub fn url(name: &str) -> &'static str {
    SERVED
        .iter()
        .find(|(_, _, a)| a.name == name)
        .map_or("/assets/missing", |(path, _, _)| path.as_str())
}

/// The response for `path` if it is an asset's.
pub fn serve(path: &str, headers: &HeaderMap) -> Option<Response<Body>> {
    let (_, etag, asset) = SERVED.iter().find(|(p, _, _)| p == path)?;
    let fresh = headers
        .get(header::IF_NONE_MATCH)
        .is_some_and(|v| v.as_bytes() == etag.as_bytes());
    let mut resp = if fresh {
        let mut resp = Response::new(Body::default());
        *resp.status_mut() = StatusCode::NOT_MODIFIED;
        resp
    } else {
        Response::new(Body::from(asset.bytes))
    };
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(asset.content_type),
    );
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    if let Ok(v) = HeaderValue::from_str(etag) {
        h.insert(header::ETAG, v);
    }
    Some(resp)
}
