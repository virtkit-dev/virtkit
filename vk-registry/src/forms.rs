//! The machinery every settings form shares: reading a POSTed form body, the CSRF check
//! those POSTs carry, the redirect that answers one, and the three error pages a form can
//! end on. One copy of the CSRF rule for the settings routes, because a second copy is a
//! second thing to get subtly wrong.
//!
//! The pages here take `db` + `user` rather than a rendered `Principal` because each also
//! re-reads the session's CSRF secret: an error page still carries the sign-out control,
//! and that control is a form too.

use anyhow::Result;
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use crate::accounts::{Db, Principal, User};
use crate::html;
use crate::{Body, body_of};
use crate::{collect_capped, query_param};

/// Cap on a form POSTed to a settings route — a handful of short fields.
const MAX_FORM_BODY: usize = 8 * 1024;

/// Read a form body, or `None` if it is over [`MAX_FORM_BODY`] or is not UTF-8.
///
/// Strict, not `from_utf8_lossy`: a submitted field may be stored and rendered back, and
/// substituting U+FFFD for bytes the client never sent would both corrupt it silently and
/// make the caller's own control-character rule meaningless.
pub(crate) async fn form_body(req: Request<Incoming>) -> Option<String> {
    let bytes = collect_capped(req, MAX_FORM_BODY).await.ok()?;
    String::from_utf8(bytes.to_vec()).ok()
}

/// A POST that changed something answers `303`, so a refresh re-fetches the page
/// instead of re-submitting the form.
pub(crate) fn see_other(location: &str) -> Result<Response<Body>> {
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(hyper::header::LOCATION, location)
        .header(hyper::header::CACHE_CONTROL, "no-store")
        .body(body_of(Bytes::new()))
        .map_err(Into::into)
}

/// `submitted`'s `csrf` field must equal the session's own `csrf_secret`, compared in
/// constant time. A form posted from anywhere but a page this server rendered for this
/// session cannot have read that value, so this rejects a missing or wrong field, a
/// token from a different session, and a request with no session cookie at all.
pub(crate) fn csrf_ok(db: &Db, session_id: Option<&str>, submitted_body: &str) -> bool {
    let Some(expected) = csrf_of(db, session_id) else {
        return false;
    };
    match query_param(submitted_body, "csrf") {
        Some(p) => crate::auth::constant_eq(expected.as_bytes(), p.as_bytes()),
        None => false,
    }
}

/// The session's CSRF secret, for embedding in the forms a settings route renders.
pub(crate) fn csrf_of(db: &Db, session_id: Option<&str>) -> Option<String> {
    let id = session_id?;
    match db.session_csrf(id) {
        Ok(v) => v,
        // The page renders fine without it; the forms on it will simply be refused, and
        // the log says why.
        Err(e) => {
            eprintln!("vk-registry: reading a session's CSRF secret: {e:#}");
            None
        }
    }
}

pub(crate) fn csrf_rejected(db: &Db, user: &User, session_id: Option<&str>) -> Response<Body> {
    html::error(
        StatusCode::FORBIDDEN,
        Some(&Principal::Session(user.clone())),
        csrf_of(db, session_id).as_deref(),
        "That request did not come from this page",
        "Its security token was missing or stale. Reload the page and try again.",
    )
}

pub(crate) fn too_large(db: &Db, user: &User, session_id: Option<&str>) -> Response<Body> {
    html::error(
        StatusCode::PAYLOAD_TOO_LARGE,
        Some(&Principal::Session(user.clone())),
        csrf_of(db, session_id).as_deref(),
        "That form was too large",
        "Shorten the fields and try again.",
    )
}

pub(crate) fn server_error(db: &Db, user: &User, session_id: Option<&str>) -> Response<Body> {
    html::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        Some(&Principal::Session(user.clone())),
        csrf_of(db, session_id).as_deref(),
        "Something went wrong",
        "The server could not complete that. Try again shortly.",
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// A store of this test's own. Unit tests run as threads in one process, so the pid
    /// alone does not separate two of them — the caller's tag does.
    fn store_for(tag: &str) -> Db {
        let dir = std::env::temp_dir().join(format!("vk-forms-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Db::open(&dir.join("registry.db")).unwrap()
    }

    #[test]
    fn csrf_ok_requires_this_sessions_token() {
        let db = store_for("csrf");
        let user = db
            .upsert_user("https://issuer", "sub-1", None, None)
            .unwrap();
        let session = db
            .create_session(&user.id, Duration::from_secs(3600))
            .unwrap();
        let real_csrf = db.session_csrf(&session).unwrap().unwrap();

        assert!(csrf_ok(&db, Some(&session), &format!("csrf={real_csrf}")));
        assert!(!csrf_ok(&db, Some(&session), "csrf=wrong"));
        // the cross-site shape: a POST with no token at all
        assert!(!csrf_ok(&db, Some(&session), "name=x&action=read"));
        assert!(!csrf_ok(&db, Some(&session), ""));
        assert!(!csrf_ok(&db, None, &format!("csrf={real_csrf}")));
        assert!(!csrf_ok(
            &db,
            Some("no-such-session"),
            &format!("csrf={real_csrf}")
        ));

        // and a token minted for a different session does not carry over
        let other = db
            .upsert_user("https://issuer", "sub-2", None, None)
            .unwrap();
        let other_session = db
            .create_session(&other.id, Duration::from_secs(3600))
            .unwrap();
        let other_csrf = db.session_csrf(&other_session).unwrap().unwrap();
        assert_ne!(real_csrf, other_csrf);
        assert!(!csrf_ok(&db, Some(&session), &format!("csrf={other_csrf}")));
    }
}
