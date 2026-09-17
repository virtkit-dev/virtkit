//! `/settings/tags/delete`: the POST an admin uses to remove a tag from `/browse/<repo>`.
//! Only the tag pointer is dropped; the content-addressed manifest and blobs are the gc's
//! to reclaim once nothing roots them (see [`crate::Store::delete_tag`]).

use anyhow::Result;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};

use crate::Body;
use crate::accounts::{self, Action, Db, Principal, User};
use crate::forms::{
    csrf_of, csrf_ok, csrf_rejected, form_body, see_other, server_error, too_large,
};
use crate::html;
use crate::{Store, query_param, valid_name, valid_tag};

pub(crate) async fn route(
    store: &Store,
    db: &Db,
    principal: &Principal,
    secure: bool,
    req: Request<Incoming>,
) -> Result<Response<Body>> {
    let Principal::Session(user) = principal else {
        return Ok(html::error(
            StatusCode::FORBIDDEN,
            Some(principal),
            None,
            "Not available to an API key",
            "Sign in with a browser session to delete a tag.",
        ));
    };
    if req.method() != Method::POST {
        return Ok(html::error(
            StatusCode::METHOD_NOT_ALLOWED,
            Some(principal),
            None,
            "That is not how a tag is deleted",
            "Tags are deleted from a repository's own page.",
        ));
    }
    delete(store, db, principal, user, secure, req).await
}

async fn delete(
    store: &Store,
    db: &Db,
    principal: &Principal,
    user: &User,
    secure: bool,
    req: Request<Incoming>,
) -> Result<Response<Body>> {
    let session_id = accounts::session_cookie(req.headers(), secure);
    let Some(body) = form_body(req).await else {
        return Ok(too_large(db, user, session_id.as_deref()));
    };
    if !csrf_ok(db, session_id.as_deref(), &body) {
        return Ok(csrf_rejected(db, user, session_id.as_deref()));
    }
    let bad = |title: &str, msg: &str| {
        Ok(html::error(
            StatusCode::BAD_REQUEST,
            Some(principal),
            csrf_of(db, session_id.as_deref()).as_deref(),
            title,
            msg,
        ))
    };
    // The repository is checked first: it is the table key `delete_tag` acts on and the
    // `Location` the redirect below builds. `valid_name` is the same gate `/v2/` applies.
    let Some(repo) = query_param(&body, "repo").filter(|r| valid_name(r)) else {
        return bad(
            "That is not a repository",
            "The form named no valid repository.",
        );
    };
    // The same `authorize` question the caption form asks, so a tag is deleted exactly where
    // a caption may be written: an admin session for this repository. One definition of that
    // rule, not a second copy of `is_admin` to keep in step.
    if !accounts::authorize(principal, Action::Write, &repo) {
        return Ok(html::error(
            StatusCode::FORBIDDEN,
            Some(principal),
            csrf_of(db, session_id.as_deref()).as_deref(),
            "Admins only",
            "A tag can only be deleted from an admin session.",
        ));
    }
    // A digest is not a tag — `valid_tag` rejects one, so this never unlinks a digest
    // reference (which has no pointer file anyway) or a name with a path separator.
    let Some(tag) = query_param(&body, "tag").filter(|t| valid_tag(t)) else {
        return bad(
            "That is not a tag",
            "The form named no valid tag to delete.",
        );
    };
    match store.delete_tag(&repo, &tag) {
        // Land back on the repository page whether or not the tag was still there: one
        // someone else deleted first is simply already gone, which is the same outcome.
        Ok(_) => see_other(&format!("/browse/{repo}")),
        Err(e) => {
            eprintln!("vk-registry: deleting the tag {repo}:{tag}: {e:#}");
            Ok(server_error(db, user, session_id.as_deref()))
        }
    }
}
