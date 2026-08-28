//! `/settings/captions`: the POST that sets or clears a repository's caption — the one line
//! `/browse/<repo>` shows above its tag list.

use anyhow::Result;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};

use crate::accounts::{self, Action, Db, Principal, User};
use crate::forms::{
    csrf_of, csrf_ok, csrf_rejected, form_body, see_other, server_error, too_large,
};
use crate::html;
use crate::{query_param, valid_name};

pub(crate) async fn route(
    db: &Db,
    principal: &Principal,
    secure: bool,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>> {
    let Principal::Session(user) = principal else {
        return Ok(html::error(
            StatusCode::FORBIDDEN,
            Some(principal),
            None,
            "Not available to an API key",
            "Sign in with a browser session to edit a caption.",
        ));
    };
    if req.method() != Method::POST {
        return Ok(html::error(
            StatusCode::METHOD_NOT_ALLOWED,
            Some(principal),
            None,
            "That is not how a caption is set",
            "Captions are edited from a repository's own page.",
        ));
    }
    set(db, principal, user, secure, req).await
}

async fn set(
    db: &Db,
    principal: &Principal,
    user: &User,
    secure: bool,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>> {
    let session_id = accounts::session_cookie(req.headers(), secure);
    let Some(body) = form_body(req).await else {
        return Ok(too_large(db, user, session_id.as_deref()));
    };
    if !csrf_ok(db, session_id.as_deref(), &body) {
        return Ok(csrf_rejected(db, user, session_id.as_deref()));
    }
    // `html::error` escapes its detail, so these say where to go rather than linking there;
    // the shared nav already carries a `browse` link on every page, and a refusal that names
    // the repository is not a dead end from it.
    let bad = |title: &str, msg: &str| {
        Ok(html::error(
            StatusCode::BAD_REQUEST,
            Some(principal),
            csrf_of(db, session_id.as_deref()).as_deref(),
            title,
            msg,
        ))
    };
    // Checked before the caption itself: a repository name is what the redirect below puts
    // in a `Location`, and it is a table key. `valid_name` is the same gate `/v2/` applies.
    let Some(repo) = query_param(&body, "repo").filter(|r| valid_name(r)) else {
        return bad(
            "That is not a repository",
            "The form named no valid repository.",
        );
    };
    // Asked of `authorize` rather than of `user.is_admin`, so the rule has one definition:
    // writing a caption is writing to the repository, and a session's write power is
    // admin-only there by a decision that doc says is meant to be revisited. A second copy
    // of it here would not be revisited with it.
    if !accounts::authorize(principal, Action::Write, &repo) {
        return Ok(html::error(
            StatusCode::FORBIDDEN,
            Some(principal),
            csrf_of(db, session_id.as_deref()).as_deref(),
            "Admins only",
            "A repository's caption can only be changed from an admin session.",
        ));
    }
    // An *absent* `caption` is a malformed request, not a clear: clearing is what an empty
    // value means, and the two must not be the same POST when one of them destroys a
    // caption. Every browser sends the field; a truncated request does not.
    let Some(caption) = query_param(&body, "caption") else {
        return bad(
            "That form was incomplete",
            &format!(
                "It carried no caption field. Reopen {repo} from browse and try again — \
                 emptying the box is how a caption is removed."
            ),
        );
    };
    // Validated here as well as in the store: this is the half a person can fix, and it
    // reaches them as a sentence instead of as a failed write. The store's own wording is
    // forwarded because it is the specific part — which limit, and by how much.
    if let Err(e) = accounts::validate_caption(caption.trim()) {
        return bad(
            "That caption cannot be stored",
            &format!("{e}. Reopen {repo} from browse to try a shorter one."),
        );
    }
    match db.set_repo_caption(&repo, &caption) {
        Ok(()) => see_other(&format!("/browse/{repo}")),
        Err(e) => {
            eprintln!("vk-registry: writing a repository caption: {e:#}");
            Ok(server_error(db, user, session_id.as_deref()))
        }
    }
}
