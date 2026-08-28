//! `/settings/keys`: session-authed API key management (list, create, revoke). Not
//! usable by an API key itself — a key that can mint keys is an escalation path — so
//! every route here requires a [`accounts::Principal::Session`].
//!
//! Creating a **write**-scoped key requires an admin session, for the same reason
//! `authorize` lets only an admin session write: a plain session that could mint one
//! would have a way around that rule. A plain session can still create read-only keys.
//!
//! State-changing requests carry the CSRF token every settings form does, and end on the
//! shared error pages — see [`crate::forms`].

use std::time::{Duration, SystemTime};

use anyhow::Result;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};

use crate::Body;
use crate::accounts::{self, Action, ApiKey, Db, Principal, Scope, User};
use crate::forms::{
    csrf_of, csrf_ok, csrf_rejected, form_body, see_other, server_error, too_large,
};
use crate::html::{self, page, respond};
use crate::{html_escape, query_param};

/// The longest life a key may be given. Ten years is past any sensible CI credential's
/// rotation, and it keeps the seconds arithmetic below far from overflowing.
const MAX_EXPIRY_DAYS: u64 = 3_650;

/// How many live keys one person may hold. This is the only route that mints them, from a
/// form, so without a bound a signed-in session — or a held-down refresh key — grows a
/// table that `Db::list_api_keys` scans linearly on every authenticated request. Far past
/// what anyone needs; revoked keys do not count, so rotating is never blocked by it.
const MAX_KEYS_PER_USER: usize = 64;

/// `secure` is `ServerState::cookies_are_secure()` — it decides which of the two names the
/// session cookie was written under, so it has to be the same answer the rest of the
/// server uses (see [`accounts::session_cookie`]).
pub(crate) async fn route(
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
            "Sign in with a browser session to manage API keys.",
        ));
    };
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    // `strip_prefix`/`strip_suffix` rather than index arithmetic: `/settings/keys/revoke`
    // satisfies both a prefix and a suffix test while leaving no id between them, and
    // slicing it by computed offsets panics.
    let revoke_id = path
        .strip_prefix("/settings/keys/")
        .and_then(|r| r.strip_suffix("/revoke"))
        .filter(|id| !id.is_empty())
        .map(str::to_string);
    match (&method, path.as_str(), revoke_id) {
        (&Method::GET | &Method::HEAD, "/settings/keys", _) => {
            let session_id = accounts::session_cookie(req.headers(), secure);
            list_page(db, user, session_id.as_deref(), StatusCode::OK, None)
        }
        (&Method::POST, "/settings/keys", _) => create(db, user, secure, req).await,
        (&Method::POST, _, Some(id)) => revoke(db, user, secure, &id, req).await,
        _ => Ok(html::error(
            StatusCode::NOT_FOUND,
            Some(principal),
            None,
            "Not found",
            "No such settings page.",
        )),
    }
}

async fn create(
    db: &Db,
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
    let bad = |msg: &str| {
        list_page(
            db,
            user,
            session_id.as_deref(),
            StatusCode::BAD_REQUEST,
            Some(msg),
        )
    };

    let Some(name) = query_param(&body, "name").filter(|n| !n.is_empty()) else {
        return bad("a name is required");
    };
    let Some(repo_pattern) = query_param(&body, "repo_pattern").filter(|p| !p.is_empty()) else {
        return bad("a repo pattern is required");
    };
    let action = match query_param(&body, "action").as_deref() {
        Some("read") => Action::Read,
        Some("write") => Action::Write,
        _ => return bad("action must be read or write"),
    };
    // A non-admin session cannot write (`accounts::authorize`'s session rule), so it must
    // not be able to mint a write-scoped key for itself either — that key would be a way
    // around the rule this check exists to enforce.
    if action == Action::Write && !user.is_admin {
        return bad("only an admin session can create a write-scoped key");
    }
    let expires_at = match query_param(&body, "expires_days").as_deref() {
        None | Some("") => None,
        Some(days) => match days.parse::<u64>() {
            // Bounded, so the multiplication and the `SystemTime` addition below cannot
            // overflow — both panic on a value a form is free to send.
            Ok(d) if (1..=MAX_EXPIRY_DAYS).contains(&d) => {
                Some(SystemTime::now() + Duration::from_secs(d * 86_400))
            }
            _ => {
                return bad(&format!(
                    "expires_days must be between 1 and {MAX_EXPIRY_DAYS}"
                ));
            }
        },
    };
    let scopes = [Scope {
        action,
        repo_pattern,
    }];
    let live = match db.list_api_keys(&user.id) {
        Ok(keys) => keys.iter().filter(|k| k.revoked_at.is_none()).count(),
        Err(e) => {
            eprintln!("vk-registry: counting API keys: {e:#}");
            return Ok(server_error(db, user, session_id.as_deref()));
        }
    };
    if live >= MAX_KEYS_PER_USER {
        return bad(&format!(
            "you already hold {MAX_KEYS_PER_USER} keys; revoke one before creating another"
        ));
    }
    // Validated first, so a complaint about the form is told apart from a failed write:
    // the first is the caller's to fix and worth showing them, the second is this server's
    // and must not escape as a 500 with an error chain in it. `create_api_key` re-validates
    // — it is the store's invariant, not this route's.
    if let Err(e) = accounts::validate_key_input(&name, &scopes) {
        return bad(&format!("{e}"));
    }
    let (_, token) = match db.create_api_key(Some(&user.id), &name, &scopes, expires_at) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("vk-registry: creating an API key: {e:#}");
            return Ok(server_error(db, user, session_id.as_deref()));
        }
    };
    Ok(respond(
        StatusCode::OK,
        &page(
            "vk-registry: new API key",
            &Principal::Session(user.clone()),
            csrf_of(db, session_id.as_deref()).as_deref(),
            &format!(
                "<h1>New API key</h1>\n\
                 <p>Copy this token now — it is not stored and will not be shown again:</p>\n\
                 <pre>{}</pre>\n\
                 <p><a href=\"/settings/keys\">&larr; back to keys</a></p>",
                html_escape(&token)
            ),
        ),
    ))
}

async fn revoke(
    db: &Db,
    user: &User,
    secure: bool,
    id: &str,
    req: Request<Incoming>,
) -> Result<Response<Body>> {
    let session_id = accounts::session_cookie(req.headers(), secure);
    let Some(body) = form_body(req).await else {
        return Ok(too_large(db, user, session_id.as_deref()));
    };
    if !csrf_ok(db, session_id.as_deref(), &body) {
        return Ok(csrf_rejected(db, user, session_id.as_deref()));
    }
    // The store checks ownership inside the same transaction as the write, so there is no
    // window between "is this mine" and "revoke it". A key belonging to someone else and
    // a key that does not exist are answered identically: an id from a listing must not
    // tell its holder anything about anyone else's keys.
    match db.revoke_api_key(&user.id, id) {
        Ok(true) => see_other("/settings/keys"),
        Ok(false) => Ok(html::error(
            StatusCode::NOT_FOUND,
            Some(&Principal::Session(user.clone())),
            csrf_of(db, session_id.as_deref()).as_deref(),
            "Not found",
            "No key of yours with that id is still active.",
        )),
        Err(e) => {
            eprintln!("vk-registry: revoking an API key: {e:#}");
            Ok(server_error(db, user, session_id.as_deref()))
        }
    }
}

fn list_page(
    db: &Db,
    user: &User,
    session_id: Option<&str>,
    status: StatusCode,
    notice: Option<&str>,
) -> Result<Response<Body>> {
    // Kept as an `Option`, not flattened to `""`: every form on this page is a POST that
    // the CSRF check will refuse without a real token, so with no token the forms are left
    // out rather than rendered dead — the same rule `html::page` applies to the sign-out
    // control. Reachable if the session expires between the gate and here.
    let csrf = csrf_of(db, session_id);
    let keys = match db.list_api_keys(&user.id) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("vk-registry: listing API keys: {e:#}");
            return Ok(server_error(db, user, session_id));
        }
    };
    let mut rows = String::new();
    for k in &keys {
        rows.push_str(&key_row(k, csrf.as_deref()));
    }
    if rows.is_empty() {
        rows = "<tr><td colspan=\"7\"><em>no API keys yet</em></td></tr>\n".to_string();
    }
    let notice_html = notice
        .map(|n| format!("<p class=\"error\">{}</p>\n", html_escape(n)))
        .unwrap_or_default();
    let table = format!(
        "<table><tr><th>Name</th><th>Token</th><th>Scopes</th><th>Created</th>\
         <th>Last used</th><th>Status</th><th></th></tr>\n{rows}</table>\n"
    );
    // No token, no form: it could only ever be refused.
    let new_key_form = match csrf.as_deref() {
        Some(token) => format!(
            "<h2>New key</h2>\n\
             <form method=\"post\" action=\"/settings/keys\">\n\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\n\
             <label>Name <input name=\"name\" maxlength=\"128\" required></label>\n\
             <label>Repo pattern <input name=\"repo_pattern\" placeholder=\"team-a/*\" required></label>\n\
             {action}\n\
             <label>Expires in days (blank = never, max {MAX_EXPIRY_DAYS}) <input name=\"expires_days\" type=\"number\" min=\"1\" max=\"{MAX_EXPIRY_DAYS}\"></label>\n\
             <button type=\"submit\">Create</button>\n\
             </form>",
            csrf = html_escape(token),
            action = action_field(user.is_admin),
        ),
        None => String::new(),
    };
    Ok(respond(
        status,
        &page(
            "vk-registry: API keys",
            &Principal::Session(user.clone()),
            csrf.as_deref(),
            &format!("<h1>API keys</h1>\n{notice_html}{table}{new_key_form}"),
        ),
    ))
}

/// The Action field for this session: a choice for an admin, and for anyone else the one value they
/// can mint, plus a line below it saying who can mint the other.
fn action_field(is_admin: bool) -> &'static str {
    if is_admin {
        "<label>Action <select name=\"action\"><option value=\"write\">write (implies read)</option>\
         <option value=\"read\">read</option></select></label>"
    } else {
        "<label>Action read</label>\n\
         <input type=\"hidden\" name=\"action\" value=\"read\">\n\
         <p>A write-scoped key can only be created from an admin session. Ask an admin \
         for one, or an operator to grant you admin \
         (<code>vk-registry accounts grant-admin</code>).</p>"
    }
}

fn key_row(k: &ApiKey, csrf: Option<&str>) -> String {
    let scopes = if k.scopes.is_empty() {
        "<em>none</em>".to_string()
    } else {
        k.scopes
            .iter()
            .map(|s| {
                let verb = match s.action {
                    Action::Read => "read",
                    Action::Write => "write",
                };
                format!("{verb} {}", html_escape(&s.repo_pattern))
            })
            .collect::<Vec<_>>()
            .join("<br>")
    };
    let status = if k.revoked_at.is_some() {
        "revoked"
    } else if k.expires_at.is_some_and(|e| e <= SystemTime::now()) {
        "expired"
    } else {
        "active"
    };
    // `id` is a sha256 hex string (`ApiKey::id`), so it needs no percent-encoding to sit
    // in a path; it is escaped anyway, because every value on this page is.
    let revoke_form = if let (false, Some(csrf)) = (k.revoked_at.is_some(), csrf) {
        format!(
            "<form method=\"post\" action=\"/settings/keys/{id}/revoke\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <button type=\"submit\">Revoke</button></form>",
            id = html_escape(&k.id),
            csrf = html_escape(csrf),
        )
    } else {
        String::new()
    };
    format!(
        "<tr><td>{name}</td><td><code>{prefix}…</code></td><td>{scopes}</td>\
         <td>{created}</td><td>{used}</td><td>{status}</td><td>{revoke_form}</td></tr>\n",
        name = html_escape(&k.name),
        prefix = html_escape(&k.token_prefix),
        created = ymd(Some(k.created_at)),
        used = ymd(k.last_used_at),
    )
}

/// A `SystemTime` as `YYYY-MM-DD`, computed from the epoch — the crate links no date
/// library, and a listing needs no more precision than the day.
fn ymd(t: Option<SystemTime>) -> String {
    let Some(secs) = t.and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok()) else {
        return "never".to_string();
    };
    // A `SystemTime` far enough past the epoch to overflow this is not a date a key was
    // created or used at; say so rather than wrap.
    let Ok(days) = i64::try_from(secs.as_secs() / 86_400) else {
        return "never".to_string();
    };
    // civil-from-days (Howard Hinnant's algorithm), shifted to a 1970 epoch
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `/settings/keys/revoke` matches both the prefix and the suffix test with nothing
    /// between them; computing the id by offset arithmetic panics on it.
    #[test]
    fn a_revoke_path_with_no_id_is_not_a_revoke() {
        let id_of = |p: &str| {
            p.strip_prefix("/settings/keys/")
                .and_then(|r| r.strip_suffix("/revoke"))
                .filter(|id| !id.is_empty())
                .map(str::to_string)
        };
        for p in [
            "/settings/keys/revoke",
            "/settings/keys//revoke",
            "/settings/keys/",
            "/settings/keys/abc",
            "/settings/keys",
        ] {
            assert_eq!(id_of(p), None, "{p}");
        }
        assert_eq!(
            id_of("/settings/keys/abc123/revoke").as_deref(),
            Some("abc123")
        );
    }

    /// The form offers only what the POST will accept: a plain session that is shown a
    /// `write` option finds out it cannot have one by submitting the form and losing it.
    #[test]
    fn the_action_choices_are_the_ones_this_session_can_mint() {
        let admin = action_field(true);
        assert!(admin.contains("value=\"write\""), "{admin}");
        assert!(admin.contains("value=\"read\""), "{admin}");

        let plain = action_field(false);
        assert!(
            !plain.contains("value=\"write\"") && !plain.contains("<option"),
            "a plain session must be offered no scope to pick from: {plain}"
        );
        assert!(plain.contains("value=\"read\""), "{plain}");
        // and it says who can, rather than dropping the option silently. Asserted across
        // both line continuations rather than on a phrase inside one: a continuation eats
        // the newline *and* the indentation after it, so a missing trailing space runs two
        // words together, and only a match spanning the seam catches that.
        assert!(
            plain.contains(
                "created from an admin session. Ask an admin for one, or an operator to \
                 grant you admin (<code>vk-registry accounts grant-admin</code>)."
            ),
            "{plain}"
        );
    }

    #[test]
    fn a_day_stamp_is_rendered_without_a_date_library() {
        let at = |s: u64| ymd(Some(SystemTime::UNIX_EPOCH + Duration::from_secs(s)));
        assert_eq!(at(0), "1970-01-01");
        assert_eq!(at(86_399), "1970-01-01");
        assert_eq!(at(86_400), "1970-01-02");
        // 2000-02-29, the leap day a naive rule gets wrong
        assert_eq!(at(951_782_400), "2000-02-29");
        assert_eq!(at(1_787_654_400), "2026-08-25");
        assert_eq!(ymd(None), "never");
    }
}
