//! The browser-facing surfaces' shared chrome: one page shell, one set of response
//! headers, one error page. `/browse` and the login routes answer people rather than OCI
//! clients, and both need the same headers, so they are set in one place instead of per
//! module.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};

use crate::{accounts, html_escape};

/// A response carrying an HTML page.
///
/// Every page here is rendered for one signed-in person and shows what that person may
/// see, so: never cached (a shared cache, or a back-button on a shared machine, would
/// show one person's page to another), never sniffed, no referrer to the identity
/// provider or anywhere else, forms only to this origin, and no resource loads at all
/// beyond the inline stylesheet.
pub(crate) fn respond(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(hyper::header::CACHE_CONTROL, "no-store")
        .header(hyper::header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(hyper::header::REFERRER_POLICY, "no-referrer")
        .header(
            hyper::header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; \
             base-uri 'none'; frame-ancestors 'none'",
        )
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("building an HTML response")
}

/// The page shell: `<head>`, the shared stylesheet, and the nav naming who the caller is.
/// `csrf` is the session's secret, needed by the sign-out control; `None` for a caller
/// that has no session to end.
pub(crate) fn page(
    title: &str,
    principal: &accounts::Principal,
    csrf: Option<&str>,
    body: &str,
) -> String {
    let nav = match principal {
        accounts::Principal::Session(u) => {
            let who = html_escape(
                u.display_name
                    .as_deref()
                    .or(u.email.as_deref())
                    .unwrap_or(&u.oidc_subject),
            );
            // Signing out changes state, so it is a POST carrying the session's CSRF
            // token — a link would let any page on the internet end this session. With no
            // token the control is omitted rather than rendered dead: a button whose only
            // possible outcome is a 403 is worse than no button.
            let links = "<a href=\"/browse\">browse</a> &middot; \
                         <a href=\"/upload\">upload</a> &middot; \
                         <a href=\"/settings/keys\">keys</a>";
            match csrf {
                Some(token) => format!(
                    "signed in as {who} &middot; {links} &middot; \
                     <form method=\"post\" action=\"/logout\">\
                     <input type=\"hidden\" name=\"csrf\" value=\"{}\">\
                     <button type=\"submit\">log out</button></form>",
                    html_escape(token)
                ),
                None => format!("signed in as {who} &middot; {links}"),
            }
        }
        accounts::Principal::ApiKey(k) => {
            format!("authenticated with API key {}", html_escape(&k.name))
        }
    };
    shell(title, &nav, body)
}

/// The page shell for a caller with no principal — the login routes, which by definition
/// answer someone who is not signed in yet.
pub(crate) fn anonymous_page(title: &str, body: &str) -> String {
    shell(title, "", body)
}

/// The exact policy [`respond`] sets, asserted by the tests rather than described: the
/// only reason a `<script>` on one of these pages does not run is that `script-src` falls
/// back to `default-src 'none'`, so a later page loosening this must not pass unnoticed.
#[cfg(test)]
pub(crate) const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; \
                              form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

fn shell(title: &str, nav: &str, body: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title>\n\
         <style>\n\
         body{{font-family:system-ui,sans-serif;margin:2rem;color:#1a1a1a}}\n\
         table{{border-collapse:collapse;margin-top:.5rem}}\n\
         td,th{{padding:.25rem .75rem;text-align:left;border-bottom:1px solid #ddd}}\n\
         a{{color:#0645ad;text-decoration:none}} a:hover{{text-decoration:underline}}\n\
         nav{{float:right;color:#555;font-size:.9rem}}\n\
         nav form{{display:inline}} label{{display:block;margin:.4rem 0}}\n\
         .error{{color:#b00020}}\n\
         code,pre{{font-size:.9rem}}\n\
         </style></head><body>\n\
         <nav>{nav}</nav>\n\
         {body}\n\
         </body></html>",
        title = html_escape(title),
    )
}

/// An error a person can read. The OCI JSON envelope renders as raw text in a browser,
/// and its `message` would carry an internal error chain to whoever asked.
pub(crate) fn error(
    status: StatusCode,
    principal: Option<&accounts::Principal>,
    csrf: Option<&str>,
    heading: &str,
    detail: &str,
) -> Response<Full<Bytes>> {
    let body = format!(
        "<h1>{}</h1>\n<p>{}</p>",
        html_escape(heading),
        html_escape(detail)
    );
    let rendered = match principal {
        Some(p) => page("vk-registry", p, csrf, &body),
        None => anonymous_page("vk-registry", &body),
    };
    respond(status, &rendered)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> accounts::Principal {
        accounts::Principal::Session(accounts::User {
            id: "https://issuer\u{1f}sub-1".to_string(),
            oidc_issuer: "https://issuer".to_string(),
            oidc_subject: "sub-1".to_string(),
            email: None,
            display_name: Some("Alice".to_string()),
            is_admin: false,
            created_at: std::time::SystemTime::UNIX_EPOCH,
            last_login_at: std::time::SystemTime::UNIX_EPOCH,
        })
    }

    fn api_key() -> accounts::Principal {
        accounts::Principal::ApiKey(accounts::ApiKey {
            id: "abc".to_string(),
            owner_user_id: None,
            name: "ci".to_string(),
            token_prefix: "vkr_1234".to_string(),
            scopes: Vec::new(),
            created_at: std::time::SystemTime::UNIX_EPOCH,
            expires_at: None,
            last_used_at: None,
            revoked_at: None,
        })
    }

    /// This module exists so that one set of headers covers every browser-facing route, so
    /// the headers are what it owes a test — the CSP by its exact value, against a policy
    /// written out separately here rather than read back out of the code.
    #[test]
    fn every_html_response_carries_the_same_headers() {
        for res in [
            respond(StatusCode::OK, "<p>hi</p>"),
            error(
                StatusCode::NOT_FOUND,
                Some(&session()),
                Some("t"),
                "Not found",
                "No such page.",
            ),
            // and the anonymous variant, which the login routes and the shared-secret
            // 404 answer with — the branch no page test reaches
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                None,
                None,
                "Something went wrong",
                "Try again shortly.",
            ),
        ] {
            let h = res.headers();
            assert_eq!(
                h.get(hyper::header::CONTENT_TYPE).unwrap(),
                "text/html; charset=utf-8"
            );
            assert_eq!(h.get(hyper::header::CACHE_CONTROL).unwrap(), "no-store");
            assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
            assert_eq!(h.get("referrer-policy").unwrap(), "no-referrer");
            assert_eq!(h.get("content-security-policy").unwrap(), CSP);
        }
    }

    /// The sign-out control is a session's, and only a session's: an API key has no session
    /// to end, so its nav must carry neither the form nor a `/logout` reference — and a
    /// caller with no principal at all gets an empty nav rather than somebody else's.
    #[test]
    fn only_a_session_gets_a_sign_out_control() {
        let signed_in = page("t", &session(), Some("s3cr3t"), "<p>b</p>");
        assert!(signed_in.contains("signed in as Alice"), "{signed_in}");
        assert!(signed_in.contains("action=\"/logout\""), "{signed_in}");
        assert!(signed_in.contains("value=\"s3cr3t\""), "{signed_in}");

        // with no token the control is omitted, not rendered dead
        let unarmed = page("t", &session(), None, "<p>b</p>");
        assert!(unarmed.contains("signed in as Alice"), "{unarmed}");
        assert!(!unarmed.contains("<form"), "{unarmed}");

        let keyed = page("t", &api_key(), Some("s3cr3t"), "<p>b</p>");
        assert!(keyed.contains("API key ci"), "{keyed}");
        assert!(!keyed.contains("<form"), "{keyed}");
        assert!(!keyed.contains("/logout"), "{keyed}");
        assert!(
            !keyed.contains("/settings/keys"),
            "a key cannot manage keys: {keyed}"
        );
        for link in ["/browse", "/upload", "/settings/keys"] {
            assert!(signed_in.contains(link), "{link}: {signed_in}");
            assert!(unarmed.contains(link), "{link}: {unarmed}");
            assert!(
                !keyed.contains(link),
                "{link}: a key browses nothing: {keyed}"
            );
        }
        assert!(
            !keyed.contains("s3cr3t"),
            "a key's page carries no session secret"
        );

        let anon = anonymous_page("t", "<p>b</p>");
        assert!(anon.contains("<nav></nav>"), "{anon}");
        assert!(!anon.contains("/logout"), "{anon}");
    }

    /// Everything interpolated into the shell is escaped — the title and the nav's claim
    /// text come from an identity provider, and the CSRF token lands in an attribute.
    #[test]
    fn the_shell_escapes_what_it_interpolates() {
        let hostile = accounts::Principal::Session(accounts::User {
            display_name: Some("<script>alert(1)</script>".to_string()),
            ..match session() {
                accounts::Principal::Session(u) => u,
                accounts::Principal::ApiKey(_) => unreachable!(),
            }
        });
        let html = page("<script>t</script>", &hostile, Some("a\"><b"), "<p>ok</p>");
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&lt;script&gt;"), "{html}");
        assert!(html.contains("value=\"a&quot;&gt;&lt;b\""), "{html}");
    }
}
