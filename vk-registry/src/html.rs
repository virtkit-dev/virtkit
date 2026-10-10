//! The browser-facing surfaces' shared chrome: one page shell, one set of response
//! headers, one error page. `/browse` and the login routes answer people rather than OCI
//! clients, and both need the same headers, so they are set in one place instead of per
//! module.

use std::sync::LazyLock;

use bytes::Bytes;
use hyper::{Response, StatusCode};

use crate::{Body, body_of};
use crate::{accounts, html_escape};

/// A response carrying an HTML page.
///
/// Every page here is rendered for one signed-in person and shows what that person may
/// see, so: never cached (a shared cache, or a back-button on a shared machine, would
/// show one person's page to another), never sniffed, no referrer to the identity
/// provider or anywhere else, forms only to this origin, and no resource loads at all
/// beyond the inline stylesheet and the `data:` tab icon.
pub(crate) fn respond(status: StatusCode, body: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(hyper::header::CACHE_CONTROL, "no-store")
        .header(hyper::header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(hyper::header::REFERRER_POLICY, "no-referrer")
        .header(
            hyper::header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; style-src 'unsafe-inline'; img-src data:; \
             form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        .body(body_of(Bytes::from(body.to_string())))
        .expect("building an HTML response")
}

/// A nav entry, marked current on its pages.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Section {
    Browse,
    Upload,
    Keys,
}

const NAV: [(Section, &str, &str); 3] = [
    (Section::Browse, "/browse", "Browse"),
    (Section::Upload, "/upload", "Upload"),
    (Section::Keys, "/settings/keys", "Keys"),
];

/// The page shell: `<head>`, the shared stylesheet, and the nav naming who the caller is.
/// `here` is the nav entry to mark as current. `csrf` is the session's secret, needed by
/// the sign-out control; `None` for a caller that has no session to end.
pub(crate) fn page(
    title: &str,
    here: Option<Section>,
    principal: &accounts::Principal,
    csrf: Option<&str>,
    body: &str,
) -> String {
    let (nav, who, home) = match principal {
        accounts::Principal::Session(u) => {
            let who = html_escape(
                u.display_name
                    .as_deref()
                    .or(u.email.as_deref())
                    .unwrap_or(&u.oidc_subject),
            );
            let links: String = NAV
                .iter()
                .map(|&(section, href, label)| {
                    let current = if here == Some(section) {
                        " aria-current=\"page\""
                    } else {
                        ""
                    };
                    format!("<a href=\"{href}\"{current}>{label}</a>")
                })
                .collect();
            // Signing out changes state, so it is a POST carrying the session's CSRF
            // token — a link would let any page on the internet end this session. With no
            // token the control is omitted rather than rendered dead: a button whose only
            // possible outcome is a 403 is worse than no button.
            let who = match csrf {
                Some(token) => format!(
                    "<span>signed in as {who}</span>\
                     <form method=\"post\" action=\"/logout\">\
                     <input type=\"hidden\" name=\"csrf\" value=\"{}\">\
                     <button type=\"submit\" class=\"secondary\">Sign out</button></form>",
                    html_escape(token)
                ),
                None => format!("<span>signed in as {who}</span>"),
            };
            (links, who, true)
        }
        // The nav is for people signed in through the browser: an API key gets no links,
        // and its brand stays plain text.
        accounts::Principal::ApiKey(k) => (
            String::new(),
            format!(
                "<span>authenticated with API key {}</span>",
                html_escape(&k.name)
            ),
            false,
        ),
    };
    shell(title, &nav, &who, home, body)
}

/// The page shell for a caller with no principal — the login routes, which by definition
/// answer someone who is not signed in yet.
pub(crate) fn anonymous_page(title: &str, body: &str) -> String {
    shell(title, "", "", false, body)
}

/// The exact policy [`respond`] sets, asserted by the tests rather than described: the
/// only reason a `<script>` on one of these pages does not run is that `script-src` falls
/// back to `default-src 'none'`, so a later page loosening this must not pass unnoticed.
#[cfg(test)]
pub(crate) const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; \
                              form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

/// vk-hub's theme (`assets/ui.css`), inlined because the policy forbids external stylesheets.
const CSS: &str = include_str!("../assets/ui.css");

/// The registry's icon: virtkit's chip holding an image's layers.
const SVG: &str = include_str!("../assets/favicon.svg");

/// [`SVG`] as a `data:` tab icon; the policy forbids external images.
static ICON: LazyLock<String> = LazyLock::new(|| {
    let mut url = String::from("data:image/svg+xml,");
    for c in SVG.chars() {
        match c {
            '\n' | '\r' => {}
            '#' => url.push_str("%23"),
            '%' => url.push_str("%25"),
            '<' => url.push_str("%3C"),
            '>' => url.push_str("%3E"),
            c => url.push(c),
        }
    }
    url
});

/// `home` links the brand to `/browse`, for a caller who may browse.
fn shell(title: &str, nav: &str, who: &str, home: bool, body: &str) -> String {
    let brand = if home {
        "<a class=\"brand\" href=\"/browse\">vk-registry</a>"
    } else {
        "<span class=\"brand\">vk-registry</span>"
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title} · vk-registry</title>\
         <link rel=\"icon\" type=\"image/svg+xml\" href=\"{icon}\">\n\
         <style>\n{CSS}</style></head><body>\n\
         <header class=\"topbar\">{brand}\
         {nav}<div class=\"who\">{who}</div></header>\n\
         <main>\n{body}\n</main>\n\
         </body></html>",
        nav = if nav.is_empty() {
            String::new()
        } else {
            format!("<nav>{nav}</nav>")
        },
        title = html_escape(title),
        icon = html_escape(&ICON),
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
) -> Response<Body> {
    let body = format!(
        "<h1>{}</h1>\n<p>{}</p>",
        html_escape(heading),
        html_escape(detail)
    );
    let rendered = match principal {
        Some(p) => page(heading, None, p, csrf, &body),
        None => anonymous_page(heading, &body),
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
        let signed_in = page("t", None, &session(), Some("s3cr3t"), "<p>b</p>");
        assert!(signed_in.contains("signed in as Alice"), "{signed_in}");
        assert!(signed_in.contains("action=\"/logout\""), "{signed_in}");
        assert!(signed_in.contains("value=\"s3cr3t\""), "{signed_in}");

        // with no token the control is omitted, not rendered dead
        let unarmed = page("t", None, &session(), None, "<p>b</p>");
        assert!(unarmed.contains("signed in as Alice"), "{unarmed}");
        assert!(!unarmed.contains("<form"), "{unarmed}");

        let keyed = page("t", None, &api_key(), Some("s3cr3t"), "<p>b</p>");
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
        assert!(!anon.contains("<nav"), "{anon}");
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
        let html = page(
            "<script>t</script>",
            None,
            &hostile,
            Some("a\"><b"),
            "<p>ok</p>",
        );
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&lt;script&gt;"), "{html}");
        assert!(html.contains("value=\"a&quot;&gt;&lt;b\""), "{html}");
    }

    /// The nav marks the current page's entry, and only that one; an error page marks none.
    #[test]
    fn the_nav_marks_the_current_page() {
        fn nav(html: &str) -> &str {
            let start = html.find("<nav>").unwrap();
            &html[start..start + html[start..].find("</nav>").unwrap()]
        }
        for (section, href) in [
            (Section::Browse, "/browse"),
            (Section::Upload, "/upload"),
            (Section::Keys, "/settings/keys"),
        ] {
            let html = page("t", Some(section), &session(), None, "<p>b</p>");
            let nav = nav(&html);
            assert!(
                nav.contains(&format!("<a href=\"{href}\" aria-current=\"page\">")),
                "{href}: {nav}"
            );
            assert_eq!(nav.matches("aria-current").count(), 1, "{nav}");
        }
        let html = page("t", None, &session(), None, "<p>b</p>");
        assert!(!nav(&html).contains("aria-current"), "{html}");
    }

    /// Every page names the registry's icon, which differs from vk-hub's so their tabs
    /// can be told apart.
    #[test]
    fn every_page_names_the_registry_icon() {
        assert_ne!(SVG, include_str!("../../vk-hub/assets/favicon.svg"));
        for html in [
            page("t", None, &session(), Some("s"), "<p>b</p>"),
            page("t", None, &api_key(), None, "<p>b</p>"),
            anonymous_page("t", "<p>b</p>"),
        ] {
            assert!(
                html.contains(
                    "<link rel=\"icon\" type=\"image/svg+xml\" href=\"data:image/svg+xml,"
                ),
                "{html}"
            );
        }
    }

    /// The `data:` URL decodes back to the SVG, minus its line breaks.
    #[test]
    fn the_icon_url_decodes_back_to_the_svg() {
        let payload = ICON.strip_prefix("data:image/svg+xml,").unwrap();
        for c in ['#', '<', '>', '\n', '\r'] {
            assert!(!payload.contains(c), "{c:?} in {payload}");
        }
        let mut decoded = String::new();
        let mut rest = payload;
        while let Some(i) = rest.find('%') {
            decoded.push_str(&rest[..i]);
            let byte = u8::from_str_radix(&rest[i + 1..i + 3], 16).unwrap();
            decoded.push(char::from(byte));
            rest = &rest[i + 3..];
        }
        decoded.push_str(rest);
        let expected: String = SVG.chars().filter(|c| !matches!(c, '\n' | '\r')).collect();
        assert_eq!(decoded, expected);
    }

    /// Each mode's tokens are a subset of vk-hub's. Every light token with a dark
    /// override in the hub has one here too.
    #[test]
    fn the_theme_tokens_match_vk_hubs() {
        const DARK: &str = "@media (prefers-color-scheme: dark)";
        // The declarations from `start` to the first `}` at the start of a line.
        fn block<'a>(css: &'a str, start: &str) -> Vec<&'a str> {
            css[css.find(start).unwrap()..]
                .lines()
                .take_while(|l| *l != "}")
                .map(str::trim)
                .filter(|l| l.starts_with("--"))
                .collect()
        }
        fn name(token: &str) -> &str {
            token.split(':').next().unwrap()
        }
        let hub = include_str!("../../vk-hub/assets/ui.css");
        let (light, dark) = (block(CSS, ":root {"), block(CSS, DARK));
        let (hub_light, hub_dark) = (block(hub, ":root {"), block(hub, DARK));
        assert!(!light.is_empty() && !dark.is_empty());
        for (ours, theirs) in [(&light, &hub_light), (&dark, &hub_dark)] {
            for token in ours {
                assert!(theirs.contains(token), "{token} is not vk-hub's");
            }
        }
        for token in &light {
            if hub_dark.iter().any(|t| name(t) == name(token)) {
                assert!(
                    dark.iter().any(|t| name(t) == name(token)),
                    "{} has no dark value",
                    name(token)
                );
            }
        }
    }

    /// Titles name the page, then the product, once; error pages use their heading.
    #[tokio::test]
    async fn the_title_names_the_product_once() {
        use http_body_util::BodyExt;
        let html = page("Upload", None, &session(), None, "<p>b</p>");
        assert!(
            html.contains("<title>Upload · vk-registry</title>"),
            "{html}"
        );
        let err = error(
            StatusCode::NOT_FOUND,
            None,
            None,
            "Not found",
            "No such page.",
        );
        let body = err.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            html.contains("<title>Not found · vk-registry</title>"),
            "{html}"
        );
    }
}
