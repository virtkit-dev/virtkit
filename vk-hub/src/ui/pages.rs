//! The pages every UI has, as [`Html`]: the frame around them, signing in, the audit log, and
//! the helpers the rest are built with. Every value in them goes through [`Html::text`] or,
//! for what the host reported, [`Html::node`].

use super::Auth;
use super::assets;
use super::html::Html;
use crate::store::AuditRow;

/// Audit lines per page of `/audit`.
pub const AUDIT_PAGE: usize = 100;

/// The page around `main`: head, stylesheet, navigation, who is signed in.
pub fn layout(title: &str, auth: &Auth, main: &Html) -> Html {
    let mut h = Html::new();
    head(&mut h, title);
    h.raw("<body><header><nav><a href=\"/\">VMs</a> <a href=\"/dev\">dev environments</a> ")
        .raw("<a href=\"/audit\">audit</a></nav>")
        .raw("<form class=\"who\" method=\"post\" action=\"/logout\"><span>")
        .text(auth.session.principal())
        .raw(", until ")
        .text(crate::utc(auth.session.expires_at))
        .raw("</span> ");
    csrf_field(&mut h, auth);
    h.raw("<button>sign out</button></form></header><main>")
        .html(main)
        .raw("</main></body></html>");
    h
}

/// htmx's configuration: nothing evaluated, no script run from a swapped fragment, no
/// inline style of its own (the policy would refuse it), requests to this origin only — and
/// a refusal (4xx, 5xx) swapped rather than dropped, so the line saying why shows, without
/// logging it as an error.
const HTMX_CONFIG: &str = r#"{"allowEval":false,"allowScriptTags":false,"includeIndicatorStyles":false,"selfRequestsOnly":true,"responseHandling":[{"code":"204","swap":false},{"code":"[23]..","swap":true},{"code":"4..","swap":true,"error":false},{"code":"5..","swap":true,"error":false},{"code":"...","swap":false,"error":true}]}"#;

fn head(h: &mut Html, title: &str) {
    h.raw("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
        .raw("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
        .raw("<meta name=\"htmx-config\" content='")
        .raw(HTMX_CONFIG)
        .raw("'><title>")
        .node(title)
        .raw(" · vk-hub</title><link rel=\"stylesheet\" href=\"")
        .text(assets::url(assets::CSS))
        .raw("\"><script src=\"")
        .text(assets::url(assets::HTMX))
        .raw("\"></script><script src=\"")
        .text(assets::url(assets::SSE))
        .raw("\"></script></head>");
}

/// The hidden field carrying the session's CSRF token.
pub fn csrf_field(h: &mut Html, auth: &Auth) {
    h.raw("<input type=\"hidden\" name=\"_csrf\" value=\"")
        .text(&auth.csrf)
        .raw("\">");
}

/// A page with one sentence and no session: an error, or signed out.
pub fn message(text: &str) -> Html {
    let mut h = Html::new();
    head(&mut h, "vk-hub");
    h.raw("<body><main><p class=\"message\">")
        .text(text)
        .raw("</p></main></body></html>");
    h
}

/// `GET /login`: the sign-in link's page, a button posting its token back.
pub fn sign_in(token: &str) -> Html {
    let mut h = Html::new();
    head(&mut h, "sign in");
    h.raw("<body><main><form class=\"message\" method=\"post\" action=\"/login\">")
        .raw("<input type=\"hidden\" name=\"t\" value=\"")
        .text(token)
        .raw("\"><p>This link signs this browser in to the hub's web UI, once.</p>")
        .raw("<button>Sign in</button></form></main></body></html>");
    h
}

/// What signing in answers: on to `/` by the page's own navigation, with a link for a
/// browser that does not follow a refresh.
pub fn signed_in() -> Html {
    let mut h = Html::new();
    h.raw("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
        .raw("<meta http-equiv=\"refresh\" content=\"0; url=/\"><title>vk-hub</title></head>")
        .raw("<body><p><a href=\"/\">Signed in; continue</a></p></body></html>");
    h
}

/// A live region's last fragment, once its session has ended.
pub fn signed_out_fragment() -> Html {
    let mut h = Html::new();
    h.raw("<p class=\"message\">Signed out: this page no longer updates. ")
        .raw("<code>vk-hub local login</code> prints a link to sign in again.</p>");
    h
}

/// `/audit`: a page of the audit log, newest first, with a link to the next.
pub fn audit(auth: &Auth, rows: &[(u64, AuditRow)]) -> Html {
    let mut main = Html::new();
    main.raw("<h1>Audit</h1>");
    audit_table(&mut main, rows);
    if rows.len() == AUDIT_PAGE
        && let Some((oldest, _)) = rows.last()
    {
        main.raw("<p><a href=\"/audit?before=")
            .text(oldest)
            .raw("\">older</a></p>");
    }
    layout("audit", auth, &main)
}

fn audit_table(h: &mut Html, rows: &[(u64, AuditRow)]) {
    if rows.is_empty() {
        h.raw("<p class=\"empty\">nothing yet</p>");
        return;
    }
    h.raw("<table class=\"grid\"><thead><tr><th>when</th>")
        .raw("<th>who</th><th>what</th></tr></thead><tbody>");
    for (_, row) in rows {
        // The event holds what the host's `vk` said, made display-safe as the store wrote it.
        h.raw("<tr><td>")
            .text(crate::utc(row.at))
            .raw("</td><td>")
            .text(&row.actor)
            .raw("</td><td>")
            .node(&row.event)
            .raw("</td></tr>");
    }
    h.raw("</tbody></table>");
}

/// Start time to the minute. Unlike uptime, it stays fixed as the workload ages.
pub fn started(secs: u64) -> String {
    let mut at = crate::utc(secs);
    // `YYYY-MM-DDTHH:MM:SSZ` without the seconds.
    at.replace_range(16..19, "");
    at
}

pub fn section(h: &mut Html, title: &'static str) {
    h.raw("<section><h2>")
        .raw(title)
        .raw("</h2><table class=\"kv\"><tbody>");
}

pub fn end_section(h: &mut Html) {
    h.raw("</tbody></table></section>");
}

/// A row of a key/value table, both of the hub's making.
pub fn kv(h: &mut Html, key: &str, value: &str) {
    h.raw("<tr><th>")
        .text(key)
        .raw("</th><td>")
        .text(value)
        .raw("</td></tr>");
}

/// A row whose value is what the host reported.
pub fn kv_node(h: &mut Html, key: &'static str, value: &str) {
    h.raw("<tr><th>")
        .text(key)
        .raw("</th><td>")
        .node(value)
        .raw("</td></tr>");
}

pub fn dash() -> String {
    "-".to_string()
}

pub fn mib(n: u64) -> String {
    bytes(n.saturating_mul(1 << 20))
}

/// `n` bytes in binary units, one decimal past the first.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    let name = UNITS.get(unit).unwrap_or(&"B");
    if unit == 0 {
        format!("{n} {name}")
    } else {
        format!("{value:.1} {name}")
    }
}

/// `n` bytes in binary units to two significant figures, so small fluctuations in a
/// changing reading do not change the page on every look.
pub fn rough_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    let name = UNITS.get(unit).unwrap_or(&"B");
    format!("{} {name}", two_figures(value))
}

/// `value`, below a thousand, to two significant figures.
fn two_figures(value: f64) -> String {
    if value >= 100.0 {
        format!("{:.0}", (value / 10.0).round() * 10.0)
    } else if value >= 10.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.1}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What moves by the second is shown in steps coarse enough that an idle page stays put.
    #[test]
    fn readings_are_shown_to_two_figures_and_start_times_to_the_minute() {
        assert_eq!(rough_bytes(197 << 20), "200 MiB");
        assert_eq!(rough_bytes(3 << 30), "3.0 GiB");
        assert_eq!(started(1_790_755_279), "2026-09-30T08:01Z");
    }
}
