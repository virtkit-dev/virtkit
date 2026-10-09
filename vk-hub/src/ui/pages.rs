//! The pages every UI has, as [`Html`]: the frame around them, signing in, the audit log, and
//! the helpers the rest are built with. Every value in them goes through [`Html::text`] or,
//! for what a node or the host reported, [`Html::node`].

use std::collections::HashMap;

use super::Auth;
use super::assets;
use super::html::Html;
use crate::store::AuditRow;

/// Audit lines per page of `/audit`.
pub const AUDIT_PAGE: usize = 100;

/// One page of `/audit`.
pub struct AuditPage {
    /// The node it is filtered to, if any.
    pub node: Option<String>,
    /// Newest first, with their sequence numbers.
    pub rows: Vec<(u64, AuditRow)>,
}

/// The page around `main`: head, stylesheet, the site's navigation `nav`, who is signed in.
pub fn frame(title: &str, auth: &Auth, nav: &'static str, main: &Html) -> Html {
    let mut h = Html::new();
    head(&mut h, title);
    h.raw("<body><header><nav>")
        .raw(nav)
        .raw("</nav><form class=\"who\" method=\"post\" action=\"/logout\"><span>")
        .text(auth.session.principal())
        .raw(", until ");
    at(&mut h, auth.session.expires_at);
    h.raw("</span> ");
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

/// Open the page through its head. `data-now` gives `time.js` the hub's page-generation
/// time so ages use the hub's clock.
fn head(h: &mut Html, title: &str) {
    h.raw("<!doctype html><html lang=\"en\" data-now=\"")
        .text(crate::utc(crate::now_secs()))
        .raw("\"><head><meta charset=\"utf-8\">")
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
        .raw("\"></script><script src=\"")
        .text(assets::url(assets::TIME))
        .raw("\" defer></script></head>");
}

/// The hidden field carrying the session's CSRF token.
pub fn csrf_field(h: &mut Html, auth: &Auth) {
    csrf_input(h, &auth.csrf);
}

/// The hidden field carrying a session's CSRF token, `csrf`.
pub fn csrf_input(h: &mut Html, csrf: &str) {
    h.raw("<input type=\"hidden\" name=\"_csrf\" value=\"")
        .text(csrf)
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

/// A page saying `text` to someone not signed in, with a button to sign in through the OIDC
/// provider at `provider`.
pub fn sign_in_with(text: &str, provider: &str) -> Html {
    let mut h = Html::new();
    head(&mut h, "sign in");
    h.raw("<body><main><form class=\"message\" method=\"get\" action=\"/auth/login\"><p>")
        .text(text)
        .raw("</p><button>Sign in with ")
        .text(provider)
        .raw("</button><p>Or, on the hub's host, <code>vk-hub ui login</code> prints a link ")
        .raw("that signs you in.</p></form></main></body></html>");
    h
}

/// An OIDC sign-in by `identity`, who is granted no role; `unverified` when the provider
/// marked their email unverified, so it was not looked up.
pub fn refused(identity: &str, unverified: bool) -> Html {
    let mut h = Html::new();
    head(&mut h, "sign in");
    h.raw("<body><main><p class=\"message\">You signed in as ")
        .text(identity)
        .raw(", who may not use this hub's web UI. Its operator lets people in by email, ")
        .raw("with <code>vk-hub accounts grant</code>");
    if unverified {
        h.raw(", but your provider marks your email unverified");
    }
    h.raw(".</p></main></body></html>");
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

/// A live region's last fragment, once its session has ended; `sign_in`, markup of the
/// site's, says how to sign in again.
pub fn signed_out_fragment(sign_in: &'static str) -> Html {
    let mut h = Html::new();
    h.raw("<p class=\"message\">Signed out: this page no longer updates. ")
        .raw(sign_in)
        .raw("</p>");
    h
}

/// `/audit`: the paginated log, newest first, optionally filtered by node.
///
/// `names` maps node IDs to names for the filter and node column; local mode has no nodes
/// and passes `None`. `nav` is the site's navigation.
pub fn audit(
    auth: &Auth,
    page: &AuditPage,
    names: Option<&[(String, String)]>,
    nav: &'static str,
) -> Html {
    let with_node = names.is_some();
    let names = names.unwrap_or_default();
    let mut main = Html::new();
    main.raw("<h1>Audit</h1>");
    if with_node {
        main.raw("<form class=\"filter\" method=\"get\" action=\"/audit\">")
            .raw("<select name=\"node\"><option value=\"\">every node</option>");
        let mut sorted: Vec<(&str, &str)> = names
            .iter()
            .map(|(id, name)| (id.as_str(), name.as_str()))
            .collect();
        sorted.sort_by_key(|&(id, name)| (name, id));
        for (id, name) in sorted {
            main.raw("<option value=\"").text(id).raw("\"");
            if page.node.as_deref() == Some(id) {
                main.raw(" selected");
            }
            main.raw(">")
                .node(name)
                .raw(" (")
                .text(id.get(..8).unwrap_or(id))
                .raw(")</option>");
        }
        main.raw("</select> <button>show</button></form>");
    }
    let names: HashMap<&str, &str> = names
        .iter()
        .map(|(id, name)| (id.as_str(), name.as_str()))
        .collect();
    audit_table(&mut main, &page.rows, &names, with_node);
    if page.rows.len() == AUDIT_PAGE
        && let Some((oldest, _)) = page.rows.last()
    {
        main.raw("<p><a href=\"/audit?");
        if let Some(node) = &page.node {
            main.raw("node=").text(node).raw("&amp;");
        }
        main.raw("before=").text(oldest).raw("\">older</a></p>");
    }
    frame("audit", auth, nav, &main)
}

fn audit_table(
    h: &mut Html,
    rows: &[(u64, AuditRow)],
    names: &HashMap<&str, &str>,
    with_node: bool,
) {
    if rows.is_empty() {
        h.raw("<p class=\"empty\">nothing yet</p>");
        return;
    }
    h.raw("<table class=\"grid\"><thead><tr><th>when</th>");
    if with_node {
        h.raw("<th>node</th>");
    }
    h.raw("<th>who</th><th>what</th></tr></thead><tbody>");
    for (_, row) in rows {
        h.raw("<tr><td>");
        time(h, row.at, &crate::utc(row.at)).raw("</td>");
        if with_node {
            h.raw("<td>");
            match row.node.as_deref() {
                Some(id) if vk_hub_proto::valid_id(id) => {
                    h.raw("<a href=\"/node/").text(id).raw("\">");
                    match names.get(id) {
                        Some(name) => h.node(name),
                        None => h.text(id.get(..8).unwrap_or(id)),
                    };
                    h.raw("</a>");
                }
                Some(id) => {
                    h.node(id);
                }
                None => {
                    h.raw("-");
                }
            }
            h.raw("</td>");
        }
        // The event holds what nodes or the host's `vk` said, made display-safe as the store
        // wrote it.
        h.raw("<td>")
            .text(&row.actor)
            .raw("</td><td>")
            .node(&row.event)
            .raw("</td></tr>");
    }
    h.raw("</tbody></table>");
}

/// The instant `secs` as a `<time>` element for `time.js` to show in the browser's zone
/// with its age. Without the script, `text` shows the UTC instant or an age; the title
/// always gives the exact UTC instant. Use only the hub's own figures.
pub fn time<'h>(h: &'h mut Html, secs: u64, text: &str) -> &'h mut Html {
    let utc = crate::utc(secs);
    // `YYYY-MM-DDTHH:MM:SSZ` as `YYYY-MM-DD HH:MM:SS UTC`.
    let title = format!("{} UTC", utc.replacen('T', " ", 1).trim_end_matches('Z'));
    h.raw("<time datetime=\"")
        .text(&utc)
        .raw("\" title=\"")
        .text(title)
        .raw("\">")
        .text(text)
        .raw("</time>")
}

/// [`time`] with [`started`] as the fallback text.
pub fn at(h: &mut Html, secs: u64) -> &mut Html {
    time(h, secs, &started(secs))
}

/// [`at`] as a standalone fragment.
pub fn at_html(secs: u64) -> Html {
    let mut h = Html::new();
    at(&mut h, secs);
    h
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

/// A row with hub-generated markup as its value.
pub fn kv_html(h: &mut Html, key: &str, value: &Html) {
    h.raw("<tr><th>")
        .text(key)
        .raw("</th><td>")
        .html(value)
        .raw("</td></tr>");
}

/// A row whose value is what a node or the host reported.
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

pub fn count(n: Option<u32>) -> String {
    n.map_or_else(dash, |n| n.to_string())
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

/// A count that moves by the second — free inodes — to two significant figures, in
/// thousands, millions and so on past a hundred.
pub fn rough_count(n: u64) -> String {
    const UNITS: [&str; 6] = ["", "k", "M", "G", "T", "P"];
    if n < 100 {
        return n.to_string();
    }
    let mut value = n as f64;
    let mut unit = 0;
    // From 995 of a unit, two figures round up to the next: 1.0M, not 1000k.
    while value >= 995.0 && unit + 1 < UNITS.len() {
        value /= 1000.0;
        unit += 1;
    }
    format!("{}{}", two_figures(value), UNITS.get(unit).unwrap_or(&""))
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
        assert_eq!(rough_count(7), "7");
        assert_eq!(rough_count(1234), "1.2k");
        assert_eq!(rough_count(54_501_783), "55M");
        assert_eq!(rough_count(54_501_781), rough_count(54_501_783));
        assert_eq!(rough_count(62_316_544), "62M");
        assert_eq!(rough_count(994_999), "990k");
        assert_eq!(rough_count(995_000), "1.0M");
        assert_eq!(rough_count(999_999), "1.0M");
        assert_eq!(rough_bytes(197 << 20), "200 MiB");
        assert_eq!(rough_bytes(3 << 30), "3.0 GiB");
        assert_eq!(started(1_790_755_279), "2026-09-30T08:01Z");
    }

    /// An instant carries its exact UTC time for the script and the title, and shows the
    /// text given without the script.
    #[test]
    fn an_instant_is_a_time_element_in_utc() {
        let mut h = Html::new();
        at(&mut h, 1_790_755_279);
        time(&mut h, 1_790_755_279, "5s ago");
        assert_eq!(
            h.into_string(),
            "<time datetime=\"2026-09-30T08:01:19Z\" title=\"2026-09-30 08:01:19 UTC\">\
             2026-09-30T08:01Z</time>\
             <time datetime=\"2026-09-30T08:01:19Z\" title=\"2026-09-30 08:01:19 UTC\">\
             5s ago</time>"
        );
    }
}
