//! The pages every UI has, as [`Html`]: the frame around them, signing in, the audit log, and
//! the helpers the rest are built with. Every value in them goes through [`Html::text`] or,
//! for what a node or the host reported, [`Html::node`].

use std::collections::HashMap;

use super::assets;
use super::html::Html;
use super::jobs::{percent_encode, thousands};
use super::{Auth, decode_form, field};
use crate::store::{AUDIT_SCAN, AuditCategory, AuditFilter, AuditFound, AuditRow, audit_who};

/// Audit lines per page of `/audit`.
pub const AUDIT_PAGE: usize = 100;

/// The longest person or actor the audit filter takes; a session's identity is far shorter.
const MAX_WHO: usize = 1024;

/// The ID of the part of `/audit` its filter's form replaces.
const AUDIT_RESULTS: &str = "audit-results";

/// One page of `/audit`.
pub struct AuditPage {
    pub filter: AuditFilter,
    pub found: AuditFound,
    /// The filter's choice of people and actors ([`crate::store::Db::audit_actors`]).
    pub actors: Vec<String>,
    /// The cursor it was read from: an older page.
    pub before: Option<u64>,
}

/// The filter and cursor of `/audit[?category=…&node=…&who=…&q=…&before=…]`. A value that
/// cannot be one is ignored.
pub fn audit_query(query: Option<&str>) -> (AuditFilter, Option<u64>) {
    let query = decode_form(query.unwrap_or("").as_bytes());
    let text = field(&query, "q")
        .map(str::trim)
        .filter(|q| !q.is_empty() && q.chars().count() <= vk_hub_proto::MAX_DISPLAY);
    let filter = AuditFilter {
        node: field(&query, "node")
            .filter(|n| vk_hub_proto::valid_id(n))
            .map(str::to_string),
        who: field(&query, "who")
            .filter(|w| !w.is_empty() && w.len() <= MAX_WHO)
            .map(str::to_string),
        category: field(&query, "category")
            .and_then(AuditCategory::parse)
            .unwrap_or_default(),
        text: text.map(str::to_string),
    };
    let before = field(&query, "before").and_then(|b| b.parse().ok());
    (filter, before)
}

/// A site's navigation: each entry's path and label, in order.
pub type Nav = &'static [(&'static str, &'static str)];

/// Wrap `main` with the head, stylesheet and top bar. The bar shows `nav`, marks the entry
/// for `here`, and displays the signed-in identity and role.
pub fn frame(title: &str, here: &str, auth: &Auth, nav: Nav, main: &Html) -> Html {
    let mut h = Html::new();
    head(&mut h, title);
    h.raw("<body><header class=\"topbar\"><a class=\"brand\" href=\"/\">vk-hub</a><nav>");
    let current = current(nav, here);
    for &(path, label) in nav {
        h.raw("<a href=\"").raw(path).raw("\"");
        if path == current {
            h.raw(" aria-current=\"page\"");
        }
        h.raw(">").raw(label);
        if let Some((_, n)) = auth.counts.iter().find(|(p, _)| *p == path) {
            nav_count(&mut h, path, *n, false);
        }
        h.raw("</a>");
    }
    let s = &auth.session;
    let principal = s.principal();
    h.raw("</nav><form class=\"who\" method=\"post\" action=\"/logout\">")
        .raw("<span class=\"identity\" title=\"")
        .text(&principal)
        .raw("\" aria-label=\"")
        .text(&principal)
        .raw("\">");
    match &s.identity {
        Some(who) => h.text(who),
        None => h.raw("link from ").text(&s.issued_by),
    };
    h.raw("</span> <span class=\"badge\">")
        .raw(s.role.name())
        .raw("</span> <span class=\"until\">until ");
    at(&mut h, s.expires_at);
    h.raw("</span> ");
    csrf_field(&mut h, auth);
    h.raw("<button class=\"secondary\">Sign out</button></form></header><main>")
        .html(main)
        .raw("</main></body></html>");
    h
}

/// The count beside the navigation's entry for `path`, when there are any, in an element of its
/// own that a live page swaps in out of band (`oob`) to keep it current.
fn nav_count(h: &mut Html, path: &str, n: u64, oob: bool) {
    h.raw("<span id=\"nav-count")
        .text(path.replace('/', "-"))
        .raw("\"");
    if oob {
        h.raw(" hx-swap-oob=\"true\"");
    }
    h.raw(">");
    if n > 0 {
        h.raw(" <span class=\"count\">").text(n).raw("</span>");
    }
    h.raw("</span>");
}

/// The longest path in `nav` matching `here` or a parent, ignoring query and fragment.
/// Fall back to `/` when no entry matches.
fn current(nav: Nav, here: &str) -> &'static str {
    let here = here.split(['?', '#']).next().unwrap_or(here);
    nav.iter()
        .map(|&(path, _)| path)
        .filter(|&path| {
            path == "/"
                || here == path
                || here
                    .strip_prefix(path)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
        .max_by_key(|path| path.len())
        .unwrap_or("/")
}

/// htmx's configuration: nothing evaluated, no script run from a swapped fragment, no
/// inline style of its own (the policy would refuse it), requests to this origin only — and
/// a refusal (4xx, 5xx) swapped rather than dropped, so the line saying why shows, without
/// logging it as an error. Disable the history cache in session storage so Back reloads
/// the URL set by the Jobs filter, restoring its form and live fragment rather than a
/// cached page with the form's initial values.
const HTMX_CONFIG: &str = r#"{"allowEval":false,"allowScriptTags":false,"includeIndicatorStyles":false,"selfRequestsOnly":true,"historyCacheSize":0,"refreshOnHistoryMiss":true,"responseHandling":[{"code":"204","swap":false},{"code":"[23]..","swap":true},{"code":"4..","swap":true,"error":false},{"code":"5..","swap":true,"error":false},{"code":"...","swap":false,"error":true}]}"#;

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
        .raw(" · vk-hub</title><link rel=\"icon\" type=\"image/svg+xml\" href=\"")
        .text(assets::url(assets::ICON))
        .raw("\"><link rel=\"stylesheet\" href=\"")
        .text(assets::url(assets::CSS))
        .raw("\"><script src=\"")
        .text(assets::url(assets::HTMX))
        .raw("\"></script><script src=\"")
        .text(assets::url(assets::SSE))
        .raw("\"></script><script src=\"")
        .text(assets::url(assets::TIME))
        .raw("\" defer></script><script src=\"")
        .text(assets::url(assets::FOLLOW))
        .raw("\" defer></script><script src=\"")
        .text(assets::url(assets::CHECKS))
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
    head(&mut h, "Sign in");
    h.raw("<body><main><form class=\"message\" method=\"post\" action=\"/login\">")
        .raw("<input type=\"hidden\" name=\"t\" value=\"")
        .text(token)
        .raw("\"><p>This link signs this browser in to the hub's web UI, once.</p>")
        .raw("<button>Sign in</button></form></main></body></html>");
    h
}

/// A page saying `text` to someone not signed in, with a button to sign in through the OIDC
/// provider at `provider`. The button is a link, not a form: `/auth/login` redirects to the
/// provider, and Chromium holds a form's redirects to `form-action 'self'` and blocks it.
pub fn sign_in_with(text: &str, provider: &str) -> Html {
    let mut h = Html::new();
    head(&mut h, "Sign in");
    h.raw("<body><main><div class=\"message\"><p>")
        .text(text)
        .raw("</p><a class=\"button\" href=\"/auth/login\">Sign in with ")
        .text(provider)
        .raw("</a><p>Or, on the hub's host, <code>vk-hub ui login</code> prints a link ")
        .raw("that signs you in.</p></div></main></body></html>");
    h
}

/// An OIDC sign-in by `identity`, who is granted no role; `unverified` when the provider
/// marked their email unverified, so it was not looked up.
pub fn refused(identity: &str, unverified: bool) -> Html {
    let mut h = Html::new();
    head(&mut h, "Sign in");
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

/// A node or a registry, as the audit log's filter and column name it.
pub struct Subject {
    pub id: String,
    pub name: String,
    /// Its page, before its ID: `/node/` or `/registry/`.
    pub page: &'static str,
}

/// `/audit`: the log, newest first, a page at a time, filtered by category, node or registry,
/// person or actor, and text. Jobs are left out unless asked for.
///
/// `subjects` names the nodes and registries for the filter and their column; local mode has
/// none, nor jobs, and passes `None`. `nav` is the site's navigation.
///
/// With htmx, a choice applies at once and typing after a 300 ms pause, as on the Jobs page:
/// the results are swapped in and the URL updated for Back and bookmarking.
pub fn audit(auth: &Auth, page: &AuditPage, subjects: Option<&[Subject]>, nav: Nav) -> Html {
    let with_node = subjects.is_some();
    let subjects = subjects.unwrap_or_default();
    let filter = &page.filter;
    let mut main = Html::new();
    main.raw("<h1>Audit</h1>");
    audit_form(
        &mut main,
        filter,
        &page.actors,
        with_node.then_some(subjects),
    );
    main.raw("<div id=\"").raw(AUDIT_RESULTS).raw("\">");
    let subjects: HashMap<&str, &Subject> = subjects.iter().map(|s| (s.id.as_str(), s)).collect();
    let found = &page.found;
    if found.cut {
        main.raw("<p class=\"sub\" role=\"status\">")
            .text(thousands(AUDIT_SCAN))
            .raw(" lines read back");
        if !found.rows.is_empty() {
            main.raw(", ").text(found.rows.len()).raw(" matching");
        }
        main.raw("; there are older ones.</p>");
    }
    if found.rows.is_empty() {
        let unfiltered = *filter == AuditFilter::default() && page.before.is_none();
        main.raw(match () {
            _ if found.cut => "",
            _ if unfiltered && !with_node => "<p class=\"empty\">nothing yet</p>",
            _ if page.before.is_some() => "<p class=\"empty\">no older lines match</p>",
            _ if with_node && filter.category == AuditCategory::NotJobs => {
                "<p class=\"empty\" role=\"status\">none match; jobs are left out unless \
                 Jobs or Everything is chosen</p>"
            }
            _ => "<p class=\"empty\" role=\"status\">none match</p>",
        });
    } else {
        audit_table(&mut main, filter, &found.rows, &subjects, with_node);
    }
    if let Some(older) = found.older {
        main.raw("<p><a href=\"");
        audit_href(&mut main, filter, Some(older));
        main.raw("\">")
            .raw(if found.cut {
                "Read further back"
            } else {
                "Older"
            })
            .raw("</a></p>");
    }
    main.raw("</div>");
    frame("Audit", "/audit", auth, nav, &main)
}

/// The filter's form: in a fleet, with its `subjects`, the category and node or registry
/// too. A choice no longer offered — a node removed, an actor past those listed — is kept.
fn audit_form(h: &mut Html, filter: &AuditFilter, actors: &[String], subjects: Option<&[Subject]>) {
    h.raw("<form id=\"audit-filter\" class=\"filter\" method=\"get\" action=\"/audit\" ")
        .raw("hx-get=\"/audit\" hx-trigger=\"submit, change from:(#audit-filter select), ")
        .raw("input changed delay:300ms from:(#audit-filter input)\" hx-target=\"#")
        .raw(AUDIT_RESULTS)
        .raw("\" hx-select=\"#")
        .raw(AUDIT_RESULTS)
        .raw("\" hx-swap=\"outerHTML\" hx-push-url=\"true\" hx-sync=\"this:replace\">");
    if let Some(subjects) = subjects {
        h.raw("<select name=\"category\" aria-label=\"Category\">");
        for category in AuditCategory::ALL {
            h.raw("<option value=\"").raw(category.name()).raw("\"");
            if filter.category == category {
                h.raw(" selected");
            }
            h.raw(">").raw(category.label()).raw("</option>");
        }
        h.raw("</select><select name=\"node\" aria-label=\"Node or registry\">")
            .raw("<option value=\"\">Every node and registry</option>");
        if let Some(node) = &filter.node
            && !subjects.iter().any(|s| s.id == *node)
        {
            h.raw("<option value=\"")
                .text(node)
                .raw("\" selected>")
                .text(node.get(..8).unwrap_or(node))
                .raw("</option>");
        }
        let mut sorted: Vec<(&str, &str)> = subjects
            .iter()
            .map(|s| (s.id.as_str(), s.name.as_str()))
            .collect();
        sorted.sort_by_key(|&(id, name)| (name, id));
        for (id, name) in sorted {
            h.raw("<option value=\"").text(id).raw("\"");
            if filter.node.as_deref() == Some(id) {
                h.raw(" selected");
            }
            h.raw(">")
                .node(name)
                .raw(" (")
                .text(id.get(..8).unwrap_or(id))
                .raw(")</option>");
        }
        h.raw("</select>");
    }
    h.raw("<select name=\"who\" aria-label=\"Who\"><option value=\"\">Everyone</option>");
    if let Some(who) = &filter.who
        && !actors.contains(who)
    {
        h.raw("<option value=\"")
            .text(who)
            .raw("\" selected>")
            .text(who)
            .raw("</option>");
    }
    for who in actors {
        h.raw("<option value=\"").text(who).raw("\"");
        if filter.who.as_ref() == Some(who) {
            h.raw(" selected");
        }
        h.raw(">").text(who).raw("</option>");
    }
    h.raw("</select><input type=\"search\" name=\"q\" placeholder=\"Text, as a job ID\" ")
        .raw("aria-label=\"Text\" value=\"")
        .text(filter.text.as_deref().unwrap_or(""))
        .raw("\" maxlength=\"")
        .text(vk_hub_proto::MAX_DISPLAY)
        .raw("\"> <button>Show</button></form>");
}

/// `/audit` with `filter`, and `before` if given, as its query. Values are percent-encoded,
/// so an identity or a text cannot end the attribute or add a parameter.
fn audit_href(h: &mut Html, filter: &AuditFilter, before: Option<u64>) {
    let before = before.map(|b| b.to_string());
    let category = Some(filter.category.name()).filter(|c| !c.is_empty());
    let fields = [
        ("category", category),
        ("node", filter.node.as_deref()),
        ("who", filter.who.as_deref()),
        ("q", filter.text.as_deref()),
        ("before", before.as_deref()),
    ];
    h.raw("/audit");
    let mut separator = "?";
    for (name, value) in fields {
        if let Some(value) = value {
            h.raw(separator)
                .raw(name)
                .raw("=")
                .text(percent_encode(value));
            separator = "&amp;";
        }
    }
}

/// The page's lines, one row each. Who did one links to the same filter narrowed to them.
fn audit_table(
    h: &mut Html,
    filter: &AuditFilter,
    rows: &[(u64, AuditRow)],
    subjects: &HashMap<&str, &Subject>,
    with_node: bool,
) {
    h.raw("<table class=\"grid\"><thead><tr><th>when</th>");
    if with_node {
        h.raw("<th>node or registry</th>");
    }
    h.raw("<th>who</th><th>what</th></tr></thead><tbody>");
    for (_, row) in rows {
        h.raw("<tr><td>");
        time(h, row.at, &crate::utc(row.at)).raw("</td>");
        if with_node {
            h.raw("<td>");
            match row.node.as_deref() {
                Some(id) if vk_hub_proto::valid_id(id) => match subjects.get(id) {
                    Some(s) => {
                        h.raw("<a href=\"")
                            .raw(s.page)
                            .text(id)
                            .raw("\">")
                            .node(&s.name)
                            .raw("</a>");
                    }
                    // Removed since: no page to link to.
                    None => {
                        h.text(id.get(..8).unwrap_or(id));
                    }
                },
                Some(id) => {
                    h.node(id);
                }
                None => {
                    h.raw("-");
                }
            }
            h.raw("</td>");
        }
        let theirs = AuditFilter {
            who: Some(audit_who(&row.actor).to_string()),
            ..filter.clone()
        };
        h.raw("<td><a href=\"");
        audit_href(h, &theirs, None);
        h.raw("\" title=\"Only theirs\">")
            .text(&row.actor)
            .raw("</a></td><td>");
        audit_event(h, &row.actor, &row.event, subjects);
        h.raw("</td></tr>");
    }
    h.raw("</tbody></table>");
}

/// Show audit `event` without the leading `actor` already shown in the who column.
/// Replace known node and registry IDs with names linked to their pages.
fn audit_event(h: &mut Html, actor: &str, event: &str, subjects: &HashMap<&str, &Subject>) {
    let event = event
        .strip_prefix(actor)
        .and_then(|rest| rest.strip_prefix(' '))
        .filter(|rest| !actor.is_empty() && !rest.is_empty())
        .unwrap_or(event);
    // The event holds what nodes or the host's `vk` said, made display-safe as the store
    // wrote it.
    let event = vk_hub_proto::display_safe(event);
    let mut shown = 0;
    let mut words = event.char_indices().peekable();
    while let Some((start, c)) = words.next() {
        if !c.is_ascii_alphanumeric() {
            continue;
        }
        let mut end = start + 1;
        while let Some(&(i, c)) = words.peek() {
            if !c.is_ascii_alphanumeric() {
                break;
            }
            end = i + 1;
            words.next();
        }
        let word = &event[start..end];
        if word.len() == 32
            && let Some(s) = subjects.get(word).filter(|_| vk_hub_proto::valid_id(word))
        {
            h.text(&event[shown..start])
                .raw("<a href=\"")
                .raw(s.page)
                .text(word)
                .raw("\">")
                .node(&s.name)
                .raw("</a>");
            shown = end;
        }
    }
    h.text(&event[shown..]);
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

/// Whether `columns[i]` is `name`, at compile time.
pub const fn column_is(columns: &[&str], i: usize, name: &str) -> bool {
    if i >= columns.len() {
        return false;
    }
    let (a, b) = (columns[i].as_bytes(), name.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut k = 0;
    while k < a.len() {
        if a[k] != b[k] {
            return false;
        }
        k += 1;
    }
    true
}

/// Right-aligned numeric columns in `vk-hub nodes` and node workloads.
/// Compile-time checks reject names absent from both column lists.
const NUMERIC: [&str; 9] = [
    "CEILING", "CONC", "CPUS", "RAM", "ADMITTED", "VMS", "PID", "RESERVED", "IN USE",
];
const _: () = {
    let mut i = 0;
    while i < NUMERIC.len() {
        let name = NUMERIC[i];
        assert!(
            has_column(&crate::NODE_COLUMNS, name) || has_column(&crate::workloads::COLUMNS, name)
        );
        i += 1;
    }
};

/// Whether `columns` holds `name`, at compile time.
const fn has_column(columns: &[&str], name: &str) -> bool {
    let mut i = 0;
    while i < columns.len() {
        if column_is(columns, i, name) {
            return true;
        }
        i += 1;
    }
    false
}

/// Whether the column `name` holds figures.
fn numeric(name: &str) -> bool {
    NUMERIC.contains(&name)
}

/// A table's header cells for `columns`.
pub fn header_cells(h: &mut Html, columns: &[&str]) {
    for &column in columns {
        h.raw(if numeric(column) {
            "<th class=\"num\">"
        } else {
            "<th>"
        })
        .text(column)
        .raw("</th>");
    }
}

/// Open the cell of `column`.
pub fn open_cell(h: &mut Html, column: &str) {
    h.raw(if numeric(column) {
        "<td class=\"num\">"
    } else {
        "<td>"
    });
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

    /// The navigation marks the entry a page is under: its own, a parent's, else `/`.
    #[test]
    fn the_current_entry_is_the_nearest_above_the_page() {
        const NAV: Nav = &[
            ("/", "Nodes"),
            ("/operations", "Operations"),
            ("/audit", "Audit"),
        ];
        assert_eq!(current(NAV, "/"), "/");
        assert_eq!(current(NAV, "/node/ab"), "/");
        assert_eq!(current(NAV, "/operations"), "/operations");
        assert_eq!(current(NAV, "/audit/x"), "/audit");
        assert_eq!(current(NAV, "/auditx"), "/");
        assert_eq!(current(NAV, "/audit?node=ab"), "/audit");
        assert_eq!(current(NAV, "/operations#rollouts"), "/operations");
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

    /// An audit event drops the actor its row shows and names the nodes and registries it
    /// knows, linked; another ID, an unknown node's or one inside a longer word, stays as
    /// written.
    #[test]
    fn an_audit_event_names_known_subjects_without_repeating_its_actor() {
        let (known, unknown) = ("ab".repeat(16), "cd".repeat(16));
        let node = Subject {
            id: known.clone(),
            name: "runner-1".into(),
            page: "/node/",
        };
        let registry_id = "ef".repeat(16);
        let registry = Subject {
            id: registry_id.clone(),
            name: "mirror".into(),
            page: crate::ui::registries::DETAIL_PREFIX,
        };
        let subjects = HashMap::from([(known.as_str(), &node), (registry_id.as_str(), &registry)]);
        let shown = |actor: &str, event: &str| {
            let mut h = Html::new();
            audit_event(&mut h, actor, event, &subjects);
            h.into_string()
        };
        assert_eq!(
            shown(
                "key gitlab",
                &format!("key gitlab canceled job {unknown} immediately")
            ),
            format!("canceled job {unknown} immediately")
        );
        assert_eq!(
            shown("hub", &format!("node {known} refused job {unknown}: busy")),
            format!("node <a href=\"/node/{known}\">runner-1</a> refused job {unknown}: busy")
        );
        assert_eq!(
            shown("hub", &format!("1 reservation(s) on node {known}")),
            format!("1 reservation(s) on node <a href=\"/node/{known}\">runner-1</a>")
        );
        assert_eq!(
            shown("hub", &format!("({known}) {known}: x")),
            format!(
                "(<a href=\"/node/{known}\">runner-1</a>) \
                 <a href=\"/node/{known}\">runner-1</a>: x"
            )
        );
        assert_eq!(
            shown("uid 0", &format!("x{known} <b>")),
            format!("x{known} &lt;b&gt;")
        );
        assert_eq!(
            shown("hub", &format!("registry {registry_id} applied")),
            format!("registry <a href=\"/registry/{registry_id}\">mirror</a> applied")
        );
        assert_eq!(shown("hub", "hub"), "hub");
        assert_eq!(shown("hub", "hubs grew"), "hubs grew");
    }
}
