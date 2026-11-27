//! Operators add, change and remove storage areas from the Job access tab via
//! `POST /registry/<id>/areas`. Adds and edits use [`NamespaceRow::check`] and the same
//! cross-area checks as `vk-hub namespaces add`. Edits and removals must match the displayed
//! revision. The store audits successful writes as the session's principal. CI areas are
//! managed from the CLI.

use anyhow::Result;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use super::fleet::FleetSite;
use super::html::Html;
use super::pages;
use super::registries::{DETAIL_PREFIX, Tab};
use super::{Auth, Body, Ui, actions, blocking, field, html_response, message};
use crate::registries::RegistryView;
use crate::store::{
    CI_BUILD, CI_CACHE, CI_PIPELINE, Expect, NamespaceChanged, NamespaceRow, NotEnrolled,
    RegistryRow, Role,
};
use vk_hub_proto::registry::{FlatSetting, FlatUsage, flat_prefixes_overlap};
use vk_hub_proto::token::under;

/// Allow for 32 access rules (job subjects up to 512 bytes) and 32 isolated ref globs
/// of up to 255 bytes each, even when every byte is percent-encoded.
const MAX_AREA_FORM: usize = 128 * 1024;

/// Registry ID from `/registry/<id>/areas`.
pub(super) fn action_target(path: &str) -> Option<&str> {
    path.strip_prefix(DETAIL_PREFIX)?
        .strip_suffix("/areas")
        .filter(|id| vk_hub_proto::valid_id(id))
}

/// Whether `name` is a CI area managed only from the CLI.
pub(super) fn managed(name: &str) -> bool {
    [CI_CACHE, CI_PIPELINE, CI_BUILD].contains(&name)
}

/// The Job access tab of registry `id`.
fn tab_path(id: &str) -> String {
    format!("{DETAIL_PREFIX}{id}?tab=access")
}

/// Form values from the operator or a stored area.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Draft {
    /// True for a new area.
    pub new: bool,
    pub name: String,
    pub path: String,
    pub alias: String,
    pub retention_days: String,
    /// Ref globs, one a line.
    pub isolate: String,
    /// Access rules, `<rights>:<subject>` one a line.
    pub grants: String,
    /// The [`NamespaceRow::revision`] a change was made against.
    pub revision: String,
}

/// Lines of `text`, trimmed, the empty ones dropped.
fn lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

impl Draft {
    pub(super) fn blank() -> Self {
        Draft {
            new: true,
            ..Draft::default()
        }
    }

    /// Stored area `ns`, to change.
    pub(super) fn of_row(ns: &NamespaceRow) -> Self {
        let grants: Vec<String> = ns
            .grants
            .iter()
            .map(crate::store::NsGrant::editable)
            .chain(ns.node_grants.iter().map(ToString::to_string))
            .collect();
        Draft {
            new: false,
            name: ns.name.clone(),
            path: ns.path.clone(),
            alias: ns.alias.clone().unwrap_or_default(),
            retention_days: ns.retention_days.map(|d| d.to_string()).unwrap_or_default(),
            isolate: ns.isolate.join("\n"),
            grants: grants.join("\n"),
            revision: ns.revision(),
        }
    }

    /// Require path, alias, retention, refs and rules even when empty. Treating a field
    /// dropped by the decoder as empty could clear a stored value.
    fn of_form(form: &[(String, String)]) -> Option<Self> {
        for name in ["path", "alias", "retention_days", "isolate", "grants"] {
            field(form, name)?;
        }
        let text = |name: &str| field(form, name).unwrap_or("").to_string();
        Some(Draft {
            new: field(form, "new") == Some("1"),
            name: text("name").trim().to_string(),
            path: text("path").trim().to_string(),
            alias: text("alias").trim().to_string(),
            retention_days: text("retention_days").trim().to_string(),
            isolate: text("isolate"),
            grants: text("grants"),
            revision: text("revision"),
        })
    }

    /// The area to store, made by `actor` at `now`, or why it may not be.
    fn row(&self, actor: &str, now: u64) -> Result<NamespaceRow, String> {
        let retention_days = match self.retention_days.as_str() {
            "" => None,
            d => Some(
                d.parse::<u64>()
                    .map_err(|_| "The retention is a whole number of days.".to_string())?,
            ),
        };
        let (grants, node_grants) = crate::store::parse_grants(&lines(&self.grants))?;
        let ns = NamespaceRow {
            name: self.name.clone(),
            path: self.path.clone(),
            retention_days,
            alias: (!self.alias.is_empty()).then(|| self.alias.clone()),
            isolate: lines(&self.isolate),
            grants,
            node_grants,
            created_at: now,
            created_by: actor.to_string(),
        };
        ns.check()?;
        Ok(ns)
    }

    /// What the store expects of the area of its name.
    fn expect(&self) -> Expect<'_> {
        if self.new {
            Expect::Absent
        } else {
            Expect::Revision(&self.revision)
        }
    }
}

fn hidden(h: &mut Html, name: &'static str, value: &str) {
    h.raw("<input type=\"hidden\" name=\"")
        .raw(name)
        .raw("\" value=\"")
        .text(value)
        .raw("\">");
}

/// The form that adds or changes `d` on registry `id`.
pub(super) fn editor(h: &mut Html, id: &str, d: &Draft, auth: &Auth) {
    h.raw("<form class=\"wide\" method=\"post\" action=\"")
        .raw(DETAIL_PREFIX)
        .text(id)
        .raw("/areas\">");
    pages::csrf_field(h, auth);
    hidden(h, "op", "put");
    if d.new {
        hidden(h, "new", "1");
        h.raw("<label>Name <input name=\"name\" required maxlength=\"64\" ")
            .raw("pattern=\"[A-Za-z0-9][A-Za-z0-9._\\-]*\" autocomplete=\"off\" value=\"")
            .text(&d.name)
            .raw("\"></label>");
    } else {
        hidden(h, "name", &d.name);
        hidden(h, "revision", &d.revision);
    }
    h.raw("<label>Path <input name=\"path\" required size=\"48\" ")
        .raw("spellcheck=\"false\" autocomplete=\"off\" value=\"")
        .text(&d.path)
        .raw("\"></label><label>Alias <input name=\"alias\" ")
        .raw("spellcheck=\"false\" autocomplete=\"off\" value=\"")
        .text(&d.alias)
        .raw("\"></label><label>Cleanup after <input type=\"number\" name=\"retention_days\" ")
        .raw("min=\"1\" max=\"3650\" value=\"")
        .text(&d.retention_days)
        .raw("\"> idle days</label>")
        // HTML drops the first newline after <textarea>. Supply one to preserve a leading
        // newline in the value.
        .raw("<label>Access rules, one a line <textarea name=\"grants\" rows=\"4\" ")
        .raw("spellcheck=\"false\" required>\n")
        .text(&d.grants)
        .raw("</textarea></label><label>Refs kept apart, one glob a line ")
        .raw("<textarea name=\"isolate\" rows=\"2\" spellcheck=\"false\">\n")
        .text(&d.isolate)
        .raw("</textarea></label><button class=\"primary\">")
        .raw(if d.new { "Add" } else { "Save" })
        .raw("</button></form><p class=\"sub\">Start the path with a fixed repository name ")
        .raw("component. Later components can be <code>{gitlab}</code>, ")
        .raw("<code>{project_id}</code>, ")
        .raw("<code>{pipeline_id}</code>, <code>{protection}</code> or <code>{scope}</code>, ")
        .raw("as in <code>sccache/{gitlab}/{project_id}/{protection}</code>. On nodes that ")
        .raw("support aliases, authorized jobs can use <code>job/&lt;alias&gt;</code> if an alias ")
        .raw("is set. An existing path under <code>job/</code> disables aliases. Write each rule ")
        .raw("as <code>&lt;rights&gt;:&lt;subject&gt;</code>. Combine <code>r</code> (read), ")
        .raw("<code>w</code> (publish) and <code>l</code> (coordinate builds) as needed. ")
        .raw("Examples include <code>rw:own project</code>, <code>r:*</code>, <code>r:gitlab gl, ")
        .raw("projects wab/**, protected</code> and <code>r:nodes</code>. To keep matching refs ")
        .raw("apart, include <code>{scope}</code> in the path so each gets its own scope. Cleanup ")
        .raw("windows set here need <code>gc</code> in the registry's <code>[hub] allow</code>. ")
        .raw("Tokens issued before a change keep their access until they expire.</p>");
}

/// Start a confirmed removal of area `ns` from registry `id`.
pub(super) fn remove_form(h: &mut Html, id: &str, ns: &NamespaceRow, auth: &Auth) {
    h.raw("<form class=\"act\" method=\"post\" action=\"")
        .raw(DETAIL_PREFIX)
        .text(id)
        .raw("/areas\">");
    pages::csrf_field(h, auth);
    hidden(h, "op", "remove");
    hidden(h, "name", &ns.name);
    hidden(h, "revision", &ns.revision());
    h.raw("<button class=\"danger\">Remove this area</button></form>");
}

/// Redisplay the submitted Job access form with the reason for refusal.
fn refused_page(id: &str, hostname: &str, d: &Draft, why: &str, auth: &Auth) -> Html {
    let mut h = Html::new();
    super::registries::heading(&mut h, id, hostname, Tab::Access);
    h.raw("<p class=\"callout warn\" role=\"alert\">")
        .text(why)
        .raw("</p><section><h2>");
    if d.new {
        h.raw("Add a storage area");
    } else {
        h.raw("Change ").text(&d.name);
    }
    h.raw("</h2>");
    editor(&mut h, id, d, auth);
    h.raw("<p><a href=\"")
        .text(tab_path(id))
        .raw("\">Back to Job access</a></p></section>");
    h
}

/// Handle `POST /registry/<id>/areas` as the operator's session principal.
/// Confirm removals and redirect successful writes to Job access.
pub(super) async fn action(
    req: Request<Incoming>,
    ui: &Ui,
    site: &FleetSite,
    id: &str,
) -> Result<Response<Body>> {
    let htmx = req.headers().contains_key("hx-request");
    let (auth, form) = match super::check_post_sized(req, ui, Role::Operator, MAX_AREA_FORM).await?
    {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(actions::refused(htmx, status, text)),
    };
    let name = field(&form, "name").unwrap_or("").trim().to_string();
    if managed(&name) {
        return Ok(message(
            StatusCode::BAD_REQUEST,
            "Refused: use vk-hub namespaces add to set a CI area or vk-hub namespaces remove to \
             remove it.",
        ));
    }
    let hub = ui.hub.clone();
    let wanted = id.to_string();
    let Some(row) = blocking(move || hub.db.registry(&wanted)).await? else {
        return Ok(message(StatusCode::NOT_FOUND, "There is no such registry."));
    };
    let principal = auth.session.principal();
    match field(&form, "op") {
        Some("put") => {
            let Some(d) = Draft::of_form(&form) else {
                return Ok(message(
                    StatusCode::BAD_REQUEST,
                    "Refused: the form is incomplete.",
                ));
            };
            let ns = match d.row(&principal, crate::now_secs()) {
                Ok(ns) => ns,
                Err(why) => {
                    let main =
                        refused_page(id, &row.hostname, &d, &format!("Refused: {why}"), &auth);
                    return Ok(layout(
                        StatusCode::BAD_REQUEST,
                        &row.hostname,
                        id,
                        &auth,
                        &main,
                    ));
                }
            };
            let (hub, wanted, draft) = (ui.hub.clone(), id.to_string(), d.clone());
            let stored = blocking(move || {
                Ok(crate::registries::put_namespace_with(
                    &hub,
                    &principal,
                    &wanted,
                    ns,
                    false,
                    draft.expect(),
                ))
            })
            .await?;
            match stored {
                Ok(_) => Ok(super::registries::see_other(&tab_path(id))),
                Err(e) if e.is::<NotEnrolled>() => {
                    Ok(message(StatusCode::NOT_FOUND, "There is no such registry."))
                }
                Err(e) => {
                    let why = format!("Refused: {e:#}.");
                    let main = refused_page(id, &row.hostname, &d, &why, &auth);
                    Ok(layout(
                        StatusCode::CONFLICT,
                        &row.hostname,
                        id,
                        &auth,
                        &main,
                    ))
                }
            }
        }
        Some("remove") => {
            let revision = field(&form, "revision").unwrap_or("").to_string();
            let mut detail = Html::new();
            detail
                .raw("<p>Storage area <strong>")
                .text(&name)
                .raw("</strong> on <strong>")
                .node(&row.hostname)
                .raw("</strong></p>");
            let ask = actions::Ask {
                path: format!("{DETAIL_PREFIX}{id}/areas"),
                back: tab_path(id),
                op: "remove".to_string(),
                what: "Remove this storage area? After removal, new tokens grant no access \
                       through it. Existing tokens keep their access until they expire. \
                       Stored data stays on the registry.",
                detail,
                asked: vec![("name", name.clone()), ("revision", revision.clone())],
            };
            if let Some(asked) = actions::ask_first(
                &site.questions,
                super::fleet::layout,
                htmx,
                &auth,
                &form,
                &ask,
            )? {
                return Ok(asked);
            }
            let (hub, wanted) = (ui.hub.clone(), id.to_string());
            let removed = blocking(move || {
                Ok(crate::registries::remove_namespace(
                    &hub,
                    &principal,
                    &wanted,
                    &name,
                    Some(&revision),
                ))
            })
            .await?;
            match removed {
                Ok(true) => Ok(super::registries::see_other(&tab_path(id))),
                Ok(false) => Ok(message(
                    StatusCode::NOT_FOUND,
                    "There is no such storage area. It may have been removed.",
                )),
                Err(e) if e.is::<NamespaceChanged>() => Ok(message(
                    StatusCode::CONFLICT,
                    &format!("Refused: {e}. Look at it again."),
                )),
                Err(e) => Ok(message(StatusCode::CONFLICT, &format!("Refused: {e:#}."))),
            }
        }
        _ => Ok(message(StatusCode::BAD_REQUEST, "No such action.")),
    }
}

fn layout(
    status: StatusCode,
    hostname: &str,
    id: &str,
    auth: &Auth,
    main: &Html,
) -> Response<Body> {
    html_response(
        status,
        super::fleet::layout(hostname, &format!("{DETAIL_PREFIX}{id}"), auth, main),
    )
}

/// Requested and reported flat stores relative to an area's [`NamespaceRow::static_prefix`].
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Flat<'a> {
    /// Its path starts with a placeholder: no fixed prefix to bind.
    NoPrefix,
    /// The hub binds its prefix.
    Bound(&'a FlatSetting),
    /// The hub binds a prefix above it.
    Within(&'a FlatSetting),
    /// The registry last reported a covering store with no current hub binding there.
    /// It may come from local config or an earlier hub binding.
    Reported(&'a FlatUsage),
    /// Requested or reported stores below the prefix would overlap a binding here.
    Below(Vec<&'a str>),
    Unbound,
}

impl<'a> Flat<'a> {
    pub(super) fn of(ns: &NamespaceRow, row: &'a RegistryRow) -> Self {
        let Some(prefix) = ns.static_prefix() else {
            return Flat::NoPrefix;
        };
        let bound = row
            .desired
            .as_ref()
            .and_then(|d| d.flat.as_deref())
            .unwrap_or_default();
        if let Some(s) = bound.iter().find(|s| s.prefix == prefix) {
            return Flat::Bound(s);
        }
        if let Some(s) = bound.iter().find(|s| under(&s.prefix, &prefix)) {
            return Flat::Within(s);
        }
        if let Some(u) = usage(row, &prefix) {
            return Flat::Reported(u);
        }
        let counted = row.usage.as_ref().map_or(&[][..], |u| &u.flat[..]);
        let below: std::collections::BTreeSet<&str> = (bound.iter().map(|s| s.prefix.as_str()))
            .chain(counted.iter().map(|u| u.prefix.as_str()))
            .filter(|p| flat_prefixes_overlap(p, &prefix))
            .collect();
        if below.is_empty() {
            Flat::Unbound
        } else {
            Flat::Below(below.into_iter().collect())
        }
    }
}

/// Last reported usage of a store at or above `prefix`.
fn usage<'a>(row: &'a RegistryRow, prefix: &str) -> Option<&'a FlatUsage> {
    row.usage
        .as_ref()?
        .flat
        .iter()
        .find(|u| under(&u.prefix, prefix))
}

/// A reported refusal applies to the latest request only once the registry acknowledges it.
fn applied(row: &RegistryRow) -> bool {
    row.desired.as_ref().is_none_or(|d| {
        row.report
            .as_ref()
            .and_then(|r| r.applied)
            .is_some_and(|a| a >= d.generation)
    })
}

/// Whether the last report refused this exact prefix.
fn refused(row: &RegistryRow, prefix: &str) -> bool {
    row.report
        .as_ref()
        .is_some_and(|r| r.flat_refused.iter().any(|p| p == prefix))
}

/// An editable cap, using an exact binary unit such as `50G` or a byte count.
fn cap_text(n: u64) -> String {
    for (shift, unit) in [(40, 'T'), (30, 'G'), (20, 'M'), (10, 'K')] {
        if n >= 1 << shift && n.is_multiple_of(1 << shift) {
            return format!("{}{unit}", n >> shift);
        }
    }
    n.to_string()
}

/// Show the area's flat store and any other areas sharing its binding.
/// Operators also get the applicable bind, resize or unbind form.
pub(super) fn flat_cell(
    h: &mut Html,
    v: &RegistryView,
    ns: &NamespaceRow,
    namespaces: &[NamespaceRow],
    operator: Option<&Auth>,
) {
    let flat = Flat::of(ns, &v.row);
    let counted = |h: &mut Html, prefix: &str| {
        if let Some(u) = usage(&v.row, prefix).filter(|u| u.prefix == prefix) {
            h.raw("<div class=\"sub\">")
                .text(format!(
                    "{} used of {}, {} object{}",
                    pages::bytes(u.bytes),
                    pages::bytes(u.cap),
                    u.objects,
                    if u.objects == 1 { "" } else { "s" }
                ))
                .raw("</div>");
        }
    };
    match &flat {
        Flat::NoPrefix => {
            h.raw("<span class=\"sub\">none: its path has no fixed prefix to bind</span>");
        }
        Flat::Bound(s) => {
            h.raw("<code>files/")
                .text(&s.prefix)
                .raw("</code><div class=\"sub\">");
            h.text(format!(
                "cap {}, evicting to {}%{}",
                pages::bytes(s.cap),
                s.evict_to_percent.unwrap_or(90),
                if s.durable == Some(true) {
                    ", durable"
                } else {
                    ""
                }
            ))
            .raw("</div>");
            counted(h, &s.prefix);
            let shared: Vec<&str> = namespaces
                .iter()
                .filter(|o| {
                    o.name != ns.name && o.static_prefix().is_some_and(|p| under(&s.prefix, &p))
                })
                .map(|o| o.name.as_str())
                .collect();
            if !shared.is_empty() {
                h.raw("<div class=\"sub\">shared with ")
                    .text(shared.join(", "))
                    .raw("</div>");
            }
        }
        Flat::Within(s) => {
            h.raw("within <code>files/")
                .text(&s.prefix)
                .raw("</code>'s");
            counted(h, &s.prefix);
        }
        Flat::Below(below) => {
            let names: Vec<String> = below.iter().map(|p| format!("files/{p}")).collect();
            h.raw("<span class=\"sub\">none of its own: ")
                .node(&names.join(", "))
                .raw(", below it, ")
                .raw(if below.len() == 1 {
                    "has one"
                } else {
                    "have some"
                })
                .raw("</span>");
        }
        Flat::Reported(u) => {
            h.raw("<code>files/")
                .node(&u.prefix)
                .raw("</code><div class=\"sub\">last reported here. A store kept by the registry, ")
                .raw("not the hub, may come from local <code>[[flat]]</code> or an earlier ")
                .raw("binding.</div>");
            counted(h, &u.prefix);
        }
        Flat::Unbound => {
            h.raw("<span class=\"sub\">none</span>");
        }
    }
    let bound = match &flat {
        Flat::Bound(s) | Flat::Within(s) => Some(s.prefix.as_str()),
        _ => None,
    };
    if bound.is_some() && !applied(&v.row) {
        h.raw("<div><span class=\"badge busy\">Not applied yet</span></div>");
    } else if let Some(prefix) = bound
        && refused(&v.row, prefix)
    {
        h.raw("<div><span class=\"badge warn\">Refused</span></div><div class=\"sub\">")
            .raw("Check for an overlapping local <code>[[flat]]</code> binding, missing ")
            .raw("<code>flat</code> in <code>[hub] allow</code>, an invalid binding list, or a ")
            .raw("store that failed to open.")
            .raw("</div>");
    }
    let Some(auth) = operator else {
        return;
    };
    let form = |h: &mut Html, op: &str| {
        h.raw("<form class=\"act\" method=\"post\" action=\"")
            .raw(DETAIL_PREFIX)
            .text(&v.id)
            .raw("/action\">");
        pages::csrf_field(h, auth);
        h.raw("<input type=\"hidden\" name=\"op\" value=\"")
            .text(op)
            .raw("\">");
        hidden(h, "area", &ns.name);
        hidden(h, "revision", &ns.revision());
        hidden(h, "back", "access");
    };
    match &flat {
        Flat::Bound(s) => {
            // Unbinding needs neither current registry support nor allowlist permission.
            if v.row.takes_flat() {
                form(h, "flat-resize");
                h.raw("<label>cap <input name=\"cap\" size=\"6\" required value=\"")
                    .text(cap_text(s.cap))
                    .raw("\"></label><button>Resize</button></form>");
            }
            form(h, "flat-remove");
            h.raw("<button>Unbind</button></form>");
        }
        Flat::Unbound
            if !ns
                .static_prefix()
                .is_some_and(|p| vk_hub_proto::registry::valid_flat_prefix(&p)) =>
        {
            h.raw("<div class=\"sub\">A flat-store prefix allows up to 14 components and 255 ")
                .raw("bytes including files/. Its first component cannot be sha256.</div>");
        }
        Flat::Unbound if v.row.takes_flat() => {
            form(h, "flat-set");
            h.raw("<label>cap <input name=\"cap\" size=\"6\" placeholder=\"50G\" required>")
                .raw("</label><button>Bind a flat store</button></form>");
        }
        Flat::Unbound => {
            h.raw("<div class=\"sub\">To bind a store here, the registry must advertise ")
                .raw("flat-store support and list ")
                .raw("<code>flat</code> in its <code>[hub] allow</code>.</div>");
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A requested or reported store below the area's fixed prefix prevents a binding there.
    #[test]
    fn an_area_falls_in_the_store_of_its_prefix() {
        use vk_hub_proto::registry::{DesiredState, Usage};
        let ns = |path: &str| NamespaceRow {
            name: "a".into(),
            path: path.into(),
            retention_days: None,
            alias: None,
            isolate: Vec::new(),
            grants: Vec::new(),
            node_grants: Vec::new(),
            created_at: 0,
            created_by: "u".into(),
        };
        let setting = |prefix: &str| FlatSetting {
            prefix: prefix.into(),
            cap: 1,
            evict_to_percent: None,
            durable: None,
        };
        let counted = |prefix: &str| FlatUsage {
            prefix: prefix.into(),
            ..FlatUsage::default()
        };
        let row = RegistryRow {
            desired: Some(DesiredState {
                flat: Some(vec![setting("cc"), setting("tools/x")]),
                ..DesiredState::default()
            }),
            usage: Some(Usage {
                flat: vec![counted("own"), counted("mixed/local")],
                ..Usage::default()
            }),
            ..RegistryRow::default()
        };
        let bound = setting("cc");
        assert_eq!(Flat::of(&ns("{gitlab}/x"), &row), Flat::NoPrefix);
        assert_eq!(Flat::of(&ns("cc/{gitlab}"), &row), Flat::Bound(&bound));
        assert_eq!(
            Flat::of(&ns("cc/deep/{gitlab}"), &row),
            Flat::Within(&bound)
        );
        assert_eq!(Flat::of(&ns("ccache/{gitlab}"), &row), Flat::Unbound);
        assert_eq!(
            Flat::of(&ns("tools/{gitlab}"), &row),
            Flat::Below(vec!["tools/x"])
        );
        assert_eq!(
            Flat::of(&ns("mixed/{gitlab}"), &row),
            Flat::Below(vec!["mixed/local"])
        );
        assert_eq!(
            Flat::of(&ns("own/{gitlab}"), &row),
            Flat::Reported(&counted("own"))
        );
    }

    #[test]
    fn a_draft_reads_back_as_the_area_it_came_from() {
        let (grants, node_grants) =
            crate::store::parse_grants(&["rw:own project", "r:nodes"]).unwrap();
        let ns = NamespaceRow {
            name: "cache".into(),
            path: "cache/{gitlab}/{project_id}/{scope}".into(),
            retention_days: Some(7),
            alias: Some("cache".into()),
            isolate: vec!["main".into(), "release/*".into()],
            grants,
            node_grants: Vec::new(),
            created_at: 1,
            created_by: "u".into(),
        };
        let d = Draft::of_row(&ns);
        assert_eq!(d.grants, "rw:own project");
        assert_eq!(d.row("u", 1), Ok(ns.clone()));
        // This 512-byte subject fits exactly. Its CLI spelling exceeds the limit.
        // The edit form must preserve the rule.
        let longest = format!(
            "rw:gitlab gl,project {},ref {},protected",
            "a".repeat(255),
            "b".repeat(224)
        );
        assert_eq!(longest.len(), "rw:".len() + 512);
        let (grants, _) = crate::store::parse_grants(&[&longest]).unwrap();
        assert!(grants[0].to_string().len() > longest.len());
        let wide = NamespaceRow {
            path: "cache/{gitlab}".into(),
            isolate: Vec::new(),
            grants,
            ..ns.clone()
        };
        assert_eq!(Draft::of_row(&wide).row("u", 1), Ok(wide));
        // Node grants require a literal path in both the form and the CLI.
        let d = Draft {
            grants: "rw:own project\n\n  r:nodes \n".into(),
            ..d
        };
        assert!(d.row("u", 1).unwrap_err().contains("without placeholders"));
        let literal = Draft {
            path: "images".into(),
            isolate: String::new(),
            grants: " r:nodes\n".into(),
            ..Draft::blank()
        };
        let row = Draft {
            name: "images".into(),
            ..literal
        }
        .row("u", 1)
        .unwrap();
        assert_eq!(row.node_grants, node_grants);
        for (bad, why) in [
            (
                Draft {
                    retention_days: "a week".into(),
                    ..Draft::of_row(&ns)
                },
                "whole number",
            ),
            (
                Draft {
                    grants: "rx:*".into(),
                    ..Draft::of_row(&ns)
                },
                "rights are some of",
            ),
            (
                Draft {
                    path: "{gitlab}/x".into(),
                    grants: "r:*".into(),
                    isolate: String::new(),
                    ..Draft::of_row(&ns)
                },
                "starts with a fixed component",
            ),
        ] {
            let got = bad.row("u", 1).unwrap_err();
            assert!(got.contains(why), "{got}");
        }
    }
}
