//! The registries the hub manages: `/registries`, each one's page at `/registry/<id>`, and an
//! operator's steering of one, posted to `/registry/<id>/action`. The registry keeps its own
//! UI; these pages show what it reports and what the hub asks of it. `/operations` lists their
//! versions and updates ([`updates_section`]); an update, from there or a registry's page, is
//! asked again first ([`actions::ask_first`]).

use anyhow::Result;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use vk_hub_proto::Outcome;
use vk_hub_proto::registry::GcPolicy;

use super::fleet::FleetSite;
use super::html::Html;
use super::pages::{self, end_section, header_cells, kv, kv_node, section};
use super::{Auth, Body, Ui, actions, blocking, field, message, page};
use crate::egress::blocked::Instances;
use crate::registries::{self as ops, RegistryView};
use crate::store::{
    NamespaceRow, NotEnrolled, Program, RegistryCommandRow, RegistryRow, Release, Role, TokenKeyRow,
};
use vk_hub_proto::registry::Operation;

/// The registries' list.
pub(super) const PATH: &str = "/registries";

/// A registry's page: this, then its ID.
pub(super) const DETAIL_PREFIX: &str = "/registry/";

/// The registry an action path `/registry/<id>/action` is for.
pub(super) fn action_target(path: &str) -> Option<&str> {
    path.strip_prefix(DETAIL_PREFIX)?
        .strip_suffix("/action")
        .filter(|id| vk_hub_proto::valid_id(id))
}

/// The registry a page path `/registry/<id>` shows.
pub(super) fn detail_target(path: &str) -> Option<&str> {
    path.strip_prefix(DETAIL_PREFIX)
        .filter(|id| vk_hub_proto::valid_id(id))
}

/// A registry's job access, as its row and its page say it.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum JobAccess {
    /// It does not take the hub's tokens (`[hub] tokens`).
    Off,
    /// It takes tokens, but jobs cannot get one yet: why.
    SetupNeeded(&'static str),
    /// A newer signing key is out; the one it applied still signs.
    Updating,
    /// Jobs get tokens; it has this many storage areas.
    Configured(usize),
}

impl JobAccess {
    /// Job access for `row`, with signing `keys` oldest first and `areas` storage areas.
    pub(super) fn of(row: &RegistryRow, keys: &[TokenKeyRow], areas: usize) -> Self {
        if !row.takes_tokens() {
            return JobAccess::Off;
        }
        if row.url.is_none() {
            return JobAccess::SetupNeeded("no address bound: nodes cannot name it");
        }
        let Some(signing) = crate::tokens::signing_key(keys, row) else {
            return JobAccess::SetupNeeded("it has applied no signing key yet");
        };
        if keys
            .last()
            .is_some_and(|k| k.public.kid != signing.public.kid)
        {
            return JobAccess::Updating;
        }
        JobAccess::Configured(areas)
    }

    fn render(&self, h: &mut Html) {
        match self {
            JobAccess::Off => {
                h.raw("<span class=\"sub\">off</span>");
            }
            JobAccess::SetupNeeded(why) => {
                h.raw("<span class=\"badge warn\">Setup needed</span><div class=\"sub\">")
                    .text(why)
                    .raw("</div>");
            }
            JobAccess::Updating => {
                h.raw("<span class=\"badge busy\">Updating signing keys</span>")
                    .raw("<div class=\"sub\">the current key still works</div>");
            }
            JobAccess::Configured(n) => {
                h.raw("<span class=\"badge ok\">Configured</span><div class=\"sub\">")
                    .text(format!(
                        "{n} storage area{}",
                        if *n == 1 { "" } else { "s" }
                    ))
                    .raw("</div>");
            }
        }
    }
}

/// `/registries`: each registry's name and address, version, whether it is connected,
/// whether jobs get access to it, and its free storage. Mode and ID are on its page.
pub(super) async fn list(auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    let hub = ui.hub.clone();
    let (views, access) = blocking(move || {
        let views = ops::views(&hub)?;
        let keys = hub.db.token_keys()?;
        let mut access = Vec::with_capacity(views.len());
        for v in &views {
            access.push(JobAccess::of(
                &v.row,
                &keys,
                hub.db.namespaces(&v.id)?.len(),
            ));
        }
        Ok::<_, anyhow::Error>((views, access))
    })
    .await?;
    let now = crate::now_secs();
    let mut main = Html::new();
    main.raw("<h1>Storage</h1>");
    if views.is_empty() {
        main.raw("<p class=\"empty\">No registry has enrolled yet: an operator issues a ")
            .raw("registry token below, or with <code>vk-hub token create --kind registry</code>, ")
            .raw("for <code>vk-registry join</code> on the registry's host.</p>");
    } else {
        main.raw("<table class=\"grid\"><thead><tr>");
        header_cells(
            &mut main,
            &[
                "REGISTRY",
                "VERSION",
                "CONNECTION",
                "JOB ACCESS",
                "FREE STORAGE",
            ],
        );
        main.raw("</tr></thead><tbody>");
        for (r, access) in views.iter().zip(&access) {
            main.raw("<tr class=\"")
                .raw(if r.connected { "up" } else { "down" })
                .raw("\"><td><a href=\"")
                .raw(DETAIL_PREFIX)
                .text(&r.id)
                .raw("\">")
                .node(&r.row.hostname)
                .raw("</a><div class=\"sub\">");
            match &r.row.url {
                Some(url) => main.text(url),
                None => main.raw("no address"),
            };
            main.raw("</div></td><td>");
            match r.row.inventory.as_ref().map(|i| i.version.trim()) {
                Some(v) if !v.is_empty() => main.node(v),
                _ => main.raw("-"),
            };
            main.raw("</td><td>");
            if r.connected {
                main.raw("<span class=\"badge ok\">Online</span>");
            } else {
                main.raw("<span class=\"badge bad\">Offline</span><div class=\"sub\">");
                match r.row.last_seen {
                    Some(t) => {
                        main.raw("last seen ");
                        pages::time(&mut main, t, &super::fleet::age(now, t));
                    }
                    None => {
                        main.raw("never seen");
                    }
                }
                main.raw("</div>");
            }
            main.raw("</td><td>");
            access.render(&mut main);
            main.raw("</td><td>");
            main.text(ops::free(r));
            main.raw("</td></tr>");
        }
        main.raw("</tbody></table>");
        for r in &views {
            for note in ops::notes(r) {
                main.raw("<p class=\"sub\">").node(&note).raw("</p>");
            }
        }
    }
    if auth.session.role >= Role::Operator {
        main.raw("<section><h2>Enroll a registry</h2><form method=\"post\" action=\"")
            .raw(super::fleet::TOKEN_PATH)
            .raw("\">");
        pages::csrf_field(&mut main, auth);
        main.raw("<input type=\"hidden\" name=\"kind\" value=\"registry\">")
            .raw("<input type=\"hidden\" name=\"ttl\" value=\"3600\">")
            .raw("<button class=\"primary\">Issue a registry token, valid an hour</button>")
            .raw("</form><p class=\"sub\">Single-use: the registry redeems it with ")
            .raw("<code>vk-registry join</code>. Its database, keys and UI are left as they ")
            .raw("are, and it serves as before whether the hub is reachable or not.</p>")
            .raw("</section>");
    }
    Ok(page(super::fleet::layout("Storage", PATH, auth, &main)))
}

/// A registry page's views: `/registry/<id>`, `?tab=access` and `?tab=settings`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    /// What it reports, what the hub asks of it, its usage and commands.
    Overview,
    /// Its storage areas: who may read, publish and coordinate builds there.
    Access,
    /// Its address and signing keys.
    Settings,
}

impl Tab {
    const ALL: [(Tab, &'static str, &'static str); 3] = [
        (Tab::Overview, "", "Overview"),
        (Tab::Access, "?tab=access", "Job access"),
        (Tab::Settings, "?tab=settings", "Settings"),
    ];

    fn of(query: Option<&str>) -> Self {
        let form = super::decode_form(query.unwrap_or("").as_bytes());
        match field(&form, "tab") {
            Some("access") => Tab::Access,
            Some("settings") => Tab::Settings,
            _ => Tab::Overview,
        }
    }
}

/// `/registry/<id>[?tab=…]`.
pub(super) async fn detail(
    id: &str,
    query: Option<&str>,
    auth: &Auth,
    ui: &Ui,
) -> Result<Response<Body>> {
    let tab = Tab::of(query);
    let hub = ui.hub.clone();
    let wanted = id.to_string();
    let Some((view, commands, namespaces, keys, instances, releases)) = blocking(move || {
        let Some((view, commands)) = ops::detail(&hub, &wanted)? else {
            return Ok(None);
        };
        let namespaces = hub.db.namespaces(&wanted)?;
        let keys = hub.db.token_keys()?;
        let instances = hub.db.gitlab_instances()?;
        let releases = hub.db.releases()?;
        Ok::<_, anyhow::Error>(Some((
            view, commands, namespaces, keys, instances, releases,
        )))
    })
    .await?
    else {
        return Ok(message(StatusCode::NOT_FOUND, "There is no such registry."));
    };
    let now = crate::now_secs();
    let mut main = Html::new();
    main.raw("<h1>").node(&view.row.hostname).raw("</h1>");
    main.raw("<nav class=\"tabs\" aria-label=\"Registry views\">");
    for (t, suffix, label) in Tab::ALL {
        main.raw("<a href=\"")
            .raw(DETAIL_PREFIX)
            .text(&view.id)
            .raw(suffix)
            .raw("\"")
            .raw(if t == tab {
                " aria-current=\"page\""
            } else {
                ""
            })
            .raw(">")
            .raw(label)
            .raw("</a>");
    }
    main.raw("</nav>");
    match tab {
        Tab::Overview => {
            status(&mut main, &view, now);
            steering(&mut main, &view, &releases, auth);
            usage(&mut main, &view);
            commands_table(&mut main, &view, &commands, now);
        }
        Tab::Access => access(&mut main, &view, &namespaces, instances.as_deref()),
        Tab::Settings => settings(&mut main, &view, &keys, now),
    }
    let here = format!("{DETAIL_PREFIX}{id}");
    Ok(page(super::fleet::layout(
        &view.row.hostname,
        &here,
        auth,
        &main,
    )))
}

/// The Job access tab: the registry's storage areas, those the hub keeps for CI folded away,
/// and what keeps jobs from getting access, when something does; access rules name their GitLab
/// instance by the hub's `instances` ([`super::access::who`]).
fn access(h: &mut Html, v: &RegistryView, namespaces: &[NamespaceRow], instances: Instances<&str>) {
    if !v.row.takes_tokens() {
        h.raw("<p class=\"callout\">Jobs get no access here: the registry does not take the ")
            .raw("hub's tokens. <code>[hub] tokens = true</code> in its config turns it on.</p>");
    }
    let cleanup = namespaces.iter().any(|n| n.retention_days.is_some());
    // Only a registry that reported its inventory says what its `[hub] allow` lists.
    let lacks_gc = v.row.inventory.as_ref().is_some_and(|i| {
        !i.allow
            .iter()
            .any(|a| a == vk_hub_proto::registry::ALLOW_GC)
    });
    let refused = v.row.report.as_ref().is_some_and(|r| {
        r.refused
            .iter()
            .any(|f| f == vk_hub_proto::registry::REFUSED_PREFIX_RETENTION)
    });
    if cleanup && lacks_gc {
        h.raw("<p class=\"callout warn\"><strong>Cleanup after inactivity is not applied:")
            .raw(
                "</strong> the registry's <code>[hub] allow</code> does not list <code>gc</code>, ",
            )
            .raw("so it keeps its own windows. List it there, or set <code>[[gc.prefix]]</code> ")
            .raw("in its config.</p>");
    } else if refused {
        h.raw("<p class=\"callout warn\"><strong>Cleanup after inactivity is not applied:")
            .raw("</strong> the registry refused a cleanup window (shorter than its floor, or ")
            .raw("invalid). A shorter one needs <code>[[gc.prefix]]</code> in its own config.</p>");
    }
    let areas: Vec<_> = namespaces
        .iter()
        .map(|ns| super::access::area(ns, instances))
        .collect();
    let (managed, own): (Vec<_>, Vec<_>) = areas.iter().partition(|a| a.managed);
    h.raw("<section><h2>Storage areas</h2><p class=\"sub\">Each is a part of the registry. ")
        .raw("Jobs get access only where an access rule allows it.</p>");
    if own.is_empty() {
        h.raw("<p class=\"empty\">None besides the ones kept for CI. ")
            .raw("<code>vk-hub namespaces add</code> declares one.</p>");
    } else {
        areas_table(h, &own);
    }
    if !managed.is_empty() {
        h.raw("<details class=\"fold\"><summary>Managed by CI <span class=\"sub\">· caches and ")
            .raw("per-pipeline storage</span></summary>");
        areas_table(h, &managed);
        h.raw("</details>");
    }
    h.raw("</section><p><a href=\"/audit?category=all&amp;node=")
        .text(&v.id)
        .raw("\">Access history in the audit log</a></p>");
}

fn areas_table(h: &mut Html, areas: &[&super::access::Area]) {
    h.raw("<table class=\"grid\"><thead><tr>");
    header_cells(h, &["AREA", "WHO CAN READ", "WHO CAN PUBLISH"]);
    h.raw("</tr></thead><tbody>");
    for a in areas {
        h.raw("<tr><td><strong>")
            .text(&a.label)
            .raw("</strong><div class=\"sub\"><code>")
            .text(&a.path)
            .raw("</code></div></td><td>");
        lines(h, &a.readers);
        h.raw("</td><td>");
        lines(h, &a.publishers);
        h.raw("</td></tr>");
    }
    h.raw("</tbody></table>");
}

fn lines(h: &mut Html, lines: &[String]) {
    if lines.is_empty() {
        h.raw("<span class=\"sub\">nobody</span>");
    }
    for (i, l) in lines.iter().enumerate() {
        if i > 0 {
            h.raw("<br>");
        }
        h.text(l);
    }
}

/// The Settings tab: the address the registry is bound to, and the signing keys it holds.
fn settings(h: &mut Html, v: &RegistryView, keys: &[TokenKeyRow], now: u64) {
    section(h, "Address");
    match &v.row.url {
        Some(url) => kv(h, "Bound to", url),
        None => kv(
            h,
            "Bound to",
            "none: nodes cannot name it, so their jobs get no access",
        ),
    }
    end_section(h);
    h.raw("<section><h2>Signing keys</h2>");
    if !v.row.takes_tokens() {
        h.raw("<p class=\"empty\">The registry does not take the hub's tokens.</p></section>");
        return;
    }
    let applied = v.row.applied();
    let signing = crate::tokens::signing_key(keys, &v.row);
    h.raw("<table class=\"grid\"><thead><tr>");
    header_cells(h, &["KEY", "STATE HERE"]);
    h.raw("</tr></thead><tbody>");
    for k in keys.iter().rev() {
        let Some(first) = v.row.key_generations.get(&k.public.kid) else {
            continue;
        };
        h.raw("<tr><td><code>")
            .text(k.public.kid.get(..12).unwrap_or(&k.public.kid))
            .raw("</code></td><td>");
        if signing.is_some_and(|s| s.public.kid == k.public.kid) {
            h.raw("<span class=\"badge ok\">Signs its tokens</span>");
        } else if *first > applied {
            h.raw("<span class=\"badge busy\">Sent, not applied yet</span>");
        } else if let Some(at) = k.superseded_at {
            h.raw("Replaced ");
            pages::time(h, at, &super::fleet::age(now, at));
            h.raw("; kept while tokens it signed may be live");
        } else {
            h.raw("Applied");
        }
        h.raw("</td></tr>");
    }
    h.raw("</tbody></table><p class=\"sub\">")
        .text(format!("Applied generation {applied}"))
        .raw(". <code>vk-hub token-keys rotate</code> replaces the signing key.</p></section>");
}

fn status(h: &mut Html, v: &RegistryView, now: u64) {
    h.raw("<p class=\"sub\"><code>")
        .text(&v.id)
        .raw("</code> · ")
        .raw(if v.connected {
            "connected"
        } else {
            "unreachable"
        })
        .raw(" · last seen ");
    match v.row.last_seen {
        Some(t) => {
            pages::time(h, t, &super::fleet::age(now, t));
        }
        None => {
            h.raw("never");
        }
    }
    h.raw("</p>");
    section(h, "Registry");
    match &v.row.inventory {
        None => kv(h, "Inventory", "not reported yet"),
        Some(i) => {
            kv_node(h, "Version", &i.version);
            kv_node(h, "Mode", &i.mode);
            kv_node(
                h,
                "Listens on",
                &format!("{}{}", i.listen, if i.tls { " (TLS)" } else { "" }),
            );
            kv_node(h, "Store", &i.store);
            let size = pages::bytes(i.store_size_bytes);
            kv(
                h,
                "Store size",
                &match &v.row.heartbeat {
                    Some(hb) => format!("{} free of {size}", pages::bytes(hb.store_free_bytes)),
                    None => size,
                },
            );
            kv(h, "WebDAV", if i.webdav { "on" } else { "off" });
            kv_node(
                h,
                "The hub may",
                &if i.allow.is_empty() {
                    "only watch ([hub] allow is empty)".to_string()
                } else {
                    i.allow.join(", ")
                },
            );
            kv(
                h,
                "Updates",
                if i.requires_signed {
                    "signed by one of its own keys only"
                } else {
                    "unsigned accepted"
                },
            );
            kv_node(h, "Config hash", &i.config_hash);
        }
    }
    if let Some(hb) = &v.row.heartbeat {
        kv(
            h,
            "Connections",
            &format!("{} of {}", hb.connections, hb.max_connections),
        );
        kv(h, "Uploads in progress", &hb.uploads.to_string());
        kv(h, "Locks held", &hb.locks.to_string());
    }
    end_section(h);
}

fn steering(h: &mut Html, v: &RegistryView, releases: &[Release], auth: &Auth) {
    let report = v.row.report.as_ref();
    let desired = v.row.desired.as_ref();
    section(h, "Steering");
    kv(
        h,
        "Writes",
        match report {
            Some(r) if r.read_only => "refused: read-only",
            Some(_) => "taken",
            None => "not reported yet",
        },
    );
    kv(
        h,
        "The hub asks",
        &match desired.and_then(|d| d.read_only) {
            Some(true) => "read-only".to_string(),
            Some(false) => "writable".to_string(),
            None => "nothing: as its config has it".to_string(),
        },
    );
    kv(
        h,
        "Scheduled gc",
        &match report.and_then(|r| r.gc) {
            Some(gc) => policy_text(gc),
            None => "none".to_string(),
        },
    );
    if let Some(gc) = report.and_then(|r| r.last_gc.as_ref()) {
        let mut text = match &gc.error {
            Some(e) => format!("failed: {e}"),
            None => format!(
                "{}{} tags, {} manifests and {} blobs dropped, {} freed",
                if gc.dry_run { "dry run: " } else { "" },
                gc.tags_dropped,
                gc.manifests_dropped,
                gc.blobs_dropped,
                pages::bytes(gc.bytes_freed)
            ),
        };
        match &gc.command {
            Some(c) => text.push_str(&format!(" (at {}, command {c})", crate::utc(gc.at))),
            None => text.push_str(&format!(" (at {}, scheduled)", crate::utc(gc.at))),
        }
        if gc.blobs_leased > 0 {
            text.push_str(&format!(
                "; {} blobs kept, read by running builds",
                gc.blobs_leased
            ));
        }
        kv_node(h, "Last gc", &text);
    }
    if let Some(u) = report.and_then(|r| r.update.as_ref()) {
        let mut text = format!("{} {}", u.version, crate::store::update_phase_name(u.phase));
        if let Some(m) = &u.message {
            text.push_str(&format!(": {m}"));
        }
        kv_node(h, "Update", &text);
    }
    if let Some(r) = report
        && !r.refused.is_empty()
    {
        kv_node(h, "Not allowed by its config", &r.refused.join(", "));
    }
    if let Some(d) = desired {
        let applied = report.and_then(|r| r.applied);
        kv(
            h,
            "Generation",
            &format!(
                "{} asked, {} applied",
                d.generation,
                applied.map_or("none".to_string(), |a| a.to_string())
            ),
        );
    }
    end_section(h);
    if auth.session.role < Role::Operator {
        return;
    }
    let path = format!("{DETAIL_PREFIX}{}/action", v.id);
    let form = |h: &mut Html, op: &str, label: &str, extra: &Html| {
        h.raw("<form class=\"act\" method=\"post\" action=\"")
            .text(&path)
            .raw("\">");
        pages::csrf_field(h, auth);
        h.raw("<input type=\"hidden\" name=\"op\" value=\"")
            .text(op)
            .raw("\">")
            .html(extra)
            .raw("<button>")
            .text(label)
            .raw("</button></form>");
    };
    let none = Html::new();
    h.raw("<section class=\"steer\"><h2>Actions</h2><div class=\"groups\"><div class=\"group\">")
        .raw("<h3>Writes</h3>");
    form(h, "read-only", "Make read-only", &none);
    form(h, "writable", "Make writable", &none);
    form(h, "read-only-default", "As its config has it", &none);
    h.raw("</div><div class=\"group\"><h3>Garbage collection</h3>");
    let mut windows = Html::new();
    windows
        .raw("<label>retention <input type=\"number\" name=\"retention_days\" min=\"1\" value=\"")
        .text(ops::GC_RETENTION_DAYS)
        .raw("\"> days</label><label>grace <input type=\"number\" name=\"grace_days\" ")
        .raw("min=\"1\" value=\"")
        .text(ops::GC_GRACE_DAYS)
        .raw("\"> days</label>");
    let mut schedule = Html::new();
    schedule
        .raw("<label>every <input type=\"number\" name=\"every_hours\" min=\"1\" value=\"24\">")
        .raw(" hours</label>")
        .html(&windows);
    form(h, "gc-schedule", "Schedule gc", &schedule);
    form(h, "gc-off", "Stop scheduled gc", &none);
    let mut now = Html::new();
    now.html(&windows)
        .raw("<label><input type=\"checkbox\" name=\"dry_run\" value=\"1\"> dry run</label>");
    form(h, "gc-now", "Run gc now", &now);
    h.raw("</div><div class=\"group\"><h3>Update</h3>");
    update_form(h, v, releases, Some(&auth.csrf));
    h.raw(
        "</div></div><p class=\"sub\">The registry applies only what its <code>[hub] allow</code> ",
    )
    .raw(
        "lists. <a href=\"/operations\">Updates</a> lists every registry's version.</p></section>",
    );
}

/// A registry as `/operations` shows it: with the last update the hub issued it.
pub(super) struct Updatable {
    view: RegistryView,
    last: Option<RegistryCommandRow>,
}

/// Every registry, with its last update command.
pub(super) fn updatables(hub: &crate::server::Hub) -> Result<Vec<Updatable>> {
    ops::views(hub)?
        .into_iter()
        .map(|view| {
            let last = hub
                .db
                .registry_commands(&view.id)?
                .into_iter()
                .filter(|c| matches!(c.command.op, Operation::Update { .. }))
                .max_by_key(|c| c.seq);
            Ok(Updatable { view, last })
        })
        .collect()
}

/// `/operations`' section of registries, in its live fragment: each one's version, whether it
/// lets the hub update it, and its update. With `steer`, the form updating each that does.
/// Nothing when no registry has enrolled.
pub(super) fn updates_section(
    h: &mut Html,
    registries: &[Updatable],
    releases: &[Release],
    steer: bool,
    now: u64,
) {
    if registries.is_empty() {
        return;
    }
    h.raw("<section><h2>Registries</h2><table class=\"grid\"><thead><tr>");
    let mut headers = vec![
        "REGISTRY",
        "VERSION",
        "CONNECTION",
        "UPDATES",
        "LAST UPDATE",
    ];
    if steer {
        headers.push("UPDATE TO");
    }
    header_cells(h, &headers);
    h.raw("</tr></thead><tbody>");
    for r in registries {
        let v = &r.view;
        h.raw("<tr><td><a href=\"")
            .raw(DETAIL_PREFIX)
            .text(&v.id)
            .raw("\">")
            .node(&v.row.hostname)
            .raw("</a></td><td>");
        match &v.row.inventory {
            Some(i) => h.node(&i.version),
            None => h.raw("-"),
        };
        h.raw("</td><td>").raw(if v.connected {
            "<span class=\"badge ok\">Online</span>"
        } else {
            "<span class=\"badge bad\">Offline</span>"
        });
        h.raw("</td><td>").raw(policy(&v.row)).raw("</td><td>");
        update_status(h, &v.row, r.last.as_ref(), now);
        h.raw("</td>");
        if steer {
            h.raw("<td>");
            update_form(h, v, releases, None);
            h.raw("</td>");
        }
        h.raw("</tr>");
    }
    h.raw("</tbody></table><p class=\"sub\">A registry downloads the release from the hub and ")
        .raw("restarts on it, dropping its open connections. One that does not come up is ")
        .raw("rolled back to the binary it ran once the registry's supervisor restarts it.</p>")
        .raw("</section>");
}

/// Whether registry `row` lets the hub update it, and to what.
fn policy(row: &RegistryRow) -> &'static str {
    match (ops::takes_updates(row), &row.inventory) {
        (None, _) | (_, None) => "not reported yet",
        (Some(false), _) => "not allowed by its <code>[hub] allow</code>",
        (Some(true), Some(i)) if i.requires_signed => "signed releases only",
        (Some(true), Some(_)) => "unsigned accepted",
    }
}

/// Registry `row`'s update: under way or how it ended, as it reports it, or the last command
/// issued while it has not taken it, or once it refused or failed it.
fn update_status(h: &mut Html, row: &RegistryRow, last: Option<&RegistryCommandRow>, now: u64) {
    // What the registry reports of the last command, once it took it; of an earlier one only
    // when the hub keeps no command.
    let reported = row
        .report
        .as_ref()
        .and_then(|r| r.update.as_ref())
        .filter(|u| {
            last.is_none_or(|c| {
                u.command == c.command.id
                    && matches!(c.outcome, Some(Outcome::Accepted | Outcome::Done))
            })
        });
    match (reported, last) {
        (Some(u), _) => {
            h.node(&u.version)
                .raw(" ")
                .text(crate::store::update_phase_name(u.phase));
            if let Some(m) = &u.message {
                h.raw(": ").node(m);
            }
        }
        (None, Some(c)) => command_line(h, c, now),
        (None, None) => {
            h.raw("-");
        }
    }
}

/// Update command `c`: the version it names, and whether the registry took it.
fn command_line(h: &mut Html, c: &RegistryCommandRow, now: u64) {
    if let Operation::Update { version, .. } = &c.command.op {
        h.raw("to ").node(version).raw(": ");
    }
    match &c.outcome {
        None if c.command.expires_at <= now => h.raw("expired, never taken"),
        None => h.raw("not taken yet"),
        Some(Outcome::Accepted) => h.raw("under way"),
        Some(Outcome::Done) => h.raw("done"),
        Some(Outcome::Failed { message }) => h
            .raw("<span class=\"reason\">failed</span>: ")
            .node(message),
        Some(Outcome::Refused { reason }) => h
            .raw("<span class=\"reason\">refused</span>: ")
            .node(reason),
        Some(Outcome::Expired) => h.raw("expired"),
    };
    h.raw(", issued ").html(&pages::at_html(c.issued_at));
}

/// The form updating registry `v` to one of `releases`' `vk-registry` ones, or why there is
/// none. On a registry's page, a plain form carrying `csrf`; in `/operations`' shared fragment,
/// without, posted by htmx with the page's token and kept while being filled in
/// (`hx-preserve`) until its choices change.
fn update_form(h: &mut Html, v: &RegistryView, releases: &[Release], csrf: Option<&str>) {
    if ops::takes_updates(&v.row) == Some(false) {
        h.raw("<span class=\"sub\">Its <code>[hub] allow</code> lacks <code>update</code>.</span>");
        return;
    }
    // Those it would take: signed ones only, if it says it requires them.
    let signed_only = v.row.inventory.as_ref().is_some_and(|i| i.requires_signed);
    let releases: Vec<&Release> = releases
        .iter()
        .filter(|r| r.row.is(Program::Registry) && (!signed_only || r.row.signature.is_some()))
        .collect();
    if releases.is_empty() {
        h.raw(if signed_only {
            "<span class=\"sub\">Add a signed vk-registry release first.</span>"
        } else {
            "<span class=\"sub\">Add a vk-registry release first.</span>"
        });
        return;
    }
    let path = format!("{DETAIL_PREFIX}{}/action", v.id);
    let mut form = Html::new();
    form.raw("<input type=\"hidden\" name=\"op\" value=\"update\">")
        .raw("<select name=\"release\" aria-label=\"Release\" required>");
    for r in releases {
        form.raw("<option value=\"")
            .text(&r.sha256)
            .raw("\">")
            .text(&r.row.version)
            .raw(" (")
            .text(crate::store::short(&r.sha256))
            .raw(if r.row.signature.is_some() {
                ", signed)"
            } else {
                ")"
            })
            .raw("</option>");
    }
    form.raw("</select><button>Update</button>");
    h.raw("<form class=\"act\" method=\"post\" action=\"")
        .text(&path)
        .raw("\"");
    match csrf {
        Some(csrf) => {
            h.raw(">");
            pages::csrf_input(h, csrf);
        }
        None => {
            let id = pages::preserved_id("registry-update", &format!("{}{}", v.id, form.as_str()));
            h.raw(" id=\"")
                .text(&id)
                .raw("\" hx-preserve=\"true\" hx-post=\"")
                .text(&path)
                .raw("\" hx-swap=\"none\">");
        }
    }
    h.html(&form).raw("</form>");
}

/// Why a registry running `own` would refuse to update to `candidate`, as its own check
/// decides (`check_version` in `vk-registry/src/hub/update.rs`): an older `MAJOR.MINOR.PATCH`,
/// unless its `[hub] allow_downgrade`, or another version not of that shape.
fn version_refusal(candidate: &str, own: &str) -> Option<&'static str> {
    let fields = |v: &str| -> Option<Vec<u64>> {
        let v: Vec<u64> = v
            .split('.')
            .map(|f| f.parse().ok())
            .collect::<Option<_>>()?;
        (v.len() == 3).then_some(v)
    };
    match (fields(candidate), fields(own)) {
        (Some(c), Some(o)) if c < o => Some(
            "It is older than the version the registry runs: the registry refuses it unless its \
             <code>[hub] allow_downgrade</code> is set.",
        ),
        (Some(_), Some(_)) => None,
        _ if candidate == own => None,
        _ => Some(
            "Its version cannot be ordered against the one the registry runs, not being \
             <code>MAJOR.MINOR.PATCH</code>: the registry refuses it.",
        ),
    }
}

/// What updating registry `v` to `release` would do, for its question.
fn update_detail(v: &RegistryView, release: &Release) -> Html {
    let mut h = Html::new();
    h.raw("<p>vk-registry ")
        .text(&release.row.version)
        .raw(" (<code>")
        .text(crate::store::short(&release.sha256))
        .raw("</code>")
        .raw(if release.row.signature.is_some() {
            ", signed"
        } else {
            ", unsigned"
        })
        .raw(") to ")
        .node(&v.row.hostname);
    let running = v.row.inventory.as_ref().map(|i| i.version.as_str());
    if let Some(own) = running {
        h.raw(", which runs ").node(own);
    }
    h.raw(".</p>");
    if let Some(why) = running.and_then(|own| version_refusal(&release.row.version, own)) {
        h.raw("<p class=\"reason\">").raw(why).raw("</p>");
    }
    if !v.connected {
        h.raw("<p>The registry is offline: it gets the update once it connects, within ")
            .text(crate::human_duration(ops::COMMAND_TTL))
            .raw(".</p>");
    }
    h
}

/// `op=update` of `POST /registry/<id>/action`: update the registry to the release `form`
/// names, once the operator has confirmed it, by the operation `vk-hub registries update` runs.
async fn update(
    ui: &Ui,
    site: &FleetSite,
    htmx: bool,
    auth: &Auth,
    form: &[(String, String)],
    id: &str,
) -> Result<Response<Body>> {
    let sha256 = field(form, "release").unwrap_or("").to_string();
    if !vk_hub_proto::valid_sha256(&sha256) {
        return Ok(actions::refused(
            htmx,
            StatusCode::BAD_REQUEST,
            "Refused: choose a release.",
        ));
    }
    let (hub, wanted, sha) = (ui.hub.clone(), id.to_string(), sha256.clone());
    let found = blocking(move || {
        let Some((view, _)) = ops::detail(&hub, &wanted)? else {
            return Ok(None);
        };
        let release = hub
            .db
            .release(&sha)?
            .map(|row| Release { sha256: sha, row });
        Ok::<_, anyhow::Error>(Some((view, release)))
    })
    .await?;
    let Some((view, release)) = found else {
        return Ok(actions::refused(
            htmx,
            StatusCode::NOT_FOUND,
            "There is no such registry.",
        ));
    };
    let Some(release) = release else {
        return Ok(actions::refused(
            htmx,
            StatusCode::CONFLICT,
            "Refused: the hub no longer holds that release.",
        ));
    };
    if let Err(e) = ops::check_update(&view.row, &release) {
        let said = vk_hub_proto::display_safe(&format!("{e:#}"));
        return Ok(actions::refused(
            htmx,
            StatusCode::CONFLICT,
            &format!("Refused: {said}."),
        ));
    }
    let page = format!("{DETAIL_PREFIX}{id}");
    let running = view.row.inventory.as_ref().map(|i| i.version.clone());
    let ask = actions::Ask {
        path: format!("{page}/action"),
        back: if htmx {
            "/operations".to_string()
        } else {
            page.clone()
        },
        op: "update".to_string(),
        what: "Update this registry? It restarts on the release, dropping its open \
               connections. If the release does not come up, the registry goes back to the \
               binary it ran once its supervisor restarts it.",
        detail: update_detail(&view, &release),
        asked: vec![
            ("release", release.sha256.clone()),
            ("version", release.row.version.clone()),
            (
                "signature",
                release.row.signature.clone().unwrap_or_default(),
            ),
            ("running", running.clone().unwrap_or_default()),
        ],
    };
    if let Some(asked) = actions::ask_first(
        &site.questions,
        super::fleet::layout,
        htmx,
        auth,
        form,
        &ask,
    )? {
        return Ok(asked);
    }
    let (hub, principal, registry) = (ui.hub.clone(), auth.session.principal(), id.to_string());
    let shown = release.clone();
    let issued = blocking(move || {
        Ok(ops::update_as_shown(
            &hub,
            &principal,
            &registry,
            &shown,
            running.as_deref(),
        ))
    })
    .await?;
    match issued {
        Ok(command) if htmx => Ok(super::fleet::said_so(&format!(
            "Sent {} the update to vk-registry {} (command {}); it shows below.",
            vk_hub_proto::display_safe(&view.row.hostname),
            release.row.version,
            command.id
        ))),
        Ok(_) => Ok(see_other(&page)),
        Err(e) if e.is::<NotEnrolled>() => Ok(actions::refused(
            htmx,
            StatusCode::NOT_FOUND,
            "There is no such registry.",
        )),
        Err(e) => {
            let said = vk_hub_proto::display_safe(&format!("{e:#}"));
            Ok(actions::refused(
                htmx,
                StatusCode::CONFLICT,
                &format!("Refused: {said}."),
            ))
        }
    }
}

/// A redirect to the hub's own `location`.
fn see_other(location: &str) -> Response<Body> {
    let mut resp = Response::new(Body::default());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    resp.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(location).unwrap_or(HeaderValue::from_static(PATH)),
    );
    resp
}

fn policy_text(gc: GcPolicy) -> String {
    format!(
        "every {}, retention {} days, grace {} days",
        crate::human_duration(std::time::Duration::from_secs(gc.every_secs)),
        gc.retention_days,
        gc.grace_days
    )
}

fn usage(h: &mut Html, v: &RegistryView) {
    let Some(u) = &v.row.usage else {
        return;
    };
    section(h, "Usage");
    kv(h, "Stored", &pages::bytes(u.stored_bytes));
    kv(h, "Referenced by tags", &pages::bytes(u.referenced_bytes));
    kv(
        h,
        "Contents",
        &format!(
            "{} tags, {} manifests, {} blobs",
            u.tags, u.manifests, u.blobs
        ),
    );
    kv(h, "Counted", &crate::utc(u.at));
    end_section(h);
    if u.repos.is_empty() {
        return;
    }
    h.raw("<section><h2>Largest repositories</h2><table class=\"grid\"><thead><tr>")
        .raw("<th>repository</th><th>tags</th><th>referenced</th></tr></thead><tbody>");
    for r in u.repos.iter().take(50) {
        h.raw("<tr><td>")
            .node(&r.name)
            .raw("</td><td>")
            .text(r.tags.to_string())
            .raw("</td><td>")
            .text(pages::bytes(r.bytes))
            .raw("</td></tr>");
    }
    h.raw("</tbody></table></section>");
}

fn commands_table(h: &mut Html, v: &RegistryView, commands: &[RegistryCommandRow], now: u64) {
    h.raw("<section><h2>Commands</h2>");
    if commands.is_empty() {
        h.raw("<p class=\"empty\">none</p>");
    } else {
        h.raw("<table class=\"grid\"><thead><tr><th>issued</th><th>command</th>")
            .raw("<th>outcome</th></tr></thead><tbody>");
        for c in commands.iter().rev() {
            h.raw("<tr><td>");
            pages::at(h, c.issued_at)
                .raw("</td><td>")
                .text(crate::store::registry_operation_name(&c.command.op))
                .raw("</td><td>");
            match &c.outcome {
                None if c.command.expires_at <= now => h.raw("expired, never taken"),
                None => h.raw("not taken yet"),
                Some(Outcome::Accepted) => h.raw("under way"),
                Some(Outcome::Done) => h.raw("done"),
                Some(Outcome::Failed { message }) => h.raw("failed: ").node(message),
                Some(Outcome::Refused { reason }) => h.raw("refused: ").node(reason),
                Some(Outcome::Expired) => h.raw("expired"),
            };
            h.raw("</td></tr>");
        }
        h.raw("</tbody></table>");
    }
    h.raw("<p><a href=\"/audit?node=")
        .text(&v.id)
        .raw("\">The registry's audit log</a></p></section>");
}

/// What an operator's form asks.
enum Act {
    ReadOnly(Option<bool>),
    Schedule(Option<GcPolicy>),
    GcNow {
        retention_days: u64,
        grace_days: u64,
        dry_run: bool,
    },
}

fn act(form: &[(String, String)]) -> Result<Act, &'static str> {
    let number = |name: &str| {
        field(form, name)
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|n| *n > 0)
    };
    Ok(match field(form, "op").unwrap_or("") {
        "read-only" => Act::ReadOnly(Some(true)),
        "writable" => Act::ReadOnly(Some(false)),
        "read-only-default" => Act::ReadOnly(None),
        "gc-off" => Act::Schedule(None),
        "gc-schedule" => {
            let (Some(hours), Some(retention_days), Some(grace_days)) = (
                number("every_hours"),
                number("retention_days"),
                number("grace_days"),
            ) else {
                return Err(
                    "Refused: the interval, retention and grace are whole numbers, at \
                            least 1.",
                );
            };
            Act::Schedule(Some(GcPolicy {
                every_secs: hours.saturating_mul(3600),
                retention_days,
                grace_days,
            }))
        }
        "gc-now" => {
            let (Some(retention_days), Some(grace_days)) =
                (number("retention_days"), number("grace_days"))
            else {
                return Err("Refused: the retention and grace are whole numbers, at least 1.");
            };
            Act::GcNow {
                retention_days,
                grace_days,
                dry_run: field(form, "dry_run").is_some(),
            }
        }
        _ => return Err("No such action."),
    })
}

/// `POST /registry/<id>/action`: an operator's steering of a registry, as the session's
/// principal; back to the registry's page. An update is asked again first, and may be posted
/// by htmx from `/operations` ([`update`]).
pub(super) async fn action(
    req: Request<Incoming>,
    ui: &Ui,
    site: &FleetSite,
    id: &str,
) -> Result<Response<Body>> {
    let htmx = req.headers().contains_key("hx-request");
    let (auth, form) = match super::check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(actions::refused(htmx, status, text)),
    };
    if field(&form, "op") == Some("update") {
        return update(ui, site, htmx, &auth, &form, id).await;
    }
    let act = match act(&form) {
        Ok(act) => act,
        Err(why) => return Ok(message(StatusCode::BAD_REQUEST, why)),
    };
    let principal = auth.session.principal();
    let hub = ui.hub.clone();
    let registry = id.to_string();
    let done = blocking(move || {
        Ok(match act {
            Act::ReadOnly(r) => ops::read_only(&hub, &principal, &registry, r).map(|_| ()),
            Act::Schedule(s) => ops::gc_schedule(&hub, &principal, &registry, s).map(|_| ()),
            Act::GcNow {
                retention_days,
                grace_days,
                dry_run,
            } => ops::gc(
                &hub,
                &principal,
                &registry,
                retention_days,
                grace_days,
                dry_run,
            )
            .map(|_| ()),
        })
    })
    .await?;
    match done {
        Ok(()) => Ok(see_other(&format!("{DETAIL_PREFIX}{id}"))),
        Err(e) if e.is::<NotEnrolled>() => {
            Ok(message(StatusCode::NOT_FOUND, "There is no such registry."))
        }
        Err(e) => Ok(message(StatusCode::CONFLICT, &format!("Refused: {e:#}."))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An update is refused as the registry's own check refuses it: to an older version, or
    /// to one that cannot be ordered against its own.
    #[test]
    fn a_version_the_registry_refuses_is_said() {
        assert_eq!(version_refusal("0.90.1", "0.90.0"), None);
        assert_eq!(version_refusal("0.90.0", "0.90.0"), None);
        assert!(
            version_refusal("0.89.9", "0.90.0")
                .unwrap()
                .contains("older")
        );
        assert!(
            version_refusal("0.90", "0.90.0")
                .unwrap()
                .contains("cannot be ordered")
        );
        assert!(
            version_refusal("0.90.0", "dev")
                .unwrap()
                .contains("cannot be ordered")
        );
        assert_eq!(version_refusal("dev", "dev"), None);
    }
}
