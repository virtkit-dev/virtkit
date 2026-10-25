//! The registries the hub manages: `/registries`, each one's page at `/registry/<id>`, and an
//! operator's steering of one, posted to `/registry/<id>/action`. The registry keeps its own
//! UI; these pages show what it reports and what the hub asks of it.

use anyhow::Result;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use vk_hub_proto::Outcome;
use vk_hub_proto::registry::GcPolicy;

use super::html::Html;
use super::pages::{self, end_section, header_cells, kv, kv_node, section};
use super::{Auth, Body, Ui, blocking, field, message, page};
use crate::registries::{self as ops, RegistryView};
use crate::store::{NamespaceRow, NotEnrolled, RegistryCommandRow, RegistryRow, Role, TokenKeyRow};

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

/// `/registries`: each registry's name and address, whether it is connected, whether jobs
/// get access to it, and its free storage. Version, mode and ID are on its page.
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
    main.raw("<h1>Registries</h1>");
    if views.is_empty() {
        main.raw("<p class=\"empty\">No registry has enrolled yet: an operator issues a ")
            .raw("registry token below, or with <code>vk-hub token create --kind registry</code>, ")
            .raw("for <code>vk-registry join</code> on the registry's host.</p>");
    } else {
        main.raw("<table class=\"grid\"><thead><tr>");
        header_cells(
            &mut main,
            &["REGISTRY", "CONNECTION", "JOB ACCESS", "FREE STORAGE"],
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
    Ok(page(super::fleet::layout("Registries", PATH, auth, &main)))
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
    let Some((view, commands, namespaces, keys, sole)) = blocking(move || {
        let Some((view, commands)) = ops::detail(&hub, &wanted)? else {
            return Ok(None);
        };
        let namespaces = hub.db.namespaces(&wanted)?;
        let keys = hub.db.token_keys()?;
        let sole = hub.db.sole_gitlab()?;
        Ok::<_, anyhow::Error>(Some((view, commands, namespaces, keys, sole)))
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
            steering(&mut main, &view, auth);
            usage(&mut main, &view);
            commands_table(&mut main, &view, &commands, now);
        }
        Tab::Access => access(&mut main, &view, &namespaces, sole.as_deref()),
        Tab::Settings => settings(&mut main, &view, &keys, now),
    }
    Ok(page(super::fleet::layout(
        &view.row.hostname,
        PATH,
        auth,
        &main,
    )))
}

/// The Job access tab: the registry's storage areas, those the hub keeps for CI folded away,
/// and what keeps jobs from getting access, when something does; access rules name their GitLab
/// instance by `sole` ([`super::access::who`]).
fn access(h: &mut Html, v: &RegistryView, namespaces: &[NamespaceRow], sole: Option<&str>) {
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
    let areas: Vec<_> = (namespaces.iter())
        .map(|ns| super::access::area(ns, sole))
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

fn steering(h: &mut Html, v: &RegistryView, auth: &Auth) {
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
    h.raw(
        "</div></div><p class=\"sub\">The registry applies only what its <code>[hub] allow</code> ",
    )
    .raw("lists. Updates are issued with <code>vk-hub registries update</code>.</p></section>");
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
/// principal; back to the registry's page.
pub(super) async fn action(req: Request<Incoming>, ui: &Ui, id: &str) -> Result<Response<Body>> {
    let (auth, form) = match super::check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(message(status, text)),
    };
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
        Ok(()) => {
            let mut resp = Response::new(Body::default());
            *resp.status_mut() = StatusCode::SEE_OTHER;
            let location = format!("{DETAIL_PREFIX}{id}");
            resp.headers_mut().insert(
                header::LOCATION,
                HeaderValue::from_str(&location).unwrap_or(HeaderValue::from_static(PATH)),
            );
            Ok(resp)
        }
        Err(e) if e.is::<NotEnrolled>() => {
            Ok(message(StatusCode::NOT_FOUND, "There is no such registry."))
        }
        Err(e) => Ok(message(StatusCode::CONFLICT, &format!("Refused: {e:#}."))),
    }
}
