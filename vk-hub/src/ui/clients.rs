//! `/clients`: the API keys the client API takes and the client instances using each — the
//! host, program and runners an instance's hello named, when it was last heard from and what
//! it holds — for viewers and operators alike: on its GitLab tab the GitLab servers and the
//! keys bound to them, on its other tab the keys bound to none. Both tabs' fragments are
//! rendered once for all open viewers' pages and once for all operators' ([`sse::feed`]), on a
//! key created, revoked or removed, a GitLab server added or removed, an instance heard from
//! anew, a hello recorded or instances pruned ([`Hub::clients_changed`]), and, while a page is
//! open, once a heartbeat interval, which moves the ages and what the instances hold.
//!
//! Operators create, revoke and remove keys here as `vk-hub keys create` and `vk-hub keys
//! revoke` do, as their session's principal. A key is created by a plain form outside the
//! fragment, whose answer is a page of its own showing the key this once: it is never in a
//! fragment, a log or the audit log. The operator's fragment carries a revoke button on each
//! working key, and a remove button on the newest of those that no longer work under a name no
//! working key holds, removing them all; as on `/operations`, it posts with the CSRF token the
//! page sets through `hx-headers`, and asks first ([`actions::ask_first`]). The store acts only
//! on the keys the operator confirmed ([`crate::store::Db::revoke_api_keys_as_seen`]).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};

use super::fleet::{self, FleetSite};
use super::html::Html;
use super::pages::{self, csrf_field};
use super::sse;
use super::{Auth, Body, Ui, actions, blocking, field, page};
use crate::clients::{InstanceView, KeyView};
use crate::server::Hub;
use crate::store::{
    ANY_POOL, CLIENT_ACTIVE_SECS, GitlabRow, KeyOp, KeyPolicy, KeyRefused, KeyRow, KeysChanged,
    Role,
};

/// The page, and where its forms post.
pub(super) const PATH: &str = "/clients";

/// The event its fragment is swapped in on, and its stream's name under `/events/`.
pub(super) const EVENT: &str = "clients";

/// Key lifetimes the form offers, in days. The first is the default, matching
/// `vk-hub keys create`; the CLI takes any lifetime up to [`crate::store::MAX_KEY_TTL`].
const KEY_TTLS: [u64; 4] = [90, 7, 30, 365];

/// Where the key page suggests vk-gitlab keeps it.
const KEY_FILE: &str = "/etc/vk-gitlab/hub.key";

/// The other API clients' tab: the keys bound to no GitLab server and their instances.
pub(super) const OTHER: &str = "/clients?tab=other";

/// The event the GitLab tab's fragment is swapped in on, and its stream's name under
/// `/events/`. Both tabs' streams carry both tabs' fragments, rendered once for all of them.
pub(super) const GITLAB_EVENT: &str = "gitlab";

/// What the page shows: every key and its instances, the GitLab servers, and whether a registry
/// takes the hub's tokens.
struct Shown {
    views: Vec<KeyView>,
    gitlabs: Vec<(String, GitlabRow)>,
    tokens: bool,
}

impl Shown {
    /// Reads the database: call off the runtime.
    fn read(hub: &Hub) -> Result<Self> {
        Ok(Shown {
            views: crate::clients::views(hub)?,
            gitlabs: hub.db.gitlabs()?,
            tokens: hub.db.registries()?.iter().any(|(_, r)| r.takes_tokens()),
        })
    }
}

/// `GET /clients[?tab=other]`: Connections. Its GitLab tab, the default, lists the GitLab
/// servers the hub takes jobs from, the runner keys bound to each and the instances using
/// them; its other tab is the API keys bound to no server and their instances. Each tab's
/// fragment is live, on a stream of its own.
pub(super) async fn get(query: Option<&str>, auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    let form = super::decode_form(query.unwrap_or("").as_bytes());
    let other = field(&form, "tab") == Some("other");
    let hub = ui.hub.clone();
    let shown = blocking(move || Shown::read(&hub)).await?;
    let mut main = Html::new();
    main.raw("<h1>Connections</h1><nav class=\"tabs\" aria-label=\"Connection kinds\">")
        .raw("<a href=\"")
        .raw(PATH)
        .raw("\"")
        .raw(if other { "" } else { " aria-current=\"page\"" })
        .raw(">GitLab</a><a href=\"")
        .raw(OTHER)
        .raw("\"")
        .raw(if other { " aria-current=\"page\"" } else { "" })
        .raw(">Other API clients</a></nav>");
    let steer = auth.session.role >= Role::Operator;
    if steer {
        // The hub derives the hex token; htmx parses the header's JSON without evaluating it.
        main.raw("<div hx-headers=\"{&quot;X-CSRF-Token&quot;:&quot;")
            .text(&auth.csrf)
            .raw("&quot;}\"><div id=\"flash\"></div>");
    }
    let now = crate::now_secs();
    let (id, event, fragment) = if other {
        ("clients", EVENT, fragment(&shown.views, now, steer))
    } else {
        (
            "gitlab-servers",
            GITLAB_EVENT,
            gitlab_fragment(&shown, now, steer),
        )
    };
    main.raw("<div id=\"")
        .raw(id)
        .raw("\" hx-ext=\"sse\" sse-connect=\"/events/")
        .raw(event)
        .raw("\" sse-swap=\"")
        .raw(event)
        .raw("\" sse-close=\"close\">")
        .html(&fragment)
        .raw("</div>");
    if steer {
        main.raw("</div>");
        if other {
            create_form(&mut main, auth);
        }
    }
    Ok(page(fleet::layout("Connections", PATH, auth, &main)))
}

/// A runner key's expiry this close draws a warning.
const EXPIRY_WARNING: u64 = 14 * 86_400;

/// The GitLab tab: each GitLab server's working runner keys, allowed projects and nearest
/// expiry; then every key bound to a server, and the instances using them. Warn about working
/// jobs keys bound to unknown servers. When a registry takes hub tokens, also warn about
/// unbound jobs keys: their jobs get no registry access.
fn gitlab_fragment(shown: &Shown, now: u64, steer: bool) -> Html {
    let Shown {
        views,
        gitlabs,
        tokens,
    } = shown;
    let mut h = Html::new();
    let runners: Vec<&KeyView> = views
        .iter()
        .filter(|v| v.row.live(now) && v.row.scopes.contains(&crate::store::Scope::Jobs))
        .collect();
    for v in &runners {
        match &v.row.gitlab {
            None if *tokens => {
                h.raw("<p class=\"callout warn\"><strong>")
                    .text(&v.row.name)
                    .raw("</strong> submits jobs but is connected to no GitLab server: its jobs ")
                    .raw(
                        "get no registry access. <code>vk-hub keys create --gitlab</code> makes a ",
                    )
                    .raw("key bound to one.</p>");
            }
            Some(g) if !known(gitlabs, g) => {
                h.raw("<p class=\"callout warn\"><strong>")
                    .text(&v.row.name)
                    .raw("</strong> is bound to <strong>")
                    .text(g)
                    .raw("</strong>, a GitLab server the hub no longer knows.</p>");
            }
            _ => {}
        }
    }
    h.raw("<section><h2>GitLab servers</h2>");
    if gitlabs.is_empty() {
        h.raw("<p class=\"empty\">None yet: <code>vk-hub gitlabs add &lt;name&gt; &lt;url&gt;</code> ")
            .raw("adds one, and <code>vk-hub keys create --gitlab &lt;name&gt;</code> binds a ")
            .raw("runner key to it.</p></section>");
    } else {
        servers_table(&mut h, gitlabs, &runners, now);
        h.raw("</section>");
    }
    let mut bound: Vec<&KeyView> = views.iter().filter(|v| v.row.gitlab.is_some()).collect();
    // Stable: a server's keys stay oldest first.
    bound.sort_by(|a, b| a.row.gitlab.cmp(&b.row.gitlab));
    if gitlabs.is_empty() && bound.is_empty() {
        return h;
    }
    h.raw("<section><h2>Runner keys</h2>");
    if bound.is_empty() {
        h.raw("<p class=\"empty\">none: <code>vk-hub keys create --gitlab &lt;name&gt;</code> ")
            .raw("makes one</p>");
    } else {
        keys_table(&mut h, &bound, views, now, steer, Some(gitlabs));
    }
    h.raw("<p class=\"sub\"><code>vk-hub keys create --gitlab &lt;name&gt; [--projects ")
        .raw("&lt;id&gt;:&lt;path&gt;,…]</code> makes a runner key. To replace one, create its ")
        .raw("successor under another name, point vk-gitlab at it, then revoke the old one.</p>")
        .raw("</section><section><h2>Instances</h2>");
    instances_table(
        &mut h,
        &bound,
        views,
        now,
        Some(gitlabs),
        "none: no runner has used a key yet",
    );
    h.raw("</section>");
    h
}

/// Whether the hub knows the GitLab server named `name`.
fn known(gitlabs: &[(String, GitlabRow)], name: &str) -> bool {
    gitlabs.iter().any(|(n, _)| n == name)
}

/// Each GitLab server with its working runner keys (of `runners`), the projects they allow and
/// their nearest expiry.
fn servers_table(h: &mut Html, gitlabs: &[(String, GitlabRow)], runners: &[&KeyView], now: u64) {
    h.raw("<table class=\"grid\"><thead><tr><th>server</th><th>runner keys</th>")
        .raw("<th>allowed projects</th><th>key expires</th></tr></thead><tbody>");
    for (name, row) in gitlabs {
        let keys: Vec<&&KeyView> = runners
            .iter()
            .filter(|v| v.row.gitlab.as_deref() == Some(name.as_str()))
            .collect();
        h.raw("<tr><td><strong>")
            .text(name)
            .raw("</strong><div class=\"sub\">")
            .text(&row.url)
            .raw("</div></td><td>");
        if keys.is_empty() {
            h.raw("<span class=\"sub\">none</span>");
        }
        for (i, v) in keys.iter().enumerate() {
            if i > 0 {
                h.raw("<br>");
            }
            h.text(&v.row.name);
        }
        h.raw("</td><td>");
        if keys.iter().any(|v| v.row.projects.is_empty()) {
            h.raw("All projects");
        } else {
            let mut paths: Vec<&str> = keys
                .iter()
                .flat_map(|v| v.row.projects.iter().map(|p| p.path.as_str()))
                .collect();
            paths.sort_unstable();
            paths.dedup();
            if paths.is_empty() {
                h.raw("<span class=\"sub\">none</span>");
            } else {
                h.text(paths.join(", "));
            }
        }
        h.raw("</td><td>");
        let within = |at: u64| {
            format!(
                "in {}",
                crate::human_duration(Duration::from_secs(at.saturating_sub(now))).trim_end()
            )
        };
        match keys.iter().map(|v| v.row.expires_at).min() {
            Some(at) if at.saturating_sub(now) < EXPIRY_WARNING => {
                h.raw("<span class=\"badge warn\">");
                pages::time(h, at, &within(at));
                h.raw("</span>");
            }
            Some(at) => {
                pages::time(h, at, &within(at));
            }
            None => {
                h.raw("<span class=\"sub\">-</span>");
            }
        }
        h.raw("</td></tr>");
    }
    h.raw("</tbody></table>");
}

/// The fragments, as one rendering for every page showing them: with the keys' buttons for an
/// operator's, without for a viewer's. The other tab's first, then the GitLab tab's.
pub(super) fn events(hub: &Arc<Hub>, steer: bool) -> sse::Events {
    let other: sse::Render = {
        let hub = hub.clone();
        Arc::new(move || {
            let views = crate::clients::views(&hub)?;
            Ok(fragment(&views, crate::now_secs(), steer).into_string())
        })
    };
    let gitlab: sse::Render = {
        let hub = hub.clone();
        Arc::new(move || {
            let shown = Shown::read(&hub)?;
            Ok(gitlab_fragment(&shown, crate::now_secs(), steer).into_string())
        })
    };
    sse::Events::from([(EVENT, other), (GITLAB_EVENT, gitlab)])
}

/// The other tab: the keys bound to no GitLab server, then their instances.
fn fragment(views: &[KeyView], now: u64, steer: bool) -> Html {
    let unbound: Vec<&KeyView> = views.iter().filter(|v| v.row.gitlab.is_none()).collect();
    let mut h = Html::new();
    h.raw("<section><h2>API keys</h2>");
    if unbound.is_empty() {
        h.raw(if steer {
            "<p class=\"empty\">none: create one below or with <code>vk-hub keys create</code>"
        } else {
            "<p class=\"empty\">none: <code>vk-hub keys create</code> creates one"
        });
        if unbound.len() < views.len() {
            h.raw(". GitLab runner keys are on the <a href=\"")
                .raw(PATH)
                .raw("\">GitLab</a> tab.");
        }
        h.raw("</p>");
    } else {
        keys_table(&mut h, &unbound, views, now, steer, None);
    }
    h.raw("</section><section><h2>Instances</h2>");
    instances_table(
        &mut h,
        &unbound,
        views,
        now,
        None,
        "none: no client has used a key yet",
    );
    h.raw("</section>");
    h
}

/// The keys `rows` of all the keys `views`, with a server and a projects column given the GitLab
/// servers (`gitlabs`). With `steer`, a working key carries the button that revokes it; under a
/// name [`target`] would remove keys of, the newest carries the button that removes them all,
/// whichever tab it is on.
fn keys_table(
    h: &mut Html,
    rows: &[&KeyView],
    views: &[KeyView],
    now: u64,
    steer: bool,
    gitlabs: Option<&[(String, GitlabRow)]>,
) {
    let working: HashSet<&str> = views
        .iter()
        .filter(|v| v.row.live(now))
        .map(|v| v.row.name.as_str())
        .collect();
    let mut removable: HashMap<&str, &KeyView> = HashMap::new();
    for v in views
        .iter()
        .filter(|v| !working.contains(v.row.name.as_str()))
    {
        let newest = removable.entry(&v.row.name).or_insert(v);
        if v.row.created_at >= newest.row.created_at {
            *newest = v;
        }
    }
    h.raw("<table class=\"grid\"><thead><tr>");
    if gitlabs.is_some() {
        h.raw("<th>server</th>");
    }
    h.raw("<th>name</th><th>key</th><th>scopes</th><th>pools</th><th>largest</th>");
    if gitlabs.is_some() {
        h.raw("<th>projects</th>");
    }
    h.raw("<th>created</th><th>by</th><th>state</th><th>last heard</th>")
        .raw("<th class=\"num\">instances</th><th class=\"num\">jobs</th>");
    if steer {
        h.raw("<th>change</th>");
    }
    h.raw("</tr></thead><tbody>");
    for &v in rows {
        key_row(h, v, views, now, gitlabs);
        if steer {
            h.raw("<td class=\"actions\">");
            if v.row.live(now) {
                change_button(h, KeyOp::Revoke, "Revoke", &v.row.name);
            } else if removable
                .get(v.row.name.as_str())
                .is_some_and(|newest| std::ptr::eq(*newest, v))
            {
                change_button(h, KeyOp::Remove, "Remove", &v.row.name);
            }
            h.raw("</td>");
        }
        h.raw("</tr>");
    }
    h.raw("</tbody></table>");
}

/// The instances shown of the keys `rows` of all the keys `views`, with a server column given
/// the GitLab servers (`gitlabs`); `empty` when there are none.
fn instances_table(
    h: &mut Html,
    rows: &[&KeyView],
    views: &[KeyView],
    now: u64,
    gitlabs: Option<&[(String, GitlabRow)]>,
    empty: &str,
) {
    if rows.iter().all(|v| shown(views, v, now).next().is_none()) {
        h.raw("<p class=\"empty\">").text(empty).raw("</p>");
        return;
    }
    h.raw("<table class=\"grid\"><thead><tr>");
    if gitlabs.is_some() {
        h.raw("<th>server</th>");
    }
    h.raw("<th>key</th><th>host</th><th>instance</th><th>program</th><th>runners</th>")
        .raw("<th>last heard</th><th class=\"num\">reservations</th>")
        .raw("<th class=\"num\">queued</th><th class=\"num\">running</th></tr></thead><tbody>");
    for v in rows {
        for i in shown(views, v, now) {
            instance_row(h, &v.row, i, now, gitlabs);
        }
    }
    h.raw("</tbody></table>");
}

/// The cell of the GitLab server key `key` is bound to, marked when the hub no longer knows it.
fn server_cell(h: &mut Html, key: &KeyRow, gitlabs: &[(String, GitlabRow)]) {
    h.raw("<td>");
    if let Some(g) = &key.gitlab {
        h.text(g);
        if !known(gitlabs, g) {
            h.raw(" <span class=\"badge warn\">unknown</span>");
        }
    }
    h.raw("</td>");
}

/// Whether instance `i` of key `v` is one a working key of the same GitLab server, or of none,
/// shows too, while `v` no longer works and `i` holds nothing: the same client, now using
/// another key, which would otherwise show twice.
fn superseded(views: &[KeyView], v: &KeyView, i: &InstanceView, now: u64) -> bool {
    let w = i.work;
    !v.row.live(now)
        && !i.row.instance.is_empty()
        && (w.reservations, w.queued, w.running) == (0, 0, 0)
        && views.iter().any(|o| {
            o.row.live(now)
                && o.row.gitlab == v.row.gitlab
                && o.instances.iter().any(|j| j.row.instance == i.row.instance)
        })
}

/// The instances of key `v` to show: those not [`superseded`].
fn shown<'a>(
    views: &'a [KeyView],
    v: &'a KeyView,
    now: u64,
) -> impl Iterator<Item = &'a InstanceView> {
    (v.instances.iter()).filter(move |i| !superseded(views, v, i, now))
}

/// Key `v`'s row, left open for an operator's button; `views` all the keys, to count only the
/// instances shown ([`superseded`]). Given the GitLab servers (`gitlabs`), with its server and
/// the projects it may submit jobs of.
fn key_row(
    h: &mut Html,
    v: &KeyView,
    views: &[KeyView],
    now: u64,
    gitlabs: Option<&[(String, GitlabRow)]>,
) {
    let k = &v.row;
    let scopes: Vec<&str> = k.scopes.iter().map(|s| s.name()).collect();
    let pools: Vec<&str> = (k.pools.iter())
        .map(|p| if p == ANY_POOL { "any" } else { p })
        .collect();
    h.raw("<tr>");
    if let Some(gitlabs) = gitlabs {
        server_cell(h, k, gitlabs);
    }
    h.raw("<td>")
        .text(&k.name)
        .raw("</td><td><code>vkk_")
        .text(&k.prefix)
        .raw("…</code></td><td>")
        .text(scopes.join(", "))
        .raw("</td><td>")
        .text(pools.join(", "))
        .raw("</td><td>")
        .text(
            k.max_envelope
                .map_or_else(pages::dash, crate::store::envelope_text),
        )
        .raw("</td><td>");
    if gitlabs.is_some() {
        if k.projects.is_empty() {
            h.raw("All projects");
        } else {
            let paths: Vec<&str> = k.projects.iter().map(|p| p.path.as_str()).collect();
            h.text(paths.join(", "));
        }
        h.raw("</td><td>");
    }
    pages::at(h, k.created_at)
        .raw("</td><td>")
        .text(&k.created_by)
        .raw("</td><td>");
    if k.revoked_at.is_some() {
        h.raw("<span class=\"badge bad\">revoked</span>");
    } else if k.expires_at <= now {
        h.raw("<span class=\"badge warn\">expired</span>");
    } else {
        h.raw("expires ");
        pages::at(h, k.expires_at);
    }
    h.raw("</td><td>");
    match v.last_seen() {
        Some(t) => heard_at(h, now, t, k.live(now)),
        None => {
            h.raw("-");
        }
    }
    h.raw("</td><td class=\"num\">")
        .text(shown(views, v, now).count())
        .raw("</td><td class=\"num\">");
    // The jobs page takes only a SHA-256 for a key: what the hub stores a key under.
    if vk_hub_proto::valid_sha256(&v.id) {
        h.raw("<a href=\"")
            .raw(super::jobs::PATH)
            .raw("?key=")
            .text(&v.id)
            .raw("\">")
            .text(v.jobs)
            .raw("</a>");
    } else {
        h.text(v.jobs);
    }
    h.raw("</td>");
}

/// A button posting `op` on the key named `name`. No CSRF field: the page around the fragment
/// sets the token as a header.
fn change_button(h: &mut Html, op: KeyOp, label: &'static str, name: &str) {
    h.raw("<form method=\"post\" action=\"")
        .raw(PATH)
        .raw("\" hx-post=\"")
        .raw(PATH)
        .raw("\" hx-swap=\"none\"><input type=\"hidden\" name=\"op\" value=\"")
        .raw(op.name())
        .raw("\"><input type=\"hidden\" name=\"name\" value=\"")
        .text(name)
        .raw("\"><button class=\"danger\">")
        .raw(label)
        .raw("</button></form>");
}

/// An operator's form creating a key, outside the live fragment: a plain POST, answered by a
/// page of its own showing the key, so it is never sent in a fragment shared by every page.
fn create_form(h: &mut Html, auth: &Auth) {
    h.raw("<section><h2>Create an API key</h2><form class=\"wide\" method=\"post\" action=\"")
        .raw(PATH)
        .raw("\">");
    csrf_field(h, auth);
    h.raw("<input type=\"hidden\" name=\"op\" value=\"create\">")
        .raw("<label for=\"key-name\">Name</label>")
        .raw("<input id=\"key-name\" type=\"text\" name=\"name\" autocomplete=\"off\" ")
        .raw("spellcheck=\"false\" required placeholder=\"gitlab-ci\">")
        .raw("<label for=\"key-pools\">Pools</label>")
        .raw("<input id=\"key-pools\" type=\"text\" name=\"pools\" autocomplete=\"off\" ")
        .raw("spellcheck=\"false\" required placeholder=\"ci, build or *\">")
        .raw("<fieldset><legend>Scopes</legend><label><input type=\"checkbox\" name=\"scope\" ")
        .raw("value=\"jobs\" checked> jobs</label><label><input type=\"checkbox\" ")
        .raw("name=\"scope\" value=\"capacity\"> capacity</label></fieldset>")
        .raw("<label for=\"key-mem\">Largest memory</label>")
        .raw("<input id=\"key-mem\" type=\"text\" name=\"max_mem\" autocomplete=\"off\" ")
        .raw("placeholder=\"any, or 16G\">")
        .raw("<label for=\"key-cpus\">Largest CPUs</label>")
        .raw("<input id=\"key-cpus\" type=\"text\" inputmode=\"numeric\" name=\"max_cpus\" ")
        .raw("autocomplete=\"off\" placeholder=\"any, or 8\">")
        .raw("<label for=\"key-disk\">Largest disk</label>")
        .raw("<input id=\"key-disk\" type=\"text\" name=\"max_disk\" autocomplete=\"off\" ")
        .raw("placeholder=\"any, or 64G\">")
        .raw("<label for=\"key-ttl\">Valid for</label><select id=\"key-ttl\" name=\"ttl\">");
    for days in KEY_TTLS {
        h.raw("<option value=\"")
            .text(days)
            .raw("\">")
            .text(days)
            .raw(" days</option>");
    }
    h.raw("</select><button class=\"primary\">Create</button></form>")
        .raw("<p class=\"sub\">As <code>vk-hub keys create</code>: scope <code>jobs</code> is ")
        .raw("the whole client API, <code>capacity</code> only asks for room. Pools are ")
        .raw("comma-separated, <code>*</code> for any. A job's largest memory and disk take ")
        .raw("<code>&lt;n&gt;K|M|G|T</code>; memory at least <code>1M</code>. A limit left ")
        .raw("empty is unbounded. The key is shown a single time.</p></section>");
}

/// `POST /clients`: create (`create`), revoke (`revoke`) or remove (`remove`) a key as the
/// operator session's principal, as `vk-hub keys create` and `vk-hub keys revoke` do.
pub(super) async fn action(
    req: Request<Incoming>,
    ui: &Ui,
    site: &FleetSite,
) -> Result<Response<Body>> {
    let htmx = req.headers().contains_key("hx-request");
    let (auth, form) = match super::check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(actions::refused(htmx, status, text)),
    };
    match field(&form, "op") {
        Some("create") => create(ui, &auth, &form).await,
        Some("revoke") => revoke(ui, site, htmx, &auth, &form, KeyOp::Revoke).await,
        Some("remove") => revoke(ui, site, htmx, &auth, &form, KeyOp::Remove).await,
        _ => Ok(actions::refused(
            htmx,
            StatusCode::BAD_REQUEST,
            "No such action.",
        )),
    }
}

/// Create the key `form` asks for, and show it this once with the vk-gitlab config using it.
/// Its policy is checked as the CLI's: by [`crate::store::Db::create_api_key`], which refuses
/// a bad name, pool or lifetime, and its limits parsed as the CLI parses them.
async fn create(ui: &Ui, auth: &Auth, form: &[(String, String)]) -> Result<Response<Body>> {
    let refused = |why: String| {
        let mut main = Html::new();
        main.raw("<p class=\"message\">")
            .text(format!("Refused: {why}."))
            .raw("</p><p><a href=\"")
            .raw(OTHER)
            .raw("\">Back to the API clients</a></p>");
        let mut resp = page(fleet::layout("API key", PATH, auth, &main));
        *resp.status_mut() = StatusCode::BAD_REQUEST;
        resp
    };
    let mut scopes = Vec::new();
    for (_, s) in form.iter().filter(|(k, _)| k == "scope") {
        match crate::parse_scope(s) {
            Ok(scope) => scopes.push(scope),
            Err(why) => return Ok(refused(why)),
        }
    }
    let pools: Vec<String> = field(form, "pools")
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect();
    let limit = |name: &str| field(form, name).map(str::trim).filter(|v| !v.is_empty());
    let max_mem = match limit("max_mem").map(crate::parse_mem_size).transpose() {
        Ok(v) => v,
        Err(why) => return Ok(refused(format!("largest memory {why}"))),
    };
    let max_cpus = match limit("max_cpus").map(str::parse::<u32>).transpose() {
        Ok(v) => v,
        Err(_) => return Ok(refused("largest CPUs: expected a whole number".into())),
    };
    let max_disk = match limit("max_disk").map(crate::parse_size).transpose() {
        Ok(v) => v,
        Err(why) => return Ok(refused(format!("largest disk {why}"))),
    };
    let Some(days) = field(form, "ttl")
        .and_then(|t| t.parse::<u64>().ok())
        .filter(|d| KEY_TTLS.contains(d))
    else {
        return Ok(refused("not one of the form's lifetimes".into()));
    };
    let policy = KeyPolicy::with_limits(scopes, pools, max_mem, max_cpus, max_disk);
    let name = field(form, "name").unwrap_or("").to_string();
    let ttl = Duration::from_secs(days.saturating_mul(86_400));
    let (hub, principal, named) = (ui.hub.clone(), auth.session.principal(), name.clone());
    let created = blocking(move || {
        Ok(hub
            .db
            .create_api_key(&named, &policy, ttl, &principal, crate::now_secs()))
    })
    .await?;
    let (key, row) = match created {
        Ok(created) => created,
        Err(e) if e.is::<KeyRefused>() => return Ok(refused(e.to_string())),
        Err(e) => return Err(e),
    };
    ui.hub.clients_changed();
    // The key itself is never logged: it is the credential.
    eprintln!(
        "vk-hub: ui: {} created API key {name}",
        auth.session.principal()
    );
    let mut main = Html::new();
    main.raw("<h1>API key</h1><p>Key <strong>")
        .text(&row.name)
        .raw("</strong> works until ");
    pages::at(&mut main, row.expires_at)
        .raw(". It is shown this once: copy it now.</p><pre>")
        .text(&key)
        .raw("</pre><p>Keep it in a file only vk-gitlab's user reads, such as <code>")
        .raw(KEY_FILE)
        .raw("</code>, and point vk-gitlab's config at it:</p><pre>[hub]\nurl = \"");
    match &ui.hub.node_url {
        Some(url) => main.text(url),
        None => main.raw("&lt;hub-url&gt;"),
    };
    main.raw("\"\napi_key_file = \"")
        .raw(KEY_FILE)
        .raw("\"</pre><p class=\"sub\">Add <code>ca_file</code> when the hub's certificate ")
        .raw("is not one the system's roots verify.</p><p><a href=\"")
        .raw(OTHER)
        .raw("\">Back to the API clients</a></p>");
    Ok(page(fleet::layout("API key", PATH, auth, &main)))
}

/// What a revoke or remove of the keys named `name` acts on, as `vk-hub keys revoke <name>`:
/// its working key, revoked (`revoke`), or with none working those that no longer work,
/// removed (`remove`). The op, and those keys.
fn target<'a>(views: &'a [KeyView], name: &str, now: u64) -> Option<(KeyOp, Vec<&'a KeyView>)> {
    let named = views.iter().filter(|v| v.row.name == name);
    let (working, dead): (Vec<&KeyView>, Vec<&KeyView>) = named.partition(|v| v.row.live(now));
    match (working.is_empty(), dead.is_empty()) {
        (false, _) => Some((KeyOp::Revoke, working)),
        (true, false) => Some((KeyOp::Remove, dead)),
        (true, true) => None,
    }
}

/// Revoke or remove the keys named in `form` once confirmed, as [`target`] finds them; `op`
/// must be what it would do, so a button shown before the keys changed acts on nothing, and the
/// store acts only if, as it writes, it would still do so to the keys confirmed.
async fn revoke(
    ui: &Ui,
    site: &FleetSite,
    htmx: bool,
    auth: &Auth,
    form: &[(String, String)],
    op: KeyOp,
) -> Result<Response<Body>> {
    let name = field(form, "name").unwrap_or("").to_string();
    let hub = ui.hub.clone();
    let views = blocking(move || crate::clients::views(&hub)).await?;
    let now = crate::now_secs();
    let Some((wanted, keys)) = target(&views, &name, now) else {
        return Ok(actions::refused(
            htmx,
            StatusCode::NOT_FOUND,
            "There is no such key.",
        ));
    };
    if wanted != op {
        return Ok(actions::refused(
            htmx,
            StatusCode::CONFLICT,
            "Refused: it changed since you looked; look again.",
        ));
    }
    let (reservations, jobs) =
        keys.iter()
            .flat_map(|v| &v.instances)
            .fold((0usize, 0usize), |(r, j), i| {
                (
                    r.saturating_add(i.work.reservations),
                    j.saturating_add(i.work.queued)
                        .saturating_add(i.work.running),
                )
            });
    let mut detail = Html::new();
    detail.raw("<p><strong>").text(&name).raw("</strong>: ");
    for (n, v) in keys.iter().enumerate() {
        if n > 0 {
            detail.raw(", ");
        }
        detail.raw("<code>vkk_").text(&v.row.prefix).raw("…</code>");
    }
    detail
        .raw("; ")
        .text(reservations)
        .raw(" reservation(s), ")
        .text(jobs)
        .raw(" job(s) queued or running</p>");
    let ids: Vec<String> = keys.iter().map(|v| v.id.clone()).collect();
    // Back to the tab showing them.
    let back = if keys.iter().any(|v| v.row.gitlab.is_some()) {
        PATH
    } else {
        OTHER
    };
    let ask = actions::Ask {
        path: PATH.to_string(),
        back: back.to_string(),
        op: op.name().to_string(),
        what: match (op, keys.len()) {
            (KeyOp::Revoke, _) => {
                "Revoke this API key? It stops working at once: whatever holds it can reserve \
                 and place nothing more, and vk-gitlab can no longer follow or settle its jobs \
                 under way."
            }
            (KeyOp::Remove, 1) => {
                "Remove this API key, which no longer works? Its client instances go with it \
                 and its name is free again; its jobs stay in the history."
            }
            (KeyOp::Remove, _) => {
                "Remove these API keys, which no longer work? Their client instances go with \
                 them and their name is free again; their jobs stay in the history."
            }
        },
        detail,
        asked: vec![("name", name.clone()), ("keys", ids.join(","))],
    };
    if let Some(asked) = actions::ask_first(&site.questions, fleet::layout, htmx, auth, form, &ask)?
    {
        return Ok(asked);
    }
    let (hub, principal, named) = (ui.hub.clone(), auth.session.principal(), name.clone());
    let done = blocking(move || {
        Ok(hub
            .db
            .revoke_api_keys_as_seen(&named, op, &ids, &principal, crate::now_secs()))
    })
    .await?;
    let done = match done {
        Ok(done) => done,
        Err(e) if e.is::<KeysChanged>() => {
            return Ok(actions::refused(
                htmx,
                StatusCode::CONFLICT,
                "Refused: it changed since you were asked; look again.",
            ));
        }
        Err(e) => return Err(e),
    };
    if !done {
        return Ok(actions::refused(
            htmx,
            StatusCode::NOT_FOUND,
            "There is no such key.",
        ));
    }
    ui.hub.clients_changed();
    let (said, done) = match op {
        KeyOp::Revoke => (format!("Revoked API key {name}."), "revoked"),
        KeyOp::Remove => (
            format!("Removed the API key(s) named {name} that no longer worked."),
            "removed",
        ),
    };
    eprintln!(
        "vk-hub: ui: {} {done} API key {name}",
        auth.session.principal()
    );
    if !htmx {
        let mut resp = Response::new(Body::default());
        *resp.status_mut() = StatusCode::SEE_OTHER;
        resp.headers_mut()
            .insert(header::LOCATION, HeaderValue::from_static(back));
        return Ok(resp);
    }
    let mut h = Html::new();
    h.raw("<div id=\"flash\" hx-swap-oob=\"true\">")
        .text(&said)
        .raw("</div>");
    Ok(actions::swap_none(super::html_response(StatusCode::OK, h)))
}

/// Instance `i` of key `key`, with its server given the GitLab servers (`gitlabs`): all that it said made display-safe again ([`Html::node`]), a
/// runner's URL linked only when it is a plain web link. Under a key that no longer works, the
/// key says so and the instance is never shown connected: it can no longer be.
fn instance_row(
    h: &mut Html,
    key: &KeyRow,
    i: &InstanceView,
    now: u64,
    gitlabs: Option<&[(String, GitlabRow)]>,
) {
    let r = &i.row;
    h.raw("<tr>");
    if let Some(gitlabs) = gitlabs {
        server_cell(h, key, gitlabs);
    }
    h.raw("<td>").text(&key.name);
    key_gone(h, key, now);
    h.raw("</td><td>");
    or_dash(h, &r.hostname);
    h.raw("</td><td>");
    if r.instance.is_empty() {
        h.raw("<span class=\"sub\">unknown instance</span>");
    } else {
        h.raw("<code>").node(&r.instance).raw("</code>");
    }
    h.raw("</td><td>");
    or_dash(h, &format!("{} {}", r.program, r.version));
    h.raw("</td><td>");
    if r.runners.is_empty() {
        h.raw("-");
    }
    for (n, runner) in r.runners.iter().enumerate() {
        if n > 0 {
            h.raw("<br>");
        }
        h.node(&runner.name).raw(" · pool ").node(&runner.pool);
        if !runner.url.is_empty() {
            h.raw(" · ").external_link(Some(&runner.url), &runner.url);
        }
    }
    h.raw("</td><td>");
    // 0 for an instance known only by what it holds, heard from before memory recalls.
    if r.last_seen == 0 {
        h.raw("-");
    } else {
        heard_at(h, now, r.last_seen, key.live(now));
    }
    let w = i.work;
    h.raw("</td><td class=\"num\">")
        .text(w.reservations)
        .raw("</td><td class=\"num\">")
        .text(w.queued)
        .raw("</td><td class=\"num\">")
        .text(w.running)
        .raw("</td></tr>");
}

/// Show a client's `value`, or `-` if blank.
fn or_dash(h: &mut Html, value: &str) {
    match value.trim() {
        "" => h.raw("-"),
        v => h.node(v),
    };
}

/// A badge after the name of `key` when it no longer works.
fn key_gone(h: &mut Html, key: &KeyRow, now: u64) {
    if key.revoked_at.is_some() {
        h.raw(" <span class=\"badge bad\">key revoked</span>");
    } else if key.expires_at <= now {
        h.raw(" <span class=\"badge warn\">key expired</span>");
    }
}

/// When `then` was, marked connected when within [`CLIENT_ACTIVE_SECS`] of `now` through a key
/// that works (`live`).
fn heard_at(h: &mut Html, now: u64, then: u64, live: bool) {
    if live && now.saturating_sub(then) <= CLIENT_ACTIVE_SECS {
        h.raw("<span class=\"badge ok\">connected</span> ");
    }
    super::fleet::time_ago(h, now, then);
}

#[cfg(test)]
mod tests {
    use vk_hub_proto::client::ClientRunner;

    use super::*;
    use crate::jobs::Work;
    use crate::store::{ClientRow, Scope};

    fn key(name: &str) -> KeyRow {
        KeyRow {
            name: name.into(),
            prefix: "0123abcd".into(),
            scopes: vec![Scope::Jobs, Scope::Capacity],
            pools: vec!["ci".into()],
            max_envelope: None,
            created_at: 100,
            created_by: "uid 0".into(),
            expires_at: 10_000,
            revoked_at: None,
            gitlab: None,
            projects: Vec::new(),
        }
    }

    fn instance(name: &str, last_seen: u64) -> InstanceView {
        InstanceView {
            row: ClientRow {
                key_name: "gitlab".into(),
                instance: name.into(),
                first_seen: 100,
                last_seen,
                hello_at: None,
                program: String::new(),
                version: String::new(),
                hostname: String::new(),
                concurrent: None,
                runners: Vec::new(),
            },
            work: Work::default(),
        }
    }

    #[test]
    fn instances_show_what_they_said_and_whether_they_are_connected() {
        let mut said = instance("s_1", 1000);
        said.row.hostname = "ci-1".into();
        said.row.program = "vk-gitlab".into();
        said.row.version = "0.91.1".into();
        said.row.runners = vec![
            ClientRunner {
                name: "docker".into(),
                url: "https://gitlab.example.com".into(),
                pool: "ci".into(),
                labels: vec![],
                limit: None,
            },
            // The hub strips credentials before storage. If any reach the renderer,
            // show the URL as text, never as a link.
            ClientRunner {
                name: "shell".into(),
                url: "https://user:pass@gitlab.example.com".into(),
                pool: "ci".into(),
                labels: vec![],
                limit: None,
            },
        ];
        said.work = Work {
            reservations: 1,
            queued: 2,
            running: 3,
        };
        let views = [
            KeyView {
                id: "ab".repeat(32),
                row: key("gitlab"),
                instances: vec![said, instance("", 999 - CLIENT_ACTIVE_SECS)],
                jobs: 7,
            },
            KeyView {
                id: "cd".repeat(32),
                row: KeyRow {
                    revoked_at: Some(200),
                    ..key("old")
                },
                instances: Vec::new(),
                jobs: 0,
            },
            KeyView {
                id: "ef".repeat(32),
                row: KeyRow {
                    pools: vec![ANY_POOL.into()],
                    expires_at: 1000,
                    ..key("lapsed")
                },
                instances: vec![instance("gone", 0)],
                jobs: 0,
            },
        ];
        let page = fragment(&views, 1000, false).into_string();
        for want in [
            "<td>gitlab</td><td><code>vkk_0123abcd…</code></td><td>jobs, capacity</td>",
            &format!("<a href=\"/jobs?key={}\">7</a>", "ab".repeat(32)),
            "<span class=\"badge bad\">revoked</span>",
            "<td>jobs, capacity</td><td>ci</td><td>-</td><td><time",
            "</td><td>expires <time",
            "<td>lapsed</td><td><code>vkk_0123abcd…</code></td><td>jobs, capacity</td>\
             <td>any</td>",
            "<span class=\"badge warn\">expired</span>",
            // Known only by what it holds: no contact to show, for it or its key.
            "<td><code>gone</code></td><td>-</td><td>-</td><td>-</td>",
            "</td><td>-</td><td class=\"num\">0</td>",
            "<td>gitlab</td><td>ci-1</td><td><code>s_1</code></td><td>vk-gitlab 0.91.1</td>",
            "docker · pool ci · <a href=\"https://gitlab.example.com\" target=\"_blank\" \
             rel=\"noopener noreferrer\">https://gitlab.example.com</a>",
            "shell · pool ci · https://user:pass@gitlab.example.com</td>",
            "<td class=\"num\">1</td><td class=\"num\">2</td><td class=\"num\">3</td>",
            "<td>-</td><td><span class=\"sub\">unknown instance</span></td><td>-</td><td>-</td>",
        ] {
            assert!(page.contains(want), "{want}: {page}");
        }
        // Heard from just now: connected; 181 seconds ago: no longer.
        assert_eq!(page.matches("badge ok\">connected").count(), 2, "{page}");

        assert!(!page.contains("<form"), "{page}");

        let none = fragment(&[], 1000, false).into_string();
        assert!(none.contains("<code>vk-hub keys create</code>"), "{none}");
        assert!(none.contains("no client has used a key yet"), "{none}");
    }

    /// An instance seen through a key that no longer works is never shown connected, and its
    /// key says why. The same instance shown under a working key, holding nothing, is not
    /// shown again: it is the client that moved to the new key.
    #[test]
    fn instances_of_a_key_that_no_longer_works_are_not_live() {
        let view = |id: &str, row: KeyRow, instances| KeyView {
            id: id.repeat(32),
            row,
            instances,
            jobs: 0,
        };
        let mut holding = instance("s_2", 990);
        holding.work.running = 1;
        let views = [
            view(
                "ab",
                KeyRow {
                    revoked_at: Some(500),
                    ..key("vk-gitlab")
                },
                vec![instance("s_1", 990), holding],
            ),
            view(
                "cd",
                KeyRow {
                    created_at: 500,
                    ..key("vk-gitlab")
                },
                vec![instance("s_1", 995)],
            ),
        ];
        let page = fragment(&views, 1000, false).into_string();
        assert_eq!(page.matches("<code>s_1</code>").count(), 1, "{page}");
        assert!(
            page.contains(
                "<td>vk-gitlab <span class=\"badge bad\">key revoked</span></td><td>-</td>\
                 <td><code>s_2</code>"
            ),
            "{page}"
        );
        // The working key's row and its instance only.
        assert_eq!(page.matches("badge ok\">connected").count(), 2, "{page}");
        // The revoked key counts the instance it shows, not the one that moved on.
        let revoked = page.split("<td>vk-gitlab</td>").nth(1).unwrap();
        let revoked = revoked.split("</tr>").next().unwrap();
        assert!(revoked.contains("<td class=\"num\">1</td>"), "{revoked}");

        // Without a working key showing it, it is shown, marked.
        let page = fragment(&views[..1], 1000, false).into_string();
        assert_eq!(page.matches("<code>s_1</code>").count(), 1, "{page}");
        assert!(!page.contains("connected"), "{page}");
    }

    /// An operator's fragment offers to revoke a working key, and to remove one that no
    /// longer works only when no working key holds its name: removing acts on the name.
    #[test]
    fn an_operator_revokes_working_keys_and_removes_dead_ones() {
        let view = |id: &str, row: KeyRow| KeyView {
            id: id.repeat(32),
            row,
            instances: Vec::new(),
            jobs: 0,
        };
        let views = [
            view("ab", key("gitlab")),
            view(
                "cd",
                KeyRow {
                    revoked_at: Some(200),
                    ..key("gitlab")
                },
            ),
            view(
                "ef",
                KeyRow {
                    expires_at: 1000,
                    ..key("old")
                },
            ),
        ];
        let page = fragment(&views, 1000, true).into_string();
        assert_eq!(page.matches(">Revoke</button>").count(), 1, "{page}");
        assert_eq!(page.matches(">Remove</button>").count(), 1, "{page}");
        assert!(
            page.contains("name=\"name\" value=\"old\"><button class=\"danger\">Remove"),
            "{page}"
        );
        assert!(!page.contains("_csrf"), "{page}");
        assert_eq!(
            target(&views, "gitlab", 1000).map(|(op, k)| (op, k.len())),
            Some((KeyOp::Revoke, 1))
        );
        assert_eq!(
            target(&views, "old", 1000).map(|(op, k)| (op, k.len())),
            Some((KeyOp::Remove, 1))
        );
        assert!(target(&views, "none", 1000).is_none());

        // Several that no longer work under one name: one button, on the newest, removing all.
        let views = [
            view(
                "ab",
                KeyRow {
                    revoked_at: Some(200),
                    ..key("gitlab")
                },
            ),
            view(
                "cd",
                KeyRow {
                    created_at: 300,
                    expires_at: 1000,
                    ..key("gitlab")
                },
            ),
            view(
                "ef",
                KeyRow {
                    created_at: 200,
                    revoked_at: Some(250),
                    ..key("gitlab")
                },
            ),
        ];
        let page = fragment(&views, 1000, true).into_string();
        assert_eq!(page.matches(">Remove</button>").count(), 1, "{page}");
        let newest = page.split("<td>gitlab</td>").nth(2).unwrap();
        let newest = newest.split("</tr>").next().unwrap();
        assert!(newest.contains(">Remove</button>"), "{page}");
        assert_eq!(
            target(&views, "gitlab", 1000).map(|(op, k)| (op, k.len())),
            Some((KeyOp::Remove, 3))
        );
    }
}
