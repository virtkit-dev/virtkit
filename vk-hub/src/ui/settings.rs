//! `/settings`: fleet-wide and per-node settings, the hub's own `tools` among them, visible to
//! every viewer. Operators set
//! and unset them through the admin socket's operation ([`crate::settings::set`]), with
//! `vk-hub settings` validation and auditing as the session's principal.

use anyhow::Result;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};

use super::html::Html;
use super::pages::csrf_field;
use super::{Auth, Body, Ui, actions, blocking, field, page};
use crate::store::{NotEnrolled, Role, SettingsLayer, SettingsLayers};

/// The page, and where its forms post.
pub(super) const PATH: &str = "/settings";

/// What the page shows: every layer, and the nodes' names by ID.
struct Shown {
    layers: SettingsLayers,
    names: Vec<(String, String)>,
}

fn read(hub: &crate::server::Hub) -> Result<Shown> {
    Ok(Shown {
        layers: hub.db.settings_layers()?,
        names: hub.db.node_names()?,
    })
}

/// `GET /settings`.
pub(super) async fn get(auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    let hub = ui.hub.clone();
    let shown = blocking(move || read(&hub)).await?;
    let steer = auth.session.role >= Role::Operator;
    let mut main = Html::new();
    main.raw("<h1>Settings</h1><p class=\"sub\">What nodes take where their own config file ")
        .raw("leaves a setting unset. A node's own settings win over the fleet's.</p>");
    if steer {
        main.raw("<div id=\"flash\"></div>");
    }
    main.html(&layers_section(&shown, steer.then_some(auth), false));
    if steer {
        set_form(&mut main, auth, &shown.names);
    }
    keys_section(&mut main);
    Ok(page(super::fleet::layout("Settings", PATH, auth, &main)))
}

/// The layers, each setting with an Unset button for `auth`'s operator session; swapped in out
/// of band when `oob`.
fn layers_section(shown: &Shown, auth: Option<&Auth>, oob: bool) -> Html {
    let mut h = Html::new();
    h.raw("<section id=\"settings\"");
    if oob {
        h.raw(" hx-swap-oob=\"true\"");
    }
    h.raw("><h2>Fleet-wide</h2>");
    layer_table(&mut h, &shown.layers.fleet, None, auth);
    for (id, layer) in &shown.layers.nodes {
        let name = shown
            .names
            .iter()
            .find(|(n, _)| n == id)
            .map_or(id.as_str(), |(_, name)| name.as_str());
        h.raw("<h2>Node <a href=\"/node/")
            .text(id)
            .raw("\">")
            .node(name)
            .raw("</a></h2>");
        layer_table(&mut h, layer, Some(id), auth);
    }
    h.raw("</section>");
    h
}

fn layer_table(h: &mut Html, layer: &SettingsLayer, node: Option<&str>, auth: Option<&Auth>) {
    if layer.is_empty() {
        h.raw("<p class=\"empty\">none</p>");
        return;
    }
    h.raw("<table class=\"grid\"><thead><tr><th>setting</th><th>value</th>");
    if auth.is_some() {
        h.raw("<th></th>");
    }
    h.raw("</tr></thead><tbody>");
    for (key, value) in layer {
        h.raw("<tr><td><code>")
            .text(key)
            .raw("</code></td><td>")
            .text(crate::store::setting_shown(value))
            .raw("</td>");
        if let Some(auth) = auth {
            h.raw("<td class=\"actions\">");
            form_open(h, auth);
            h.raw("<input type=\"hidden\" name=\"op\" value=\"unset\">")
                .raw("<input type=\"hidden\" name=\"key\" value=\"")
                .text(key)
                .raw("\"><input type=\"hidden\" name=\"node\" value=\"")
                .text(node.unwrap_or(""))
                .raw("\"><button>Unset</button></form></td>");
        }
        h.raw("</tr>");
    }
    h.raw("</tbody></table>");
}

/// The start of a form posting to [`PATH`], by htmx or as a plain form.
fn form_open(h: &mut Html, auth: &Auth) {
    h.raw("<form method=\"post\" action=\"")
        .raw(PATH)
        .raw("\" hx-post=\"")
        .raw(PATH)
        .raw("\" hx-swap=\"none\">");
    csrf_field(h, auth);
}

/// The form setting a setting fleet-wide or for one of `names`' nodes.
fn set_form(h: &mut Html, auth: &Auth, names: &[(String, String)]) {
    h.raw("<section><h2>Set a setting</h2><form class=\"wide\" method=\"post\" action=\"")
        .raw(PATH)
        .raw("\" hx-post=\"")
        .raw(PATH)
        .raw("\" hx-swap=\"none\">");
    csrf_field(h, auth);
    h.raw("<input type=\"hidden\" name=\"op\" value=\"set\">")
        .raw("<select name=\"key\" aria-label=\"Setting\">");
    for key in crate::store::setting_keys() {
        h.raw("<option>").text(key).raw("</option>");
    }
    h.raw("</select><input type=\"text\" name=\"value\" aria-label=\"Value\" required ")
        .raw("autocomplete=\"off\" spellcheck=\"false\" placeholder=\"8G, 4, true…\">")
        .raw("<select name=\"node\" aria-label=\"For\"><option value=\"\">Fleet-wide</option>");
    for (id, name) in names {
        h.raw("<option value=\"")
            .text(id)
            .raw("\">")
            .node(name)
            .raw("</option>");
    }
    h.raw("</select><button class=\"primary\">Set</button></form></section>");
}

/// The settings the hub may set, and what each takes.
fn keys_section(h: &mut Html) {
    h.raw("<section><h2>What the hub may set</h2><table class=\"kv\"><tbody>");
    for (key, kind) in vk_hub_proto::settings::KEYS {
        let what = match kind {
            vk_hub_proto::settings::Kind::Registry => {
                "a registry's ID, as Storage lists it, once it has a URL"
            }
            kind => kind.describe(),
        };
        h.raw("<tr><th><code>")
            .text(key)
            .raw("</code></th><td>")
            .text(what)
            .raw("</td></tr>");
    }
    h.raw("<tr><th><code>")
        .text(crate::deploy::KEY)
        .raw("</code></th><td>")
        .text(format!(
            "the CI tools the hub builds on the nodes: {}",
            crate::deploy::DESCRIBE
        ))
        .raw("</td></tr>");
    h.raw("</tbody></table></section>");
}

/// `POST /settings`: `op=set` sets `key` to `value`, `op=unset` unsets it, fleet-wide or for
/// `node`, as the operator session's principal. For htmx, a status line and the layers
/// swapped in; for a plain form, back to the page or the refusal.
pub(super) async fn action(req: Request<Incoming>, ui: &Ui) -> Result<Response<Body>> {
    let htmx = req.headers().contains_key("hx-request");
    let (auth, form) = match super::check_post(req, ui, Role::Operator).await? {
        Ok(checked) => checked,
        Err((status, text)) => return Ok(actions::refused(htmx, status, text)),
    };
    let key = field(&form, "key").unwrap_or("").to_string();
    let node = field(&form, "node")
        .filter(|n| !n.is_empty())
        .map(str::to_string);
    if node.as_deref().is_some_and(|n| !vk_hub_proto::valid_id(n)) {
        return Ok(actions::refused(
            htmx,
            StatusCode::NOT_FOUND,
            "There is no such node.",
        ));
    }
    let value = match field(&form, "op") {
        Some("set") => match crate::settings::parse(&key, field(&form, "value").unwrap_or("")) {
            Ok(value) => Some(value),
            Err(e) => {
                return Ok(actions::refused(
                    htmx,
                    StatusCode::BAD_REQUEST,
                    &format!("Refused: {e:#}."),
                ));
            }
        },
        Some("unset") => None,
        _ => {
            return Ok(actions::refused(
                htmx,
                StatusCode::BAD_REQUEST,
                "No such action.",
            ));
        }
    };
    let principal = auth.session.principal();
    let hub = ui.hub.clone();
    let (k, n, v) = (key.clone(), node.clone(), value.clone());
    let done = blocking(move || {
        let done = crate::settings::set(&hub, &principal, n.as_deref(), &k, v);
        Ok((done, read(&hub)?))
    })
    .await?;
    let (changed, shown) = match done {
        (Ok(changed), shown) => (changed, shown),
        (Err(e), _) if e.is::<NotEnrolled>() => {
            return Ok(actions::refused(
                htmx,
                StatusCode::NOT_FOUND,
                "There is no such node.",
            ));
        }
        (Err(e), _) => {
            return Ok(actions::refused(
                htmx,
                StatusCode::BAD_REQUEST,
                &format!("Refused: {e:#}."),
            ));
        }
    };
    if !htmx {
        let mut resp = Response::new(Body::default());
        *resp.status_mut() = StatusCode::SEE_OTHER;
        resp.headers_mut()
            .insert(header::LOCATION, HeaderValue::from_static(PATH));
        return Ok(resp);
    }
    let scope = match &node {
        Some(id) => {
            let name = shown
                .names
                .iter()
                .find(|(n, _)| n == id)
                .map_or(id.as_str(), |(_, name)| name.as_str());
            format!(" for {}", vk_hub_proto::display_safe(name))
        }
        None => " fleet-wide".to_string(),
    };
    let said = match (changed, &value) {
        (false, _) => "Nothing changed: it was already set that way.".to_string(),
        (true, Some(v)) => format!("Set {key} to {}{scope}.", crate::store::setting_shown(v)),
        (true, None) => format!("Unset {key}{scope}."),
    };
    let mut h = Html::new();
    h.raw("<div id=\"flash\" hx-swap-oob=\"true\">")
        .text(&said)
        .raw("</div>")
        .html(&layers_section(&shown, Some(&auth), true));
    Ok(actions::swap_none(super::html_response(StatusCode::OK, h)))
}
