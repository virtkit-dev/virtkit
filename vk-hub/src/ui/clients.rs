//! `/clients`: the API keys the client API takes and the client instances using each — the
//! host, program and runners an instance's hello named, when it was last heard from and what
//! it holds — for viewers and operators alike, read only: `vk-hub keys` creates and revokes
//! keys. Its fragment is rendered once for all open pages ([`sse::feed`]), on a key created,
//! revoked or removed, an instance heard from anew, a hello recorded or instances pruned
//! ([`Hub::clients_changed`]), and, while a page is open, once a heartbeat interval, which
//! moves the ages and what the instances hold.

use std::sync::Arc;

use anyhow::Result;
use hyper::Response;

use super::html::Html;
use super::pages;
use super::sse;
use super::{Auth, Body, Ui, blocking, page};
use crate::clients::{InstanceView, KeyView};
use crate::server::Hub;
use crate::store::{ANY_POOL, CLIENT_ACTIVE_SECS, KeyRow};

/// The page.
pub(super) const PATH: &str = "/clients";

/// The event its fragment is swapped in on, and its stream's name under `/events/`.
pub(super) const EVENT: &str = "clients";

/// `GET /clients`.
pub(super) async fn get(auth: &Auth, ui: &Ui) -> Result<Response<Body>> {
    let hub = ui.hub.clone();
    let views = blocking(move || crate::clients::views(&hub)).await?;
    let mut main = Html::new();
    main.raw("<h1>Clients</h1><div id=\"clients\" hx-ext=\"sse\" ")
        .raw("sse-connect=\"/events/clients\" sse-swap=\"clients\" sse-close=\"close\">")
        .html(&fragment(&views, crate::now_secs()))
        .raw("</div>");
    Ok(page(super::fleet::layout("Clients", PATH, auth, &main)))
}

/// The fragment, as one rendering for every page showing it.
pub(super) fn events(hub: &Arc<Hub>) -> sse::Events {
    let hub = hub.clone();
    let render: sse::Render = Arc::new(move || {
        let views = crate::clients::views(&hub)?;
        Ok(fragment(&views, crate::now_secs()).into_string())
    });
    sse::Events::from([(EVENT, render)])
}

/// The keys, then their instances.
fn fragment(views: &[KeyView], now: u64) -> Html {
    let mut h = Html::new();
    h.raw("<section><h2>API keys</h2>");
    if views.is_empty() {
        h.raw("<p class=\"empty\">none: <code>vk-hub keys create</code> creates one</p>");
    } else {
        h.raw("<table class=\"grid\"><thead><tr><th>name</th><th>key</th><th>scopes</th>")
            .raw("<th>pools</th><th>largest</th><th>created</th><th>by</th><th>state</th>")
            .raw("<th>last heard</th><th class=\"num\">instances</th>")
            .raw("<th class=\"num\">jobs</th></tr></thead><tbody>");
        for v in views {
            key_row(&mut h, v, now);
        }
        h.raw("</tbody></table>");
    }
    h.raw("</section><section><h2>Instances</h2>");
    if views.iter().all(|v| v.instances.is_empty()) {
        h.raw("<p class=\"empty\">none: no client has used a key yet</p>");
    } else {
        h.raw("<table class=\"grid\"><thead><tr><th>key</th><th>host</th><th>instance</th>")
            .raw("<th>program</th><th>runners</th><th>last heard</th>")
            .raw("<th class=\"num\">reservations</th><th class=\"num\">queued</th>")
            .raw("<th class=\"num\">running</th></tr></thead><tbody>");
        for v in views {
            for i in &v.instances {
                instance_row(&mut h, &v.row, i, now);
            }
        }
        h.raw("</tbody></table>");
    }
    h.raw("</section>");
    h
}

fn key_row(h: &mut Html, v: &KeyView, now: u64) {
    let k = &v.row;
    let scopes: Vec<&str> = k.scopes.iter().map(|s| s.name()).collect();
    let pools: Vec<&str> = (k.pools.iter())
        .map(|p| if p == ANY_POOL { "any" } else { p })
        .collect();
    h.raw("<tr><td>")
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
        Some(t) => heard_at(h, now, t),
        None => {
            h.raw("-");
        }
    }
    h.raw("</td><td class=\"num\">")
        .text(v.instances.len())
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
    h.raw("</td></tr>");
}

/// Instance `i` of key `key`: all that it said made display-safe again ([`Html::node`]), a
/// runner's URL linked only when it is a plain web link.
fn instance_row(h: &mut Html, key: &KeyRow, i: &InstanceView, now: u64) {
    let r = &i.row;
    h.raw("<tr><td>").text(&key.name).raw("</td><td>");
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
        heard_at(h, now, r.last_seen);
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

/// When `then` was, marked connected when within [`CLIENT_ACTIVE_SECS`] of `now`.
fn heard_at(h: &mut Html, now: u64, then: u64) {
    if now.saturating_sub(then) <= CLIENT_ACTIVE_SECS {
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
        let page = fragment(&views, 1000).into_string();
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

        let none = fragment(&[], 1000).into_string();
        assert!(none.contains("<code>vk-hub keys create</code>"), "{none}");
        assert!(none.contains("no client has used a key yet"), "{none}");
    }
}
