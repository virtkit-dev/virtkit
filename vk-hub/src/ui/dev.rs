//! `/dev` lists the host's dev environments on page load using `vk dev list`, including
//! stopped environments omitted by `vk workloads`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use hyper::Response;
use serde::Deserialize;

use super::html::Html;
use super::pages;
use super::{Auth, Body, Ui};
use crate::local::{Keep, Local};
use crate::server::Hub;

/// Timeout for `vk dev list` while a page waits for it.
const LIST_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for waiting on another page's listing. Longer than `LIST_TIMEOUT` so an
/// in-progress listing has time to finish.
const LIST_WAIT: Duration = Duration::from_secs(40);

/// How long to reuse a listing unless the hub reports a change.
const LIST_FRESH: Duration = Duration::from_secs(5);

/// Whether `name` is a dev environment's name as `vk dev list` gives one: its state dir's
/// own name, never an option's shape. A row named otherwise is not shown.
pub(super) fn valid_dev_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with(['.', '-'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// One row of `vk dev list --json`: the fields this page reads, whose names are that
/// command's interface and are only ever added to.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct DevRow {
    pub name: String,
    pub workspace: Option<String>,
    pub environment: Option<String>,
    pub status: String,
    #[serde(default)]
    pub booted_secs: Option<u64>,
    #[serde(default)]
    pub flags: Vec<String>,
}

/// What `vk dev list` last listed, or why it could not.
pub(super) type Rows = Arc<Result<Vec<DevRow>, String>>;

/// The last `vk dev list`, one run at a time: a load that finds one under way waits for it
/// and shows what it read.
pub(super) struct DevList(tokio::sync::Mutex<Option<Listed>>);

struct Listed {
    at: Instant,
    /// The hub's change count it was read at.
    change: u64,
    rows: Rows,
}

impl DevList {
    pub(super) fn new() -> Self {
        DevList(tokio::sync::Mutex::new(None))
    }

    /// The environments, as read within `fresh` with nothing changed since, or read now. A
    /// failure is not kept: the next load tries again.
    pub(super) async fn get(&self, local: &Local, hub: &Hub, fresh: Duration) -> Rows {
        let Ok(mut held) = tokio::time::timeout(LIST_WAIT, self.0.lock()).await else {
            return Arc::new(Err(
                "Not read: another page is listing them; reload in a moment.".to_string(),
            ));
        };
        let change = *hub.subscribe().borrow();
        if let Some(l) = held
            .as_ref()
            .filter(|l| l.change == change && l.at.elapsed() < fresh)
        {
            return l.rows.clone();
        }
        let rows = Arc::new(dev_rows(local).await);
        if rows.is_ok() {
            *held = Some(Listed {
                at: Instant::now(),
                change,
                rows: rows.clone(),
            });
        }
        rows
    }
}

/// Every dev environment this host keeps state for, by `vk dev list`, or why there is none.
async fn dev_rows(local: &Local) -> Result<Vec<DevRow>, String> {
    let out = local
        .run(
            &[
                "dev".as_ref(),
                "list".as_ref(),
                "--json".as_ref(),
                "--no-sizes".as_ref(),
            ],
            LIST_TIMEOUT,
            Keep::Head,
        )
        .await
        .map_err(|e| format!("{e:#}"))?;
    if out.cut {
        return Err(format!("`vk dev list` printed too much: {}", out.status));
    }
    if !out.ok {
        return Err(format!(
            "`vk dev list` {}: {}",
            out.status,
            out.stderr.trim()
        ));
    }
    let rows: Vec<DevRow> = serde_json::from_str(&out.stdout)
        .map_err(|e| format!("`vk dev list` printed something this vk-hub cannot read: {e}"))?;
    Ok(rows
        .into_iter()
        .filter(|r| valid_dev_name(&r.name))
        .collect())
}

/// `GET /dev`.
pub(super) async fn page(auth: &Auth, ui: &Ui) -> Response<Body> {
    let rows = ui.dev_list.get(&ui.local, &ui.hub, LIST_FRESH).await;
    let mut main = Html::new();
    main.raw("<h1>Dev environments</h1>");
    match &*rows {
        Err(why) => {
            main.raw("<p class=\"notes\">").node(why).raw("</p>");
        }
        Ok(rows) if rows.is_empty() => {
            main.raw("<p class=\"empty\">This host keeps no dev environment.</p>");
        }
        Ok(rows) => table(&mut main, rows),
    }
    main.raw("<p class=\"sub\">Read as the page loads; <a href=\"/dev\">reload</a> for newer.</p>");
    super::page(pages::layout("dev environments", auth, &main))
}

fn table(h: &mut Html, rows: &[DevRow]) {
    h.raw("<table class=\"grid\"><thead><tr><th>NAME</th><th>STATUS</th><th>WORKSPACE</th>")
        .raw("<th>ENV</th><th>BOOTED</th><th>FLAGS</th></tr></thead><tbody>");
    for r in rows {
        let dash = pages::dash;
        h.raw("<tr><td>")
            .node(&r.name)
            .raw("</td><td>")
            .node(&r.status)
            .raw("</td><td>")
            .node(r.workspace.as_deref().unwrap_or("-"))
            .raw("</td><td>")
            .node(r.environment.as_deref().unwrap_or("-"))
            .raw("</td><td>")
            .text(r.booted_secs.map_or_else(dash, pages::started))
            .raw("</td><td>")
            .node(&r.flags.join(", "))
            .raw("</td></tr>");
    }
    h.raw("</tbody></table>");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_checked() {
        assert!(valid_dev_name("wab-12.0-4c56c17b88a2af17"));
        for bad in [
            "",
            ".",
            "..",
            ".hidden",
            "-a",
            "--all-stale",
            "a/b",
            "a b",
            "a\n",
        ] {
            assert!(!valid_dev_name(bad), "{bad:?}");
        }
    }
}
