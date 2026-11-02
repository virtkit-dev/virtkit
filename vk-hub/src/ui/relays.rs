//! GitLab relay updates: the `/operations` section ([`updates`]) and `/relay/<id>/action`
//! handler, using the same operation as `vk-hub relays update`. The relay list is on `/relays`
//! ([`super::clients`]).

use anyhow::Result;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use vk_hub_proto::gitlab::Operation;

use super::fleet::FleetSite;
use super::{Body, Ui, actions, field, updates};
use crate::relays::{self as ops, RelayView};
use crate::server::Hub;
use crate::store::{NotEnrolled, Program, RelayCommandRow, Role};

/// Where a relay's update is posted: this, its ID, then `/action`.
const PREFIX: &str = "/relay/";

/// The relay `/relay/<id>/action` is for, if `path` is that for a well-formed ID.
pub(super) fn action_target(path: &str) -> Option<&str> {
    path.strip_prefix(PREFIX)?
        .strip_suffix("/action")
        .filter(|id| vk_hub_proto::valid_id(id))
}

/// Relays, as their updates show them, looked up, checked and issued as `vk-hub relays update`
/// issues them.
pub(super) static KIND: updates::Kind = updates::Kind {
    noun: "relay",
    heading: "GitLab adapters",
    column: "ADAPTER",
    program: Program::Gitlab,
    note: "A relay downloads the release and stops asking GitLab for jobs. Once its requests \
           out to GitLab have ended, the relay restarts on the release. Its running jobs go on, \
           and their logs resume where GitLab has them. If the release does not come up, the \
           relay rolls back to the binary it ran before, once the relay's supervisor restarts \
           it.",
    question: "Update this relay? The relay stops asking GitLab for jobs and restarts on the \
               release. Its running jobs go on. If the release does not come up, the relay goes \
               back to the binary it ran before, once its supervisor restarts it.",
    command_ttl: ops::COMMAND_TTL,
    allow: "<code>[hub] allow</code>, which lacks <code>update</code>",
    allow_downgrade: "<code>[hub] allow_downgrade</code>",
    started: updates::sent,
    ops: updates::Ops {
        find: |hub, id| {
            let Some(view) = ops::detail(hub, id)? else {
                return Ok(None);
            };
            let last = last_update(hub, id)?;
            Ok(Some(peer(view, last)))
        },
        check: |hub, id, release| {
            let row = hub
                .db
                .relay(id)?
                .ok_or_else(|| NotEnrolled(id.to_string()))?;
            ops::check_update(&row, release)
        },
        issue: |hub, actor, id, release, running| {
            ops::update_as_shown(hub, actor, id, release, running).map(|c| c.id)
        },
    },
};

/// The last update the hub issued relay `id`.
fn last_update(hub: &Hub, id: &str) -> Result<Option<RelayCommandRow>> {
    Ok(hub.db.relay_commands(id)?.into_iter().max_by_key(|c| c.seq))
}

/// Relay `v` as its update shows it, `last` the last update the hub issued it.
fn peer(v: RelayView, last: Option<RelayCommandRow>) -> updates::Peer {
    let inventory = v.row.inventory.as_ref();
    updates::Peer {
        page: None,
        action: format!("{PREFIX}{}/action", v.id),
        hostname: v.row.hostname.clone(),
        version: inventory.map(|i| i.version.clone()),
        connected: v.connected,
        takes_updates: ops::takes_updates(&v.row),
        allows_downgrade: None,
        requires_signed: inventory.is_some_and(|i| i.requires_signed),
        reported: v.row.report.as_ref().and_then(|r| r.update.clone()),
        last: last.map(|c| {
            let Operation::Update { version, .. } = c.command.op;
            updates::Issued {
                id: c.command.id,
                version,
                issued_at: c.issued_at,
                expires_at: c.command.expires_at,
                outcome: c.outcome,
            }
        }),
        id: v.id,
    }
}

/// Every relay as `/operations` shows its update, with the last one the hub issued it.
pub(super) fn updatables(hub: &Hub) -> Result<Vec<updates::Peer>> {
    ops::views(hub)?
        .into_iter()
        .map(|view| {
            let last = last_update(hub, &view.id)?;
            Ok(peer(view, last))
        })
        .collect()
}

/// `POST /relay/<id>/action`: `op=update`, an operator's update of the relay, asked again first.
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
    if field(&form, "op") != Some("update") {
        return Ok(actions::refused(
            htmx,
            StatusCode::BAD_REQUEST,
            "No such action.",
        ));
    }
    updates::update(ui, site, htmx, &auth, &form, &KIND, id).await
}
