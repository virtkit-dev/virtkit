//! Hub updates: the `/operations` section ([`updates`]) and `/hub/action` handler, using the
//! same update path as `vk-hub update` ([`crate::update`]).

use anyhow::Result;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use super::fleet::FleetSite;
use super::{Body, Ui, actions, field, updates};
use crate::server::Hub;
use crate::store::{Program, Role};

/// Where the hub's update is posted.
pub(super) const ACTION_PATH: &str = "/hub/action";

/// The one hub there is to update, by this ID.
const ID: &str = "hub";

/// The hub, as its update shows it, checked and started as `vk-hub update` starts it.
pub(super) static KIND: updates::Kind = updates::Kind {
    noun: "hub",
    heading: "Hub",
    column: "HUB",
    program: Program::Hub,
    note: "The hub copies the release and settles its jobs: it takes no new job, waits for \
           those queued to start on a node, and fails the update, changing nothing, should one \
           be left waiting. Then it stops accepting connections, which wait, and runs the \
           release in its place, handing it its listeners; pages and peers reconnect. A release \
           that does not come up is rolled back to the binary the hub ran once its supervisor \
           restarts <code>vk-hub serve</code>.",
    question: "Update the hub? It settles its jobs and runs the release in its place, \
               connections waiting meanwhile. If the release does not come up, the hub goes \
               back to the binary it runs now once its supervisor restarts it.",
    // Never offline: the hub serves the page.
    command_ttl: std::time::Duration::ZERO,
    allow: "<code>[update] allow</code>",
    allow_downgrade: "<code>[update] allow_downgrade</code>",
    started: |_, program, version, id| {
        format!(
            "The hub is updating itself to {program} {version} (update {id}); this page \
             reconnects once it runs the release."
        )
    },
    ops: updates::Ops {
        find: |hub, id| Ok((id == ID).then(|| peer(hub))),
        check: |hub, _, release| crate::update::check(hub, release),
        issue: |hub, actor, _, release, running| {
            crate::update::start_as_shown(hub, actor, release, running)
        },
    },
};

/// The hub as its update shows it.
fn peer(hub: &Hub) -> updates::Peer {
    let status = crate::update::status(hub);
    updates::Peer {
        id: ID.to_string(),
        hostname: "this hub".to_string(),
        page: None,
        action: ACTION_PATH.to_string(),
        version: Some(status.version),
        connected: true,
        takes_updates: status.allowed,
        allows_downgrade: Some(status.allows_downgrade),
        requires_signed: status.requires_signed,
        reported: status.update,
        last: status.last.map(|l| updates::Issued {
            id: l.id,
            version: l.version,
            issued_at: l.at,
            expires_at: u64::MAX,
            outcome: l.outcome,
        }),
    }
}

/// The hub, as `/operations` shows its update: none for a hub that does not update itself.
pub(super) fn updatables(hub: &Hub) -> Vec<updates::Peer> {
    let peer = peer(hub);
    if peer.takes_updates.is_none() {
        return Vec::new();
    }
    vec![peer]
}

/// `POST /hub/action`: `op=update`, an operator's update of the hub, asked again first.
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
    if field(&form, "op") != Some("update") {
        return Ok(actions::refused(
            htmx,
            StatusCode::BAD_REQUEST,
            "No such action.",
        ));
    }
    updates::update(ui, site, htmx, &auth, &form, &KIND, ID).await
}
