//! Claimed admissions and relay session turnover, across hub restarts.

use super::*;
use vk_hub_proto::client::ReservationTicket;
use vk_hub_proto::gitlab::{Heartbeat as RelayHeartbeat, RunnerLoad};

/// Report `key`'s current-session heartbeat: the first runner lists `requests` as its
/// request admissions; all other runners list none.
fn report(hub: &Hub, key: &str, requests: &[&str]) {
    let session = hub.current_session(relay_id(key));
    let inventory = hub
        .db
        .relay(relay_id(key))
        .unwrap()
        .unwrap()
        .inventory
        .unwrap();
    let runners = inventory
        .runners
        .iter()
        .enumerate()
        .map(|(i, runner)| {
            let listed: Vec<String> = match i {
                0 => requests.iter().map(|r| r.to_string()).collect(),
                _ => Vec::new(),
            };
            RunnerLoad {
                name: runner.name.clone(),
                requests: u32::try_from(listed.len()).unwrap(),
                request_admissions: listed,
                ..Default::default()
            }
        })
        .collect();
    hub.db
        .record_relay_from_session(
            relay_id(key),
            crate::store::RelayWrite::Heartbeat(RelayHeartbeat { runners }),
            now_secs(),
            session,
            || true,
        )
        .unwrap();
    if let Some(session) = session {
        hub.heartbeat_stored(relay_id(key), session, tokio::time::Instant::now());
    }
}

/// Queue a request of `key`'s relay for runner `runner`: its ticket.
async fn queue_runner(addr: SocketAddr, key: &str, n: u8, runner: &str) -> String {
    let mut body = reservation_body(n, 0);
    body["queue"] = json!(true);
    body["runner"] = json!(runner);
    let reply = api(addr, "POST", "/v1/reservations", Some(key), Some(body)).await;
    assert_eq!(reply.status, 202, "{reply:?}");
    reply.json::<ReservationTicket>().ticket
}

#[tokio::test]
async fn a_claimed_admission_keeps_its_lane_and_class_across_a_restart_and_change() {
    let dir = scratch("capacity-recovery");
    let db = Arc::new(Db::open_memory().unwrap());
    let (addr, hub) = serve_hub(Arc::clone(&db), &dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    let id = relay_id(&key);
    let mut policy = db.capacity_policy().unwrap();
    lane_42(&mut policy).max_slots = Some(1);
    policy.probe_limit = 2;
    db.set_capacity_policy(&policy, "tests", now_secs())
        .unwrap();
    report(&hub, &key, &[]);
    let mut node = ready_node(addr, &hub, 8192).await;
    let ticket = queue_runner(addr, &key, 1, "test").await;
    let HubJobMsg::Offer { reservation, .. } = node.job().await else {
        panic!("expected offer")
    };
    node.send(NodeJobMsg::OfferReply {
        reservation: reservation.clone(),
        reply: OfferReply::Accepted { lease_secs: 90 },
    });
    let path = format!("/v1/reservations/tickets/{ticket}?wait=10");
    let reply = api(addr, "GET", &path, Some(&key), None).await;
    assert_eq!(reply.status, 201, "{reply:?}");
    let path = format!("/v1/reservations/{reservation}/claim");
    let reply = api(addr, "POST", &path, Some(&key), None).await;
    assert_eq!(reply.status, 204, "{reply:?}");
    assert!(db.admission(&ticket).unwrap().is_some());

    // Its lane is now production; a new hub holds no ticket or node lease of the old one.
    let lane = lane_42(&mut policy);
    lane.class = crate::policy::Class::Production;
    for p in lane.projects.iter_mut().flatten() {
        p.branches = Some(vec!["main".into()]);
    }
    db.set_capacity_policy(&policy, "tests", now_secs())
        .unwrap();
    let (addr, hub) = serve_hub(Arc::clone(&db), &dir, Duration::from_secs(30)).await;
    hub.open_session(id);
    let _node = ready_node(addr, &hub, 8192).await;
    let waiting = queue_runner(addr, &key, 2, "test").await;
    // The stored heartbeat predates this session; omitting the claim cannot release it.
    assert_eq!(
        reason_now(&hub, 42).await,
        Some("awaiting relay reconciliation")
    );
    assert!(db.admission(&ticket).unwrap().is_some());
    // Listed, it is still charged to its lane, at its max slots.
    report(&hub, &key, &[&ticket]);
    assert_eq!(reason_now(&hub, 42).await, Some("lane at max slots"));
    let reply = api(
        addr,
        "GET",
        &format!("/v1/reservations/tickets/{waiting}"),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(reply.status, 202, "{reply:?}");
    // A job on it keeps the identity it was admitted under.
    let mut body = job_body(3, None, 30);
    body["admission"] = json!(ticket);
    body["spec"]["sources"]["ref"] = json!("main");
    body["spec"]["sources"]["refspecs"] = json!(["+refs/heads/main:refs/remotes/origin/main"]);
    let reply = api(addr, "POST", "/v1/jobs", Some(&key), Some(body)).await;
    assert_eq!(reply.status, 201, "{reply:?}");
    let job = reply.json::<JobView>();
    let identity = db.job(&job.id).unwrap().unwrap().scheduling.unwrap();
    assert_eq!(
        identity.lane,
        crate::policy::LaneId::Runner {
            gitlab: "gl".into(),
            id: 42
        }
    );
    assert_eq!(identity.class, crate::policy::Class::Normal);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn closing_old_session_preserves_new_session_tickets() {
    let dir = scratch("capacity-session-epoch");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    relay_limits(&hub, &key, 64, 2);
    let id = relay_id(&key);
    let old = hub.current_session(id).unwrap();
    let first = queue_runner(addr, &key, 1, "test").await;
    let (new, _) = hub.open_session(id);
    report(&hub, &key, &[]);
    let second = queue_runner(addr, &key, 2, "test").await;
    crate::jobs::relay_disconnected(&hub, id, old);
    assert_ne!(old, new);
    let reply = api(
        addr,
        "GET",
        &format!("/v1/reservations/tickets/{second}"),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(reply.status, 202, "{reply:?}");
    let reply = api(
        addr,
        "GET",
        &format!("/v1/reservations/tickets/{first}"),
        Some(&key),
        None,
    )
    .await;
    // Released with the session that asked for it: ended, as an unknown ticket is.
    assert_eq!(
        (reply.status, reply.code()),
        (410, ErrorCode::ReservationGone),
        "{reply:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
