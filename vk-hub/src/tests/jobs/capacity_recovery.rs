//! Ending an old relay session preserves the new session's tickets.

use super::*;
use vk_hub_proto::client::ReservationTicket;
use vk_hub_proto::gitlab::{Heartbeat as RelayHeartbeat, RunnerLoad};

/// A heartbeat of `key`'s relay in its current session, listing no admission.
fn report(hub: &Hub, key: &str) {
    let session = hub.current_session(relay_id(key));
    hub.db
        .record_relay_from_session(
            relay_id(key),
            crate::store::RelayWrite::Heartbeat(RelayHeartbeat {
                runners: vec![RunnerLoad {
                    name: "test".into(),
                    ..Default::default()
                }],
            }),
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
async fn closing_old_session_preserves_new_session_tickets() {
    let dir = scratch("capacity-session-epoch");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    relay_limits(&hub, &key, 64, 2);
    let id = relay_id(&key);
    let old = hub.current_session(id).unwrap();
    let first = queue_runner(addr, &key, 1, "test").await;
    let (new, _) = hub.open_session(id);
    report(&hub, &key);
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
