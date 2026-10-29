//! Capacity queue behavior over the client and node protocols.

use super::*;
use vk_hub_proto::client::ReservationTicket;

/// Have `key`'s relay connected, in a session, its heartbeat listing nothing it holds.
pub(super) fn ready_relay(hub: &Hub, key: &str) {
    if hub.current_session(relay_id(key)).is_none() {
        hub.open_session(relay_id(key));
    }
    heartbeat(hub, key, now_secs(), 0);
}

/// A heartbeat of `key`'s relay in its current session, received `at`, listing no admission
/// and `jobs` jobs held by each of its runners.
fn heartbeat(hub: &Hub, key: &str, at: u64, jobs: u32) {
    heartbeat_in(hub, key, at, hub.current_session(relay_id(key)), &[], jobs);
}

/// A heartbeat of `key`'s relay tagged with `session`, received `at` (a time past now is as
/// far ahead on the hub's monotonic clock), its first runner listing `requests` as the
/// admissions it requests work under, and each runner `jobs` jobs held.
fn heartbeat_in(hub: &Hub, key: &str, at: u64, session: Option<u64>, requests: &[&str], jobs: u32) {
    let ahead = Duration::from_secs(at.saturating_sub(now_secs()));
    let received = tokio::time::Instant::now() + ahead;
    heartbeat_received(hub, key, at, received, session, requests, jobs);
}

/// [`heartbeat_in`], stamped `at` by the relay's wall clock but received `received` by the
/// hub's monotonic one.
fn heartbeat_received(
    hub: &Hub,
    key: &str,
    at: u64,
    received: tokio::time::Instant,
    session: Option<u64>,
    requests: &[&str],
    jobs: u32,
) {
    let id = relay_id(key);
    let inventory = hub.db.relay(id).unwrap().unwrap().inventory.unwrap();
    let runners = inventory
        .runners
        .iter()
        .enumerate()
        .map(|(i, runner)| {
            let listed: Vec<String> = match i {
                0 => requests.iter().map(|r| r.to_string()).collect(),
                _ => Vec::new(),
            };
            vk_hub_proto::gitlab::RunnerLoad {
                name: runner.name.clone(),
                jobs,
                requests: u32::try_from(listed.len()).unwrap(),
                request_admissions: listed,
                ..Default::default()
            }
        })
        .collect();
    hub.db
        .record_relay_from_session(
            id,
            crate::store::RelayWrite::Heartbeat(vk_hub_proto::gitlab::Heartbeat { runners }),
            at,
            session,
            || true,
        )
        .unwrap();
    if let Some(session) = session {
        hub.heartbeat_stored(id, session, received);
    }
}

/// Waits for the reason the hub gives for not granting runner 42's waiting request.
async fn wait_reason(hub: &Hub, reason: &str) {
    wait_reason_of(hub, 42, reason).await;
}

/// Waits for the reason the hub gives for not granting the waiting request of runner
/// `runner_id` of GitLab instance `gl`.
async fn wait_reason_of(hub: &Hub, runner_id: u64, reason: &str) {
    for _ in 0..1500 {
        let snapshot = crate::jobs::arbitration_snapshot(hub).unwrap();
        if snapshot
            .get(&("gl".to_string(), runner_id))
            .is_some_and(|v| v.reason == Some(reason))
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the request never waited for {reason:?}");
}

/// Give `key`'s relay a second runner, `name` with GitLab runner ID `runner_id`, mapped to
/// tenant `tests` in `class`.
fn add_runner(hub: &Hub, key: &str, name: &str, runner_id: u64, class: crate::policy::Class) {
    let id = relay_id(key);
    let mut inventory = hub.db.relay(id).unwrap().unwrap().inventory.unwrap();
    let mut runner = inventory.runners[0].clone();
    runner.name = name.into();
    runner.runner_id = Some(runner_id);
    inventory.runners.push(runner);
    hub.db
        .record_relay(
            id,
            crate::store::RelayWrite::Inventory(inventory),
            now_secs(),
        )
        .unwrap();
    let mut policy = hub.db.capacity_policy().unwrap();
    policy.runners.push(crate::policy::RunnerMapping {
        gitlab: "gl".into(),
        runner_id,
        tenant: "tests".into(),
        class,
    });
    hub.db
        .set_capacity_policy(&policy, "u", now_secs())
        .unwrap();
}

/// Queue request `n` of `key`'s runner `test`: its ticket.
pub(super) async fn queue(addr: SocketAddr, key: &str, n: u8) -> String {
    queue_for(addr, key, n, "test").await
}

/// Queue request `n` of `key`'s runner `runner`: its ticket.
async fn queue_for(addr: SocketAddr, key: &str, n: u8, runner: &str) -> String {
    let mut body = reservation_body(n, 0);
    body["queue"] = json!(true);
    body["runner"] = json!(runner);
    let answer = api(addr, "POST", "/v1/reservations", Some(key), Some(body)).await;
    assert_eq!(answer.status, 202, "{answer:?}");
    answer.json::<ReservationTicket>().ticket
}

/// `GET` ticket `ticket` of `key`, long-polling for at most `wait` seconds.
async fn poll(addr: SocketAddr, key: &str, ticket: &str, wait: u32) -> Resp {
    let path = format!("/v1/reservations/tickets/{ticket}?wait={wait}");
    api(addr, "GET", &path, Some(key), None).await
}

/// Accept the offer `node` is sent for ticket `ticket`, and long-poll the ticket until it is
/// granted.
pub(super) async fn accept_ticket(
    addr: SocketAddr,
    key: &str,
    ticket: &str,
    node: &mut FakeNode,
) -> ReservationGrant {
    let HubJobMsg::Offer { reservation, .. } = node.job().await else {
        panic!("expected offer")
    };
    node.send(NodeJobMsg::OfferReply {
        reservation,
        reply: OfferReply::Accepted { lease_secs: 90 },
    });
    for _ in 0..3 {
        let answer = poll(addr, key, ticket, 10).await;
        if answer.status == 201 {
            return answer.json();
        }
        assert_eq!(answer.status, 202, "{answer:?}");
    }
    panic!("grant did not arrive")
}

/// Claim `grant` as `key`'s relay.
async fn claim(addr: SocketAddr, key: &str, grant: &ReservationGrant) -> Resp {
    let path = format!("/v1/reservations/{}/claim", grant.reservation);
    api(addr, "POST", &path, Some(key), None).await
}

/// Report `outcome` for admission `admission` as `key`'s relay, naming `named` in the body.
async fn outcome(addr: SocketAddr, key: &str, admission: &str, named: &str, what: &str) -> Resp {
    api(
        addr,
        "POST",
        &format!("/v1/reservations/{admission}/outcome"),
        Some(key),
        Some(json!({"admission": named, "outcome": what})),
    )
    .await
}

#[tokio::test]
async fn queue_retries_claim_and_outcome_are_idempotent() {
    let dir = scratch("capacity-lifecycle");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let mut node = ready_node(addr, &hub, 8192).await;
    let ticket = queue(addr, &key, 1).await;
    assert_eq!(queue(addr, &key, 1).await, ticket);
    let grant = accept_ticket(addr, &key, &ticket, &mut node).await;
    assert_eq!(grant.admission.as_deref(), Some(ticket.as_str()));
    for _ in 0..2 {
        let reply = claim(addr, &key, &grant).await;
        assert_eq!(reply.status, 204, "{reply:?}");
    }
    for _ in 0..2 {
        let reply = outcome(addr, &key, &ticket, &ticket, "empty").await;
        assert_eq!(reply.status, 204, "{reply:?}");
    }
    assert_eq!(crate::jobs::testing::reservations(&hub), 0);
    assert_eq!(
        node.job().await,
        HubJobMsg::Release {
            reservation: grant.reservation
        }
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_runner_queues_no_more_requests_than_its_request_concurrency() {
    let dir = scratch("capacity-request-concurrency");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    // No node: the first request waits, and holds the runner's one request.
    queue(addr, &key, 1).await;
    let mut body = reservation_body(2, 0);
    body["queue"] = json!(true);
    body["runner"] = json!("test");
    let reply = api(addr, "POST", "/v1/reservations", Some(&key), Some(body)).await;
    assert_eq!(
        (reply.status, reply.code()),
        (503, ErrorCode::Unavailable),
        "{reply:?}"
    );
    // Its relay allows two.
    relay_limits(&hub, &key, 64, 2);
    queue(addr, &key, 3).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn queued_grants_go_to_the_least_loaded_node() {
    let dir = scratch("capacity-spread");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    // Memory for eight envelopes, and for four.
    let mut big = ready_node(addr, &hub, 32768).await;
    let mut small = ready_node(addr, &hub, 16384).await;
    // Both empty: the roomier first, then the one with the smaller share of placed work. Each
    // admission takes a job, so the runner is busy and the next request no probe.
    for n in 1..=4 {
        let node = if n % 2 == 1 { &mut big } else { &mut small };
        let ticket = queue(addr, &key, n).await;
        let grant = accept_ticket(addr, &key, &ticket, node).await;
        assert_eq!(grant.node, node.id, "request {n}");
        assert_eq!(claim(addr, &key, &grant).await.status, 204);
        let reply = outcome(addr, &key, &ticket, &ticket, "job").await;
        assert_eq!(reply.status, 204, "{reply:?}");
    }
    assert_eq!(
        (
            crate::jobs::placed_on(&hub, &big.id),
            crate::jobs::placed_on(&hub, &small.id),
        ),
        (2, 2)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn idle_lanes_share_one_fleet_wide_probe() {
    let dir = scratch("capacity-probes");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    add_runner(
        &hub,
        &key,
        "production",
        43,
        crate::policy::Class::Production,
    );
    ready_relay(&hub, &key);
    let normal = queue(addr, &key, 1).await;
    let production = queue_for(addr, &key, 2, "production").await;
    let mut node = ready_node(addr, &hub, 16384).await;
    let grant = accept_ticket(addr, &key, &normal, &mut node).await;
    assert_eq!(grant.admission.as_deref(), Some(normal.as_str()));
    // The other runner's request waits on the probe out, not for a node.
    wait_reason_of(&hub, 43, "shared probe budget").await;
    let snapshot = crate::jobs::arbitration_snapshot(&hub).unwrap();
    assert_eq!(snapshot.get(&("gl".to_string(), 43)).unwrap().waiting, 1);
    let answer = poll(addr, &key, &production, 0).await;
    assert_eq!(answer.status, 202, "{answer:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn unmapped_runner_is_refused_before_an_offer() {
    let dir = scratch("capacity-unmapped");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let mut policy = hub.db.capacity_policy().unwrap();
    policy.runners.clear();
    hub.db
        .set_capacity_policy(&policy, "u", now_secs())
        .unwrap();
    let mut node = ready_node(addr, &hub, 8192).await;
    let mut body = reservation_body(1, 0);
    body["queue"] = json!(true);
    let reply = api(addr, "POST", "/v1/reservations", Some(&key), Some(body)).await;
    assert_eq!(reply.status, 403, "{reply:?}");
    node.quiet(Duration::from_millis(200)).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn an_api_key_cannot_name_a_relay_runner() {
    let dir = scratch("capacity-key-runner");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = plain_key(&hub);
    for (path, mut body) in [
        ("/v1/capacity", json!({"placement": placement()})),
        ("/v1/reservations", reservation_body(1, 0)),
    ] {
        body["runner"] = json!("test");
        let reply = api(addr, "POST", path, Some(&key), Some(body)).await;
        assert_eq!(
            (reply.status, reply.code()),
            (403, ErrorCode::Forbidden),
            "{path}: {reply:?}"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn unqueued_grant_survives_idle_sweep() {
    let dir = scratch("capacity-unqueued-idle");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = plain_key(&hub);
    let mut node = ready_node(addr, &hub, 8192).await;
    let grant = reserve_on(addr, &key, &mut node, 1, None).await;
    crate::jobs::testing::age_ticket_and_step(&hub, &grant.reservation).await;
    assert_eq!(crate::jobs::testing::reservations(&hub), 1);
    let reply = api(
        addr,
        "DELETE",
        &format!("/v1/reservations/{}", grant.reservation),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(reply.status, 204, "{reply:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn cancelling_a_granted_ticket_releases_its_reservation() {
    let dir = scratch("capacity-cancel-grant");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let mut node = ready_node(addr, &hub, 8192).await;
    let ticket = queue(addr, &key, 1).await;
    let grant = accept_ticket(addr, &key, &ticket, &mut node).await;
    let path = format!("/v1/reservations/tickets/{ticket}");
    let reply = api(addr, "DELETE", &path, Some(&key), None).await;
    assert_eq!(reply.status, 204, "{reply:?}");
    assert_eq!(
        node.job().await,
        HubJobMsg::Release {
            reservation: grant.reservation.clone()
        }
    );
    assert_eq!(crate::jobs::testing::reservations(&hub), 0);
    // Given back, it can no longer be claimed, and polling it says it ended.
    assert_eq!(claim(addr, &key, &grant).await.status, 410);
    let reply = poll(addr, &key, &ticket, 0).await;
    assert_eq!(
        (reply.status, reply.code()),
        (410, ErrorCode::ReservationGone),
        "{reply:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn only_the_granted_relay_claims_a_grant() {
    let dir = scratch("capacity-claims");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    let other = jobs_key(&hub);
    ready_relay(&hub, &key);
    let mut node = ready_node(addr, &hub, 8192).await;
    let ticket = queue(addr, &key, 1).await;
    // Offered to the node, not yet granted: nothing to claim.
    let HubJobMsg::Offer { reservation, .. } = node.job().await else {
        panic!("expected offer")
    };
    let offered = ReservationGrant {
        reservation: reservation.clone(),
        node: String::new(),
        envelope: envelope(),
        lease_secs: 90,
        admission: None,
    };
    let reply = claim(addr, &key, &offered).await;
    assert_eq!(
        (reply.status, reply.code()),
        (410, ErrorCode::ReservationGone),
        "{reply:?}"
    );
    node.send(NodeJobMsg::OfferReply {
        reservation,
        reply: OfferReply::Accepted { lease_secs: 90 },
    });
    let reply = poll(addr, &key, &ticket, 10).await;
    assert_eq!(reply.status, 201, "{reply:?}");
    let grant: ReservationGrant = reply.json();
    // Another relay can neither claim the grant nor see its ticket.
    let reply = claim(addr, &other, &grant).await;
    assert_eq!(reply.status, 410, "{reply:?}");
    let reply = poll(addr, &other, &ticket, 0).await;
    assert_eq!(reply.status, 404, "{reply:?}");
    assert_eq!(claim(addr, &key, &grant).await.status, 204);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn outcomes_are_checked_against_their_admission() {
    let dir = scratch("capacity-outcomes");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    let other = jobs_key(&hub);
    ready_relay(&hub, &key);
    let mut node = ready_node(addr, &hub, 16384).await;
    let first = queue(addr, &key, 1).await;
    let grant = accept_ticket(addr, &key, &first, &mut node).await;
    assert_eq!(claim(addr, &key, &grant).await.status, 204);
    // The body names another admission, or another relay reports it.
    let reply = outcome(addr, &key, &first, &"0".repeat(32), "job").await;
    assert_eq!(
        (reply.status, reply.code()),
        (400, ErrorCode::Invalid),
        "{reply:?}"
    );
    let reply = outcome(addr, &other, &first, &first, "job").await;
    assert_eq!(
        (reply.status, reply.code()),
        (404, ErrorCode::NotFound),
        "{reply:?}"
    );
    // A job took it: reported again, the same; an error contradicts it.
    for _ in 0..2 {
        let reply = outcome(addr, &key, &first, &first, "job").await;
        assert_eq!(reply.status, 204, "{reply:?}");
    }
    let reply = outcome(addr, &key, &first, &first, "error").await;
    assert_eq!(
        (reply.status, reply.code()),
        (409, ErrorCode::Conflict),
        "{reply:?}"
    );
    // An error backs the runner off: its next request waits.
    let second = queue(addr, &key, 2).await;
    let grant = accept_ticket(addr, &key, &second, &mut node).await;
    assert_eq!(claim(addr, &key, &grant).await.status, 204);
    let reply = outcome(addr, &key, &second, &second, "error").await;
    assert_eq!(reply.status, 204, "{reply:?}");
    assert_eq!(
        node.job().await,
        HubJobMsg::Release {
            reservation: grant.reservation
        }
    );
    queue(addr, &key, 3).await;
    wait_reason(&hub, "backoff").await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn unanswered_abandoned_probe_closes_node_session() {
    let dir = scratch("capacity-abandoned-probe");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let mut node = ready_node(addr, &hub, 8192).await;
    let ticket = queue(addr, &key, 1).await;
    let HubJobMsg::Offer { reservation, .. } = node.job().await else {
        panic!("expected offer");
    };
    let reply = api(
        addr,
        "DELETE",
        &format!("/v1/reservations/tickets/{ticket}"),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(reply.status, 204, "{reply:?}");
    assert!(matches!(node.job().await, HubJobMsg::Release { .. }));
    crate::jobs::testing::age_abandoned_and_step(&hub, &reservation).await;
    node.ended().await;
    wait_until(|| crate::jobs::testing::reservations(&hub) == 0).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn finished_legacy_job_does_not_hold_capacity_after_restart() {
    let dir = scratch("capacity-legacy");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let mut node = ready_node(addr, &hub, 8192).await;
    let id = running_job(addr, &key, &mut node, 1).await;
    node.send(NodeJobMsg::Result {
        job: id.clone(),
        result: result(None, 0),
    });
    assert_eq!(node.job().await, HubJobMsg::Recorded { job: id.clone() });
    view_until(addr, &key, &id, |view| view.state == JobState::Finished).await;
    let mut row = hub.db.job(&id).unwrap().unwrap();
    row.scheduling = None;
    row.revision += 1;
    hub.db.put_job(&id, &row, &[], now_secs()).unwrap();
    let (restarted_addr, restarted) =
        serve_hub(hub.db.clone(), &dir, Duration::from_secs(30)).await;
    ready_relay(&restarted, &key);
    let mut new_node = ready_node(restarted_addr, &restarted, 8192).await;
    let ticket = queue(restarted_addr, &key, 2).await;
    let grant = accept_ticket(restarted_addr, &key, &ticket, &mut new_node).await;
    assert_eq!(grant.admission.as_deref(), Some(ticket.as_str()));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_restarted_hub_keeps_claimed_admissions_and_forgets_grants() {
    let dir = scratch("capacity-restart");
    let db = Arc::new(Db::open_memory().unwrap());
    let (addr, hub) = serve_hub(db.clone(), &dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    // Two runners, each probing at once.
    add_runner(&hub, &key, "second", 43, crate::policy::Class::Normal);
    let mut policy = hub.db.capacity_policy().unwrap();
    policy.probe_limit = 2;
    hub.db
        .set_capacity_policy(&policy, "u", now_secs())
        .unwrap();
    ready_relay(&hub, &key);
    let mut node = ready_node(addr, &hub, 16384).await;
    let claimed = queue(addr, &key, 1).await;
    let grant = accept_ticket(addr, &key, &claimed, &mut node).await;
    assert_eq!(claim(addr, &key, &grant).await.status, 204);
    let granted = queue_for(addr, &key, 2, "second").await;
    accept_ticket(addr, &key, &granted, &mut node).await;
    // Restarted over the same database, as the relay reconnects.
    let (addr, hub) = serve_hub(db, &dir, Duration::from_secs(30)).await;
    hub.open_session(relay_id(&key));
    // The grant is gone with the hub that made it.
    let reply = poll(addr, &key, &granted, 0).await;
    assert_eq!(
        (reply.status, reply.code()),
        (410, ErrorCode::ReservationGone),
        "{reply:?}"
    );
    // Until its heartbeat says what it holds, the relay's requests wait.
    let waiting = queue(addr, &key, 3).await;
    wait_reason(&hub, "awaiting relay reconciliation").await;
    // It still requests work under the claimed admission, whose outcome then arrives.
    let session = hub.current_session(relay_id(&key));
    heartbeat_in(&hub, &key, now_secs(), session, &[&claimed], 0);
    crate::jobs::testing::step(&hub).await;
    let reply = outcome(addr, &key, &claimed, &claimed, "empty").await;
    assert_eq!(reply.status, 204, "{reply:?}");
    let reply = poll(addr, &key, &waiting, 0).await;
    assert_eq!(reply.status, 202, "{reply:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_claim_its_sessions_heartbeats_leave_out_is_reclaimed() {
    let dir = scratch("capacity-unlisted");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let mut node = ready_node(addr, &hub, 8192).await;
    let ticket = queue(addr, &key, 1).await;
    let grant = accept_ticket(addr, &key, &ticket, &mut node).await;
    let reply = claim(addr, &key, &grant).await;
    assert_eq!(reply.status, 204, "{reply:?}");
    // A heartbeat from around the claim may have been taken before the relay listed it.
    heartbeat(&hub, &key, now_secs(), 0);
    crate::jobs::testing::step(&hub).await;
    assert_eq!(crate::jobs::testing::reservations(&hub), 1);
    // So may one received at once from a relay whose clock runs ahead: the hub goes by when
    // it received a heartbeat, not by the time the relay put on it.
    let session = hub.current_session(relay_id(&key));
    let now = tokio::time::Instant::now();
    heartbeat_received(&hub, &key, now_secs() + 60, now, session, &[], 0);
    crate::jobs::testing::step(&hub).await;
    assert_eq!(crate::jobs::testing::reservations(&hub), 1);
    // One well after it, leaving the admission out, ends it: its outcome was lost.
    heartbeat(&hub, &key, now_secs() + 60, 0);
    assert_eq!(
        node.job().await,
        HubJobMsg::Release {
            reservation: grant.reservation
        }
    );
    let reply = outcome(addr, &key, &ticket, &ticket, "empty").await;
    assert_eq!(reply.status, 404, "{reply:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn only_a_heartbeat_of_the_relay_s_current_session_reclaims_a_claim() {
    let dir = scratch("capacity-stale-heartbeat");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let mut node = ready_node(addr, &hub, 8192).await;
    let ticket = queue(addr, &key, 1).await;
    let grant = accept_ticket(addr, &key, &ticket, &mut node).await;
    assert_eq!(claim(addr, &key, &grant).await.status, 204);
    let old = hub.current_session(relay_id(&key));
    // The relay reconnects; a heartbeat of its old session, late, says nothing of it.
    hub.open_session(relay_id(&key));
    heartbeat_in(&hub, &key, now_secs() + 60, old, &[], 0);
    crate::jobs::testing::step(&hub).await;
    assert_eq!(crate::jobs::testing::reservations(&hub), 1);
    // The new session's first heartbeat leaves it out: the relay holds nothing under it, and
    // the node's reservation goes too.
    heartbeat(&hub, &key, now_secs() + 60, 0);
    assert_eq!(
        node.job().await,
        HubJobMsg::Release {
            reservation: grant.reservation
        }
    );
    assert_eq!(crate::jobs::testing::reservations(&hub), 0);
    let reply = outcome(addr, &key, &ticket, &ticket, "empty").await;
    assert_eq!(reply.status, 404, "{reply:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn jobs_held_without_admissions_count_against_the_relay() {
    let dir = scratch("capacity-unadmitted");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    relay_limits(&hub, &key, 1, 1);
    ready_relay(&hub, &key);
    // A job taken before the relay upgraded: counted, not awaited as unreconciled.
    heartbeat(&hub, &key, now_secs(), 1);
    let mut node = ready_node(addr, &hub, 8192).await;
    let ticket = queue(addr, &key, 1).await;
    wait_reason(&hub, "relay concurrent limit").await;
    node.quiet(Duration::from_millis(200)).await;
    heartbeat(&hub, &key, now_secs(), 0);
    let grant = accept_ticket(addr, &key, &ticket, &mut node).await;
    assert_eq!(grant.admission.as_deref(), Some(ticket.as_str()));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_job_its_relay_holds_back_ends_saying_why() {
    let dir = scratch("capacity-held-back");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    relay_limits(&hub, &key, 1, 1);
    ready_relay(&hub, &key);
    // A job held without an admission fills the relay; one asked with no window to wait in
    // ends at once.
    heartbeat(&hub, &key, now_secs(), 1);
    let reply = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(1, None, 0)),
    )
    .await;
    assert_eq!(reply.status, 201, "{reply:?}");
    let id = reply.json::<JobView>().id;
    let view = view_until(addr, &key, &id, |v| v.state == JobState::Finished).await;
    let result = view.result.unwrap();
    assert_eq!(result.failure, Some(FailureClass::NoCapacity));
    assert_eq!(
        result.message.as_deref(),
        Some("no node took it within its placement window (relay concurrent limit)")
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_refused_submission_ends_its_admission() {
    let dir = scratch("capacity-refused-submission");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let mut node = ready_node(addr, &hub, 8192).await;
    let ticket = queue(addr, &key, 1).await;
    let grant = accept_ticket(addr, &key, &ticket, &mut node).await;
    let reply = claim(addr, &key, &grant).await;
    assert_eq!(reply.status, 204, "{reply:?}");
    // A project an operator has yet to approve.
    let mut body = job_body(2, Some(&grant.reservation), 30);
    body["admission"] = json!(ticket);
    body["spec"]["job"]["project_id"] = json!(PROJECT_ID + 1);
    let reply = api(addr, "POST", "/v1/jobs", Some(&key), Some(body)).await;
    assert_eq!(reply.status, 403, "{reply:?}");
    assert_eq!(
        node.job().await,
        HubJobMsg::Release {
            reservation: grant.reservation
        }
    );
    // The relay's own report of it is the outcome the hub already has.
    let reply = outcome(addr, &key, &ticket, &ticket, "empty").await;
    assert_eq!(reply.status, 204, "{reply:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_runner_at_its_limit_waits() {
    let dir = scratch("capacity-runner-limit");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    let id = relay_id(&key);
    let mut inventory = hub.db.relay(id).unwrap().unwrap().inventory.unwrap();
    inventory.runners[0].limit = Some(1);
    hub.db
        .record_relay(
            id,
            crate::store::RelayWrite::Inventory(inventory),
            now_secs(),
        )
        .unwrap();
    ready_relay(&hub, &key);
    // The runner holds a job: room on its relay, none under its own limit.
    heartbeat(&hub, &key, now_secs(), 1);
    let mut node = ready_node(addr, &hub, 8192).await;
    let ticket = queue(addr, &key, 1).await;
    wait_reason(&hub, "runner limit").await;
    node.quiet(Duration::from_millis(200)).await;
    heartbeat(&hub, &key, now_secs(), 0);
    let grant = accept_ticket(addr, &key, &ticket, &mut node).await;
    assert_eq!(grant.admission.as_deref(), Some(ticket.as_str()));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn the_tenant_holding_less_is_granted_first() {
    let dir = scratch("capacity-tenants");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    add_runner(&hub, &key, "other", 43, crate::policy::Class::Normal);
    let mut policy = hub.db.capacity_policy().unwrap();
    policy.tenants.insert(
        "other".into(),
        crate::policy::Tenant {
            weight: 1,
            cap: None,
            projects: Vec::new(),
        },
    );
    for mapping in &mut policy.runners {
        if mapping.runner_id == 43 {
            mapping.tenant = "other".into();
        }
    }
    hub.db
        .set_capacity_policy(&policy, "u", now_secs())
        .unwrap();
    ready_relay(&hub, &key);
    // Tenant `tests` holds a node's two slots with jobs.
    let mut full = ready_node(addr, &hub, 8192).await;
    for n in 1..=2 {
        let ticket = queue(addr, &key, n).await;
        let grant = accept_ticket(addr, &key, &ticket, &mut full).await;
        assert_eq!(claim(addr, &key, &grant).await.status, 204);
        let reply = outcome(addr, &key, &ticket, &ticket, "job").await;
        assert_eq!(reply.status, 204, "{reply:?}");
    }
    // Both tenants wait, `tests` first; one slot frees up and goes to `other`.
    let tests = queue(addr, &key, 3).await;
    wait_reason_of(&hub, 42, "no fitting node").await;
    let other = queue_for(addr, &key, 4, "other").await;
    wait_reason_of(&hub, 43, "no fitting node").await;
    let mut free = ready_node(addr, &hub, 4096).await;
    let grant = accept_ticket(addr, &key, &other, &mut free).await;
    assert_eq!(grant.admission.as_deref(), Some(other.as_str()));
    let answer = poll(addr, &key, &tests, 0).await;
    assert_eq!(answer.status, 202, "{answer:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Claim `grant` of ticket `ticket` and report that a job took it, as `key`'s relay.
pub(super) async fn take_job(addr: SocketAddr, key: &str, ticket: &str, grant: &ReservationGrant) {
    assert_eq!(claim(addr, key, grant).await.status, 204);
    let reply = outcome(addr, key, ticket, ticket, "job").await;
    assert_eq!(reply.status, 204, "{reply:?}");
}

/// Cap tenant `tests` at `cap` admissions and jobs.
fn cap_tests(hub: &Hub, cap: u32) {
    let mut policy = hub.db.capacity_policy().unwrap();
    policy.tenants.get_mut("tests").unwrap().cap = Some(cap);
    hub.db
        .set_capacity_policy(&policy, "u", now_secs())
        .unwrap();
}

/// Settle job `id` as `key`'s relay, once it finished.
async fn settle(addr: SocketAddr, key: &str, id: &str) {
    view_until(addr, key, id, |v| v.state == JobState::Finished).await;
    let path = format!("/v1/jobs/{id}/settle");
    let reply = api(addr, "POST", &path, Some(key), None).await;
    assert_eq!(reply.status, 204, "{reply:?}");
}

#[tokio::test]
async fn a_claimed_admission_stays_charged_to_its_tenant_cap() {
    let dir = scratch("capacity-cap");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    cap_tests(&hub, 1);
    let mut node = ready_node(addr, &hub, 8192).await;
    let first = queue(addr, &key, 1).await;
    let grant = accept_ticket(addr, &key, &first, &mut node).await;
    assert_eq!(claim(addr, &key, &grant).await.status, 204);
    // Claimed, its runner asks GitLab under it: the tenant's one slot is taken.
    let second = queue(addr, &key, 2).await;
    assert_eq!(reason_now(&hub, 42).await, Some("tenant cap"));
    let reply = poll(addr, &key, &second, 0).await;
    assert_eq!(reply.status, 202, "{reply:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_job_keeps_its_admission_charged_until_settled() {
    let dir = scratch("capacity-settle");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    cap_tests(&hub, 1);
    let mut node = ready_node(addr, &hub, 16384).await;
    let first = queue(addr, &key, 1).await;
    let grant = accept_ticket(addr, &key, &first, &mut node).await;
    take_job(addr, &key, &first, &grant).await;
    let mut body = job_body(10, Some(&grant.reservation), 30);
    body["admission"] = json!(first);
    let reply = api(addr, "POST", "/v1/jobs", Some(&key), Some(body)).await;
    assert_eq!(reply.status, 201, "{reply:?}");
    let job = reply.json::<JobView>().id;
    let HubJobMsg::Start(start) = node.job().await else {
        panic!("expected job start")
    };
    assert_eq!(start.job, job);
    node.send(NodeJobMsg::Job {
        job: job.clone(),
        state: RunState::Accepted,
    });
    view_until(addr, &key, &job, |view| view.state == JobState::Running).await;
    let second = queue(addr, &key, 2).await;
    assert_eq!(reason_now(&hub, 42).await, Some("tenant cap"));
    // Finished, the job holds its admission until its relay settles it.
    node.send(NodeJobMsg::Result {
        job: job.clone(),
        result: result(None, 0),
    });
    assert_eq!(node.job().await, HubJobMsg::Recorded { job: job.clone() });
    view_until(addr, &key, &job, |view| view.state == JobState::Finished).await;
    assert_eq!(reason_now(&hub, 42).await, Some("tenant cap"));
    settle(addr, &key, &job).await;
    let next = accept_ticket(addr, &key, &second, &mut node).await;
    assert_eq!(next.admission.as_deref(), Some(second.as_str()));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn direct_submissions_obey_the_tenant_cap() {
    let dir = scratch("capacity-direct-cap");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    cap_tests(&hub, 1);
    let mut node = ready_node(addr, &hub, 16384).await;
    let first = running_job(addr, &key, &mut node, 1).await;
    let reply = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(2, None, 30)),
    )
    .await;
    assert_eq!(reply.status, 201, "{reply:?}");
    let second = reply.json::<JobView>().id;
    crate::jobs::testing::step(&hub).await;
    assert_eq!(
        crate::jobs::testing::job_blocked(&hub, &second),
        Some("tenant cap")
    );
    node.send(NodeJobMsg::Result {
        job: first.clone(),
        result: result(None, 0),
    });
    assert_eq!(node.job().await, HubJobMsg::Recorded { job: first.clone() });
    settle(addr, &key, &first).await;
    let HubJobMsg::Start(start) = node.job().await else {
        panic!("expected the second job's start")
    };
    assert_eq!(start.job, second);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn weighted_tenants_go_by_load_per_weight() {
    let dir = scratch("capacity-weighted");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    // Three requests waiting per runner.
    relay_limits(&hub, &key, 64, 3);
    add_runner(&hub, &key, "other", 43, crate::policy::Class::Normal);
    let mut policy = hub.db.capacity_policy().unwrap();
    policy.tenants.get_mut("tests").unwrap().weight = 2;
    policy.tenants.insert(
        "other".into(),
        crate::policy::Tenant {
            weight: 1,
            cap: None,
            projects: Vec::new(),
        },
    );
    for mapping in &mut policy.runners {
        if mapping.runner_id == 43 {
            mapping.tenant = "other".into();
        }
    }
    hub.db
        .set_capacity_policy(&policy, "u", now_secs())
        .unwrap();
    ready_relay(&hub, &key);
    let mut node = ready_node(addr, &hub, 32768).await;
    crate::ops::set_ceiling(&hub, "u", &node.id, Some(1)).unwrap();
    let a1 = queue(addr, &key, 1).await;
    let b1 = queue_for(addr, &key, 2, "other").await;
    let b2 = queue_for(addr, &key, 3, "other").await;
    let a2 = queue(addr, &key, 4).await;
    let a3 = queue(addr, &key, 5).await;
    // Add one slot at a time: oldest first when idle, then `other` holding none,
    // then `tests` (jobs/weight 1/2 < 1/1), then the older request at equal shares,
    // then `tests` (2/2 < 2/1).
    for (slots, ticket) in (1..).zip([&a1, &b1, &a2, &b2, &a3]) {
        crate::ops::set_ceiling(&hub, "u", &node.id, Some(slots)).unwrap();
        crate::jobs::testing::step(&hub).await;
        let grant = accept_ticket(addr, &key, ticket, &mut node).await;
        assert_eq!(grant.admission.as_deref(), Some(ticket.as_str()));
        take_job(addr, &key, ticket, &grant).await;
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_production_probe_burst_owes_normal_work_a_turn() {
    let dir = scratch("capacity-probe-turn");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    for (name, id) in [("prod1", 43), ("prod2", 44), ("prod3", 45)] {
        add_runner(&hub, &key, name, id, crate::policy::Class::Production);
    }
    let mut policy = hub.db.capacity_policy().unwrap();
    policy.production_probe_burst = 2;
    hub.db
        .set_capacity_policy(&policy, "u", now_secs())
        .unwrap();
    ready_relay(&hub, &key);
    // A hub starts owing normal work its turn: of two probes, the normal one goes first.
    let p1 = queue_for(addr, &key, 1, "prod1").await;
    let n1 = queue(addr, &key, 2).await;
    let mut node = ready_node(addr, &hub, 32768).await;
    crate::ops::set_ceiling(&hub, "u", &node.id, Some(1)).unwrap();
    let n1_grant = accept_ticket(addr, &key, &n1, &mut node).await;
    assert_eq!(claim(addr, &key, &n1_grant).await.status, 204);
    let n2 = queue(addr, &key, 3).await;
    let reply = outcome(addr, &key, &n1, &n1, "job").await;
    assert_eq!(reply.status, 204, "{reply:?}");
    // Add one slot at a time: two production probes, then normal work's owed turn.
    let mut slots = 1;
    let mut next = async |ticket: &str, node: &mut FakeNode| {
        slots += 1;
        crate::ops::set_ceiling(&hub, "u", &node.id, Some(slots)).unwrap();
        crate::jobs::testing::step(&hub).await;
        let grant = accept_ticket(addr, &key, ticket, node).await;
        assert_eq!(grant.admission.as_deref(), Some(ticket));
        take_job(addr, &key, ticket, &grant).await;
    };
    next(&p1, &mut node).await;
    // n1's job starts on its own reservation: normal work, but no turn taken.
    let mut body = job_body(10, Some(&n1_grant.reservation), 30);
    body["admission"] = json!(n1);
    let reply = api(addr, "POST", "/v1/jobs", Some(&key), Some(body)).await;
    assert_eq!(reply.status, 201, "{reply:?}");
    let job = reply.json::<JobView>().id;
    let HubJobMsg::Start(start) = node.job().await else {
        panic!("expected n1's job to start")
    };
    assert_eq!(start.job, job);
    let p2 = queue_for(addr, &key, 4, "prod2").await;
    next(&p2, &mut node).await;
    let p3 = queue_for(addr, &key, 5, "prod3").await;
    next(&n2, &mut node).await;
    let reply = poll(addr, &key, &p3, 0).await;
    assert_eq!(reply.status, 202, "{reply:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Keep `entries`, placements and their slots, for production work.
fn headroom(hub: &Hub, entries: Vec<(Placement, u32)>) {
    let mut policy = hub.db.capacity_policy().unwrap();
    policy.headroom = entries
        .into_iter()
        .map(|(placement, slots)| crate::policy::Headroom { placement, slots })
        .collect();
    hub.db
        .set_capacity_policy(&policy, "u", now_secs())
        .unwrap();
}

#[tokio::test]
async fn normal_work_leaves_an_overlapping_entry_its_room() {
    let dir = scratch("capacity-headroom");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    add_runner(
        &hub,
        &key,
        "production",
        43,
        crate::policy::Class::Production,
    );
    ready_relay(&hub, &key);
    // The node fits four requests, or one of a whole node's memory, labelled or not.
    let mut whole = placement();
    whole.labels.clear();
    whole.envelope.mem_mib = 16384;
    let mut disjoint = placement();
    disjoint.labels = vec!["not-present".into()];
    // The requests' own entry would leave room to spare, and the disjoint one has no room
    // anywhere to keep; a normal request would take the whole node's.
    headroom(&hub, vec![(placement(), 1), (whole, 1), (disjoint, 1)]);
    let mut node = ready_node(addr, &hub, 16384).await;
    let normal = queue(addr, &key, 1).await;
    assert_eq!(reason_now(&hub, 42).await, Some("production headroom"));
    let production = queue_for(addr, &key, 2, "production").await;
    let grant = accept_ticket(addr, &key, &production, &mut node).await;
    assert_eq!(grant.admission.as_deref(), Some(production.as_str()));
    let reply = poll(addr, &key, &normal, 0).await;
    assert_eq!(reply.status, 202, "{reply:?}");
    // Without headroom, a normal request takes the room left.
    take_job(addr, &key, &production, &grant).await;
    headroom(&hub, Vec::new());
    crate::jobs::testing::step(&hub).await;
    let next = accept_ticket(addr, &key, &normal, &mut node).await;
    assert_eq!(next.admission.as_deref(), Some(normal.as_str()));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn an_entry_already_short_loses_no_more_room() {
    let dir = scratch("capacity-headroom-short");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    // Two slots of three requests' memory: only the roomier node has any, for one.
    let mut large = placement();
    large.envelope.mem_mib = 12288;
    headroom(&hub, vec![(large, 2)]);
    let _roomy = ready_node(addr, &hub, 12288).await;
    let mut small = ready_node(addr, &hub, 8192).await;
    crate::ops::set_ceiling(&hub, "u", &small.id, Some(1)).unwrap();
    // The roomier node goes first, but would lose the entry its one slot: the other takes it.
    let first = queue(addr, &key, 1).await;
    let grant = accept_ticket(addr, &key, &first, &mut small).await;
    assert_eq!(grant.node, small.id);
    take_job(addr, &key, &first, &grant).await;
    queue(addr, &key, 2).await;
    assert_eq!(reason_now(&hub, 42).await, Some("production headroom"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_job_kept_from_headroom_ends_saying_why() {
    let dir = scratch("capacity-headroom-job");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    headroom(&hub, vec![(placement(), 2)]);
    let _node = ready_node(addr, &hub, 8192).await;
    let reply = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(1, None, 1)),
    )
    .await;
    assert_eq!(reply.status, 201, "{reply:?}");
    let id = reply.json::<JobView>().id;
    crate::jobs::testing::step(&hub).await;
    assert_eq!(
        crate::jobs::testing::job_blocked(&hub, &id),
        Some("production headroom")
    );
    let view = view_until(addr, &key, &id, |v| v.state == JobState::Finished).await;
    let result = view.result.unwrap();
    assert_eq!(result.failure, Some(FailureClass::NoCapacity));
    assert_eq!(
        result.message.as_deref(),
        Some("no node took it within its placement window (production headroom)")
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_job_whose_reservation_cannot_take_it_is_kept_from_headroom() {
    let dir = scratch("capacity-headroom-reserved");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let mut reserved = ready_node(addr, &hub, 16384).await;
    let mut other = ready_node(addr, &hub, 8192).await;
    let ticket = queue(addr, &key, 1).await;
    let grant = accept_ticket(addr, &key, &ticket, &mut reserved).await;
    take_job(addr, &key, &ticket, &grant).await;
    // Its node takes no work now; the other's room is all kept.
    crate::jobs::testing::unhold(&hub, &reserved.id);
    headroom(&hub, vec![(placement(), 2)]);
    let mut body = job_body(2, Some(&grant.reservation), 1);
    body["admission"] = json!(ticket);
    let reply = api(addr, "POST", "/v1/jobs", Some(&key), Some(body)).await;
    assert_eq!(reply.status, 201, "{reply:?}");
    let id = reply.json::<JobView>().id;
    crate::jobs::testing::step(&hub).await;
    assert_eq!(
        crate::jobs::testing::job_blocked(&hub, &id),
        Some("production headroom")
    );
    let view = view_until(addr, &key, &id, |v| v.state == JobState::Finished).await;
    assert_eq!(
        view.result.unwrap().message.as_deref(),
        Some("no node took it within its placement window (production headroom)")
    );
    other.quiet(Duration::from_millis(100)).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_refusal_on_the_only_node_that_keeps_headroom_is_asked_again() {
    let dir = scratch("capacity-headroom-retry");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    // One slot of three requests' memory, on the busier node alone.
    let mut large = placement();
    large.envelope.mem_mib = 12288;
    headroom(&hub, vec![(large, 1)]);
    let mut busy = loaded_node(addr, &hub, 12288, Some(400)).await;
    let mut idle = ready_node(addr, &hub, 8192).await;
    queue(addr, &key, 1).await;
    // The idle node goes first, and refuses; the busy one would lose the entry its slot.
    for _ in 0..2 {
        let HubJobMsg::Offer { reservation, .. } = idle.job().await else {
            panic!("expected an offer")
        };
        idle.send(NodeJobMsg::OfferReply {
            reservation,
            reply: OfferReply::Refused {
                reason: Refusal::Memory,
                message: None,
            },
        });
        // Not kept from the node that refused: asked again after a pause.
        wait_reason(&hub, "no fitting node").await;
    }
    busy.quiet(Duration::from_millis(100)).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_grant_in_the_same_pass_counts_against_headroom() {
    let dir = scratch("capacity-headroom-pass");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    add_runner(&hub, &key, "second", 43, crate::policy::Class::Normal);
    let mut policy = hub.db.capacity_policy().unwrap();
    policy.probe_limit = 2;
    hub.db
        .set_capacity_policy(&policy, "u", now_secs())
        .unwrap();
    ready_relay(&hub, &key);
    // Four slots, three kept: one request may go, not two.
    headroom(&hub, vec![(placement(), 3)]);
    let first = queue(addr, &key, 1).await;
    queue_for(addr, &key, 2, "second").await;
    let mut node = ready_node(addr, &hub, 16384).await;
    let grant = accept_ticket(addr, &key, &first, &mut node).await;
    assert_eq!(grant.admission.as_deref(), Some(first.as_str()));
    assert_eq!(reason_now(&hub, 43).await, Some("production headroom"));
    node.quiet(Duration::from_millis(100)).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn the_larger_of_two_entries_of_one_placement_holds() {
    let dir = scratch("capacity-headroom-dedupe");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    // Four slots: one kept would leave room for three requests, three kept for one.
    headroom(&hub, vec![(placement(), 1), (placement(), 3)]);
    let mut node = ready_node(addr, &hub, 16384).await;
    let first = queue(addr, &key, 1).await;
    let grant = accept_ticket(addr, &key, &first, &mut node).await;
    take_job(addr, &key, &first, &grant).await;
    queue(addr, &key, 2).await;
    assert_eq!(reason_now(&hub, 42).await, Some("production headroom"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_short_entry_admits_what_leaves_its_room() {
    let dir = scratch("capacity-headroom-short-kept");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    // Two slots of three requests' memory: the node has room for one, and keeps it with a
    // request placed.
    let mut large = placement();
    large.envelope.mem_mib = 12288;
    headroom(&hub, vec![(large, 2)]);
    let mut node = ready_node(addr, &hub, 20480).await;
    let ticket = queue(addr, &key, 1).await;
    let grant = accept_ticket(addr, &key, &ticket, &mut node).await;
    assert_eq!(grant.admission.as_deref(), Some(ticket.as_str()));
    std::fs::remove_dir_all(&dir).unwrap();
}
