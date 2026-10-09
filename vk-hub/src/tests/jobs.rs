//! The client API and protocol version 3 end to end: a hub on a real socket, fake nodes
//! speaking the session from the node's side, and API requests made by hand over HTTP.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use ring::signature::Ed25519KeyPair;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use vk_hub_proto::client::{Capacity, ErrorCode, JobState, JobView, Placement, ReservationGrant};
use vk_hub_proto::dispatch::{
    Held, HeldJob, HeldReservation, HubJobMsg, LeaseEnd, LeaseState, NodeJobMsg, OfferReply,
    Refusal, RunState,
};
use vk_hub_proto::job::{CiJob, Envelope, FailureClass, JobResult, JobSpec};
use vk_hub_proto::{
    Admission, FsUsage, Hardware, Heartbeat, HubMsg, Inventory, JOBS, NodeMsg, NodeState, Report,
    StorageRole, VersionRange,
};

use super::*;
use crate::store::{KeyPolicy, Scope};

const V3: VersionRange = VersionRange { min: 1, max: JOBS };
const V2: VersionRange = VersionRange { min: 1, max: 2 };

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("vk-hub-jobs-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A hub placing jobs, its output in `dir`, losing a job's node after `lost_after`.
async fn start_jobs(dir: &std::path::Path, lost_after: Duration) -> (SocketAddr, Arc<Hub>) {
    let db = Arc::new(Db::open_memory().unwrap());
    serve_hub(db, dir, lost_after).await
}

/// A hub over `db`, as one restarted over the same database and output would be.
async fn serve_hub(
    db: Arc<Db>,
    dir: &std::path::Path,
    lost_after: Duration,
) -> (SocketAddr, Arc<Hub>) {
    let (addr, hub) = serve_undriven(db, dir, lost_after).await;
    tokio::spawn(crate::jobs::drive(hub.clone()));
    (addr, hub)
}

/// A hub as [`serve_hub`]'s with no placement loop: its jobs stay queued.
async fn serve_undriven(
    db: Arc<Db>,
    dir: &std::path::Path,
    lost_after: Duration,
) -> (SocketAddr, Arc<Hub>) {
    let listener = server::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let hub = Arc::new(
        Hub::new(db, None)
            .with_jobs(
                dir.join("jobs"),
                lost_after,
                crate::store::DEFAULT_JOB_HISTORY,
            )
            .unwrap(),
    );
    crate::jobs::recover(&hub).await.unwrap();
    tokio::spawn(server::serve(listener, None, hub.clone()));
    (addr, hub)
}

fn envelope() -> Envelope {
    Envelope {
        mem_mib: 4096,
        cpus: 2,
        disk_bytes: 1 << 30,
    }
}

fn placement() -> Placement {
    Placement {
        pool: "ci".into(),
        labels: vec!["big".into()],
        envelope: envelope(),
    }
}

/// An API key for pool `ci` with `scopes`, created at `at`, valid for `ttl`.
fn api_key(hub: &Hub, name: &str, scopes: &[Scope], at: u64, ttl: Duration) -> String {
    let policy = KeyPolicy {
        scopes: scopes.to_vec(),
        pools: vec!["ci".into()],
        max_envelope: Some(Envelope {
            mem_mib: 8192,
            cpus: 4,
            disk_bytes: 8 << 30,
        }),
    };
    hub.db
        .create_api_key(name, &policy, ttl, "uid 0", at)
        .unwrap()
        .0
}

fn jobs_key(hub: &Hub) -> String {
    api_key(
        hub,
        "gitlab",
        &[Scope::Jobs],
        now_secs(),
        Duration::from_secs(3600),
    )
}

/// An answer to a client API request.
#[derive(Debug)]
struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Resp {
    fn json<T: serde::de::DeserializeOwned>(&self) -> T {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&self.body)))
    }

    fn code(&self) -> ErrorCode {
        self.json::<vk_hub_proto::client::ClientError>().code
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A client API request by hand, on a connection of its own.
async fn api(
    addr: SocketAddr,
    method: &str,
    path: &str,
    key: Option<&str>,
    body: Option<Value>,
) -> Resp {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let body = body
        .map(|b| serde_json::to_vec(&b).unwrap())
        .unwrap_or_default();
    let auth = key
        .map(|k| format!("Authorization: Bearer {k}\r\n"))
        .unwrap_or_default();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: hub\r\n{auth}Content-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.unwrap();
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = std::str::from_utf8(&resp[..split]).unwrap();
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap()[9..12].parse().unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Resp {
        status,
        headers,
        body: resp[split + 4..].to_vec(),
    }
}

fn request_id(n: u8) -> String {
    format!("{n:02x}").repeat(16)
}

fn reservation_body(n: u8, wait_secs: u32) -> Value {
    json!({
        "request_id": request_id(n),
        "placement": placement(),
        "lease_secs": 90,
        "wait_secs": wait_secs,
    })
}

fn spec(gitlab_id: u64) -> JobSpec {
    let mut ci = CiJob {
        server_url: "https://gitlab.example.com".into(),
        ..CiJob::default()
    };
    ci.job.id = gitlab_id;
    ci.job.project_path = "group/project".into();
    ci.job.name = "test".into();
    ci.token = "glcbt-secret".into();
    ci.trace.limit_bytes = 1 << 20;
    JobSpec::GitlabCi(ci)
}

fn job_body(n: u8, reservation: Option<&str>, place_within_secs: u32) -> Value {
    let mut body = json!({
        "request_id": request_id(n),
        "placement": placement(),
        "place_within_secs": place_within_secs,
        "spec": spec(u64::from(n)),
    });
    if let Some(r) = reservation {
        body["reservation"] = json!(r);
    }
    body
}

/// A node at the far end of a session: what the hub sends it arrives in `inbox`, what it
/// sends goes through `outbox`, and it heartbeats on its own meanwhile.
struct FakeNode {
    id: String,
    outbox: mpsc::UnboundedSender<NodeMsg>,
    inbox: mpsc::UnboundedReceiver<HubMsg>,
}

impl FakeNode {
    fn send(&self, msg: NodeJobMsg) {
        self.outbox.send(NodeMsg::Job(msg)).unwrap();
    }

    /// The next job message from the hub.
    async fn job(&mut self) -> HubJobMsg {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let msg = tokio::time::timeout_at(deadline, self.inbox.recv())
                .await
                .expect("no job message came")
                .expect("the session ended");
            if let HubMsg::Job(job) = msg {
                return job;
            }
        }
    }

    /// No job message for a while.
    async fn quiet(&mut self, within: Duration) {
        let deadline = tokio::time::Instant::now() + within;
        while let Ok(msg) = tokio::time::timeout_at(deadline, self.inbox.recv()).await {
            match msg {
                Some(HubMsg::Job(job)) => panic!("unexpected {job:?}"),
                Some(_) => {}
                None => return,
            }
        }
    }

    /// How the session ended: the refusal the hub sent, if any.
    async fn ended(&mut self) -> Option<HubMsg> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut refusal = None;
        loop {
            match tokio::time::timeout_at(deadline, self.inbox.recv()).await {
                Ok(Some(msg @ HubMsg::Refused { .. })) => refusal = Some(msg),
                Ok(Some(_)) => {}
                Ok(None) => return refusal,
                Err(_) => panic!("the session did not end"),
            }
        }
    }
}

/// Enroll a node with `key`, in pool `ci`.
async fn new_node(addr: SocketAddr, hub: &Hub, key: &Ed25519KeyPair) -> String {
    let id = enrolled(addr, hub, key).await;
    hub.db
        .set_pools(&id, &["ci".to_string()], "uid 0", now_secs())
        .unwrap();
    id
}

/// Open a session for `id` speaking `versions`, report itself ready with `mem_mib` free, and
/// send `held` when given.
async fn connect(
    addr: SocketAddr,
    id: &str,
    key: &Ed25519KeyPair,
    versions: VersionRange,
    mem_mib: u64,
    held: Option<Held>,
) -> FakeNode {
    connect_beating(
        addr,
        id,
        key,
        versions,
        mem_mib,
        held,
        Duration::from_millis(300),
    )
    .await
}

/// [`connect`], heartbeating every `beat` after the first.
async fn connect_beating(
    addr: SocketAddr,
    id: &str,
    key: &Ed25519KeyPair,
    versions: VersionRange,
    mem_mib: u64,
    held: Option<Held>,
    beat: Duration,
) -> FakeNode {
    let mut ws = dial(addr).await;
    let twist = Twist {
        versions: Some(versions),
        ..Twist::default()
    };
    let incarnation = "5a".repeat(16);
    let welcome = open_with(&mut ws, id, &incarnation, key, twist).await;
    assert!(matches!(welcome, HubMsg::Welcome { .. }), "{welcome:?}");
    let inventory = Inventory {
        hostname: format!("node-{}", &id[..6]),
        hardware: Hardware {
            cpus: 8,
            ..Hardware::default()
        },
        labels: vec!["big".into()],
        ..Inventory::default()
    };
    let heartbeat = Heartbeat {
        admission: Some(Admission {
            committed_mib: 0,
            budget_mib: Some(mem_mib),
            running: 0,
            waiting: 0,
        }),
        storage: vec![FsUsage {
            role: StorageRole::Jobs,
            free_bytes: 100 << 30,
            free_inodes: 1 << 20,
            inodes: 1 << 20,
        }],
        ..Heartbeat::default()
    };
    send(&mut ws, &NodeMsg::Inventory(inventory)).await;
    send(&mut ws, &NodeMsg::Heartbeat(heartbeat.clone())).await;
    send(
        &mut ws,
        &NodeMsg::Report(Report {
            state: Some(NodeState::Ready),
            ..Report::default()
        }),
    )
    .await;
    if let Some(held) = held {
        send(&mut ws, &NodeMsg::Job(NodeJobMsg::Held(held))).await;
    }
    let (outbox, mut out_rx) = mpsc::unbounded_channel::<NodeMsg>();
    let (in_tx, inbox) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + beat, beat);
        loop {
            tokio::select! {
                msg = out_rx.recv() => match msg {
                    Some(msg) => {
                        let text = serde_json::to_string(&msg).unwrap();
                        if ws.send(Message::text(text)).await.is_err() {
                            return;
                        }
                    }
                    None => {
                        let _ = ws.close(None).await;
                        return;
                    }
                },
                frame = ws.next() => match frame {
                    Some(Ok(Message::Text(t))) => {
                        let msg: HubMsg = serde_json::from_str(t.as_str()).unwrap();
                        if in_tx.send(msg).is_err() {
                            return;
                        }
                    }
                    Some(Ok(_)) => {}
                    _ => return,
                },
                _ = tick.tick() => {
                    let text = serde_json::to_string(&NodeMsg::Heartbeat(heartbeat.clone())).unwrap();
                    if ws.send(Message::text(text)).await.is_err() {
                        return;
                    }
                }
            }
        }
    });
    FakeNode {
        id: id.to_string(),
        outbox,
        inbox,
    }
}

/// A version-3 node in pool `ci`, connected, ready and holding nothing.
async fn ready_node(addr: SocketAddr, hub: &Hub, mem_mib: u64) -> FakeNode {
    let key = keypair();
    let id = new_node(addr, hub, &key).await;
    let node = connect(addr, &id, &key, V3, mem_mib, Some(Held::default())).await;
    wait_until(|| crate::jobs::testing::linked(hub, &id) && heard(hub, &id)).await;
    node
}

/// Whether the hub has stored a heartbeat and the inventory from `id`.
fn heard(hub: &Hub, id: &str) -> bool {
    hub.db
        .node(id)
        .unwrap()
        .is_some_and(|r| r.heartbeat.is_some() && r.inventory.is_some_and(|i| !i.labels.is_empty()))
}

async fn wait_until(mut cond: impl FnMut() -> bool) {
    for _ in 0..1000 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition never held");
}

/// Job `id`'s view, once it satisfies `cond`.
async fn view_until(
    addr: SocketAddr,
    key: &str,
    id: &str,
    cond: impl Fn(&JobView) -> bool,
) -> JobView {
    for _ in 0..200 {
        let resp = api(addr, "GET", &format!("/v1/jobs/{id}"), Some(key), None).await;
        assert_eq!(resp.status, 200, "{resp:?}");
        let view: JobView = resp.json();
        if cond(&view) {
            return view;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("job {id} never got there");
}

/// Reserve on `node`, answering its offer: the grant.
async fn reserve_on(addr: SocketAddr, key: &str, node: &mut FakeNode, n: u8) -> ReservationGrant {
    let key = key.to_string();
    let ask = tokio::spawn(async move {
        api(
            addr,
            "POST",
            "/v1/reservations",
            Some(&key),
            Some(reservation_body(n, 5)),
        )
        .await
    });
    let HubJobMsg::Offer { reservation, .. } = node.job().await else {
        panic!("expected an offer");
    };
    node.send(NodeJobMsg::OfferReply {
        reservation,
        reply: OfferReply::Accepted { lease_secs: 90 },
    });
    let resp = ask.await.unwrap();
    assert_eq!(resp.status, 201, "{resp:?}");
    resp.json()
}

/// Submit job `n` and have `node` accept its start: the job's ID.
async fn running_job(addr: SocketAddr, key: &str, node: &mut FakeNode, n: u8) -> String {
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(key),
        Some(job_body(n, None, 30)),
    )
    .await;
    assert_eq!(resp.status, 201, "{resp:?}");
    let view: JobView = resp.json();
    let HubJobMsg::Start(start) = node.job().await else {
        panic!("expected a start");
    };
    assert_eq!(start.job, view.id);
    node.send(NodeJobMsg::Job {
        job: view.id.clone(),
        state: RunState::Accepted,
    });
    view_until(addr, key, &view.id, |v| v.state == JobState::Running).await;
    view.id
}

fn output(job: &str, offset: u64, data: &[u8]) -> NodeJobMsg {
    NodeJobMsg::Output {
        job: job.to_string(),
        offset,
        data: vk_hub_proto::to_base64(data),
    }
}

fn result(failure: Option<FailureClass>, output_len: u64) -> JobResult {
    JobResult {
        failure,
        exit_code: None,
        message: None,
        output_len,
        artifacts: vec![],
        usage: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn api_keys_are_checked_on_every_request() {
    let dir = scratch("keys");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let ask = || Some(json!({"placement": placement()}));
    let key = jobs_key(&hub);
    let resp = api(addr, "POST", "/v1/capacity", Some(&key), ask()).await;
    assert_eq!(resp.status, 200, "{resp:?}");
    assert_eq!(resp.json::<Capacity>().fits, 0);

    // No key, a guess, a key expired, a key revoked.
    let resp = api(addr, "POST", "/v1/capacity", None, ask()).await;
    assert_eq!((resp.status, resp.code()), (401, ErrorCode::Unauthorized));
    let resp = api(addr, "POST", "/v1/capacity", Some("vkk_00"), ask()).await;
    assert_eq!(resp.status, 401);
    let expired = api_key(
        &hub,
        "old",
        &[Scope::Jobs],
        now_secs() - 100,
        Duration::from_secs(10),
    );
    let resp = api(addr, "POST", "/v1/capacity", Some(&expired), ask()).await;
    assert_eq!(resp.status, 401);
    assert!(
        hub.db
            .revoke_api_key("gitlab", "uid 0", now_secs())
            .unwrap()
    );
    let resp = api(addr, "POST", "/v1/capacity", Some(&key), ask()).await;
    assert_eq!(resp.status, 401);

    // A capacity-only key may ask for room and nothing else.
    let watcher = api_key(
        &hub,
        "watcher",
        &[Scope::Capacity],
        now_secs(),
        Duration::from_secs(60),
    );
    let resp = api(addr, "POST", "/v1/capacity", Some(&watcher), ask()).await;
    assert_eq!(resp.status, 200);
    let resp = api(
        addr,
        "POST",
        "/v1/reservations",
        Some(&watcher),
        Some(reservation_body(1, 0)),
    )
    .await;
    assert_eq!((resp.status, resp.code()), (403, ErrorCode::Forbidden));

    // A pool or an envelope outside the key's policy; a malformed body or ID.
    let key = api_key(
        &hub,
        "gitlab2",
        &[Scope::Jobs],
        now_secs(),
        Duration::from_secs(60),
    );
    let mut body = reservation_body(1, 0);
    body["placement"]["pool"] = json!("prod");
    let resp = api(addr, "POST", "/v1/reservations", Some(&key), Some(body)).await;
    assert_eq!((resp.status, resp.code()), (403, ErrorCode::Forbidden));
    let mut body = reservation_body(1, 0);
    body["placement"]["envelope"]["cpus"] = json!(64);
    let resp = api(addr, "POST", "/v1/reservations", Some(&key), Some(body)).await;
    assert_eq!(resp.status, 403);
    let resp = api(
        addr,
        "POST",
        "/v1/reservations",
        Some(&key),
        Some(json!({"nope": 1})),
    )
    .await;
    assert_eq!((resp.status, resp.code()), (400, ErrorCode::Invalid));
    let resp = api(addr, "GET", "/v1/jobs/xyz", Some(&key), None).await;
    assert_eq!(resp.status, 400);
    let resp = api(
        addr,
        "GET",
        &format!("/v1/jobs/{}", "ab".repeat(16)),
        Some(&key),
        None,
    )
    .await;
    assert_eq!((resp.status, resp.code()), (404, ErrorCode::NotFound));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn capacity_long_polls_until_it_moves_and_counts_only_version_3_nodes() {
    let dir = scratch("capacity");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let resp = api(
        addr,
        "POST",
        "/v1/capacity",
        Some(&key),
        Some(json!({"placement": placement()})),
    )
    .await;
    let first: Capacity = resp.json();
    assert_eq!(first.fits, 0);

    // A version-2 node in the pool, ready and roomy, counts for nothing.
    let old_key = keypair();
    let old = new_node(addr, &hub, &old_key).await;
    let mut old = connect(addr, &old, &old_key, V2, 65536, None).await;
    wait_until(|| heard(&hub, &old.id)).await;
    let resp = api(
        addr,
        "POST",
        "/v1/capacity",
        Some(&key),
        Some(json!({"placement": placement(), "after": first.revision, "wait_secs": 1})),
    )
    .await;
    assert_eq!(resp.json::<Capacity>(), first);

    let waiting = {
        let key = key.clone();
        tokio::spawn(async move {
            let started = tokio::time::Instant::now();
            let resp = api(
                addr,
                "POST",
                "/v1/capacity",
                Some(&key),
                Some(json!({"placement": placement(), "after": first.revision, "wait_secs": 30})),
            )
            .await;
            (resp.json::<Capacity>(), started.elapsed())
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _node = ready_node(addr, &hub, 16384).await;
    let (moved, took) = waiting.await.unwrap();
    assert!(moved.revision > first.revision, "{moved:?}");
    assert_eq!(moved.fits, 4);
    assert!(took < Duration::from_secs(20), "{took:?}");
    // The version-2 node was never offered anything, and still has its session.
    old.quiet(Duration::from_millis(500)).await;
    assert_eq!(hub.reach(&old.id), Reach::Connected);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reservation_goes_to_a_node_that_accepts_and_is_renewed_released_and_expires() {
    let dir = scratch("reserve");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    // The roomier node is offered first; it refuses, the other accepts.
    let mut big = ready_node(addr, &hub, 32768).await;
    let mut small = ready_node(addr, &hub, 8192).await;
    let ask = {
        let key = key.clone();
        tokio::spawn(async move {
            api(
                addr,
                "POST",
                "/v1/reservations",
                Some(&key),
                Some(reservation_body(1, 5)),
            )
            .await
        })
    };
    let HubJobMsg::Offer {
        reservation,
        envelope: offered,
        lease_secs,
    } = big.job().await
    else {
        panic!("expected an offer");
    };
    assert_eq!((offered, lease_secs), (envelope(), 90));
    big.send(NodeJobMsg::OfferReply {
        reservation,
        reply: OfferReply::Refused {
            reason: Refusal::Memory,
            message: Some("4096 MiB does not fit".into()),
        },
    });
    let HubJobMsg::Offer { reservation, .. } = small.job().await else {
        panic!("expected an offer");
    };
    small.send(NodeJobMsg::OfferReply {
        reservation: reservation.clone(),
        reply: OfferReply::Accepted { lease_secs: 60 },
    });
    let resp = ask.await.unwrap();
    assert_eq!(resp.status, 201, "{resp:?}");
    let grant: ReservationGrant = resp.json();
    assert_eq!(
        (&grant.reservation, &grant.node, grant.lease_secs),
        (&reservation, &small.id, 60)
    );
    // Why the node refused is kept for `vk-hub nodes`, until it accepts again.
    let views = ops::node_views(&hub).unwrap();
    let refusal = |id: &str| {
        views
            .iter()
            .find(|v| v.id == id)
            .and_then(|v| v.last_refusal.clone())
    };
    assert_eq!(
        refusal(&big.id).as_deref(),
        Some("memory: 4096 MiB does not fit")
    );
    assert_eq!(refusal(&small.id), None);

    // The same request again is answered the same, with no second offer; with another body,
    // it conflicts.
    let resp = api(
        addr,
        "POST",
        "/v1/reservations",
        Some(&key),
        Some(reservation_body(1, 5)),
    )
    .await;
    assert_eq!(
        (resp.status, resp.json::<ReservationGrant>()),
        (201, grant.clone())
    );
    let mut other = reservation_body(1, 5);
    other["lease_secs"] = json!(30);
    let resp = api(addr, "POST", "/v1/reservations", Some(&key), Some(other)).await;
    assert_eq!((resp.status, resp.code()), (409, ErrorCode::Conflict));
    big.quiet(Duration::from_millis(200)).await;
    small.quiet(Duration::from_millis(200)).await;

    // Renewed: the node answers with the lease it grants.
    let renew = {
        let (key, r) = (key.clone(), reservation.clone());
        tokio::spawn(async move {
            api(
                addr,
                "POST",
                &format!("/v1/reservations/{r}/renew"),
                Some(&key),
                Some(json!({"lease_secs": 90})),
            )
            .await
        })
    };
    let HubJobMsg::Renew {
        reservation: renewed,
        lease_secs,
    } = small.job().await
    else {
        panic!("expected a renew");
    };
    assert_eq!((renewed.as_str(), lease_secs), (reservation.as_str(), 90));
    small.send(NodeJobMsg::Lease {
        reservation: reservation.clone(),
        state: LeaseState::Held { remaining_secs: 90 },
    });
    let resp = renew.await.unwrap();
    assert_eq!(
        (resp.status, resp.json::<ReservationGrant>().lease_secs),
        (200, 90)
    );

    // Another key does not see it.
    let other_key = api_key(
        &hub,
        "other",
        &[Scope::Jobs],
        now_secs(),
        Duration::from_secs(60),
    );
    let resp = api(
        addr,
        "DELETE",
        &format!("/v1/reservations/{reservation}"),
        Some(&other_key),
        None,
    )
    .await;
    assert_eq!(resp.status, 404);

    // The node lets it lapse: renewing is then `reservation_gone`.
    small.send(NodeJobMsg::Lease {
        reservation: reservation.clone(),
        state: LeaseState::Gone {
            why: LeaseEnd::Expired,
        },
    });
    wait_until(|| crate::jobs::testing::reservations(&hub) == 0).await;
    let resp = api(
        addr,
        "POST",
        &format!("/v1/reservations/{reservation}/renew"),
        Some(&key),
        Some(json!({"lease_secs": 90})),
    )
    .await;
    assert_eq!(
        (resp.status, resp.code()),
        (410, ErrorCode::ReservationGone)
    );
    let audit = hub.db.audits(Some(&small.id), 20).unwrap();
    assert!(
        audit
            .iter()
            .any(|r| r.event == format!("reservation {reservation} on node {} expired", small.id)),
        "{audit:?}"
    );

    // Released: the node is told, and a release of one gone is 204 too.
    let grant = reserve_on(addr, &key, &mut big, 2).await;
    let resp = api(
        addr,
        "DELETE",
        &format!("/v1/reservations/{}", grant.reservation),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(resp.status, 204);
    assert_eq!(
        big.job().await,
        HubJobMsg::Release {
            reservation: grant.reservation.clone()
        }
    );
    let resp = api(
        addr,
        "DELETE",
        &format!("/v1/reservations/{}", grant.reservation),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(resp.status, 204);

    // Nobody accepts within the wait: `no_capacity`, to retry later.
    let ask = {
        let key = key.clone();
        tokio::spawn(async move {
            api(
                addr,
                "POST",
                "/v1/reservations",
                Some(&key),
                Some(reservation_body(3, 1)),
            )
            .await
        })
    };
    for node in [&mut big, &mut small] {
        let HubJobMsg::Offer { reservation, .. } = node.job().await else {
            panic!("expected an offer");
        };
        node.send(NodeJobMsg::OfferReply {
            reservation,
            reply: OfferReply::Refused {
                reason: Refusal::NotReady,
                message: None,
            },
        });
    }
    let resp = ask.await.unwrap();
    assert_eq!((resp.status, resp.code()), (503, ErrorCode::NoCapacity));
    assert!(
        resp.json::<vk_hub_proto::client::ClientError>()
            .retry_after_secs
            .is_some()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_version_2_node_is_never_offered_work() {
    let dir = scratch("v2");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let node_key = keypair();
    let id = new_node(addr, &hub, &node_key).await;
    let mut node = connect(addr, &id, &node_key, V2, 65536, None).await;
    wait_until(|| heard(&hub, &id)).await;
    assert_eq!(hub.db.node(&id).unwrap().unwrap().protocol, Some(2));
    let resp = api(
        addr,
        "POST",
        "/v1/reservations",
        Some(&key),
        Some(reservation_body(1, 1)),
    )
    .await;
    assert_eq!((resp.status, resp.code()), (503, ErrorCode::NoCapacity));
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(2, None, 1)),
    )
    .await;
    assert_eq!(resp.status, 201);
    let job: JobView = resp.json();
    let ended = view_until(addr, &key, &job.id, |v| v.state == JobState::Finished).await;
    assert_eq!(
        ended.result.unwrap().failure,
        Some(FailureClass::NoCapacity)
    );
    node.quiet(Duration::from_millis(300)).await;
    // A job message from a version-2 node ends its session.
    node.send(NodeJobMsg::Held(Held::default()));
    let Some(HubMsg::Refused { code, .. }) = node.ended().await else {
        panic!("expected a refusal");
    };
    assert_eq!(code, RefusalCode::Protocol);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_job_runs_on_its_reservation_streams_output_and_settles() {
    let dir = scratch("run");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 16384).await;
    let grant = reserve_on(addr, &key, &mut node, 1).await;
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(2, Some(&grant.reservation), 30)),
    )
    .await;
    assert_eq!(resp.status, 201, "{resp:?}");
    let submitted: JobView = resp.json();
    let id = submitted.id.clone();
    // Its spec reaches the node whole; the hub's record holds it redacted.
    let HubJobMsg::Start(start) = node.job().await else {
        panic!("expected a start");
    };
    assert_eq!(
        start.reservation.as_deref(),
        Some(grant.reservation.as_str())
    );
    assert_eq!(start.spec, spec(2));
    let stored = String::from_utf8(hub.db.job_spec(&id).unwrap().unwrap()).unwrap();
    assert!(!stored.contains("glcbt-secret"), "{stored}");

    // A long poll wakes when the node accepts it.
    let poll = {
        let (key, id) = (key.clone(), id.clone());
        let after = submitted.revision;
        tokio::spawn(async move {
            api(
                addr,
                "GET",
                &format!("/v1/jobs/{id}?after={after}&wait=30"),
                Some(&key),
                None,
            )
            .await
        })
    };
    node.send(NodeJobMsg::Job {
        job: id.clone(),
        state: RunState::Accepted,
    });
    let view: JobView = poll.await.unwrap().json();
    assert!(view.revision > submitted.revision);
    assert_ne!(view.state, JobState::Queued);
    node.send(NodeJobMsg::Job {
        job: id.clone(),
        state: RunState::Running {
            stage: "step_script".into(),
        },
    });
    view_until(addr, &key, &id, |v| {
        v.stage.as_deref() == Some("step_script")
    })
    .await;

    // Output: stored, acked, an overlap trimmed.
    node.send(output(&id, 0, b"hello "));
    assert_eq!(
        node.job().await,
        HubJobMsg::OutputAck {
            job: id.clone(),
            offset: 6
        }
    );
    node.send(output(&id, 3, b"lo world\n"));
    assert_eq!(
        node.job().await,
        HubJobMsg::OutputAck {
            job: id.clone(),
            offset: 12
        }
    );
    let resp = api(
        addr,
        "GET",
        &format!("/v1/jobs/{id}/output?offset=6"),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"world\n");
    assert_eq!(resp.header("vk-output-offset"), Some("6"));
    assert_eq!(resp.header("vk-output-length"), Some("12"));
    assert_eq!(resp.header("vk-output-complete"), None);
    let resp = api(
        addr,
        "GET",
        &format!("/v1/jobs/{id}/output?offset=13"),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(
        (resp.status, resp.header("vk-output-length")),
        (416, Some("12"))
    );
    // A read at the end waits for more.
    let read = {
        let (key, id) = (key.clone(), id.clone());
        tokio::spawn(async move {
            api(
                addr,
                "GET",
                &format!("/v1/jobs/{id}/output?offset=12&wait=30"),
                Some(&key),
                None,
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    node.send(output(&id, 12, b"done\n"));
    assert_eq!(
        node.job().await,
        HubJobMsg::OutputAck {
            job: id.clone(),
            offset: 17
        }
    );
    let resp = read.await.unwrap();
    assert_eq!(resp.body, b"done\n");

    // The result, recorded with what the job used; the output complete.
    let mut ended = result(Some(FailureClass::Script), 17);
    ended.usage = Some(vk_hub_proto::job::JobUsage {
        wall_ms: 4200,
        cpu_ms: Some(1500),
        peak_mem_bytes: Some(1 << 30),
        cpus: Some(2),
        mem_mib: Some(4096),
    });
    node.send(NodeJobMsg::Result {
        job: id.clone(),
        result: ended.clone(),
    });
    assert_eq!(node.job().await, HubJobMsg::Recorded { job: id.clone() });
    let done = view_until(addr, &key, &id, |v| v.state == JobState::Finished).await;
    let done_result = done.result.unwrap();
    assert_eq!(done_result.failure, Some(FailureClass::Script));
    assert_eq!(done_result.usage, ended.usage);
    assert_eq!(done.output_len, 17);
    let resp = api(
        addr,
        "GET",
        &format!("/v1/jobs/{id}/output?offset=0"),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(resp.body, b"hello world\ndone\n");
    assert_eq!(resp.header("vk-output-complete"), Some("true"));
    let resp = api(
        addr,
        "GET",
        &format!("/v1/jobs/{id}/output?offset=17&wait=30"),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(
        (resp.status, resp.header("vk-output-complete")),
        (200, Some("true"))
    );
    // A result repeated is recorded again and changes nothing.
    node.send(NodeJobMsg::Result {
        job: id.clone(),
        result: result(None, 17),
    });
    assert_eq!(node.job().await, HubJobMsg::Recorded { job: id.clone() });

    // Settled: the output goes, the record stays.
    let resp = api(
        addr,
        "POST",
        &format!("/v1/jobs/{id}/settle"),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(resp.status, 204);
    assert!(!dir.join("jobs").join(format!("{id}.out")).exists());
    let resp = api(
        addr,
        "GET",
        &format!("/v1/jobs/{id}/output?offset=0"),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(resp.status, 404);
    let resp = api(
        addr,
        "POST",
        &format!("/v1/jobs/{id}/settle"),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(resp.status, 204);
    view_until(addr, &key, &id, |v| {
        v.result
            .as_ref()
            .is_some_and(|r| r.failure == Some(FailureClass::Script))
    })
    .await;

    // Output past what the hub holds is a protocol error: the node's session ends.
    let id2 = running_job(addr, &key, &mut node, 3).await;
    node.send(output(&id2, 5, b"gap"));
    let Some(HubMsg::Refused { code, .. }) = node.ended().await else {
        panic!("expected a refusal");
    };
    assert_eq!(code, RefusalCode::Protocol);
    let events: Vec<String> = hub
        .db
        .audits(None, 50)
        .unwrap()
        .into_iter()
        .map(|r| r.event)
        .collect();
    for want in [
        format!("key gitlab submitted job {id}: GitLab job 2 of group/project (test)"),
        format!("node {} accepted job {id}", node.id),
        format!("job {id} finished on node {}: script failure", node.id),
        format!("key gitlab settled job {id}"),
    ] {
        assert!(events.contains(&want), "{want} not in {events:?}");
    }
    // The UI links the job to its page on GitLab, and its history shows where it ran, when,
    // and what it used.
    let row = hub.db.job(&id).unwrap().unwrap();
    assert_eq!(
        row.job_url.as_deref(),
        Some("https://gitlab.example.com/group/project/-/jobs/2")
    );
    assert_eq!(
        (row.project.as_deref(), row.name.as_deref()),
        (Some("group/project"), Some("test"))
    );
    assert!(row.started_at.is_some() && row.started_at <= row.finished_at);
    assert_eq!(row.ran_ms(crate::now_secs()), Some(4200));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A job ended in memory but not yet written is read as it ended, never as the older row
/// the database still holds, whose output is shorter than a reader was already given.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_read_while_its_end_is_written_is_not_older_than_before() {
    let dir = scratch("finishing");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 16384).await;
    let id = running_job(addr, &key, &mut node, 1).await;
    node.send(output(&id, 0, b"hello world\n"));
    assert_eq!(
        node.job().await,
        HubJobMsg::OutputAck {
            job: id.clone(),
            offset: 12
        }
    );
    let path = format!("/v1/jobs/{id}/output?offset=12");
    let resp = api(addr, "GET", &path, Some(&key), None).await;
    assert_eq!(
        (resp.status, resp.header("vk-output-length")),
        (200, Some("12"))
    );
    // The stored row predates the output.
    assert_eq!(hub.db.job(&id).unwrap().unwrap().output_len, 0);

    crate::jobs::testing::finish_unwritten(&hub, &id);
    let resp = api(addr, "GET", &path, Some(&key), None).await;
    assert_eq!(
        (
            resp.status,
            resp.header("vk-output-length"),
            resp.header("vk-output-complete")
        ),
        (200, Some("12"), Some("true")),
        "{resp:?}"
    );
    let view: JobView = api(addr, "GET", &format!("/v1/jobs/{id}"), Some(&key), None)
        .await
        .json();
    assert_eq!((view.state, view.output_len), (JobState::Finished, 12));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restarted_hub_keeps_running_jobs_and_their_output_and_loses_the_rest() {
    let dir = scratch("restart");
    let db = Arc::new(Db::open_memory().unwrap());
    let (addr, hub) = serve_hub(db.clone(), &dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let node_key = keypair();
    let id = new_node(addr, &hub, &node_key).await;
    let mut node = connect(addr, &id, &node_key, V3, 16384, Some(Held::default())).await;
    wait_until(|| crate::jobs::testing::linked(&hub, &id) && heard(&hub, &id)).await;
    let job = running_job(addr, &key, &mut node, 1).await;
    node.send(output(&job, 0, b"before restart\n"));
    assert_eq!(
        node.job().await,
        HubJobMsg::OutputAck {
            job: job.clone(),
            offset: 15
        }
    );
    // A second job, sent but not yet accepted when the hub stops.
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(2, None, 30)),
    )
    .await;
    let pending: JobView = resp.json();
    let HubJobMsg::Start(_) = node.job().await else {
        panic!("expected a start");
    };
    drop(node);

    // The same database and output, a hub with nothing in memory.
    let (addr, hub) = serve_hub(db, &dir, Duration::from_secs(60)).await;
    let lost = view_until(addr, &key, &pending.id, |v| v.state == JobState::Finished).await;
    assert_eq!(lost.result.unwrap().failure, Some(FailureClass::Lost));
    let resp = api(
        addr,
        "GET",
        &format!("/v1/jobs/{job}/output?offset=0"),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(resp.body, b"before restart\n");
    let held = Held {
        reservations: vec![HeldReservation {
            reservation: "ee".repeat(16),
            envelope: envelope(),
            remaining_secs: 30,
        }],
        jobs: vec![
            HeldJob {
                job: job.clone(),
                state: RunState::Running {
                    stage: "step_script".into(),
                },
                output_len: 40,
                finished: false,
            },
            HeldJob {
                job: pending.id.clone(),
                state: RunState::Accepted,
                output_len: 0,
                finished: false,
            },
        ],
    };
    let mut node = connect(addr, &id, &node_key, V3, 16384, Some(held)).await;
    // The answers to its `held`: the reservation the hub no longer knows released, the job it
    // follows acked where its output ends, the one it gave up on canceled.
    let mut answers = HashSet::new();
    for _ in 0..3 {
        answers.insert(serde_json::to_string(&node.job().await).unwrap());
    }
    for want in [
        HubJobMsg::Release {
            reservation: "ee".repeat(16),
        },
        HubJobMsg::OutputAck {
            job: job.clone(),
            offset: 15,
        },
        HubJobMsg::Cancel {
            job: pending.id.clone(),
            mode: vk_hub_proto::client::CancelMode::Immediate,
        },
    ] {
        assert!(
            answers.contains(&serde_json::to_string(&want).unwrap()),
            "{want:?} not in {answers:?}"
        );
    }
    node.send(output(&job, 15, b"after restart\n"));
    assert_eq!(
        node.job().await,
        HubJobMsg::OutputAck {
            job: job.clone(),
            offset: 29
        }
    );
    let resp = api(
        addr,
        "GET",
        &format!("/v1/jobs/{job}/output?offset=0"),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(resp.body, b"before restart\nafter restart\n");
    node.send(NodeJobMsg::Result {
        job: job.clone(),
        result: result(None, 29),
    });
    assert_eq!(node.job().await, HubJobMsg::Recorded { job: job.clone() });
    let done = view_until(addr, &key, &job, |v| v.state == JobState::Finished).await;
    assert_eq!(done.result.unwrap().failure, None);
    drop(hub);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn cancellation_ends_a_queued_job_and_reaches_a_running_one() {
    let dir = scratch("cancel");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    // Queued, with no node to take it: canceled at once.
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(1, None, 60)),
    )
    .await;
    let queued: JobView = resp.json();
    assert_eq!(queued.state, JobState::Queued);
    let resp = api(
        addr,
        "POST",
        &format!("/v1/jobs/{}/cancel", queued.id),
        Some(&key),
        Some(json!({"mode": "graceful"})),
    )
    .await;
    assert_eq!(resp.status, 202);
    let view: JobView = resp.json();
    assert_eq!(view.state, JobState::Finished);
    assert_eq!(view.result.unwrap().failure, Some(FailureClass::Canceled));

    // Running: graceful, then immediate overriding it, then graceful again changing nothing.
    let mut node = ready_node(addr, &hub, 16384).await;
    let id = running_job(addr, &key, &mut node, 2).await;
    let cancel = |mode: &'static str| {
        let (key, id) = (key.clone(), id.clone());
        async move {
            api(
                addr,
                "POST",
                &format!("/v1/jobs/{id}/cancel"),
                Some(&key),
                Some(json!({ "mode": mode })),
            )
            .await
        }
    };
    use vk_hub_proto::client::CancelMode;
    let resp = cancel("graceful").await;
    assert_eq!(resp.json::<JobView>().cancel, Some(CancelMode::Graceful));
    assert_eq!(
        node.job().await,
        HubJobMsg::Cancel {
            job: id.clone(),
            mode: CancelMode::Graceful
        }
    );
    let resp = cancel("immediate").await;
    assert_eq!(resp.json::<JobView>().cancel, Some(CancelMode::Immediate));
    assert_eq!(
        node.job().await,
        HubJobMsg::Cancel {
            job: id.clone(),
            mode: CancelMode::Immediate
        }
    );
    let resp = cancel("graceful").await;
    assert_eq!(resp.json::<JobView>().cancel, Some(CancelMode::Immediate));
    node.quiet(Duration::from_millis(300)).await;
    node.send(NodeJobMsg::Result {
        job: id.clone(),
        result: result(Some(FailureClass::Canceled), 0),
    });
    assert_eq!(node.job().await, HubJobMsg::Recorded { job: id.clone() });
    // Canceling a finished job changes nothing.
    let resp = cancel("immediate").await;
    assert_eq!(resp.status, 202);
    assert_eq!(resp.json::<JobView>().state, JobState::Finished);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lost_node_loses_its_job_and_is_told_to_cancel_it_when_back() {
    let dir = scratch("lost");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(1)).await;
    let key = jobs_key(&hub);
    let node_key = keypair();
    let id = new_node(addr, &hub, &node_key).await;
    let mut node = connect(addr, &id, &node_key, V3, 16384, Some(Held::default())).await;
    wait_until(|| crate::jobs::testing::linked(&hub, &id) && heard(&hub, &id)).await;
    let job = running_job(addr, &key, &mut node, 1).await;
    drop(node);
    let lost = view_until(addr, &key, &job, |v| v.state == JobState::Finished).await;
    let result = lost.result.unwrap();
    assert_eq!(result.failure, Some(FailureClass::Lost));
    assert_eq!(
        vk_hub_proto::job::gitlab_failure_reason(FailureClass::Lost, &[]),
        "runner_system_failure"
    );
    // Back, still running it: canceled, its result recorded and ignored.
    let held = Held {
        reservations: vec![],
        jobs: vec![HeldJob {
            job: job.clone(),
            state: RunState::Running {
                stage: "step_script".into(),
            },
            output_len: 0,
            finished: false,
        }],
    };
    let mut node = connect(addr, &id, &node_key, V3, 16384, Some(held)).await;
    assert_eq!(
        node.job().await,
        HubJobMsg::Cancel {
            job: job.clone(),
            mode: vk_hub_proto::client::CancelMode::Immediate
        }
    );
    node.send(output(&job, 0, b"late\n"));
    assert_eq!(
        node.job().await,
        HubJobMsg::OutputAck {
            job: job.clone(),
            offset: 5
        }
    );
    node.send(NodeJobMsg::Result {
        job: job.clone(),
        result: JobResult {
            failure: Some(FailureClass::Canceled),
            exit_code: None,
            message: None,
            output_len: 5,
            artifacts: vec![],
            usage: None,
        },
    });
    assert_eq!(node.job().await, HubJobMsg::Recorded { job: job.clone() });
    let view = view_until(addr, &key, &job, |_| true).await;
    assert_eq!(view.result.unwrap().failure, Some(FailureClass::Lost));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_job_is_placed_again_only_while_no_node_can_have_started_it() {
    let dir = scratch("replace");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    // No node: ended `no_capacity` once its window passes.
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(1, None, 1)),
    )
    .await;
    let job: JobView = resp.json();
    let ended = view_until(addr, &key, &job.id, |v| v.state == JobState::Finished).await;
    assert_eq!(
        ended.result.unwrap().failure,
        Some(FailureClass::NoCapacity)
    );

    // On a reservation that is gone, placed afresh; refused by one node, sent to the other.
    let mut a = ready_node(addr, &hub, 32768).await;
    let mut b = ready_node(addr, &hub, 8192).await;
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(2, Some(&"dd".repeat(16)), 30)),
    )
    .await;
    let job: JobView = resp.json();
    let HubJobMsg::Start(start) = a.job().await else {
        panic!("expected a start");
    };
    assert_eq!(start.reservation, None);
    a.send(NodeJobMsg::Job {
        job: job.id.clone(),
        state: RunState::Refused {
            reason: Refusal::Memory,
            message: None,
        },
    });
    let HubJobMsg::Start(start) = b.job().await else {
        panic!("expected a start");
    };
    assert_eq!(start.job, job.id);

    // B's answer is lost with its session: the start waits for B's `held`, and A is not asked
    // meanwhile.
    let b_id = b.id.clone();
    drop(b);
    a.quiet(Duration::from_millis(500)).await;
    let view = view_until(addr, &key, &job.id, |_| true).await;
    assert_eq!(
        (view.state, view.node.as_deref()),
        (JobState::Starting, Some(b_id.as_str()))
    );
    let b_key_row = hub.db.node(&b_id).unwrap().unwrap();
    assert!(b_key_row.pools.contains(&"ci".to_string()));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_start_the_node_never_took_is_placed_again_after_its_held() {
    let dir = scratch("held");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let node_key = keypair();
    let id = new_node(addr, &hub, &node_key).await;
    let mut node = connect(addr, &id, &node_key, V3, 16384, Some(Held::default())).await;
    wait_until(|| crate::jobs::testing::linked(&hub, &id) && heard(&hub, &id)).await;
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(1, None, 30)),
    )
    .await;
    let job: JobView = resp.json();
    let HubJobMsg::Start(_) = node.job().await else {
        panic!("expected a start");
    };
    drop(node);
    // Back, holding nothing: the start never reached its journal, so it is sent again.
    let mut node = connect(addr, &id, &node_key, V3, 16384, Some(Held::default())).await;
    let HubJobMsg::Start(start) = node.job().await else {
        panic!("expected a start");
    };
    assert_eq!(start.job, job.id);
    node.send(NodeJobMsg::Job {
        job: job.id.clone(),
        state: RunState::Accepted,
    });
    view_until(addr, &key, &job.id, |v| v.state == JobState::Running).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_job_submitted_twice_runs_once() {
    let dir = scratch("idempotent");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 16384).await;
    let first: JobView = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(1, None, 30)),
    )
    .await
    .json();
    let HubJobMsg::Start(_) = node.job().await else {
        panic!("expected a start");
    };
    let again = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(1, None, 30)),
    )
    .await;
    assert_eq!(again.status, 201);
    assert_eq!(again.json::<JobView>().id, first.id);
    let mut other = job_body(1, None, 30);
    other["place_within_secs"] = json!(31);
    let resp = api(addr, "POST", "/v1/jobs", Some(&key), Some(other)).await;
    assert_eq!((resp.status, resp.code()), (409, ErrorCode::Conflict));
    node.quiet(Duration::from_millis(300)).await;
    // Another key's job is not this one's to see.
    let other_key = api_key(
        &hub,
        "other",
        &[Scope::Jobs],
        now_secs(),
        Duration::from_secs(60),
    );
    let resp = api(
        addr,
        "GET",
        &format!("/v1/jobs/{}", first.id),
        Some(&other_key),
        None,
    )
    .await;
    assert_eq!(resp.status, 404);
    // Too large a spec.
    let mut big = job_body(2, None, 30);
    big["spec"]["server_url"] = json!("x".repeat(530 * 1024));
    let resp = api(addr, "POST", "/v1/jobs", Some(&key), Some(big)).await;
    assert_eq!(resp.status, 413, "{resp:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A job past its keep reads as having no output, and a create retried after its job left
/// the history is told so.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_expired_or_dropped_from_the_history_says_so() {
    let dir = scratch("history");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let job: JobView = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(1, None, 60)),
    )
    .await
    .json();
    let resp = api(
        addr,
        "POST",
        &format!("/v1/jobs/{}/cancel", job.id),
        Some(&key),
        Some(json!({"mode": "immediate"})),
    )
    .await;
    assert_eq!(resp.status, 202);
    let output = format!("/v1/jobs/{}/output?offset=0", job.id);
    assert_eq!(
        api(addr, "GET", &output, Some(&key), None).await.status,
        200
    );

    // Never settled, past its keep.
    let later = now_secs() + 31 * 86_400;
    assert_eq!(
        hub.db.prune_jobs(later, 100).unwrap(),
        std::slice::from_ref(&job.id)
    );
    let resp = api(addr, "GET", &output, Some(&key), None).await;
    assert_eq!((resp.status, resp.code()), (404, ErrorCode::NotFound));

    // Dropped from the history.
    assert!(hub.db.prune_jobs(later, 0).unwrap().is_empty());
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(1, None, 60)),
    )
    .await;
    assert_eq!((resp.status, resp.code()), (410, ErrorCode::NotFound));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A restarted hub deletes the output files no job may read again: a settled job's, and one
/// of a job it holds no record of.
#[tokio::test(flavor = "multi_thread")]
async fn a_restarted_hub_deletes_output_no_job_may_read() {
    let dir = scratch("sweep");
    let db = Arc::new(Db::open_memory().unwrap());
    let (addr, hub) = serve_hub(db.clone(), &dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut ids = Vec::new();
    for n in 1..=2 {
        let job: JobView = api(
            addr,
            "POST",
            "/v1/jobs",
            Some(&key),
            Some(job_body(n, None, 60)),
        )
        .await
        .json();
        let cancel = format!("/v1/jobs/{}/cancel", job.id);
        let mode = json!({"mode": "immediate"});
        let resp = api(addr, "POST", &cancel, Some(&key), Some(mode)).await;
        assert_eq!(resp.status, 202);
        ids.push(job.id);
    }
    let settle = format!("/v1/jobs/{}/settle", ids[1]);
    assert_eq!(
        api(addr, "POST", &settle, Some(&key), None).await.status,
        204
    );
    let jobs = dir.join("jobs");
    let unread = jobs.join(format!("{}.out", ids[0]));
    let settled = jobs.join(format!("{}.out", ids[1]));
    let unknown = jobs.join(format!("{}.out", "f".repeat(32)));
    let other = jobs.join("notes");
    for path in [&unread, &settled, &unknown, &other] {
        std::fs::write(path, b"x").unwrap();
    }

    serve_hub(db, &dir, Duration::from_secs(60)).await;
    assert!(unread.exists() && other.exists());
    assert!(!settled.exists() && !unknown.exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_start_gives_its_reservation_back_and_a_canceled_one_ends() {
    let dir = scratch("refused");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 16384).await;
    let grant = reserve_on(addr, &key, &mut node, 1).await;
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(2, Some(&grant.reservation), 30)),
    )
    .await;
    let job: JobView = resp.json();
    let HubJobMsg::Start(start) = node.job().await else {
        panic!("expected a start");
    };
    assert_eq!(
        start.reservation.as_deref(),
        Some(grant.reservation.as_str())
    );
    // Canceled while its start is out: the node is told.
    let resp = api(
        addr,
        "POST",
        &format!("/v1/jobs/{}/cancel", job.id),
        Some(&key),
        Some(json!({"mode": "immediate"})),
    )
    .await;
    assert_eq!(resp.json::<JobView>().state, JobState::Starting);
    assert!(matches!(node.job().await, HubJobMsg::Cancel { .. }));
    // Refused: the reservation goes back, and the job, ran nowhere, ends canceled.
    node.send(NodeJobMsg::Job {
        job: job.id.clone(),
        state: RunState::Refused {
            reason: Refusal::Policy,
            message: Some("no".into()),
        },
    });
    assert_eq!(
        node.job().await,
        HubJobMsg::Release {
            reservation: grant.reservation.clone()
        }
    );
    let ended = view_until(addr, &key, &job.id, |v| v.state == JobState::Finished).await;
    assert_eq!(ended.result.unwrap().failure, Some(FailureClass::Canceled));
    node.quiet(Duration::from_millis(300)).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_mode_the_hub_does_not_know_is_immediate() {
    let dir = scratch("cancel-other");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 16384).await;
    let id = running_job(addr, &key, &mut node, 1).await;
    let resp = api(
        addr,
        "POST",
        &format!("/v1/jobs/{id}/cancel"),
        Some(&key),
        Some(json!({"mode": "kill"})),
    )
    .await;
    assert_eq!(resp.status, 202, "{resp:?}");
    let view: Value = resp.json();
    assert_eq!(view["cancel"], json!("immediate"));
    assert_eq!(
        node.job().await,
        HubJobMsg::Cancel {
            job: id.clone(),
            mode: vk_hub_proto::client::CancelMode::Immediate
        }
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn output_past_the_cap_is_acked_and_dropped_and_the_cap_has_a_ceiling() {
    let dir = scratch("output-cap");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 16384).await;
    let submit = |n: u8, limit: u64| {
        let mut body = job_body(n, None, 30);
        body["spec"]["trace"]["limit_bytes"] = json!(limit);
        body
    };
    let resp = api(addr, "POST", "/v1/jobs", Some(&key), Some(submit(1, 16))).await;
    assert_eq!(resp.status, 201, "{resp:?}");
    let id = resp.json::<JobView>().id;
    let HubJobMsg::Start(_) = node.job().await else {
        panic!("expected a start");
    };
    node.send(NodeJobMsg::Job {
        job: id.clone(),
        state: RunState::Accepted,
    });
    view_until(addr, &key, &id, |v| v.state == JobState::Running).await;
    let cap = 16 + 64 * 1024;
    assert_eq!(crate::jobs::testing::output_cap(&hub, &id), cap);
    // Chunks up to and well past the cap: each acked to its end, the session kept.
    let chunk = vec![b'x'; 60_000];
    for n in 0..4u64 {
        node.send(output(&id, n * 60_000, &chunk));
        assert_eq!(
            node.job().await,
            HubJobMsg::OutputAck {
                job: id.clone(),
                offset: (n + 1) * 60_000
            }
        );
    }
    let view = view_until(addr, &key, &id, |_| true).await;
    assert_eq!(view.output_len, cap);
    node.send(NodeJobMsg::Result {
        job: id.clone(),
        result: result(None, 240_000),
    });
    assert_eq!(node.job().await, HubJobMsg::Recorded { job: id.clone() });

    // A trace limit past what the hub stores is held to the hub's.
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(submit(2, 1 << 40)),
    )
    .await;
    let id = resp.json::<JobView>().id;
    assert_eq!(crate::jobs::testing::output_cap(&hub, &id), 64 << 20);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_replaced_or_ended_ends_its_reservations() {
    let dir = scratch("resv-session");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let node_key = keypair();
    let id = new_node(addr, &hub, &node_key).await;
    let mut first = connect(addr, &id, &node_key, V3, 16384, Some(Held::default())).await;
    wait_until(|| crate::jobs::testing::linked(&hub, &id) && heard(&hub, &id)).await;
    let grant = reserve_on(addr, &key, &mut first, 1).await;
    let held = |r: &str| Held {
        reservations: vec![HeldReservation {
            reservation: r.to_string(),
            envelope: envelope(),
            remaining_secs: 60,
        }],
        jobs: vec![],
    };
    let renew = |r: String| {
        let key = key.clone();
        async move {
            api(
                addr,
                "POST",
                &format!("/v1/reservations/{r}/renew"),
                Some(&key),
                Some(json!({"lease_secs": 90})),
            )
            .await
        }
    };

    // A second session while the first is open: the reservation ends, and is released when
    // the node names it.
    let mut second = connect(
        addr,
        &id,
        &node_key,
        V3,
        16384,
        Some(held(&grant.reservation)),
    )
    .await;
    assert_eq!(
        second.job().await,
        HubJobMsg::Release {
            reservation: grant.reservation.clone()
        }
    );
    assert_eq!(crate::jobs::testing::reservations(&hub), 0);
    let resp = renew(grant.reservation.clone()).await;
    assert_eq!(
        (resp.status, resp.code()),
        (410, ErrorCode::ReservationGone)
    );
    drop(first);

    // The session ends: so does its reservation, released when the node is back.
    wait_until(|| heard(&hub, &id)).await;
    let grant = reserve_on(addr, &key, &mut second, 2).await;
    drop(second);
    wait_until(|| crate::jobs::testing::reservations(&hub) == 0).await;
    let resp = renew(grant.reservation.clone()).await;
    assert_eq!(
        (resp.status, resp.code()),
        (410, ErrorCode::ReservationGone)
    );
    let mut third = connect(
        addr,
        &id,
        &node_key,
        V3,
        16384,
        Some(held(&grant.reservation)),
    )
    .await;
    assert_eq!(
        third.job().await,
        HubJobMsg::Release {
            reservation: grant.reservation.clone()
        }
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn capacity_revisions_are_kept_for_a_bounded_number_of_placements() {
    let dir = scratch("capacity-cap");
    let (_, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let asked = |i: usize| Placement {
        labels: vec![format!("l{i}")],
        ..placement()
    };
    let first = crate::jobs::capacity(&hub, &asked(0)).await.unwrap();
    assert_eq!(crate::jobs::capacity(&hub, &asked(0)).await.unwrap(), first);
    let mut latest = first.revision;
    for i in 1..=1100 {
        latest = latest.max(
            crate::jobs::capacity(&hub, &asked(i))
                .await
                .unwrap()
                .revision,
        );
    }
    assert_eq!(crate::jobs::testing::capacity_entries(&hub), 1024);
    // The first, forgotten, comes back with a revision past every one given out.
    let again = crate::jobs::capacity(&hub, &asked(0)).await.unwrap();
    assert!(again.revision > latest, "{again:?} after {latest}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn submissions_past_the_live_jobs_cap_are_told_to_retry() {
    let dir = scratch("live-cap");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut first = None;
    for n in 0..8 {
        let resp = api(
            addr,
            "POST",
            "/v1/jobs",
            Some(&key),
            Some(job_body(n, None, 600)),
        )
        .await;
        assert_eq!(resp.status, 201, "{resp:?}");
        first.get_or_insert(resp.json::<JobView>().id);
    }
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(8, None, 600)),
    )
    .await;
    assert_eq!((resp.status, resp.code()), (503, ErrorCode::Unavailable));
    assert_eq!(
        resp.json::<vk_hub_proto::client::ClientError>()
            .retry_after_secs,
        Some(5)
    );
    // A request made before is answered with its job, at the cap too.
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(0, None, 600)),
    )
    .await;
    assert_eq!(resp.status, 201, "{resp:?}");
    assert_eq!(Some(resp.json::<JobView>().id), first);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn client_connections_past_the_cap_are_told_to_retry() {
    let dir = scratch("client-cap");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let ask = || Some(json!({"placement": placement()}));
    let all = u32::try_from(server::MAX_CLIENT_CONNS).unwrap();
    let held = hub.clients.clone().try_acquire_many_owned(all).unwrap();
    let resp = api(addr, "POST", "/v1/capacity", Some(&key), ask()).await;
    assert_eq!((resp.status, resp.code()), (503, ErrorCode::Unavailable));
    assert_eq!(
        resp.json::<vk_hub_proto::client::ClientError>()
            .retry_after_secs,
        Some(1)
    );
    // Room again once the connections holding it close.
    drop(held);
    let resp = api(addr, "POST", "/v1/capacity", Some(&key), ask()).await;
    assert_eq!(resp.status, 200, "{resp:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reservation_stops_offering_at_its_wait() {
    let dir = scratch("reserve-wait");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut big = ready_node(addr, &hub, 32768).await;
    let mut small = ready_node(addr, &hub, 8192).await;
    let started = std::time::Instant::now();
    let ask = tokio::spawn(async move {
        api(
            addr,
            "POST",
            "/v1/reservations",
            Some(&key),
            Some(reservation_body(1, 1)),
        )
        .await
    });
    // The first offer goes unanswered past the wait: no second node is asked.
    let HubJobMsg::Offer { .. } = big.job().await else {
        panic!("expected an offer");
    };
    let resp = ask.await.unwrap();
    assert_eq!((resp.status, resp.code()), (503, ErrorCode::NoCapacity));
    assert!(started.elapsed() < Duration::from_millis(1900));
    small.quiet(Duration::from_millis(300)).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_queued_job_ended_gives_its_reservation_back() {
    let dir = scratch("queued-resv");
    let db = Arc::new(Db::open_memory().unwrap());
    let (addr, hub) = serve_undriven(db, &dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 16384).await;
    let grant = reserve_on(addr, &key, &mut node, 1).await;
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(2, Some(&grant.reservation), 30)),
    )
    .await;
    let job: JobView = resp.json();
    assert_eq!(job.state, JobState::Queued);
    let resp = api(
        addr,
        "POST",
        &format!("/v1/jobs/{}/cancel", job.id),
        Some(&key),
        Some(json!({"mode": "graceful"})),
    )
    .await;
    assert_eq!(resp.json::<JobView>().state, JobState::Finished);
    assert_eq!(
        node.job().await,
        HubJobMsg::Release {
            reservation: grant.reservation.clone()
        }
    );
    assert_eq!(crate::jobs::testing::reservations(&hub), 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_start_on_a_reservation_counts_against_room_until_a_heartbeat_shows_it() {
    let dir = scratch("room-start");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let node_key = keypair();
    let id = new_node(addr, &hub, &node_key).await;
    // Room for two envelopes, and no heartbeat after the first.
    let mut node = connect_beating(
        addr,
        &id,
        &node_key,
        V3,
        8192,
        Some(Held::default()),
        Duration::from_secs(3600),
    )
    .await;
    wait_until(|| crate::jobs::testing::linked(&hub, &id) && heard(&hub, &id)).await;
    let fits = || async {
        crate::jobs::capacity(&hub, &placement())
            .await
            .unwrap()
            .fits
    };
    assert_eq!(fits().await, 2);
    let grant = reserve_on(addr, &key, &mut node, 1).await;
    assert_eq!(fits().await, 1);
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(2, Some(&grant.reservation), 30)),
    )
    .await;
    let job: JobView = resp.json();
    let HubJobMsg::Start(start) = node.job().await else {
        panic!("expected a start");
    };
    assert_eq!(start.job, job.id);
    view_until(addr, &key, &job.id, |v| v.state == JobState::Starting).await;
    assert_eq!(crate::jobs::testing::reservations(&hub), 0);
    assert_eq!(fits().await, 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_job_on_a_reservation_with_no_placement_window_starts() {
    let dir = scratch("window-0");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 16384).await;
    let grant = reserve_on(addr, &key, &mut node, 1).await;
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(2, Some(&grant.reservation), 0)),
    )
    .await;
    let job: JobView = resp.json();
    let HubJobMsg::Start(start) = node.job().await else {
        panic!("expected a start");
    };
    assert_eq!(
        (start.job.as_str(), start.reservation.as_deref()),
        (job.id.as_str(), Some(grant.reservation.as_str()))
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn keys_and_sizes_parse_on_the_command_line() {
    assert_eq!(parse_size("16G"), Ok(16 << 30));
    assert_eq!(parse_size("512M"), Ok(512 << 20));
    for bad in ["16", "0G", "G", "-1G", "16X"] {
        assert!(parse_size(bad).is_err(), "{bad}");
    }
    let cli = Cli::try_parse_from([
        "vk-hub",
        "keys",
        "create",
        "--name",
        "gitlab",
        "--pool",
        "ci",
        "--pool",
        "big",
        "--scope",
        "jobs",
        "--scope",
        "capacity",
        "--max-mem",
        "16G",
        "--max-cpus",
        "8",
    ])
    .unwrap();
    let Cmd::Keys {
        cmd:
            Some(KeysCmd::Create {
                name,
                scopes,
                pools,
                max_mem,
                max_cpus,
                max_disk,
                ttl,
            }),
        ..
    } = cli.cmd
    else {
        panic!("expected keys create");
    };
    assert_eq!(name, "gitlab");
    assert_eq!(scopes, [Scope::Jobs, Scope::Capacity]);
    assert_eq!(pools, ["ci", "big"]);
    assert_eq!(
        (max_mem, max_cpus, max_disk),
        (Some(16 << 30), Some(8), None)
    );
    assert_eq!(ttl, Duration::from_secs(90 * 86_400));
    // Memory below 1 MiB is refused; a limit left unset prints as any.
    assert!(
        Cli::try_parse_from([
            "vk-hub",
            "keys",
            "create",
            "--name",
            "x",
            "--pool",
            "ci",
            "--max-mem",
            "512K"
        ])
        .is_err()
    );
    assert_eq!(
        crate::store::envelope_text(Envelope {
            mem_mib: 16384,
            cpus: u32::MAX,
            disk_bytes: u64::MAX,
        }),
        "16384 MiB, any CPUs, any disk"
    );
    // A pool is required; a lifetime past a year is refused.
    assert!(Cli::try_parse_from(["vk-hub", "keys", "create", "--name", "x"]).is_err());
    assert!(
        Cli::try_parse_from([
            "vk-hub", "keys", "create", "--name", "x", "--pool", "ci", "--ttl", "400d"
        ])
        .is_err()
    );
}

#[test]
fn the_jobs_table_says_how_each_job_stands() {
    let row = |state, result: Option<JobResult>| crate::store::JobRow {
        key: "k".into(),
        key_name: "gitlab".into(),
        request_id: request_id(1),
        placement: placement(),
        title: "GitLab job 7 of g/p (test)".into(),
        job_url: None,
        project: None,
        name: None,
        created_at: 1000,
        state,
        revision: 1,
        node: Some("ab".repeat(16)),
        stage: Some("step_script".into()),
        cancel: None,
        result,
        output_len: 42,
        started_at: None,
        finished_at: None,
        settled_at: None,
        expired_at: None,
    };
    let mut running = row(JobState::Running, None);
    running.started_at = Some(1010);
    let mut measured = row(JobState::Finished, Some(result(None, 0)));
    measured.result.as_mut().unwrap().usage = Some(vk_hub_proto::job::JobUsage {
        wall_ms: 185_000,
        peak_mem_bytes: Some(3 << 30),
        ..Default::default()
    });
    let mut small = row(JobState::Finished, Some(result(None, 0)));
    small.result.as_mut().unwrap().usage = Some(vk_hub_proto::job::JobUsage {
        wall_ms: 400,
        peak_mem_bytes: Some(300 << 10),
        ..Default::default()
    });
    let out = render_jobs(
        &[
            ("aa".repeat(16), running),
            (
                "bb".repeat(16),
                row(
                    JobState::Finished,
                    Some(result(Some(FailureClass::Lost), 0)),
                ),
            ),
            ("cc".repeat(16), measured),
            ("dd".repeat(16), small),
        ],
        1060,
    );
    let lines: Vec<&str> = out.lines().collect();
    assert!(
        lines[0].starts_with("ID") && lines[0].contains("RAN") && lines[0].contains("PEAK"),
        "{out}"
    );
    // Running for 50 seconds; nothing measured yet.
    assert!(
        lines[1].contains("running: step_script")
            && lines[1].contains("1m ago")
            && lines[1].contains("50s"),
        "{out}"
    );
    assert!(lines[2].contains("failed: lost"), "{out}");
    assert!(
        lines[3].contains("succeeded") && lines[3].contains("3m05s") && lines[3].contains("3G"),
        "{out}"
    );
    // Under a second and a MiB: neither reads as nothing.
    assert!(
        lines[4].contains("<1s") && lines[4].contains(" 1M "),
        "{out}"
    );
}

/// A page of the history shows the job as the hub holds it ahead of the database, and leaves
/// out one that no longer matches the filter.
#[test]
fn a_history_page_shows_jobs_as_the_hub_holds_them() {
    use crate::store::{JobFilter, JobOutcome};
    let hub = Hub::new(Arc::new(Db::open_memory().unwrap()), None);
    let row = |n: u8| crate::store::JobRow {
        key: "k".into(),
        key_name: "gitlab".into(),
        request_id: request_id(n),
        placement: placement(),
        title: format!("GitLab job {n}"),
        job_url: None,
        project: None,
        name: None,
        created_at: 1000,
        state: JobState::Running,
        revision: 1,
        node: Some("ab".repeat(16)),
        stage: Some("step_script".into()),
        cancel: None,
        result: None,
        output_len: 0,
        started_at: Some(1000),
        finished_at: None,
        settled_at: None,
        expired_at: None,
    };
    for n in 1..=2 {
        let id = format!("{n:032x}");
        hub.db
            .submit_job(&id, &row(n), &n.to_string(), b"{}", "key gitlab", 1000)
            .unwrap();
    }
    let mut ended = row(2);
    ended.state = JobState::Finished;
    ended.revision = 2;
    ended.result = Some(result(Some(FailureClass::Script), 0));
    let (one, two) = (format!("{:032x}", 1), format!("{:032x}", 2));
    crate::jobs::testing::hold_finished(&hub, &two, ended);

    let page = crate::jobs::history(&hub, &JobFilter::default(), None, 10).unwrap();
    let states: Vec<_> = page.rows.iter().map(|r| (r.1.clone(), r.2.state)).collect();
    assert_eq!(
        states,
        [
            (two.clone(), JobState::Finished),
            (one.clone(), JobState::Running)
        ]
    );
    let running = JobFilter {
        outcome: Some(JobOutcome::Running),
        ..JobFilter::default()
    };
    let page = crate::jobs::history(&hub, &running, None, 10).unwrap();
    assert_eq!(page.rows.iter().map(|r| &r.1).collect::<Vec<_>>(), [&one]);
    // The summary is of the stored rows.
    assert_eq!(page.summary.matched, 2);
}

/// The job history's live pages wake on what changes a job's record — its submission, start,
/// stage and result — and not on its output.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_s_record_wakes_the_history_and_its_output_does_not() {
    let dir = scratch("wakes");
    // Undriven: the submission alone, nothing placed after it.
    let db = Arc::new(Db::open_memory().unwrap());
    let (addr, hub) = serve_undriven(db, &dir.join("undriven"), Duration::from_secs(60)).await;
    let jobs = hub.subscribe_jobs();
    let key = jobs_key(&hub);
    let body = job_body(1, None, 30);
    let resp = api(addr, "POST", "/v1/jobs", Some(&key), Some(body)).await;
    assert_eq!(resp.status, 201, "{resp:?}");
    assert!(jobs.has_changed().unwrap());

    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 16384).await;
    let mut jobs = hub.subscribe_jobs();
    let id = running_job(addr, &key, &mut node, 2).await;
    assert!(jobs.has_changed().unwrap());
    // A session handles its messages in order: once this output is acknowledged, the start
    // before it is written and noted.
    node.send(output(&id, 0, b"hello\n"));
    assert_eq!(
        node.job().await,
        HubJobMsg::OutputAck {
            job: id.clone(),
            offset: 6
        }
    );
    jobs.borrow_and_update();
    node.send(output(&id, 6, b"world\n"));
    assert_eq!(
        node.job().await,
        HubJobMsg::OutputAck {
            job: id.clone(),
            offset: 12
        }
    );
    assert!(!jobs.has_changed().unwrap());
    node.send(NodeJobMsg::Job {
        job: id.clone(),
        state: RunState::Running {
            stage: "step_script".into(),
        },
    });
    wait_until(|| jobs.has_changed().unwrap()).await;
    jobs.borrow_and_update();
    node.send(NodeJobMsg::Result {
        job: id.clone(),
        result: result(None, 6),
    });
    assert_eq!(node.job().await, HubJobMsg::Recorded { job: id.clone() });
    assert!(jobs.has_changed().unwrap());
    std::fs::remove_dir_all(&dir).unwrap();
}
