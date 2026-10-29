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
use vk_hub_proto::client::{
    Capacity, ErrorCode, INSTANCE_HEADER, JobState, JobView, Placement, ReservationGrant,
};
use vk_hub_proto::dispatch::{
    Held, HeldJob, HeldReservation, HubJobMsg, LeaseEnd, LeaseState, NodeJobMsg, OfferReply,
    Refusal, RunState,
};
use vk_hub_proto::job::{
    CiJob, Envelope, FailureClass, JobEvent, JobEventKind, JobResult, JobSpec, MAX_JOB_EVENTS,
};
use vk_hub_proto::{
    Admission, FsUsage, Hardware, Heartbeat, HubMsg, Inventory, JOBS, NodeMsg, NodeState, Report,
    StorageRole, VersionRange,
};

use super::*;
use crate::store::{KeyPolicy, NoAccess, RegistryAccess, Scope};

mod capacity;
mod capacity_placement;
mod capacity_recovery;

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
    serve_hub_with(db, dir, lost_after, |hub| hub).await
}

/// A hub as [`serve_hub`]'s, configured by `configure` past its jobs' defaults.
async fn serve_hub_with(
    db: Arc<Db>,
    dir: &std::path::Path,
    lost_after: Duration,
    configure: impl FnOnce(Hub) -> Hub,
) -> (SocketAddr, Arc<Hub>) {
    let (addr, hub) = serve_undriven_with(db, dir, lost_after, configure).await;
    tokio::spawn(crate::jobs::drive(hub.clone()));
    (addr, hub)
}

/// A hub as [`serve_hub`]'s with no placement loop: its jobs stay queued.
async fn serve_undriven(
    db: Arc<Db>,
    dir: &std::path::Path,
    lost_after: Duration,
) -> (SocketAddr, Arc<Hub>) {
    serve_undriven_with(db, dir, lost_after, |hub| hub).await
}

/// A hub as [`serve_undriven`]'s, configured by `configure` past its jobs' defaults.
async fn serve_undriven_with(
    db: Arc<Db>,
    dir: &std::path::Path,
    lost_after: Duration,
    configure: impl FnOnce(Hub) -> Hub,
) -> (SocketAddr, Arc<Hub>) {
    let listener = server::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let hub = Arc::new(configure(
        Hub::new(db, None)
            .with_token_keys(dir.join("token-keys"), crate::tokens::DEFAULT_MAX_JOB_TOKEN)
            .with_jobs(dir.join("jobs"), lost_after, None)
            .unwrap(),
    ));
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

/// An API key for pool `ci` with scope `jobs`, named `gitlab`.
fn plain_key(hub: &Hub) -> String {
    api_key(
        hub,
        "gitlab",
        &[Scope::Jobs],
        now_secs(),
        Duration::from_secs(3600),
    )
}

/// The GitLab server of [`spec`]'s jobs, approved as instance `gl`.
const GITLAB_URL: &str = "https://gitlab.example.com";

/// The project of [`spec`]'s jobs, approved.
const PROJECT_ID: u64 = 7;

/// A relay enrolled with `hub` and bound to [`GITLAB_URL`], approved as instance `gl` with
/// project [`PROJECT_ID`], connected ([`connect_relay`]): its credential for [`api`],
/// `relay:<id>:<seed hex>`. Its `concurrent` is 64 and its runner's `request_concurrency` 1,
/// as vk-gitlab's defaults ([`relay_limits`]).
fn jobs_key(hub: &Hub) -> String {
    let key = enrolled_key(hub);
    connect_relay(hub, relay_id(&key));
    key
}

/// [`jobs_key`]'s relay before it ever connects.
fn enrolled_key(hub: &Hub) -> String {
    let seed: [u8; 32] = vk_hub_proto::from_hex_lower(&random_hex(32).unwrap()).unwrap();
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let public = vk_hub_proto::to_hex(ring::signature::KeyPair::public_key(&pair).as_ref());
    let (token, _) = hub
        .db
        .create_token_for(
            crate::store::TokenKind::Gitlab,
            Duration::from_secs(60),
            None,
            "u",
            now_secs(),
        )
        .unwrap();
    let crate::store::RelayEnrollment::Enrolled { id } = hub
        .db
        .enroll_relay(&token, &public, "relay-1", "peer p", now_secs())
        .unwrap()
    else {
        panic!("expected an enrollment");
    };
    let inventory = vk_hub_proto::gitlab::Inventory {
        hostname: "relay-1".into(),
        concurrent: 64,
        runners: vec![vk_hub_proto::gitlab::Runner {
            name: "test".into(),
            runner_id: Some(42),
            placement: placement(),
            limit: None,
            request_concurrency: 1,
            verified: true,
        }],
        server: vk_hub_proto::gitlab::Server {
            url: GITLAB_URL.into(),
            ..Default::default()
        },
        ..Default::default()
    };
    hub.db
        .record_relay(
            &id,
            crate::store::RelayWrite::Inventory(inventory),
            now_secs(),
        )
        .unwrap();
    if hub.db.gitlab("gl").unwrap().is_none() {
        hub.db
            .add_gitlab("gl", GITLAB_URL, "u", now_secs())
            .unwrap();
    }
    let project = crate::store::ProjectRef::parse(&format!("{PROJECT_ID}:group/project")).unwrap();
    hub.db
        .decide_projects(
            "gl",
            &[project],
            crate::store::Decision::Approve,
            "u",
            now_secs(),
        )
        .unwrap();
    let mut policy = hub.db.capacity_policy().unwrap();
    policy
        .tenants
        .entry("tests".into())
        .or_insert_with(|| crate::policy::Tenant {
            weight: 1,
            cap: None,
            // [`spec`]'s project, and the one the approval tests' [`bound_body`] uses.
            projects: [PROJECT_ID, 42]
                .into_iter()
                .map(|id| crate::policy::Project {
                    gitlab: "gl".into(),
                    id,
                    production_branches: vec![],
                    placement_rules: vec![],
                })
                .collect(),
        });
    if policy.runner("gl", 42).is_none() {
        policy.runners.push(crate::policy::RunnerMapping {
            gitlab: "gl".into(),
            runner_id: 42,
            tenant: "tests".into(),
            class: crate::policy::Class::Normal,
        });
    }
    hub.db
        .set_capacity_policy(&policy, "tests", now_secs())
        .unwrap();
    format!("relay:{id}:{}", vk_hub_proto::to_hex(&seed))
}

/// Have relay `id` open a session at relay protocol 2 and send a heartbeat in it listing no
/// admission, as a relay does on connecting.
fn connect_relay(hub: &Hub, id: &str) {
    let (session, _) = hub.open_session(id);
    hub.db
        .record_relay_session(id, "test", 2, now_secs(), || true)
        .unwrap();
    let inventory = hub.db.relay(id).unwrap().unwrap().inventory.unwrap();
    let runners = inventory
        .runners
        .iter()
        .map(|runner| vk_hub_proto::gitlab::RunnerLoad {
            name: runner.name.clone(),
            ..Default::default()
        })
        .collect();
    hub.db
        .record_relay_from_session(
            id,
            crate::store::RelayWrite::Heartbeat(vk_hub_proto::gitlab::Heartbeat { runners }),
            now_secs(),
            Some(session),
            || true,
        )
        .unwrap();
    hub.heartbeat_stored(id, session, tokio::time::Instant::now());
}

/// Set the concurrency limits of [`jobs_key`]'s relay: its `concurrent` and its runner's
/// `request_concurrency`, past the defaults of 64 and 1 for a test that needs more.
fn relay_limits(hub: &Hub, key: &str, concurrent: u32, request_concurrency: u32) {
    let id = relay_id(key);
    let mut inventory = hub.db.relay(id).unwrap().unwrap().inventory.unwrap();
    inventory.concurrent = concurrent;
    for runner in &mut inventory.runners {
        runner.request_concurrency = request_concurrency;
    }
    hub.db
        .record_relay(
            id,
            crate::store::RelayWrite::Inventory(inventory),
            now_secs(),
        )
        .unwrap();
}

/// What the audit log calls the relay of credential `key`, from [`jobs_key`].
fn actor_of(key: &str) -> String {
    let id = key
        .strip_prefix("relay:")
        .unwrap()
        .split(':')
        .next()
        .unwrap();
    format!("relay {id}")
}

fn relay_id(key: &str) -> &str {
    key.strip_prefix("relay:")
        .unwrap()
        .split(':')
        .next()
        .unwrap()
}

/// The headers authenticating a request as [`jobs_key`]'s relay or with an API key.
fn auth_headers(key: &str, method: &str, path: &str, body: &[u8]) -> String {
    let Some((id, seed)) = key.strip_prefix("relay:").and_then(|k| k.split_once(':')) else {
        return format!("Authorization: Bearer {key}\r\n");
    };
    let seed: [u8; 32] = vk_hub_proto::from_hex_lower(seed).unwrap();
    let pair = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    let at = now_secs();
    let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(body).into();
    let message = vk_hub_proto::client::client_request_message(
        id,
        method,
        path,
        &digest,
        at,
        vk_hub_proto::Channel::Plaintext,
    );
    let signature = vk_hub_proto::to_hex(pair.sign(&message).as_ref());
    format!(
        "{}: {id}\r\n{}: {at}\r\n{}: {signature}\r\n",
        vk_hub_proto::client::RELAY_HEADER,
        vk_hub_proto::TIME_HEADER,
        vk_hub_proto::SIGNATURE_HEADER
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
    api_as(addr, method, path, key, None, body).await
}

/// [`api`], naming client instance `instance`.
async fn api_as(
    addr: SocketAddr,
    method: &str,
    path: &str,
    key: Option<&str>,
    instance: Option<&str>,
    body: Option<Value>,
) -> Resp {
    let body = body
        .map(|b| serde_json::to_vec(&b).unwrap())
        .unwrap_or_default();
    let auth = key
        .map(|k| auth_headers(k, method, path, &body))
        .unwrap_or_default();
    let instance = instance
        .map(|i| format!("{INSTANCE_HEADER}: {i}\r\n"))
        .unwrap_or_default();
    send_raw(addr, method, path, &format!("{auth}{instance}"), &body).await
}

/// A request with `headers`, each line ending in CRLF, and `body`, on a connection of its own.
async fn send_raw(addr: SocketAddr, method: &str, path: &str, headers: &str, body: &[u8]) -> Resp {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: hub\r\n{headers}\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
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

fn relay_reservation_body(n: u8, wait_secs: u32) -> Value {
    let mut body = reservation_body(n, wait_secs);
    body["runner"] = json!("test");
    body
}

fn spec(gitlab_id: u64) -> JobSpec {
    let mut ci = CiJob {
        server_url: "https://gitlab.example.com".into(),
        ..CiJob::default()
    };
    ci.job.id = gitlab_id;
    ci.job.runner_id = 42;
    ci.job.project_path = "group/project".into();
    ci.job.project_id = PROJECT_ID;
    ci.job.name = "test".into();
    ci.job.pipeline_id = 900 + gitlab_id;
    ci.sources.git_ref = "feature/\u{202e}menu".into();
    ci.sources.sha = "0123456789ABCDEF0123456789ABCDEF01234567".into();
    ci.token = "glcbt-secret".into();
    ci.trace.limit_bytes = 1 << 20;
    JobSpec::GitlabCi(ci)
}

fn job_body(n: u8, reservation: Option<&str>, place_within_secs: u32) -> Value {
    let mut body = json!({
        "runner": "test",
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
        heartbeat(mem_mib, None),
        held,
        Duration::from_millis(300),
    )
    .await
}

/// A heartbeat with `mem_mib` free, and `load1_hundredths` the load average.
fn heartbeat(mem_mib: u64, load1_hundredths: Option<u32>) -> Heartbeat {
    Heartbeat {
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
        load1_hundredths,
        ..Heartbeat::default()
    }
}

/// [`connect`], sending `heartbeat` every `beat` after the first.
async fn connect_beating(
    addr: SocketAddr,
    id: &str,
    key: &Ed25519KeyPair,
    versions: VersionRange,
    heartbeat: Heartbeat,
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
    loaded_node(addr, hub, mem_mib, None).await
}

/// [`ready_node`], reporting `load1_hundredths` as its load average.
async fn loaded_node(
    addr: SocketAddr,
    hub: &Hub,
    mem_mib: u64,
    load1_hundredths: Option<u32>,
) -> FakeNode {
    let key = keypair();
    let id = new_node(addr, hub, &key).await;
    let node = connect_beating(
        addr,
        &id,
        &key,
        V3,
        heartbeat(mem_mib, load1_hundredths),
        Some(Held::default()),
        Duration::from_millis(300),
    )
    .await;
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

/// Why `gl` runner `runner_id`'s request waits after a placement pass.
async fn reason_now(hub: &Hub, runner_id: u64) -> Option<&'static str> {
    crate::jobs::testing::step(hub).await;
    let snapshot = crate::jobs::arbitration_snapshot(hub).unwrap();
    snapshot
        .get(&("gl".to_string(), runner_id))
        .and_then(|v| v.reason)
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

/// The audit events naming job `id`, oldest first.
fn job_audit(hub: &Hub, id: &str) -> Vec<String> {
    hub.db
        .audits(None, 50)
        .unwrap()
        .into_iter()
        .map(|r| r.event)
        .filter(|e| e.contains(id))
        .collect()
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
async fn reserve_on(
    addr: SocketAddr,
    key: &str,
    node: &mut FakeNode,
    n: u8,
    runner: Option<&str>,
) -> ReservationGrant {
    let key = key.to_string();
    let mut body = reservation_body(n, 5);
    if let Some(runner) = runner {
        body["runner"] = json!(runner);
    }
    let ask =
        tokio::spawn(
            async move { api(addr, "POST", "/v1/reservations", Some(&key), Some(body)).await },
        );
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
        events: Vec::new(),
        egress: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn capacity_checks_the_explicit_runner_identity() {
    let dir = scratch("runner-identity");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let id = relay_id(&key);
    let inventory = hub.db.relay(id).unwrap().unwrap().inventory.unwrap();
    let capacity = |runner: Option<&str>| {
        let mut body = json!({"placement": placement()});
        if let Some(runner) = runner {
            body["runner"] = json!(runner);
        }
        body
    };
    let missing = api(
        addr,
        "POST",
        "/v1/capacity",
        Some(&key),
        Some(capacity(None)),
    )
    .await;
    assert_eq!(
        (missing.status, missing.code()),
        (403, ErrorCode::Forbidden)
    );
    let missing = api(
        addr,
        "POST",
        "/v1/reservations",
        Some(&key),
        Some(reservation_body(1, 0)),
    )
    .await;
    assert_eq!(
        (missing.status, missing.code()),
        (403, ErrorCode::Forbidden)
    );

    let api_key = plain_key(&hub);
    let named = api(
        addr,
        "POST",
        "/v1/capacity",
        Some(&api_key),
        Some(capacity(Some("test"))),
    )
    .await;
    assert_eq!((named.status, named.code()), (403, ErrorCode::Forbidden));
    let named = api(
        addr,
        "POST",
        "/v1/reservations",
        Some(&api_key),
        Some(relay_reservation_body(1, 0)),
    )
    .await;
    assert_eq!((named.status, named.code()), (403, ErrorCode::Forbidden));

    let mut unverified = inventory.clone();
    unverified.runners[0].verified = false;
    let mut zero = inventory.clone();
    zero.runners[0].runner_id = Some(0);
    let mut duplicate = inventory.clone();
    duplicate.runners.push(duplicate.runners[0].clone());
    for invalid in [unverified, zero, duplicate] {
        hub.db
            .record_relay(id, crate::store::RelayWrite::Inventory(invalid), now_secs())
            .unwrap();
        let resp = api(
            addr,
            "POST",
            "/v1/capacity",
            Some(&key),
            Some(capacity(Some("test"))),
        )
        .await;
        assert_eq!((resp.status, resp.code()), (403, ErrorCode::Forbidden));
    }
    hub.db
        .record_relay(
            id,
            crate::store::RelayWrite::Inventory(inventory),
            now_secs(),
        )
        .unwrap();
    let resp = api(
        addr,
        "POST",
        "/v1/capacity",
        Some(&key),
        Some(capacity(Some("test"))),
    )
    .await;
    assert_eq!(resp.status, 200, "{resp:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Each way a relay's runner can fail to resolve is refused with its own reason.
#[tokio::test(flavor = "multi_thread")]
async fn each_unresolvable_runner_is_refused_with_its_reason() {
    let dir = scratch("runner-reasons");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let id = relay_id(&key);
    let inventory = hub.db.relay(id).unwrap().unwrap().inventory.unwrap();
    let ask = |runner: &str, placement: Placement| {
        let (key, runner) = (key.clone(), runner.to_owned());
        async move {
            api(
                addr,
                "POST",
                "/v1/capacity",
                Some(&key),
                Some(json!({"runner": runner, "placement": placement})),
            )
            .await
        }
    };
    let refused = |resp: &Resp, reason: &str| {
        assert_eq!(
            (resp.status, resp.code()),
            (403, ErrorCode::Forbidden),
            "{resp:?}"
        );
        let message = resp.json::<vk_hub_proto::client::ClientError>().error;
        assert!(message.contains(reason), "{message}");
    };
    let missing = api(
        addr,
        "POST",
        "/v1/capacity",
        Some(&key),
        Some(json!({"placement": placement()})),
    )
    .await;
    refused(&missing, "upgrade vk-gitlab");
    refused(&ask("other", placement()).await, "absent");
    let mut other = placement();
    other.envelope.cpus += 1;
    refused(&ask("test", other).await, "placement differs");

    let mut no_id = inventory.clone();
    no_id.runners[0].runner_id = None;
    hub.db
        .record_relay(id, crate::store::RelayWrite::Inventory(no_id), now_secs())
        .unwrap();
    refused(&ask("test", placement()).await, "no GitLab runner ID");
    hub.db
        .record_relay(
            id,
            crate::store::RelayWrite::Inventory(inventory),
            now_secs(),
        )
        .unwrap();

    let mut policy = hub.db.capacity_policy().unwrap();
    let expected = policy.digest().unwrap();
    policy.runners.retain(|r| r.runner_id != 42);
    hub.db
        .replace_capacity_policy_if(&policy, &expected, "tests", now_secs())
        .unwrap();
    refused(
        &ask("test", placement()).await,
        "gl/42 is mapped to no capacity tenant",
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// New jobs must name their runner, belong to that runner, and use a project listed for
/// its tenant.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_job_must_be_its_runner_s_and_of_its_tenant_s_projects() {
    let dir = scratch("job-identity");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let submit = |body: Value| {
        let key = key.clone();
        async move { api(addr, "POST", "/v1/jobs", Some(&key), Some(body)).await }
    };
    let mut body = job_body(1, None, 30);
    body.as_object_mut().unwrap().remove("runner");
    let resp = submit(body).await;
    assert_eq!(
        (resp.status, resp.code()),
        (403, ErrorCode::Forbidden),
        "{resp:?}"
    );

    let mut body = job_body(2, None, 30);
    body["spec"]["job"]["runner_id"] = json!(43);
    let resp = submit(body).await;
    assert_eq!(
        (resp.status, resp.code()),
        (403, ErrorCode::Forbidden),
        "{resp:?}"
    );

    // Approved on the hub, but not one of the tenant's projects.
    let other = crate::store::ProjectRef::parse("999:group/other").unwrap();
    hub.db
        .decide_projects(
            "gl",
            &[other],
            crate::store::Decision::Approve,
            "u",
            now_secs(),
        )
        .unwrap();
    let mut body = job_body(3, None, 30);
    body["spec"]["job"]["project_id"] = json!(999);
    body["spec"]["job"]["project_path"] = json!("group/other");
    let resp = submit(body).await;
    assert_eq!(
        (resp.status, resp.code()),
        (403, ErrorCode::Forbidden),
        "{resp:?}"
    );

    let mut body = job_body(4, None, 30);
    body["spec"]["job"]["project_id"] = json!(0);
    let resp = submit(body).await;
    assert_eq!(
        (resp.status, resp.code()),
        (400, ErrorCode::Invalid),
        "{resp:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Granted reservations and accepted jobs replay after their runner becomes unverified.
#[tokio::test(flavor = "multi_thread")]
async fn a_granted_reservation_replays_after_its_runner_is_unverified() {
    let dir = scratch("reservation-replay");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 16384).await;
    let grant = reserve_on(addr, &key, &mut node, 1, Some("test")).await;
    let id = relay_id(&key);
    let mut inventory = hub.db.relay(id).unwrap().unwrap().inventory.unwrap();
    inventory.runners[0].verified = false;
    hub.db
        .record_relay(
            id,
            crate::store::RelayWrite::Inventory(inventory),
            now_secs(),
        )
        .unwrap();
    let mut body = reservation_body(1, 5);
    body["runner"] = json!("test");
    let again = api(addr, "POST", "/v1/reservations", Some(&key), Some(body)).await;
    assert_eq!(
        (again.status, again.json::<ReservationGrant>()),
        (201, grant),
        "{again:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn accepted_job_replays_after_its_runner_is_unverified() {
    let dir = scratch("identity-replay");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let body = job_body(1, None, 30);
    let first = api(addr, "POST", "/v1/jobs", Some(&key), Some(body.clone())).await;
    assert_eq!(first.status, 201, "{first:?}");
    let id = relay_id(&key);
    let mut inventory = hub.db.relay(id).unwrap().unwrap().inventory.unwrap();
    inventory.runners[0].verified = false;
    hub.db
        .record_relay(
            id,
            crate::store::RelayWrite::Inventory(inventory),
            now_secs(),
        )
        .unwrap();
    let again = api(addr, "POST", "/v1/jobs", Some(&key), Some(body)).await;
    assert_eq!(again.status, 201, "{again:?}");
    assert_eq!(first.json::<JobView>().id, again.json::<JobView>().id);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn production_runner_requires_a_mapped_project_and_branch() {
    let dir = scratch("production-identity");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut policy = hub.db.capacity_policy().unwrap();
    let expected = policy.digest().unwrap();
    policy
        .runners
        .iter_mut()
        .find(|r| r.runner_id == 42)
        .unwrap()
        .class = crate::policy::Class::Production;
    policy
        .tenants
        .get_mut("tests")
        .unwrap()
        .projects
        .iter_mut()
        .find(|p| p.id == PROJECT_ID)
        .unwrap()
        .production_branches
        .push("main".into());
    hub.db
        .replace_capacity_policy_if(&policy, &expected, "tests", now_secs())
        .unwrap();
    let mut body = job_body(3, None, 30);
    body["spec"]["sources"]["ref"] = json!("main");
    body["spec"]["sources"]["refspecs"] = json!(["+refs/heads/main:refs/remotes/origin/main"]);
    // A merge request's pipeline, then another branch's.
    let mut wrong = body.clone();
    wrong["request_id"] = json!(format!("{:032}", 1));
    wrong["spec"]["sources"]["refspecs"] =
        json!(["+refs/merge-requests/1/head:refs/merge-requests/1/head"]);
    let resp = api(addr, "POST", "/v1/jobs", Some(&key), Some(wrong)).await;
    assert_eq!(
        (resp.status, resp.code()),
        (403, ErrorCode::Forbidden),
        "{resp:?}"
    );
    let mut wrong = body.clone();
    wrong["request_id"] = json!(format!("{:032}", 2));
    wrong["spec"]["sources"]["ref"] = json!("feature");
    wrong["spec"]["sources"]["refspecs"] =
        json!(["+refs/heads/feature:refs/remotes/origin/feature"]);
    let resp = api(addr, "POST", "/v1/jobs", Some(&key), Some(wrong)).await;
    assert_eq!(
        (resp.status, resp.code()),
        (403, ErrorCode::Forbidden),
        "{resp:?}"
    );
    let resp = api(addr, "POST", "/v1/jobs", Some(&key), Some(body)).await;
    assert_eq!(resp.status, 201, "{resp:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// What a relay asks of the hub that takes capacity: a capacity reading, a reservation
/// queued and one not, and a new job; each as `key`'s, with request number `n` and up.
async fn acquisitions(addr: SocketAddr, key: &str, n: u8) -> Vec<(&'static str, Resp)> {
    let mut queued = relay_reservation_body(n, 0);
    queued["queue"] = json!(true);
    let asks = [
        (
            "capacity",
            "/v1/capacity",
            json!({"runner": "test", "placement": placement()}),
        ),
        (
            "reservation",
            "/v1/reservations",
            relay_reservation_body(n + 1, 0),
        ),
        ("queued reservation", "/v1/reservations", queued),
        ("job", "/v1/jobs", job_body(n + 2, None, 30)),
    ];
    let mut out = Vec::new();
    for (what, path, body) in asks {
        out.push((what, api(addr, "POST", path, Some(key), Some(body)).await));
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn version_one_relay_can_settle_held_work_but_cannot_acquire() {
    let dir = scratch("legacy-relay-settle");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 16384).await;
    let job = running_job(addr, &key, &mut node, 1).await;
    let canceled = running_job(addr, &key, &mut node, 2).await;
    hub.db
        .record_relay_session(relay_id(&key), "legacy", 1, now_secs(), || true)
        .unwrap();
    for (what, resp) in acquisitions(addr, &key, 3).await {
        assert_eq!(
            (resp.status, resp.code()),
            (403, ErrorCode::Forbidden),
            "{what}: {resp:?}"
        );
    }
    // It has no ticket to poll.
    let path = format!("/v1/reservations/tickets/{}", "0".repeat(32));
    let resp = api(addr, "GET", &path, Some(&key), None).await;
    assert_eq!(resp.status, 410, "{resp:?}");
    // What it holds it still replays, reads, cancels and settles.
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(1, None, 30)),
    )
    .await;
    assert_eq!(resp.status, 201, "{resp:?}");
    assert_eq!(resp.json::<JobView>().id, job);
    let path = format!("/v1/jobs/{job}/output?offset=0");
    let resp = api(addr, "GET", &path, Some(&key), None).await;
    assert_eq!(resp.status, 200, "{resp:?}");
    let resp = api(
        addr,
        "POST",
        &format!("/v1/jobs/{canceled}/cancel"),
        Some(&key),
        Some(json!({"mode": "immediate"})),
    )
    .await;
    assert_eq!(resp.status, 202, "{resp:?}");
    assert_eq!(
        node.job().await,
        HubJobMsg::Cancel {
            job: canceled,
            mode: vk_hub_proto::client::CancelMode::Immediate,
        }
    );
    node.send(NodeJobMsg::Result {
        job: job.clone(),
        result: result(None, 0),
    });
    assert_eq!(node.job().await, HubJobMsg::Recorded { job: job.clone() });
    view_until(addr, &key, &job, |v| v.state == JobState::Finished).await;
    let resp = api(
        addr,
        "POST",
        &format!("/v1/jobs/{job}/settle"),
        Some(&key),
        None,
    )
    .await;
    assert_eq!(resp.status, 204, "{resp:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A relay that never opened a session has said no protocol: it acquires nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_never_connected_cannot_acquire() {
    let dir = scratch("unconnected-relay");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = enrolled_key(&hub);
    for (what, resp) in acquisitions(addr, &key, 1).await {
        assert_eq!(
            (resp.status, resp.code()),
            (403, ErrorCode::Forbidden),
            "{what}: {resp:?}"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn api_keys_are_checked_on_every_request() {
    let dir = scratch("keys");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let ask = || Some(json!({"placement": placement()}));
    let key = plain_key(&hub);
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

/// A relay is who its signature says, over the request's method, path, body and time, while
/// it is enrolled; only a relay submits GitLab jobs, and a hello is not its.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_signs_each_request() {
    let dir = scratch("relay-signed");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let ask = serde_json::to_vec(&json!({"runner": "test", "placement": placement()})).unwrap();
    let signed = |path: &str, body: &[u8]| auth_headers(&key, "POST", path, body);
    let resp = send_raw(
        addr,
        "POST",
        "/v1/capacity",
        &signed("/v1/capacity", &ask),
        &ask,
    )
    .await;
    assert_eq!(resp.status, 200, "{resp:?}");
    // Signed over another body, path or method; a time out of skew; an unknown relay.
    let other = serde_json::to_vec(&json!({"placement": placement(), "wait_secs": 1})).unwrap();
    for headers in [
        signed("/v1/capacity", &other),
        signed("/v1/reservations", &ask),
        auth_headers(&key, "GET", "/v1/capacity", &ask),
        signed("/v1/capacity", &ask).replace(
            &format!("{}: {}", vk_hub_proto::TIME_HEADER, now_secs()),
            &format!("{}: {}", vk_hub_proto::TIME_HEADER, now_secs() - 600),
        ),
        signed("/v1/capacity", &ask).replace(
            &format!("{}: ", vk_hub_proto::client::RELAY_HEADER),
            &format!("{}: {}", vk_hub_proto::client::RELAY_HEADER, "0".repeat(32)),
        ),
    ] {
        let resp = send_raw(addr, "POST", "/v1/capacity", &headers, &ask).await;
        assert_eq!(
            (resp.status, resp.code()),
            (401, ErrorCode::Unauthorized),
            "{headers}"
        );
    }
    // A relay's hello is refused: it reports in its session.
    let hello = serde_json::to_vec(&hello_body("s_1")).unwrap();
    let resp = send_raw(
        addr,
        "POST",
        "/v1/clients",
        &signed("/v1/clients", &hello),
        &hello,
    )
    .await;
    assert_eq!((resp.status, resp.code()), (403, ErrorCode::Forbidden));
    assert!(hub.db.clients().unwrap().is_empty());
    // An API key's GitLab job is refused.
    let plain = plain_key(&hub);
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&plain),
        Some(job_body(1, None, 300)),
    )
    .await;
    assert_eq!((resp.status, resp.code()), (403, ErrorCode::Forbidden));
    // A removed relay is no one.
    let id = actor_of(&key).trim_start_matches("relay ").to_string();
    assert!(crate::relays::remove(&hub, "uid 0", &id).unwrap());
    let resp = send_raw(
        addr,
        "POST",
        "/v1/capacity",
        &signed("/v1/capacity", &ask),
        &ask,
    )
    .await;
    assert_eq!((resp.status, resp.code()), (401, ErrorCode::Unauthorized));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A job of a project not approved is refused and makes it pending; a retry of that request
/// gets the same answer and counts once, approved or not, and the project's next job passes.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_of_a_project_not_approved_is_refused_until_it_is() {
    let dir = scratch("relay-gate");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let submit = |body: Value| {
        let key = key.clone();
        async move { api(addr, "POST", "/v1/jobs", Some(&key), Some(body)).await }
    };
    let resp = submit(bound_body(1, 42, "acme/web", 600)).await;
    assert_eq!(
        (resp.status, resp.code()),
        (403, ErrorCode::ApprovalPending)
    );
    let error = resp.json::<vk_hub_proto::client::ClientError>().error;
    assert!(error.contains("acme/web (ID 42)"), "{error}");
    let resp = submit(bound_body(1, 42, "acme/web", 600)).await;
    assert_eq!(
        (resp.status, resp.code()),
        (403, ErrorCode::ApprovalPending)
    );
    // The same request ID with another body is a conflict.
    let resp = submit(bound_body(1, 42, "acme/site", 600)).await;
    assert_eq!((resp.status, resp.code()), (409, ErrorCode::Conflict));
    let pending = hub.db.gitlab_projects(Some("gl")).unwrap();
    let p = pending.iter().find(|p| p.id == 42).unwrap();
    assert_eq!(
        (p.row.state, p.row.refused),
        (crate::store::ProjectState::Pending, 1)
    );
    approve(&hub, "42");
    let resp = submit(bound_body(1, 42, "acme/web", 600)).await;
    assert_eq!(
        (resp.status, resp.code()),
        (403, ErrorCode::ApprovalPending)
    );
    let resp = submit(bound_body(2, 42, "acme/web", 600)).await;
    assert_eq!(resp.status, 201, "{resp:?}");
    let row = hub.db.job(&resp.json::<JobView>().id).unwrap().unwrap();
    assert_eq!(
        (row.gitlab.as_deref(), row.project_id),
        (Some("gl"), Some(42))
    );
    assert_eq!(row.key_name, "relay-1");
    // Once accepted, a later rejection leaves the request's answer alone.
    let project = crate::store::ProjectRef::parse("42").unwrap();
    hub.db
        .decide_projects(
            "gl",
            &[project],
            crate::store::Decision::Reject,
            "u",
            now_secs(),
        )
        .unwrap();
    let again = submit(bound_body(2, 42, "acme/web", 600)).await;
    assert_eq!(again.status, 201, "{again:?}");
    assert_eq!(again.json::<JobView>().id, row_id(&resp));
    let resp = submit(bound_body(3, 42, "acme/web", 600)).await;
    assert_eq!(
        (resp.status, resp.code()),
        (403, ErrorCode::ProjectRejected)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

fn row_id(resp: &Resp) -> String {
    resp.json::<JobView>().id
}

fn hello_body(instance: &str) -> Value {
    json!({
        "instance": instance,
        "program": "vk-gitlab",
        "version": "0.91.1",
        "hostname": "ci-1",
        "runners": [{"name": "docker", "url": "https://gitlab.example.com", "pool": "ci"}],
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn client_instances_are_recorded_from_their_requests_and_hellos() {
    let dir = scratch("clients");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = plain_key(&hub);
    let watcher = api_key(
        &hub,
        "watcher",
        &[Scope::Capacity],
        now_secs(),
        Duration::from_secs(60),
    );
    let hello = |key: &str, instance: &str, body: Value| {
        let (key, instance) = (key.to_string(), instance.to_string());
        async move {
            api_as(
                addr,
                "POST",
                "/v1/clients",
                Some(&key),
                Some(&instance),
                Some(body),
            )
            .await
        }
    };

    // A hello from a key of either scope; none from a request without a key.
    assert_eq!(hello(&key, "s_1", hello_body("s_1")).await.status, 204);
    assert_eq!(hello(&watcher, "s_2", hello_body("s_2")).await.status, 204);
    let resp = api(addr, "POST", "/v1/clients", None, Some(hello_body("s_3"))).await;
    assert_eq!((resp.status, resp.code()), (401, ErrorCode::Unauthorized));

    // Malformed or oversized hellos.
    let resp = hello(&key, "s_1", hello_body("a/b")).await;
    assert_eq!((resp.status, resp.code()), (400, ErrorCode::Invalid));
    let mut body = hello_body("s_1");
    body["runners"] = json!(vec![body["runners"][0].clone(); 65]);
    assert_eq!(hello(&key, "s_1", body).await.status, 400);
    let mut body = hello_body("s_1");
    body["hostname"] = json!("x".repeat(70_000));
    let resp = hello(&key, "s_1", body).await;
    assert_eq!((resp.status, resp.code()), (413, ErrorCode::TooLarge));

    // The header names the instance a request comes from, one refused included: an API key
    // submits no GitLab job. Without it, or malformed, the request is recorded under its key
    // alone.
    let resp = api_as(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some("s_1"),
        Some(job_body(1, None, 300)),
    )
    .await;
    assert_eq!((resp.status, resp.code()), (403, ErrorCode::Forbidden));
    let ask = || Some(json!({"placement": placement()}));
    let resp = api_as(addr, "POST", "/v1/capacity", Some(&key), Some("a b"), ask()).await;
    assert_eq!(resp.status, 200);
    wait_until(|| hub.db.clients().unwrap().len() == 3).await;
    let mut rows: Vec<_> = hub.db.clients().unwrap().into_iter().map(|c| c.1).collect();
    rows.sort_by(|a, b| (&a.key_name, &a.instance).cmp(&(&b.key_name, &b.instance)));
    let names: Vec<(&str, &str)> = rows
        .iter()
        .map(|r| (r.key_name.as_str(), r.instance.as_str()))
        .collect();
    assert_eq!(
        names,
        [("gitlab", ""), ("gitlab", "s_1"), ("watcher", "s_2")]
    );
    assert_eq!(rows[1].hostname, "ci-1");
    assert_eq!(rows[1].runners[0].pool, "ci");
    assert_eq!(rows[0].hello_at, None);

    // The clients page's view: each key with its instances.
    let id = crate::store::token_key(&key);
    let views = crate::clients::views(&hub).unwrap();
    let shown: Vec<(&str, u64, Vec<&str>)> = views
        .iter()
        .map(|v| {
            let instances = v.instances.iter().map(|i| i.row.instance.as_str());
            (v.row.name.as_str(), v.jobs, instances.collect())
        })
        .collect();
    assert_eq!(shown.len(), 2);
    assert!(shown.contains(&("watcher", 0, vec!["s_2"])), "{shown:?}");
    let gitlab = views.iter().find(|v| v.id == id).unwrap();
    assert_eq!(gitlab.jobs, 0);
    assert_eq!(gitlab.instances.len(), 2);

    // A revoked key's requests are not recorded.
    assert!(
        hub.db
            .revoke_api_key("gitlab", "uid 0", now_secs())
            .unwrap()
    );
    let resp = hello(&key, "s_9", hello_body("s_9")).await;
    assert_eq!(resp.status, 401);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(hub.db.clients().unwrap().len(), 3);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_hello_is_recorded_under_the_instance_its_body_names() {
    let dir = scratch("hello-instance");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = plain_key(&hub);
    let hello = |header: Option<&'static str>, body: &str| {
        let (key, body) = (key.clone(), hello_body(body));
        async move { api_as(addr, "POST", "/v1/clients", Some(&key), header, Some(body)).await }
    };
    // The header names one instance, the body another.
    let resp = hello(Some("s_1"), "s_2").await;
    assert_eq!((resp.status, resp.code()), (400, ErrorCode::Invalid));
    // No header, or a malformed one: the body's instance alone, not the key's unknown one.
    assert_eq!(hello(None, "s_3").await.status, 204);
    assert_eq!(hello(Some("a b"), "s_4").await.status, 204);
    assert_eq!(hello(Some("s_5"), "s_5").await.status, 204);
    // `s_1` was heard from all the same.
    wait_until(|| hub.db.clients().unwrap().len() == 4).await;
    crate::clients::flush(&hub).await.unwrap();
    let names: Vec<String> = hub
        .db
        .clients()
        .unwrap()
        .into_iter()
        .map(|c| c.1.instance)
        .collect();
    assert_eq!(names, ["s_1", "s_3", "s_4", "s_5"]);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_hello_at_a_full_key_evicts_as_memory_does() {
    let dir = scratch("hello-evict");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = plain_key(&hub);
    let id = crate::store::token_key(&key);
    let now = now_secs();
    for i in 0..crate::store::MAX_INSTANCES_PER_KEY {
        hub.instances
            .note(&id, &format!("s_{i:02}"), now - 1000 + i as u64);
    }
    crate::clients::flush(&hub).await.unwrap();
    // `s_00` heard from since, in memory only: no longer the least recent.
    hub.instances.note(&id, "s_00", now - 10);
    let resp = api(
        addr,
        "POST",
        "/v1/clients",
        Some(&key),
        Some(hello_body("new")),
    )
    .await;
    assert_eq!(resp.status, 204, "{resp:?}");
    let names: Vec<String> = hub
        .db
        .clients()
        .unwrap()
        .into_iter()
        .map(|c| c.1.instance)
        .collect();
    assert_eq!(names.len(), crate::store::MAX_INSTANCES_PER_KEY);
    assert!(names.contains(&"s_00".into()) && names.contains(&"new".into()));
    assert!(!names.contains(&"s_01".into()));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_first_contact_at_a_full_key_evicts_as_memory_does() {
    let dir = scratch("contact-evict");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = plain_key(&hub);
    let id = crate::store::token_key(&key);
    let now = now_secs();
    // As after a restart: the database holds a full key, memory nothing of it.
    for i in 0..crate::store::MAX_INSTANCES_PER_KEY {
        hub.db
            .record_client(
                &id,
                "gitlab",
                &format!("s_{i:02}"),
                None,
                now - 1000 + i as u64,
                redb::Durability::Immediate,
            )
            .unwrap();
    }
    // `s_00` heard from since, its contact not yet written: no longer the least recent.
    hub.instances.note(&id, "s_00", now - 10);
    let ask = Some(json!({"placement": placement()}));
    let resp = api_as(addr, "POST", "/v1/capacity", Some(&key), Some("new"), ask).await;
    assert_eq!(resp.status, 200, "{resp:?}");
    let names = || -> Vec<String> {
        hub.db
            .clients()
            .unwrap()
            .into_iter()
            .map(|c| c.1.instance)
            .collect()
    };
    wait_until(|| names().contains(&"new".into())).await;
    let names = names();
    assert_eq!(names.len(), crate::store::MAX_INSTANCES_PER_KEY);
    assert!(names.contains(&"s_00".into()));
    assert!(!names.contains(&"s_01".into()));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn contacts_reach_the_database_through_the_flush() {
    let dir = scratch("clients-flush");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = plain_key(&hub);
    let id = crate::store::token_key(&key);
    let ask = || Some(json!({"placement": placement()}));
    let row = |instance: &str| {
        hub.db
            .clients()
            .unwrap()
            .into_iter()
            .map(|c| c.1)
            .find(|r| r.instance == instance)
    };
    let resp = api_as(addr, "POST", "/v1/capacity", Some(&key), Some("s_1"), ask()).await;
    assert_eq!(resp.status, 200, "{resp:?}");
    wait_until(|| row("s_1").is_some()).await;
    let first = row("s_1").unwrap().last_seen;
    while now_secs() <= first {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let resp = api_as(addr, "POST", "/v1/capacity", Some(&key), Some("s_1"), ask()).await;
    assert_eq!(resp.status, 200, "{resp:?}");
    // Held in memory until the flush.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(row("s_1").unwrap().last_seen, first);
    crate::clients::flush(&hub).await.unwrap();
    let flushed = row("s_1").unwrap();
    assert!(flushed.last_seen > first);
    assert_eq!(flushed.first_seen, first);

    // An instance whose first write failed: memory holds it, the database does not.
    let now = now_secs();
    assert!(hub.instances.note(&id, "s_2", now));
    assert!(row("s_2").is_none());
    crate::clients::flush(&hub).await.unwrap();
    assert_eq!(row("s_2").unwrap().last_seen, now);

    // One the database evicted while memory still holds it, heard from again.
    for i in 0..crate::store::MAX_INSTANCES_PER_KEY {
        let at = now + 10 + i as u64;
        hub.db
            .record_client(
                &id,
                "gitlab",
                &format!("x_{i:02}"),
                None,
                at,
                redb::Durability::Immediate,
            )
            .unwrap();
    }
    assert!(row("s_1").is_none() && row("s_2").is_none());
    assert!(!hub.instances.note(&id, "s_1", now + 1000));
    crate::clients::flush(&hub).await.unwrap();
    assert_eq!(row("s_1").unwrap().last_seen, now + 1000);
    assert!(row("x_00").is_none());
    assert_eq!(
        hub.db.clients().unwrap().len(),
        crate::store::MAX_INSTANCES_PER_KEY
    );
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
        Some(json!({"runner": "test", "placement": placement()})),
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
        Some(json!({"runner": "test", "placement": placement(), "after": first.revision, "wait_secs": 1})),
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
                Some(json!({"runner": "test", "placement": placement(), "after": first.revision, "wait_secs": 30})),
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
async fn simultaneous_reservations_account_for_an_offer_before_selecting_again() {
    let dir = scratch("simultaneous-reservations");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    relay_limits(&hub, &key, 64, 2);
    let mut node = ready_node(addr, &hub, envelope().mem_mib).await;
    let ask = |n, wait_secs| {
        let key = key.clone();
        tokio::spawn(async move {
            api(
                addr,
                "POST",
                "/v1/reservations",
                Some(&key),
                Some(relay_reservation_body(n, wait_secs)),
            )
            .await
        })
    };
    // Asked at once: whichever is offered the node's one envelope first, the other is not
    // offered it too. The one offered is accepted well within its wait, the other gives up.
    let (first, second) = (ask(1, 10), ask(2, 2));
    let HubJobMsg::Offer { reservation, .. } = node.job().await else {
        panic!("expected an offer");
    };
    node.quiet(Duration::from_millis(200)).await;
    node.send(NodeJobMsg::OfferReply {
        reservation,
        reply: OfferReply::Accepted { lease_secs: 90 },
    });
    let mut answers = [first.await.unwrap(), second.await.unwrap()];
    answers.sort_unstable_by_key(|a| a.status);
    assert_eq!(answers[0].status, 201, "{:?}", answers[0]);
    assert_eq!(
        (answers[1].status, answers[1].code()),
        (503, ErrorCode::NoCapacity),
        "{:?}",
        answers[1]
    );
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
                Some(relay_reservation_body(1, 5)),
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
    // A runner reserves before every poll, so a grant is not audited.
    let audit = hub.db.audits(None, 50).unwrap();
    assert!(
        audit.iter().all(|a| !a.event.contains(" reserved ")),
        "{audit:?}"
    );

    // The same request again is answered the same, with no second offer; with another body,
    // it conflicts.
    let resp = api(
        addr,
        "POST",
        "/v1/reservations",
        Some(&key),
        Some(relay_reservation_body(1, 5)),
    )
    .await;
    assert_eq!(
        (resp.status, resp.json::<ReservationGrant>()),
        (201, grant.clone())
    );
    let mut other = relay_reservation_body(1, 5);
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
    // Gone from memory before its audit is written.
    let expired = format!("reservation {reservation} on node {} expired", small.id);
    wait_until(|| {
        let audit = hub.db.audits(Some(&small.id), 20).unwrap();
        audit.iter().any(|r| r.event == expired)
    })
    .await;

    // Released: the node is told, and a release of one gone is 204 too.
    let grant = reserve_on(addr, &key, &mut big, 2, Some("test")).await;
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
                Some(relay_reservation_body(3, 1)),
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
    assert_eq!(
        resp.json::<vk_hub_proto::client::ClientError>()
            .retry_after_secs,
        Some(5)
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
        Some(relay_reservation_body(1, 1)),
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
    let grant = reserve_on(addr, &key, &mut node, 1, Some("test")).await;
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
    // Waiting for another job's image build is shown and counted as preparation.
    node.send(NodeJobMsg::Job {
        job: id.clone(),
        state: RunState::Running {
            stage: "prepare_executor".into(),
            activity: Some(vk_hub_proto::dispatch::Activity::Waiting {
                image: "docker/wab/Dockerfile#builder".into(),
                building: true,
                holder: Some("https://gitlab.example.com/g/p/-/jobs/1".into()),
            }),
            guest: None,
        },
    });
    view_until(addr, &key, &id, |v| {
        v.stage.as_deref() == Some("prepare_executor")
    })
    .await;
    eventually(|| {
        hub.db.job(&id).unwrap().is_some_and(|row| {
            crate::jobs::state_text(&row) == "waiting for build"
                && row.preparing()
                && row.ran_ms(now_secs()).is_none()
        })
    })
    .await;
    node.send(NodeJobMsg::Job {
        job: id.clone(),
        state: RunState::Running {
            stage: "step_script".into(),
            activity: None,
            guest: Some(vk_hub_proto::dispatch::GuestSize {
                cpus: 8,
                mem_mib: 16384,
            }),
        },
    });
    view_until(addr, &key, &id, |v| {
        v.stage.as_deref() == Some("step_script")
    })
    .await;
    eventually(|| {
        hub.db.job(&id).unwrap().is_some_and(|row| {
            row.guest
                == Some(vk_hub_proto::dispatch::GuestSize {
                    cpus: 8,
                    mem_mib: 16384,
                })
                && row.activity.is_none()
                && row.prepared_at.is_some()
                && !row.preparing()
                && crate::jobs::state_text(&row) == "running: step_script"
        })
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
        prepare_ms: None,
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
    // Its audit holds who submitted it; its record, where it ran and how it ended.
    let actor = actor_of(&key);
    assert_eq!(
        job_audit(&hub, &id),
        [format!(
            "{actor} submitted job {id}: GitLab job 2 of group/project (test)"
        )]
    );
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
    // Its branch made display-safe, and its pipeline.
    assert_eq!(
        (row.git_ref.as_deref(), row.pipeline),
        (Some("feature/menu"), Some(902))
    );
    assert_eq!(
        row.commit.as_deref(),
        Some("0123456789abcdef0123456789abcdef01234567")
    );
    assert!(row.started_at.is_some() && row.started_at <= row.finished_at);
    // Its run excludes preparation, which the node did not measure: the hub's stage times
    // give it in whole seconds, more than 0 when a second turned while it prepared.
    let now = crate::now_secs();
    let prepare = row.prepare_ms(now).unwrap();
    assert_eq!(prepare % 1000, 0);
    assert_eq!(row.ran_ms(now), Some(4200 - prepare));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Events a node reports with a job's result are kept, held to their bounds and made
/// displayable without losing the end of a long detail, found by the events filter, and shown
/// by `vk-hub jobs` and `vk-hub jobs show`.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_s_events_are_kept_bounded_found_and_shown() {
    let dir = scratch("job-events");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 8192).await;

    let stalled = running_job(addr, &key, &mut node, 1).await;
    let long_tail = format!(
        "{}: suspected lost interrupt, signalling again",
        "x".repeat(300)
    );
    let mut ended = result(None, 0);
    ended.events = (0..20)
        .map(|i| {
            let detail = if i == 0 {
                long_tail.clone()
            } else {
                format!("stall {i}\x1b[31m")
            };
            JobEvent::new(JobEventKind::VirtioFsStall, 2, &detail)
        })
        .collect();
    node.send(NodeJobMsg::Result {
        job: stalled.clone(),
        result: ended,
    });
    assert_eq!(
        node.job().await,
        HubJobMsg::Recorded {
            job: stalled.clone()
        }
    );
    let done = view_until(addr, &key, &stalled, |v| v.state == JobState::Finished).await;
    let events = done.result.unwrap().events;
    assert_eq!(events.len(), MAX_JOB_EVENTS);
    assert_eq!(
        events[0].detail, long_tail,
        "kept whole, past the usual 256 characters"
    );
    assert_eq!(
        events[1].detail, "stall 1[31m",
        "control characters dropped"
    );

    let quiet = running_job(addr, &key, &mut node, 2).await;
    node.send(NodeJobMsg::Result {
        job: quiet.clone(),
        result: result(None, 0),
    });
    assert_eq!(node.job().await, HubJobMsg::Recorded { job: quiet.clone() });
    view_until(addr, &key, &quiet, |v| v.state == JobState::Finished).await;

    let with_events = crate::store::JobFilter {
        events: true,
        ..Default::default()
    };
    let page = crate::jobs::history(&hub, &with_events, None, 10).unwrap();
    let found: Vec<&str> = page.rows.iter().map(|(_, id, _)| id.as_str()).collect();
    assert_eq!(found, [stalled.as_str()]);
    // `vk-hub jobs --events`.
    let listed = crate::admin::dispatch(
        br#"{"v":1,"call":{"op":"list-jobs","limit":10,"events":true}}"#,
        &hub,
        0,
    )
    .unwrap();
    let listed: Vec<(String, crate::store::JobRow)> = serde_json::from_value(listed).unwrap();
    let found: Vec<&str> = listed.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(found, [stalled.as_str()]);

    let rows = crate::jobs::listing(&hub, 10).unwrap();
    let listed = crate::render_jobs(&rows, crate::now_secs());
    assert!(
        listed.lines().next().unwrap().contains("EVENTS"),
        "{listed}"
    );
    let row = |id: &str| {
        listed
            .lines()
            .find(|l| l.starts_with(id))
            .unwrap()
            .to_string()
    };
    assert!(row(&stalled).contains("virtio-fs stall ×2"), "{listed}");
    assert!(!row(&quiet).contains("virtio-fs"), "{listed}");

    let (detail, _) = crate::jobs::detail(&hub, &stalled).unwrap().unwrap();
    let shown = crate::render_job(&stalled, &detail, None, crate::now_secs());
    assert!(
        shown.contains(&format!(
            "event        virtio-fs stall (2 times): {long_tail}\n"
        )),
        "{shown}"
    );
}

/// The egress report a node sends with a job's result is held to its bounds again before it is
/// kept: past the bound, denials are counted rather than listed, and a destination that is not
/// a name is kept as text.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_s_egress_report_is_kept_bounded() {
    use vk_hub_proto::egress::{
        EgressCoverage, EgressDestination, EgressEntry, EgressLayer, EgressOutcome, EgressPhase,
        EgressPhaseReport, EgressProtocol, EgressReport, EgressSource, MAX_EGRESS_DENIALS,
    };
    let dir = scratch("job-egress");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 8192).await;

    let id = running_job(addr, &key, &mut node, 1).await;
    let denial = |name: String| EgressEntry {
        outcome: EgressOutcome::Blocked,
        protocol: EgressProtocol::Dns,
        destination: EgressDestination::Domain { name },
        phase: EgressPhase::Run,
        source: EgressSource::Job,
        layer: Some(EgressLayer::NodeCap),
        count: 1,
        first_seen_ms: 1_000,
        last_seen_ms: 1_000,
        stage: None,
        rule: None,
    };
    let mut ended = result(None, 0);
    ended.egress = Some(EgressReport {
        revision: 1,
        entries: std::iter::once("evil\x1b[2J.example".to_string())
            .chain((1..MAX_EGRESS_DENIALS + 10).map(|i| format!("d{i}.example")))
            .map(denial)
            .collect(),
        phases: vec![EgressPhaseReport {
            phase: EgressPhase::Run,
            coverage: EgressCoverage::Complete,
            omitted: Default::default(),
            sent_bytes: Some(1),
            received_bytes: Some(2),
            caps: None,
        }],
        ..EgressReport::default()
    });
    node.send(NodeJobMsg::Result {
        job: id.clone(),
        result: ended,
    });
    assert_eq!(node.job().await, HubJobMsg::Recorded { job: id.clone() });
    view_until(addr, &key, &id, |v| v.state == JobState::Finished).await;
    let row = hub.db.job(&id).unwrap().unwrap();
    let report = row.result.unwrap().egress.unwrap();
    assert_eq!(report.entries.len(), MAX_EGRESS_DENIALS);
    assert!(
        matches!(&report.entries[0].destination, EgressDestination::Malformed { text }
            if !text.contains('\x1b')),
        "{:?}",
        report.entries[0]
    );
    let run = &report.phases[0];
    assert_eq!(
        (run.coverage, run.omitted.blocked),
        (EgressCoverage::Partial, 10)
    );
    // `vk-hub jobs show` sums it up, lists the first denials and says what it left out.
    let (detail, _) = crate::jobs::detail(&hub, &id).unwrap().unwrap();
    let shown = crate::render_job(&id, &detail, None, crate::now_secs());
    for want in [
        "network      Blocked: 512+ destinations (522 attempts) · incomplete record\n",
        "blocked      DNS evil\u{fffd}[2J.example (run, job, 1 attempt): the node's cap; nothing to \
         allow: not a name or an address\n",
        "blocked      DNS d1.example (run, job, 1 attempt): the node's cap; check [egress] \
         allow_name on its node\n",
        "             … 502 more on the job's page\n",
        "coverage     run: Partial: recording incomplete, 10 blocked attempts not listed; 1 bytes \
         sent, 2 bytes received\n",
    ] {
        assert!(shown.contains(want), "{want}\n{shown}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A running job's egress report from a version-6 node is kept on its record and in the Egress
/// page's rows, never replaced by an older revision; its result's replaces it. A job its hub
/// ends keeps the last, as far as it went. A version-3 node sending one ends its session.
/// (Written as it comes: [`Hub::writing_egress_every`] is zero.)
#[tokio::test(flavor = "multi_thread")]
async fn a_running_job_s_egress_report_is_kept_until_it_ends() {
    use vk_hub_proto::egress::{
        EgressCoverage, EgressDestination, EgressEntry, EgressLayer, EgressOutcome, EgressPhase,
        EgressPhaseReport, EgressProtocol, EgressReport, EgressSource,
    };
    let dir = scratch("live-egress");
    let db = Arc::new(Db::open_memory().unwrap());
    let (addr, hub) = serve_hub_with(db, &dir, Duration::from_secs(1), |hub| {
        hub.writing_egress_every(Duration::ZERO)
    })
    .await;
    let key = jobs_key(&hub);
    let node_key = keypair();
    let id = new_node(addr, &hub, &node_key).await;
    let v6 = VersionRange {
        min: 1,
        max: vk_hub_proto::LIVE_EGRESS,
    };
    let mut node = connect(addr, &id, &node_key, v6, 16384, Some(Held::default())).await;
    wait_until(|| crate::jobs::testing::linked(&hub, &id) && heard(&hub, &id)).await;
    let report = |revision, count| EgressReport {
        revision,
        entries: vec![EgressEntry {
            outcome: EgressOutcome::Blocked,
            protocol: EgressProtocol::Dns,
            destination: EgressDestination::domain("a.example"),
            phase: EgressPhase::Run,
            source: EgressSource::Job,
            layer: Some(EgressLayer::NodeCap),
            count,
            first_seen_ms: 1_000,
            last_seen_ms: 1_000,
            stage: None,
            rule: None,
        }],
        phases: vec![EgressPhaseReport {
            phase: EgressPhase::Run,
            coverage: EgressCoverage::Complete,
            omitted: Default::default(),
            sent_bytes: None,
            received_bytes: None,
            caps: None,
        }],
        ..EgressReport::default()
    };
    let live = |job: &str| hub.db.job(job).unwrap().unwrap().egress;
    let attempts = || {
        hub.db
            .egress_rows()
            .unwrap()
            .iter()
            .map(|(_, r)| r.attempts)
            .sum::<u64>()
    };

    let job = running_job(addr, &key, &mut node, 1).await;
    node.send(NodeJobMsg::Egress {
        job: job.clone(),
        report: report(2, 3),
    });
    wait_until(|| live(&job).is_some_and(|r| r.revision == 2)).await;
    assert_eq!(attempts(), 3, "the Blocked rows follow it");
    // An older revision, replayed, changes nothing; a newer one replaces the counts.
    node.send(NodeJobMsg::Egress {
        job: job.clone(),
        report: report(1, 9),
    });
    node.send(NodeJobMsg::Egress {
        job: job.clone(),
        report: report(3, 5),
    });
    wait_until(|| live(&job).is_some_and(|r| r.revision == 3)).await;
    assert_eq!(attempts(), 5);
    let mut ended = result(None, 0);
    ended.egress = Some(report(4, 6));
    node.send(NodeJobMsg::Result {
        job: job.clone(),
        result: ended,
    });
    assert_eq!(node.job().await, HubJobMsg::Recorded { job: job.clone() });
    view_until(addr, &key, &job, |v| v.state == JobState::Finished).await;
    let row = hub.db.job(&job).unwrap().unwrap();
    assert_eq!(row.egress, None);
    assert_eq!(row.result.unwrap().egress, Some(report(4, 6)));
    assert_eq!(attempts(), 6);

    // Lost with its node: what it reported, as far as it went.
    let lost = running_job(addr, &key, &mut node, 2).await;
    node.send(NodeJobMsg::Egress {
        job: lost.clone(),
        report: report(1, 2),
    });
    wait_until(|| live(&lost).is_some()).await;
    drop(node);
    view_until(addr, &key, &lost, |v| v.state == JobState::Finished).await;
    // Shown ended from memory before its record is written: the sweep persists it after.
    let stored = || hub.db.job(&lost).unwrap().unwrap();
    wait_until(|| stored().state == JobState::Finished).await;
    let kept = stored().result.unwrap().egress;
    assert_eq!(kept, Some(report(1, 2).interrupted()));

    // Not in a session below version 6.
    let mut old = ready_node(addr, &hub, 16384).await;
    old.send(NodeJobMsg::Egress {
        job: job.clone(),
        report: report(9, 1),
    });
    let Some(HubMsg::Refused { code, .. }) = old.ended().await else {
        panic!("expected a refusal");
    };
    assert_eq!(code, RefusalCode::Protocol);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A running job's egress report shows at once, and its record is written with it at once the
/// first time, then at most every [`Hub::writing_egress_every`] — or with any other change to the
/// record, such as a new stage. A hub restarted past what it wrote gets the latest again from
/// the node, which sends it after a reconnect.
#[tokio::test(flavor = "multi_thread")]
async fn a_running_job_s_egress_report_is_written_at_most_every_so_often() {
    use vk_hub_proto::egress::EgressReport;
    let dir = scratch("live-egress-writes");
    let db = Arc::new(Db::open_memory().unwrap());
    let hourly = |hub: Hub| hub.writing_egress_every(Duration::from_secs(3600));
    let (addr, hub) = serve_hub_with(db.clone(), &dir, Duration::from_secs(60), hourly).await;
    let key = jobs_key(&hub);
    let node_key = keypair();
    let id = new_node(addr, &hub, &node_key).await;
    let v6 = VersionRange {
        min: 1,
        max: vk_hub_proto::LIVE_EGRESS,
    };
    let mut node = connect(addr, &id, &node_key, v6, 16384, Some(Held::default())).await;
    wait_until(|| crate::jobs::testing::linked(&hub, &id) && heard(&hub, &id)).await;
    let job = running_job(addr, &key, &mut node, 1).await;
    let report = |revision| EgressReport {
        revision,
        ..EgressReport::default()
    };
    let written = || db.job(&job).unwrap().unwrap().egress.map(|r| r.revision);
    let shown = |hub: &Hub| {
        crate::jobs::detail(hub, &job)
            .unwrap()
            .unwrap()
            .0
            .egress
            .map(|r| r.revision)
    };

    node.send(NodeJobMsg::Egress {
        job: job.clone(),
        report: report(1),
    });
    wait_until(|| written() == Some(1)).await;
    for revision in 2..=20 {
        node.send(NodeJobMsg::Egress {
            job: job.clone(),
            report: report(revision),
        });
    }
    wait_until(|| shown(&hub) == Some(20)).await;
    // Past two of the writer's passes, the record still holds the first.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(written(), Some(1));
    // A new stage writes the record, with the latest report.
    node.send(NodeJobMsg::Job {
        job: job.clone(),
        state: RunState::Running {
            stage: "step_script".into(),
            activity: None,
            guest: None,
        },
    });
    wait_until(|| written() == Some(20)).await;
    node.send(NodeJobMsg::Egress {
        job: job.clone(),
        report: report(21),
    });
    wait_until(|| shown(&hub) == Some(21)).await;
    drop(node);

    // Restarted over the same database: the 21st was never written, and comes again.
    let (addr, hub) = serve_hub_with(db.clone(), &dir, Duration::from_secs(60), hourly).await;
    assert_eq!(shown(&hub), Some(20));
    let held = Held {
        reservations: Vec::new(),
        jobs: vec![HeldJob {
            job: job.clone(),
            state: RunState::Running {
                stage: "step_script".into(),
                activity: None,
                guest: None,
            },
            output_len: 0,
            finished: false,
        }],
    };
    let mut node = connect(addr, &id, &node_key, v6, 16384, Some(held)).await;
    assert_eq!(
        node.job().await,
        HubJobMsg::OutputAck {
            job: job.clone(),
            offset: 0
        }
    );
    node.send(NodeJobMsg::Egress {
        job: job.clone(),
        report: report(21),
    });
    // The first report since the restart is written at once.
    wait_until(|| written() == Some(21)).await;
    drop(hub);
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

/// A job settled before the hub has written how it ended keeps that ending's audit line.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_settled_before_its_end_is_written_keeps_its_audit() {
    let dir = scratch("settle-race");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 16384).await;
    let id = running_job(addr, &key, &mut node, 1).await;
    let (row, events) =
        crate::jobs::testing::fail_unwritten(&hub, &id, FailureClass::System, "disk gone");
    let settle = format!("/v1/jobs/{id}/settle");
    assert_eq!(
        api(addr, "POST", &settle, Some(&key), None).await.status,
        204
    );
    crate::jobs::testing::persist(&hub, &id, row, events).await;
    let stored = hub.db.job(&id).unwrap().unwrap();
    assert!(stored.settled_at.is_some());
    assert!(
        job_audit(&hub, &id).contains(&format!("job {id} ended: system failure: disk gone")),
        "{:?}",
        job_audit(&hub, &id)
    );
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
    node.send(NodeJobMsg::Job {
        job: job.clone(),
        state: RunState::Running {
            stage: "prepare_executor".into(),
            activity: Some(vk_hub_proto::dispatch::Activity::Building {
                image: "img".into(),
            }),
            guest: None,
        },
    });
    eventually(|| {
        hub.db.job(&job).unwrap().is_some_and(|row| {
            row.activity
                == Some(vk_hub_proto::dispatch::Activity::Building {
                    image: "img".into(),
                })
        })
    })
    .await;
    node.send(output(&job, 0, b"before restart\n"));
    assert_eq!(
        node.job().await,
        HubJobMsg::OutputAck {
            job: job.clone(),
            offset: 15
        }
    );
    assert!(hub.db.job(&job).unwrap().unwrap().preparing());
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
                    activity: None,
                    guest: Some(vk_hub_proto::dispatch::GuestSize {
                        cpus: 2,
                        mem_mib: 4096,
                    }),
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
    // Preparation finished while the hub was away: `held` reports the stage and VM size
    // without another stage update.
    let row = hub.db.job(&job).unwrap().unwrap();
    assert_eq!(
        (row.stage.as_deref(), &row.activity, row.preparing()),
        (Some("step_script"), &None, false)
    );
    assert_eq!(row.vm_size(), Some((2, 4096)));
    assert!(row.prepared_at.is_some());
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
    // Its canceler's line stands for its ending.
    let id = &queued.id;
    let actor = actor_of(&key);
    assert_eq!(
        job_audit(&hub, id),
        [
            format!("{actor} submitted job {id}: GitLab job 1 of group/project (test)"),
            format!("{actor} canceled job {id} before it was placed"),
        ]
    );

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
    // The hub ended it: audited.
    wait_until(|| job_audit(&hub, &job).len() == 2).await;
    let actor = actor_of(&key);
    assert_eq!(
        job_audit(&hub, &job),
        [
            format!("{actor} submitted job {job}: GitLab job 1 of group/project (test)"),
            format!("job {job} ended: lost: node {id} was unreachable for 1s"),
        ]
    );
    // Back, still running it: canceled, its result recorded and ignored.
    let held = Held {
        reservations: vec![],
        jobs: vec![HeldJob {
            job: job.clone(),
            state: RunState::Running {
                stage: "step_script".into(),
                activity: None,
                guest: None,
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
            events: Vec::new(),
            egress: None,
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
    let id = &job.id;
    wait_until(|| job_audit(&hub, id).len() == 2).await;
    let actor = actor_of(&key);
    assert_eq!(
        job_audit(&hub, id),
        [
            format!("{actor} submitted job {id}: GitLab job 1 of group/project (test)"),
            format!("job {id} ended: no capacity: no node took it within its placement window"),
        ]
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
        hub.db.prune_jobs(later, 100).unwrap().outputs,
        std::slice::from_ref(&job.id)
    );
    let resp = api(addr, "GET", &output, Some(&key), None).await;
    assert_eq!((resp.status, resp.code()), (404, ErrorCode::NotFound));

    // Dropped from the history.
    assert!(hub.db.prune_jobs(later, 0).unwrap().outputs.is_empty());
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

/// A count set lower than the history, as the Jobs page sets it, trims the history in the
/// background, past what one write drops, to the newest jobs; cleared, `job_history` applies
/// again and the audit says so.
#[tokio::test(flavor = "multi_thread")]
async fn a_lower_history_count_trims_the_history_write_after_write() {
    use crate::jobs::HistorySource;
    use crate::store::JobFilter;
    let dir = scratch("trim");
    let db = Arc::new(Db::open_memory().unwrap());
    let settled = |n: u64| crate::store::JobRow {
        key: "k".into(),
        key_name: "gitlab".into(),
        instance: None,
        request_id: format!("{n:032x}"),
        scheduling: None,
        admission: None,
        placement: placement(),
        title: format!("GitLab job {n}"),
        job_url: None,
        project: None,
        name: None,
        created_at: 1000 + n,
        state: JobState::Finished,
        revision: 2,
        node: Some("ab".repeat(16)),
        stage: None,
        cancel: None,
        result: None,
        output_len: 0,
        started_at: Some(1000 + n),
        finished_at: Some(1010 + n),
        settled_at: Some(1010 + n),
        git_ref: None,
        pipeline: None,
        expired_at: None,
        commit: None,
        activity: None,
        prepared_at: None,
        guest: None,
        registry_access: None,
        gitlab: None,
        project_id: None,
        protected: None,
        egress_rules: None,
        egress_caps: None,
        egress: None,
    };
    // Well past the 1,000 jobs one trim drops at most.
    let jobs = 2_500u64;
    db.fill_history((1..=jobs).map(|n| (format!("{n:032x}"), settled(n))))
        .unwrap();
    let (_, hub) = serve_hub_with(db, &dir, Duration::from_secs(60), |hub| {
        hub.with_jobs(dir.join("jobs"), Duration::from_secs(60), Some(5_000))
            .unwrap()
    })
    .await;
    assert_eq!(
        crate::jobs::history_unset(&hub),
        (5_000, HistorySource::Config)
    );
    let all = JobFilter::default();
    let held = || {
        let page = hub.db.job_page(&all, None, 1).unwrap();
        (!page.reading).then_some(page.summary.matched)
    };
    // Counting and trimming 2,500 rows is slow on a loaded machine.
    let within = Duration::from_secs(60);
    eventually_within(within, || held() == Some(2_500)).await;

    crate::jobs::set_history(&hub, "uid 0", Some(100)).unwrap();
    eventually_within(within, || held() == Some(100)).await;
    let page = hub.db.job_page(&all, None, 1).unwrap();
    assert_eq!(page.rows[0].1, format!("{jobs:032x}"));
    let oldest = hub.db.job_page(&all, Some(page.rows[0].0 - 98), 1).unwrap();
    assert_eq!(oldest.rows[0].1, format!("{:032x}", jobs - 99));
    assert_eq!(oldest.older, None);

    crate::jobs::set_history(&hub, "uid 0", None).unwrap();
    assert_eq!(
        crate::jobs::history_count(&hub).unwrap(),
        (5_000, HistorySource::Config)
    );
    let audit = hub.db.audits(None, 10).unwrap();
    assert!(
        (audit.iter()).any(|r| r
            .event
            .ends_with("cleared: job_history in hub.toml applies, 5000 jobs")),
        "{audit:?}"
    );
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
    let grant = reserve_on(addr, &key, &mut node, 1, Some("test")).await;
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
    let grant = reserve_on(addr, &key, &mut first, 1, Some("test")).await;
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
    let grant = reserve_on(addr, &key, &mut second, 2, Some("test")).await;
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
    let key = plain_key(&hub);
    let ask = || Some(json!({"placement": placement()}));
    let all = u32::try_from(server::MAX_CLIENT_CONNS).unwrap();
    let held = hub
        .client_conns
        .clone()
        .try_acquire_many_owned(all)
        .unwrap();
    let resp = api_as(addr, "POST", "/v1/capacity", Some(&key), Some("s_1"), ask()).await;
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
    // The request turned away is no contact.
    crate::clients::flush(&hub).await.unwrap();
    let rows = hub.db.clients().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1.instance, "");
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
            Some(relay_reservation_body(1, 1)),
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
    // The placement loop offers the reservation; stopped once it is granted, the job
    // submitted on the grant stays queued.
    let driver = tokio::spawn(crate::jobs::drive(hub.clone()));
    let grant = reserve_on(addr, &key, &mut node, 1, Some("test")).await;
    driver.abort();
    assert!(driver.await.unwrap_err().is_cancelled());
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
        heartbeat(8192, None),
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
    let grant = reserve_on(addr, &key, &mut node, 1, Some("test")).await;
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

/// The next start the hub sends `node`, past the other job messages.
async fn next_start(node: &mut FakeNode) -> Box<vk_hub_proto::dispatch::JobStart> {
    loop {
        if let HubJobMsg::Start(start) = node.job().await {
            return start;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_at_its_ceiling_is_placed_nothing_until_a_job_ends() {
    let dir = scratch("ceiling");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    // Memory for four envelopes, a ceiling of two.
    let mut node = ready_node(addr, &hub, 16384).await;
    crate::ops::set_ceiling(&hub, "uid 0", &node.id, Some(2)).unwrap();
    let fits = || async {
        crate::jobs::capacity(&hub, &placement())
            .await
            .unwrap()
            .fits
    };
    assert_eq!(fits().await, 2);
    // A reservation and a job fill it.
    reserve_on(addr, &key, &mut node, 1, Some("test")).await;
    assert_eq!(fits().await, 1);
    let first = running_job(addr, &key, &mut node, 2).await;
    assert_eq!(fits().await, 0);
    assert_eq!(crate::jobs::placed_on(&hub, &node.id), 2);
    // Asked with an API key, whose requests the relay's own limits do not hold back.
    let resp = api(
        addr,
        "POST",
        "/v1/reservations",
        Some(&plain_key(&hub)),
        Some(reservation_body(3, 1)),
    )
    .await;
    assert_eq!(resp.code(), ErrorCode::NoCapacity, "{resp:?}");
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(4, None, 30)),
    )
    .await;
    let waiting: JobView = resp.json();
    node.quiet(Duration::from_secs(1)).await;
    // Lowered under what it holds, nothing it runs is canceled.
    crate::ops::set_ceiling(&hub, "uid 0", &node.id, Some(1)).unwrap();
    node.quiet(Duration::from_millis(500)).await;
    crate::ops::set_ceiling(&hub, "uid 0", &node.id, Some(2)).unwrap();
    // The job ends: the waiting one goes to the node.
    node.send(NodeJobMsg::Result {
        job: first,
        result: result(None, 0),
    });
    assert_eq!(next_start(&mut node).await.job, waiting.id);
    assert_eq!(fits().await, 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Report `node`'s placed-job intake and wait for the hub to store it.
async fn report_placed(hub: &Hub, node: &FakeNode, placed: vk_hub_proto::PlacedIntake) {
    node.outbox
        .send(NodeMsg::Report(Report {
            state: Some(NodeState::Ready),
            placed: Some(placed.clone()),
            ..Report::default()
        }))
        .unwrap();
    wait_until(|| {
        hub.db
            .node(&node.id)
            .unwrap()
            .and_then(|r| r.report)
            .is_some_and(|r| r.placed.as_ref() == Some(&placed))
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_running_its_own_runner_is_offered_nothing() {
    let dir = scratch("own-runner");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 16384).await;
    let fits = || async {
        crate::jobs::capacity(&hub, &placement())
            .await
            .unwrap()
            .fits
    };
    // Saying it runs none changes nothing.
    report_placed(&hub, &node, vk_hub_proto::PlacedIntake::default()).await;
    assert_eq!(fits().await, 4);
    let runner = vk_hub_proto::PlacedIntake {
        runner: Some("gitlab-runner.service runs the vk custom executor".into()),
        ..vk_hub_proto::PlacedIntake::default()
    };
    report_placed(&hub, &node, runner).await;
    assert_eq!(fits().await, 0);
    let resp = api(
        addr,
        "POST",
        "/v1/reservations",
        Some(&key),
        Some(relay_reservation_body(1, 1)),
    )
    .await;
    assert_eq!(resp.code(), ErrorCode::NoCapacity, "{resp:?}");
    node.quiet(Duration::from_millis(300)).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A node's own limit caps what the hub places on it with the operator's ceiling, the smaller
/// binding; a node older than reporting it has it read from its runner's concurrency.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_s_own_limit_caps_what_it_is_placed_with_the_ceiling() {
    let dir = scratch("own-limit");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    // Memory for four envelopes.
    let mut node = ready_node(addr, &hub, 16384).await;
    let fits = || async {
        crate::jobs::capacity(&hub, &placement())
            .await
            .unwrap()
            .fits
    };
    let limit = |n| vk_hub_proto::PlacedIntake {
        limit: Some(n),
        ..vk_hub_proto::PlacedIntake::default()
    };
    report_placed(&hub, &node, limit(2)).await;
    assert_eq!(fits().await, 2);
    crate::ops::set_ceiling(&hub, "uid 0", &node.id, Some(3)).unwrap();
    assert_eq!(fits().await, 2);
    crate::ops::set_ceiling(&hub, "uid 0", &node.id, Some(1)).unwrap();
    assert_eq!(fits().await, 1);
    crate::ops::set_ceiling(&hub, "uid 0", &node.id, None).unwrap();
    report_placed(&hub, &node, limit(1)).await;
    // Full at one: nothing more is offered, to the relay or to an API key.
    reserve_on(addr, &key, &mut node, 1, Some("test")).await;
    assert_eq!(fits().await, 0);
    let resp = api(
        addr,
        "POST",
        "/v1/reservations",
        Some(&plain_key(&hub)),
        Some(reservation_body(2, 1)),
    )
    .await;
    assert_eq!(resp.code(), ErrorCode::NoCapacity, "{resp:?}");
    node.quiet(Duration::from_millis(300)).await;
    // An older node's report has no such field: its runner's local ceiling stands in.
    node.outbox
        .send(NodeMsg::Report(Report {
            state: Some(NodeState::Ready),
            concurrency: Some(vk_hub_proto::Concurrency {
                local_ceiling: Some(3),
                ..vk_hub_proto::Concurrency::default()
            }),
            ..Report::default()
        }))
        .unwrap();
    wait_until(|| {
        hub.db
            .node(&node.id)
            .unwrap()
            .and_then(|r| r.report)
            .is_some_and(|r| r.placed.is_none() && r.concurrency.is_some())
    })
    .await;
    assert_eq!(fits().await, 2);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn placed_work_goes_to_the_least_loaded_node() {
    let dir = scratch("spread");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    // Four grants held at once: an API key's, as a relay runner probes for one at a time
    // (the queued spread is [`capacity::queued_grants_go_to_the_least_loaded_node`]).
    let reservation_key = plain_key(&hub);
    // Memory for eight envelopes, for four, and for none.
    let mut big = ready_node(addr, &hub, 32768).await;
    let mut small = ready_node(addr, &hub, 16384).await;
    let mut full = ready_node(addr, &hub, 2048).await;
    // Both empty: the roomier first. Then each goes to the one with the smaller share of
    // placed work and of its CPUs, on a tie the roomier.
    reserve_on(addr, &reservation_key, &mut big, 1, None).await;
    reserve_on(addr, &reservation_key, &mut small, 2, None).await;
    reserve_on(addr, &reservation_key, &mut big, 3, None).await;
    reserve_on(addr, &reservation_key, &mut small, 4, None).await;
    // Starts are ordered the same.
    running_job(addr, &key, &mut big, 5).await;
    for node in [&mut big, &mut small, &mut full] {
        node.quiet(Duration::from_millis(200)).await;
    }
    assert_eq!(
        (
            crate::jobs::placed_on(&hub, &big.id),
            crate::jobs::placed_on(&hub, &small.id),
            crate::jobs::placed_on(&hub, &full.id),
        ),
        (3, 2, 0)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Job `n`'s body, its image `image`.
fn job_body_with_image(n: u8, reservation: Option<&str>, image: &str) -> Value {
    let mut body = job_body(n, reservation, 30);
    let JobSpec::GitlabCi(mut ci) = spec(u64::from(n));
    ci.image.name = image.into();
    body["spec"] = json!(JobSpec::GitlabCi(ci));
    body
}

/// A Dockerfile job prefers a lightly loaded node that ran the same project's Dockerfile,
/// releasing its reservation on a cold node. A job with a pulled image uses its reservation.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_goes_to_a_lightly_loaded_node_holding_its_image() {
    let dir = scratch("affinity");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    // A load of 1 on 8 CPUs, and none.
    let mut warm = loaded_node(addr, &hub, 16384, Some(100)).await;
    let image = "dockerfile:ci/Dockerfile";
    // The first runs on `warm`, alone in the pool.
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body_with_image(1, None, image)),
    )
    .await;
    let first: JobView = resp.json();
    assert_eq!(next_start(&mut warm).await.job, first.id);
    warm.send(NodeJobMsg::Job {
        job: first.id.clone(),
        state: RunState::Accepted,
    });
    view_until(addr, &key, &first.id, |v| v.state == JobState::Running).await;
    warm.send(NodeJobMsg::Result {
        job: first.id.clone(),
        result: result(None, 0),
    });
    view_until(addr, &key, &first.id, |v| v.state == JobState::Finished).await;
    let mut cold = loaded_node(addr, &hub, 16384, Some(0)).await;
    // A reservation goes to the less loaded `cold`; the job submitted on it, to `warm`.
    let grant = reserve_on(addr, &key, &mut cold, 2, Some("test")).await;
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body_with_image(3, Some(&grant.reservation), image)),
    )
    .await;
    let second: JobView = resp.json();
    let start = next_start(&mut warm).await;
    assert_eq!(
        (start.job.as_str(), start.reservation),
        (second.id.as_str(), None)
    );
    assert_eq!(
        cold.job().await,
        HubJobMsg::Release {
            reservation: grant.reservation.clone()
        }
    );
    assert_eq!(crate::jobs::testing::reservations(&hub), 0);
    // Refused there, it starts on `cold` all the same, without the reservation it gave back.
    warm.send(NodeJobMsg::Job {
        job: second.id.clone(),
        state: RunState::Refused {
            reason: Refusal::Memory,
            message: None,
        },
    });
    let start = next_start(&mut cold).await;
    assert_eq!(
        (start.job.as_str(), start.reservation),
        (second.id.as_str(), None)
    );
    assert_eq!(crate::jobs::testing::reservations(&hub), 0);
    cold.send(NodeJobMsg::Job {
        job: second.id.clone(),
        state: RunState::Accepted,
    });
    view_until(addr, &key, &second.id, |v| v.state == JobState::Running).await;
    cold.send(NodeJobMsg::Result {
        job: second.id.clone(),
        result: result(None, 0),
    });
    view_until(addr, &key, &second.id, |v| v.state == JobState::Finished).await;
    assert_eq!(
        cold.job().await,
        HubJobMsg::Recorded {
            job: second.id.clone()
        }
    );
    // Its image pulled: it starts on its reservation.
    let grant = reserve_on(addr, &key, &mut cold, 4, Some("test")).await;
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body_with_image(5, Some(&grant.reservation), "alpine:3")),
    )
    .await;
    let third: JobView = resp.json();
    let start = next_start(&mut cold).await;
    assert_eq!(
        (start.job.as_str(), start.reservation.as_deref()),
        (third.id.as_str(), Some(grant.reservation.as_str()))
    );
    warm.quiet(Duration::from_millis(300)).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Which node holds which image survives a restart: read back from the job history.
#[tokio::test(flavor = "multi_thread")]
async fn a_restarted_hub_still_knows_which_node_holds_a_job_s_image() {
    let dir = scratch("affinity-restart");
    let db = Arc::new(Db::open_memory().unwrap());
    let (addr, hub) = serve_hub(db.clone(), &dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let warm_key = keypair();
    let warm_id = new_node(addr, &hub, &warm_key).await;
    let connect_warm = |addr| {
        connect_beating(
            addr,
            &warm_id,
            &warm_key,
            V3,
            heartbeat(16384, Some(100)),
            Some(Held::default()),
            Duration::from_millis(300),
        )
    };
    let mut warm = connect_warm(addr).await;
    wait_until(|| crate::jobs::testing::linked(&hub, &warm_id) && heard(&hub, &warm_id)).await;
    let image = "dockerfile:ci/Dockerfile";
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body_with_image(1, None, image)),
    )
    .await;
    let first: JobView = resp.json();
    assert_eq!(next_start(&mut warm).await.job, first.id);
    warm.send(NodeJobMsg::Job {
        job: first.id.clone(),
        state: RunState::Accepted,
    });
    view_until(addr, &key, &first.id, |v| v.state == JobState::Running).await;
    warm.send(NodeJobMsg::Result {
        job: first.id.clone(),
        result: result(None, 0),
    });
    wait_until(|| {
        db.job(&first.id)
            .unwrap()
            .is_some_and(|r| r.finished_at.is_some())
    })
    .await;
    drop(warm);
    // Restarted over the same database: `warm` comes back, `cold` is new and less loaded.
    let (addr, hub) = serve_hub(db.clone(), &dir, Duration::from_secs(60)).await;
    connect_relay(&hub, relay_id(&key));
    let mut warm = connect_warm(addr).await;
    wait_until(|| crate::jobs::testing::linked(&hub, &warm_id) && heard(&hub, &warm_id)).await;
    let mut cold = loaded_node(addr, &hub, 16384, Some(0)).await;
    let grant = reserve_on(addr, &key, &mut cold, 2, Some("test")).await;
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body_with_image(3, Some(&grant.reservation), image)),
    )
    .await;
    let second: JobView = resp.json();
    let start = next_start(&mut warm).await;
    assert_eq!(
        (start.job.as_str(), start.reservation),
        (second.id.as_str(), None)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A job still running when the hub restarts gets its image key back from its spec, and its
/// end, after the restart, counts as its node's latest use of the image.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_running_across_a_restart_keeps_its_image() {
    let dir = scratch("affinity-running");
    let db = Arc::new(Db::open_memory().unwrap());
    let (addr, hub) = serve_hub(db.clone(), &dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let node_key = keypair();
    let node_id = new_node(addr, &hub, &node_key).await;
    let connect_node = |addr, held| {
        connect_beating(
            addr,
            &node_id,
            &node_key,
            V3,
            heartbeat(16384, Some(100)),
            Some(held),
            Duration::from_millis(300),
        )
    };
    let mut node = connect_node(addr, Held::default()).await;
    wait_until(|| crate::jobs::testing::linked(&hub, &node_id) && heard(&hub, &node_id)).await;
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body_with_image(1, None, "dockerfile:ci/Dockerfile")),
    )
    .await;
    let job: JobView = resp.json();
    assert_eq!(next_start(&mut node).await.job, job.id);
    node.send(NodeJobMsg::Job {
        job: job.id.clone(),
        state: RunState::Accepted,
    });
    view_until(addr, &key, &job.id, |v| v.state == JobState::Running).await;
    let image = crate::jobs::testing::image_key(&hub, &job.id).unwrap();
    // Wait for the start to be persisted so recovery can read it.
    wait_until(|| {
        db.job(&job.id)
            .unwrap()
            .is_some_and(|r| r.started_at.is_some())
    })
    .await;
    drop(node);
    // Restarted over the same database, the job still running on its node.
    let (addr, hub) = serve_hub(db.clone(), &dir, Duration::from_secs(60)).await;
    assert_eq!(
        crate::jobs::testing::image_key(&hub, &job.id).as_deref(),
        Some(image.as_str())
    );
    let recalled = crate::jobs::testing::warm_at(&hub, &image, &node_id).unwrap();
    let held = Held {
        reservations: vec![],
        jobs: vec![HeldJob {
            job: job.id.clone(),
            state: RunState::Running {
                stage: "step_script".into(),
                activity: None,
                guest: None,
            },
            output_len: 0,
            finished: false,
        }],
    };
    let node = connect_node(addr, held).await;
    wait_until(|| crate::jobs::testing::linked(&hub, &node_id)).await;
    // Its end is a later use.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    node.send(NodeJobMsg::Result {
        job: job.id.clone(),
        result: result(None, 0),
    });
    wait_until(|| {
        crate::jobs::testing::warm_at(&hub, &image, &node_id).is_some_and(|at| at > recalled)
    })
    .await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_job_the_hub_disowned_counts_against_the_ceiling_until_it_ends() {
    let dir = scratch("ceiling-disowned");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let node_key = keypair();
    let id = new_node(addr, &hub, &node_key).await;
    crate::ops::set_ceiling(&hub, "uid 0", &id, Some(1)).unwrap();
    let stray = "5e".repeat(16);
    let held = Held {
        reservations: vec![],
        jobs: vec![HeldJob {
            job: stray.clone(),
            state: RunState::Running {
                stage: "step_script".into(),
                activity: None,
                guest: None,
            },
            output_len: 0,
            finished: false,
        }],
    };
    let mut node = connect(addr, &id, &node_key, V3, 16384, Some(held)).await;
    wait_until(|| crate::jobs::testing::linked(&hub, &id) && heard(&hub, &id)).await;
    assert!(matches!(node.job().await, HubJobMsg::Cancel { .. }));
    let fits = || async {
        crate::jobs::capacity(&hub, &placement())
            .await
            .unwrap()
            .fits
    };
    assert_eq!(fits().await, 0);
    node.send(NodeJobMsg::Result {
        job: stray.clone(),
        result: result(Some(FailureClass::Canceled), 0),
    });
    assert_eq!(node.job().await, HubJobMsg::Recorded { job: stray });
    assert_eq!(fits().await, 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A node refusing `ceiling` while the hub counts room on it is passed over: the offer goes
/// to another node, and so does the start it refuses.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_refusing_at_its_ceiling_is_passed_over() {
    let dir = scratch("ceiling-refused");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut big = ready_node(addr, &hub, 32768).await;
    let mut small = ready_node(addr, &hub, 8192).await;
    let ceiling = || OfferReply::Refused {
        reason: Refusal::Ceiling,
        message: None,
    };
    let ask = {
        let key = key.clone();
        tokio::spawn(async move {
            api(
                addr,
                "POST",
                "/v1/reservations",
                Some(&key),
                Some(relay_reservation_body(1, 5)),
            )
            .await
        })
    };
    let HubJobMsg::Offer { reservation, .. } = big.job().await else {
        panic!("expected an offer");
    };
    big.send(NodeJobMsg::OfferReply {
        reservation,
        reply: ceiling(),
    });
    let HubJobMsg::Offer { reservation, .. } = small.job().await else {
        panic!("expected an offer");
    };
    small.send(NodeJobMsg::OfferReply {
        reservation,
        reply: OfferReply::Accepted { lease_secs: 60 },
    });
    let resp = ask.await.unwrap();
    assert_eq!(resp.status, 201, "{resp:?}");
    assert_eq!(
        crate::jobs::last_refusal(&hub, &big.id).as_deref(),
        Some("ceiling")
    );

    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(2, None, 30)),
    )
    .await;
    let job: JobView = resp.json();
    let start = next_start(&mut big).await;
    assert_eq!(start.job, job.id);
    big.send(NodeJobMsg::Job {
        job: job.id.clone(),
        state: RunState::Refused {
            reason: Refusal::Ceiling,
            message: None,
        },
    });
    assert_eq!(next_start(&mut small).await.job, job.id);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A node's page wakes when the hub places work on it, which only dispatch notes, and not for
/// work placed elsewhere.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_s_page_wakes_when_work_is_placed_on_it() {
    let hub = Arc::new(Hub::new(Arc::new(Db::open_memory().unwrap()), None));
    let (node, other) = ("ab".repeat(16), "cd".repeat(16));
    let mut work = crate::jobs::subscribe_node_work(&hub, &node);
    let elsewhere = crate::jobs::subscribe_node_work(&hub, &other);
    crate::jobs::testing::offer_unanswered(&hub, &node);
    wait_until(|| work.has_changed().unwrap()).await;
    assert!(!elsewhere.has_changed().unwrap());
    work.borrow_and_update();
    crate::jobs::testing::offer_unanswered(&hub, &other);
    wait_until(|| elsewhere.has_changed().unwrap()).await;
    assert!(!work.has_changed().unwrap());
}

/// The task behind a node page's wake-ups ends with the page's stream.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_s_page_wake_ups_end_with_its_stream() {
    let hub = Arc::new(Hub::new(Arc::new(Db::open_memory().unwrap()), None));
    let node = "ab".repeat(16);
    let work = crate::jobs::subscribe_node_work(&hub, &node);
    // The task holds the hub, and the node's notifications, until it ends.
    assert_eq!(hub.followed_nodes(), 1);
    assert!(Arc::strong_count(&hub) > 1);
    drop(work);
    crate::jobs::testing::offer_unanswered(&hub, &node);
    wait_until(|| Arc::strong_count(&hub) == 1).await;
    // A notification for the node finds no one following it and forgets it.
    hub.changed(&node);
    assert_eq!(hub.followed_nodes(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_job_on_a_reservation_with_no_placement_window_starts() {
    let dir = scratch("window-0");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 16384).await;
    let grant = reserve_on(addr, &key, &mut node, 1, Some("test")).await;
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
    for bad in ["", "16", "0G", "G", "-1G", "16X", "1é", "é"] {
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
                ..
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
        instance: None,
        request_id: request_id(1),
        scheduling: None,
        admission: None,
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
        git_ref: None,
        pipeline: None,
        expired_at: None,
        commit: None,
        activity: None,
        prepared_at: None,
        guest: None,
        registry_access: None,
        gitlab: None,
        project_id: None,
        protected: None,
        egress_rules: None,
        egress_caps: None,
        egress: None,
    };
    let mut running = row(JobState::Running, None);
    running.started_at = Some(1010);
    running.prepared_at = Some(1020);
    let mut preparing = row(JobState::Running, None);
    preparing.started_at = Some(1030);
    preparing.stage = Some("prepare_executor".into());
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
            ("ee".repeat(16), preparing),
        ],
        1060,
    );
    let lines: Vec<&str> = out.lines().collect();
    assert!(
        lines[0].starts_with("ID")
            && lines[0].contains("PREP")
            && lines[0].contains("RAN")
            && lines[0].contains("PEAK"),
        "{out}"
    );
    // Prepared in 10 seconds, running for 40; nothing measured yet.
    assert!(
        lines[1].contains("running: step_script")
            && lines[1].contains("1m ago")
            && lines[1].contains(" 10s ")
            && lines[1].contains(" 40s "),
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
    // Preparing for 30 seconds: no run yet.
    assert!(
        lines[5].contains("preparing") && lines[5].contains(" 30s ") && lines[5].contains(" - "),
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
        instance: None,
        request_id: request_id(n),
        scheduling: None,
        admission: None,
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
        git_ref: None,
        pipeline: None,
        expired_at: None,
        commit: None,
        activity: None,
        prepared_at: None,
        guest: None,
        registry_access: None,
        gitlab: None,
        project_id: None,
        protected: None,
        egress_rules: None,
        egress_caps: None,
        egress: None,
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
            activity: None,
            guest: None,
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

/// A hub as [`start_jobs`]'s keeping `keep` bytes of a failed job's output when it is settled,
/// and `(bytes, total)` of others' ([`Hub::keeping_output`]).
async fn start_keeping(
    dir: &std::path::Path,
    keep: u64,
    (bytes, total): (u64, u64),
) -> (SocketAddr, Arc<Hub>) {
    let listener = server::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let hub = Hub::new(Arc::new(Db::open_memory().unwrap()), None)
        .with_jobs(dir.join("jobs"), Duration::from_secs(60), None)
        .unwrap()
        .keeping_failure_output(keep)
        .keeping_output(bytes, total);
    let hub = Arc::new(hub);
    tokio::spawn(server::serve(listener, None, hub.clone()));
    tokio::spawn(crate::jobs::drive(hub.clone()));
    (addr, hub)
}

/// Run job `n` on `node` to `failure` with `out` as its output, then settle it: its ID.
async fn settled_job(
    addr: SocketAddr,
    key: &str,
    node: &mut FakeNode,
    n: u8,
    out: &[u8],
    failure: Option<FailureClass>,
) -> String {
    let id = running_job(addr, key, node, n).await;
    node.send(output(&id, 0, out));
    assert!(matches!(node.job().await, HubJobMsg::OutputAck { .. }));
    node.send(NodeJobMsg::Result {
        job: id.clone(),
        result: result(failure, out.len() as u64),
    });
    assert_eq!(node.job().await, HubJobMsg::Recorded { job: id.clone() });
    view_until(addr, key, &id, |v| v.state == JobState::Finished).await;
    let path = format!("/v1/jobs/{id}/settle");
    assert_eq!(api(addr, "POST", &path, Some(key), None).await.status, 204);
    id
}

/// Settled, a failed job keeps the end of its output, from a line's start, with its record;
/// a job that succeeded or was canceled keeps its end in the hub's cache, the oldest going
/// past its total; a hub configured to keep none keeps none.
#[tokio::test(flavor = "multi_thread")]
async fn a_settled_job_keeps_the_end_of_its_output() {
    let dir = scratch("kept");
    let (addr, hub) = start_keeping(&dir, 16, (8, 16)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 16384).await;
    let out = b"first line\nsecond line\nthird\n";

    // Finished and not yet settled, its page reads the end of the output stored.
    let id = running_job(addr, &key, &mut node, 1).await;
    node.send(output(&id, 0, out));
    assert!(matches!(node.job().await, HubJobMsg::OutputAck { .. }));
    node.send(NodeJobMsg::Result {
        job: id.clone(),
        result: result(Some(FailureClass::System), out.len() as u64),
    });
    assert_eq!(node.job().await, HubJobMsg::Recorded { job: id.clone() });
    let (_, tail) = crate::jobs::detail(&hub, &id).unwrap().unwrap();
    assert_eq!(tail.as_deref(), Some(&b"third\n"[..]));
    assert_eq!(hub.db.job_tail(&id).unwrap(), None);
    let path = format!("/v1/jobs/{id}/settle");
    assert_eq!(api(addr, "POST", &path, Some(&key), None).await.status, 204);
    assert!(!dir.join("jobs").join(format!("{id}.out")).exists());
    // The last 16 bytes, from the line they cut into on.
    assert_eq!(
        hub.db.job_tail(&id).unwrap().as_deref(),
        Some(&b"third\n"[..])
    );
    let (row, tail) = crate::jobs::detail(&hub, &id).unwrap().unwrap();
    assert!(row.settled_at.is_some());
    assert_eq!(tail.as_deref(), Some(&b"third\n"[..]));

    let script = settled_job(
        addr,
        &key,
        &mut node,
        2,
        b"boom\n",
        Some(FailureClass::Script),
    )
    .await;
    assert_eq!(
        hub.db.job_tail(&script).unwrap().as_deref(),
        Some(&b"boom\n"[..])
    );
    // The last 8 bytes from a line's start; detail reads the same before it is settled.
    let ok = running_job(addr, &key, &mut node, 3).await;
    node.send(output(&ok, 0, out));
    assert!(matches!(node.job().await, HubJobMsg::OutputAck { .. }));
    node.send(NodeJobMsg::Result {
        job: ok.clone(),
        result: result(None, out.len() as u64),
    });
    assert_eq!(node.job().await, HubJobMsg::Recorded { job: ok.clone() });
    let (_, tail) = crate::jobs::detail(&hub, &ok).unwrap().unwrap();
    assert_eq!(tail.as_deref(), Some(&b"third\n"[..]));
    let path = format!("/v1/jobs/{ok}/settle");
    assert_eq!(api(addr, "POST", &path, Some(&key), None).await.status, 204);
    assert_eq!(
        hub.db.job_tail(&ok).unwrap().as_deref(),
        Some(&b"third\n"[..])
    );
    let (row, tail) = crate::jobs::detail(&hub, &ok).unwrap().unwrap();
    assert!(row.settled_at.is_some());
    assert_eq!(tail.as_deref(), Some(&b"third\n"[..]));
    let canceled = settled_job(
        addr,
        &key,
        &mut node,
        4,
        b"stop\n",
        Some(FailureClass::Canceled),
    )
    .await;
    assert_eq!(
        hub.db.job_tail(&canceled).unwrap().as_deref(),
        Some(&b"stop\n"[..])
    );
    // 7 and 6 bytes stored of 16, each with its format's byte: 8 more evict the oldest, and
    // only it.
    let more = settled_job(addr, &key, &mut node, 5, b"later!\n", None).await;
    assert_eq!(hub.db.job_tail(&ok).unwrap(), None);
    assert_eq!(crate::jobs::detail(&hub, &ok).unwrap().unwrap().1, None);
    assert!(hub.db.job_tail(&canceled).unwrap().is_some());
    assert!(hub.db.job_tail(&more).unwrap().is_some());
    // A failed job's end is outside the cache.
    assert_eq!(
        hub.db.job_tail(&script).unwrap().as_deref(),
        Some(&b"boom\n"[..])
    );

    // Configured to keep none.
    let off = dir.join("off");
    let (addr, hub) = start_keeping(&off, 0, (0, 1 << 20)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 16384).await;
    let id = settled_job(addr, &key, &mut node, 1, out, Some(FailureClass::System)).await;
    assert_eq!(hub.db.job_tail(&id).unwrap(), None);
    assert_eq!(crate::jobs::detail(&hub, &id).unwrap().unwrap().1, None);
    let ok = settled_job(addr, &key, &mut node, 2, out, None).await;
    assert_eq!(hub.db.job_tail(&ok).unwrap(), None);
    assert_eq!(crate::jobs::detail(&hub, &ok).unwrap().unwrap().1, None);
    // Nor does a cache of no room.
    let none = dir.join("none");
    let (addr, hub) = start_keeping(&none, 0, (1 << 20, 0)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 16384).await;
    let ok = settled_job(addr, &key, &mut node, 1, out, None).await;
    assert_eq!(hub.db.job_tail(&ok).unwrap(), None);
    // A cache no larger than a tail keeps one that does not compress, cut to fit stored.
    let tight = dir.join("tight");
    let (addr, hub) = start_keeping(&tight, 0, (16, 16)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 16384).await;
    let ok = settled_job(addr, &key, &mut node, 1, b"0123456789\nabcd\n", None).await;
    assert_eq!(
        hub.db.job_tail(&ok).unwrap().as_deref(),
        Some(&b"abcd\n"[..])
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A job its node failed, or whose image it could not pull, is audited with the node's
/// message; one its script failed is not.
#[tokio::test(flavor = "multi_thread")]
async fn a_system_or_image_pull_failure_is_audited() {
    let dir = scratch("failaudit");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let mut node = ready_node(addr, &hub, 16384).await;
    for (n, failure, line) in [
        (1, FailureClass::System, Some("system failure: the VM died")),
        (
            2,
            FailureClass::ImagePull,
            Some("image pull failure: the VM died"),
        ),
        (3, FailureClass::Script, None),
    ] {
        let id = running_job(addr, &key, &mut node, n).await;
        let mut ended = result(Some(failure), 0);
        ended.message = Some("the VM died".into());
        node.send(NodeJobMsg::Result {
            job: id.clone(),
            result: ended,
        });
        assert_eq!(node.job().await, HubJobMsg::Recorded { job: id.clone() });
        let actor = actor_of(&key);
        let mut expected = vec![format!(
            "{actor} submitted job {id}: GitLab job {n} of group/project (test)"
        )];
        expected.extend(line.map(|l| format!("job {id} ended: {l}")));
        assert_eq!(job_audit(&hub, &id), expected);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A trace is made readable: stamps parsed and continued lines joined, a line rewritten by
/// carriage returns shown as it was left, section markers and escape sequences dropped.
#[test]
fn a_trace_is_made_readable() {
    let stamp = "2026-10-09T12:10:43.123456Z";
    let trace = format!(
        "{stamp} 00O \x1b[0KRunning with vk\x1b[0;m\n\
         {stamp} 00O section_start:1700000000:step_script\r\x1b[0K\n\
         {stamp} 00O+\x1b[0KExecuting \"step_script\"\x1b[0;m\n\
         {stamp} 01O 10%\r50%\r100%\r\n\
         {stamp} 01E \x1b[31m<b>error</b>\x1b[0m: \x07boom\n\
         {stamp} 00O section_end:1700000001:step_script\r\x1b[0K\n\
         plain \x1b]0;title\x07line\n"
    );
    let lines = crate::jobs::readable(trace.as_bytes());
    let at = Some(stamp.to_string());
    let want = [
        (at.clone(), "Running with vk"),
        (at.clone(), "Executing \"step_script\""),
        (at.clone(), "100%"),
        (at.clone(), "<b>error</b>: boom"),
        (None, "plain line"),
    ];
    assert_eq!(
        lines
            .iter()
            .map(|l| (l.at.clone(), l.text.as_str()))
            .collect::<Vec<_>>(),
        want
    );
    // Not valid UTF-8, it is shown all the same.
    let lines = crate::jobs::readable(b"bad \xff byte\n");
    assert_eq!(lines[0].text, "bad \u{fffd} byte");
    // A continued line joins its own stream's last line, whatever came between.
    let trace = format!(
        "{stamp} 01O 10%\r\n\
         {stamp} 01E warn\n\
         {stamp} 01O+50%\r100%\n"
    );
    let lines = crate::jobs::readable(trace.as_bytes());
    assert_eq!(
        lines.iter().map(|l| l.text.as_str()).collect::<Vec<_>>(),
        ["100%", "warn"]
    );
}

/// The end of a job's output starts at a line's start: a line the cut fell inside is dropped,
/// one starting right at the cut is kept whole.
#[test]
fn an_output_s_end_starts_at_a_line() {
    let dir = scratch("tail");
    let id = "a".repeat(32);
    let output = b"one\ntwo\nthree\n";
    std::fs::write(dir.join(format!("{id}.out")), output).unwrap();
    let len = output.len() as u64;
    let tail = |max| crate::jobs::testing::output_tail(&dir, &id, len, max).unwrap();
    assert_eq!(tail(len), output);
    // "two\n" starts right at the cut.
    assert_eq!(tail(len - 4), b"two\nthree\n");
    assert_eq!(tail(len - 5), b"three\n");
    // Inside the last line, with no line after it: nothing.
    assert_eq!(tail(3), b"");
    // A line cut with no newline after the cut keeps what follows it.
    std::fs::write(dir.join(format!("{id}.out")), b"one\ntwo").unwrap();
    let tail = crate::jobs::testing::output_tail(&dir, &id, 7, 2).unwrap();
    assert_eq!(tail, b"wo");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `vk-hub jobs show <id>` prints a job's record and the end of its output, without the
/// job's escape sequences.
#[test]
fn a_job_is_shown_on_the_command_line() {
    let cli = Cli::try_parse_from(["vk-hub", "jobs", "show", "abc"]).unwrap();
    let Cmd::Jobs {
        cmd: Some(JobsCmd::Show { id }),
        ..
    } = cli.cmd
    else {
        panic!("expected jobs show");
    };
    assert_eq!(id, "abc");
    assert!(Cli::try_parse_from(["vk-hub", "jobs", "--limit", "5", "show", "abc"]).is_err());
    let mut row = crate::store::JobRow {
        key: "k".into(),
        key_name: "gitlab".into(),
        instance: None,
        request_id: request_id(1),
        scheduling: None,
        admission: None,
        placement: placement(),
        title: "GitLab job 7 of g/p (test)".into(),
        job_url: Some("https://gitlab.example.com/g/p/-/jobs/7".into()),
        project: Some("g/p".into()),
        name: Some("test".into()),
        created_at: 1000,
        state: JobState::Finished,
        revision: 3,
        node: Some("ab".repeat(16)),
        stage: None,
        cancel: None,
        result: Some(result(Some(FailureClass::System), 30)),
        output_len: 30,
        started_at: Some(1010),
        finished_at: Some(1070),
        settled_at: Some(1080),
        git_ref: None,
        pipeline: None,
        expired_at: None,
        commit: Some("ab12".into()),
        activity: None,
        prepared_at: Some(1030),
        guest: Some(vk_hub_proto::dispatch::GuestSize {
            cpus: 2,
            mem_mib: 4096,
        }),
        registry_access: None,
        gitlab: None,
        project_id: None,
        protected: None,
        egress_rules: None,
        egress_caps: None,
        egress: None,
    };
    row.result.as_mut().unwrap().message = Some("the VM did not boot".into());
    let id = "cd".repeat(16);
    let out = render_job(
        &id,
        &row,
        Some(b"2026-10-09T12:10:43.123456Z 00O \x1b[31mno kernel\x1b[0m\n"),
        2000,
    );
    for want in [
        format!("job          {id}\n"),
        "state        failed: system failure\n".to_string(),
        "project      g/p\nbranch       -\ncommit       ab12\n".to_string(),
        "message      the VM did not boot\n".to_string(),
        "gitlab       https://gitlab.example.com/g/p/-/jobs/7\n".to_string(),
        "finished     1970-01-01T00:17:50Z\n".to_string(),
        "prepared in  20s\nran          40s\nsize         2 vCPUs, 4G\n".to_string(),
        "\nThe last 51 bytes of its output, masked as the node streamed it:\n\
         12:10:43 no kernel\n"
            .to_string(),
    ] {
        assert!(out.contains(&want), "{want:?} not in {out}");
    }
    assert!(!out.contains('\x1b'), "{out}");
    // A link that is not a plain web one is left out.
    row.job_url = Some("javascript:alert(1)".into());
    assert!(!render_job(&id, &row, None, 2000).contains("gitlab "));
    // An unreported size is unknown.
    row.guest = None;
    assert!(render_job(&id, &row, None, 2000).contains("size         -\n"));
}

/// A spec's commit is kept lowercased, and only as hex no longer than a SHA-256.
#[test]
fn a_commit_is_hex_or_nothing() {
    use crate::client::commit;
    assert_eq!(commit("AbC123").as_deref(), Some("abc123"));
    assert_eq!(commit(&"f".repeat(64)), Some("f".repeat(64)));
    for bad in ["", "abc\"><x", "0123456789 ", &"f".repeat(65)] {
        assert_eq!(commit(bad), None, "{bad:?}");
    }
}

/// Approve project `id_path`, `<id>[:<path>]`, of instance `gl`.
fn approve(hub: &Hub, id_path: &str) {
    let project = crate::store::ProjectRef::parse(id_path).unwrap();
    let id: u64 = id_path.split(':').next().unwrap().parse().unwrap();
    let mut policy = hub.db.capacity_policy().unwrap();
    if let Some(tenant) = policy.tenants.get_mut("tests")
        && !tenant
            .projects
            .iter()
            .any(|p| p.gitlab == "gl" && p.id == id)
    {
        tenant.projects.push(crate::policy::Project {
            gitlab: "gl".into(),
            id,
            production_branches: vec![],
            placement_rules: vec![],
        });
    }
    hub.db
        .set_capacity_policy(&policy, "tests", now_secs())
        .unwrap();
    hub.db
        .decide_projects(
            "gl",
            &[project],
            crate::store::Decision::Approve,
            "u",
            now_secs(),
        )
        .unwrap();
}

/// A job body of project `id` at `path`, from the instance [`jobs_key`]'s relay is bound to,
/// which runs for `timeout_secs`.
fn bound_body(n: u8, id: u64, path: &str, timeout_secs: u64) -> Value {
    let mut body = job_body(n, None, 30);
    let JobSpec::GitlabCi(mut ci) = spec(u64::from(n));
    ci.job.project_id = id;
    ci.job.project_path = path.into();
    ci.timeout_secs = timeout_secs;
    body["spec"] = json!(JobSpec::GitlabCi(ci));
    body
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_s_approved_job_gets_a_token_for_its_node_s_registry() {
    let dir = scratch("token");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let registry = super::tokens::token_registry(&hub, super::tokens::REGISTRY_URL, "cc");
    // Room for every job below at once: none of them ends.
    let mut node = ready_node(addr, &hub, 16384 * 8).await;
    let node_id = node.id.clone();
    let set_inventory = |registry: Option<&str>, job_tokens: bool| {
        let mut inventory = hub.db.node(&node_id).unwrap().unwrap().inventory.unwrap();
        inventory.registry = registry.map(str::to_string);
        inventory.job_tokens = job_tokens;
        hub.db
            .record_inventory(&node_id, inventory, true, now_secs())
            .unwrap();
    };
    set_inventory(Some("https://REG.example.com"), true);
    let submit = |key: String, body: Value| async move {
        api(addr, "POST", "/v1/jobs", Some(&key), Some(body)).await
    };
    // What the approval gate does not let through is refused before it is queued: another
    // server's job, a job naming no project, and one of a project not approved yet, which
    // makes it pending.
    let mut foreign = bound_body(1, 42, "wab/core", 600);
    foreign["spec"]["server_url"] = json!("https://evil.example.com");
    let resp = submit(key.clone(), foreign).await;
    assert_eq!((resp.status, resp.code()), (403, ErrorCode::Forbidden));
    let resp = submit(key.clone(), bound_body(1, 0, "wab/core", 600)).await;
    assert_eq!((resp.status, resp.code()), (400, ErrorCode::Invalid));
    let resp = submit(key.clone(), bound_body(1, 42, "wab/core", 600)).await;
    assert_eq!(
        (resp.status, resp.code()),
        (403, ErrorCode::ApprovalPending)
    );
    approve(&hub, "42");
    let resp = submit(key.clone(), bound_body(2, 42, "wab/core", 600)).await;
    assert_eq!(resp.status, 201, "{resp:?}");
    let view: JobView = resp.json();
    // Its record keeps the claims the gate held it to, and the protection reported.
    let row = hub.db.job(&view.id).unwrap().unwrap();
    assert_eq!(
        (row.gitlab.as_deref(), row.project_id, row.protected),
        (Some("gl"), Some(42), None)
    );
    let HubJobMsg::Start(start) = node.job().await else {
        panic!("expected a start");
    };
    let access = start.registry.expect("a registry token");
    assert_eq!(access.registry_id, registry);
    assert_eq!(
        access.cache_repo.as_deref(),
        Some("ci-cache/gl/42/unprotected")
    );
    assert_eq!(
        access.pipeline_prefix.as_deref(),
        Some("ci-pipeline/gl/42/902")
    );
    let keys = hub
        .db
        .registry(&registry)
        .unwrap()
        .unwrap()
        .desired
        .unwrap()
        .token_keys
        .unwrap();
    let claims = vk_peer::token::verify(&access.token, &keys, &registry, now_secs()).unwrap();
    assert_eq!(claims.sub, format!("job:{}", view.id));
    assert_eq!(claims.pipeline.as_deref(), Some("gl/902"));
    assert_eq!(claims.grants, access.grants);
    assert_eq!(claims.exp, access.expires_at);
    // Its timeout, and what is stored after its last step.
    assert_eq!(
        claims.exp - claims.iat,
        600 + crate::tokens::JOB_TOKEN_MARGIN
    );
    let rights: Vec<(String, String)> = claims
        .grants
        .iter()
        .map(|g| (g.prefix.clone(), g.rights()))
        .collect();
    assert_eq!(
        rights,
        [
            ("ci-cache/gl/42/unprotected".to_string(), "rw".to_string()),
            ("ci-pipeline/gl/42/902".to_string(), "rwl".to_string())
        ]
    );
    assert!(format!("{access:?}").contains("[redacted]"));
    // The issue is audited beside the start, under the registry, naming the node.
    wait_until(|| {
        hub.db
            .audits(Some(&registry), 200)
            .unwrap()
            .iter()
            .any(|a| a.event.contains(&claims.jti) && a.event.contains(&node_id))
    })
    .await;
    let audit = hub.db.audits(None, 200).unwrap();
    assert!(audit.iter().all(|a| !a.event.contains("vkt_")));
    // The job's record shows what it got, never the token.
    let shown = |id: &str| {
        crate::jobs::detail(&hub, id)
            .unwrap()
            .unwrap()
            .0
            .registry_access
    };
    assert_eq!(
        shown(&view.id),
        Some(RegistryAccess::Issued {
            registry: registry.clone(),
            grants: claims.grants.clone(),
            expires_at: claims.exp,
            jti: claims.jti.clone(),
        })
    );
    // A token lives no longer than max_job_token_secs, whatever the job's timeout.
    let resp = submit(key.clone(), bound_body(3, 42, "wab/core", 30 * 86_400)).await;
    assert_eq!(resp.status, 201, "{resp:?}");
    let HubJobMsg::Start(start) = node.job().await else {
        panic!("expected a start");
    };
    let access = start.registry.expect("a registry token");
    let claims = vk_peer::token::verify(&access.token, &keys, &registry, now_secs()).unwrap();
    assert_eq!(
        claims.exp - claims.iat,
        crate::tokens::DEFAULT_MAX_JOB_TOKEN.as_secs()
    );
    assert!(access.areas.is_empty(), "no namespace has an alias yet");
    // A namespace's alias reaches a job only on a node that maps it.
    let tc = crate::store::NamespaceRow {
        name: "tc".into(),
        path: "task-cache/{gitlab}/{project_id}/{protection}".into(),
        retention_days: None,
        alias: Some("task-cache".into()),
        grants: vec![crate::store::NsGrant::parse("rwl:own project").unwrap()],
        created_at: 0,
        created_by: "t".into(),
    };
    crate::registries::put_namespace(&hub, "u", &registry, &tc).unwrap();
    let area = vk_hub_proto::dispatch::Area {
        alias: "task-cache".into(),
        prefix: "task-cache/gl/42/unprotected".into(),
    };
    for (n, maps, want) in [(40, false, vec![]), (41, true, vec![area])] {
        let mut inventory = hub.db.node(&node_id).unwrap().unwrap().inventory.unwrap();
        inventory.registry_areas = maps;
        hub.db
            .record_inventory(&node_id, inventory, true, now_secs())
            .unwrap();
        let resp = submit(key.clone(), bound_body(n, 42, "wab/core", 600)).await;
        assert_eq!(resp.status, 201, "{resp:?}");
        let HubJobMsg::Start(start) = node.job().await else {
            panic!("expected a start");
        };
        assert_eq!(start.registry.expect("a registry token").areas, want);
    }
    // Jobs go without when anything a token needs is missing: a node that uses none or names
    // no registry the hub binds.
    let mut n = 4;
    let mut goes_without = |key: String| {
        n += 1;
        let body = bound_body(n, 42, "wab/core", 600);
        async move { (key, body) }
    };
    let none = |reason, registry: Option<&str>, url: Option<&str>| {
        Some(RegistryAccess::None {
            reason,
            registry: registry.map(str::to_string),
            url: url.map(str::to_string),
        })
    };
    // A registry bound to the URL but taking no tokens.
    let untokened = super::tokens::token_registry(&hub, "https://plain.example.com", "dd");
    let inventory = vk_hub_proto::registry::Inventory::default();
    hub.db
        .record_registry(
            &untokened,
            crate::store::RegistryWrite::Inventory(inventory),
            now_secs(),
        )
        .unwrap();
    for (url, job_tokens, why, want) in [
        (
            Some("https://reg.example.com"),
            false,
            "a node not using tokens",
            none(NoAccess::NodeWithoutJobTokens, None, None),
        ),
        (
            Some("https://other.example.com"),
            true,
            "a registry the hub does not bind",
            none(
                NoAccess::UnknownRegistry,
                None,
                Some("https://other.example.com"),
            ),
        ),
        (
            Some("https://plain.example.com"),
            true,
            "a registry taking no tokens",
            none(
                NoAccess::RegistryTakesNoTokens,
                Some(&untokened),
                Some("https://plain.example.com"),
            ),
        ),
        (
            None,
            true,
            "a node naming no registry",
            none(NoAccess::UnknownRegistry, None, None),
        ),
    ] {
        set_inventory(url, job_tokens);
        let (k, body) = goes_without(key.clone()).await;
        let resp = submit(k, body).await;
        assert_eq!(resp.status, 201);
        let HubJobMsg::Start(start) = node.job().await else {
            panic!("expected a start");
        };
        assert!(start.registry.is_none(), "{why}");
        assert_eq!(shown(&resp.json::<JobView>().id), want, "{why}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Requeued jobs clear their registry access; the next placement records its own.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_start_forgets_the_registry_access_it_was_given() {
    let dir = scratch("token-refused");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    approve(&hub, "42:wab/core");
    super::tokens::token_registry(&hub, super::tokens::REGISTRY_URL, "cc");
    let node = ready_node(addr, &hub, 16384 * 8).await;
    let mut inventory = hub.db.node(&node.id).unwrap().unwrap().inventory.unwrap();
    inventory.registry = Some(super::tokens::REGISTRY_URL.into());
    inventory.job_tokens = true;
    hub.db
        .record_inventory(&node.id, inventory, true, now_secs())
        .unwrap();
    let mut node = node;
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(bound_body(1, 42, "wab/core", 600)),
    )
    .await;
    assert_eq!(resp.status, 201, "{resp:?}");
    let view: JobView = resp.json();
    let HubJobMsg::Start(_) = node.job().await else {
        panic!("expected a start");
    };
    let shown = || {
        crate::jobs::detail(&hub, &view.id)
            .unwrap()
            .unwrap()
            .0
            .registry_access
    };
    assert!(matches!(shown(), Some(RegistryAccess::Issued { .. })));
    node.send(NodeJobMsg::Job {
        job: view.id.clone(),
        state: RunState::Refused {
            reason: Refusal::Memory,
            message: None,
        },
    });
    wait_until(|| shown().is_none()).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// With `[jobs] egress_rules`, a job is placed only on a node that enforces the rules, with
/// the layer they resolve to from its claims, bounded by its key; one whose layer cannot be
/// sent fails, saying why.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_under_egress_rules_takes_its_layer_to_a_node_that_enforces_them() {
    use crate::store::{RuleChange, RuleMode};
    use crate::subject::Subject;
    use vk_hub_proto::egress::HubPhase;
    let dir = scratch("egress-rules");
    let db = Arc::new(Db::open_memory().unwrap().with_egress_rules(true));
    let (addr, hub) = serve_hub(db, &dir, Duration::from_secs(60)).await;
    let now = now_secs();
    let key = jobs_key(&hub);
    let none = HubPhase::Allow {
        names: Vec::new(),
        ips: Vec::new(),
    };
    let rule = |name: &str, subject: Option<&str>, run: HubPhase| RuleChange {
        name: name.into(),
        subject: subject.map(|s| Subject::parse(s).unwrap()),
        run: Some(run),
        build: Some(none.clone()),
        mode: Some(RuleMode::Enforce),
    };
    let wab = HubPhase::Allow {
        names: vec!["corp.example.com".into()],
        ips: Vec::new(),
    };
    for r in [
        rule("default", None, HubPhase::Unrestricted),
        rule("wab", Some("gitlab gl, projects wab/**"), wab.clone()),
    ] {
        hub.db.put_egress_rule(&r, false, "uid 0", now).unwrap();
    }
    approve(&hub, "42:wab/core");
    let mut node = ready_node(addr, &hub, 16384 * 8).await;
    // A node that does not say it enforces the rules has no room, and is sent nothing.
    let fits = |key: String| async move {
        api(
            addr,
            "POST",
            "/v1/capacity",
            Some(&key),
            Some(json!({"runner": "test", "placement": placement()})),
        )
        .await
        .json::<Capacity>()
        .fits
    };
    assert_eq!(fits(key.clone()).await, 0);
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(bound_body(1, 42, "wab/core", 600)),
    )
    .await;
    assert_eq!(resp.status, 201, "{resp:?}");
    let first: JobView = resp.json();
    node.quiet(Duration::from_millis(1500)).await;
    let node_id = node.id.clone();
    let mut inventory = hub.db.node(&node_id).unwrap().unwrap().inventory.unwrap();
    inventory.egress_rules = true;
    // Its caps, which the job's record names by fingerprint.
    let mut caps =
        vk_hub_proto::egress::EgressCaps::normalized(HubPhase::Unrestricted, false, none.clone())
            .unwrap();
    caps.fingerprint =
        vk_hub_proto::to_hex(&<sha2::Sha256 as sha2::Digest>::digest(caps.canonical()));
    inventory.egress_caps = Some(vk_hub_proto::egress::NodeEgressCaps::Listed(caps.clone()));
    hub.db
        .record_inventory(&node_id, inventory, true, now_secs())
        .unwrap();
    assert!(fits(key.clone()).await > 0);
    let HubJobMsg::Start(start) = node.job().await else {
        panic!("expected a start");
    };
    let egress = start.egress.expect("the hub's layer");
    assert_eq!(
        (egress.rules.as_slice(), &egress.run),
        (&["wab".to_string()][..], &wab)
    );
    // Written once the start is sent.
    wait_until(|| (hub.db.job(&first.id).unwrap()).is_some_and(|r| r.egress_rules.is_some())).await;
    let applied = hub
        .db
        .job(&first.id)
        .unwrap()
        .unwrap()
        .egress_rules
        .unwrap();
    assert_eq!(applied.rules, ["wab"]);
    assert_eq!(
        hub.db.job(&first.id).unwrap().unwrap().egress_caps,
        Some(caps.fingerprint)
    );
    assert_eq!(
        crate::egress::rules_applied_text(&applied),
        "wab (rules generation 2)"
    );
    // A project no rule selects: the Fallback alone.
    let mut body = bound_body(2, PROJECT_ID, "group/project", 600);
    body["placement"] = json!(placement());
    let resp = api(addr, "POST", "/v1/jobs", Some(&key), Some(body)).await;
    assert_eq!(resp.status, 201, "{resp:?}");
    let HubJobMsg::Start(start) = node.job().await else {
        panic!("expected a start");
    };
    let egress = start.egress.expect("the hub's layer");
    assert_eq!(egress.rules, ["default"]);
    assert_eq!(egress.run, HubPhase::Unrestricted);
    // More rules selecting a job than a layer may name: it fails, saying why.
    for i in 0..32 {
        let r = rule(&format!("r{i:02}"), Some("gitlab gl"), none.clone());
        hub.db.put_egress_rule(&r, false, "uid 0", now).unwrap();
    }
    let resp = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(bound_body(3, 42, "wab/core", 600)),
    )
    .await;
    let third: JobView = resp.json();
    let failed = view_until(addr, &key, &third.id, |v| v.state == JobState::Finished).await;
    let result = failed.result.expect("a result");
    assert_eq!(result.failure, Some(FailureClass::Configuration));
    let message = result.message.unwrap_or_default();
    assert!(
        message.contains("egress rules") && message.contains("past 32"),
        "{message}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
