//! The relay's one HTTP/2 connection to the hub: its session and its client's requests on
//! it, the hub's notices ending the client's waits, the connection dialed again once lost, a
//! hub that cannot carry it refused, and a session that outlives a link saturated by output
//! and submissions.

mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use support::fakehub::{FakeHub, TEST_RELAY_ID};
use support::gl::{eventually, hold_session, job_json, quick_retry, server_status, within};
use vk_gitlab::config::Config;
use vk_gitlab::dispatch::{Dispatcher, FakeDispatcher, Placement, QueueAnswer, Submission};
use vk_gitlab::hub::HubClient;
use vk_gitlab::relay;
use vk_gitlab::runners::Runners;
use vk_gitlab::session::Status;
use vk_gitlab::spec::{self, SpecContext};
use vk_hub_proto::gitlab::ServerState;
use vk_hub_proto::job::JobSpec;
use vk_peer::identity::Identity;

/// A relay's placement: no pool, its runner's lane on the hub placing its work.
fn p1() -> Placement {
    Placement::default()
}

/// What the hub's listener offers a relay over TLS.
const RELAY_OR_HTTP1: &[&[u8]] = &[vk_hub_proto::gitlab::ALPN, b"http/1.1"];

/// What a hub from before the relay's connection offers.
const HTTP1: &[&[u8]] = &[b"http/1.1"];

/// A relay enrolled with the hub at `url`, verified against the fixtures' CA over TLS.
fn enroll(hub: &FakeHub, url: &str, tag: &str) -> PathBuf {
    let state = support::gl::temp_dir(tag);
    let dir = relay::dir(&state);
    vk_peer::net::create_dir(&dir).unwrap();
    let identity = Identity::load_or_create(&dir).unwrap();
    hub.enroll(identity.public_key());
    let tls = url.starts_with("https:");
    if tls {
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls/hub-ca.pem"),
            dir.join("ca.pem"),
        )
        .unwrap();
    }
    std::fs::write(
        dir.join("enrollment.json"),
        format!(r#"{{"hub":"{url}","relay_id":"{TEST_RELAY_ID}","ca":{tls}}}"#),
    )
    .unwrap();
    state
}

/// The relay in `state` in session, its server approved, and its client.
struct Relay {
    state: PathBuf,
    status: Arc<Status>,
    client: HubClient,
    session: tokio::task::JoinHandle<()>,
}

impl Relay {
    fn start(state: PathBuf) -> Self {
        let cfg = Config::parse(
            &format!(
                "state_dir = \"{}\"\n[gitlab]\nurl = \"https://gitlab.example.com\"\n\
                 [[runners]]\nname = \"r1\"\ntoken = \"glrt-x\"\n",
                state.display()
            ),
            Path::new("/"),
        )
        .unwrap();
        let status = Status::new(&cfg, "s_0123456789ab", "relay-host");
        status.set_server(Some(server_status(ServerState::Approved)));
        let (registry, _changes) = Runners::new(&cfg, "s_0123456789ab", Arc::clone(&status));
        let (link, session) = hold_session(&state, &cfg, &status, registry);
        Relay {
            state,
            status,
            client: HubClient::new(link, quick_retry()),
            session,
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.session.abort();
        let _ = std::fs::remove_dir_all(&self.state);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_session_and_requests_share_one_connection() {
    let dispatcher = FakeDispatcher::new();
    dispatcher.set_slots("r1", 8);
    let hub = FakeHub::start_tls(dispatcher.clone(), RELAY_OR_HTTP1).await;
    let relay = Relay::start(enroll(&hub, &hub.url, "conn-shared"));
    let placement = p1();
    // Sent before the session is up, answered once it is.
    let answers = within(
        "the capacity",
        futures::future::join_all((0..8).map(|_| {
            relay
                .client
                .capacity("r1", &placement, None, Duration::ZERO)
        })),
    )
    .await;
    for answer in answers {
        answer.unwrap();
    }
    assert_eq!((hub.connections(), hub.sessions()), (1, 1));
    assert_eq!(hub.requests_to("/v1/capacity"), 8);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ticket_told_of_before_it_is_known_is_fetched_at_once() {
    let dispatcher = FakeDispatcher::new();
    dispatcher.set_slots("r1", 1);
    let hub = FakeHub::start(dispatcher.clone()).await;
    let relay = Relay::start(enroll(&hub, &hub.url, "conn-early"));
    // Granted, and told of, before the relay has the ticket's answer.
    hub.delay_next_queue_response(Duration::from_millis(300));
    let QueueAnswer::Ticket(ticket) = within(
        "the ticket",
        relay.client.queue(
            "r1",
            &"1".repeat(32),
            &p1(),
            Duration::from_secs(30),
            Duration::ZERO,
        ),
    )
    .await
    .unwrap() else {
        panic!("expected a ticket");
    };
    let started = Instant::now();
    let QueueAnswer::Grant(grant) = within(
        "the grant",
        relay.client.poll_ticket(&ticket, Duration::from_secs(50)),
    )
    .await
    .unwrap() else {
        panic!("expected a grant");
    };
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(grant.sent >= started.into());
    // A ticket left queued is fetched once, then waited on for the time asked.
    let QueueAnswer::Ticket(queued) = relay
        .client
        .queue(
            "r1",
            &"2".repeat(32),
            &p1(),
            Duration::from_secs(30),
            Duration::ZERO,
        )
        .await
        .unwrap()
    else {
        panic!("expected a ticket");
    };
    let started = Instant::now();
    for wait in [Duration::ZERO, Duration::from_millis(500)] {
        let QueueAnswer::Ticket(_) = relay.client.poll_ticket(&queued, wait).await.unwrap() else {
            panic!("expected the ticket queued");
        };
    }
    assert!(started.elapsed() >= Duration::from_millis(500));
    assert_eq!(
        hub.requests_to(&format!("/v1/reservations/tickets/{queued}")),
        2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_connection_is_dialed_again_with_a_new_session() {
    let dispatcher = FakeDispatcher::new();
    dispatcher.set_slots("r1", 1);
    let hub = FakeHub::start_tls(dispatcher.clone(), RELAY_OR_HTTP1).await;
    let relay = Relay::start(enroll(&hub, &hub.url, "conn-lost"));
    within(
        "the capacity",
        relay.client.capacity("r1", &p1(), None, Duration::ZERO),
    )
    .await
    .unwrap();
    hub.cut_connections().await;
    // A request while the relay redials waits for its new session.
    within(
        "the capacity",
        relay.client.capacity("r1", &p1(), None, Duration::ZERO),
    )
    .await
    .unwrap();
    assert_eq!((hub.connections(), hub.sessions()), (2, 2));
    // A request whose stream the hub resets is sent again.
    hub.fail_next(
        1,
        "/v1/capacity",
        0,
        vk_hub_proto::client::ErrorCode::Other,
        None,
    );
    within(
        "the capacity",
        relay.client.capacity("r1", &p1(), None, Duration::ZERO),
    )
    .await
    .unwrap();
    assert_eq!(hub.requests_to("/v1/capacity"), 4);
}

/// A hub restarted at a lower revision of a job than the relay last saw is waited on again,
/// not fetched from in a loop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_job_at_a_lower_revision_after_a_new_session_is_waited_on() {
    let dispatcher = FakeDispatcher::new();
    dispatcher.set_slots("r1", 1);
    let hub = FakeHub::start(dispatcher.clone()).await;
    let relay = Relay::start(enroll(&hub, &hub.url, "conn-rewound"));
    let client = &relay.client;
    let id = within(
        "the job",
        client.submit(Submission {
            request_id: "1".repeat(32),
            runner: Some("r1".to_owned()),
            admission: None,
            placement: p1(),
            reservation: None,
            place_within: Duration::from_secs(60),
            gitlab_job: 1,
            spec: spec(1, 0),
        }),
    )
    .await
    .unwrap()
    .id;
    dispatcher.set_revision(&id, 10);
    let view = within("the view", client.job(&id, None, Duration::ZERO))
        .await
        .unwrap();
    assert_eq!(view.revision, 10);
    // The hub comes back at revision 2.
    dispatcher.set_revision(&id, 2);
    hub.cut_connections().await;
    eventually("a new session", || hub.sessions() == 2).await;
    let path = format!("/v1/jobs/{id}");
    let before = hub.requests_to(&path);
    let mut after = view.revision;
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(1) {
        let view = within(
            "the view",
            client.job(&id, Some(after), Duration::from_millis(250)),
        )
        .await
        .unwrap();
        after = view.revision;
    }
    assert_eq!(after, 2);
    let fetches = hub.requests_to(&path) - before;
    assert!(fetches <= 8, "{fetches} fetches in a second");
    // A revision past it is still told, and fetched.
    dispatcher.accept(&id);
    let started = Instant::now();
    let view = within(
        "the view",
        client.job(&id, Some(after), Duration::from_secs(30)),
    )
    .await
    .unwrap();
    assert_eq!(view.revision, 3);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hub_speaking_only_http1_takes_no_jobs_until_upgraded() {
    let hub = FakeHub::start_tls(FakeDispatcher::new(), HTTP1).await;
    let relay = Relay::start(enroll(&hub, &hub.url, "conn-old"));
    eventually("the relay to stop taking jobs", || !relay.status.approved()).await;
    assert_eq!(hub.sessions(), 0);
    assert!(hub.requests.lock().unwrap().is_empty());
}

/// Forwards each connection to `upstream`, each way at most `rate` bytes a second.
async fn throttled(upstream: std::net::SocketAddr, rate: usize) -> String {
    async fn pace(
        mut from: tokio::net::tcp::OwnedReadHalf,
        mut to: tokio::net::tcp::OwnedWriteHalf,
        rate: usize,
    ) {
        let mut buf = vec![0u8; 16 << 10];
        loop {
            let Ok(n) = from.read(&mut buf).await else {
                return;
            };
            let started = tokio::time::Instant::now();
            if n == 0 || to.write_all(&buf[..n]).await.is_err() {
                return;
            }
            // No credit for the time the link was idle: each read waits its own share.
            tokio::time::sleep_until(started + Duration::from_secs_f64(n as f64 / rate as f64))
                .await;
        }
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                return;
            };
            let Ok(server) = TcpStream::connect(upstream).await else {
                return;
            };
            let (client_read, client_write) = client.into_split();
            let (server_read, server_write) = server.into_split();
            tokio::spawn(pace(client_read, server_write, rate));
            tokio::spawn(pace(server_read, client_write, rate));
        }
    });
    url
}

/// A job's spec of about `size` bytes.
fn spec(id: i64, size: usize) -> JobSpec {
    let mut job = job_json(id);
    job["variables"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"key": "BULK", "value": "x".repeat(size)}));
    let job: vk_gitlab::job::Job = serde_json::from_value(job).unwrap();
    let translated = spec::translate(
        &job,
        &SpecContext {
            server_url: "https://gitlab.example.com".to_owned(),
            output_limit: 4 << 20,
            ..Default::default()
        },
    );
    JobSpec::GitlabCi(translated.job)
}

/// On a link slow enough that the bulk in flight takes a good part of the heartbeat's silence
/// limit to cross it, outputs one way and submissions the other, saturating it for longer than
/// that limit, hold neither the session's heartbeats nor the hub's pings past it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_session_outlives_a_link_saturated_by_outputs_and_submissions() {
    const JOBS: i64 = 8;
    const OUTPUT: usize = 3 << 19;
    let dispatcher = FakeDispatcher::new();
    dispatcher.set_slots("r1", 64);
    let hub = FakeHub::start(dispatcher.clone()).await;
    let upstream = hub.url.trim_start_matches("http://").parse().unwrap();
    // 4 MiB in flight takes 1.3 s of the session's 3 s silence limit.
    let url = throttled(upstream, 3 << 20).await;
    let relay = Relay::start(enroll(&hub, &url, "conn-saturated"));
    let client = &relay.client;
    let submit = |id: i64, size: usize| async move {
        client
            .submit(Submission {
                request_id: format!("{id:032x}"),
                runner: Some("r1".to_owned()),
                admission: None,
                placement: p1(),
                reservation: None,
                place_within: Duration::from_secs(60),
                gitlab_job: id,
                spec: spec(id, size),
            })
            .await
            .unwrap()
            .id
    };
    // The jobs whose output is read, submitted small.
    let ids = within(
        "the jobs",
        futures::future::join_all((1..=JOBS).map(|id| submit(id, 1 << 10))),
    )
    .await;
    let output = vec![b'o'; OUTPUT];
    for id in &ids {
        dispatcher.accept(id);
        dispatcher.push_output(id, &output);
        dispatcher.finish(id, None, Some(0));
    }
    let read = |id: String| async move {
        let mut offset = 0u64;
        loop {
            let chunk = client
                .output(&id, offset, Duration::from_secs(60))
                .await
                .unwrap();
            offset = chunk.offset + chunk.data.len() as u64;
            if chunk.complete {
                return offset;
            }
        }
    };
    // Outputs read while large submissions go the other way.
    let (read, submitted) = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(
            futures::future::join_all(ids.iter().cloned().map(read)),
            futures::future::join_all((JOBS + 1..=4 * JOBS).map(|id| submit(id, 400 << 10))),
        )
    })
    .await
    .expect("the outputs read and the jobs submitted");
    assert_eq!(submitted.len(), 3 * JOBS as usize);
    assert!(read.iter().all(|&len| len == OUTPUT as u64), "{read:?}");
    assert_eq!(
        (hub.connections(), hub.sessions()),
        (1, 1),
        "the session was lost"
    );
}
