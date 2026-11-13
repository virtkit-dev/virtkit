//! Lane placement over the client and node protocols.

use super::capacity::{
    accept_ticket, add_runner, queue, queue_for, ready_relay, take_job, wait_reason,
};
use super::*;

/// Have every runner lane select `nodes` and `pools`, and nothing else.
fn confine(hub: &Hub, nodes: &[&str], pools: &[&str]) {
    let mut policy = hub.db.capacity_policy().unwrap();
    let targets: Vec<String> = (nodes.iter().map(|n| crate::policy::node_pool(n)))
        .chain(pools.iter().map(|p| (*p).to_owned()))
        .collect();
    for lane in policy.lanes.iter_mut().filter(|l| l.runner.is_some()) {
        lane.pools.clone_from(&targets);
    }
    hub.db
        .set_capacity_policy(&policy, "u", now_secs())
        .unwrap();
}

/// `body` as a job of a pipeline of `branch`.
fn on_branch(mut body: Value, branch: &str) -> Value {
    body["spec"]["sources"]["ref"] = json!(branch);
    body["spec"]["sources"]["refspecs"] =
        json!([format!("+refs/heads/{branch}:refs/remotes/origin/{branch}")]);
    body
}

/// A grant of `key`'s runner on `node`, claimed, a job taken under it: its admission and grant.
async fn admitted(
    addr: SocketAddr,
    key: &str,
    node: &mut FakeNode,
    n: u8,
) -> (String, ReservationGrant) {
    let ticket = queue(addr, key, n).await;
    let grant = accept_ticket(addr, key, &ticket, node).await;
    take_job(addr, key, &ticket, &grant).await;
    (ticket, grant)
}

/// Submit `body` as `key`'s relay, on `admission` if any: the job's ID.
async fn submit(addr: SocketAddr, key: &str, mut body: Value, admission: Option<&str>) -> String {
    if let Some(admission) = admission {
        body["admission"] = json!(admission);
    }
    let reply = api(addr, "POST", "/v1/jobs", Some(key), Some(body)).await;
    assert_eq!(reply.status, 201, "{reply:?}");
    reply.json::<JobView>().id
}

#[tokio::test]
async fn a_lane_s_pool_holds_its_jobs_to_nodes_in_the_pool() {
    let dir = scratch("placement-pool");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let mut idle = ready_node(addr, &hub, 16384).await;
    // Busier, so it would go last but for the lane's nodes.
    let mut trusted = loaded_node(addr, &hub, 16384, Some(400)).await;
    hub.db
        .set_pools(
            &trusted.id,
            &["ci".into(), "trusted".into()],
            "u",
            now_secs(),
        )
        .unwrap();
    confine(&hub, &[], &["trusted"]);
    let job = submit(addr, &key, job_body(1, None, 30), None).await;
    assert_eq!(next_start(&mut trusted).await.job, job);
    idle.quiet(Duration::from_millis(100)).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Unconfined, the job would go to the warm node, releasing its reservation, as in
/// `a_job_goes_to_a_lightly_loaded_node_holding_its_image` in `tests/jobs.rs`.
#[tokio::test]
async fn image_affinity_cannot_escape_a_lane_s_nodes() {
    let dir = scratch("placement-affinity");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    // A node that built the job's image, lightly loaded.
    let mut warm = loaded_node(addr, &hub, 16384, Some(100)).await;
    let image = "dockerfile:ci/Dockerfile";
    let first = submit(addr, &key, job_body_with_image(1, None, image), None).await;
    assert_eq!(next_start(&mut warm).await.job, first);
    warm.send(NodeJobMsg::Job {
        job: first.clone(),
        state: RunState::Accepted,
    });
    view_until(addr, &key, &first, |v| v.state == JobState::Running).await;
    warm.send(NodeJobMsg::Result {
        job: first.clone(),
        result: result(None, 0),
    });
    assert_eq!(warm.job().await, HubJobMsg::Recorded { job: first.clone() });
    view_until(addr, &key, &first, |v| v.state == JobState::Finished).await;
    let path = format!("/v1/jobs/{first}/settle");
    let reply = api(addr, "POST", &path, Some(&key), None).await;
    assert_eq!(reply.status, 204, "{reply:?}");
    // A job reserved on another node, which alone its lane allows, stays there.
    let mut cold = loaded_node(addr, &hub, 16384, Some(0)).await;
    let (admission, grant) = admitted(addr, &key, &mut cold, 2).await;
    confine(&hub, &[&cold.id], &[]);
    let body = job_body_with_image(3, Some(&grant.reservation), image);
    let job = submit(addr, &key, body, Some(&admission)).await;
    let start = next_start(&mut cold).await;
    assert_eq!(start.job, job);
    assert_eq!(
        start.reservation.as_deref(),
        Some(grant.reservation.as_str())
    );
    warm.quiet(Duration::from_millis(100)).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_job_whose_project_is_delisted_is_held_saying_why() {
    let dir = scratch("placement-delisted");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    // Submitted while listed, with no node to take it yet; then its lane drops the project.
    let job = submit(addr, &key, job_body(1, None, 2), None).await;
    list_project(&hub, false);
    let mut node = ready_node(addr, &hub, 16384).await;
    crate::jobs::testing::step(&hub).await;
    assert_eq!(
        crate::jobs::testing::job_blocked(&hub, &job),
        Some("no longer allowed by its lane")
    );
    let ended = view_until(addr, &key, &job, |v| v.state == JobState::Finished).await;
    assert_eq!(
        ended.result.unwrap().message.as_deref(),
        Some("no node took it within its placement window (no longer allowed by its lane)")
    );
    node.quiet(Duration::from_millis(100)).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// List [`spec`]'s project for runner 42's lane, with `branches` if any, or with `listed`
/// false no longer.
fn list_project_on(hub: &Hub, listed: bool, branches: Option<&[&str]>) {
    let mut policy = hub.db.capacity_policy().unwrap();
    let projects = lane_42(&mut policy).projects.get_or_insert_default();
    projects.retain(|p| p.id != PROJECT_ID);
    if listed {
        projects.push(crate::policy::LaneProject {
            gitlab: "gl".into(),
            id: PROJECT_ID,
            branches: branches.map(|b| b.iter().map(|s| (*s).to_owned()).collect()),
        });
    }
    hub.db
        .set_capacity_policy(&policy, "u", now_secs())
        .unwrap();
}

fn list_project(hub: &Hub, listed: bool) {
    list_project_on(hub, listed, None);
}

#[tokio::test]
async fn a_job_of_a_branch_its_lane_no_longer_allows_is_held() {
    let dir = scratch("placement-branch-narrowed");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let job = submit(addr, &key, on_branch(job_body(1, None, 30), "dev"), None).await;
    list_project_on(&hub, true, Some(&["main"]));
    let mut node = ready_node(addr, &hub, 16384).await;
    crate::jobs::testing::step(&hub).await;
    assert_eq!(
        crate::jobs::testing::job_blocked(&hub, &job),
        Some("no longer allowed by its lane")
    );
    list_project_on(&hub, true, Some(&["main", "dev"]));
    crate::jobs::testing::step(&hub).await;
    assert_eq!(next_start(&mut node).await.job, job);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_job_of_a_runner_unmapped_is_held() {
    let dir = scratch("placement-unmapped");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let job = submit(addr, &key, job_body(1, None, 30), None).await;
    let mut policy = hub.db.capacity_policy().unwrap();
    let lane = lane_42(&mut policy).clone();
    policy.lanes.retain(|l| l.runner.is_none());
    hub.db
        .set_capacity_policy(&policy, "u", now_secs())
        .unwrap();
    let mut node = ready_node(addr, &hub, 16384).await;
    crate::jobs::testing::step(&hub).await;
    assert_eq!(
        crate::jobs::testing::job_blocked(&hub, &job),
        Some("no longer allowed by its lane")
    );
    node.quiet(Duration::from_millis(100)).await;
    policy.lanes.push(lane);
    hub.db
        .set_capacity_policy(&policy, "u", now_secs())
        .unwrap();
    crate::jobs::testing::step(&hub).await;
    assert_eq!(next_start(&mut node).await.job, job);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_job_whose_project_is_listed_again_starts() {
    let dir = scratch("placement-relisted");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let job = submit(addr, &key, job_body(1, None, 30), None).await;
    list_project(&hub, false);
    let mut node = ready_node(addr, &hub, 16384).await;
    crate::jobs::testing::step(&hub).await;
    assert_eq!(
        crate::jobs::testing::job_blocked(&hub, &job),
        Some("no longer allowed by its lane")
    );
    // Its server's page gives it as its runner's reason, with no request of the runner waiting.
    let snapshot = crate::jobs::arbitration_snapshot(&hub).unwrap();
    let view = &snapshot[&("gl".to_string(), 42)];
    assert_eq!(
        (view.waiting, view.jobs, view.reason),
        (0, 1, Some("no longer allowed by its lane"))
    );
    list_project(&hub, true);
    crate::jobs::testing::step(&hub).await;
    assert_eq!(next_start(&mut node).await.job, job);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A pass changing why a runner's job waits wakes the live updates of its server's page, and of
/// no other GitLab page; one changing nothing does not.
#[tokio::test]
async fn a_pass_changing_a_runner_s_reason_wakes_its_server_s_page() {
    let dir = scratch("placement-wakes");
    let db = Arc::new(Db::open_memory().unwrap());
    let (addr, hub) = serve_undriven(db, &dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let job = submit(addr, &key, job_body(1, None, 30), None).await;
    crate::jobs::testing::step(&hub).await;
    let mut server = hub.subscribe_server();
    server.mark_unchanged();
    let mut clients = hub.subscribe_clients();
    clients.mark_unchanged();
    crate::jobs::testing::step(&hub).await;
    assert!(!server.has_changed().unwrap());
    list_project(&hub, false);
    crate::jobs::testing::step(&hub).await;
    assert_eq!(
        crate::jobs::testing::job_blocked(&hub, &job),
        Some("no longer allowed by its lane")
    );
    assert!(server.has_changed().unwrap());
    assert!(!clients.has_changed().unwrap());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn the_lane_s_reason_lasts_while_nodes_are_full_and_goes_with_its_nodes() {
    let dir = scratch("placement-runner-sticky");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    // Its lane may use only a node that is not there; another runner's, any node.
    confine(&hub, &["0123456789abcdef0123456789abcdef"], &[]);
    add_runner(&hub, &key, "other", 43, crate::policy::Class::Normal);
    ready_relay(&hub, &key);
    let mut node = ready_node(addr, &hub, 16384).await;
    crate::ops::set_ceiling(&hub, "u", &node.id, Some(1)).unwrap();
    let job = submit(addr, &key, job_body(1, None, 30), None).await;
    crate::jobs::testing::step(&hub).await;
    let blocked = || crate::jobs::testing::job_blocked(&hub, &job);
    assert_eq!(blocked(), Some("its lane's allowed nodes"));
    // The other runner's request fills the node: the reason stays its lane's nodes.
    let ticket = queue_for(addr, &key, 2, "other").await;
    accept_ticket(addr, &key, &ticket, &mut node).await;
    crate::jobs::testing::step(&hub).await;
    assert_eq!(blocked(), Some("its lane's allowed nodes"));
    // Free to use the node's pool, it merely finds the node full.
    confine(&hub, &[], &["ci"]);
    crate::jobs::testing::step(&hub).await;
    assert_eq!(blocked(), None);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A lane's work goes to the union of what it selects: a node in no pool at all, selected as
/// its implicit pool, beside the members of a pool.
#[tokio::test]
async fn a_lane_s_work_goes_to_the_members_of_the_pools_and_nodes_it_selects() {
    let dir = scratch("placement-union");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    // The idle node is in no pool at all; the others are busier, in `trusted`.
    let mut idle = ready_node(addr, &hub, 16384).await;
    hub.db.set_pools(&idle.id, &[], "u", now_secs()).unwrap();
    let mut busy = loaded_node(addr, &hub, 16384, Some(400)).await;
    let mut busier = loaded_node(addr, &hub, 16384, Some(800)).await;
    for node in [&busy.id, &busier.id] {
        hub.db
            .set_pools(node, &["trusted".into()], "u", now_secs())
            .unwrap();
    }
    // The pool alone: the least loaded of its members, never the idle node.
    confine(&hub, &[], &["trusted"]);
    let job = submit(addr, &key, job_body(1, None, 30), None).await;
    assert_eq!(next_start(&mut busy).await.job, job);
    idle.quiet(Duration::from_millis(100)).await;
    // The pool and the node: the idle node, outside every pool, joins and goes first.
    confine(&hub, &[&idle.id], &["trusted"]);
    let job = submit(addr, &key, job_body(2, None, 30), None).await;
    assert_eq!(next_start(&mut idle).await.job, job);
    busier.quiet(Duration::from_millis(100)).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A runner lane selecting nothing gets no work, its requests and queued jobs saying so, until
/// it selects something.
#[tokio::test]
async fn a_lane_selecting_nothing_gets_no_work_and_says_so() {
    let dir = scratch("placement-empty");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let mut node = ready_node(addr, &hub, 16384).await;
    confine(&hub, &[], &[]);
    let ticket = queue(addr, &key, 1).await;
    wait_reason(&hub, "its lane selects no pool or node").await;
    node.quiet(Duration::from_millis(100)).await;
    confine(&hub, &[], &["ci"]);
    accept_ticket(addr, &key, &ticket, &mut node).await;
    confine(&hub, &[], &[]);
    let job = submit(addr, &key, job_body(2, None, 30), None).await;
    crate::jobs::testing::step(&hub).await;
    assert_eq!(
        crate::jobs::testing::job_blocked(&hub, &job),
        Some("its lane selects no pool or node")
    );
    node.quiet(Duration::from_millis(100)).await;
    confine(&hub, &[], &["ci"]);
    crate::jobs::testing::step(&hub).await;
    assert_eq!(next_start(&mut node).await.job, job);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_lane_s_requests_go_only_to_nodes_it_may_use() {
    let dir = scratch("placement-runner-request");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let mut idle = ready_node(addr, &hub, 16384).await;
    // Both trusted, the busier would go last anyway; the idle one is not trusted.
    let mut busy = loaded_node(addr, &hub, 16384, Some(400)).await;
    let mut trusted = loaded_node(addr, &hub, 16384, Some(100)).await;
    for node in [&busy.id, &trusted.id] {
        hub.db
            .set_pools(node, &["ci".into(), "trusted".into()], "u", now_secs())
            .unwrap();
    }
    // No node is in its pool: the request waits for one.
    confine(&hub, &[], &["nowhere"]);
    let ticket = queue(addr, &key, 1).await;
    wait_reason(&hub, "its lane's allowed nodes").await;
    confine(&hub, &[], &["trusted"]);
    accept_ticket(addr, &key, &ticket, &mut trusted).await;
    idle.quiet(Duration::from_millis(100)).await;
    busy.quiet(Duration::from_millis(100)).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_lane_s_job_leaves_a_reservation_on_a_node_it_may_no_longer_use() {
    let dir = scratch("placement-runner-job");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let mut wrong = ready_node(addr, &hub, 16384).await;
    let (admission, grant) = admitted(addr, &key, &mut wrong, 1).await;
    let mut right = ready_node(addr, &hub, 16384).await;
    confine(&hub, &[&right.id], &[]);
    let body = job_body(2, Some(&grant.reservation), 30);
    let job = submit(addr, &key, body, Some(&admission)).await;
    assert_eq!(
        wrong.job().await,
        HubJobMsg::Release {
            reservation: grant.reservation
        }
    );
    let start = next_start(&mut right).await;
    assert_eq!(start.job, job);
    assert_eq!(start.reservation, None);
    std::fs::remove_dir_all(&dir).unwrap();
}
