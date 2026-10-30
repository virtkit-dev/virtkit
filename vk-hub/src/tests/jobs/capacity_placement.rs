//! Project placement over the client and node protocols.

use super::capacity::{
    accept_ticket, add_runner, queue, queue_for, ready_relay, take_job, wait_reason,
};
use super::*;
use crate::policy::PlacementRule;

/// Give [`spec`]'s project, in tenant `tests`, the placement `rules`.
fn rules(hub: &Hub, rules: Vec<PlacementRule>) {
    let mut policy = hub.db.capacity_policy().unwrap();
    let project = policy
        .tenants
        .get_mut("tests")
        .unwrap()
        .projects
        .iter_mut()
        .find(|p| p.id == PROJECT_ID)
        .unwrap();
    project.placement_rules = rules;
    hub.db
        .set_capacity_policy(&policy, "u", now_secs())
        .unwrap();
}

fn rule(branches: &[&str], nodes: &[&str], pools: &[&str]) -> PlacementRule {
    PlacementRule {
        branches: branches.iter().map(|s| (*s).into()).collect(),
        nodes: nodes.iter().map(|s| (*s).into()).collect(),
        pools: pools.iter().map(|s| (*s).into()).collect(),
    }
}

/// Let every mapped runner use only `nodes` and nodes in `pools`.
fn confine(hub: &Hub, nodes: &[&str], pools: &[&str]) {
    let mut policy = hub.db.capacity_policy().unwrap();
    for r in &mut policy.runners {
        r.nodes = nodes.iter().map(|s| (*s).into()).collect();
        r.pools = pools.iter().map(|s| (*s).into()).collect();
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
async fn a_branch_rule_picks_the_machine_of_its_branches_alone() {
    let dir = scratch("placement-branch-routing");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let mut ordinary = ready_node(addr, &hub, 16384).await;
    let mut release = ready_node(addr, &hub, 16384).await;
    rules(
        &hub,
        vec![rule(&["main", "release/**"], &[&release.id], &[])],
    );
    for (n, branch) in [(1, "main"), (2, "release/x")] {
        let job = submit(addr, &key, on_branch(job_body(n, None, 30), branch), None).await;
        assert_eq!(next_start(&mut release).await.job, job, "{branch}");
    }
    // No rule applies to `feature`: it goes to the less loaded node, `release` holding two jobs.
    let job = submit(
        addr,
        &key,
        on_branch(job_body(3, None, 30), "feature"),
        None,
    )
    .await;
    assert_eq!(next_start(&mut ordinary).await.job, job);
    release.quiet(Duration::from_millis(100)).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_reservation_on_a_disallowed_node_is_released_for_an_allowed_one() {
    let dir = scratch("placement-reservation");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let mut wrong = ready_node(addr, &hub, 16384).await;
    let (admission, grant) = admitted(addr, &key, &mut wrong, 1).await;
    let mut right = ready_node(addr, &hub, 16384).await;
    hub.db
        .set_pools(&right.id, &["ci".into(), "trusted".into()], "u", now_secs())
        .unwrap();
    // Every rule that applies allows it: a trusted pool, and the one node.
    rules(
        &hub,
        vec![rule(&[], &[], &["trusted"]), rule(&[], &[&right.id], &[])],
    );
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
    assert_eq!(crate::jobs::testing::reservations(&hub), 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn rules_intersect_and_a_job_no_node_satisfies_ends_saying_why() {
    let dir = scratch("placement-branch");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let mut wrong = ready_node(addr, &hub, 16384).await;
    let (admission, grant) = admitted(addr, &key, &mut wrong, 1).await;
    let mut right = ready_node(addr, &hub, 16384).await;
    // Every job to one node, `main` jobs to another: no node allows a `main` job.
    rules(
        &hub,
        vec![
            rule(&[], &[&wrong.id], &[]),
            rule(&["main"], &[&right.id], &[]),
        ],
    );
    let body = on_branch(job_body(2, Some(&grant.reservation), 1), "main");
    let job = submit(addr, &key, body, Some(&admission)).await;
    assert_eq!(
        wrong.job().await,
        HubJobMsg::Release {
            reservation: grant.reservation
        }
    );
    let ended = view_until(addr, &key, &job, |v| v.state == JobState::Finished).await;
    let result = ended.result.unwrap();
    assert_eq!(result.failure, Some(FailureClass::NoCapacity));
    assert_eq!(
        result.message.as_deref(),
        Some("no node took it within its placement window (project placement rules)")
    );
    assert_eq!(crate::jobs::testing::reservations(&hub), 0);
    right.quiet(Duration::from_millis(100)).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_pool_rule_holds_jobs_to_nodes_in_the_pool() {
    let dir = scratch("placement-pool");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let mut idle = ready_node(addr, &hub, 16384).await;
    // Busier, so it would go last but for the rule.
    let mut trusted = loaded_node(addr, &hub, 16384, Some(400)).await;
    hub.db
        .set_pools(
            &trusted.id,
            &["ci".into(), "trusted".into()],
            "u",
            now_secs(),
        )
        .unwrap();
    rules(&hub, vec![rule(&[], &[], &["trusted"])]);
    let job = submit(addr, &key, job_body(1, None, 30), None).await;
    assert_eq!(next_start(&mut trusted).await.job, job);
    idle.quiet(Duration::from_millis(100)).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Without rules the job would go to the warm node, releasing its reservation, as in
/// `a_job_goes_to_a_lightly_loaded_node_holding_its_image` in `tests/jobs.rs`.
#[tokio::test]
async fn image_affinity_cannot_escape_project_rules() {
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
    // A job reserved on another node, which alone the rules allow, stays there.
    let mut cold = loaded_node(addr, &hub, 16384, Some(0)).await;
    let (admission, grant) = admitted(addr, &key, &mut cold, 2).await;
    rules(&hub, vec![rule(&[], &[&cold.id], &[])]);
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
    // Submitted while listed, with no node to take it yet; then its tenant drops the project.
    let job = submit(addr, &key, job_body(1, None, 2), None).await;
    list_project(&hub, false);
    let mut node = ready_node(addr, &hub, 16384).await;
    crate::jobs::testing::step(&hub).await;
    assert_eq!(
        crate::jobs::testing::job_blocked(&hub, &job),
        Some("project no longer listed for its tenant")
    );
    let ended = view_until(addr, &key, &job, |v| v.state == JobState::Finished).await;
    assert_eq!(
        ended.result.unwrap().message.as_deref(),
        Some(
            "no node took it within its placement window (project no longer listed for its tenant)"
        )
    );
    node.quiet(Duration::from_millis(100)).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// List [`spec`]'s project for tenant `tests`, or with `listed` false no longer.
fn list_project(hub: &Hub, listed: bool) {
    let mut policy = hub.db.capacity_policy().unwrap();
    let tests = policy.tenants.get_mut("tests").unwrap();
    tests.projects.retain(|p| p.id != PROJECT_ID);
    if listed {
        tests.projects.push(crate::policy::Project {
            gitlab: "gl".into(),
            id: PROJECT_ID,
            production_branches: vec![],
            placement_rules: vec![],
        });
    }
    hub.db
        .set_capacity_policy(&policy, "u", now_secs())
        .unwrap();
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
        Some("project no longer listed for its tenant")
    );
    // Its server's page gives it as its runner's reason, with no request of the runner waiting.
    let snapshot = crate::jobs::arbitration_snapshot(&hub).unwrap();
    let view = &snapshot[&("gl".to_string(), 42)];
    assert_eq!(
        (view.waiting, view.jobs, view.reason),
        (0, 1, Some("project no longer listed for its tenant"))
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
        Some("project no longer listed for its tenant")
    );
    assert!(server.has_changed().unwrap());
    assert!(!clients.has_changed().unwrap());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn the_rules_reason_lasts_while_nodes_are_full_and_goes_with_the_rules() {
    let dir = scratch("placement-sticky");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    ready_relay(&hub, &key);
    let mut node = ready_node(addr, &hub, 16384).await;
    crate::ops::set_ceiling(&hub, "u", &node.id, Some(1)).unwrap();
    // Only a node that is not there may take the project's jobs.
    rules(
        &hub,
        vec![rule(&[], &["0123456789abcdef0123456789abcdef"], &[])],
    );
    let job = submit(addr, &key, job_body(1, None, 30), None).await;
    crate::jobs::testing::step(&hub).await;
    let blocked = || crate::jobs::testing::job_blocked(&hub, &job);
    assert_eq!(blocked(), Some("project placement rules"));
    // A runner request, which rules do not restrict, fills the node: the reason stays the rules.
    let ticket = queue(addr, &key, 2).await;
    accept_ticket(addr, &key, &ticket, &mut node).await;
    crate::jobs::testing::step(&hub).await;
    assert_eq!(blocked(), Some("project placement rules"));
    // Without rules, the node is merely full.
    rules(&hub, Vec::new());
    crate::jobs::testing::step(&hub).await;
    assert_eq!(blocked(), None);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn the_runner_s_reason_lasts_while_nodes_are_full_and_goes_with_its_nodes() {
    let dir = scratch("placement-runner-sticky");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    // Its runner may use only a node that is not there; another runner, any node.
    confine(&hub, &["0123456789abcdef0123456789abcdef"], &[]);
    add_runner(&hub, &key, "other", 43, crate::policy::Class::Normal);
    ready_relay(&hub, &key);
    let mut node = ready_node(addr, &hub, 16384).await;
    crate::ops::set_ceiling(&hub, "u", &node.id, Some(1)).unwrap();
    let job = submit(addr, &key, job_body(1, None, 30), None).await;
    crate::jobs::testing::step(&hub).await;
    let blocked = || crate::jobs::testing::job_blocked(&hub, &job);
    assert_eq!(blocked(), Some("its runner's allowed nodes"));
    // The other runner's request fills the node: the reason stays its runner's nodes.
    let ticket = queue_for(addr, &key, 2, "other").await;
    accept_ticket(addr, &key, &ticket, &mut node).await;
    crate::jobs::testing::step(&hub).await;
    assert_eq!(blocked(), Some("its runner's allowed nodes"));
    // Free to use any node, it merely finds the node full.
    confine(&hub, &[], &[]);
    crate::jobs::testing::step(&hub).await;
    assert_eq!(blocked(), None);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The node its runner may use has room, but its project's rules allow only another: the rules
/// are the reason, until they go, though the runner still may not use the other node.
#[tokio::test]
async fn the_rules_reason_goes_with_the_rules_under_a_runner_s_nodes() {
    let dir = scratch("placement-runner-rules");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(30)).await;
    let key = jobs_key(&hub);
    add_runner(&hub, &key, "other", 43, crate::policy::Class::Normal);
    ready_relay(&hub, &key);
    let mut full = ready_node(addr, &hub, 16384).await;
    crate::ops::set_ceiling(&hub, "u", &full.id, Some(1)).unwrap();
    let ticket = queue_for(addr, &key, 2, "other").await;
    let grant = accept_ticket(addr, &key, &ticket, &mut full).await;
    take_job(addr, &key, &ticket, &grant).await;
    let mut usable = ready_node(addr, &hub, 16384).await;
    crate::ops::set_ceiling(&hub, "u", &usable.id, Some(1)).unwrap();
    // Runner 43 too, but its tickets go to `usable` alone, which it may use.
    confine(&hub, &[&usable.id], &[]);
    rules(&hub, vec![rule(&[], &[&full.id], &[])]);
    let job = submit(addr, &key, job_body(1, None, 30), None).await;
    crate::jobs::testing::step(&hub).await;
    let blocked = || crate::jobs::testing::job_blocked(&hub, &job);
    assert_eq!(blocked(), Some("project placement rules"));
    let ticket = queue_for(addr, &key, 3, "other").await;
    accept_ticket(addr, &key, &ticket, &mut usable).await;
    crate::jobs::testing::step(&hub).await;
    assert_eq!(blocked(), Some("project placement rules"));
    rules(&hub, Vec::new());
    crate::jobs::testing::step(&hub).await;
    assert_eq!(blocked(), None);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_runner_s_requests_go_only_to_nodes_it_may_use() {
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
    wait_reason(&hub, "its runner's allowed nodes").await;
    confine(&hub, &[], &["trusted"]);
    accept_ticket(addr, &key, &ticket, &mut trusted).await;
    idle.quiet(Duration::from_millis(100)).await;
    busy.quiet(Duration::from_millis(100)).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_runner_s_job_leaves_a_reservation_on_a_node_it_may_not_use() {
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
