//! Project placement over the client and node protocols.

use super::capacity::ready_relay;
use super::*;

/// Submit `body` as `key`'s relay, on `admission` if any: the job's ID.
async fn submit(addr: SocketAddr, key: &str, mut body: Value, admission: Option<&str>) -> String {
    if let Some(admission) = admission {
        body["admission"] = json!(admission);
    }
    let reply = api(addr, "POST", "/v1/jobs", Some(key), Some(body)).await;
    assert_eq!(reply.status, 201, "{reply:?}");
    reply.json::<JobView>().id
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
        });
    }
    hub.db
        .set_capacity_policy(&policy, "u", now_secs())
        .unwrap();
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
    list_project(&hub, true);
    crate::jobs::testing::step(&hub).await;
    assert_eq!(next_start(&mut node).await.job, job);
    std::fs::remove_dir_all(&dir).unwrap();
}
