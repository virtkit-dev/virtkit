//! The hub settling its jobs before it hands over to a release ([`crate::update::settle`]): it
//! takes no new job, and goes on only once no job is left that a restart would lose.

use super::*;

/// A job queued with no node to start on keeps the hand-over from going on, and the hub takes
/// no new job meanwhile; once it serves as before, it does.
#[tokio::test(flavor = "multi_thread")]
async fn a_hand_over_waits_for_the_jobs_queued_and_takes_none_meanwhile() {
    let dir = scratch("handover-queued");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let queued = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(1, None, 30)),
    )
    .await;
    assert_eq!(queued.status, 201, "{queued:?}");
    assert_eq!(hub.dispatch.waiting(), (1, 0));
    let e = crate::update::settle(&hub).await.unwrap_err();
    assert!(
        format!("{e:#}").contains("jobs still waited for a node"),
        "{e:#}"
    );
    let refused = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(2, None, 30)),
    )
    .await;
    assert_eq!(refused.status, 503, "{refused:?}");
    assert!(
        refused
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("retry-after") && v == "5"),
        "{refused:?}"
    );
    hub.handover.resume();
    let taken = api(
        addr,
        "POST",
        "/v1/jobs",
        Some(&key),
        Some(job_body(2, None, 30)),
    )
    .await;
    assert_eq!(taken.status, 201, "{taken:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// With no job waiting, the hand-over goes on, holding off job messages and placing until it
/// is done with.
#[tokio::test(flavor = "multi_thread")]
async fn a_settled_hub_holds_off_job_messages_until_it_hands_over() {
    let dir = scratch("handover-settled");
    let (addr, hub) = start_jobs(&dir, Duration::from_secs(60)).await;
    let key = jobs_key(&hub);
    let quiet = crate::update::settle(&hub).await.unwrap();
    assert!(hub.handover.intake_paused() && hub.handover.placing_paused());
    let turn = tokio::time::timeout(Duration::from_millis(200), hub.handover.turn()).await;
    assert!(turn.is_err(), "a job message was handled while settled");
    // A job submitted meanwhile is answered at once, to retry, rather than held.
    let refused = tokio::time::timeout(
        Duration::from_secs(5),
        api(
            addr,
            "POST",
            "/v1/jobs",
            Some(&key),
            Some(job_body(1, None, 30)),
        ),
    )
    .await
    .expect("a submission waited on the hand-over");
    assert_eq!(refused.status, 503, "{refused:?}");
    drop(quiet);
    hub.handover.resume();
    let _turn = tokio::time::timeout(Duration::from_secs(5), hub.handover.turn())
        .await
        .unwrap();
    assert!(!hub.handover.intake_paused() && !hub.handover.placing_paused());
    std::fs::remove_dir_all(&dir).unwrap();
}
