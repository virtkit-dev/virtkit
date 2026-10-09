//! Tools definitions on the hub: added from a build context, issued to nodes that speak
//! protocol version 4, served only to a node building them, and audited.

use vk_hub_proto::{CommandAck, Operation, Outcome, TOOLS, VersionRange};

use super::*;

const V3: VersionRange = VersionRange {
    min: 1,
    max: vk_hub_proto::JOBS,
};
const V4: VersionRange = VersionRange { min: 1, max: TOOLS };

/// A build context in `dir`/`name`, differing by `marker`.
fn context(dir: &std::path::Path, name: &str, marker: &str) -> std::path::PathBuf {
    let ctx = dir.join(name);
    std::fs::create_dir_all(&ctx).unwrap();
    std::fs::write(
        ctx.join("Dockerfile"),
        format!("FROM scratch AS tools\n# {marker}\n"),
    )
    .unwrap();
    ctx
}

/// The headers node `node_id` sends to download tools `sha256`, signed by `key` at `at`.
fn tools_headers(
    key: &Ed25519KeyPair,
    node_id: &str,
    sha256: &str,
    at: u64,
) -> Vec<(&'static str, String)> {
    let digest = vk_hub_proto::from_hex_lower::<{ vk_hub_proto::SHA256_LEN }>(sha256).unwrap();
    let message = vk_hub_proto::tools_download_message(
        node_id,
        &digest,
        at,
        vk_hub_proto::Channel::Plaintext,
    );
    vec![
        (vk_hub_proto::NODE_HEADER, node_id.to_string()),
        (vk_hub_proto::TIME_HEADER, at.to_string()),
        (
            vk_hub_proto::SIGNATURE_HEADER,
            vk_hub_proto::to_hex(key.sign(&message).as_ref()),
        ),
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn a_definition_is_held_once_by_its_digest_and_kept_private() {
    let (dir, _, hub) = start_releases("tools-add", None).await;
    let ctx = context(&dir, "ctx", "a");
    let added = crate::tools::add(&hub, "uid 0", &ctx, "2026.10").unwrap();
    assert_eq!(added.row.files, 1);
    let held = dir.join("tools").join(&added.sha256);
    let tar = std::fs::read(&held).unwrap();
    assert_eq!(tar.len() as u64, added.row.size);
    assert_eq!(crate::tools::pack(&ctx).unwrap().tar, tar);
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!((mode(&held), mode(&dir.join("tools"))), (0o600, 0o700));
    }
    // Again as the same version: the one held, its lost tar restored; as another, refused.
    std::fs::remove_file(&held).unwrap();
    assert_eq!(
        crate::tools::add(&hub, "uid 0", &ctx, "2026.10").unwrap(),
        added
    );
    assert_eq!(std::fs::read(&held).unwrap(), tar);
    let err = crate::tools::add(&hub, "uid 0", &ctx, "2026.11").unwrap_err();
    assert!(format!("{err:#}").contains("already held"), "{err:#}");
    let err = crate::tools::add(&hub, "uid 0", &ctx, "a b").unwrap_err();
    assert!(format!("{err:#}").contains("is not a version"), "{err:#}");
    assert!(crate::tools::remove(&hub, "uid 0", &added.sha256).unwrap());
    assert!(!held.exists());
    // Nothing is left of the adds but what they published, and that is gone too.
    let left: Vec<_> = std::fs::read_dir(dir.join("tools")).unwrap().collect();
    assert!(left.is_empty(), "{left:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A definition is served only to a node with a build of it under way, signing for it under
/// the tools label; a release download's signature fetches nothing here.
#[tokio::test(flavor = "multi_thread")]
async fn a_definition_is_served_only_to_a_node_building_it_that_signs_for_it() {
    let (dir, addr, hub) = start_releases("tools-download", None).await;
    let added = crate::tools::add(&hub, "uid 0", &context(&dir, "ctx", "a"), "2026.10").unwrap();
    let sha = added.sha256.clone();
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    let path = format!("{}{sha}", vk_hub_proto::TOOLS_PATH);
    let signed = |key: &Ed25519KeyPair, at| tools_headers(key, &node_id, &sha, at);
    assert_eq!(
        get_with(addr, &path, &signed(&key, now_secs())).await.0,
        403
    );

    let command = ops::tools(&hub, "uid 0", &node_id, &sha[..8]).unwrap();
    assert_eq!(
        command.op,
        Operation::Tools {
            version: "2026.10".into(),
            sha256: sha.clone(),
            size: added.row.size,
        }
    );
    let (status, body) = get_with(addr, &path, &signed(&key, now_secs())).await;
    assert_eq!(status, 200);
    assert_eq!(body, std::fs::read(dir.join("tools").join(&sha)).unwrap());
    assert_eq!(get_with(addr, &path, &[]).await.0, 401);
    assert_eq!(
        get_with(addr, &path, &signed(&keypair(), now_secs()))
            .await
            .0,
        403
    );
    let stale = now_secs() - vk_hub_proto::DOWNLOAD_SKEW_SECS - 5;
    assert_eq!(get_with(addr, &path, &signed(&key, stale)).await.0, 401);
    // A release download's signature, for the same digest, is not one for tools.
    let release_signed = download_headers(
        &key,
        &node_id,
        &sha,
        now_secs(),
        vk_hub_proto::Channel::Plaintext,
    );
    assert_eq!(get_with(addr, &path, &release_signed).await.0, 403);
    // Nor is a tools signature one for a release of that digest.
    let as_release = format!("{}{sha}", vk_hub_proto::RELEASE_PATH);
    assert_eq!(
        get_with(addr, &as_release, &signed(&key, now_secs()))
            .await
            .0,
        403
    );

    let err = crate::tools::remove(&hub, "uid 0", &sha).unwrap_err();
    assert!(format!("{err:#}").contains("still has to build"), "{err:#}");
    let done = CommandAck {
        id: command.id,
        outcome: Outcome::Done,
    };
    assert!(hub.db.record_ack(&node_id, &done, now_secs()).unwrap());
    assert_eq!(
        get_with(addr, &path, &signed(&key, now_secs())).await.0,
        403
    );
    assert!(crate::tools::remove(&hub, "uid 0", &sha).unwrap());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A tools build goes to a node only in a session at version 4: one at version 3 is sent
/// nothing, and the hub refuses to issue another to it once it has connected so.
#[tokio::test(flavor = "multi_thread")]
async fn a_tools_build_goes_only_to_a_node_speaking_version_4() {
    let (dir, addr, hub) = start_releases("tools-session", None).await;
    let sha = crate::tools::add(&hub, "uid 0", &context(&dir, "ctx", "a"), "2026.10")
        .unwrap()
        .sha256;
    let key = keypair();
    let node_id = enrolled(addr, &hub, &key).await;
    // Issued on trust before the node's first session.
    let command = ops::tools(&hub, "uid 0", &node_id, &sha).unwrap();

    let mut ws = dial(addr).await;
    let twist = Twist {
        versions: Some(V3),
        ..Twist::default()
    };
    assert!(matches!(
        open_with(&mut ws, &node_id, &"41".repeat(16), &key, twist).await,
        HubMsg::Welcome { .. }
    ));
    send(&mut ws, &applied(None)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(1500), receive(&mut ws))
            .await
            .is_err()
    );
    let err = ops::tools(&hub, "uid 0", &node_id, &sha).unwrap_err();
    assert!(format!("{err:#}").contains("update its vk"), "{err:#}");
    ws.close(None).await.unwrap();

    let mut ws = dial(addr).await;
    let twist = Twist {
        versions: Some(V4),
        ..Twist::default()
    };
    assert!(matches!(
        open_with(&mut ws, &node_id, &"42".repeat(16), &key, twist).await,
        HubMsg::Welcome { .. }
    ));
    send(&mut ws, &applied(None)).await;
    assert_eq!(receive(&mut ws).await, HubMsg::Command(command.clone()));
    // The node's progress is recorded and audited phase by phase.
    let progress = |phase, message: Option<&str>| {
        NodeMsg::Report(vk_hub_proto::Report {
            state: Some(vk_hub_proto::NodeState::Ready),
            tools: Some(vk_hub_proto::ToolsProgress {
                command: command.id.clone(),
                version: "2026.10".into(),
                sha256: sha.clone(),
                phase,
                message: message.map(str::to_string),
                log: vec!["step 3/4\u{1b}[2J".into()],
            }),
            ..vk_hub_proto::Report::default()
        })
    };
    send(&mut ws, &progress(vk_hub_proto::ToolsPhase::Building, None)).await;
    eventually(|| {
        hub.db
            .node(&node_id)
            .unwrap()
            .unwrap()
            .report
            .and_then(|r| r.tools)
            .is_some()
    })
    .await;
    tokio::time::sleep(crate::server::HEARTBEAT).await;
    send(
        &mut ws,
        &progress(vk_hub_proto::ToolsPhase::Failed, Some("no stage tools")),
    )
    .await;
    eventually(|| {
        hub.db
            .node(&node_id)
            .unwrap()
            .unwrap()
            .report
            .and_then(|r| r.tools)
            .is_some_and(|t| t.phase == vk_hub_proto::ToolsPhase::Failed)
    })
    .await;
    let stored = hub.db.node(&node_id).unwrap().unwrap().report.unwrap();
    assert_eq!(stored.tools.unwrap().log, ["step 3/4[2J"]);
    let events: Vec<String> = hub
        .db
        .audits(Some(&node_id), 100)
        .unwrap()
        .into_iter()
        .map(|r| r.event)
        .collect();
    let short = crate::store::short(&sha);
    for want in [
        format!("uid 0 issued tools 2026.10 ({short})"),
        format!("tools 2026.10 ({short}): building"),
        format!("tools 2026.10 ({short}): failed: no stage tools"),
    ] {
        assert!(
            events.iter().any(|e| e.starts_with(&want)),
            "{want}: {events:?}"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Every node at once: those that cannot take the build, or have no need of it, are skipped
/// with the reason.
#[tokio::test(flavor = "multi_thread")]
async fn a_tools_build_for_every_node_skips_those_that_cannot_or_need_not() {
    let (dir, _, hub) = start_releases("tools-all", None).await;
    let sha = crate::tools::add(&hub, "uid 0", &context(&dir, "ctx", "a"), "2026.10")
        .unwrap()
        .sha256;
    let [old, monitored, current, building, fresh, ready] = [
        "a-old",
        "b-monitored",
        "c-current",
        "d-building",
        "e-fresh",
        "f-ready",
    ]
    .map(|name| enroll_as(&hub, name));
    let connect = |id: &str, version| {
        hub.db
            .record_session(id, "inc", version, now_secs(), || true)
            .unwrap();
    };
    connect(&old, vk_hub_proto::JOBS);
    connect(&monitored, 1);
    for id in [&current, &building, &ready] {
        connect(id, TOOLS);
    }
    let mut inventory = Inventory {
        hostname: "c-current".into(),
        ..Inventory::default()
    };
    inventory.versions.tools = Some(vk_hub_proto::ToolsInstalled {
        sha256: sha.clone(),
        version: "2026.10".into(),
        tools: Default::default(),
        in_use: true,
    });
    hub.db
        .record_inventory(&current, inventory, true, now_secs())
        .unwrap();
    ops::tools(&hub, "uid 0", &building, &sha).unwrap();

    let issued = ops::tools_all(&hub, "uid 0", &sha[..8]).unwrap();
    let got: Vec<(&str, Option<&str>)> = issued
        .iter()
        .map(|n| (n.hostname.as_str(), n.skipped.as_deref()))
        .collect();
    assert_eq!(
        got,
        [
            (
                "a-old",
                Some("speaks protocol version 3, and tools take version 4: update its vk")
            ),
            (
                "b-monitored",
                Some("speaks protocol version 1, and tools take version 4: update its vk")
            ),
            ("c-current", Some("has these tools current already")),
            ("d-building", Some("is building these tools already")),
            ("e-fresh", None),
            ("f-ready", None),
        ]
    );
    assert!(
        issued
            .iter()
            .filter(|n| n.skipped.is_none())
            .all(|n| n.command.is_some())
    );
    assert_eq!(
        hub.db.pending_commands(&fresh, now_secs()).unwrap().len(),
        1
    );
    // A command is no way to issue one: it names a definition the hub holds.
    let err = ops::command(
        &hub,
        "uid 0",
        &ready,
        Operation::Tools {
            version: "x".into(),
            sha256: "cd".repeat(32),
            size: 1,
        },
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("vk-hub nodes tools"), "{err:#}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `vk-hub nodes` notes a node's tools: those current, and a failed build with its output.
#[test]
fn the_nodes_table_notes_the_tools_and_a_failed_build() {
    let sha = "ab".repeat(32);
    let view = ops::NodeView {
        id: "11".repeat(16),
        hostname: "ci-1".into(),
        tools: Some(vk_hub_proto::ToolsInstalled {
            sha256: sha.clone(),
            version: "2026.10".into(),
            tools: [
                ("git".to_string(), "git version 2.49.0".to_string()),
                ("gitlab-runner".to_string(), "Version: 19.1.0".to_string()),
            ]
            .into(),
            in_use: false,
        }),
        report: Some(vk_hub_proto::Report {
            tools: Some(vk_hub_proto::ToolsProgress {
                command: "22".repeat(16),
                version: "2026.11".into(),
                sha256: "cd".repeat(32),
                phase: vk_hub_proto::ToolsPhase::Failed,
                message: Some("the build failed".into()),
                log: vec!["ERROR: no stage tools".into()],
            }),
            ..vk_hub_proto::Report::default()
        }),
        ..ops::NodeView::default()
    };
    let shown = render_nodes(&[view], now_secs());
    for want in [
        "ci-1: tools 2026.10 (abababababab): git version 2.49.0, Version: 19.1.0; not in use: \
         [executor] tools_dir names another directory",
        "ci-1: tools 2026.11 (cdcdcdcdcdcd): failed: the build failed",
        "    ERROR: no stage tools",
    ] {
        assert!(shown.contains(want), "{want}\n{shown}");
    }
}

#[test]
fn tools_arguments_parse() {
    use clap::Parser;
    let parse = |args: &[&str]| Cli::try_parse_from([&["vk-hub"], args].concat());
    assert!(parse(&["tools", "add", "ctx", "--version", "1"]).is_ok());
    assert!(parse(&["tools", "add", "ctx"]).is_err());
    assert!(parse(&["nodes", "tools", "abcdabcd", "--tools", "12345678"]).is_ok());
    assert!(parse(&["nodes", "tools", "--all", "--tools", "12345678"]).is_ok());
    assert!(parse(&["nodes", "tools", "--tools", "12345678"]).is_err());
    assert!(parse(&["nodes", "tools", "abcdabcd", "--all", "--tools", "12345678"]).is_err());
}
