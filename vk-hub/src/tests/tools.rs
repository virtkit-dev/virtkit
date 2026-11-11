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

    let command = ops::tools(&hub, "uid 0", &node_id, Some(&sha[..8])).unwrap();
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
    let command = ops::tools(&hub, "uid 0", &node_id, Some(&sha)).unwrap();

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
    let err = ops::tools(&hub, "uid 0", &node_id, Some(&sha)).unwrap_err();
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
            .record_session(id, "inc", version, None, now_secs(), || true)
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
        files: Default::default(),
        egress: None,
        check: None,
    });
    hub.db
        .record_inventory(&current, inventory, true, now_secs())
        .unwrap();
    ops::tools(&hub, "uid 0", &building, Some(&sha)).unwrap();

    let issued = ops::tools_all(&hub, "uid 0", Some(&sha[..8])).unwrap();
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
            files: Default::default(),
            egress: None,
            check: None,
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

/// The hub keeps every node it can reach on the tools its `tools` setting names: each one that
/// lacks them is asked at once, a failed build is retried after a while, and an operator's
/// build of other tools is refused unless the setting leaves the node alone.
#[tokio::test(flavor = "multi_thread")]
async fn nodes_are_kept_on_the_tools_the_setting_names() {
    let (dir, _, hub) = start_releases("tools-deploy", None).await;
    let a = crate::tools::add(&hub, "uid 0", &context(&dir, "a", "a"), "2026.10")
        .unwrap()
        .sha256;
    let b = crate::tools::add(&hub, "uid 0", &context(&dir, "b", "b"), "2026.11")
        .unwrap()
        .sha256;
    let [old, alone, current, ready] =
        ["a-old", "b-alone", "c-current", "d-ready"].map(|name| enroll_as(&hub, name));
    let inventory = |id: &str, host: &str, tools: Option<&str>| {
        let mut inventory = Inventory {
            hostname: host.into(),
            hub_settings: true,
            ..Inventory::default()
        };
        inventory.versions.tools = tools.map(|sha| vk_hub_proto::ToolsInstalled {
            sha256: sha.into(),
            version: "x".into(),
            tools: Default::default(),
            in_use: true,
            files: Default::default(),
            egress: None,
            check: None,
        });
        hub.db
            .record_inventory(id, inventory, true, now_secs())
            .unwrap();
    };
    for (id, host, version) in [
        (&old, "a-old", vk_hub_proto::JOBS),
        (&alone, "b-alone", TOOLS),
        (&current, "c-current", TOOLS),
        (&ready, "d-ready", TOOLS),
    ] {
        hub.db
            .record_session(id, "inc", version, None, now_secs(), || true)
            .unwrap();
        inventory(id, host, (id == &current).then_some(a.as_str()));
    }
    let set = |node: Option<&str>, value: &str| {
        crate::settings::set(
            &hub,
            "uid 0",
            node,
            "tools",
            Some(crate::settings::parse("tools", value).unwrap()),
        )
    };
    assert!(format!("{:#}", set(None, "zz").unwrap_err()).contains("builtin"));
    assert!(format!("{:#}", set(None, "ffffffff").unwrap_err()).contains("no tools"));
    set(None, &a[..8]).unwrap();
    set(Some(&alone), "none").unwrap();
    let layers = hub.db.settings_layers().unwrap();
    assert_eq!(layers.fleet["tools"], serde_json::json!(a), "kept whole");
    // The hub's own: never sent to a node.
    let sent = hub.db.node(&ready).unwrap().unwrap().desired;
    assert!(sent.is_none_or(|d| !d.settings.contains_key("tools")));

    let builtin = crate::tools::builtin().packed.sha256.clone();
    let advance_at = |now: u64| hub.db.advance_tools(now, &builtin, &|_| true).unwrap();
    let advance = || advance_at(now_secs());
    assert_eq!(advance(), (true, vec![ready.clone()]));
    assert_eq!(advance(), (false, Vec::new()), "asked once");
    let command = |id: &str| {
        hub.db
            .pending_commands(id, now_secs())
            .unwrap()
            .into_iter()
            .find(|c| matches!(&c.op, Operation::Tools { sha256, .. } if *sha256 == a))
            .unwrap()
            .id
    };
    let first = command(&ready);
    let note = |id: &str| {
        ops::node_views(&hub)
            .unwrap()
            .into_iter()
            .find(|v| v.id == id)
            .unwrap()
            .tools_deploy
    };
    assert!(
        note(&ready)
            .unwrap()
            .contains("building the CI tools 2026.10")
    );
    assert_eq!(note(&current), None);
    assert_eq!(note(&alone), None);
    assert!(note(&old).unwrap().contains("protocol version 3"));
    let ack = |id: &str, command: &str, outcome| {
        hub.db
            .record_ack(
                id,
                &CommandAck {
                    id: command.to_string(),
                    outcome,
                },
                now_secs(),
            )
            .unwrap();
    };
    ack(
        &ready,
        &first,
        Outcome::Failed {
            message: "vk build failed".into(),
        },
    );
    assert_eq!(advance(), (true, Vec::new()));
    assert_eq!(advance(), (false, Vec::new()), "not tried again at once");
    let shown = note(&ready).unwrap();
    assert!(
        shown.contains("attempt 1 of 5 to build the CI tools 2026.10")
            && shown.contains("failed: vk build failed; the next is due after"),
        "{shown}"
    );
    // A while later it is: its second attempt.
    assert_eq!(
        advance_at(now_secs() + crate::deploy::RETRY_DELAYS_SECS[0] * 6 / 5 + 1),
        (true, vec![ready.clone()])
    );
    let second = command(&ready);
    assert_ne!(second, first);
    assert!(note(&ready).unwrap().contains("attempt 2 of 5"));
    ack(
        &ready,
        &second,
        Outcome::Refused {
            reason: "busy".into(),
        },
    );
    assert_eq!(advance(), (true, Vec::new()));
    assert!(note(&ready).unwrap().contains("attempt 2 of 5"));

    // Other tools than the setting's are refused; the node left alone takes any.
    let err = ops::tools(&hub, "uid 0", &ready, Some(&b)).unwrap_err();
    assert!(
        format!("{err:#}").contains("`tools` setting keeps it"),
        "{err:#}"
    );
    ops::tools(&hub, "uid 0", &alone, Some(&b)).unwrap();
    // Asked for again, by default the setting's: the failure is forgotten.
    let again = ops::tools(&hub, "uid 0", &ready, None).unwrap();
    assert!(matches!(&again.op, Operation::Tools { sha256, .. } if *sha256 == a));
    let shown = note(&ready).unwrap();
    assert!(
        shown.contains("building the CI tools 2026.10") && !shown.contains("attempt"),
        "counted afresh: {shown}"
    );
    assert_eq!(advance(), (false, Vec::new()), "its build is under way");
    ack(&ready, &again.id, Outcome::Done);
    // Followed as the hub's own, until the node reports the tools: never asked for twice.
    assert_eq!(advance(), (true, Vec::new()));
    assert_eq!(advance(), (false, Vec::new()));
    inventory(&ready, "d-ready", Some(&a));
    assert_eq!(advance(), (true, Vec::new()));
    assert_eq!(note(&ready), None);

    // A definition a setting names is kept.
    let err = crate::tools::remove(&hub, "uid 0", &a).unwrap_err();
    assert!(
        format!("{err:#}").contains("names it fleet-wide"),
        "{err:#}"
    );
    // Naming others moves the nodes on; one whose automatic build ends is followed until it
    // reports the tools.
    set(None, &b).unwrap();
    let (_, mut issued) = advance();
    issued.sort();
    let mut want = vec![current.clone(), ready.clone()];
    want.sort();
    assert_eq!(issued, want);
    let built = hub
        .db
        .pending_commands(&current, now_secs())
        .unwrap()
        .into_iter()
        .find(|c| matches!(&c.op, Operation::Tools { .. }))
        .unwrap()
        .id;
    ack(&current, &built, Outcome::Done);
    assert_eq!(advance(), (true, Vec::new()));
    assert!(
        note(&current)
            .unwrap()
            .contains("installed the CI tools 2026.11")
    );
    inventory(&current, "c-current", Some(&b));
    assert_eq!(advance(), (true, Vec::new()));
    assert!(!hub.db.tools_deploys().unwrap().contains_key(&current));
    let events: Vec<String> = hub
        .db
        .audits(Some(&ready), 50)
        .unwrap()
        .into_iter()
        .map(|a| a.event)
        .collect();
    assert!(
        events
            .iter()
            .any(|e| e.starts_with("auto-deploy issued tools 2026.10")),
        "{events:?}"
    );
    assert!(
        events.iter().any(|e| e.contains("failed: vk build failed")),
        "{events:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// An automatic build that keeps failing is retried, later each time, until its attempts are
/// spent; then it waits for an operator, whose build starts the count afresh.
#[tokio::test(flavor = "multi_thread")]
async fn a_failing_build_is_retried_until_its_attempts_are_spent() {
    let (dir, _, hub) = start_releases("tools-retry", None).await;
    let a = crate::tools::add(&hub, "uid 0", &context(&dir, "a", "a"), "2026.10")
        .unwrap()
        .sha256;
    let node = enroll_as(&hub, "n");
    hub.db
        .record_session(&node, "inc", TOOLS, None, now_secs(), || true)
        .unwrap();
    hub.db
        .record_inventory(
            &node,
            Inventory {
                hostname: "n".into(),
                hub_settings: true,
                ..Inventory::default()
            },
            true,
            now_secs(),
        )
        .unwrap();
    crate::settings::set(
        &hub,
        "uid 0",
        None,
        "tools",
        Some(crate::settings::parse("tools", &a).unwrap()),
    )
    .unwrap();
    let builtin = crate::tools::builtin().packed.sha256.clone();
    let advance = |now: u64| hub.db.advance_tools(now, &builtin, &|_| true).unwrap();
    let fail = |now: u64| {
        let command = hub
            .db
            .pending_commands(&node, now)
            .unwrap()
            .into_iter()
            .find(|c| matches!(&c.op, Operation::Tools { .. }))
            .unwrap()
            .id;
        hub.db
            .record_ack(
                &node,
                &CommandAck {
                    id: command,
                    outcome: Outcome::Failed {
                        message: "503".into(),
                    },
                },
                now,
            )
            .unwrap();
        advance(now);
        match hub.db.tools_deploys().unwrap().remove(&node) {
            Some(crate::deploy::Deploy::Failed {
                attempt, retry_at, ..
            }) => (attempt, retry_at),
            other => panic!("{other:?}"),
        }
    };
    let mut now = now_secs();
    assert_eq!(advance(now), (true, vec![node.clone()]));
    for (attempt, delay) in (1..).zip(crate::deploy::RETRY_DELAYS_SECS) {
        let (failed, due) = fail(now);
        assert_eq!(failed, attempt);
        let due = due.unwrap();
        assert!(due >= now + delay * 4 / 5 && due <= now + delay * 6 / 5);
        assert_eq!(
            advance(due - 1),
            (false, Vec::new()),
            "not before it is due"
        );
        // Due but not reachable: it waits, and spends no attempt.
        assert_eq!(
            hub.db.advance_tools(due, &builtin, &|_| false).unwrap(),
            (false, Vec::new())
        );
        now = due;
        assert_eq!(
            advance(now),
            (true, vec![node.clone()]),
            "attempt {}",
            attempt + 1
        );
    }
    assert_eq!(fail(now), (crate::deploy::ATTEMPTS, None), "spent");
    assert_eq!(advance(now + 30 * 86_400), (false, Vec::new()));
    let shown = ops::node_views(&hub)
        .unwrap()
        .into_iter()
        .find(|v| v.id == node)
        .unwrap()
        .tools_deploy
        .unwrap();
    assert!(
        shown.contains("attempt 5 of 5") && shown.contains("no more are made automatically"),
        "{shown}"
    );
    let events: Vec<String> = hub
        .db
        .audits(Some(&node), 50)
        .unwrap()
        .into_iter()
        .map(|a| a.event)
        .collect();
    assert!(
        events
            .iter()
            .any(|e| e.contains("attempt 1 of 5")
                && e.contains("failed: 503; the next is due after")),
        "{events:?}"
    );
    // An operator's build is the first attempt again, and a failure of it is retried.
    ops::tools(&hub, "uid 0", &node, None).unwrap();
    assert_eq!(fail(now_secs()).0, 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Nodes report each file of their tools: the hub notes and audits a node whose files differ
/// from those other nodes built from the same definition, and one whose tools changed since it
/// installed them, which it then asks to build them anew.
#[tokio::test(flavor = "multi_thread")]
async fn tools_that_differ_across_nodes_or_changed_are_noted_audited_and_rebuilt() {
    use vk_hub_proto::{ToolsCheck, ToolsFile};
    let (dir, _, hub) = start_releases("tools-outputs", None).await;
    let a = crate::tools::add(&hub, "uid 0", &context(&dir, "a", "a"), "2026.10")
        .unwrap()
        .sha256;
    crate::settings::set(
        &hub,
        "uid 0",
        None,
        "tools",
        Some(crate::settings::parse("tools", &a).unwrap()),
    )
    .unwrap();
    let [n1, n2, n3] = ["n1", "n2", "n3"].map(|name| enroll_as(&hub, name));
    let files = |git: &str| {
        std::collections::BTreeMap::from([
            (
                "git".to_string(),
                ToolsFile::File {
                    sha256: git.repeat(64),
                    size: 10,
                },
            ),
            (
                "git-remote-https".to_string(),
                ToolsFile::Link {
                    target: "git-remote-http".into(),
                },
            ),
        ])
    };
    let report = |id: &str, host: &str, git: &str, check: ToolsCheck| {
        let mut inventory = Inventory {
            hostname: host.into(),
            ..Inventory::default()
        };
        inventory.versions.tools = Some(vk_hub_proto::ToolsInstalled {
            sha256: a.clone(),
            version: "2026.10".into(),
            tools: Default::default(),
            in_use: true,
            files: files(git),
            egress: None,
            check: Some(check),
        });
        hub.db
            .record_inventory(id, inventory, true, now_secs())
            .unwrap();
    };
    for (id, host, git) in [(&n1, "n1", "1"), (&n2, "n2", "1"), (&n3, "n3", "2")] {
        hub.db
            .record_session(id, "inc", TOOLS, None, now_secs(), || true)
            .unwrap();
        hub.db
            .record_report(id, vk_hub_proto::Report::default(), now_secs())
            .unwrap();
        report(id, host, git, ToolsCheck::Intact);
    }
    let views = ops::node_views(&hub).unwrap();
    let peers = |id: &str| {
        views
            .iter()
            .find(|v| v.id == id)
            .unwrap()
            .tools_peers
            .clone()
            .unwrap()
    };
    assert_eq!((peers(&n1).same, peers(&n1).differ.len()), (1, 1));
    let differ: Vec<(String, Vec<String>)> = peers(&n3)
        .differ
        .into_iter()
        .map(|d| (d.hostname, d.entries))
        .collect();
    let git = vec!["git".to_string()];
    assert_eq!(differ, [("n1".into(), git.clone()), ("n2".into(), git)]);
    let outputs = ops::tools_outputs(&hub.db.nodes().unwrap());
    let mut nodes = vec![n1.clone(), n2.clone()];
    nodes.sort();
    assert_eq!(outputs[&a].outputs.len(), 2);
    assert_eq!(outputs[&a].outputs[0].nodes, nodes);
    let shown = render_nodes(&views, now_secs());
    let want = format!(
        "n3: tools 2026.10 ({}) hold other files than n1, n2 built from the same definition \
         (git); 0 other nodes hold the same",
        &a[..12]
    );
    assert!(shown.contains(&want), "{want}\n{shown}");
    let audited = |id: &str, what: &str| {
        hub.db
            .audits(Some(id), 50)
            .unwrap()
            .iter()
            .any(|r| r.event.contains(what))
    };
    assert!(audited(
        &n3,
        "hold other files than n1, n2 built from the same definition (git)"
    ));
    assert!(
        !audited(&n1, "hold other files"),
        "the first to report had nothing to differ from"
    );

    // Nothing is asked of nodes that have their tools.
    let builtin = crate::tools::builtin().packed.sha256.clone();
    let advance = || {
        hub.db
            .advance_tools(now_secs(), &builtin, &|_| true)
            .unwrap()
    };
    assert_eq!(advance(), (false, Vec::new()));

    // n2's tools changed since it installed them: noted, audited, and built anew.
    report(
        &n2,
        "n2",
        "1",
        ToolsCheck::Modified {
            entries: vec!["git".into()],
        },
    );
    let shown = render_nodes(&ops::node_views(&hub).unwrap(), now_secs());
    assert!(
        shown.contains("n2: tools 2026.10")
            && shown.contains(
                "have changed since it installed them (git): its jobs are not given them"
            ),
        "{shown}"
    );
    assert!(audited(&n2, "have changed since it installed them (git)"));
    assert_eq!(advance(), (true, vec![n2.clone()]));
    // Installed with nothing recorded: built anew too.
    report(&n1, "n1", "1", ToolsCheck::Unrecorded);
    assert_eq!(advance(), (true, vec![n1.clone()]));
    std::fs::remove_dir_all(&dir).unwrap();
}
