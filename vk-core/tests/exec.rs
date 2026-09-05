//! End-to-end tests over a unix socket, and hybrid-vsock (vsock-mux://) handshake
//! tests against a fake VMM mux. Real AF_VSOCK needs a VM (or the vsock_loopback
//! module), so the vsock:// transport itself is not covered here.

use futures::{SinkExt, StreamExt};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::time::timeout;
use vk_core::addr::SocketAddr;
use vk_core::exec::client::{Stdin, client_run_connect};
use vk_core::exec::server::run_server;
use vk_core::framing::wrap_stream;
use vk_core::messages::{CmdExec, Fd, Message, RunMode, Status, Tty};
use vk_core::net::connect;
use vk_core::status::get_status;

fn tmp_socket_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "virtkit-agent-test-{}-{tag}.socket",
        std::process::id()
    ))
}

async fn start_server(tag: &str) -> SocketAddr {
    let path = tmp_socket_path(tag);
    let _ = std::fs::remove_file(&path);
    let addr = SocketAddr::Unix(path.clone());
    let server_addr = addr.clone();
    tokio::spawn(async move {
        run_server(&server_addr, Some(Duration::from_secs(60)), None, vec![])
            .await
            .unwrap();
    });
    while !path.exists() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    addr
}

/// Run the command as whoever the test process is. `build_command` falls back to
/// `VIRTKIT_DEFAULT_RUN_USER` when a request names no user, and these tests run inside a
/// microVM whose agent exports it — so an unset user would make every spawn try to drop
/// privileges and fail with EPERM. An empty one is already `Some`, so it wins over the
/// fallback and is then dropped as empty, pinning the tests to the ambient user wherever
/// they run.
const AMBIENT_USER: Option<String> = Some(String::new());

/// A TCP echo server, standing in for an arbitrary "target on the guest's LAN" — the
/// thing `CmdConnect` dials on the caller's behalf.
async fn echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match conn.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) if conn.write_all(&buf[..n]).await.is_err() => break,
                        Ok(_) => {}
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn unix_exec_roundtrip() {
    let addr = start_server("exec").await;

    let (mut stream, mut sink) = connect(&addr).await.unwrap();
    sink.send(Message::CmdExec(CmdExec {
        name: "sh".into(),
        args: vec!["-c".into(), "echo hi".into()],
        env: vec![],
        clear_env: false,
        mode: RunMode::Interactive,
        tty: None,
        dir: None,
        user: AMBIENT_USER,
    }))
    .await
    .unwrap();

    let mut stdout = Vec::new();
    let code = timeout(Duration::from_secs(10), async {
        assert!(matches!(
            stream.next().await.unwrap().unwrap(),
            Message::StartOK
        ));
        loop {
            match stream.next().await.unwrap().unwrap() {
                Message::Data {
                    fd: Fd::Stdout,
                    msg,
                } => stdout.extend(msg),
                Message::ExecDone(result) => return result.code,
                _ => {}
            }
        }
    })
    .await
    .unwrap();

    assert_eq!(code, Some(0));
    assert_eq!(stdout, b"hi\n");
}

/// A process outliving the command inherits its stdout and stderr pipes, so the
/// readers never see end-of-file. The session must still end on the command's own exit.
#[tokio::test]
async fn exec_ends_when_a_leftover_process_holds_the_pipes() {
    let addr = start_server("exec-leftover").await;

    let (mut stream, mut sink) = connect(&addr).await.unwrap();
    sink.send(Message::CmdExec(CmdExec {
        name: "sh".into(),
        args: vec!["-c".into(), "sleep 5 & echo bye".into()],
        env: vec![],
        clear_env: false,
        mode: RunMode::Interactive,
        tty: None,
        dir: None,
        user: AMBIENT_USER,
    }))
    .await
    .unwrap();

    let started = Instant::now();
    let mut stdout = Vec::new();
    let code = timeout(Duration::from_secs(10), async {
        assert!(matches!(
            stream.next().await.unwrap().unwrap(),
            Message::StartOK
        ));
        loop {
            match stream.next().await.unwrap().unwrap() {
                Message::Data {
                    fd: Fd::Stdout,
                    msg,
                } => stdout.extend(msg),
                Message::ExecDone(result) => return result.code,
                _ => {}
            }
        }
    })
    .await
    .unwrap();

    assert_eq!(code, Some(0));
    assert_eq!(stdout, b"bye\n");
    // the session ends on the drain's grace period, not on the leftover's lifetime
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(3), "took {elapsed:?}");
}

/// `CmdConnect` end to end at the protocol level: dial an echo server through the
/// agent and get bytes back framed as an exec session's Stdout would be.
#[tokio::test]
async fn connect_roundtrip_echoes_bytes() {
    let addr = start_server("connect").await;
    let echo_addr = echo_server().await;

    let (mut stream, mut sink) = connect(&addr).await.unwrap();
    sink.send(Message::CmdConnect {
        target: format!("tcp://{echo_addr}"),
    })
    .await
    .unwrap();
    assert!(matches!(
        stream.next().await.unwrap().unwrap(),
        Message::StartOK
    ));

    sink.send(Message::Data {
        fd: Fd::Stdin,
        msg: b"ping".to_vec(),
    })
    .await
    .unwrap();

    let echoed = timeout(Duration::from_secs(10), async {
        loop {
            if let Message::Data {
                fd: Fd::Stdout,
                msg,
            } = stream.next().await.unwrap().unwrap()
            {
                return msg;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(echoed, b"ping");

    sink.send(Message::Close {
        fd: Fd::Stdin,
        error: None,
    })
    .await
    .unwrap();
}

/// A target string that fails to parse as a `SocketAddr` (unlike a bare path, which
/// always parses as `unix:`) is refused before ever dialing anything.
#[tokio::test]
async fn connect_with_unparseable_target_gets_start_err() {
    let addr = start_server("connect-badaddr").await;
    let (mut stream, mut sink) = connect(&addr).await.unwrap();
    sink.send(Message::CmdConnect {
        target: "vsock://not-a-port".into(),
    })
    .await
    .unwrap();
    match stream.next().await.unwrap().unwrap() {
        Message::StartErr { msg } => assert!(msg.contains("invalid connect target"), "got: {msg}"),
        other => panic!("expected StartErr, got {other:?}"),
    }
}

/// A well-formed target nothing answers on fails at dial time, not parse time.
#[tokio::test]
async fn connect_to_missing_target_gets_start_err() {
    let addr = start_server("connect-missing").await;
    let (mut stream, mut sink) = connect(&addr).await.unwrap();
    sink.send(Message::CmdConnect {
        target: "/nonexistent/vk-connect-test.sock".into(),
    })
    .await
    .unwrap();
    match stream.next().await.unwrap().unwrap() {
        Message::StartErr { msg } => assert!(msg.contains("nonexistent"), "got: {msg}"),
        other => panic!("expected StartErr, got {other:?}"),
    }
}

/// A wrapped channel (the host-exec allowlist a guest's requests are forced through)
/// has no notion of wrapping an arbitrary dial, so it must refuse CmdConnect outright
/// rather than let it bypass the allowlist.
#[tokio::test]
async fn connect_refused_on_wrapped_channel() {
    let path = tmp_socket_path("connect-wrapped");
    let _ = std::fs::remove_file(&path);
    let addr = SocketAddr::Unix(path.clone());
    let server_addr = addr.clone();
    tokio::spawn(async move {
        run_server(
            &server_addr,
            Some(Duration::from_secs(60)),
            Some(std::path::PathBuf::from("/bin/true")),
            vec![],
        )
        .await
        .unwrap();
    });
    while !path.exists() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let (mut stream, mut sink) = connect(&addr).await.unwrap();
    sink.send(Message::CmdConnect {
        target: "tcp://127.0.0.1:1".into(),
    })
    .await
    .unwrap();
    match stream.next().await.unwrap().unwrap() {
        Message::StartErr { msg } => assert!(msg.contains("wrapped"), "got: {msg}"),
        other => panic!("expected StartErr, got {other:?}"),
    }
}

/// `client_run_connect` end to end: a real local TCP connection (standing in for
/// `vk publish`'s already-accepted host side) relayed through the agent to a real
/// TCP target, exercising the same path `vk publish` will use.
#[tokio::test]
async fn client_run_connect_relays_between_local_and_target() {
    let addr = start_server("connect-client").await;
    let echo_addr = echo_server().await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
    let mut caller = TcpStream::connect(listener_addr).await.unwrap();
    let local = accept.await.unwrap();

    let (stream, sink) = connect(&addr).await.unwrap();
    let relay = tokio::spawn(async move {
        client_run_connect(stream, sink, format!("tcp://{echo_addr}"), local)
            .await
            .unwrap();
    });

    caller.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    timeout(Duration::from_secs(10), caller.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"hello");

    drop(caller);
    timeout(Duration::from_secs(10), relay)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn exec_drops_to_user() {
    // setgroups/setgid/setuid need root; most dev/CI runs are not, so skip then.
    let euid = std::process::Command::new("id").arg("-u").output().unwrap();
    if String::from_utf8_lossy(&euid.stdout).trim() != "0" {
        eprintln!("skipping exec_drops_to_user: not running as root");
        return;
    }

    let addr = start_server("user").await;
    let (mut stream, mut sink) = connect(&addr).await.unwrap();
    sink.send(Message::CmdExec(CmdExec {
        name: "id".into(),
        args: vec!["-un".into()],
        env: vec![],
        clear_env: false,
        mode: RunMode::Interactive,
        tty: None,
        dir: None,
        user: Some("nobody".into()),
    }))
    .await
    .unwrap();

    let mut stdout = Vec::new();
    let code = timeout(Duration::from_secs(10), async {
        assert!(matches!(
            stream.next().await.unwrap().unwrap(),
            Message::StartOK
        ));
        loop {
            match stream.next().await.unwrap().unwrap() {
                Message::Data {
                    fd: Fd::Stdout,
                    msg,
                } => stdout.extend(msg),
                Message::ExecDone(result) => return result.code,
                _ => {}
            }
        }
    })
    .await
    .unwrap();

    assert_eq!(code, Some(0));
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "nobody");
}

#[tokio::test]
async fn large_output_roundtrip() {
    // 8 MiB > the bounded channels' ~1 MiB buffering: exercises the backpressure
    // path end to end without losing or reordering data
    const SIZE: usize = 8 * 1024 * 1024;
    let addr = start_server("large").await;

    let (mut stream, mut sink) = connect(&addr).await.unwrap();
    sink.send(Message::CmdExec(CmdExec {
        name: "sh".into(),
        args: vec!["-c".into(), format!("head -c {SIZE} /dev/zero")],
        env: vec![],
        clear_env: false,
        mode: RunMode::Interactive,
        tty: None,
        dir: None,
        user: AMBIENT_USER,
    }))
    .await
    .unwrap();

    let (mut received, mut code) = (0usize, None);
    timeout(Duration::from_secs(30), async {
        assert!(matches!(
            stream.next().await.unwrap().unwrap(),
            Message::StartOK
        ));
        loop {
            match stream.next().await.unwrap().unwrap() {
                Message::Data {
                    fd: Fd::Stdout,
                    msg,
                } => {
                    assert!(msg.iter().all(|&b| b == 0));
                    received += msg.len();
                }
                Message::ExecDone(result) => {
                    code = result.code;
                    break;
                }
                _ => {}
            }
        }
    })
    .await
    .unwrap();

    assert_eq!(code, Some(0));
    assert_eq!(received, SIZE);
}

/// Has `pid` stopped running? The killed grandchild is orphaned when its `sh` dies, so
/// it lingers as a zombie unless whoever adopts it reaps: PID 1 does that on a normal
/// system, but not when the suite runs as PID 1 of a bare container (`docker run`
/// without `--init`). A zombie has been killed, which is all this asserts on.
fn reaped_or_zombie(pid: i32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return true; // gone entirely: reaped by whoever adopted it
    };
    // the state field follows the comm field, which is parenthesised and may itself
    // contain ')' and spaces
    stat.rsplit_once(") ")
        .is_some_and(|(_, rest)| rest.starts_with('Z'))
}

#[tokio::test]
async fn disconnect_kills_remote_process() {
    let addr = start_server("kill").await;
    let pid_file = std::env::temp_dir().join(format!(
        "virtkit-agent-test-{}-kill.pid",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&pid_file);

    let (mut stream, sink) = connect(&addr).await.unwrap();
    let mut sink = sink;
    // track the pid of the GRANDCHILD (the sleep, not the sh): the disconnect must
    // take down the whole process group, not just the direct child
    sink.send(Message::CmdExec(CmdExec {
        name: "sh".into(),
        args: vec![
            "-c".into(),
            format!("sleep 30 & echo $! > {}; wait", pid_file.display()),
        ],
        env: vec![],
        clear_env: false,
        mode: RunMode::Interactive,
        tty: None,
        dir: None,
        user: AMBIENT_USER,
    }))
    .await
    .unwrap();
    assert!(matches!(
        stream.next().await.unwrap().unwrap(),
        Message::StartOK
    ));

    let pid: i32 = timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(content) = std::fs::read_to_string(&pid_file)
                && let Ok(pid) = content.trim().parse()
            {
                return pid;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();

    // disconnect mid-run: the server must kill the command instead of letting the
    // 30s sleep finish unattended
    drop(stream);
    drop(sink);
    timeout(Duration::from_secs(10), async {
        while !reaped_or_zombie(pid) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("remote process still alive after client disconnect");
    let _ = std::fs::remove_file(&pid_file);
}

/// Drive a tty exec and return (stdout, exit code).
async fn run_tty(addr: &SocketAddr, script: &str, rows: u16, cols: u16) -> (String, Option<i32>) {
    let (mut stream, mut sink) = connect(addr).await.unwrap();
    sink.send(Message::CmdExec(CmdExec {
        name: "sh".into(),
        args: vec!["-c".into(), script.into()],
        env: vec![],
        clear_env: false,
        mode: RunMode::Interactive,
        tty: Some(Tty {
            term: Some("xterm".into()),
            rows,
            cols,
        }),
        dir: None,
        user: AMBIENT_USER,
    }))
    .await
    .unwrap();

    timeout(Duration::from_secs(10), async {
        assert!(matches!(
            stream.next().await.unwrap().unwrap(),
            Message::StartOK
        ));
        let mut stdout = Vec::new();
        loop {
            match stream.next().await.unwrap().unwrap() {
                Message::Data {
                    fd: Fd::Stdout,
                    msg,
                } => stdout.extend(msg),
                Message::ExecDone(result) => {
                    return (String::from_utf8_lossy(&stdout).into_owned(), result.code);
                }
                _ => {}
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn tty_exec() {
    let addr = start_server("tty").await;
    let (stdout, code) = run_tty(
        &addr,
        "test -t 0 && test -t 1 && test -t 2 && stty size && echo TERM=$TERM",
        33,
        117,
    )
    .await;
    assert_eq!(code, Some(0), "stdout: {stdout}");
    // the pty translates \n to \r\n (ONLCR)
    assert!(stdout.contains("33 117\r\n"), "stdout: {stdout}");
    assert!(stdout.contains("TERM=xterm\r\n"), "stdout: {stdout}");
}

/// A process outliving the command keeps a pty slave handle open, so the master
/// never reports EIO. The session must still end on the command's own exit.
#[tokio::test]
async fn tty_exec_ends_when_a_leftover_process_holds_the_pty() {
    let addr = start_server("tty-leftover").await;
    // the trap has to be installed before the fork, not inside the background job: the
    // kernel hangs up the pty's process group when the session leader exits, and a
    // leftover that takes the SIGHUP closes the pty, hiding the case under test
    let started = Instant::now();
    let (stdout, code) = run_tty(&addr, "trap '' HUP; sleep 5 & echo bye", 24, 80).await;
    assert_eq!(code, Some(0), "stdout: {stdout}");
    assert!(stdout.contains("bye\r\n"), "stdout: {stdout}");
    // the session ends on the drain's grace period, not on the leftover's lifetime
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(3), "took {elapsed:?}");
}

#[tokio::test]
async fn tty_stderr_merges_into_the_terminal() {
    let addr = start_server("tty-stderr").await;
    let (stdout, code) = run_tty(&addr, "echo on-stderr >&2", 24, 80).await;
    assert_eq!(code, Some(0));
    assert!(stdout.contains("on-stderr\r\n"), "stdout: {stdout}");
}

#[tokio::test]
async fn unix_status() {
    let addr = start_server("status").await;
    timeout(Duration::from_secs(10), get_status(&addr))
        .await
        .unwrap()
        .unwrap();
}

/// Fake VMM mux: accept one connection, expect `CONNECT <port>\n`, send back
/// `response`, then (if ok) answer one status request like the real server.
async fn fake_mux(listener: UnixListener, expected_port: u32, response: &str, then_serve: bool) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], format!("CONNECT {expected_port}\n").as_bytes());
    stream.write_all(response.as_bytes()).await.unwrap();
    if !then_serve {
        return;
    }
    let (mut stream, mut sink) = wrap_stream(stream);
    assert!(matches!(
        stream.next().await.unwrap().unwrap(),
        Message::CmdStatus
    ));
    sink.send(Message::RespStatus {
        status: Status::default(),
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn vsock_mux_handshake() {
    let path = tmp_socket_path("mux");
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    tokio::spawn(fake_mux(listener, 4444, "OK 1024\n", true));

    let addr = SocketAddr::VsockMux { path, port: 4444 };
    timeout(Duration::from_secs(10), get_status(&addr))
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn vsock_mux_refused() {
    let path = tmp_socket_path("mux-refused");
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    tokio::spawn(fake_mux(listener, 4444, "FAIL\n", false));

    let addr = SocketAddr::VsockMux { path, port: 4444 };
    let err = timeout(Duration::from_secs(10), get_status(&addr))
        .await
        .unwrap()
        .unwrap_err();
    assert!(err.to_string().contains("refused"), "got: {err}");
}

/// Exercise [`Stdin::Closed`] across multiple commands. The client must signal end-of-input
/// and leave fd 0 open for later commands and files. [`Stdin::Forward`] closes fd 0 and is
/// limited to an exiting process, so it cannot be covered by an in-process test.
#[tokio::test]
async fn commands_run_back_to_back_without_forwarding_stdin() {
    let addr = start_server("exec-twice").await;
    let run = async |script: &str| {
        let (stream, sink) = connect(&addr).await.unwrap();
        timeout(
            Duration::from_secs(10),
            vk_core::exec::client::client_run_cmd(
                stream,
                sink,
                CmdExec {
                    name: "sh".into(),
                    args: vec!["-c".into(), script.into()],
                    env: vec![],
                    clear_env: false,
                    mode: RunMode::Interactive,
                    tty: None,
                    dir: None,
                    user: AMBIENT_USER,
                },
                Stdin::Closed,
            ),
        )
        .await
        .expect("command never finished")
        .unwrap()
    };

    // With no writer, `cat` hangs unless the client tells the guest to close stdin.
    assert_eq!(run("cat").await.code, Some(0));
    assert_eq!(run("exit 7").await.code, Some(7));
    // A new file must not reuse fd 0.
    let opened = std::fs::File::open("/dev/null").unwrap();
    assert_ne!(opened.as_raw_fd(), 0, "a run freed fd 0");
    drop(opened);
    assert_eq!(run("exit 0").await.code, Some(0));
}
