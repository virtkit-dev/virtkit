//! End-to-end tests over a unix socket, and hybrid-vsock (vsock-mux://) handshake
//! tests against a fake VMM mux. Real AF_VSOCK needs a VM (or the vsock_loopback
//! module), so the vsock:// transport itself is not covered here.

use futures::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::time::timeout;
use virtkit_agent::addr::SocketAddr;
use virtkit_agent::exec::server::run_server;
use virtkit_agent::framing::wrap_stream;
use virtkit_agent::messages::{CmdExec, Fd, Message, RunMode, Status, Tty};
use virtkit_agent::net::connect;
use virtkit_agent::status::get_status;

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
        run_server(&server_addr, Some(Duration::from_secs(60)), None)
            .await
            .unwrap();
    });
    while !path.exists() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
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
        user: None,
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
        user: None,
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
        user: None,
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
    // 30s sleep finish unattended (kill(pid, 0) probes existence; the server reaps
    // the child via wait(), so the pid disappears once killed)
    drop(stream);
    drop(sink);
    timeout(Duration::from_secs(10), async {
        while unsafe { libc::kill(pid, 0) } == 0 {
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
        user: None,
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
