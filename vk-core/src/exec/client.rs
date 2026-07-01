use crate::messages::{CmdExec, Message};
use std::io::Write;
use std::process;
use std::thread;

use crate::messages;
use crate::messages::CmdResult;
use anyhow::anyhow;
use futures::{Sink, SinkExt, Stream, StreamExt};
use log::{debug, error, info};
use tokio::sync::mpsc;

pub async fn client_run_cmd(
    mut stream: impl Stream<Item = Result<Message, std::io::Error>> + Unpin,
    mut sink: impl Sink<Message, Error = std::io::Error> + Unpin + Send + 'static,
    cmd: CmdExec,
) -> Result<CmdResult, anyhow::Error> {
    let background = cmd.mode == messages::RunMode::Background;
    sink.send(Message::CmdExec(cmd)).await?;
    debug!("Wrote payload");

    let srv_msg = stream
        .next()
        .await
        .ok_or(RunCmdError::StreamUnexpectedInterrupt)??;
    match srv_msg {
        Message::StartOK => {
            if background {
                // nothing more flows on this connection for a background command
                return Ok(CmdResult {
                    code: Some(0),
                    signal: None,
                });
            }
            // foreground task started
        }
        // the caller prints this on stderr and exits non-zero
        Message::StartErr { msg } => return Err(RunCmdError::StartFailed(msg).into()),
        _ => return Err(RunCmdError::InvalidMessage(srv_msg).into()),
    }

    let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(super::DATA_CHANNEL_CAPACITY);

    let _copy_stdin = thread::spawn(move || {
        read_stdin(&stdin_tx);
    });

    // async task to write stdin
    let stdin_handle = tokio::spawn(async move {
        while let Some(msg) = stdin_rx.recv().await {
            if msg.is_empty() {
                let _ = sink
                    .send(Message::Close {
                        fd: messages::Fd::Stdin,
                        error: None,
                    })
                    .await;
                break;
            }
            let m = Message::Data {
                fd: messages::Fd::Stdin,
                msg,
            };
            if (sink.send(m).await).is_err() {
                drop(stdin_rx);
                break;
            }
        }
    });

    // stdout writing thread
    let (stdout_tx, mut stdout_rx) = mpsc::channel::<Vec<u8>>(super::DATA_CHANNEL_CAPACITY);

    let mut stdout_tx = Some(stdout_tx);

    let th_copy_stdout = thread::spawn(move || {
        let mut stdout = std::io::stdout();
        while let Some(data) = stdout_rx.blocking_recv() {
            debug!("copy_stdout_thread, writing {} bytes", &data.len());
            if std::io::Write::write_all(&mut stdout, &data).is_err() {
                // downstream is gone (e.g. `... | head`): draining forever would let
                // the remote command run unattended; disconnect instead — the server
                // kills the remote process group on EOF. 141 = 128 + SIGPIPE.
                process::exit(141);
            }
            debug!("copy_stdout_thread, wrote {} bytes", &data.len());
        }
        info!("copy_stdout_thread done");
        stdout.flush()
    });

    // stderr writing thread
    let (stderr_tx, mut stderr_rx) = mpsc::channel::<Vec<u8>>(super::DATA_CHANNEL_CAPACITY);

    let mut stderr_tx = Some(stderr_tx);

    let th_copy_stderr = thread::spawn(move || {
        let mut stderr = std::io::stderr();
        while let Some(data) = stderr_rx.blocking_recv() {
            debug!("copy_stderr_thread, writing {} bytes", &data.len());
            if std::io::Write::write_all(&mut stderr, &data).is_err() {
                // see the stdout thread: a closed stderr must disconnect too
                process::exit(141);
            }
            debug!("copy_stderr_thread, wrote {} bytes", &data.len());
        }
        info!("copy_stderr_thread done");
        stderr.flush()
    });

    let exit_code: CmdResult;
    let (mut stdout_recv, mut stderr_recv) = (0, 0);
    loop {
        let srv_msg = stream
            .next()
            .await
            .ok_or(RunCmdError::StreamUnexpectedInterrupt)??;
        match srv_msg {
            Message::Data { fd, msg } => match fd {
                messages::Fd::Stdout => {
                    stdout_recv += &msg.len();
                    if let Some(ref tx) = stdout_tx {
                        let _ = tx.send(msg).await;
                    } else {
                        error!("attempt to write to stdout after it is closed");
                    }
                }
                messages::Fd::Stderr => {
                    stderr_recv += &msg.len();
                    if let Some(ref tx) = stderr_tx {
                        let _ = tx.send(msg).await;
                    } else {
                        error!("attempt to write to stderr after it is closed");
                    }
                }
                messages::Fd::Stdin => return Err(anyhow!("cannot write to stdin")),
            },
            Message::Close { fd, error } => {
                if let Some(err) = error {
                    info!("got close message on {fd:?} with error {err}");
                }
                match fd {
                    messages::Fd::Stdout => {
                        info!("closing stdout from msg");
                        stdout_tx = None;
                    }
                    messages::Fd::Stderr => {
                        info!("closing stderr from msg");
                        stderr_tx = None;
                    }
                    messages::Fd::Stdin => {
                        stdin_handle.abort();
                    }
                }
            }
            Message::ExecDone(cr) => {
                info!(
                    "Process exit status: code={:?} signal={:?} (stdout: {}, stderr: {})",
                    &cr.code, &cr.signal, stdout_recv, stderr_recv
                );
                drop(stdout_tx);
                drop(stderr_tx);
                stdin_handle.abort();
                unsafe {
                    libc::close(0);
                }
                exit_code = cr;
                break;
            }
            _ => return Err(RunCmdError::InvalidMessage(srv_msg).into()),
        }
    }

    info!("waiting stdout...");
    let _ = th_copy_stdout.join();
    info!("waiting stderr...");
    let _ = th_copy_stderr.join();
    Ok(exit_code)
}

/// `exec --tty`: drive a remote pty from the local terminal. The local terminal is
/// switched to raw mode for the whole session (restored on drop), terminal output
/// arrives as a single Fd::Stdout stream, and SIGWINCH is relayed as Resize.
pub async fn client_run_tty(
    mut stream: impl Stream<Item = Result<Message, std::io::Error>> + Unpin,
    mut sink: impl Sink<Message, Error = std::io::Error> + Unpin + Send + 'static,
    cmd: CmdExec,
) -> Result<CmdResult, anyhow::Error> {
    sink.send(Message::CmdExec(cmd)).await?;

    let srv_msg = stream
        .next()
        .await
        .ok_or(RunCmdError::StreamUnexpectedInterrupt)??;
    match srv_msg {
        Message::StartOK => {}
        Message::StartErr { msg } => return Err(RunCmdError::StartFailed(msg).into()),
        _ => return Err(RunCmdError::InvalidMessage(srv_msg).into()),
    }

    let _raw = crate::pty::RawModeGuard::enable(0)?;

    // single owner of the sink: stdin bytes and resize events funnel through it
    let (msg_tx, mut msg_rx) = mpsc::channel::<Message>(super::DATA_CHANNEL_CAPACITY);
    let sink_writer = tokio::spawn(async move {
        while let Some(msg) = msg_rx.recv().await {
            if sink.send(msg).await.is_err() {
                break;
            }
        }
    });

    let stdin_tx = msg_tx.clone();
    let _stdin_pump = thread::spawn(move || {
        use std::io::Read;
        let mut buf = [0u8; 4096];
        let mut stdin = std::io::stdin();
        while let Ok(size) = stdin.read(&mut buf) {
            if size == 0 {
                break;
            }
            let data = Message::Data {
                fd: messages::Fd::Stdin,
                msg: buf[..size].into(),
            };
            if stdin_tx.blocking_send(data).is_err() {
                break;
            }
        }
    });

    let winch_tx = msg_tx.clone();
    let winch = tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let Ok(mut winch) = signal(SignalKind::window_change()) else {
            return;
        };
        while winch.recv().await.is_some() {
            if let Ok((rows, cols)) = crate::pty::get_winsize(0)
                && winch_tx.send(Message::Resize { rows, cols }).await.is_err()
            {
                break;
            }
        }
    });
    drop(msg_tx);

    let mut stdout = std::io::stdout();
    let exit_code = loop {
        let srv_msg = stream
            .next()
            .await
            .ok_or(RunCmdError::StreamUnexpectedInterrupt)??;
        match srv_msg {
            Message::Data {
                fd: messages::Fd::Stdout,
                msg,
            } => {
                if stdout
                    .write_all(&msg)
                    .and_then(|()| stdout.flush())
                    .is_err()
                {
                    // local terminal gone: returning drops the connection and the
                    // server kills the remote process group
                    break CmdResult {
                        code: Some(141),
                        signal: None,
                    };
                }
            }
            Message::Close { .. } => {}
            Message::ExecDone(cr) => break cr,
            _ => return Err(RunCmdError::InvalidMessage(srv_msg).into()),
        }
    };
    winch.abort();
    sink_writer.abort();
    Ok(exit_code)
}

fn read_stdin(stdin_tx: &mpsc::Sender<Vec<u8>>) {
    use std::io::Read;

    let mut buf = [0u8; 4096];
    let mut stdin = std::io::stdin();
    loop {
        let Ok(size) = stdin.read(&mut buf) else {
            debug!("stdin thread, read done");
            break;
        };
        let data = &buf[0..size];
        if let Err(e) = stdin_tx.blocking_send(data.into()) {
            error!("error writing stdin to channel {e}");
            break;
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum RunCmdError {
    #[error("stream interrupted unexpectedly")]
    StreamUnexpectedInterrupt,
    #[error("Invalid message {0:?}")]
    InvalidMessage(Message),
    #[error("error starting remote process: {0}")]
    StartFailed(String),
}
