//! run_exec: execute one gitlab-runner stage script inside the job's VM.
//!
//! gitlab-runner hands us a script *path*; we pipe its content into the stdin of
//! a shell started by the in-guest virtkit-agent (vsock), and relay stdout/stderr —
//! gitlab-runner captures both for the job log. This is the virtkit-agent client
//! protocol with a file (not the terminal) as the stdin source, hence a local
//! pump instead of virtkit_agent::exec::client.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use futures::{SinkExt, StreamExt};
use virtkit_agent::addr::SocketAddr;
use virtkit_agent::messages::{CmdExec, CmdResult, Fd, Message, RunMode};

use crate::jobctx::JobCtx;

const STDIN_CHUNK: usize = 4096;

pub async fn run_stage(ctx: &JobCtx, script_path: &Path) -> Result<CmdResult> {
    let script = std::fs::read(script_path)
        .with_context(|| format!("reading stage script {}", script_path.display()))?;
    // None => virtkit-agent falls back to VIRTKIT_DEFAULT_RUN_USER (the guest
    // image's USER), so an unset MICROVM_USER runs as the image default.
    exec_script(
        &vsock_addr(ctx),
        &guest_shell(ctx),
        script,
        ctx.user_req.clone(),
    )
    .await
}

/// The VMM's hybrid-vsock socket for this job, as a virtkit-agent connect address.
pub fn vsock_addr(ctx: &JobCtx) -> SocketAddr {
    SocketAddr::VsockMux {
        path: ctx.vsock_sock(),
        port: ctx.cfg.vm.vsock_port,
    }
}

/// The shell stage scripts are piped into. The configured run_command (bash)
/// targets disk guests (the default bundle and systemd images); only a cpio/OCI
/// guest (alpine/distroless in RAM) lacks bash, so fall back to POSIX sh there.
/// prepare records the boot flavour in the job dir (run is a separate process and
/// cannot recompute it cheaply).
pub fn guest_shell(ctx: &JobCtx) -> Vec<String> {
    let cpio = std::fs::read_to_string(ctx.job_dir.join("boot.kind"))
        .map(|s| s.trim() == "generic-cpio")
        .unwrap_or(false);
    if cpio {
        vec!["sh".into()]
    } else {
        ctx.cfg.guest.run_command.clone()
    }
}

/// Run `script` (piped to `command`, e.g. bash) as `user` and relay its output,
/// returning the command result. Shared by the gitlab-runner stages (run_stage)
/// and the in-prepare services bring-up (which runs as root).
pub async fn exec_script(
    addr: &SocketAddr,
    command: &[String],
    script: Vec<u8>,
    user: Option<String>,
) -> Result<CmdResult> {
    let (mut stream, mut sink) = virtkit_agent::net::connect(addr)
        .await
        .context("connecting to the VM's virtkit-agent")?;

    let (name, args) = command
        .split_first()
        .ok_or_else(|| anyhow!("run command is empty"))?;
    sink.send(Message::CmdExec(CmdExec {
        name: name.clone(),
        args: args.to_vec(),
        env: vec![],
        clear_env: false,
        mode: RunMode::Interactive,
        dir: None,
        tty: None,
        user,
    }))
    .await?;

    match next(&mut stream).await? {
        Message::StartOK => {}
        Message::StartErr { msg } => bail!("starting {name} in the VM: {msg}"),
        other => bail!("unexpected reply to exec: {other:?}"),
    }

    // The guest interleaves stdin consumption with output: pump the script in
    // concurrently with the output loop, or a chatty script would deadlock both
    // sides on full buffers.
    let feed_stdin = tokio::spawn(async move {
        for chunk in script.chunks(STDIN_CHUNK) {
            sink.send(Message::Data {
                fd: Fd::Stdin,
                msg: chunk.to_vec(),
            })
            .await?;
        }
        sink.send(Message::Close {
            fd: Fd::Stdin,
            error: None,
        })
        .await?;
        Ok::<_, std::io::Error>(())
    });

    let result = loop {
        match next(&mut stream).await? {
            Message::Data {
                fd: Fd::Stdout,
                msg,
            } => {
                let mut out = std::io::stdout();
                out.write_all(&msg)?;
                out.flush()?;
            }
            Message::Data {
                fd: Fd::Stderr,
                msg,
            } => {
                let mut err = std::io::stderr();
                err.write_all(&msg)?;
                err.flush()?;
            }
            // the shell exited without draining the script: stop feeding it
            Message::Close { fd: Fd::Stdin, .. } => feed_stdin.abort(),
            Message::Close { .. } => {}
            Message::ExecDone(result) => break result,
            other => bail!("unexpected message: {other:?}"),
        }
    };
    feed_stdin.abort();
    Ok(result)
}

async fn next(
    stream: &mut (impl futures::Stream<Item = Result<Message, std::io::Error>> + Unpin),
) -> Result<Message> {
    Ok(stream
        .next()
        .await
        .ok_or_else(|| anyhow!("connection to the VM lost"))??)
}
