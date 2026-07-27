//! run_exec: execute one gitlab-runner stage script inside the job's VM.
//!
//! gitlab-runner hands us a script *path*; we pipe its content into the stdin of
//! a shell started by the in-guest virtkit-agent (vsock), and relay stdout/stderr —
//! gitlab-runner captures both for the job log. This is the virtkit-agent client
//! protocol with a file (not the terminal) as the stdin source, hence a local
//! pump instead of vk_core::exec::client.

use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use futures::{SinkExt, StreamExt};
use tokio_util::sync::CancellationToken;
use vk_core::addr::SocketAddr;
use vk_core::messages::{CmdExec, CmdResult, Fd, Message, RunMode};

use crate::jobctx::JobCtx;

const STDIN_CHUNK: usize = 4096;

/// Where a guest command's stdout/stderr go. `Inherit` relays them straight to the
/// process stdout/stderr (the default — `vk run`, the gitlab-runner stages, internal
/// quiesce commands). `Routed` hands each chunk to a callback tagged by fd — the `vk
/// build` progress reporter uses this to line-buffer and stage-prefix RUN output so
/// concurrent stages stay legible instead of interleaving unattributed.
/// The callback a [`OutputSink::Routed`] hands each output chunk to, tagged by fd.
pub type OutputFn = Arc<dyn Fn(Fd, &[u8]) + Send + Sync>;

#[derive(Clone)]
pub enum OutputSink {
    Inherit,
    Routed(OutputFn),
}

impl OutputSink {
    fn relay(&self, fd: Fd, msg: &[u8]) -> std::io::Result<()> {
        match self {
            OutputSink::Inherit => {
                if matches!(fd, Fd::Stderr) {
                    let mut err = std::io::stderr();
                    err.write_all(msg)?;
                    err.flush()
                } else {
                    let mut out = std::io::stdout();
                    out.write_all(msg)?;
                    out.flush()
                }
            }
            OutputSink::Routed(f) => {
                f(fd, msg);
                Ok(())
            }
        }
    }
}

/// gitlab-runner's final `run_exec` sub-stage, run unconditionally after every other stage
/// (even after a failed script). Its output still lands in the job trace — unlike
/// `cleanup_exec` — so it is where the once-per-job summaries are emitted: the egress audit
/// and what the job cost the runner.
const FINAL_STAGE: &str = "cleanup_file_variables";

pub async fn run_stage(ctx: &JobCtx, script_path: &Path, stage: Option<&str>) -> Result<CmdResult> {
    let script = std::fs::read(script_path)
        .with_context(|| format!("reading stage script {}", script_path.display()))?;
    // None => virtkit-agent falls back to VIRTKIT_DEFAULT_RUN_USER (the guest
    // image's USER), so an unset MICROVM_USER runs as the image default.
    let result = exec_script(
        &vsock_addr(ctx),
        &guest_shell(ctx),
        script,
        ctx.user_req.clone(),
        &OutputSink::Inherit,
        None,
    )
    .await;
    // Surface egress the switch blocked during this step into the job trace: the switch
    // logs allowlist refusals to a host-side file the job never sees, so a script that
    // fails because it could not reach a host would otherwise get no hint why. Reported
    // whether the step passed or failed.
    report_egress_blocks(ctx);
    // On the last stage, print the once-per-job summaries — the "domains contacted" audit
    // (a no-op unless audit is on) and what the job cost the runner — so they appear at the
    // end of the trace.
    if stage == Some(FINAL_STAGE) {
        report_egress_audit(ctx);
        report_resource_usage(ctx);
    }
    result
}

/// Forward the per-job switch's egress refusals into the job trace. The switch
/// (`net.mode = "switch"`) appends a typed denial record per refusal to its denial channel
/// (see egress_report), which the running job never sees. This drains only the records
/// added since the previous stage — a byte offset persisted in the job dir — so each block
/// is reported once, in the stage during which it happened, then prints them deduplicated
/// to stderr (gitlab-runner captures it). Best-effort: no channel (net.mode != "switch")
/// or an IO error is a silent no-op.
fn report_egress_blocks(ctx: &JobCtx) {
    let pos_file = ctx.job_dir.join("egress-denied.offset");
    let start: u64 = std::fs::read_to_string(&pos_file)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let (denials, new_offset) = crate::egress_report::read_since(&ctx.egress_denied_log(), start);
    if new_offset == start {
        return; // nothing new (and no offset to persist)
    }

    // Unique denials in first-seen order, counting repeats so a retry loop hammering one
    // blocked host does not flood the trace.
    let mut seen: Vec<(String, usize)> = Vec::new();
    for d in &denials {
        let msg = d.display();
        match seen.iter_mut().find(|(m, _)| *m == msg) {
            Some((_, n)) => *n += 1,
            None => seen.push((msg, 1)),
        }
    }
    if !seen.is_empty() {
        eprintln!("virtkit: egress blocked by the allowlist:");
        for (msg, n) in &seen {
            if *n > 1 {
                eprintln!("  {msg} (x{n})");
            } else {
                eprintln!("  {msg}");
            }
        }
    }
    let _ = std::fs::write(&pos_file, new_offset.to_string());
}

/// Print the per-job egress audit summary into the job trace: every external domain the switch
/// saw this job's guest resolve, then every external IP it dialed directly (without a matching
/// resolution), each most-contacted first. In audit mode (`[egress] audit` or
/// `MICROVM_EGRESS_AUDIT`) the switch records each contact to its audit channel (see
/// egress_report); this drains the whole file once, at the end of the job. Best-effort: audit
/// off (no channel) or nothing contacted is a silent no-op.
fn report_egress_audit(ctx: &JobCtx) {
    if let Some(summary) = crate::egress_report::contacts_summary(
        &ctx.egress_audit_log(),
        "external domains contacted (audit)",
    ) {
        eprintln!("{summary}");
    }
    if let Some(summary) = crate::egress_report::ip_contacts_summary(
        &ctx.egress_audit_log(),
        "external IPs/ports contacted (audit)",
    ) {
        eprintln!("{summary}");
    }
}

/// Print what the job cost the runner — the CPU time and peak memory of its microVM and the
/// host helpers around it (see usage) — into the job trace, so a job can be sized from what
/// it actually used. Sampled here rather than at cleanup because this is the last stage whose
/// output the trace still keeps, and the job's processes are all still alive to be read: it
/// therefore covers everything but the guest's own shutdown. Best-effort: a job whose
/// supervisor is already gone (the guest died) reports nothing.
///
/// The same figure is what the next run of this job is admitted against where the host
/// reserves from history (`[schedule] from_history`), so it is recorded here too.
fn report_resource_usage(ctx: &JobCtx) {
    if let Some(pid) = crate::vm::live_supervisor_pid(ctx)
        && let Some(usage) = crate::usage::tree(pid)
    {
        eprintln!("{}", usage.summary("job"));
        // Recorded in the same bytes the line above prints, so one run never reads as two
        // figures. Stamped with the ceiling it ran under, which is what makes a job whose
        // MICROVM_MEM changed start again rather than be predicted from runs it can no longer
        // repeat. A job whose declared size will not parse never booted, so there is nothing
        // to remember.
        if let Ok(ceiling_mib) = crate::vm::declared_mem_mib(ctx)
            && let Some(ceiling) = ceiling_mib.checked_mul(1024 * 1024)
        {
            crate::admit::remember(
                &ctx.history_dir(),
                &ctx.usage_key(),
                usage.peak_rss,
                ceiling,
            );
        }
    }
}

/// The exec-channel connect address for this job's VM, matching the selected backend
/// (hybrid vsock-mux for cloud-hypervisor, a plain unix socket for libkrun).
pub fn vsock_addr(ctx: &JobCtx) -> SocketAddr {
    crate::vmm::exec_addr(&ctx.vsock_sock(), ctx.cfg.vm.vsock_port)
}

/// The shell stage scripts are piped into: the configured run_command (bash) when
/// the guest has bash, else POSIX sh — prepare probes the booted guest and records
/// the result in the job dir (run is a separate process and cannot probe cheaply).
pub fn guest_shell(ctx: &JobCtx) -> Vec<String> {
    let sh = std::fs::read_to_string(ctx.job_dir.join("guest.shell"))
        .map(|s| s.trim() == "sh")
        .unwrap_or(false);
    if sh {
        vec!["sh".into()]
    } else {
        ctx.cfg.guest.run_command.clone()
    }
}

/// Run `script` (piped to `command`, e.g. bash) as `user` and relay its output,
/// returning the command result. Shared by the gitlab-runner stages (run_stage)
/// and the in-prepare services bring-up (which runs as root).
///
/// `cancel`, when set, aborts the running command promptly (the caller tears the guest
/// down afterwards): the parallel build passes the shared build-cancellation token so a
/// stage failure stops the RUN steps still executing in sibling stages' guests.
pub async fn exec_script(
    addr: &SocketAddr,
    command: &[String],
    script: Vec<u8>,
    user: Option<String>,
    output: &OutputSink,
    cancel: Option<&CancellationToken>,
) -> Result<CmdResult> {
    let (mut stream, mut sink) = vk_core::net::connect(addr)
        .await
        .context("connecting to the VM's vk-agent")?;

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
        let msg = match cancel {
            // Race the next guest message against cancellation so a build-wide abort
            // interrupts a long RUN mid-flight instead of waiting for it to finish.
            Some(c) => tokio::select! {
                biased;
                () = c.cancelled() => {
                    feed_stdin.abort();
                    bail!("guest command aborted: build stopped after an earlier stage failed");
                }
                m = next(&mut stream) => m?,
            },
            None => next(&mut stream).await?,
        };
        match msg {
            Message::Data {
                fd: Fd::Stdout,
                msg,
            } => output.relay(Fd::Stdout, &msg)?,
            Message::Data {
                fd: Fd::Stderr,
                msg,
            } => output.relay(Fd::Stderr, &msg)?,
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
