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
/// `cleanup_exec` — so it is where the once-per-job summaries are emitted: the egress audit,
/// the names the job reaches out to, and what it cost the runner.
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
    // (a no-op unless audit is on), the job's standing list of names, and what the job cost
    // the runner — so they appear at the end of the trace.
    if stage == Some(FINAL_STAGE) {
        report_egress_audit(ctx);
        report_contacted_names(ctx);
        report_resource_usage(ctx).await;
        report_project_usage(ctx);
        finalize_atop(ctx).await;
    }
    result
}

/// End this job's statistics log on a whole sample and say where it is (`[gitlab] atop`).
///
/// The guest sampler takes SIGUSR2 as "one last sample, then exit", so asking for that here —
/// the last stage whose output the trace keeps, with the guest still alive — means the log
/// covers the job to its very end instead of stopping at the last interval boundary before
/// teardown. The agent does the asking (`vk-agent atop --stop`, like the writable-layer mark
/// above), so the job's own image needs no shell and the pid it signals is confirmed to be
/// the sampler rather than whatever the job left in that file.
///
/// Briefly bounded: nothing about this may hold a job up, and a log one interval short is a
/// far smaller loss than a stage that hangs. Best effort throughout — a guest that is
/// already gone just gets no signal.
async fn finalize_atop(ctx: &JobCtx) {
    let Some(dir) = crate::atop::job_archive_dir(ctx) else {
        return;
    };
    // Output discarded: the guest side has nothing to say that belongs in a job's trace.
    let quiet = OutputSink::Routed(Arc::new(|_fd, _msg| {}));
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        exec_script(
            &vsock_addr(ctx),
            &[
                crate::run::GUEST_AGENT.to_string(),
                "atop".to_string(),
                "--stop".to_string(),
            ],
            Vec::new(),
            // uid 0: the sampler is a child of the guest's PID 1, and a job running as the
            // image's own user could not signal it. The number rather than the name, which
            // an image without a `root` passwd entry would not resolve.
            Some("0".into()),
            &quiet,
            None,
        ),
    )
    .await;
    report_guest(ctx, &dir.join(vk_core::atop::LOG_NAME));
}

/// End the trace with what the job's guest did, folded away.
///
/// The log holds a few hundred lines per interval and the account of it is twenty; those twenty
/// are worth a reader's attention at the end of every job, which is why they are here rather
/// than only in `vk atop --summary`. They go in a collapsed section, so a reader who
/// wants them opens them and everyone else sees one line.
///
/// Silent whenever there is nothing to say — recording off, a guest that died before it
/// finished a sample, a log that will not read — because a job's trace is not the place to
/// report that its accounting was unavailable.
fn report_guest(ctx: &JobCtx, log: &std::path::Path) {
    let Some(body) = crate::atop_report::trace_body(log) else {
        return;
    };
    // The command that opens the same log again, so a reader who wants the samples behind the
    // account knows where they are without a path to copy.
    let header = format!("what the job's guest did (vk atop {})", ctx.job_id);
    // One write: the markers and what they wrap have to reach the trace together, or a section
    // that opens in one chunk and closes in another folds the wrong lines away.
    eprint!("{}", section("vk_atop", &header, &body, now_secs()));
}

/// A GitLab trace section, collapsed: the markers it folds between are exact byte sequences
/// (`\e[0K` before each, a carriage return between marker and text), and a section whose
/// framing is off by one byte is a section GitLab does not fold — it prints the escapes into
/// the log instead. Hence one place that writes them, and a test that reads them back.
///
/// `name` identifies the section to the web UI and may hold only letters, digits, `_`, `.` and
/// `-`; anything else is replaced, since a name GitLab rejects would take the fold with it.
fn section(name: &str, header: &str, body: &str, at: u64) -> String {
    let name: String = name
        .chars()
        .map(
            |c| match c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
                true => c,
                false => '_',
            },
        )
        .collect();
    let body = match body.ends_with('\n') {
        true => body.to_string(),
        false => format!("{body}\n"),
    };
    // Each marker is preceded by the erase-line escape and separated from the text after it by
    // a carriage return: that is the shape GitLab matches on, and the reason this is one
    // format string rather than a few pushes.
    let start = format!("\x1b[0Ksection_start:{at}:{name}[collapsed=true]\r\x1b[0K");
    let end = format!("\x1b[0Ksection_end:{at}:{name}\r\x1b[0K\n");
    format!("{start}{header}\n{body}{end}")
}

/// Now, in seconds since the epoch — what the section markers are stamped with.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
/// egress_report); this reads the whole file at the end of the job and leaves it, which the
/// standing list of names below depends on — it reads the same channel just after. The channel
/// is there either way, so this stays gated on the audit setting rather than on the file.
/// Best-effort: nothing contacted is a silent no-op.
fn report_egress_audit(ctx: &JobCtx) {
    // The channel is written whether or not this job audits (see the switch spawn), so what
    // makes the per-run summary an audit feature is this: without it the trace gets the
    // job's standing list of names, not every resolution of this one run.
    if !ctx.egress_audit() {
        return;
    }
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

/// Print the names this job is known to reach out to — everything its guests have resolved
/// across the runs it has had under the egress policy in force now, this run included (see
/// sites). Unlike the audit summary above, which is one run's resolutions and opt-in, this is
/// the standing list an `[egress] allow_name` is written from, and every job gets it.
///
/// Recorded before the resource lines so the trace ends with what the job cost, which is what
/// most readers are after. Best-effort: a job whose policy will not resolve — one already
/// failed for it — has nothing to stamp a list with, and says nothing.
fn report_contacted_names(ctx: &JobCtx) {
    let Ok((allow_ip, allow_name, restrict)) = crate::vm::effective_run_egress(&ctx.cfg, ctx)
    else {
        return;
    };
    let policy = crate::sites::fingerprint(&allow_ip, &allow_name, restrict);
    let contacted: Vec<String> = crate::egress_report::read_contacts(&ctx.egress_audit_log())
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    if let Some(names) =
        crate::sites::remember(&ctx.sites_dir(), &ctx.usage_key(), &policy, &contacted)
        && let Some(summary) = crate::sites::summary(&names, &policy)
    {
        eprintln!("{summary}");
    }
}

/// Print what the job cost the runner — the CPU time, peak memory, the writable layer it
/// filled, and the disk and network traffic of its microVM and the host helpers around it (see
/// usage) — into the job trace, so a job can be sized from what it actually used. Sampled here
/// rather than at cleanup because this is the last stage whose output the trace still keeps,
/// and the job's processes are all still alive to be read: it therefore covers everything but
/// the guest's own shutdown. Best-effort: a job whose supervisor is already gone (the guest
/// died) reports nothing.
///
/// The same figure is what the next run of this job is admitted against where the host
/// reserves from history (`[schedule] from_history`), so it is recorded here too.
async fn report_resource_usage(ctx: &JobCtx) {
    // Asked of the guest before the tree is read, so the memory marks stay the last thing
    // measured and cover as much of the job as they can.
    let overlay = overlay_mark(ctx).await;
    if let Some(pid) = crate::vm::live_supervisor_pid(ctx)
        && let Some(usage) = crate::usage::tree(pid)
            .map(|u| u.with_network(&ctx.net_bytes_log()).with_overlay(overlay))
    {
        eprintln!("{}", usage.summary("job"));
        // Recorded before it is summarised, so the line below counts this run too, and in the
        // same bytes the line above prints, so one run never reads as two figures. Stamped
        // with the ceiling it ran under, which is what makes a job whose MICROVM_MEM changed
        // start again rather than be predicted from runs it can no longer repeat. A job whose
        // declared size will not parse — or will not fit in bytes — never booted, so there is
        // nothing to remember.
        if let Ok(ceiling_mib) = crate::vm::declared_mem_mib(ctx)
            && let Some(ceiling) = ceiling_mib.checked_mul(1024 * 1024)
        {
            crate::admit::remember(
                &ctx.history_dir(),
                &ctx.usage_key(),
                crate::admit::Run {
                    peak: usage.peak_rss,
                    ceiling,
                    disk: usage.disk,
                    network: usage.network,
                    overlay: usage.overlay,
                },
            );
            report_job_history(ctx, ceiling_mib);
        }
    }
}

/// How full the guest's writable layer got, asked of the guest's own agent (`vk-agent fsmark`):
/// with `[gitlab] checkout_overlay` the job's writes land on a tmpfs inside the VM, which is
/// guest RAM and so invisible to every host counter — the agent is the only thing that can
/// measure it, and it keeps the high-water mark rather than what happens to be left now.
///
/// `None` where there is no such layer to ask about, so a host that mounts the checkout
/// read-write costs no round-trip at all. A guest whose agent predates the subcommand answers
/// non-zero and reads the same way: unmeasured, which is not a layer that stayed empty.
async fn overlay_mark(ctx: &JobCtx) -> Option<(u64, u64)> {
    let gitlab = ctx.cfg.gitlab.as_ref()?;
    if !(gitlab.host_checkout && gitlab.checkout_overlay) {
        return None;
    }
    let out = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = {
        let out = Arc::clone(&out);
        OutputSink::Routed(Arc::new(move |fd, bytes: &[u8]| {
            // stdout only: the subcommand explains itself on stderr when it has no layer to
            // report, and that is prose, not a figure.
            if matches!(fd, Fd::Stdout)
                && let Ok(mut buf) = out.lock()
            {
                buf.extend_from_slice(bytes);
            }
        }))
    };
    let asked = exec_script(
        &vsock_addr(ctx),
        &[crate::run::GUEST_AGENT.to_string(), "fsmark".to_string()],
        Vec::new(),
        None,
        &sink,
        None,
    )
    .await;
    if !matches!(asked, Ok(r) if r.code == Some(0)) {
        return None;
    }
    parse_mark(&out.lock().ok()?)
}

/// The two figures `vk-agent fsmark` prints, `<used> <total>` in bytes. `None` for anything
/// else: a mark read short — or read from a guest answering something else entirely — is no
/// measurement, and reporting half of one as a whole one would understate the layer.
fn parse_mark(out: &[u8]) -> Option<(u64, u64)> {
    let text = std::str::from_utf8(out).ok()?;
    let mut figures = text.split_whitespace();
    let used = figures.next()?.parse().ok()?;
    let total = figures.next()?.parse().ok()?;
    Some((used, total))
}

/// Follow the run's own figures with what runs of this job have been using lately — the
/// number `[schedule] mem_budget` has to be sized against, and what a host reserving from
/// history sizes the next run's reservation from. Printed whether or not the host reserves
/// that way: seeing it is how an operator decides to.
fn report_job_history(ctx: &JobCtx, declared_mib: u64) {
    let schedule = &ctx.cfg.schedule;
    if let Some(line) = crate::admit::history_summary(
        &ctx.history_dir(),
        &ctx.usage_key(),
        declared_mib,
        // The reserve clause only where there is a reservation to promise: `from_history`
        // decides how a job is admitted, but without a budget nothing is admitted at all.
        schedule.from_history && schedule.mem_budget.is_some(),
    ) {
        eprintln!("{line}");
    }
}

/// `MICROVM_USAGE_REPORT`: end the trace with what every job of this project has been using,
/// not just this one. A `when: manual` job carrying the variable is how an operator sizes a
/// project from the GitLab UI, without a shell on the runner. Printed after this run has been
/// recorded, so the job asking is counted in its own report.
///
/// This project exactly, never one whose directory name merely contains it: the job asking
/// may have no sight of the other's pipelines at all. Which project that is comes from the
/// runner's account of the job rather than the variables beside it (see jobctx), so it is
/// not something a job can name for itself.
fn report_project_usage(ctx: &JobCtx) {
    if !ctx.usage_report_req {
        return;
    }
    // This prints a whole project's history into a job's trace, so it goes out only where the
    // project is the runner's word and not the job's. Without a readable job response the
    // identity falls back to `CUSTOM_ENV_CI_PROJECT_*`, which a job sets for itself — and a job
    // could then name another project and read its jobs, peaks and traffic out of its own log.
    if !ctx.identity_from_runner {
        eprintln!(
            "virtkit: not reporting this project's usage: without a readable JOB_RESPONSE_FILE \
             the project is only what this job's own variables claim"
        );
        return;
    }
    match crate::admit::own_project_report(
        &ctx.history_dir(),
        &ctx.usage_project(),
        crate::vm::budget_mib(&ctx.cfg).map(|r| r.map_err(|e| format!("{e:#}"))),
        ctx.cfg.schedule.from_history,
    ) {
        Some(report) => eprint!("{report}"),
        None => eprintln!("virtkit: no job of this project has run on this host yet"),
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

/// A [`tokio::spawn`]ed task aborted when its handle goes out of scope.
///
/// [`exec_script`]'s stdin feeder owns the connection's write half, so an early `?`
/// that merely dropped the handle would leave the task pumping into a socket nobody
/// closes: the guest never sees stdin EOF, the remote process keeps running, and the
/// fd plus the whole script buffer leak. Aborting on drop makes every exit path —
/// including the error ones — tear it down.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> AbortOnDrop<T> {
    fn abort(&self) {
        self.0.abort();
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
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
    let feed_stdin = AbortOnDrop(tokio::spawn(async move {
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
    }));

    let result = loop {
        let msg = match cancel {
            // Race the next guest message against cancellation so a build-wide abort
            // interrupts a long RUN mid-flight instead of waiting for it to finish.
            Some(c) => tokio::select! {
                biased;
                () = c.cancelled() => {
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
    Ok(result)
}

/// The next message from the guest, with the connection falling silent reported as the
/// error it is. Shared with the other exec-channel drivers (`atop_attach`).
pub async fn next(
    stream: &mut (impl futures::Stream<Item = Result<Message, std::io::Error>> + Unpin),
) -> Result<Message> {
    Ok(stream
        .next()
        .await
        .ok_or_else(|| anyhow!("connection to the VM lost"))??)
}

#[cfg(test)]
mod tests {
    use super::{parse_mark, section};

    /// The framing of a collapsed section, byte for byte. GitLab reads these markers with no
    /// tolerance at all: an escape or a carriage return out of place and the section does not
    /// fold — the trace shows the raw markers instead, on every job.
    #[test]
    fn a_section_is_framed_exactly_as_gitlab_reads_it() {
        let out = section(
            "vk_atop",
            "what the job's guest did (vk atop 42137)",
            "one\ntwo\n",
            1_767_225_600,
        );
        assert_eq!(
            out,
            "\x1b[0Ksection_start:1767225600:vk_atop[collapsed=true]\r\x1b[0K\
             what the job's guest did (vk atop 42137)\n\
             one\ntwo\n\
             \x1b[0Ksection_end:1767225600:vk_atop\r\x1b[0K\n"
        );
        // The markers open and close once each, and the body sits between them.
        assert_eq!(out.matches("section_start:").count(), 1);
        assert_eq!(out.matches("section_end:").count(), 1);
        assert!(out.find("one").unwrap() > out.find("section_start:").unwrap());
        assert!(out.find("two").unwrap() < out.find("section_end:").unwrap());
        // Folded by default, and the same name at both ends or the fold never closes.
        assert!(out.contains("[collapsed=true]"));
        assert!(
            out.ends_with('\n'),
            "the next line of the trace starts clean"
        );

        // A body without its own trailing newline still gets one, or the closing marker would
        // land on the end of the last line and be read as part of it.
        let out = section("vk_atop", "head", "no newline", 1);
        assert!(out.contains("no newline\n\x1b[0Ksection_end:"), "{out:?}");

        // A name GitLab would reject takes the fold with it, so it cannot get out.
        let out = section("vk atop/2", "head", "body\n", 7);
        assert!(
            out.contains("section_start:7:vk_atop_2[collapsed=true]"),
            "{out:?}"
        );
        assert!(out.contains("section_end:7:vk_atop_2"), "{out:?}");
    }

    #[test]
    fn the_writable_layer_mark_is_the_two_figures_the_agent_prints() {
        assert_eq!(
            parse_mark(b"10431037440 10737418240\n"),
            Some((10_431_037_440, 10_737_418_240))
        );
    }

    #[test]
    fn anything_but_two_figures_is_no_mark() {
        // The guest is asked over the same channel that runs job scripts, so the reply has to
        // be checked rather than trusted: an agent too old for the subcommand, a shell that
        // wrote a diagnostic to stdout, or a reply cut short all mean "unmeasured" — and half a
        // pair reported as a whole one would understate the layer a job was working in.
        for out in [
            &b""[..],
            b"10431037440",
            b"10431037440 \n",
            b"nine 10737418240",
            b"/proc/self/exe: not found\n",
            b"-1 10737418240",
        ] {
            assert_eq!(
                parse_mark(out),
                None,
                "accepted {:?}",
                String::from_utf8_lossy(out)
            );
        }
    }

    #[test]
    fn a_mark_that_is_not_utf8_is_no_mark() {
        assert_eq!(parse_mark(&[0xff, 0xfe]), None);
    }
}
