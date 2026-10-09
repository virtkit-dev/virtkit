//! Moving a job's files in and out of its guest: `vk-agent archive` streams a tar of what a
//! cache or an artifact selects, `vk-agent extract` unpacks one, both over the VM's exec
//! channel, so no archiver needs to be in the job's image. The node does the network side.

use anyhow::{Context, Result, anyhow, bail};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vk_core::addr::SocketAddr;
use vk_core::messages::{CmdExec, Fd, Message, RunMode};

use super::trace::Trace;

/// How much of the input one stdin message carries.
const CHUNK: usize = 64 * 1024;

/// The most of the agent's stderr kept for an error.
const MAX_STDERR: usize = 16 * 1024;

/// What an archive holds, as gitlab-runner's `paths`, `exclude` and `untracked` select it,
/// relative to the project dir.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Selection {
    pub paths: Vec<String>,
    pub exclude: Vec<String>,
    pub untracked: bool,
}

impl Selection {
    /// `vk-agent archive`'s arguments after its root.
    fn args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if self.untracked {
            args.push("--untracked".to_string());
        }
        for pattern in &self.exclude {
            args.push("--exclude".to_string());
            args.push(pattern.clone());
        }
        args.push("--".to_string());
        args.extend(self.paths.iter().cloned());
        args
    }
}

/// Stream a tar of the files `sel` selects under `root` in the guest into `out`, as `user`.
/// Returns how many entries it holds. The agent's warnings (a path matching nothing) and its
/// counts go to `trace`, as gitlab-runner's archiver prints them.
pub async fn archive(
    addr: &SocketAddr,
    user: Option<&str>,
    root: &str,
    sel: &Selection,
    out: &mut (dyn tokio::io::AsyncWrite + Unpin + Send),
    trace: &Trace,
) -> Result<u64> {
    let mut args = vec!["archive".to_string(), root.to_string()];
    args.extend(sel.args());
    let mut entries = TarCounter::default();
    let mut tap = |chunk: &[u8]| {
        entries.feed(chunk);
        Ok(())
    };
    let ended = run(addr, user, args, None, Some((out, &mut tap)), Some(trace)).await?;
    if !ended.ok {
        bail!("vk-agent archive failed: {}", ended.text());
    }
    Ok(entries.entries)
}

/// Unpack the tar read from `input` under `root` in the guest, as `user`.
pub async fn extract(
    addr: &SocketAddr,
    user: Option<&str>,
    root: &str,
    input: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
) -> Result<()> {
    let args = vec!["extract".to_string(), root.to_string()];
    let ended = run(addr, user, args, Some(input), None, None).await?;
    if !ended.ok {
        bail!("vk-agent extract failed: {}", ended.text());
    }
    Ok(())
}

/// How an agent command ended, with the stderr it wrote that was not a trace line.
struct Ended {
    ok: bool,
    stderr: Vec<u8>,
}

impl Ended {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).trim().to_string()
    }
}

/// Where a command's stdout goes, and what sees each chunk on its way.
type Output<'a> = (
    &'a mut (dyn tokio::io::AsyncWrite + Unpin + Send),
    &'a mut (dyn FnMut(&[u8]) -> Result<()> + Send),
);

/// Run the guest's agent with `args`: `input` streamed to its stdin, its stdout to `output`
/// once its tap has passed each chunk, its stderr lines to `trace` when given, else kept for
/// the error.
async fn run(
    addr: &SocketAddr,
    user: Option<&str>,
    args: Vec<String>,
    mut input: Option<&mut (dyn tokio::io::AsyncRead + Unpin + Send)>,
    mut output: Option<Output<'_>>,
    trace: Option<&Trace>,
) -> Result<Ended> {
    let (mut stream, mut sink) = vk_core::net::connect(addr)
        .await
        .context("connecting to the VM's vk-agent")?;
    sink.send(Message::CmdExec(CmdExec {
        name: crate::run::GUEST_AGENT.to_string(),
        args,
        env: vec![],
        clear_env: false,
        mode: RunMode::Interactive,
        dir: None,
        tty: None,
        user: user.map(str::to_string),
    }))
    .await?;
    match next(&mut stream).await? {
        Message::StartOK => {}
        Message::StartErr { msg } => bail!("starting vk-agent in the VM: {msg}"),
        other => bail!("unexpected reply to exec: {other:?}"),
    }
    if input.is_none() {
        sink.send(Message::Close {
            fd: Fd::Stdin,
            error: None,
        })
        .await?;
    }
    let mut stderr = Vec::new();
    let mut line = Vec::new();
    let mut buf = vec![0u8; CHUNK];
    let result = loop {
        let msg = match input.as_mut() {
            // Fed while the output is read, so neither side waits on a full pipe. A read is
            // cancel-safe: a chunk read is sent before the next select.
            Some(reader) => tokio::select! {
                read = reader.read(&mut buf) => {
                    let n = read.context("reading the archive for the guest")?;
                    if n == 0 {
                        input = None;
                        sink.send(Message::Close { fd: Fd::Stdin, error: None }).await?;
                    } else {
                        let msg = buf.get(..n).unwrap_or_default().to_vec();
                        sink.send(Message::Data { fd: Fd::Stdin, msg }).await?;
                    }
                    continue;
                }
                m = next(&mut stream) => m?,
            },
            None => next(&mut stream).await?,
        };
        match msg {
            Message::Data {
                fd: Fd::Stdout,
                msg,
            } => {
                if let Some((out, tap)) = output.as_mut() {
                    tap(&msg)?;
                    out.write_all(&msg)
                        .await
                        .context("writing the guest's archive")?;
                }
            }
            Message::Data {
                fd: Fd::Stderr,
                msg,
            } => match trace {
                Some(trace) => {
                    line.extend_from_slice(&msg);
                    while let Some(end) = line.iter().position(|&b| b == b'\n') {
                        let text: Vec<u8> = line.drain(..=end).collect();
                        report(trace, &text, &mut stderr);
                    }
                }
                None => keep(&mut stderr, &msg),
            },
            // The command exited without draining its stdin: stop feeding it.
            Message::Close { fd: Fd::Stdin, .. } => input = None,
            Message::Close { .. } => {}
            Message::ExecDone(result) => break result,
            other => bail!("unexpected message: {other:?}"),
        }
    };
    if let Some(trace) = trace
        && !line.is_empty()
    {
        report(trace, &line, &mut stderr);
    }
    if let Some((out, _)) = output.as_mut() {
        out.flush().await.context("writing the guest's archive")?;
    }
    Ok(Ended {
        ok: result.code == Some(0),
        stderr,
    })
}

/// One stderr line of the agent's: a warning or a count for the trace, else kept for the
/// error.
fn report(trace: &Trace, line: &[u8], stderr: &mut Vec<u8>) {
    let text = String::from_utf8_lossy(line);
    let text = text.trim_end();
    if let Some(warning) = text.strip_prefix("WARNING: ") {
        trace.warning(warning);
    } else if text.starts_with("archive:") || text.starts_with("usage:") {
        keep(stderr, line);
    } else if !text.is_empty() {
        trace.print(text);
    }
}

fn keep(stderr: &mut Vec<u8>, b: &[u8]) {
    let room = MAX_STDERR.saturating_sub(stderr.len());
    stderr.extend_from_slice(b.get(..b.len().min(room)).unwrap_or_default());
}

async fn next(
    stream: &mut (impl futures::Stream<Item = Result<Message, std::io::Error>> + Unpin),
) -> Result<Message> {
    Ok(stream
        .next()
        .await
        .ok_or_else(|| anyhow!("connection to the VM lost"))??)
}

/// Counts a tar stream's entries as it passes, from their headers: each 512-byte header is
/// followed by its data rounded up to 512; a zero block ends the archive. Only a count for
/// the trace: what parses the stream bounds its headers itself.
#[derive(Default)]
struct TarCounter {
    /// Bytes still to skip: the data of the entry whose header was last read.
    skip: u64,
    header: Vec<u8>,
    entries: u64,
    ended: bool,
}

impl TarCounter {
    fn feed(&mut self, mut b: &[u8]) {
        while !b.is_empty() && !self.ended {
            if self.skip > 0 {
                let n = usize::try_from(self.skip)
                    .unwrap_or(usize::MAX)
                    .min(b.len());
                self.skip -= n as u64;
                b = b.get(n..).unwrap_or_default();
                continue;
            }
            let n = (512 - self.header.len()).min(b.len());
            self.header
                .extend_from_slice(b.get(..n).unwrap_or_default());
            b = b.get(n..).unwrap_or_default();
            if self.header.len() < 512 {
                return;
            }
            let header = std::mem::take(&mut self.header);
            if header.iter().all(|&x| x == 0) {
                self.ended = true;
                return;
            }
            let size = octal(header.get(124..136).unwrap_or_default());
            // GNU long names and pax headers describe the entry after them.
            if !matches!(header.get(156), Some(b'L' | b'K' | b'x' | b'g')) {
                self.entries += 1;
            }
            self.skip = size.div_ceil(512).saturating_mul(512);
        }
    }
}

/// A tar header's size field: octal digits, or GNU's base-256 when its high bit is set.
fn octal(field: &[u8]) -> u64 {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        return field.iter().skip(1).fold(0u64, |n, &b| {
            n.saturating_mul(256).saturating_add(u64::from(b))
        });
    }
    field
        .iter()
        .skip_while(|b| **b == b' ')
        .take_while(|b| (b'0'..=b'7').contains(b))
        .fold(0u64, |n, &b| {
            n.saturating_mul(8).saturating_add(u64::from(b - b'0'))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_are_counted_from_the_stream_whatever_its_chunking() {
        let mut tar = tar::Builder::new(Vec::new());
        for (name, data) in [
            ("a", &b"x"[..]),
            ("dir/b", &[7u8; 1000][..]),
            ("c", &b""[..]),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            tar.append_data(&mut h, name, data).unwrap();
        }
        // A name past 100 bytes takes a GNU long-name header, which is no entry of its own.
        let long = "d/".repeat(60) + "e";
        let mut h = tar::Header::new_gnu();
        h.set_size(3);
        h.set_mode(0o644);
        tar.append_data(&mut h, &long, &b"abc"[..]).unwrap();
        let bytes = tar.into_inner().unwrap();
        for chunk in [1, 7, 512, 513, 4096] {
            let mut count = TarCounter::default();
            for piece in bytes.chunks(chunk) {
                count.feed(piece);
            }
            assert_eq!(count.entries, 4, "chunks of {chunk}");
        }
    }

    #[test]
    fn a_selection_becomes_the_agents_arguments() {
        let sel = Selection {
            paths: vec!["target/".into(), "-odd".into()],
            exclude: vec!["target/tmp/**".into()],
            untracked: true,
        };
        assert_eq!(
            sel.args(),
            [
                "--untracked",
                "--exclude",
                "target/tmp/**",
                "--",
                "target/",
                "-odd"
            ]
        );
    }
}
