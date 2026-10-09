//! For the stages' tests: a server played by a socket, and a job to run stages for.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use vk_hub_proto::job::{CiJob, CiJobInfo};

use super::StageCtx;
use super::trace::Trace;
use super::vars::Vars;
use crate::config::Config;

/// One request as the fake server read it.
#[derive(Debug, Clone)]
pub struct Req {
    pub line: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A server answering each connection with the next of `answers`, one request per
/// connection, recording what it was sent.
pub async fn gitlab(answers: Vec<Vec<u8>>) -> (String, Arc<Mutex<Vec<Req>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        for answer in answers {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let head_end = loop {
                let mut chunk = [0u8; 4096];
                let n = sock.read(&mut chunk).await.unwrap();
                assert!(n > 0, "connection closed mid-request");
                buf.extend_from_slice(&chunk[..n]);
                if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break at;
                }
            };
            let head = String::from_utf8(buf[..head_end].to_vec()).unwrap();
            let mut lines = head.split("\r\n");
            let line = lines.next().unwrap().to_string();
            let headers: Vec<(String, String)> = lines
                .filter_map(|l| l.split_once(": "))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let len: usize = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .map_or(0, |(_, v)| v.parse().unwrap());
            let mut body = buf[head_end + 4..].to_vec();
            while body.len() < len {
                let mut chunk = [0u8; 65536];
                let n = sock.read(&mut chunk).await.unwrap();
                assert!(n > 0, "connection closed mid-body");
                body.extend_from_slice(&chunk[..n]);
            }
            log.lock().unwrap().push(Req {
                line,
                headers,
                body,
            });
            sock.write_all(&answer).await.unwrap();
            sock.shutdown().await.unwrap();
        }
    });
    (format!("http://{addr}"), seen)
}

pub fn answer(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    out
}

/// A job of GitLab's at `server_url`, with a private dir as its scratch and its trace in
/// `output` there, unstamped unless made [`Fixture::stamped`].
pub struct Fixture {
    pub dir: std::path::PathBuf,
    pub cfg: Config,
    pub job: CiJob,
    pub vars: Vars,
    pub trace: Arc<Trace>,
    pub cancel: CancellationToken,
}

impl Fixture {
    pub fn new(tag: &str, server_url: &str) -> Fixture {
        Fixture::with(tag, server_url, false)
    }

    /// A fixture whose trace stamps its lines (`FF_TIMESTAMPS`).
    pub fn stamped(tag: &str, server_url: &str) -> Fixture {
        Fixture::with(tag, server_url, true)
    }

    fn with(tag: &str, server_url: &str, timestamps: bool) -> Fixture {
        // `vk` installs it in main; reqwest needs it for any client.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!("vk-stages-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let trace = Trace::open(&dir.join("output"), &[], &[], 1 << 20, false, timestamps);
        let trace = Arc::new(trace.unwrap());
        let job = CiJob {
            server_url: server_url.into(),
            job: CiJobInfo {
                id: 4242,
                ..CiJobInfo::default()
            },
            token: "glcbt-64_jobtoken123".into(),
            ..CiJob::default()
        };
        let vars = Vars::default();
        Fixture {
            cfg: Config::default(),
            job,
            vars,
            trace,
            cancel: CancellationToken::new(),
            dir,
        }
    }

    pub fn ctx(&self) -> StageCtx<'_> {
        StageCtx {
            cfg: &self.cfg,
            job: &self.job,
            vars: &self.vars,
            addr: vk_core::addr::SocketAddr::Unix(self.dir.join("vsock")),
            user: None,
            project_dir: "/builds/acme/web".into(),
            trace: &self.trace,
            scratch: &self.dir,
            cancel: &self.cancel,
        }
    }

    pub fn output(&self) -> String {
        std::fs::read_to_string(self.dir.join("output")).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
