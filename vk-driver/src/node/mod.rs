//! `vk node`: this host as a member of a fleet managed by a `vk-hub` (experimental).
//!
//! `vk node join` generates the node's ed25519 identity, passes the `vk check` gate, and
//! enrolls with the hub using a single-use token; `vk node run` then holds a session with the
//! hub for as long as it runs — inventory at the start and whenever it changes, a heartbeat
//! every few seconds — and redials with backoff whenever the session is lost, until SIGTERM
//! or SIGINT closes it (cleanly unless a send to the hub is stuck) or the hub refuses it for
//! good. It applies the desired state and commands the hub sends — a concurrency ceiling,
//! stopping acquisition, drain, quarantine, update, reset — through its persisted state
//! ([`state`]), sets the runner's concurrency every half minute within the hub's ceiling
//! ([`core`]), whether or not a session is up, with `[node] runner = "managed"` runs
//! gitlab-runner itself ([`runner`]), updates its own `vk` on trial ([`update`]), clears
//! what past jobs left ([`reset`]), and builds the CI tools its jobs are given ([`tools`]).
//! `vk node service` installs a systemd unit running it ([`service`]).
//! See `docs/fleet-prototype.md`, "Hub and node".
//!
//! Everything the node keeps is under `<state_dir>/node/`, a `0700` directory: `key.pk8`
//! (the private key, `0600`), `enrollment.json` (the hub's URL and the node ID it assigned),
//! `state.json` (what the hub asked, the node's own state and its command journal),
//! `runner.pid` (a managed runner's pid and start time, for a restarted node to find), `ca.pem`
//! (the CA the hub is verified against, copied at `join` when one was given), `releases/` (a
//! release being installed, and the binary it replaces) and `lock`, which one `vk node`
//! process at a time holds. A `join` whose answer was lost keeps the key it made
//! and joins again with a new token: the hub answers a key it already pinned with the node it
//! pinned it to.
//!
//! Both HTTP paths go straight to the hub, never through `HTTP(S)_PROXY`: the session is a
//! raw socket a proxy variable cannot reach, and enrollment follows the same route rather
//! than handing its token to a proxy.

/// `eprintln!` with the `vk node: ` prefix, minus its panic when stderr cannot be written:
/// `vk node run` outlives whatever its stderr was pointed at, a full log disk included.
macro_rules! say {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        // Nowhere left to report a failed write to.
        let _ = writeln!(std::io::stderr(), "vk node: {}", format_args!($($arg)*));
    }};
}

pub(crate) mod ci_user;
mod core;
mod identity;
mod inventory;
pub mod jobs;
mod reset;
mod runner;
pub mod service;
mod session;
mod state;
pub(crate) mod tools;
mod update;

pub use ci_user::{runner_mode, runner_mode_in};

use std::io::{BufRead, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use vk_hub_proto::{EnrollRequest, EnrollResponse, ErrorBody};

use crate::config::Config;
use identity::Identity;

const ENROLLMENT_FILE: &str = "enrollment.json";
const CA_FILE: &str = "ca.pem";
const LOCK_FILE: &str = "lock";

/// Tries at the lock, 100 ms apart: ten seconds, for a `vk tune` pass holding it shared to end.
const LOCK_TRIES: u32 = 100;

/// The first redial's delay, and the ceiling doubling reaches. A hub restart brings every
/// node back within seconds; a hub down for longer is not helped by being dialed more often.
const BACKOFF: (Duration, Duration) = (Duration::from_secs(1), Duration::from_secs(60));

/// A session that lasted this long was a working one, so the next failure starts the backoff
/// over rather than continuing it.
const STABLE_SESSION: Duration = Duration::from_secs(60);

/// Supersessions in a row after which the node is taken to share its identity with another
/// running node, rather than to be racing its own previous session.
const SUPERSEDED_IN_A_ROW: u32 = 3;

/// How often the node sets its runner's concurrency when nothing prompts it sooner: the
/// half minute `vk tune`'s timer runs at.
const CONTROL_EVERY: Duration = Duration::from_secs(30);

/// How often the node reclaims the staging dirs of builds and pulls that died with their job.
const SWEEP_EVERY: Duration = Duration::from_secs(600);

/// A token or a CA bundle is a few kilobytes at most; this bounds what a wrong file costs.
const MAX_INPUT: u64 = 1 << 20;

/// `vk node run`'s exit status when another `vk node` holds the state dir (`EX_TEMPFAIL`):
/// a supervisor can tell it from a failure and start it again once the other is done.
pub const LOCKED_EXIT: i32 = 75;

/// Another `vk node` holds the state dir's lock.
#[derive(Debug)]
pub struct Locked(String);

impl std::fmt::Display for Locked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Locked {}

/// What `join` leaves for `run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrollment {
    pub hub: String,
    pub node_id: String,
    /// Whether the hub is verified against `ca.pem` alone rather than the system's roots.
    #[serde(default)]
    pub ca: bool,
}

/// Where `join` reads the enrollment token from.
pub enum TokenSource {
    /// Given on the command line, where other local users can read it in the process list.
    Literal(String),
    Stdin,
    File(PathBuf),
}

impl TokenSource {
    fn read(&self) -> Result<String> {
        let text = match self {
            TokenSource::Literal(token) => {
                say!(
                    "warning: a token on the command line is visible to every local user in the \
                     process list; prefer `--token -` or --token-file"
                );
                token.clone()
            }
            // One line, so a token piped from a terminal or a process that keeps its end
            // open is taken without waiting for EOF.
            TokenSource::Stdin => {
                let mut line = String::new();
                std::io::stdin()
                    .lock()
                    .take(MAX_INPUT)
                    .read_line(&mut line)
                    .context("reading the token on stdin")?;
                line
            }
            TokenSource::File(path) => {
                let mut text = String::new();
                std::fs::File::open(path)
                    .and_then(|f| f.take(MAX_INPUT).read_to_string(&mut text))
                    .with_context(|| format!("reading the token from {}", path.display()))?;
                text
            }
        };
        let token = text.trim();
        if token.is_empty() || token.contains(char::is_whitespace) {
            bail!("expected one enrollment token, as `vk-hub token create` prints it");
        }
        Ok(token.to_string())
    }
}

/// `<state_dir>/node`.
fn dir(cfg: &Config) -> PathBuf {
    cfg.state_dir().join("node")
}

/// Whether this host is enrolled as a node.
pub fn enrolled(cfg: &Config) -> bool {
    dir(cfg).join(ENROLLMENT_FILE).exists()
}

/// Add enrollment instructions to `e` when an enrollment file is missing.
fn not_enrolled(e: anyhow::Error) -> anyhow::Error {
    if is_not_found(&e) {
        e.context("this host is not enrolled — run `vk node join <hub-url> --token -`")
    } else {
        e
    }
}

/// What `vk node join` does besides enrolling.
#[derive(Debug, Default)]
pub struct JoinOptions {
    /// Re-enroll a host as a new node, preserving its old identity in a separate directory.
    pub replace: bool,
    /// Set the host up for this user and enroll as it (root only).
    pub user: Option<String>,
    /// Then run the node as a service, stopping one already running first.
    pub service: bool,
    /// Go ahead though the host's CI jobs run as another user than `user`.
    pub ignore_ci_user: bool,
}

/// `vk node join`.
pub async fn join(
    cfg: &Config,
    hub: &str,
    token: &TokenSource,
    ca: Option<&Path>,
    opts: &JoinOptions,
) -> Result<()> {
    // The hub URL is checked, an enrolled host refused and the token read before anything
    // changes on the host.
    let hub = normalize_hub_url(hub)?;
    ci_user::runner_mode(cfg).map_err(anyhow::Error::msg)?;
    if !opts.replace {
        match read_enrollment(&dir(cfg)) {
            Ok(existing) => return Err(already_enrolled(&existing)),
            Err(e) if is_not_found(&e) => {}
            Err(e) => return Err(e),
        }
    }
    let token = token.read()?;
    if let Some(name) = &opts.user {
        service::root_for_user(name)?;
        // Checked as root here, and again as the user by the join run as it.
        host_checks(cfg)?;
        // Check before transferring state ownership hides the executor's user. A managed
        // runner runs as the node, so the transfer also fixes ownership of a former user's state.
        if cfg.node.runner != Some(vk_hub_proto::RunnerMode::Managed) {
            let uid = service::Account::lookup(name)?.map(|a| a.uid);
            service::ci_user_matches(cfg, uid, name, opts.ignore_ci_user)?;
        }
    }
    // A running node holds the state dir; the service is started again if the join fails.
    let stopped = opts.service && service::stop_running()?;
    let mut handed = false;
    let joined = async {
        match opts.user.as_deref() {
            // Enrolled as the user it will run as, by this same command run as that user.
            Some(name) => {
                service::idle_for_join(&dir(cfg), name, opts.service)?;
                let account = service::prepare_account(name, cfg, &mut handed)?;
                service::run_as(&account, &child_args(cfg, &hub, ca, opts.replace)?, &token)?
            }
            None => enroll_here(cfg, &hub, &token, ca, opts.replace).await?,
        }
        if opts.service {
            let timeout = crate::dev::config::parse_duration(service::DEFAULT_STOP_TIMEOUT)?;
            let ci_user = match (&opts.user, opts.ignore_ci_user) {
                // Checked above, or left unchecked there for a managed runner.
                (Some(_), _) => service::CiUser::Checked,
                (None, true) => service::CiUser::Warn,
                (None, false) => service::CiUser::Refuse,
            };
            service::install(cfg, true, timeout, opts.user.as_deref(), ci_user)?;
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(e) = joined {
        if stopped {
            restart_after(cfg, opts.user.as_deref().filter(|_| handed));
        }
        return Err(e);
    }
    if !opts.service && std::env::var_os(service::JOIN_CHILD).is_none() {
        // Only the operator's join prints the next step; the child join leaves it to us.
        println!("vk node: {}", service::next_step(opts.user.as_deref()));
    }
    Ok(())
}

/// Start the node `join` stopped again after the join failed, unless [`why_left_stopped`].
/// `handed_to` is the user the state dir was handed to, if it was.
fn restart_after(cfg: &Config, handed_to: Option<&str>) {
    let enrolled = read_enrollment(&dir(cfg)).is_ok();
    let left = match why_left_stopped(enrolled, handed_to, service::unit_runs_as) {
        Some(why) => why,
        None => match service::start_again() {
            Ok(()) => return,
            Err(e) => format!("{e:#}"),
        },
    };
    println!("vk node: warning: {} stays stopped: {left}", service::UNIT);
}

/// Why a node stopped for a failed join cannot run as it did: a failed `--replace` leaves the
/// node dir without an enrollment, the error saying where the old one went, and once the state
/// dir is handed to `handed_to`, a unit that does not `runs_as` that user may no longer reach it.
fn why_left_stopped(
    enrolled: bool,
    handed_to: Option<&str>,
    runs_as: impl Fn(&str) -> bool,
) -> Option<String> {
    if !enrolled {
        return Some("this host has no enrollment left".to_string());
    }
    let user = handed_to.filter(|user| !runs_as(user))?;
    Some(format!(
        "it runs the node as another user than {user}, to whom the state dir now belongs"
    ))
}

/// That this host passes `vk check`, which a node needs.
fn host_checks(cfg: &Config) -> Result<()> {
    let failed: Vec<String> = inventory::checks(cfg)
        .into_iter()
        .filter(|c| !c.ok)
        .map(|c| format!("{}: {}", c.name, c.detail))
        .collect();
    if !failed.is_empty() {
        bail!(
            "this host fails `vk check`, so it cannot join a fleet:\n  {}",
            failed.join("\n  ")
        );
    }
    Ok(())
}

/// Arguments for the child `vk node join`: pass the token on stdin and make paths absolute
/// because the child runs from `/` as the node's user.
fn child_args(
    cfg: &Config,
    hub: &str,
    ca: Option<&Path>,
    replace: bool,
) -> Result<Vec<std::ffi::OsString>> {
    let absolute =
        |p: &Path| std::path::absolute(p).with_context(|| format!("resolving {}", p.display()));
    let mut args: Vec<std::ffi::OsString> = Vec::new();
    if let Some(config) = &cfg.source {
        args.extend(["--config".into(), absolute(config)?.into()]);
    }
    args.extend(["node".into(), "join".into(), hub.into()]);
    args.extend(["--token".into(), "-".into()]);
    if let Some(ca) = ca {
        args.extend(["--ca".into(), absolute(ca)?.into()]);
    }
    if replace {
        args.push("--replace".into());
    }
    Ok(args)
}

/// Report that `existing` cannot be replaced without `--replace`.
fn already_enrolled(existing: &Enrollment) -> anyhow::Error {
    anyhow!(
        "this host is already enrolled as node {} with {} — pass --replace to enroll it again \
         as a new node, its old identity kept aside",
        existing.node_id,
        existing.hub,
    )
}

/// Enroll this host as the current user, moving any earlier enrollment aside if `replace`.
async fn enroll_here(
    cfg: &Config,
    hub: &str,
    token: &str,
    ca: Option<&Path>,
    replace: bool,
) -> Result<()> {
    let dir = dir(cfg);
    host_checks(cfg)?;
    // Copied, so the node does not depend on a file elsewhere staying where it was, and
    // checked now rather than on the first `run`.
    let ca_pem = match ca {
        Some(path) => {
            let mut pem = Vec::new();
            std::fs::File::open(path)
                .and_then(|f| f.take(MAX_INPUT).read_to_end(&mut pem))
                .with_context(|| format!("reading {}", path.display()))?;
            roots_from_pem(&pem, path)?;
            Some(pem)
        }
        None => None,
    };
    // An enrollment to be replaced is moved aside only once the host passes its checks.
    let (_lock, aside) = make_room(&dir, replace)?;
    let enrolled = async {
        let identity = Identity::load_or_create(&dir)?;
        let public_key = identity.public_key();
        let ask = EnrollRequest {
            token: token.to_string(),
            public_key: vk_hub_proto::to_hex(public_key),
            signature: identity.sign(&vk_hub_proto::enroll_message(token, public_key)),
            hostname: inventory::hostname(),
        };
        let node_id = enroll(hub, ca_pem.as_deref(), &ask).await?;
        if let Some(pem) = &ca_pem {
            let path = dir.join(CA_FILE);
            vk_fs::write_atomic(&path, pem, 0o600)
                .with_context(|| format!("writing {}", path.display()))?;
        }
        let enrollment = Enrollment {
            hub: hub.to_string(),
            node_id: node_id.clone(),
            ca: ca_pem.is_some(),
        };
        let json = serde_json::to_vec_pretty(&enrollment).context("encoding the enrollment")?;
        let path = dir.join(ENROLLMENT_FILE);
        vk_fs::write_atomic(&path, &json, 0o600)
            .with_context(|| format!("writing {}", path.display()))?;
        Ok::<_, anyhow::Error>(node_id)
    }
    .await;
    let node_id = enrolled.map_err(|e| match &aside {
        Some(aside) => e.context(format!(
            "the old identity is in {}: replace {} with it to stay the node it was",
            aside.display(),
            dir.display()
        )),
        None => e,
    })?;
    println!("vk node: enrolled with {hub} as node {node_id}");
    Ok(())
}

/// Lock `dir` and ensure it holds no enrollment. Refuse an existing enrollment unless
/// `replace` is set; then move it to a unique sibling `node.replaced-<time>` and recreate
/// `dir`. Return the lock and the previous enrollment's location.
fn make_room(dir: &Path, replace: bool) -> Result<(std::fs::File, Option<PathBuf>)> {
    create_dir(dir)?;
    let lock = lock(dir).map_err(|e| {
        if e.is::<Locked>() {
            e.context(
                "a node is running on this host: stop it first (`systemctl stop vk-node`), or \
                 pass --service, which stops it and starts it again once enrolled",
            )
        } else {
            e
        }
    })?;
    let existing = match read_enrollment(dir) {
        Ok(existing) => existing,
        Err(e) if is_not_found(&e) => return Ok((lock, None)),
        Err(e) => return Err(e),
    };
    if !replace {
        return Err(already_enrolled(&existing));
    }
    // Only a join holding this lock names these, so a name found free stays free; a rename
    // onto an empty directory would replace it, hence the check.
    let stem = format!("node.replaced-{}", session::now_secs());
    let aside = (0..)
        .map(|n| match n {
            0 => dir.with_file_name(&stem),
            n => dir.with_file_name(format!("{stem}.{n}")),
        })
        .find(|p| {
            std::fs::symlink_metadata(p).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        })
        .expect("an unbounded range");
    std::fs::rename(dir, &aside)
        .with_context(|| format!("moving {} aside to {}", dir.display(), aside.display()))?;
    println!(
        "vk node: moved this host's previous enrollment, node {} of {}, to {}",
        existing.node_id,
        existing.hub,
        aside.display()
    );
    println!(
        "vk node: {} still lists that node; remove it there: `vk-hub nodes remove {}`",
        existing.hub, existing.node_id
    );
    // The old lock moved with its dir; a node starting meanwhile finds the new one taken.
    create_dir(dir)?;
    let new = self::lock(dir)?;
    drop(lock);
    Ok((new, Some(aside)))
}

/// `POST /v1/enroll`, answering with the node ID the hub assigned.
async fn enroll(hub: &str, ca_pem: Option<&[u8]>, ask: &EnrollRequest) -> Result<String> {
    // TLS 1.3 like the session, and no redirect: the token goes to the hub named and nowhere
    // else.
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .tls_version_min(reqwest::tls::Version::TLS_1_3);
    if let Some(pem) = ca_pem {
        let certs =
            reqwest::Certificate::from_pem_bundle(pem).context("reading the CA certificates")?;
        builder = builder.tls_certs_only(certs);
    }
    let client = builder.build().context("building the HTTPS client")?;
    let url = format!("{hub}{}", vk_hub_proto::ENROLL_PATH);
    let mut resp = client
        .post(&url)
        .json(ask)
        .send()
        .await
        .with_context(|| format!("enrolling with {hub}"))?;
    let status = resp.status();
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("reading the hub's answer")? {
        if body.len().saturating_add(chunk.len()) > vk_hub_proto::MAX_MESSAGE {
            bail!(
                "the hub's answer is larger than {} bytes",
                vk_hub_proto::MAX_MESSAGE
            );
        }
        body.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        let why = serde_json::from_slice::<ErrorBody>(&body)
            .map(|e| vk_hub_proto::display_safe(&e.error))
            .unwrap_or_else(|_| format!("HTTP {status}"));
        bail!("the hub refused the enrollment: {why}");
    }
    let answer: EnrollResponse =
        serde_json::from_slice(&body).context("the hub's enrollment answer is malformed")?;
    if !vk_hub_proto::valid_id(&answer.node_id) {
        bail!(
            "the hub assigned a malformed node ID {:?}",
            vk_hub_proto::display_safe(&answer.node_id)
        );
    }
    Ok(answer.node_id)
}

/// `vk node run`: hold a session with the hub, redialing until told to stop. Fails on a local
/// problem no redial can fix — no enrollment, an unreadable key — and when the hub refuses
/// the node for good (removed, or not the key it pinned).
pub async fn run(cfg: Config) -> Result<()> {
    let dir = dir(&cfg);
    check_private(&dir).map_err(not_enrolled)?;
    let _lock = lock(&dir).map_err(not_enrolled)?;
    // Before anything else: this may be the previous binary of an update on trial, whose part
    // is to count the attempt and hand over, or to take the node back.
    match update::on_start(&dir, session::now_secs())? {
        update::Start::Run => {}
        update::Start::Exec(binary, alarm_at) => {
            drop(_lock);
            return Err(update::exec(&binary, alarm_at));
        }
    }
    update::arm_trial_deadline(&dir, session::now_secs())?;
    update::note_installed(&dir)?;
    let enrollment = read_enrollment(&dir).map_err(not_enrolled)?;
    inventory::labels(&cfg)?;
    let local_runner = ci_user::local_runner(&cfg);
    // A host that says it runs no runner but does would take the hub's jobs beside its own
    // and let a reset clear that runner's jobs: refused outright rather than half-trusted.
    let visible = local_runner.is_some() || ci_user::runner_visible(&ci_user::SYSTEMD_PATH);
    let mode = ci_user::runner_mode_of(cfg.node.runner, local_runner.as_deref(), visible)
        .map_err(anyhow::Error::msg)?;
    if let Some(why) = ci_user::this_node(&cfg) {
        say!("warning: {why}");
    }
    if let Some(why) = tools::unused_warning(&cfg) {
        say!("warning: {why}");
    }
    let identity = Identity::load(&dir).with_context(|| {
        format!(
            "loading the node's identity ({})",
            identity::key_path(&dir).display()
        )
    })?;
    let tls = client_tls(enrollment.ca.then(|| dir.join(CA_FILE)).as_deref())?;
    let mut incarnation = [0u8; vk_hub_proto::ID_BYTES];
    fill_random(&mut incarnation)?;
    let incarnation = vk_hub_proto::to_hex(&incarnation);
    say!(
        "node {} of {}, incarnation {incarnation}",
        enrollment.node_id,
        enrollment.hub
    );
    let spec = match mode {
        vk_hub_proto::RunnerMode::Managed => {
            let config = crate::schedule::runner_config(&cfg).context(
                "[node] runner = \"managed\" needs [node] runner_config, or HOME for the default",
            )?;
            warn_on_executor_config(&cfg, &config);
            Some(runner::Spec {
                binary: cfg
                    .node
                    .gitlab_runner
                    .clone()
                    .unwrap_or_else(|| PathBuf::from("gitlab-runner")),
                config,
                dir: dir.clone(),
            })
        }
        vk_hub_proto::RunnerMode::External | vk_hub_proto::RunnerMode::None => None,
    };
    let (mut stop, abort) = stop_on_signal(spec.is_some())?;
    let issuer = state::Issuer {
        hub: enrollment.hub.clone(),
        node_id: enrollment.node_id.clone(),
    };
    let (runner_tx, runner_state) = tokio::sync::watch::channel(vk_hub_proto::RunnerState::Stopped);
    let policy =
        crate::release_key::Policy::from_config(&cfg.node.release_keys, cfg.node.require_signed)?;
    let runner = match mode {
        vk_hub_proto::RunnerMode::Managed => core::Runner::Managed(runner_state),
        vk_hub_proto::RunnerMode::External => core::Runner::External,
        vk_hub_proto::RunnerMode::None => core::Runner::None,
    };
    let core = core::Core::open(&dir, issuer, runner)?;
    core.set_allow_downgrade(cfg.node.allow_downgrade);
    core.set_release_policy(policy);
    core.set_placed(vk_hub_proto::PlacedIntake {
        runner: local_runner,
        limit: (cfg.executor.schedule.max_concurrency).map(std::num::NonZeroU32::get),
    });
    let (halt, halted) = tokio::sync::watch::channel(false);
    let supervisor = spec.map(|spec| {
        let signals = runner::Signals {
            allowed: core.acquire(),
            halt: halted,
            abort,
        };
        tokio::spawn(runner::supervise(spec, signals, runner_tx))
    });
    let cfg = Arc::new(cfg);
    tokio::spawn(
        core.clone()
            .control(cfg.clone(), CONTROL_EVERY, stop.clone()),
    );
    // Read now, so the first inventory carries it and no session waits on it.
    if tokio::task::spawn_blocking(update::own_sha256)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        say!("warning: cannot read the running vk to report its sha256");
    }
    let mut gatherer = session::Gatherer::spawn(cfg.clone());
    let jobs = jobs::Jobs::open(&dir, cfg.clone()).context("reading the placed jobs")?;
    let node = Arc::new(session::Node {
        dir,
        jobs,
        enrollment,
        core: core.clone(),
        identity,
        incarnation,
        tls,
    });
    tokio::spawn(tools::maintain(
        core.clone(),
        cfg.clone(),
        node.clone(),
        stop.clone(),
    ));
    tokio::spawn(sweep_node_caches(cfg.clone(), stop.clone()));
    tokio::spawn(update::maintain(core, cfg, node.clone(), stop.clone()));
    let ended = hold_sessions(&node, &mut gatherer, &mut stop).await;
    // Stopping, or refused for good, the node quits a managed runner and waits for its jobs to
    // finish: a node its hub no longer knows should not go on taking the fleet's work, and a
    // runner left running would be one nothing steers.
    if let Some(supervisor) = supervisor {
        // `send_replace`: raised whether or not the supervisor still listens.
        halt.send_replace(true);
        say!(
            "waiting for gitlab-runner to finish its jobs (SIGTERM or SIGINT again abandons them)"
        );
        if let Err(e) = supervisor.await {
            say!("the runner supervisor failed: {e}");
        }
    }
    ended
}

/// Warn when the managed runner's config runs the vk executor with another vk config than
/// this node's own: the node tells a drain is done from the admission ledger and the job dirs
/// under its own state dir, so the executor must be keeping them there. Only what is cheap to
/// read is compared — a `--config` among a custom executor's arguments, or a `VIRTKIT_CONFIG`
/// in a runner's environment — and only when it names a file.
fn warn_on_executor_config(cfg: &Config, runner_config: &Path) {
    let Ok(text) = std::fs::read_to_string(runner_config) else {
        return;
    };
    let ours = cfg
        .source
        .as_deref()
        .and_then(|p| std::fs::canonicalize(p).ok());
    for (runner, named) in executor_configs(&text) {
        let theirs = std::fs::canonicalize(&named).ok();
        if theirs.is_none() || theirs != ours {
            say!(
                "warning: runner {runner:?} in {} runs the vk executor with the config {}, \
                 while this node reads {}: drains are judged from this node's state dir, which \
                 the executor must be using too",
                runner_config.display(),
                named.display(),
                ours.as_deref().map_or_else(
                    || "the built-in defaults".to_string(),
                    |p| p.display().to_string()
                ),
            );
        }
    }
}

/// Each custom-executor runner in a gitlab-runner config that names a vk config: its name and
/// the file.
fn executor_configs(text: &str) -> Vec<(String, PathBuf)> {
    let Ok(table) = toml::from_str::<toml::Table>(text) else {
        return Vec::new();
    };
    let runners = table
        .get("runners")
        .and_then(toml::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let mut out = Vec::new();
    for runner in runners {
        if runner.get("executor").and_then(toml::Value::as_str) != Some("custom") {
            continue;
        }
        let name = runner
            .get("name")
            .and_then(toml::Value::as_str)
            .unwrap_or("")
            .to_string();
        let from_env = runner
            .get("environment")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
            .filter_map(|e| e.strip_prefix("VIRTKIT_CONFIG="));
        let from_args = runner
            .get("custom")
            .and_then(toml::Value::as_table)
            .into_iter()
            .flat_map(|custom| custom.iter())
            .filter(|(key, _)| key.ends_with("_args"))
            .filter_map(|(_, args)| args.as_array())
            .filter_map(|args| {
                let args: Vec<&str> = args.iter().filter_map(toml::Value::as_str).collect();
                args.iter()
                    .position(|a| *a == "--config")
                    .and_then(|at| args.get(at + 1).copied())
            });
        let mut named: Vec<&str> = from_env.chain(from_args).collect();
        named.sort_unstable();
        named.dedup();
        out.extend(named.into_iter().map(|p| (name.clone(), PathBuf::from(p))));
    }
    out
}

/// Sessions back to back, with backoff between them, until the node is told to stop or the
/// hub refuses it for good.
async fn hold_sessions(
    node: &session::Node,
    gatherer: &mut session::Gatherer,
    stop: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut backoff = BACKOFF.0;
    let mut superseded = 0u32;
    loop {
        let started = Instant::now();
        match session::run(node, gatherer, stop).await {
            Ok(()) => {
                say!("stopped");
                return Ok(());
            }
            Err(e) if e.is::<session::Permanent>() => return Err(e),
            Err(e) => {
                say!("{e:#}");
                superseded = if e.is::<session::Superseded>() {
                    superseded.saturating_add(1)
                } else {
                    0
                };
            }
        }
        if started.elapsed() >= STABLE_SESSION {
            backoff = BACKOFF.0;
        }
        // Each session taking over from the other's: two running nodes share this identity,
        // and redialing quickly only keeps them trading places.
        if superseded >= SUPERSEDED_IN_A_ROW {
            if superseded == SUPERSEDED_IN_A_ROW {
                say!(
                    "warning: the hub keeps handing this node's session to another — a \
                     `vk node run` on another host with a copy of this state dir? Each host \
                     needs a node identity of its own; redialing every {}s meanwhile",
                    BACKOFF.1.as_secs()
                );
            }
            backoff = BACKOFF.1;
        }
        let delay = jittered(backoff);
        say!("reconnecting in {}s", delay.as_secs());
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            () = session::stopped(stop) => {
                say!("stopped");
                return Ok(());
            }
        }
        backoff = (backoff * 2).min(BACKOFF.1);
    }
}

/// Reclaim the staging dirs of builds and pulls that died with their job — a job killed with
/// the node service, cancelled, or on a node taken out of its pool runs no cleanup — and the
/// built and pulled images no job has used for `image_cache_idle_secs`, now and every
/// [`SWEEP_EVERY`] until `stop`. Both sit on the jobs' filesystem, whose free space the hub
/// places by; without this, idle images went only when a job missed the cache. Only the first
/// sweep names the dead staging dirs it has to leave; an image it fails to evict is reported
/// when it fails.
async fn sweep_node_caches(cfg: Arc<Config>, mut stop: tokio::sync::watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(SWEEP_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut leftovers = crate::image::Leftovers::Name;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            () = session::stopped(&mut stop) => return,
        }
        let cfg = cfg.clone();
        // Off the runtime: it walks and removes trees.
        let swept = tokio::task::spawn_blocking(move || {
            crate::image::sweep_orphaned_staging(cfg.state_dir(), leftovers);
            crate::image::evict_idle_images(cfg.state_dir(), cfg.image_cache_idle());
        });
        leftovers = crate::image::Leftovers::Quiet;
        if let Err(e) = swept.await {
            say!("sweeping the image caches failed: {e}");
        }
    }
}

/// Two flags: `stop`, raised by the first SIGTERM or SIGINT, for the session to close on and a
/// managed runner to be quit; `abort`, raised by the second. Without a managed runner, the
/// second one exits at once, for a close the hub is not taking; with one, `abort` has the
/// runner sent SIGTERM, which abandons its jobs, and `vk node run` returns once it has exited.
/// A third exits at once, for a runner that does not.
///
/// A service manager that signals every process of the unit reaches gitlab-runner too, which
/// takes SIGTERM as abandoning its jobs: a unit running `vk node run` with a managed runner
/// wants `KillMode=mixed`, so that the stop reaches the node alone and the node quits the
/// runner.
fn stop_on_signal(managed: bool) -> Result<(Flag, Flag)> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).context("handling SIGTERM")?;
    let mut int = signal(SignalKind::interrupt()).context("handling SIGINT")?;
    let (raise_stop, stop) = tokio::sync::watch::channel(false);
    let (raise_abort, abort) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
        // `send_replace`: raised whether or not anything still listens.
        raise_stop.send_replace(true);
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
        if managed {
            raise_abort.send_replace(true);
            // A third leaves at once, whatever the runner is doing.
            tokio::select! {
                _ = term.recv() => {}
                _ = int.recv() => {}
            }
            say!("stopped without waiting for gitlab-runner to exit");
        } else {
            say!("stopped without closing the session");
        }
        std::process::exit(1);
    });
    Ok((stop, abort))
}

/// Shared lock on the node's state dir for a `vk tune` pass, preventing `vk node run` from
/// starting mid-pass. Holds nothing on a host without a node.
pub struct TuneClaim {
    _lock: Option<std::fs::File>,
}

/// Claim the concurrency for `vk tune`, or `None` when a `vk node` holds this host's node
/// state dir: `vk node run` is then the one concurrency writer.
pub fn claim_tuning(cfg: &Config) -> Result<Option<TuneClaim>> {
    let path = dir(cfg).join(LOCK_FILE);
    let file = match std::fs::File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Some(TuneClaim { _lock: None }));
        }
        Err(e) => return Err(e).with_context(|| format!("opening {}", path.display())),
    };
    // SAFETY: the fd is owned by `file`, which outlives the call; flock returns 0 or -1.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0 {
        return Ok(Some(TuneClaim { _lock: Some(file) }));
    }
    let e = std::io::Error::last_os_error();
    if e.kind() == std::io::ErrorKind::WouldBlock {
        return Ok(None);
    }
    Err(e).with_context(|| format!("probing {}", path.display()))
}

/// Last persisted hub concurrency ceiling, or `None` without a fleet enrollment or when the
/// state belongs to another enrollment. The next `vk node run` forgets that old ceiling.
pub fn hub_ceiling(cfg: &Config) -> Result<Option<u32>> {
    let dir = dir(cfg);
    let enrollment = match read_enrollment(&dir) {
        Ok(e) => e,
        Err(e) if is_not_found(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    let persisted = state::Persisted::load(&dir)?;
    let issuer = state::Issuer {
        hub: enrollment.hub,
        node_id: enrollment.node_id,
    };
    Ok(if persisted.issuer.as_ref() == Some(&issuer) {
        persisted.hub_ceiling()
    } else {
        None
    })
}

type Flag = tokio::sync::watch::Receiver<bool>;

/// Hold `<dir>/lock` for as long as the returned file lives: one `vk node` process per state
/// dir, since two would supersede each other's sessions at the hub, or pair a key with an
/// enrollment made for another.
fn lock(dir: &Path) -> Result<std::fs::File> {
    lock_tries(dir, LOCK_TRIES)
}

/// [`lock`] with `tries` attempts 100 ms apart, so a shared lock held for one `vk tune` pass
/// is not mistaken for another node.
fn lock_tries(dir: &Path, tries: u32) -> Result<std::fs::File> {
    let path = dir.join(LOCK_FILE);
    let file = std::fs::File::options()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|e| anyhow::Error::new(e).context(format!("opening {}", path.display())))?;
    for attempt in 0..tries {
        // SAFETY: the fd is owned by `file`, which outlives the call; flock returns 0 or -1.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(file);
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::WouldBlock {
            return Err(e).with_context(|| format!("locking {}", path.display()));
        }
        if attempt + 1 < tries {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    Err(anyhow::Error::new(Locked(format!(
        "another `vk node` is running on {} — one at a time per state dir",
        dir.display()
    ))))
}

/// `d` plus up to a quarter more, so a fleet that lost its hub together does not redial it
/// in lockstep.
fn jittered(d: Duration) -> Duration {
    let mut b = [0u8; 2];
    let spread = fill_random(&mut b)
        .map(|()| u32::from(u16::from_le_bytes(b)))
        .unwrap_or(0);
    d + d / 4 * spread / u32::from(u16::MAX)
}

/// The certificates of a PEM bundle, refusing one that holds none.
fn roots_from_pem(pem: &[u8], origin: &Path) -> Result<rustls::RootCertStore> {
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(pem) {
        let cert =
            cert.with_context(|| format!("reading certificates from {}", origin.display()))?;
        roots
            .add(cert)
            .with_context(|| format!("adding a CA certificate from {}", origin.display()))?;
    }
    if roots.is_empty() {
        bail!("{} holds no certificate", origin.display());
    }
    Ok(roots)
}

/// Verify sessions against the CA copied at `join` alone, if supplied: a private-CA hub
/// must not also be trusted through public roots. Otherwise use the platform verifier,
/// like `vk`'s other HTTPS clients.
fn client_tls(ca: Option<&Path>) -> Result<Arc<rustls::ClientConfig>> {
    // TLS 1.3 only: the auth signs the connection's exporter, which TLS 1.2 ties to the
    // handshake only with the extended master secret (RFC 7627).
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .context("building the TLS client config")?;
    let config = match ca {
        Some(path) => {
            let pem = read_nofollow(path)?;
            builder
                .with_root_certificates(roots_from_pem(&pem, path)?)
                .with_no_client_auth()
        }
        None => {
            use rustls_platform_verifier::BuilderVerifierExt;
            builder
                .with_platform_verifier()
                .context("loading the platform's TLS verifier")?
                .with_no_client_auth()
        }
    };
    Ok(Arc::new(config))
}

/// The hub's URL without a trailing slash, checked: `https`, or `http` to a loopback hub —
/// the hub refuses cleartext off loopback, and a node should not send its enrollment token
/// that way either — and nothing but scheme, host and port.
fn normalize_hub_url(hub: &str) -> Result<String> {
    let url = reqwest::Url::parse(hub).with_context(|| format!("parsing the hub URL {hub:?}"))?;
    let host = url.host_str().context("the hub URL has no host")?;
    let loopback = host == "localhost"
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        "http" => bail!("{hub}: a hub off loopback is reached over https"),
        other => bail!("{hub}: expected an https URL, not {other}"),
    }
    if url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("{hub}: give the hub's base URL, scheme://host[:port]");
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

/// `enrollment.json`, held to what `join` writes: the file is the node's own, but a hand
/// edit should not reach the dialer or the hub unchecked.
fn read_enrollment(dir: &Path) -> Result<Enrollment> {
    let path = dir.join(ENROLLMENT_FILE);
    let text = read_nofollow(&path)?;
    let mut enrollment: Enrollment =
        serde_json::from_slice(&text).with_context(|| format!("parsing {}", path.display()))?;
    enrollment.hub = normalize_hub_url(&enrollment.hub)
        .with_context(|| format!("checking {}", path.display()))?;
    if !vk_hub_proto::valid_id(&enrollment.node_id) {
        bail!(
            "{} holds a malformed node ID {:?}",
            path.display(),
            vk_hub_proto::display_safe(&enrollment.node_id)
        );
    }
    Ok(enrollment)
}

/// A file of the node's, up to [`MAX_INPUT`], refusing a symlink in its place. A missing one
/// is an `io::Error` of kind `NotFound` at the root of the chain.
fn read_nofollow(path: &Path) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    std::fs::File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .and_then(|f| f.take(MAX_INPUT).read_to_end(&mut buf))
        .map_err(|e| anyhow::Error::new(e).context(format!("reading {}", path.display())))?;
    Ok(buf)
}

fn is_not_found(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}

/// `dir`, `0700` — it holds the node's private key — and [`check_private`].
fn create_dir(dir: &Path) -> Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    check_private(dir)
}

/// Check that `dir` is private to this process's effective uid, using [`check_private_to`].
fn check_private(dir: &Path) -> Result<()> {
    // SAFETY: `geteuid` reads this process's own id and cannot fail.
    check_private_to(dir, unsafe { libc::geteuid() })
}

/// That `dir` is a directory of `uid`'s that nobody else can enter, judged off a descriptor
/// opened without following a symlink. A missing one is an `io::Error` of kind `NotFound` at
/// the root of the chain.
fn check_private_to(dir: &Path, uid: u32) -> Result<()> {
    let meta = std::fs::File::from(vk_fs::open_dir_nofollow(dir)?)
        .metadata()
        .with_context(|| format!("statting {}", dir.display()))?;
    if meta.uid() != uid || meta.mode() & 0o077 != 0 {
        bail!(
            "{} must belong to uid {uid} and be private to it (chmod 700); it is uid {} with \
             mode {:o}",
            dir.display(),
            meta.uid(),
            meta.mode() & 0o7777
        );
    }
    Ok(())
}

fn fill_random(buf: &mut [u8]) -> Result<()> {
    use ring::rand::SecureRandom;
    ring::rand::SystemRandom::new()
        .fill(buf)
        .map_err(|_| anyhow!("the system random number generator failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_executor_config_a_runner_names_is_found() {
        let text = r#"
concurrent = 4
[[runners]]
  name = "vk"
  executor = "custom"
  environment = ["VIRTKIT_CONFIG=/etc/virtkit/ci.toml", "OTHER=1"]
  [runners.custom]
    prepare_exec = "/usr/local/bin/vk"
    prepare_args = ["--config", "/etc/virtkit/ci.toml", "gitlab", "prepare"]
    run_args = ["gitlab", "run"]
[[runners]]
  name = "docker"
  executor = "docker"
  environment = ["VIRTKIT_CONFIG=/elsewhere.toml"]
"#;
        assert_eq!(
            executor_configs(text),
            [("vk".to_string(), PathBuf::from("/etc/virtkit/ci.toml"))]
        );
        assert!(executor_configs("not toml [").is_empty());
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-node-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn hub_urls_are_https_or_loopback_http_and_bare() {
        assert_eq!(
            normalize_hub_url("https://hub.example.com/").unwrap(),
            "https://hub.example.com"
        );
        assert_eq!(
            normalize_hub_url("https://hub:8443").unwrap(),
            "https://hub:8443"
        );
        assert_eq!(
            normalize_hub_url("http://127.0.0.1:8443").unwrap(),
            "http://127.0.0.1:8443"
        );
        assert!(normalize_hub_url("http://[::1]:8443").is_ok());
        assert!(normalize_hub_url("http://localhost:8443").is_ok());
        for bad in [
            "http://hub.example.com",
            "ftp://hub",
            "https://hub/v1",
            "https://u@hub",
            "https://:p@hub",
            "https://hub/?x=1",
            "https://hub/#top",
            "hub:8443",
        ] {
            assert!(normalize_hub_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn jitter_stays_within_a_quarter() {
        for _ in 0..100 {
            let d = jittered(Duration::from_secs(8));
            assert!(
                d >= Duration::from_secs(8) && d <= Duration::from_secs(10),
                "{d:?}"
            );
        }
    }

    #[test]
    fn an_enrolled_host_is_enrolled_again_only_when_asked_its_old_identity_kept() {
        let parent = scratch("replace");
        let dir = parent.join("node");
        drop(make_room(&dir, false).unwrap());
        let e = Enrollment {
            hub: "https://old".into(),
            node_id: "cd".repeat(16),
            ca: false,
        };
        std::fs::write(dir.join(ENROLLMENT_FILE), serde_json::to_vec(&e).unwrap()).unwrap();
        let refused = make_room(&dir, false).unwrap_err().to_string();
        assert!(
            refused.contains("--replace") && refused.contains(&e.node_id),
            "{refused}"
        );
        let (lock, moved) = make_room(&dir, true).unwrap();
        assert!(is_not_found(&read_enrollment(&dir).unwrap_err()));
        let aside: Vec<_> = std::fs::read_dir(&parent)
            .unwrap()
            .map(|d| d.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("node.replaced-")
            })
            .collect();
        assert_eq!(aside, [moved.unwrap()]);
        assert_eq!(read_enrollment(&aside[0]).unwrap(), e);
        // The new dir is held: no other node can take it until the join is done.
        assert!(lock_tries(&dir, 1).is_err());
        drop(lock);
        // Replaced again within the same second, it is moved aside under a name of its own:
        // neither an earlier identity nor an empty directory in the way is replaced.
        let first = aside[0].clone();
        let empty = PathBuf::from(format!("{}.1", first.display()));
        std::fs::create_dir(&empty).unwrap();
        let mut moved = Vec::new();
        for _ in 0..2 {
            std::fs::write(dir.join(ENROLLMENT_FILE), serde_json::to_vec(&e).unwrap()).unwrap();
            let (lock, aside) = make_room(&dir, true).unwrap();
            drop(lock);
            moved.push(aside.unwrap());
        }
        assert!(!moved.contains(&first) && !moved.contains(&empty) && moved[0] != moved[1]);
        for p in moved.iter().chain([&first]) {
            assert_eq!(read_enrollment(p).unwrap(), e);
        }
        assert_eq!(std::fs::read_dir(&empty).unwrap().count(), 0);
        std::fs::remove_dir_all(&parent).unwrap();
    }

    #[test]
    fn a_node_stopped_for_a_failed_join_restarts_unless_it_can_no_longer_run() {
        let as_ci = |user: &str| user == "ci";
        assert_eq!(why_left_stopped(true, None, as_ci), None);
        assert_eq!(why_left_stopped(true, Some("ci"), as_ci), None);
        let why = why_left_stopped(true, Some("other"), as_ci).unwrap();
        assert!(why.contains("another user than other"), "{why}");
        let why = why_left_stopped(false, None, as_ci).unwrap();
        assert!(why.contains("no enrollment"), "{why}");
    }

    #[test]
    fn a_join_as_another_user_passes_absolute_paths_and_replace_on() {
        let cfg = Config {
            source: Some(PathBuf::from("vk.toml")),
            ..Config::default()
        };
        let cwd = std::env::current_dir().unwrap();
        let args = child_args(&cfg, "https://hub", Some(Path::new("ca.pem")), true).unwrap();
        let want: Vec<std::ffi::OsString> = vec![
            "--config".into(),
            cwd.join("vk.toml").into(),
            "node".into(),
            "join".into(),
            "https://hub".into(),
            "--token".into(),
            "-".into(),
            "--ca".into(),
            cwd.join("ca.pem").into(),
            "--replace".into(),
        ];
        assert_eq!(args, want);
        let args = child_args(&Config::default(), "https://hub", None, false).unwrap();
        assert_eq!(args, ["node", "join", "https://hub", "--token", "-"]);
    }

    #[test]
    fn an_enrollment_round_trips_and_a_missing_one_is_not_found() {
        let dir = scratch("enroll");
        assert!(is_not_found(&read_enrollment(&dir).unwrap_err()));
        let e = Enrollment {
            hub: "https://hub".into(),
            node_id: "ab".repeat(16),
            ca: true,
        };
        std::fs::write(dir.join(ENROLLMENT_FILE), serde_json::to_vec(&e).unwrap()).unwrap();
        assert_eq!(read_enrollment(&dir).unwrap(), e);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn one_vk_node_holds_a_state_dir_at_a_time() {
        let dir = scratch("lock");
        let held = lock(&dir).unwrap();
        let err = lock_tries(&dir, 1).unwrap_err();
        assert!(err.is::<Locked>());
        assert!(format!("{err:#}").contains("another `vk node`"), "{err:#}");
        drop(held);
        crate::testutil::once_released("another `vk node`", || lock(&dir)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn vk_tune_stands_aside_for_a_running_node_and_takes_its_ceiling() {
        let root = scratch("tune");
        let cfg: Config =
            toml::from_str(&format!("state_dir = {:?}\n", root.display().to_string())).unwrap();
        assert!(claim_tuning(&cfg).unwrap().is_some());
        assert_eq!(hub_ceiling(&cfg).unwrap(), None);
        let node = dir(&cfg);
        create_dir(&node).unwrap();
        let enrollment = Enrollment {
            hub: "https://hub".into(),
            node_id: "ab".repeat(16),
            ca: false,
        };
        std::fs::write(
            node.join(ENROLLMENT_FILE),
            serde_json::to_vec(&enrollment).unwrap(),
        )
        .unwrap();
        let ceiling_from = |hub: &str| {
            let mut persisted = state::Persisted::default();
            persisted.adopt_issuer(state::Issuer {
                hub: hub.into(),
                node_id: enrollment.node_id.clone(),
            });
            persisted.apply_desired(vk_hub_proto::DesiredState {
                generation: 1,
                ceiling: Some(3),
                acquisition: vk_hub_proto::Acquisition::Run,
            });
            persisted.save(&node).unwrap();
            hub_ceiling(&cfg).unwrap()
        };
        assert_eq!(ceiling_from("https://hub"), Some(3));
        // Another enrollment's ceiling is one `vk node run` would forget.
        assert_eq!(ceiling_from("https://other"), None);
        let held = lock(&node).unwrap();
        assert!(claim_tuning(&cfg).unwrap().is_none());
        drop(held);
        // A tune pass holds the lock shared, and a node starting meanwhile waits it out.
        let claim = claim_tuning(&cfg).unwrap().unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(claim);
        });
        let held = lock(&node).unwrap();
        release.join().unwrap();
        drop(held);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_token_file_holds_exactly_one_token() {
        let dir = scratch("token");
        let path = dir.join("t");
        std::fs::write(&path, "vkh_abc\n").unwrap();
        assert_eq!(TokenSource::File(path.clone()).read().unwrap(), "vkh_abc");
        for bad in ["", "\n", "vkh_a vkh_b\n"] {
            std::fs::write(&path, bad).unwrap();
            assert!(TokenSource::File(path.clone()).read().is_err(), "{bad:?}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_ca_bundle_without_a_certificate_is_refused() {
        let err = roots_from_pem(b"not a certificate\n", Path::new("x.pem")).unwrap_err();
        assert!(format!("{err:#}").contains("no certificate"), "{err:#}");
    }
}
