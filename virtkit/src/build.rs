//! `virtkit build` — a from-scratch Dockerfile builder (no docker, no buildkit).
//!
//! A from-scratch builder for the narrow job we actually need: build a Dockerfile
//! target and export it as a filesystem (ext4) image, with `RUN` steps run in a
//! Cloud Hypervisor microVM rather than rootless containers. It is intentionally the
//! *classic* (pre-buildkit) builder shape — stages in topological order, a linear
//! per-instruction cache — not a buildkit reimplementation: no concurrent solver, no
//! content-addressed per-op cache graph.
//!
//! Pipeline: [`parser`] (Dockerfile → instructions, lexing mirrors buildkit's
//! parser) → [`plan`] (stages + cross-stage deps + toposort) → [`exec`] (a backend
//! applies each stage). Backends: [`exec::DryRun`] (records the build, for tests +
//! `--print-plan`), [`exec::Host`] (`FROM scratch` + `COPY`, pure-Rust ext4), and
//! [`exec::MicroVm`] (`FROM <image>` + `RUN` in a CH guest, exported as a clean ext4).
//!
//! Instruction-level cache: each instruction advances a chained content key; for a
//! filesystem-changing instruction (RUN/COPY) the resulting ext4 snapshot is pushed
//! to / pulled from virtkit's own `[registry]` keyed by that key (the CDC chunk dedup
//! makes successive snapshots share almost all blobs). On a rebuild the longest cached
//! prefix is restored and only the changed tail re-runs.
//!
//! A context `COPY` also keys on a sha256 of the (sorted, `.dockerignore`-filtered)
//! content of the files it references, so editing a copied source busts the cache; a
//! `COPY --from=<stage>` is already covered by that stage's key chain.
//!
//! The key chain is computed once by [`resolve_stages`] (the single source of truth):
//! a `FROM <image>` seeds on the resolved manifest digest when available, so a moved tag
//! busts the cache; the build driver applies the resolved steps, and `docker-hash` prints
//! the same per-stage keys ([`stage_keys`]).

mod exec;
mod interp;
mod parser;
mod plan;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use exec::{DryRun, Executor, Host, ResolvedMount, Rootfs, ShellState};
use interp::Vars;
use parser::Instruction;
use plan::{Base, Plan};

/// What/how to build. (The microVM backend and its options — cloud-hypervisor/kernel/
/// agent/cache registry/journal — are added with that backend in a following commit.)
pub struct Options {
    pub dockerfile: PathBuf,
    /// Stage selector: an `AS` name or index; `None` = the last stage.
    pub target: Option<String>,
    /// Build context root for `COPY` (default: the Dockerfile's directory).
    pub context: Option<PathBuf>,
    /// ext4 output path (unused in `--print-plan`).
    pub out: Option<PathBuf>,
    /// Parse + plan + print the build order and primitives, build nothing.
    pub print_plan: bool,
    /// `--build-arg NAME=VALUE` overrides for ARG defaults.
    pub build_args: Vec<(String, String)>,
}

/// Entry point for the `build` subcommand.
pub fn build(opts: &Options) -> Result<()> {
    let src = std::fs::read_to_string(&opts.dockerfile)
        .with_context(|| format!("reading {}", opts.dockerfile.display()))?;
    let df = parser::parse(&src)?;
    let build_args: Vars = opts.build_args.iter().cloned().collect();
    let plan = Plan::from_dockerfile(&df, &build_args)?;
    let target = plan.resolve_target(opts.target.as_deref())?;
    let order = plan.build_order(target)?;
    let context = opts.context.clone().unwrap_or_else(|| {
        opts.dockerfile
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    });

    // --print-plan: dry-run the whole pipeline and print the primitives, build nothing.
    if opts.print_plan {
        let mut ex = DryRun::new();
        drive(&plan, &order, &build_args, &mut ex, &context)?;
        println!("# build order: {order:?} (target stage {target})");
        for line in &ex.transcript {
            println!("{line}");
        }
        return Ok(());
    }

    // Only the host backend (FROM scratch + COPY, exported via virtkit's own pure-Rust
    // ext4 builder — no docker/buildkit/mke2fs/VM) is wired; the microVM backend
    // (FROM <image> + RUN in a Cloud Hypervisor guest) is added in a following commit.
    let out = opts
        .out
        .as_deref()
        .context("build needs --out <file> (or --print-plan)")?;
    let scratch = std::env::temp_dir().join(format!("virtkit-build-{}", std::process::id()));
    let mut ex = Host::new(context.clone(), scratch.clone());
    let result = (|| -> Result<()> {
        let committed = drive(&plan, &order, &build_args, &mut ex, &context)?;
        let fs = committed
            .get(&target)
            .context("internal: target stage not committed")?;
        ex.export_ext4(fs, out)
    })();
    let _ = std::fs::remove_dir_all(&scratch); // best-effort scratch cleanup
    result?;
    println!(
        "virtkit: built {} -> {}",
        opts.dockerfile.display(),
        out.display()
    );
    Ok(())
}

/// One resolved instruction ready to apply: the interpolated instruction, its chain key
/// (the content hash up to and including it), and the shell state (ENV/USER/WORKDIR) in
/// effect when it runs. Only filesystem-changing instructions (RUN/COPY) become steps —
/// ENV/WORKDIR/USER fold into the following steps' state, ARG into the interpolation
/// scope. Produced by [`resolve_stages`] so the build driver and `docker-hash` share one
/// key + interpolation computation and cannot drift.
struct Step {
    instr: Instruction,
    key: String,
    state: ShellState,
}

/// A stage resolved to its keyed instruction stream, without materializing any rootfs.
struct Resolved {
    /// the filesystem-changing instructions in order, each with its chain key + state.
    steps: Vec<Step>,
    /// the stage's final chain key (its cache identity / `stage_key`) — the key after the
    /// stage's last instruction, even a trailing ENV/WORKDIR/USER.
    final_key: String,
    /// the stage's final shell state, inherited by a child `FROM <stage>`.
    final_state: ShellState,
}

/// Replay every stage's cache-key chain and ENV/USER/WORKDIR scope in topological order,
/// without materializing anything: the base seed (the resolved manifest digest when
/// available, so a moved tag busts the cache, else the image ref), then each
/// instruction's chained key against the interpolated form. Calls only the executor's
/// read-only queries ([`Executor::resolve_base_digest`], [`Executor::base_config`]) — no
/// pull/run/copy — so it is the single source of truth for a stage's identity, shared by
/// the build driver (which then applies the steps) and `docker-hash` (which just prints
/// the keys).
fn resolve_stages(
    plan: &Plan,
    order: &[usize],
    build_args: &Vars,
    context: &Path,
    ex: &mut dyn Executor,
    dsh: Option<&str>,
) -> Result<HashMap<usize, Resolved>> {
    let mut out: HashMap<usize, Resolved> = HashMap::new();
    for &idx in order {
        let stage = &plan.stages[idx];
        // base cache key (independent of materializing the rootfs). A `FROM <image>` keys
        // on the resolved manifest digest when available; a `FROM <stage>` continues its
        // parent's chain.
        let mut key = match &stage.base {
            Base::Image(image) => match ex.resolve_base_digest(image) {
                Some(d) => hash_key(&format!("FROM image {image}@{d}")),
                None => hash_key(&format!("FROM image {image}")),
            },
            Base::Scratch => hash_key("FROM scratch"),
            Base::Stage(parent) => out
                .get(parent)
                .map(|r| r.final_key.clone())
                .context("internal: parent stage resolved out of order")?,
        };
        // Seed ENV/USER/WORKDIR: a stage inherits its base — a prior stage's final state,
        // or (for FROM <image>) the image config's ENV/USER/WORKDIR, so RUNs get the
        // base PATH etc. The config is fetched only when the stage actually runs commands.
        let has_run = stage
            .instructions
            .iter()
            .any(|i| matches!(i, Instruction::Run(_)));
        let mut state = match &stage.base {
            Base::Stage(parent) => out
                .get(parent)
                .map(|r| r.final_state.clone())
                .unwrap_or_default(),
            Base::Image(image) if has_run => {
                let cfg = ex.base_config(image)?;
                ShellState {
                    env: cfg.env,
                    user: cfg.user.unwrap_or_else(|| "root".into()),
                    workdir: cfg.workdir.unwrap_or_else(|| "/".into()),
                }
            }
            _ => ShellState::default(),
        };
        if state.user.is_empty() {
            state.user = "root".into();
        }
        if state.workdir.is_empty() {
            state.workdir = "/".into();
        }
        // Interpolation scope: the inherited ENV (base image / parent stage) plus the
        // stage's own ARG/ENV as they are declared. ARG is per-stage (not inherited).
        let mut vars: Vars = state.env.iter().cloned().collect();
        let mut steps: Vec<Step> = Vec::new();
        for raw in &stage.instructions {
            // ARG only feeds the interpolation scope; it does not chain into the key, and
            // is a cache input only through the instructions that reference it (once
            // expanded).
            if let Instruction::Arg { name: arg, default } = raw {
                // DOCKER_STAGE_HASH is a reserved, auto-injected arg: its value is the
                // declaring ancestor's stage_key (see [`drive`]). It is forced empty while
                // keying (`dsh` = None) so a stage's identity never depends on the injected
                // hash — that would make a self-declaring stage's key depend on itself — and
                // set to the injected value in the exec pass (`dsh` = Some). A user-supplied
                // `--build-arg DOCKER_STAGE_HASH` is ignored (the value is synthesized).
                let value = if arg == DOCKER_STAGE_HASH {
                    dsh.unwrap_or_default().to_string()
                } else {
                    let default = default.as_deref().map(|d| interp::interpolate(d, &vars));
                    if default.is_some() {
                        build_args.get(arg).cloned().or(default).unwrap_or_default()
                    } else {
                        build_args
                            .get(arg)
                            .or(plan.global_args.get(arg))
                            .cloned()
                            .unwrap_or_default()
                    }
                };
                vars.insert(arg.clone(), value);
                continue;
            }
            // expand $VAR / ${VAR} against the current scope, then key the result.
            let instr = interp::expand_instruction(raw, &vars);
            // A context COPY (no `--from`) also keys on the sha256 of the files it
            // references, so editing a copied source busts the cache (Docker semantics);
            // a `--from=<stage>` copy is already covered by that stage's key chain.
            let content = match &instr {
                Instruction::Copy(c) if c.from.is_none() => Some(context_copy_hash(context, c)),
                _ => None,
            };
            key = chain_key(&key, &instr, content.as_deref());
            if matches!(instr, Instruction::Run(_) | Instruction::Copy(_)) {
                // a step runs under the state accumulated by the prior ENV/WORKDIR/USER.
                steps.push(Step {
                    instr,
                    key: key.clone(),
                    state: state.clone(),
                });
            } else {
                // ENV/WORKDIR/USER: fold into the running state (+ scope) for later steps.
                apply_meta(&mut state, &instr);
                if let Instruction::Env(kvs) = &instr {
                    for (k, v) in kvs {
                        vars.insert(k.clone(), v.clone()); // ENV joins the scope (overrides ARG)
                    }
                }
            }
        }
        out.insert(
            idx,
            Resolved {
                steps,
                final_key: key,
                final_state: state,
            },
        );
    }
    Ok(out)
}

/// Resolve every stage's cache key (name or index → `stage_key`: the chain key after the
/// stage's last instruction) without building — the exact identity virtkit's instruction
/// cache stores a stage's snapshot under. Resolves base digests + base image config over
/// the network (like a real build) so the keys match what a build would store. Backs the
/// `docker-hash` subcommand.
pub fn stage_keys(
    dockerfile: &Path,
    context: Option<&Path>,
    build_args: &[(String, String)],
) -> Result<Vec<(String, String)>> {
    let src = std::fs::read_to_string(dockerfile)
        .with_context(|| format!("reading {}", dockerfile.display()))?;
    let df = parser::parse(&src)?;
    let ba: Vars = build_args.iter().cloned().collect();
    let plan = Plan::from_dockerfile(&df, &ba)?;
    let order = plan.all_order()?;
    let ctx = context.map(Path::to_path_buf).unwrap_or_else(|| {
        dockerfile
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    });
    let mut ex = exec::Planner::new();
    // canonical keys: DOCKER_STAGE_HASH is excluded (its injected value never affects a
    // stage's identity), so `docker-hash` prints exactly the key a build would store.
    let resolved = resolve_stages(&plan, &order, &ba, &ctx, &mut ex, None)?;
    let mut out = Vec::new();
    for &idx in &order {
        let name = plan.stages[idx]
            .name
            .clone()
            .unwrap_or_else(|| idx.to_string());
        out.push((name, resolved[&idx].final_key.clone()));
    }
    Ok(out)
}

/// The reserved build arg whose value virtkit synthesizes (the declaring stage's
/// `stage_key`) instead of taking from the user — see [`drive`]/[`resolve_stages`].
const DOCKER_STAGE_HASH: &str = "DOCKER_STAGE_HASH";

/// The stage nearest `target` (BFS over the dependency DAG, `target` first) that declares
/// `ARG DOCKER_STAGE_HASH`, or `None` if no stage in the target's closure does. Mirrors
/// wabbuilder docker-tool.sh `_closure_args`: the closest declarer to the target wins
/// (self included), and its `stage_key` is the value injected for the whole build.
fn nearest_dsh_declarer(plan: &Plan, target: usize) -> Option<usize> {
    use std::collections::VecDeque;
    let declares = |i: usize| {
        plan.stages[i]
            .instructions
            .iter()
            .any(|ins| matches!(ins, Instruction::Arg { name, .. } if name == DOCKER_STAGE_HASH))
    };
    let mut seen = vec![false; plan.stages.len()];
    let mut queue = VecDeque::from([target]);
    seen[target] = true;
    while let Some(cur) = queue.pop_front() {
        if declares(cur) {
            return Some(cur);
        }
        for d in plan.deps(cur) {
            if !seen[d] {
                seen[d] = true;
                queue.push_back(d);
            }
        }
    }
    None
}

/// Combine the canonical key pass (value-independent keys) with the exec pass (the
/// instructions + shell state interpolated with the injected DOCKER_STAGE_HASH): keep
/// each step's cache key from the key pass, take its executed instruction + state from
/// the exec pass. Both passes see the same instruction kinds/order, so the steps zip 1:1.
fn merge_exec(
    keyed: &HashMap<usize, Resolved>,
    exec: HashMap<usize, Resolved>,
) -> HashMap<usize, Resolved> {
    let mut out = HashMap::new();
    for (idx, xr) in exec {
        let kr = &keyed[&idx];
        let steps = kr
            .steps
            .iter()
            .zip(xr.steps)
            .map(|(k, x)| Step {
                instr: x.instr,
                key: k.key.clone(),
                state: x.state,
            })
            .collect();
        out.insert(
            idx,
            Resolved {
                steps,
                final_key: kr.final_key.clone(),
                final_state: xr.final_state,
            },
        );
    }
    out
}

/// Walk the stages in topological order, applying each stage's instructions through
/// the executor, and return each stage's committed rootfs (so later stages can fork
/// it / COPY --from it). Backend-agnostic. Keys + interpolation come from
/// [`resolve_stages`] (the shared identity computation), so the build and `docker-hash`
/// agree on every stage's cache key.
fn drive(
    plan: &Plan,
    order: &[usize],
    build_args: &Vars,
    ex: &mut dyn Executor,
    context: &Path,
) -> Result<HashMap<usize, Rootfs>> {
    // Canonical, value-independent keys (DOCKER_STAGE_HASH forced empty while keying).
    let keyed = resolve_stages(plan, order, build_args, context, ex, None)?;
    // Auto-inject DOCKER_STAGE_HASH for execution: its value is the stage_key of the
    // declaring stage nearest the target (self included), mirroring the wabbuilder
    // docker-tool.sh `BUILDER_TAG` scheme. A second pass re-interpolates the instructions
    // with that value; the cache keys stay the canonical ones above, so the injected hash
    // never alters what is cached (and `docker-hash` agrees with the build).
    let target = *order.last().context("internal: empty build order")?;
    let resolved = match nearest_dsh_declarer(plan, target) {
        Some(d) => {
            let value = keyed
                .get(&d)
                .context("internal: DOCKER_STAGE_HASH declarer not resolved")?
                .final_key
                .clone();
            let exec = resolve_stages(plan, order, build_args, context, ex, Some(&value))?;
            merge_exec(&keyed, exec)
        }
        None => keyed,
    };
    let mut committed: HashMap<usize, Rootfs> = HashMap::new();
    for &idx in order {
        let stage = &plan.stages[idx];
        let name = stage.name.clone().unwrap_or_else(|| format!("stage{idx}"));
        let steps = &resolved
            .get(&idx)
            .context("internal: stage not resolved")?
            .steps;
        // Declare the source stages this stage copies/mounts from, so the backend can
        // attach them before the guest boots.
        ex.stage_sources(&stage_source_rootfs(plan, &stage.instructions, &committed))?;
        // Instruction-level cache + lazy base: every step carries the chained key; the
        // base rootfs is materialized only when something must actually run (the first
        // cache miss). A fully-cached stage never pulls/flattens the base — it just
        // restores the final snapshot. `fs` is None until materialized.
        let mut fs: Option<Rootfs> = None;
        let mut building = false;
        let mut last_hit: Option<String> = None;
        for step in steps {
            if !building && ex.cache_has(&step.key) {
                println!("virtkit: build CACHED  {}", instr_label(&step.instr));
                last_hit = Some(step.key.clone());
                continue;
            }
            // first miss: materialize the rootfs — restore the last cached snapshot if
            // there was a cached prefix, else build the base from scratch/image/stage.
            if !building {
                fs = Some(match &last_hit {
                    Some(k) => restore_into(ex, &name, k)?,
                    None => materialize_base(ex, &stage.base, &name, &committed)?,
                });
                building = true;
            }
            let f = fs.as_mut().expect("materialized on first miss");
            apply_fs(plan, &committed, ex, f, &step.state, &step.instr)?;
            ex.cache_save(f, &step.key)?;
        }
        // Nothing ran: the whole instruction run was cached → restore the final
        // snapshot; or there were no fs-changing instructions → the stage is the base.
        let final_fs = match fs {
            Some(f) => f,
            None => match &last_hit {
                Some(k) => restore_into(ex, &name, k)?,
                None => materialize_base(ex, &stage.base, &name, &committed)?,
            },
        };
        // Finalize the stage: tear down its long-lived guest (if any) and commit its
        // overlay back into the stage ext4 so forks / COPY --from / export see the writes.
        ex.stage_end(&final_fs)?;
        committed.insert(idx, final_fs);
    }
    Ok(committed)
}

/// The committed rootfs of the stages an instruction list references via `COPY --from`
/// / `RUN --mount=from` (distinct, in source order). Resolved on the raw `--from` text
/// — literal stage names; a `--from=$VAR` would not be seen (a known limitation).
fn stage_source_rootfs(
    plan: &Plan,
    instructions: &[Instruction],
    committed: &HashMap<usize, Rootfs>,
) -> Vec<Rootfs> {
    let mut refs: Vec<&str> = Vec::new();
    for instr in instructions {
        match instr {
            Instruction::Copy(c) => {
                if let Some(f) = &c.from {
                    refs.push(f);
                }
            }
            Instruction::Run(r) => {
                for m in &r.mounts {
                    if let Some(f) = &m.from {
                        refs.push(f);
                    }
                }
            }
            _ => {}
        }
    }
    let mut srcs = Vec::new();
    let mut seen: Vec<usize> = Vec::new();
    for r in refs {
        if let Some(si) = plan.stage_ref(r)
            && !seen.contains(&si)
            && let Some(rf) = committed.get(&si)
        {
            seen.push(si);
            srcs.push(rf.clone());
        }
    }
    srcs
}

/// sha256 hex of `s` — the base cache key.
fn hash_key(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex(&h.finalize())
}

/// Chain the cache key with one instruction (an explicit canonical form, [`canonical`])
/// plus, for a context `COPY`, a content hash of the files it references. A change anywhere
/// in the prefix — or in the copied bytes — changes the key.
fn chain_key(prev: &str, instr: &Instruction, content: Option<&str>) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(b"\n");
    h.update(canonical(instr).as_bytes());
    if let Some(c) = content {
        h.update(b"\n");
        h.update(c.as_bytes());
    }
    hex(&h.finalize())
}

/// An explicit, stable canonical string for an instruction — the cache-key identity. Spelled
/// out field by field (with a unit-separator delimiter) rather than the `Debug` repr, so the
/// key is a deliberate contract: refactoring the parser structs can't silently shift it.
fn canonical(instr: &Instruction) -> String {
    use parser::{Cmdline, Instruction as I};
    const US: char = '\u{1f}'; // unit separator — not expected in any field
    let cmd = |c: &Cmdline| match c {
        Cmdline::Shell(s) => format!("shell{US}{s}"),
        Cmdline::Exec(v) => format!("exec{US}{}", v.join(&US.to_string())),
    };
    let o = |x: &Option<String>| x.clone().unwrap_or_default();
    match instr {
        I::From(f) => format!(
            "FROM{US}{}{US}{}{US}{}",
            f.image,
            o(&f.as_name),
            o(&f.platform)
        ),
        I::Run(r) => format!(
            "RUN{US}{}{US}net={}{US}sec={}{US}mounts={}",
            cmd(&r.cmd),
            o(&r.network),
            o(&r.security),
            r.mounts
                .iter()
                .map(|m| format!(
                    "{}:from={}:src={}:tgt={}:ro={}",
                    m.typ,
                    o(&m.from),
                    o(&m.source),
                    o(&m.target),
                    m.readonly
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
        I::Copy(c) => format!(
            "COPY{US}from={}{US}chown={}{US}chmod={}{US}link={}{US}{}->{}",
            o(&c.from),
            o(&c.chown),
            o(&c.chmod),
            c.link,
            c.sources.join(&US.to_string()),
            c.dest
        ),
        I::Arg { name, default } => format!("ARG{US}{name}={}", o(default)),
        I::Env(kvs) => format!("ENV{US}{}", kv(kvs, US)),
        I::Workdir(w) => format!("WORKDIR{US}{w}"),
        I::User(u) => format!("USER{US}{u}"),
        I::Label(kvs) => format!("LABEL{US}{}", kv(kvs, US)),
        I::Entrypoint(c) => format!("ENTRYPOINT{US}{}", cmd(c)),
        I::Cmd(c) => format!("CMD{US}{}", cmd(c)),
        I::Other { name, args } => format!("OTHER{US}{name}{US}{args}"),
    }
}

fn kv(kvs: &[(String, String)], sep: char) -> String {
    kvs.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(&sep.to_string())
}

/// sha256 over the (sorted, `.dockerignore`-filtered) content of the context files a
/// `COPY` (without `--from`) references — so the cache key tracks the copied bytes, not
/// just the instruction text. Each source may be a file, a directory (recursed), or a
/// trailing-segment glob (`dir/*.json`). Unreadable/absent sources contribute a marker.
fn context_copy_hash(context: &Path, copy: &parser::Copy) -> String {
    use sha2::{Digest, Sha256};
    let ign = virtkit_agent::diskmount::Ignore::load(context);
    let mut files: Vec<PathBuf> = Vec::new();
    for src in &copy.sources {
        files.extend(copy_src_files(context, &ign, src));
    }
    files.sort();
    files.dedup();
    let mut h = Sha256::new();
    for f in &files {
        let rel = f.strip_prefix(context).unwrap_or(f).to_string_lossy();
        h.update(rel.as_bytes());
        h.update(b"\0");
        match std::fs::read(f) {
            Ok(bytes) => h.update(Sha256::digest(&bytes)),
            Err(_) => h.update(b"?"),
        }
        h.update(b"\n");
    }
    hex(&h.finalize())
}

/// The context files one `COPY` source references (absolute, `.dockerignore`-filtered): a
/// literal file/dir (recursed), else a trailing-segment glob matched against its dir.
fn copy_src_files(
    context: &Path,
    ign: &virtkit_agent::diskmount::Ignore,
    src: &str,
) -> Vec<PathBuf> {
    let rel = src.trim_start_matches('/');
    let rel = rel.strip_prefix("./").unwrap_or(rel);
    let start = if rel.is_empty() || rel == "." {
        context.to_path_buf()
    } else {
        context.join(rel)
    };
    if start.exists() {
        return ign.included_files(&start);
    }
    // glob fallback: split into <dir>/<pattern> and match the dir's entries by name.
    let (dir, pat) = match rel.rsplit_once('/') {
        Some((d, p)) => (context.join(d), p),
        None => (context.to_path_buf(), rel),
    };
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&dir) {
        let mut entries: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        entries.sort();
        for e in entries {
            if let Some(name) = e.file_name().and_then(|n| n.to_str())
                && glob_seg(pat, name)
            {
                out.extend(ign.included_files(&e));
            }
        }
    }
    out
}

/// Match one path segment against a `*`/`?` glob.
fn glob_seg(pat: &str, s: &str) -> bool {
    fn m(p: &[u8], s: &[u8]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some(b'*') => m(&p[1..], s) || (!s.is_empty() && m(p, &s[1..])),
            Some(b'?') => !s.is_empty() && m(&p[1..], &s[1..]),
            Some(&c) => !s.is_empty() && s[0] == c && m(&p[1..], &s[1..]),
        }
    }
    m(pat.as_bytes(), s.as_bytes())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A short human label for an instruction (the CACHED progress line).
fn instr_label(instr: &Instruction) -> String {
    match instr {
        Instruction::Run(r) => format!(
            "RUN {}",
            match &r.cmd {
                parser::Cmdline::Shell(s) => s.clone(),
                parser::Cmdline::Exec(v) => v.join(" "),
            }
        ),
        Instruction::Copy(c) => format!("COPY {:?} -> {}", c.sources, c.dest),
        other => format!("{other:?}"),
    }
}

/// Materialize a stage's base rootfs (pull/flatten an image, an empty scratch, or fork
/// a parent stage). Called lazily — only when the stage actually has to build.
fn materialize_base(
    ex: &mut dyn Executor,
    base: &Base,
    name: &str,
    committed: &HashMap<usize, Rootfs>,
) -> Result<Rootfs> {
    match base {
        Base::Image(image) => ex.from_image(name, image),
        Base::Scratch => ex.from_scratch(name),
        Base::Stage(parent) => {
            let parent_fs = committed
                .get(parent)
                .context("internal: base stage built out of order")?;
            ex.from_stage(name, parent_fs)
        }
    }
}

/// Restore a cached snapshot as stage `name`'s rootfs (no base build needed).
fn restore_into(ex: &mut dyn Executor, name: &str, key: &str) -> Result<Rootfs> {
    let fs = Rootfs {
        label: name.to_string(),
    };
    ex.cache_restore(&fs, key)?;
    Ok(fs)
}

/// Apply a non-filesystem instruction (ENV/WORKDIR/USER) — updates the shell state
/// only, so it needs no materialized rootfs.
fn apply_meta(state: &mut ShellState, instr: &Instruction) {
    match instr {
        Instruction::Env(kvs) => {
            for (k, v) in kvs {
                upsert(&mut state.env, k, v);
            }
        }
        Instruction::Workdir(w) => state.workdir = w.clone(),
        Instruction::User(u) => state.user = u.clone(),
        // ARG/LABEL/ENTRYPOINT/CMD/Other: no effect in the prototype (LABEL/ENTRYPOINT/
        // CMD would land in the exported image config; ARG would feed interpolation).
        _ => {}
    }
}

/// Apply a filesystem-changing instruction (RUN/COPY) to the materialized rootfs.
fn apply_fs(
    plan: &Plan,
    committed: &HashMap<usize, Rootfs>,
    ex: &mut dyn Executor,
    fs: &mut Rootfs,
    state: &ShellState,
    instr: &Instruction,
) -> Result<()> {
    match instr {
        Instruction::Run(r) => {
            // resolve each --mount=…,from= to a committed stage rootfs (external-image
            // mounts are pulled). Hold the pulled handles so borrows outlive the call.
            let mut pulled: Vec<Rootfs> = Vec::new();
            let mut resolved: Vec<(usize, Option<usize>)> = Vec::new(); // (mount idx, committed key)
            for (mi, m) in r.mounts.iter().enumerate() {
                if let Some(from) = &m.from {
                    match plan.stage_ref(from) {
                        Some(s) => resolved.push((mi, Some(s))),
                        None => {
                            pulled.push(ex.pull(from)?);
                            resolved.push((mi, None));
                        }
                    }
                }
            }
            let mut pi = 0;
            let mounts: Vec<ResolvedMount> = r
                .mounts
                .iter()
                .enumerate()
                .map(|(mi, m)| {
                    let from = if m.from.is_none() {
                        None
                    } else {
                        match resolved
                            .iter()
                            .find(|(i, _)| *i == mi)
                            .and_then(|(_, k)| *k)
                        {
                            Some(s) => committed.get(&s),
                            None => {
                                let r = pulled.get(pi);
                                pi += 1;
                                r
                            }
                        }
                    };
                    ResolvedMount { spec: m, from }
                })
                .collect();
            ex.run(fs, &r.cmd, &mounts, state)?;
        }
        Instruction::Copy(c) => {
            let from = match &c.from {
                None => None,
                Some(reference) => match plan.stage_ref(reference) {
                    Some(s) => committed.get(&s).cloned(),
                    None => Some(ex.pull(reference)?), // COPY --from=<external image>
                },
            };
            ex.copy(fs, c, from.as_ref())?;
        }
        // only RUN/COPY reach here (the driver routes ENV/WORKDIR/USER to apply_meta).
        _ => {}
    }
    Ok(())
}

fn upsert(env: &mut Vec<(String, String)>, k: &str, v: &str) {
    if let Some(e) = env.iter_mut().find(|(ek, _)| ek == k) {
        e.1 = v.to_string();
    } else {
        env.push((k.to_string(), v.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transcript(src: &str, target: Option<&str>) -> Vec<String> {
        let ba = Vars::new();
        let df = parser::parse(src).unwrap();
        let plan = Plan::from_dockerfile(&df, &ba).unwrap();
        let t = plan.resolve_target(target).unwrap();
        let order = plan.build_order(t).unwrap();
        let mut ex = DryRun::new();
        drive(&plan, &order, &ba, &mut ex, Path::new("/nonexistent")).unwrap();
        ex.transcript
    }

    #[test]
    fn canonical_is_explicit_and_stable() {
        use parser::{Cmdline, Run};
        let run = |s: &str| {
            Instruction::Run(Run {
                cmd: Cmdline::Shell(s.into()),
                mounts: vec![],
                network: None,
                security: None,
            })
        };
        // an explicit, deliberate string (not the Debug repr)
        assert_eq!(
            canonical(&run("make")),
            "RUN\u{1f}shell\u{1f}make\u{1f}net=\u{1f}sec=\u{1f}mounts="
        );
        // content-sensitive and stable; distinct instruction kinds differ
        assert_ne!(canonical(&run("make")), canonical(&run("make test")));
        assert_ne!(
            canonical(&Instruction::Workdir("/a".into())),
            canonical(&Instruction::User("/a".into()))
        );
    }

    #[test]
    fn context_copy_hash_tracks_content_and_dockerignore() {
        let dir = std::env::temp_dir().join(format!("vk-copyhash-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/a.rs"), "fn main() {}").unwrap();
        std::fs::write(dir.join("README.md"), "hi").unwrap();
        std::fs::write(dir.join(".dockerignore"), "*.md\n").unwrap();
        let cp = |srcs: &[&str]| parser::Copy {
            sources: srcs.iter().map(|s| s.to_string()).collect(),
            dest: "/app".into(),
            from: None,
            chown: None,
            chmod: None,
            link: false,
        };
        let h1 = context_copy_hash(&dir, &cp(&["."]));
        // editing a copied source changes the hash
        std::fs::write(dir.join("src/a.rs"), "fn main() { /* x */ }").unwrap();
        assert_ne!(h1, context_copy_hash(&dir, &cp(&["."])));
        // editing a .dockerignore'd file does NOT change the hash
        let before = context_copy_hash(&dir, &cp(&["."]));
        std::fs::write(dir.join("README.md"), "changed").unwrap();
        assert_eq!(before, context_copy_hash(&dir, &cp(&["."])));
        // a glob source matches by segment (src/*.rs covers a.rs)
        assert_eq!(
            context_copy_hash(&dir, &cp(&["src/*.rs"])),
            context_copy_hash(&dir, &cp(&["src/a.rs"]))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn end_to_end_multistage_drive() {
        let src = "\
FROM debian:bookworm AS build
WORKDIR /src
RUN apt-get update && apt-get install -y gcc
COPY . .
RUN make

FROM debian:bookworm AS final
USER app
COPY --from=build /src/out /usr/bin/out
RUN --mount=type=bind,from=build,source=/src,target=/s /usr/bin/out --selftest
";
        let t = transcript(src, Some("final"));
        // stage 'build' is based on an image; its working rootfs is labelled 'build'.
        assert!(
            t.contains(&"from-image build (debian:bookworm)".to_string()),
            "{t:#?}"
        );
        assert!(
            t.iter()
                .any(|l| l.starts_with("run [user=root cwd=/src") && l.contains("apt-get update"))
        );
        assert!(
            t.iter()
                .any(|l| l.starts_with("copy from=context") && l.contains("\".\""))
        );
        // final stage: COPY --from=build resolves to the build stage's rootfs (label
        // 'build'), and the RUN runs as the USER with the bind mount from that stage.
        assert!(
            t.iter()
                .any(|l| l.starts_with("copy from=build ") && l.contains("/usr/bin/out")),
            "COPY --from=build should resolve to the build stage:\n{t:#?}"
        );
        assert!(
            t.iter()
                .any(|l| l.starts_with("run [user=app") && l.contains("mounts_from=[\"build\"]")),
            "final RUN should run as 'app' with a bind mount from the build stage:\n{t:#?}"
        );
    }

    #[test]
    fn resolve_stages_keys_are_stable_and_chained() {
        let src = "\
FROM debian:bookworm AS build
ENV V=1
RUN make $V
FROM build AS final
RUN ship
";
        let ba = Vars::new();
        let resolve = |source: &str| {
            let df = parser::parse(source).unwrap();
            let plan = Plan::from_dockerfile(&df, &ba).unwrap();
            let order = plan.all_order().unwrap();
            let mut ex = DryRun::new();
            resolve_stages(&plan, &order, &ba, Path::new("/nonexistent"), &mut ex, None).unwrap()
        };
        let r = resolve(src);
        // every stage key is a full sha256 hex, and the computation is deterministic.
        let r_again = resolve(src);
        for i in [0usize, 1] {
            assert_eq!(r[&i].final_key.len(), 64);
            assert_eq!(r[&i].final_key, r_again[&i].final_key);
        }
        // a `FROM <stage>` child continues a distinct chain from its parent.
        assert_ne!(r[&0].final_key, r[&1].final_key);
        // the build stage ends on a RUN, so its identity is that last step's key.
        assert_eq!(r[&0].final_key, r[&0].steps.last().unwrap().key);
        // ENV is in the interpolation scope: `$V` expanded into the RUN's command.
        assert!(matches!(
            &r[&0].steps.last().unwrap().instr,
            Instruction::Run(run) if matches!(&run.cmd, parser::Cmdline::Shell(s) if s == "make 1")
        ));
        // editing an upstream ENV busts the upstream key and chains through to the
        // dependent stage's key.
        let r2 = resolve(&src.replace("ENV V=1", "ENV V=2"));
        assert_ne!(r[&0].final_key, r2[&0].final_key);
        assert_ne!(r[&1].final_key, r2[&1].final_key);
    }

    #[test]
    fn docker_stage_hash_injects_into_exec_but_not_keys() {
        // 'core' declares ARG DOCKER_STAGE_HASH and bakes it into an ENV its RUN reads;
        // 'app' builds on 'core' without re-declaring. Building 'app' injects core's
        // stage_key as DOCKER_STAGE_HASH — and the cache keys must not depend on it.
        let src = "\
FROM debian:bookworm AS core
ARG DOCKER_STAGE_HASH
ENV BUILDER_TAG=$DOCKER_STAGE_HASH
RUN echo $BUILDER_TAG
FROM core AS app
RUN ship
";
        let ba = Vars::new();
        let df = parser::parse(src).unwrap();
        let plan = Plan::from_dockerfile(&df, &ba).unwrap();
        let target = plan.resolve_target(Some("app")).unwrap();
        let order = plan.build_order(target).unwrap();
        let nonexistent = Path::new("/nonexistent");
        // 'app' does not declare it; the nearest declarer in its closure is 'core' (0).
        assert_eq!(nearest_dsh_declarer(&plan, target), Some(0));

        // canonical (key-pass) keys, DOCKER_STAGE_HASH excluded.
        let mut ex = DryRun::new();
        let keyed = resolve_stages(&plan, &order, &ba, nonexistent, &mut ex, None).unwrap();
        let value = keyed[&0].final_key.clone();
        // exec pass injects core's stage_key, then merge keeps the canonical keys.
        let mut ex2 = DryRun::new();
        let exec = resolve_stages(&plan, &order, &ba, nonexistent, &mut ex2, Some(&value)).unwrap();
        let merged = merge_exec(&keyed, exec);

        // the executed RUN in 'core' sees the injected value via BUILDER_TAG …
        let run = match &merged[&0].steps[0].instr {
            Instruction::Run(r) => r.cmd.clone(),
            other => panic!("expected RUN, got {other:?}"),
        };
        assert_eq!(run, parser::Cmdline::Shell(format!("echo {value}")));
        // … but its cache key is the canonical, value-independent one.
        assert_eq!(merged[&0].steps[0].key, keyed[&0].steps[0].key);

        // injecting a different value yields identical keys (no self-reference circularity).
        let mut ex3 = DryRun::new();
        let exec_other =
            resolve_stages(&plan, &order, &ba, nonexistent, &mut ex3, Some("deadbeef")).unwrap();
        let merged_other = merge_exec(&keyed, exec_other);
        assert_eq!(merged_other[&0].steps[0].key, merged[&0].steps[0].key);
    }

    #[test]
    fn independent_stage_is_pruned_from_the_drive() {
        let src = "FROM a AS x\nRUN one\nFROM b AS y\nRUN two\nFROM x AS z\nRUN three\n";
        let t = transcript(src, Some("z"));
        assert!(t.iter().any(|l| l.contains("one")));
        assert!(t.iter().any(|l| l.contains("three")));
        assert!(
            !t.iter().any(|l| l.contains("two")),
            "stage y must be pruned"
        );
    }
}
