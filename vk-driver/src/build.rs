//! `vk build` — a from-scratch Dockerfile builder (no docker, no buildkit).
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
//! prefix is restored and only the changed tail re-runs; a stage whose last key is
//! cached restores that one snapshot directly (no per-instruction probes), and a stage
//! only such fully-cached consumers read is skipped entirely.
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

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use exec::{DryRun, Executor, Host, MicroVm, ResolvedMount, Rootfs, ShellState};
use interp::Vars;
use parser::Instruction;
use plan::{Base, Plan, PlanInput};

/// What/how to build.
pub struct Options {
    /// Dockerfile(s), merged into one stage namespace (see [`Plan::from_dockerfiles`]).
    pub dockerfiles: Vec<PathBuf>,
    /// Stage selector: an `AS` name or index; `None` = the last stage.
    pub target: Option<String>,
    /// Build-context roots, zipped positionally with `dockerfiles`; a file without one
    /// defaults to its own directory.
    pub contexts: Vec<PathBuf>,
    /// ext4 output path (unused in `--print-plan`).
    pub out: Option<PathBuf>,
    /// Parse + plan + print the build order and primitives, build nothing.
    pub print_plan: bool,
    /// Use the microVM backend (RUN executes in a Cloud Hypervisor guest) instead of
    /// the host backend (FROM scratch + COPY only). Needs the three tool paths.
    pub microvm: bool,
    pub cloud_hypervisor: Option<PathBuf>,
    pub kernel: Option<PathBuf>,
    pub agent: Option<PathBuf>,
    /// instruction-cache destination: a registry repo (e.g. a `vk registry serve` at
    /// `127.0.0.1:5000`), an absolute store directory path (accessed in-process), or
    /// `none` to disable caching. `None` = the builtin local store
    /// (`regserve::default_root`).
    pub cache_registry: Option<String>,
    /// the cache registry speaks plain HTTP (a loopback regserve).
    pub cache_insecure: bool,
    /// add an ext4 journal to the exported image (the build stays journal-less).
    pub journal: bool,
    /// `--build-arg NAME=VALUE` overrides for ARG defaults.
    pub build_args: Vec<(String, String)>,
    /// Egress for the microVM build's `RUN` guests (see [`BuildNet`]).
    pub net: BuildNet,
}

/// Egress policy for the microVM build's `RUN` guests.
#[derive(Clone, Debug, PartialEq)]
pub enum BuildNet {
    /// No switch: `RUN` steps get no network.
    None,
    /// Unrestricted egress via the guest's `vk switch` (the default, as `docker build`).
    All,
    /// Egress restricted to destination CIDRs (optionally port-scoped) and DNS-name
    /// suffixes, enforced by the guest's `vk switch`: it refuses lookups of other
    /// names, and a connection may only reach a listed CIDR or an IP a permitted
    /// lookup just resolved.
    Allow {
        ips: Vec<String>,
        names: Vec<String>,
    },
}

impl BuildNet {
    /// Map the `--build-net` / `--build-allow-*` flags to a policy: allow flags
    /// restrict egress (and contradict `--build-net none`); with none of them,
    /// `--build-net` picks unrestricted (`all`, the default) or no network (`none`).
    /// Allowlist syntax is validated here so a bad flag fails before any build work.
    pub fn from_flags(net: &str, ips: &[String], names: &[String]) -> Result<BuildNet> {
        let restricted = !ips.is_empty() || !names.is_empty();
        match net {
            "none" if restricted => {
                bail!("--build-net none contradicts --build-allow-ip/--build-allow-name")
            }
            "none" => Ok(BuildNet::None),
            "all" if restricted => {
                crate::switch::Egress::new(ips, names)?;
                Ok(BuildNet::Allow {
                    ips: ips.to_vec(),
                    names: names.to_vec(),
                })
            }
            "all" => Ok(BuildNet::All),
            other => bail!("--build-net {other:?} (want all or none)"),
        }
    }
}

/// What a completed build exposes to its caller: the target stage's runtime config
/// (env/user/workdir/entrypoint/cmd — what a container runtime would read from the
/// image config), so a caller booting the exported image can run its command the way
/// `docker run` would — e.g. `run -f` putting the base image's `PATH` in scope so
/// `cargo` resolves. The same config is written as the `<out>.json` sidecar, so a
/// later boot of the ext4 (fleet skipping a fresh rebuild) reads it without a build.
#[derive(Default)]
pub struct Built {
    pub config: vk_core::runcfg::RunConfig,
}

/// The runtime-config sidecar path for a built ext4: `<out>.json` (appended, so
/// `svc.ext4` maps to `svc.ext4.json`).
pub fn config_sidecar(out: &Path) -> PathBuf {
    let mut s = out.as_os_str().to_os_string();
    s.push(".json");
    PathBuf::from(s)
}

/// A stage's final [`ShellState`] as the exported [`RunConfig`].
fn run_config(st: &ShellState) -> vk_core::runcfg::RunConfig {
    vk_core::runcfg::RunConfig {
        env: st.env.clone(),
        user: st.user.clone(),
        workdir: st.workdir.clone(),
        entrypoint: st.entrypoint.clone(),
        cmd: st.cmd.clone(),
    }
}

/// Resolve the instruction-cache destination: an explicit registry/store wins; `none`
/// disables; the default is the builtin local store — the same content-addressed root
/// a `vk registry serve` shares, accessed in-process (no server, no port). A
/// dot-relative path is rejected: only absolute paths and `file://` URLs select the
/// in-process store, everything else is a registry host.
fn cache_repo(cache_registry: Option<&str>) -> Result<Option<String>> {
    Ok(match cache_registry {
        Some("none") => None,
        // A hostname can't start with a dot, so this is a relative path — which
        // Registry::local_root would silently treat as a registry host.
        Some(repo) if repo.starts_with('.') => bail!(
            "cache destination {repo:?} is a relative path; \
             an in-process store needs an absolute path (or a file:// URL)"
        ),
        Some(repo) => Some(repo.to_string()),
        None => Some(
            crate::regserve::default_root()
                .context("resolving the builtin cache store dir")?
                .display()
                .to_string(),
        ),
    })
}

/// Read + parse the Dockerfiles into [`PlanInput`]s, zipping each with its context
/// (`--context` values pair positionally with `-f`; a file without one defaults to
/// its own directory).
fn load_inputs(dockerfiles: &[PathBuf], contexts: &[PathBuf]) -> Result<Vec<PlanInput>> {
    if dockerfiles.is_empty() {
        bail!("no Dockerfile given");
    }
    if contexts.len() > dockerfiles.len() {
        bail!(
            "{} --context values for {} -f file(s) — contexts zip positionally with -f",
            contexts.len(),
            dockerfiles.len()
        );
    }
    dockerfiles
        .iter()
        .enumerate()
        .map(|(i, dockerfile)| {
            let src = std::fs::read_to_string(dockerfile)
                .with_context(|| format!("reading {}", dockerfile.display()))?;
            let context = contexts.get(i).cloned().unwrap_or_else(|| {
                dockerfile
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf()
            });
            Ok(PlanInput {
                dockerfile: parser::parse(&src)
                    .with_context(|| format!("parsing {}", dockerfile.display()))?,
                origin: dockerfile.clone(),
                context,
            })
        })
        .collect()
}

/// Entry point for the `build` subcommand.
pub fn build(opts: &Options) -> Result<Built> {
    let inputs = load_inputs(&opts.dockerfiles, &opts.contexts)?;
    let build_args: Vars = opts.build_args.iter().cloned().collect();
    let plan = Plan::from_dockerfiles(&inputs, &build_args)?;
    let target = plan.resolve_target(opts.target.as_deref())?;
    let order = plan.build_order(target)?;

    // --print-plan: dry-run the whole pipeline and print the primitives, build nothing.
    if opts.print_plan {
        let mut ex = DryRun::new();
        drive(&plan, &order, &build_args, &mut ex)?;
        println!("# build order: {order:?} (target stage {target})");
        for line in &ex.transcript {
            println!("{line}");
        }
        return Ok(Built::default());
    }

    // Real build: the Host backend (FROM scratch + COPY, exported via virtkit's own
    // ext4 builder — no docker/buildkit/mke2fs/VM). RUN / FROM <image> error here.
    let out = opts
        .out
        .as_deref()
        .context("build needs --out <file> (or --print-plan)")?;
    // microVM scratch holds each stage's raw ext4 (booted read-write — keep it off
    // tmpfs), so place it next to the output; the host backend's scratch is just dirs.
    let scratch = if opts.microvm {
        out.parent()
            .unwrap_or_else(|| Path::new("."))
            .join(format!(".build-{}", std::process::id()))
    } else {
        std::env::temp_dir().join(format!("virtkit-build-{}", std::process::id()))
    };
    // Resolve the microVM's kernel + agent up front and hold them for the whole build:
    // an embedded asset lives in a memfd whose /proc/self/fd path is valid only while the
    // fd is open, and every stage boot (and the initramfs packer) reopens it.
    let (kernel, agent) = if opts.microvm {
        let kernel = crate::embed::resolve(crate::embed::Asset::Kernel, opts.kernel.as_deref())?;
        if !kernel.is_embedded() && !kernel.path.is_file() {
            bail!(
                "kernel not found at {} (pass --kernel, or use a `vk` with it embedded)",
                kernel.path.display()
            );
        }
        let agent = crate::embed::resolve(crate::embed::Asset::Agent, opts.agent.as_deref())?;
        if !agent.is_embedded() && !agent.path.is_file() {
            bail!(
                "vk-agent not found at {} (pass --agent, or use a `vk` with it embedded)",
                agent.path.display()
            );
        }
        (Some(kernel), Some(agent))
    } else {
        (None, None)
    };
    let mut ex: Box<dyn Executor> = if opts.microvm {
        let cache = cache_repo(opts.cache_registry.as_deref())?.map(|repo| {
            crate::config::Registry::for_share(
                repo,
                opts.cache_insecure,
                None,
                String::new(),
                None,
                None,
            )
        });
        let kernel = kernel.as_ref().expect("resolved under opts.microvm");
        let agent = agent.as_ref().expect("resolved under opts.microvm");
        Box::new(MicroVm::new(
            opts.cloud_hypervisor
                .clone()
                .context("--microvm needs --cloud-hypervisor")?,
            kernel.path.clone(),
            agent.path.clone(),
            scratch.clone(),
            cache,
            opts.journal,
            opts.net.clone(),
        ))
    } else {
        Box::new(Host::new(scratch.clone()))
    };
    let result = (|| -> Result<Built> {
        let (committed, states) = drive(&plan, &order, &build_args, ex.as_mut())?;
        let fs = committed
            .get(&target)
            .context("internal: target stage not committed")?;
        ex.export_ext4(fs, out)?;
        let st = states.get(&target).cloned().unwrap_or_default();
        let config = run_config(&st);
        // The sidecar persists the config the image itself deliberately does not
        // carry (clean-image model: config is supplied at boot, never baked in).
        let sidecar = config_sidecar(out);
        std::fs::write(&sidecar, serde_json::to_vec_pretty(&config)?)
            .with_context(|| format!("writing {}", sidecar.display()))?;
        Ok(Built { config })
    })();
    let _ = std::fs::remove_dir_all(&scratch); // best-effort scratch cleanup
    let built = result?;
    println!(
        "virtkit: built {} -> {}",
        opts.dockerfiles
            .iter()
            .map(|f| f.display().to_string())
            .collect::<Vec<_>>()
            .join(" + "),
        out.display()
    );
    Ok(built)
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
        // Seed the shell state: a stage inherits its base — a prior stage's final
        // state, or (for FROM <image>) the image config's ENV/USER/WORKDIR/
        // ENTRYPOINT/CMD — so RUNs get the base PATH etc. and the runtime config
        // survives RUN-less stages (a service stage that only COPYs still exports
        // its base's entrypoint). Fetched unconditionally (memoized per image).
        let mut state = match &stage.base {
            Base::Stage(parent) => out
                .get(parent)
                .map(|r| r.final_state.clone())
                .unwrap_or_default(),
            Base::Image(image) => {
                let cfg = ex.base_config(image)?;
                ShellState {
                    env: cfg.env,
                    user: cfg.user.unwrap_or_else(|| "root".into()),
                    workdir: cfg.workdir.unwrap_or_else(|| "/".into()),
                    entrypoint: cfg.entrypoint,
                    cmd: cfg.cmd,
                }
            }
            Base::Scratch => ShellState::default(),
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
            // Content the key must track beyond the instruction text (Docker semantics —
            // the cache follows the bytes an instruction reads, not just its spelling):
            //   - a context COPY keys on the sha256 of the files it references, so
            //     editing a copied source busts the cache;
            //   - a COPY --from=<stage> / RUN --mount=from=<stage> keys on the source
            //     stage's final key, so a change anywhere in the source stage chains
            //     into every consumer — without it, a consumer whose own instructions
            //     did not change would restore a snapshot holding the *old* source
            //     content. `--from=<image>` sources stay keyed by their reference text.
            let content = match &instr {
                Instruction::Copy(c) => match &c.from {
                    None => Some(context_copy_hash(&stage.context, c)),
                    Some(r) => source_stage_key(plan, &out, r),
                },
                Instruction::Run(r) => {
                    let keys: Vec<String> = r
                        .mounts
                        .iter()
                        .filter_map(|m| m.from.as_deref())
                        .filter_map(|f| source_stage_key(plan, &out, f))
                        .collect();
                    (!keys.is_empty()).then(|| keys.join("\n"))
                }
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
    dockerfiles: &[PathBuf],
    contexts: &[PathBuf],
    build_args: &[(String, String)],
) -> Result<Vec<(String, String)>> {
    let inputs = load_inputs(dockerfiles, contexts)?;
    let ba: Vars = build_args.iter().cloned().collect();
    let plan = Plan::from_dockerfiles(&inputs, &ba)?;
    let order = plan.all_order()?;
    let mut ex = exec::Planner::new();
    // canonical keys: DOCKER_STAGE_HASH is excluded (its injected value never affects a
    // stage's identity), so `docker-hash` prints exactly the key a build would store.
    let resolved = resolve_stages(&plan, &order, &ba, &mut ex, None)?;
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

/// The final key of the stage a `--from=<x>` names — its content identity, folded into
/// the consuming instruction's key. `None` when `x` is an external image (keyed by its
/// reference text alone) or an unresolvable `$VAR` ref (the same known limitation as
/// [`stage_source_refs`]). The source is always resolved first: it is a dependency, so
/// the topological order places it earlier.
fn source_stage_key(
    plan: &Plan,
    resolved: &HashMap<usize, Resolved>,
    reference: &str,
) -> Option<String> {
    let s = plan.stage_ref(reference)?;
    resolved.get(&s).map(|r| r.final_key.clone())
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
) -> Result<(HashMap<usize, Rootfs>, HashMap<usize, ShellState>)> {
    // Canonical, value-independent keys (DOCKER_STAGE_HASH forced empty while keying).
    let keyed = resolve_stages(plan, order, build_args, ex, None)?;
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
            let exec = resolve_stages(plan, order, build_args, ex, Some(&value))?;
            merge_exec(&keyed, exec)
        }
        None => keyed,
    };
    let mut committed: HashMap<usize, Rootfs> = HashMap::new();
    // Fast-path plan, back-to-front: a stage whose last snapshot is cached is "fully
    // cached" (keys chain, so that one key covers the stage's whole history including
    // its base and COPY --from sources) — it restores that snapshot alone, with no
    // per-instruction probes (a round trip each on a remote cache). A stage only ever
    // read by fully-cached consumers is skipped outright: nothing that runs will look
    // at it. `needed` propagates from the target; a stage that will run pulls in its
    // parent stage and `--from` sources.
    let mut needed: HashSet<usize> = HashSet::from([target]);
    let mut cached_final: HashMap<usize, String> = HashMap::new();
    for &idx in order.iter().rev() {
        if !needed.contains(&idx) {
            continue;
        }
        let steps = &resolved
            .get(&idx)
            .context("internal: stage not resolved")?
            .steps;
        if let Some(last) = steps.last()
            && ex.cache_has(&last.key)
        {
            cached_final.insert(idx, last.key.clone());
            continue;
        }
        let stage = &plan.stages[idx];
        if let Base::Stage(parent) = &stage.base {
            needed.insert(*parent);
        }
        needed.extend(stage_source_refs(plan, &stage.instructions));
    }
    for &idx in order {
        if !needed.contains(&idx) {
            continue;
        }
        let stage = &plan.stages[idx];
        let name = stage.name.clone().unwrap_or_else(|| format!("stage{idx}"));
        let steps = &resolved
            .get(&idx)
            .context("internal: stage not resolved")?
            .steps;
        // Fully cached: restore the final snapshot directly, nothing to probe or run.
        if let Some(key) = cached_final.get(&idx) {
            println!(
                "virtkit: build CACHED  {name} ({} instructions)",
                steps.len()
            );
            let fs = restore_into(ex, &name, key)?;
            ex.stage_end(&fs)?;
            committed.insert(idx, fs);
            continue;
        }
        // Declare the stage's inputs — the source stages it copies/mounts from, and its
        // build context — so the backend can attach them before the guest boots.
        ex.stage_sources(
            &stage_source_rootfs(plan, &stage.instructions, &committed),
            &stage.context,
        )?;
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
    // Each stage's final ENV/USER/WORKDIR, so a caller booting the exported image can run
    // a command with the image's environment (e.g. `run -f` applying PATH).
    let states = resolved
        .into_iter()
        .map(|(idx, r)| (idx, r.final_state))
        .collect();
    Ok((committed, states))
}

/// The stage indices an instruction list references via `COPY --from` / `RUN
/// --mount=from` (distinct, in source order). Resolved on the raw `--from` text —
/// literal stage names; a `--from=$VAR` would not be seen (a known limitation).
fn stage_source_refs(plan: &Plan, instructions: &[Instruction]) -> Vec<usize> {
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
    let mut seen: Vec<usize> = Vec::new();
    for r in refs {
        if let Some(si) = plan.stage_ref(r)
            && !seen.contains(&si)
        {
            seen.push(si);
        }
    }
    seen
}

/// [`stage_source_refs`] resolved to committed rootfs (stages not committed are
/// dropped — their consumers are fully cached, so no guest ever reads them).
fn stage_source_rootfs(
    plan: &Plan,
    instructions: &[Instruction],
    committed: &HashMap<usize, Rootfs>,
) -> Vec<Rootfs> {
    stage_source_refs(plan, instructions)
        .into_iter()
        .filter_map(|si| committed.get(&si).cloned())
        .collect()
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
    let ign = vk_core::dockerignore::Ignore::load(context);
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
fn copy_src_files(context: &Path, ign: &vk_core::dockerignore::Ignore, src: &str) -> Vec<PathBuf> {
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

/// Apply a non-filesystem instruction (ENV/WORKDIR/USER/ENTRYPOINT/CMD) — updates the
/// shell state only, so it needs no materialized rootfs.
fn apply_meta(state: &mut ShellState, instr: &Instruction) {
    match instr {
        Instruction::Env(kvs) => {
            for (k, v) in kvs {
                upsert(&mut state.env, k, v);
            }
        }
        Instruction::Workdir(w) => state.workdir = w.clone(),
        Instruction::User(u) => state.user = u.clone(),
        Instruction::Entrypoint(c) => {
            state.entrypoint = cmdline_argv(c);
            // Docker: declaring ENTRYPOINT resets an inherited CMD (a CMD later in
            // the same stage still applies).
            state.cmd.clear();
        }
        Instruction::Cmd(c) => state.cmd = cmdline_argv(c),
        // ARG/LABEL/Other: no effect here (ARG feeds interpolation upstream; LABEL
        // would land in an exported image config).
        _ => {}
    }
}

/// An ENTRYPOINT/CMD as argv: exec form verbatim, shell form wrapped `/bin/sh -c` —
/// Docker's runtime equivalence.
fn cmdline_argv(c: &parser::Cmdline) -> Vec<String> {
    match c {
        parser::Cmdline::Exec(v) => v.clone(),
        parser::Cmdline::Shell(s) => vec!["/bin/sh".into(), "-c".into(), s.clone()],
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

    /// A single-file plan whose stages' context is `/nonexistent` (the tests' COPYs
    /// hash an empty file set — deterministic without touching the host).
    fn plan_one(src: &str, ba: &Vars) -> Plan {
        Plan::from_dockerfiles(
            &[PlanInput {
                dockerfile: parser::parse(src).unwrap(),
                origin: "Dockerfile".into(),
                context: "/nonexistent".into(),
            }],
            ba,
        )
        .unwrap()
    }

    fn transcript(src: &str, target: Option<&str>) -> Vec<String> {
        let ba = Vars::new();
        let plan = plan_one(src, &ba);
        let t = plan.resolve_target(target).unwrap();
        let order = plan.build_order(t).unwrap();
        let mut ex = DryRun::new();
        drive(&plan, &order, &ba, &mut ex).unwrap();
        ex.transcript
    }

    /// A [`DryRun`] with an instruction cache: `cache_save` records keys, `cache_has`
    /// answers from them, and every cache primitive lands in the transcript so tests
    /// can assert what a warm rebuild touches.
    #[derive(Default)]
    struct CachedDry {
        inner: DryRun,
        cache: HashSet<String>,
        /// key of the most recent `cache_save` — the target's final key after a cold
        /// run, so tests can evict it to simulate a partially cached rebuild.
        last_saved: Option<String>,
    }

    impl Executor for CachedDry {
        fn from_image(&mut self, stage: &str, image: &str) -> Result<Rootfs> {
            self.inner.from_image(stage, image)
        }
        fn from_scratch(&mut self, stage: &str) -> Result<Rootfs> {
            self.inner.from_scratch(stage)
        }
        fn from_stage(&mut self, stage: &str, parent: &Rootfs) -> Result<Rootfs> {
            self.inner.from_stage(stage, parent)
        }
        fn pull(&mut self, image: &str) -> Result<Rootfs> {
            self.inner.pull(image)
        }
        fn run(
            &mut self,
            fs: &Rootfs,
            cmd: &parser::Cmdline,
            mounts: &[ResolvedMount<'_>],
            state: &ShellState,
        ) -> Result<()> {
            self.inner.run(fs, cmd, mounts, state)
        }
        fn copy(&mut self, fs: &Rootfs, op: &parser::Copy, from: Option<&Rootfs>) -> Result<()> {
            self.inner.copy(fs, op, from)
        }
        fn export_ext4(&mut self, fs: &Rootfs, out: &Path) -> Result<()> {
            self.inner.export_ext4(fs, out)
        }
        fn cache_has(&mut self, key: &str) -> bool {
            let hit = self.cache.contains(key);
            self.inner
                .transcript
                .push(format!("cache-has {key} -> {hit}"));
            hit
        }
        fn cache_restore(&mut self, fs: &Rootfs, key: &str) -> Result<()> {
            self.inner
                .transcript
                .push(format!("cache-restore {} <- {key}", fs.label));
            Ok(())
        }
        fn cache_save(&mut self, _fs: &Rootfs, key: &str) -> Result<()> {
            self.cache.insert(key.to_string());
            self.last_saved = Some(key.to_string());
            Ok(())
        }
    }

    #[test]
    fn fully_cached_build_restores_final_snapshot_only() {
        let src = "FROM alpine AS builder\nRUN one\n\nFROM alpine\nRUN two\nRUN three\n";
        let ba = Vars::new();
        let plan = plan_one(src, &ba);
        let t = plan.resolve_target(None).unwrap();
        let order = plan.build_order(t).unwrap();
        // cold: everything runs and populates the cache
        let mut ex = CachedDry::default();
        drive(&plan, &order, &ba, &mut ex).unwrap();
        assert!(ex.inner.transcript.iter().any(|l| l.starts_with("run ")));
        // warm: one probe of the target's final key, one restore — no per-step
        // probes, nothing built, the builder stage never touched
        let mut ex = CachedDry {
            inner: DryRun::new(),
            cache: ex.cache,
            last_saved: None,
        };
        drive(&plan, &order, &ba, &mut ex).unwrap();
        let t = &ex.inner.transcript;
        assert_eq!(t.len(), 2, "{t:?}");
        assert!(
            t[0].starts_with("cache-has ") && t[0].ends_with("-> true"),
            "{t:?}"
        );
        assert!(t[1].starts_with("cache-restore "), "{t:?}");
    }

    #[test]
    fn partially_cached_build_fast_paths_cached_stages() {
        let src = "FROM alpine AS builder\nRUN one\nRUN two\n\n\
                   FROM alpine\nRUN three\nCOPY --from=builder /a /b\n";
        let ba = Vars::new();
        let plan = plan_one(src, &ba);
        let t = plan.resolve_target(None).unwrap();
        let order = plan.build_order(t).unwrap();
        // cold run populates the cache; evict the target's final key so only the
        // target's last instruction must re-run
        let mut ex = CachedDry::default();
        drive(&plan, &order, &ba, &mut ex).unwrap();
        let mut cache = ex.cache;
        cache.remove(&ex.last_saved.unwrap());
        let mut ex = CachedDry {
            inner: DryRun::new(),
            cache,
            last_saved: None,
        };
        drive(&plan, &order, &ba, &mut ex).unwrap();
        let t = &ex.inner.transcript;
        let count = |p: &str| t.iter().filter(|l| l.starts_with(p)).count();
        // probes: the target's last key (miss), the builder's last key (hit), then the
        // target per-step (hit, miss) — the builder's per-step keys are never probed
        assert_eq!(count("cache-has "), 4, "{t:?}");
        // restores: the builder's final snapshot + the target's cached prefix
        assert_eq!(count("cache-restore "), 2, "{t:?}");
        // only the evicted COPY re-runs; no RUN and no base pull anywhere
        assert_eq!(count("copy "), 1, "{t:?}");
        assert_eq!(count("run "), 0, "{t:?}");
        assert_eq!(count("from-image "), 0, "{t:?}");
    }

    #[test]
    fn cache_repo_resolution() {
        assert_eq!(cache_repo(Some("none")).unwrap(), None);
        assert_eq!(
            cache_repo(Some("127.0.0.1:5000")).unwrap().as_deref(),
            Some("127.0.0.1:5000")
        );
        // The default must be an absolute path so Registry::local_root treats it
        // as an in-process store rather than a registry host.
        let default = cache_repo(None).unwrap().unwrap();
        assert!(default.starts_with('/'), "not absolute: {default}");
        // A relative path would be misread as a registry host; refuse it.
        assert!(cache_repo(Some("./cache")).is_err());
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
    fn copy_keys_hash_the_stage_context() {
        // A context COPY's content hash reads the *stage's* recorded context — and the
        // context path itself never enters the key (same content in two places, same key).
        let tmp = std::env::temp_dir().join(format!("vk-stagectx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        for d in ["a", "b", "c"] {
            std::fs::create_dir_all(tmp.join(d)).unwrap();
        }
        std::fs::write(tmp.join("a/f.txt"), "one").unwrap();
        std::fs::write(tmp.join("b/f.txt"), "two").unwrap();
        std::fs::write(tmp.join("c/f.txt"), "one").unwrap(); // same content as a/
        let ba = Vars::new();
        let key = |ctx: &Path| {
            let plan = Plan::from_dockerfiles(
                &[PlanInput {
                    dockerfile: parser::parse("FROM scratch\nCOPY f.txt /f\n").unwrap(),
                    origin: "Dockerfile".into(),
                    context: ctx.to_path_buf(),
                }],
                &ba,
            )
            .unwrap();
            assert_eq!(plan.stages[0].context, ctx);
            let order = plan.all_order().unwrap();
            let mut ex = DryRun::new();
            resolve_stages(&plan, &order, &ba, &mut ex, None).unwrap()[&0]
                .final_key
                .clone()
        };
        let (a, b, c) = (tmp.join("a"), tmp.join("b"), tmp.join("c"));
        assert_ne!(key(&a), key(&b)); // different content -> different key
        assert_eq!(key(&a), key(&c)); // same content elsewhere -> same key
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn drive_declares_each_stage_context() {
        let t = transcript("FROM scratch AS s\nCOPY f /f\n", None);
        assert!(
            t.contains(&"stage-context /nonexistent".to_string()),
            "{t:#?}"
        );
    }

    #[test]
    fn load_inputs_zips_contexts_with_files() {
        let tmp = std::env::temp_dir().join(format!("vk-loadinputs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("a")).unwrap();
        std::fs::create_dir_all(tmp.join("b")).unwrap();
        std::fs::write(tmp.join("a/Dockerfile"), "FROM scratch AS x\n").unwrap();
        std::fs::write(tmp.join("b/Dockerfile"), "FROM scratch AS y\n").unwrap();
        let files = [tmp.join("a/Dockerfile"), tmp.join("b/Dockerfile")];

        // no --context: each file defaults to its own directory.
        let inputs = load_inputs(&files, &[]).unwrap();
        assert_eq!(inputs[0].context, tmp.join("a"));
        assert_eq!(inputs[1].context, tmp.join("b"));
        // one --context: pairs with the first file, the second keeps its default.
        let inputs = load_inputs(&files, std::slice::from_ref(&tmp)).unwrap();
        assert_eq!(inputs[0].context, tmp);
        assert_eq!(inputs[1].context, tmp.join("b"));
        // more contexts than files / no files: errors.
        let err = load_inputs(&files[..1], &[tmp.clone(), tmp.clone()]).unwrap_err();
        assert!(format!("{err:#}").contains("zip positionally"), "{err:#}");
        assert!(load_inputs(&[], &[]).is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn build_net_from_flags() {
        assert_eq!(
            BuildNet::from_flags("all", &[], &[]).unwrap(),
            BuildNet::All
        );
        assert_eq!(
            BuildNet::from_flags("none", &[], &[]).unwrap(),
            BuildNet::None
        );
        let ips = vec!["10.0.0.0/8:443".to_string()];
        let names = vec!["crates.io".to_string()];
        assert_eq!(
            BuildNet::from_flags("all", &ips, &names).unwrap(),
            BuildNet::Allow {
                ips: ips.clone(),
                names: names.clone()
            }
        );
        // `none` + an allowlist is contradictory; bad values fail before any build work.
        assert!(BuildNet::from_flags("none", &ips, &[]).is_err());
        assert!(BuildNet::from_flags("all", &["not-a-cidr".into()], &[]).is_err());
        assert!(BuildNet::from_flags("half", &[], &[]).is_err());
    }

    #[test]
    fn cross_file_build_uses_each_files_context() {
        // Two files, two contexts: the merged build hashes each stage's COPY against
        // its own file's context, and editing one context busts only that stage's key
        // (and its dependents' — the chain), not the other file's.
        let tmp = std::env::temp_dir().join(format!("vk-crossctx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        for d in ["a", "b"] {
            std::fs::create_dir_all(tmp.join(d)).unwrap();
        }
        std::fs::write(tmp.join("a/Dockerfile"), "FROM scratch AS lib\nCOPY f /f\n").unwrap();
        std::fs::write(tmp.join("a/f"), "lib-v1").unwrap();
        std::fs::write(
            tmp.join("b/Dockerfile"),
            "FROM scratch AS app\nCOPY --from=lib /f /lib-f\nCOPY f /app-f\n",
        )
        .unwrap();
        std::fs::write(tmp.join("b/f"), "app-v1").unwrap();
        let files = [tmp.join("a/Dockerfile"), tmp.join("b/Dockerfile")];

        let keys = || {
            let m: HashMap<String, String> =
                stage_keys(&files, &[], &[]).unwrap().into_iter().collect();
            (m["lib"].clone(), m["app"].clone())
        };
        let (lib1, app1) = keys();
        // editing file a's context changes lib's key, and chains into app (which
        // COPY --froms it) …
        std::fs::write(tmp.join("a/f"), "lib-v2").unwrap();
        let (lib2, app2) = keys();
        assert_ne!(lib1, lib2);
        assert_ne!(app1, app2);
        // … while editing file b's context touches only app.
        std::fs::write(tmp.join("b/f"), "app-v2").unwrap();
        let (lib3, app3) = keys();
        assert_eq!(lib2, lib3);
        assert_ne!(app2, app3);

        // the drive declares each stage's own context to the backend.
        let ba = Vars::new();
        let plan = Plan::from_dockerfiles(&load_inputs(&files, &[]).unwrap(), &ba).unwrap();
        let order = plan
            .build_order(plan.resolve_target(Some("app")).unwrap())
            .unwrap();
        let mut ex = DryRun::new();
        drive(&plan, &order, &ba, &mut ex).unwrap();
        let t = ex.transcript;
        assert!(
            t.contains(&format!("stage-context {}", tmp.join("a").display())),
            "{t:#?}"
        );
        assert!(
            t.contains(&format!("stage-context {}", tmp.join("b").display())),
            "{t:#?}"
        );
        assert!(t.iter().any(|l| l.starts_with("copy from=lib ")), "{t:#?}");
        let _ = std::fs::remove_dir_all(&tmp);
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
            let plan = plan_one(source, &ba);
            let order = plan.all_order().unwrap();
            let mut ex = DryRun::new();
            resolve_stages(&plan, &order, &ba, &mut ex, None).unwrap()
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
    fn source_stage_changes_chain_into_consumers() {
        // A consumer restoring its cached snapshot must re-key whenever a stage it
        // copies/mounts from changed — else it would restore the old source content.
        let ba = Vars::new();
        let keys = |src: &str| {
            let plan = plan_one(src, &ba);
            let order = plan.all_order().unwrap();
            let mut ex = DryRun::new();
            let r = resolve_stages(&plan, &order, &ba, &mut ex, None).unwrap();
            (r[&0].final_key.clone(), r[&1].final_key.clone())
        };
        // COPY --from=<stage>
        let a = "FROM alpine AS lib\nRUN one\nFROM alpine AS app\nCOPY --from=lib /f /f\n";
        let (lib1, app1) = keys(a);
        let (lib2, app2) = keys(&a.replace("RUN one", "RUN two"));
        assert_ne!(lib1, lib2);
        assert_ne!(app1, app2);
        // RUN --mount=from=<stage>
        let a = "FROM alpine AS lib\nRUN one\nFROM alpine AS app\n\
                 RUN --mount=type=bind,from=lib,target=/l use\n";
        let (lib1, app1) = keys(a);
        let (lib2, app2) = keys(&a.replace("RUN one", "RUN two"));
        assert_ne!(lib1, lib2);
        assert_ne!(app1, app2);
        // a COPY --from=<external image> folds no stage key (keyed by its text alone):
        // the consumer's key is indifferent to unrelated stage edits.
        let a = "FROM alpine AS lib\nRUN one\nFROM alpine AS app\n\
                 COPY --from=busybox:latest /bin/sh /sh\n";
        let (lib1, app1) = keys(a);
        let (lib2, app2) = keys(&a.replace("RUN one", "RUN two"));
        assert_ne!(lib1, lib2);
        assert_eq!(app1, app2);
    }

    #[test]
    fn runtime_config_accumulates_and_inherits_across_stages() {
        // ENTRYPOINT/CMD/ENV/USER/WORKDIR fold into the stage state, inherit through
        // FROM <stage>, and follow Docker's ENTRYPOINT-resets-CMD rule.
        let ba = Vars::new();
        let src = "\
FROM scratch AS base
ENV A=1
ENTRYPOINT [\"/bin/app\"]
CMD [\"--serve\"]
FROM base AS child
FROM base AS override
ENTRYPOINT run me
";
        let plan = plan_one(src, &ba);
        let order = plan.all_order().unwrap();
        let mut ex = DryRun::new();
        let r = resolve_stages(&plan, &order, &ba, &mut ex, None).unwrap();
        let base = &r[&0].final_state;
        assert_eq!(base.entrypoint, ["/bin/app"]);
        assert_eq!(base.cmd, ["--serve"]);
        // an instruction-less child inherits everything
        let child = &r[&1].final_state;
        assert_eq!(child.entrypoint, ["/bin/app"]);
        assert_eq!(child.cmd, ["--serve"]);
        assert_eq!(child.env, [("A".to_string(), "1".to_string())]);
        // re-declaring ENTRYPOINT (shell form -> /bin/sh -c) resets the inherited CMD
        let ov = &r[&2].final_state;
        assert_eq!(ov.entrypoint, ["/bin/sh", "-c", "run me"]);
        assert!(ov.cmd.is_empty());
    }

    #[test]
    fn build_writes_the_runtime_config_sidecar() {
        // a Host (FROM scratch + COPY) build exports the ext4 plus its config sidecar.
        let tmp = std::env::temp_dir().join(format!("vk-sidecar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("f"), "x").unwrap();
        std::fs::write(
            tmp.join("Dockerfile"),
            "FROM scratch\nCOPY f /f\nENV PORT=6379\nUSER svc\nWORKDIR /srv\n\
             ENTRYPOINT [\"/bin/app\"]\nCMD [\"--port\", \"6379\"]\n",
        )
        .unwrap();
        let out = tmp.join("img.ext4");
        let built = build(&Options {
            dockerfiles: vec![tmp.join("Dockerfile")],
            target: None,
            contexts: vec![],
            out: Some(out.clone()),
            print_plan: false,
            microvm: false,
            cloud_hypervisor: None,
            kernel: None,
            agent: None,
            cache_registry: Some("none".into()),
            cache_insecure: false,
            journal: false,
            build_args: vec![],
            net: BuildNet::None, // host backend: no RUN guests, no network
        })
        .unwrap();
        let sidecar = config_sidecar(&out);
        let cfg: vk_core::runcfg::RunConfig =
            serde_json::from_slice(&std::fs::read(&sidecar).unwrap()).unwrap();
        assert_eq!(cfg, built.config);
        assert_eq!(cfg.env, [("PORT".to_string(), "6379".to_string())]);
        assert_eq!(cfg.user, "svc");
        assert_eq!(cfg.workdir, "/srv");
        assert_eq!(cfg.argv(), ["/bin/app", "--port", "6379"]);
        let _ = std::fs::remove_dir_all(&tmp);
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
        let plan = plan_one(src, &ba);
        let target = plan.resolve_target(Some("app")).unwrap();
        let order = plan.build_order(target).unwrap();
        // 'app' does not declare it; the nearest declarer in its closure is 'core' (0).
        assert_eq!(nearest_dsh_declarer(&plan, target), Some(0));

        // canonical (key-pass) keys, DOCKER_STAGE_HASH excluded.
        let mut ex = DryRun::new();
        let keyed = resolve_stages(&plan, &order, &ba, &mut ex, None).unwrap();
        let value = keyed[&0].final_key.clone();
        // exec pass injects core's stage_key, then merge keeps the canonical keys.
        let mut ex2 = DryRun::new();
        let exec = resolve_stages(&plan, &order, &ba, &mut ex2, Some(&value)).unwrap();
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
        let exec_other = resolve_stages(&plan, &order, &ba, &mut ex3, Some("deadbeef")).unwrap();
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
