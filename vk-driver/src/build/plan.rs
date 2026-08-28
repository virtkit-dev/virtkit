//! Group the instruction stream into build stages and order them by dependency.
//!
//! A stage begins at each `FROM`. Its base is either another stage (when `FROM`
//! names a prior stage by `AS` name or by index) or an external image. Cross-stage
//! edges also come from `COPY --from=<stage>` and `RUN --mount=…,from=<stage>`.
//! `build_order(target)` returns the target stage's transitive dependencies in
//! topological order; a cycle is an error. This mirrors how buildkit resolves stages
//! and only solves the subgraph the requested target needs (moby/buildkit
//! frontend/dockerfile/dockerfile2llb: `toDispatchState` + stage resolution).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use super::interp::{self, Vars};
use super::parser::{Dockerfile, Instruction};

/// What a stage builds on top of.
#[derive(Debug, Clone, PartialEq)]
pub enum Base {
    /// An external image reference (e.g. `debian:bookworm`).
    Image(String),
    /// A prior build stage, by index into [`Plan::stages`].
    Stage(usize),
    /// `FROM scratch` — the empty base.
    Scratch,
}

/// One build stage.
#[derive(Debug, Clone)]
pub struct Stage {
    /// This stage's index in [`Plan::stages`] (used by callers/diagnostics).
    #[allow(dead_code)]
    pub index: usize,
    pub name: Option<String>,
    pub base: Base,
    /// `FROM --kernel=image`: run this stage's RUN steps on the kernel from its base
    /// image (the preinit boot), not vk's embedded build kernel. The base must carry a
    /// kernel (build one in a prior stage and `FROM` it).
    pub image_kernel: bool,
    /// `# vk: mem=8G cpus=16` above the `FROM`: how big a guest this stage's RUN steps
    /// want. Unset fields take the build-wide `[build] mem` / `[build] cpus`.
    pub guest: crate::build::parser::GuestHint,
    /// Instructions after the `FROM`, in order (the `FROM` itself excluded).
    pub instructions: Vec<Instruction>,
    /// Build-context root the stage's `COPY` (no `--from`) resolves against — the
    /// context of the [`PlanInput`] that declared the stage. The path itself never
    /// enters cache keys (only context-relative names + file content do), so where a
    /// context lives cannot bust the cache.
    pub context: PathBuf,
}

/// One Dockerfile going into a [`Plan`], with the paths its stages resolve against.
#[derive(Debug)]
pub struct PlanInput {
    pub dockerfile: Dockerfile,
    /// Where the Dockerfile came from (diagnostics only).
    pub origin: PathBuf,
    /// Build-context root for the stages this file declares (default: the file's dir).
    pub context: PathBuf,
}

/// A resolved Dockerfile: its stages, plus a name→index lookup.
#[derive(Debug, Clone)]
pub struct Plan {
    pub stages: Vec<Stage>,
    /// Resolved global `ARG`s (declared before the first `FROM`): name → value, after
    /// applying `--build-arg` overrides over the declared defaults. Available to `FROM`
    /// interpolation and, when a stage re-declares `ARG <name>` with no default, to that
    /// stage.
    pub global_args: Vars,
    /// Named build contexts (`--build-context <name>=<dir>`): a `--from=<name>` reference
    /// resolves to this host directory, letting a stage read files outside its own build
    /// context. Set from the build options after planning; empty by default.
    pub named_contexts: BTreeMap<String, PathBuf>,
    by_name: BTreeMap<String, usize>,
}

impl Plan {
    /// Build the plan from parsed Dockerfiles, merged into one stage namespace: split
    /// each file into stages (indices run across files, in input order) and resolve
    /// every `FROM` base.
    ///
    /// Within a file, references keep the Docker rule — a `FROM <name>` only sees
    /// stages declared before it in that file, and a `FROM <index>` only earlier
    /// (global) indices. Across files, a name declared in a *different* file resolves
    /// as a stage regardless of input order (the topological build order handles the
    /// forward edges; cycles are rejected there). Precedence: same-file-earlier stage,
    /// then other-file stage, then external image. A stage name declared in two files
    /// is an error.
    ///
    /// Global `ARG`s (before a file's first `FROM`) interpolate that file's `FROM`
    /// refs file-locally, and merge into one namespace for `stage_ref` lookups —
    /// two files re-declaring one name must resolve it to the same value
    /// (`build_args` overrides both sides, so `--build-arg` always unifies).
    pub fn from_dockerfiles(inputs: &[PlanInput], build_args: &Vars) -> Result<Plan> {
        /// A `FROM` base after pass 1: resolved, or a name deferred to pass 2 (it may
        /// be a stage of another file, else an external image).
        enum Pending {
            Done(Base),
            Name(String),
        }

        let mut stages: Vec<Stage> = Vec::new();
        let mut pending: Vec<Pending> = Vec::new(); // parallel to `stages`
        let mut file_of: Vec<usize> = Vec::new(); // stage index -> input index
        // name -> (stage index, declaring input index)
        let mut by_name: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        let mut global_args: Vars = Vars::new();
        let mut arg_of: BTreeMap<String, usize> = BTreeMap::new(); // ARG -> input index

        // Pass 1: split every file into stages. Same-file name references resolve
        // exactly as before (source order, latest-earlier declaration); anything else
        // non-numeric is deferred.
        for (fi, input) in inputs.iter().enumerate() {
            let mut file_names: BTreeMap<String, usize> = BTreeMap::new();
            let mut file_args: Vars = Vars::new();
            let mut file_has_stage = false;
            for instr in &input.dockerfile.instructions {
                match instr {
                    Instruction::From(f) => {
                        // expand ${ARG} in the image ref against this file's global args.
                        let image = interp::interpolate(&f.image, &file_args);
                        let index = stages.len();
                        let base = if image.eq_ignore_ascii_case("scratch") {
                            Pending::Done(Base::Scratch)
                        } else if let Some(&i) = file_names.get(&image) {
                            Pending::Done(Base::Stage(i))
                        } else if let Ok(i) = image.parse::<usize>() {
                            // `FROM 0` — a stage by (global) numeric index, backward only
                            if i < index {
                                Pending::Done(Base::Stage(i))
                            } else {
                                Pending::Done(Base::Image(image.clone()))
                            }
                        } else {
                            Pending::Name(image)
                        };
                        if let Some(name) = &f.as_name {
                            file_names.insert(name.clone(), index);
                        }
                        stages.push(Stage {
                            index,
                            name: f.as_name.clone(),
                            base: Base::Scratch, // placeholder until pass 2
                            image_kernel: f.image_kernel,
                            guest: f.guest.clone(),
                            instructions: Vec::new(),
                            context: input.context.clone(),
                        });
                        pending.push(base);
                        file_of.push(fi);
                        file_has_stage = true;
                    }
                    // Global ARG before this file's first stage: resolve it (build-arg
                    // override, else its interpolated default, else empty) into the
                    // file scope, and merge into the shared namespace equal-or-error.
                    Instruction::Arg { name, default } if !file_has_stage => {
                        let value = build_args.get(name).cloned().unwrap_or_else(|| {
                            default
                                .as_deref()
                                .map(|d| interp::interpolate(d, &file_args))
                                .unwrap_or_default()
                        });
                        match global_args.get(name) {
                            // conflict only across files: within one file, Docker's
                            // last-declaration-wins rule applies.
                            Some(prev) if *prev != value && arg_of[name] != fi => bail!(
                                "global ARG {name} resolves to {prev:?} in {} but {value:?} in {} \
                                 (pass --build-arg {name}=... to unify)",
                                inputs[arg_of[name]].origin.display(),
                                input.origin.display()
                            ),
                            _ => {
                                global_args.insert(name.clone(), value.clone());
                                arg_of.entry(name.clone()).or_insert(fi);
                            }
                        }
                        file_args.insert(name.clone(), value);
                    }
                    other => {
                        // only this file's own stages may receive instructions.
                        if !file_has_stage {
                            bail!(
                                "instruction before the first FROM in {}: {other:?}",
                                input.origin.display()
                            );
                        }
                        let stage = stages.last_mut().expect("file_has_stage");
                        stage.instructions.push(other.clone());
                    }
                }
            }
            // Fold this file's names into the merged namespace: a name declared in two
            // files is ambiguous everywhere it is referenced, so it is always an error.
            for (name, idx) in file_names {
                if let Some((_, prev_fi)) = by_name.get(&name)
                    && *prev_fi != fi
                {
                    bail!(
                        "stage {name:?} is declared in both {} and {}",
                        inputs[*prev_fi].origin.display(),
                        input.origin.display()
                    );
                }
                by_name.insert(name, (idx, fi));
            }
        }
        if stages.is_empty() {
            bail!("no FROM / no stages in the Dockerfile");
        }
        // Pass 2: a deferred name declared in a *different* file is a stage (any input
        // order); a same-file (necessarily later) declaration keeps Docker's rule — the
        // ref is an external image. A name in two files never gets here (error above).
        for (g, p) in pending.into_iter().enumerate() {
            stages[g].base = match p {
                Pending::Done(base) => base,
                Pending::Name(n) => match by_name.get(&n) {
                    Some(&(i, fi)) if fi != file_of[g] => Base::Stage(i),
                    _ => Base::Image(n),
                },
            };
        }
        Ok(Plan {
            stages,
            global_args,
            named_contexts: BTreeMap::new(),
            by_name: by_name.into_iter().map(|(k, (i, _))| (k, i)).collect(),
        })
    }

    /// Resolve a target selector (a stage `AS` name, or an index) to its stage index.
    /// `None` selects the last stage (Docker's default build target).
    pub fn resolve_target(&self, target: Option<&str>) -> Result<usize> {
        match target {
            None => Ok(self.stages.len() - 1),
            Some(t) => {
                if let Some(&i) = self.by_name.get(t) {
                    return Ok(i);
                }
                if let Ok(i) = t.parse::<usize>()
                    && i < self.stages.len()
                {
                    return Ok(i);
                }
                bail!("unknown build target {t:?}");
            }
        }
    }

    /// The direct stage dependencies of `stage`: its base (if a stage) plus every
    /// `COPY --from`/`RUN --mount=…,from=` that names a stage. External-image refs are
    /// not build dependencies (they are pulled, not built), so they are excluded.
    pub fn deps(&self, stage: usize) -> Vec<usize> {
        let s = &self.stages[stage];
        let mut deps = Vec::new();
        if let Base::Stage(i) = s.base {
            deps.push(i);
        }
        let mut note = |reference: &str| {
            if let Some(i) = self.stage_ref(reference) {
                deps.push(i);
            }
        };
        for instr in &s.instructions {
            match instr {
                Instruction::Copy(c) => {
                    if let Some(from) = &c.from {
                        note(from);
                    }
                }
                Instruction::Run(r) => {
                    for m in &r.mounts {
                        if let Some(from) = &m.from {
                            note(from);
                        }
                    }
                }
                _ => {}
            }
        }
        deps.sort_unstable();
        deps.dedup();
        deps
    }

    /// A `--from=<x>` reference → a stage index, or `None` when `x` is an external
    /// image (so it does not create a build edge). `${ARG}` in the reference is expanded
    /// against the global args (e.g. `COPY --from=builder-${ver}`); a stage-local ARG in
    /// a `--from` is still not resolved here (it is not in scope at plan time).
    pub(crate) fn stage_ref(&self, reference: &str) -> Option<usize> {
        let reference = interp::interpolate(reference, &self.global_args);
        if let Some(&i) = self.by_name.get(&reference) {
            return Some(i);
        }
        reference
            .parse::<usize>()
            .ok()
            .filter(|&i| i < self.stages.len())
    }

    /// Reject a stage name the backend reserves. `--from=scratch` always names the reserved
    /// empty base a `RUN --mount` gets as an ephemeral writable disk, so it never resolves to a
    /// stage — meaning nothing could ever read from one by that name. A `/` is rejected too: it
    /// is what keeps a stage's label out of the `image/<ref>` and `context/<name>` namespaces
    /// a non-stage `--from` source is attached under (see `exec::image_source_label` and
    /// `exec::context_source_label`), and Docker rejects it in a stage name anyway. Both fail
    /// here, before any build work, rather than letting a `COPY --from=…` silently read the
    /// wrong thing. Only the stages in `order` (the ones actually built) are checked.
    pub fn check_reserved_names(&self, order: &[usize]) -> Result<()> {
        for &idx in order {
            let Some(name) = self.stages[idx].name.as_deref() else {
                continue;
            };
            if name == "scratch" {
                bail!(
                    "stage name \"scratch\" is reserved: `--from=scratch` always names the empty \
                     base a `RUN --mount` uses as writable scratch, so nothing could read from \
                     this stage. Rename it."
                );
            }
            if name.contains('/') {
                bail!(
                    "stage name {name:?} may not contain '/': a `--from=` source that is not a \
                     stage is attached under `image/<ref>` or `context/<name>`, which such a name \
                     would shadow. Rename it."
                );
            }
        }
        Ok(())
    }

    /// A `--from=<x>` reference naming a build context declared with `--build-context`.
    /// Resolved *after* stages and *before* an external image, so declaring a context can
    /// never change what an existing Dockerfile means: a stage of the same name still wins.
    /// `${ARG}` is expanded as in [`Plan::stage_ref`].
    pub(crate) fn named_context(&self, reference: &str) -> Option<&Path> {
        let reference = interp::interpolate(reference, &self.global_args);
        self.named_contexts.get(&reference).map(PathBuf::as_path)
    }

    /// Reject a `COPY --from=<stage>` / `RUN --mount=…,from=<stage>` whose source lives
    /// under `/tmp`. A build guest's `/tmp` is an ephemeral scratch disk that never enters
    /// the stage's committed image (see the microVM executor), so such a source is always
    /// empty when another stage reads it — this fails here, before any build work, with a
    /// fix instead of a late, cryptic "No such file" from inside the guest. External-image
    /// `--from`s are exempt (their `/tmp` is a real, committed part of the image). Only the
    /// stages in `order` (the ones actually built) are checked.
    pub fn check_tmp_sources(&self, order: &[usize]) -> Result<()> {
        for &idx in order {
            for instr in &self.stages[idx].instructions {
                match instr {
                    Instruction::Copy(c) => {
                        if let Some(from) = &c.from
                            && self.stage_ref(from).is_some()
                        {
                            for src in &c.sources {
                                if is_ephemeral_tmp(src) {
                                    bail!("{}", tmp_source_error("COPY --from", from, src));
                                }
                            }
                        }
                    }
                    Instruction::Run(r) => {
                        for m in &r.mounts {
                            if let Some(from) = &m.from
                                && self.stage_ref(from).is_some()
                                && let Some(src) = &m.source
                                && is_ephemeral_tmp(src)
                            {
                                bail!("{}", tmp_source_error("RUN --mount=…,from", from, src));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Topological build order for `target` and its transitive dependencies only.
    /// Errors on a dependency cycle.
    pub fn build_order(&self, target: usize) -> Result<Vec<usize>> {
        let mut order = Vec::new();
        // 0 = unvisited, 1 = on stack (visiting), 2 = done
        let mut state = vec![0u8; self.stages.len()];
        self.visit(target, &mut state, &mut order)?;
        Ok(order)
    }

    /// Topological build order for a *set* of targets and their transitive dependencies —
    /// the union pruned to what those targets need, each stage after its deps (a stage
    /// shared by several targets appears once). Backs a unified multi-target build. Errors
    /// on a dependency cycle.
    pub fn build_order_multi(&self, targets: &[usize]) -> Result<Vec<usize>> {
        let mut order = Vec::new();
        let mut state = vec![0u8; self.stages.len()];
        for &t in targets {
            self.visit(t, &mut state, &mut order)?;
        }
        Ok(order)
    }

    /// Topological order over *every* stage (not pruned to a single target), so a caller
    /// that needs all stages — e.g. `docker-hash` printing every stage's key — gets each
    /// one after its dependencies. Errors on a dependency cycle.
    pub fn all_order(&self) -> Result<Vec<usize>> {
        let mut order = Vec::new();
        let mut state = vec![0u8; self.stages.len()];
        for i in 0..self.stages.len() {
            self.visit(i, &mut state, &mut order)?;
        }
        Ok(order)
    }

    /// Iterative post-order DFS (explicit stack, not recursion) so a deeply-nested but
    /// acyclic `FROM` chain in an untrusted Dockerfile cannot overflow the call stack.
    /// `stack` entries are `(node, finalize)`: a node is first visited (marked in-progress
    /// and its deps pushed), then popped a second time to finalize into `order`. Deps are
    /// pushed in reverse so they finalize in `deps()` order, matching the old recursion.
    fn visit(&self, node: usize, state: &mut [u8], order: &mut Vec<usize>) -> Result<()> {
        let mut stack = vec![(node, false)];
        while let Some((n, finalize)) = stack.pop() {
            if finalize {
                if state[n] != 2 {
                    state[n] = 2;
                    order.push(n);
                }
                continue;
            }
            match state[n] {
                2 => continue,
                1 => bail!(
                    "dependency cycle through stage {} ({:?})",
                    n,
                    self.stages[n].name
                ),
                _ => {}
            }
            state[n] = 1;
            stack.push((n, true));
            for dep in self.deps(n).into_iter().rev() {
                stack.push((dep, false));
            }
        }
        Ok(())
    }
}

/// Whether `path` (a `--from` source, so relative to the source stage's root) lands under
/// the ephemeral `/tmp` disk — after stripping a leading `/` or `./`.
fn is_ephemeral_tmp(path: &str) -> bool {
    let p = path.trim_start_matches('/');
    let p = p.strip_prefix("./").unwrap_or(p);
    p == "tmp" || p.starts_with("tmp/")
}

fn tmp_source_error(kind: &str, from: &str, src: &str) -> String {
    format!(
        "{kind}={from} {src:?}: /tmp is an ephemeral build scratch disk that is never part \
         of a stage's committed image, so it cannot be a cross-stage source. Have the \
         {from:?} stage write the artifact to a persistent path (e.g. /out) instead of /tmp."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::parser::parse;

    /// A single-file [`PlanInput`] with a placeholder origin/context (tests that care
    /// about contexts build their own inputs).
    fn input(src: &str) -> PlanInput {
        PlanInput {
            dockerfile: parse(src).unwrap(),
            origin: "Dockerfile".into(),
            context: "/nonexistent".into(),
        }
    }

    fn plan_args(src: &str, build_args: &Vars) -> Result<Plan> {
        Plan::from_dockerfiles(&[input(src)], build_args)
    }

    fn plan(src: &str) -> Plan {
        plan_args(src, &Vars::new()).unwrap()
    }

    #[test]
    fn later_file_leading_args_stay_global_and_stray_instructions_bail() {
        // Per-file boundary: a second file's leading ARG is global — it must not
        // attach to the previous file's last stage — and its instruction before the
        // file's first FROM errors.
        let two = |a: &str, b: &str| Plan::from_dockerfiles(&[input(a), input(b)], &Vars::new());
        let p = two(
            "FROM alpine AS one\nRUN x\n",
            "ARG ver=9\nFROM debian:${ver} AS two\n",
        )
        .unwrap();
        assert_eq!(p.stages[0].instructions.len(), 1); // RUN x only, no stray ARG
        assert_eq!(p.stages[1].base, Base::Image("debian:9".into()));
        assert!(two("FROM alpine\n", "RUN x\nFROM alpine\n").is_err());
    }

    #[test]
    fn named_context_lookup_is_separate_from_stage_ref() {
        let mut p = plan("FROM alpine AS base\nFROM alpine\nCOPY --from=base /a /a\n");
        p.named_contexts
            .insert("base".into(), PathBuf::from("/shadowed"));
        p.named_contexts
            .insert("shared".into(), PathBuf::from("/repo/shared"));
        // A stage of the same name keeps its meaning: declaring a context cannot silently
        // repoint an existing `--from=<stage>`. (What resolves first is decided by the callers
        // that consult both — `non_stage_source` and `source_content_key`.)
        assert_eq!(p.stage_ref("base"), Some(0));
        // A declared name that is not a stage resolves to its directory...
        assert_eq!(p.named_context("shared"), Some(Path::new("/repo/shared")));
        // ...and an undeclared ref stays an external image (pulled, not read from disk).
        assert_eq!(p.named_context("golang:1.22"), None);
        // A `--from=<stage>` is a build edge...
        assert_eq!(p.deps(1), vec![0]);
        // ...while a `--from=<named context>` is not: there is nothing to build before it.
        let mut ctx_only = plan("FROM alpine\nCOPY --from=shared /a /a\n");
        ctx_only
            .named_contexts
            .insert("shared".into(), PathBuf::from("/repo/shared"));
        assert!(ctx_only.deps(0).is_empty());
    }

    #[test]
    fn global_arg_interpolates_into_from() {
        let p = plan("ARG ver=bookworm\nFROM debian:${ver} AS base\nRUN x\n");
        assert_eq!(p.stages[0].base, Base::Image("debian:bookworm".into()));
        assert_eq!(
            p.global_args.get("ver").map(String::as_str),
            Some("bookworm")
        );
    }

    #[test]
    fn a_stage_named_scratch_is_rejected() {
        let order = |p: &Plan| p.build_order(p.resolve_target(None).unwrap()).unwrap();

        // `--from=scratch` always means the reserved empty base, so nothing could read from a
        // stage by that name — say so rather than let a COPY silently read the build context.
        let bad = plan("FROM alpine AS scratch\nRUN x\nFROM alpine\nCOPY --from=scratch /a /a\n");
        assert!(bad.check_reserved_names(&order(&bad)).is_err());

        // A `/` in a stage name would put its label inside the `image/<ref>` namespace an
        // external source is attached under, where it shadows one — here the second COPY would
        // read the stage instead of the image. The Dockerfile parser takes an `AS` name
        // verbatim, so nothing else stops this.
        let shadow = plan(
            "FROM alpine AS image/busybox:latest\nRUN x\n\
             FROM alpine\nCOPY --from=image/busybox:latest /a /a\n\
             COPY --from=busybox:latest /bin/sh /b\n",
        );
        assert!(shadow.check_reserved_names(&order(&shadow)).is_err());

        // `FROM scratch` itself is the empty base, not a stage name — and unnamed stages are fine.
        let good = plan("FROM scratch\nCOPY x /x\n");
        assert!(good.check_reserved_names(&order(&good)).is_ok());
        // A stage whose name merely contains it is fine.
        let ok = plan("FROM alpine AS scratchpad\nRUN x\n");
        assert!(ok.check_reserved_names(&order(&ok)).is_ok());
    }

    #[test]
    fn tmp_cross_stage_source_is_rejected() {
        let order = |p: &Plan| p.build_order(p.resolve_target(None).unwrap()).unwrap();

        // COPY --from=<stage> of a /tmp path fails up front — /tmp is never committed.
        let bad = plan(
            "FROM alpine AS builder\nRUN x\n\
             FROM alpine\nCOPY --from=builder /tmp/artifact /usr/bin/artifact\n",
        );
        assert!(bad.check_tmp_sources(&order(&bad)).is_err());

        // A persistent source path is fine.
        let good = plan(
            "FROM alpine AS builder\nRUN x\n\
             FROM alpine\nCOPY --from=builder /out/artifact /usr/bin/artifact\n",
        );
        assert!(good.check_tmp_sources(&order(&good)).is_ok());

        // --from an external image: its /tmp is real (committed), so it is not rejected.
        let img = plan("FROM alpine\nCOPY --from=busybox:latest /tmp/x /x\n");
        assert!(img.check_tmp_sources(&order(&img)).is_ok());

        // RUN --mount=type=bind,from=<stage>,source=/tmp/... is rejected the same way.
        let mnt = plan(
            "FROM alpine AS builder\nRUN x\n\
             FROM alpine\nRUN --mount=type=bind,from=builder,source=/tmp/a,target=/a use\n",
        );
        assert!(mnt.check_tmp_sources(&order(&mnt)).is_err());

        // A relative and a `./`-prefixed /tmp source are rejected too — the source is
        // relative to the stage root, so these still land on the ephemeral scratch.
        for src in ["tmp/artifact", "./tmp/artifact"] {
            let rel = plan(&format!(
                "FROM alpine AS builder\nRUN x\n\
                 FROM alpine\nCOPY --from=builder {src} /usr/bin/artifact\n"
            ));
            assert!(rel.check_tmp_sources(&order(&rel)).is_err(), "{src}");
        }
    }

    #[test]
    fn is_ephemeral_tmp_matches_tmp_only_at_a_path_boundary() {
        for good in ["/tmp", "/tmp/x", "tmp", "tmp/x", "./tmp", "./tmp/x"] {
            assert!(is_ephemeral_tmp(good), "{good} should be ephemeral /tmp");
        }
        // A sibling whose name merely starts with "tmp" is a persistent path, not /tmp.
        for bad in ["/tmpfoo", "/tmpfoo/x", "tmpish", "/out/tmp", "/var/tmp"] {
            assert!(!is_ephemeral_tmp(bad), "{bad} is not the ephemeral /tmp");
        }
    }

    #[test]
    fn stage_ref_resolves_global_arg_in_from() {
        // COPY --from=builder-${ver} resolves the global ARG to the right stage edge.
        let p = plan("ARG ver=9\nFROM alpine AS builder-9\nFROM alpine AS final\n");
        assert_eq!(p.stage_ref("builder-${ver}"), Some(0));
        assert_eq!(p.stage_ref("builder-9"), Some(0));
        assert_eq!(p.stage_ref("nope-${ver}"), None);
    }

    #[test]
    fn build_arg_overrides_global_default_in_from() {
        let mut ba = Vars::new();
        ba.insert("ver".into(), "trixie".into());
        let p = plan_args("ARG ver=bookworm\nFROM debian:${ver}\n", &ba).unwrap();
        assert_eq!(p.stages[0].base, Base::Image("debian:trixie".into()));
    }

    #[test]
    fn stages_split_and_base_resolution() {
        let p = plan("FROM debian AS base\nRUN a\nFROM base AS app\nRUN b\nFROM scratch\n");
        assert_eq!(p.stages.len(), 3);
        assert_eq!(p.stages[0].base, Base::Image("debian".into()));
        assert_eq!(p.stages[0].name.as_deref(), Some("base"));
        assert_eq!(p.stages[1].base, Base::Stage(0)); // FROM base
        assert_eq!(p.stages[2].base, Base::Scratch);
        assert_eq!(p.stages[0].instructions.len(), 1); // RUN a
    }

    #[test]
    fn copy_from_and_mount_from_create_edges() {
        let p = plan(
            "FROM debian AS build\nRUN make\n\
             FROM debian AS assets\nRUN gen\n\
             FROM debian AS final\n\
             COPY --from=build /out /out\n\
             RUN --mount=type=bind,from=assets,target=/a use\n",
        );
        let final_idx = p.resolve_target(Some("final")).unwrap();
        assert_eq!(final_idx, 2);
        let mut deps = p.deps(final_idx);
        deps.sort_unstable();
        assert_eq!(deps, vec![0, 1]); // build + assets
    }

    #[test]
    fn build_order_is_topological_and_pruned() {
        // 'extra' is independent of the target and must NOT be in the order.
        let p = plan(
            "FROM debian AS a\n\
             FROM a AS b\nCOPY --from=a /x /x\n\
             FROM debian AS extra\n\
             FROM b AS c\n",
        );
        let target = p.resolve_target(Some("c")).unwrap();
        let order = p.build_order(target).unwrap();
        // a before b before c; extra excluded
        let pos = |i| order.iter().position(|&x| x == i).unwrap();
        assert!(pos(0) < pos(1) && pos(1) < pos(3));
        assert!(!order.contains(&2)); // extra pruned
        assert_eq!(*order.last().unwrap(), 3); // target last
    }

    #[test]
    fn build_order_multi_unions_targets_and_shares_deps() {
        // A diamond of one shared base plus two independent tails:
        //   base -> {left, right}. Two targets 'left' and 'right' share 'base'.
        let p = plan(
            "FROM debian AS base\n\
             FROM base AS left\nCOPY --from=base /x /x\n\
             FROM base AS right\nCOPY --from=base /y /y\n",
        );
        let left = p.resolve_target(Some("left")).unwrap();
        let right = p.resolve_target(Some("right")).unwrap();
        let order = p.build_order_multi(&[left, right]).unwrap();
        // both targets present, deps before dependents, and 'base' appears exactly once.
        let pos = |i| order.iter().position(|&x| x == i).unwrap();
        assert!(order.contains(&left) && order.contains(&right));
        assert!(pos(0) < pos(left) && pos(0) < pos(right)); // base before both tails
        assert_eq!(order.iter().filter(|&&x| x == 0).count(), 1); // shared dep once
        assert_eq!(order.len(), 3); // base + left + right, no duplication
    }

    #[test]
    fn build_order_multi_target_is_a_dep_of_another_target() {
        // 'a' is itself a dependency of 'b'. Requesting both must not duplicate 'a', and
        // must still order it before 'b'.
        let p = plan("FROM debian AS a\nFROM a AS b\n");
        let a = p.resolve_target(Some("a")).unwrap();
        let b = p.resolve_target(Some("b")).unwrap();
        let order = p.build_order_multi(&[a, b]).unwrap();
        assert_eq!(order, vec![a, b]); // a before b, each once
    }

    #[test]
    fn build_order_multi_rejects_a_cycle() {
        // Force a cycle (not expressible via forward-only FROM): make x depend back on y.
        let mut p = plan("FROM debian AS x\nFROM x AS y\n");
        p.stages[0]
            .instructions
            .push(Instruction::Copy(crate::build::parser::Copy {
                sources: vec!["/a".into()],
                dest: "/a".into(),
                from: Some("y".into()),
                chown: None,
                chmod: None,
                link: false,
            }));
        assert!(p.build_order_multi(&[0, 1]).is_err());
    }

    #[test]
    fn default_target_is_last_stage() {
        let p = plan("FROM a\nFROM b\nFROM c\n");
        assert_eq!(p.resolve_target(None).unwrap(), 2);
    }

    /// Two files as one merged plan, each with its own origin/context.
    fn plan2(a: &str, b: &str) -> Result<Plan> {
        let file = |src: &str, name: &str, ctx: &str| PlanInput {
            dockerfile: parse(src).unwrap(),
            origin: format!("{name}/Dockerfile").into(),
            context: ctx.into(),
        };
        Plan::from_dockerfiles(
            &[file(a, "a", "/ctx-a"), file(b, "b", "/ctx-b")],
            &Vars::new(),
        )
    }

    #[test]
    fn cross_file_from_resolves_in_both_orders() {
        // b's stage builds on a's `tools` — with the files given in either order.
        let a = "FROM debian AS tools\nRUN t\n";
        let b = "FROM tools AS app\nRUN a\n";
        let p = plan2(a, b).unwrap();
        assert_eq!(p.stages[1].base, Base::Stage(0));
        // reversed input order: the reference is now forward, and still resolves.
        let p = plan2(b, a).unwrap();
        assert_eq!(p.stages[0].base, Base::Stage(1));
        // ... and the topological order builds `tools` first anyway.
        let target = p.resolve_target(Some("app")).unwrap();
        assert_eq!(p.build_order(target).unwrap(), vec![1, 0]);
    }

    #[test]
    fn cross_file_copy_from_and_mount_from_create_edges() {
        let a = "FROM app AS bundle\nCOPY --from=tools /t /t\n\
                 RUN --mount=type=bind,from=app,target=/a use\n";
        let b = "FROM debian AS tools\nFROM debian AS app\n";
        let p = plan2(a, b).unwrap();
        let mut deps = p.deps(0);
        deps.sort_unstable();
        assert_eq!(deps, vec![1, 2]); // tools + app (base `app` + the two refs, deduped)
    }

    #[test]
    fn same_file_forward_ref_stays_an_image() {
        // Docker compat pin: within one file a FROM only sees earlier stages, even
        // when a later stage declares the name — and even in a multi-file plan.
        let p = plan("FROM foo\nFROM scratch AS foo\n");
        assert_eq!(p.stages[0].base, Base::Image("foo".into()));
        let p = plan2("FROM foo\nFROM scratch AS foo\n", "FROM debian AS other\n").unwrap();
        assert_eq!(p.stages[0].base, Base::Image("foo".into()));
    }

    #[test]
    fn within_file_duplicate_name_last_wins() {
        // compat pin: a re-declared name in one file resolves to the latest earlier one.
        let p = plan("FROM a AS x\nFROM b AS x\nFROM x\n");
        assert_eq!(p.stages[2].base, Base::Stage(1));
    }

    #[test]
    fn cross_file_duplicate_name_is_an_error() {
        let err = plan2("FROM debian AS web\n", "FROM alpine AS web\n").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("\"web\""), "{msg}");
        assert!(
            msg.contains("a/Dockerfile") && msg.contains("b/Dockerfile"),
            "{msg}"
        );
    }

    #[test]
    fn numeric_refs_are_global_and_backward_only() {
        // `FROM 0` in the second file reaches the first file's stage 0; a forward
        // numeric ref stays an image (Docker's rule, globally applied).
        let p = plan2("FROM debian AS base\n", "FROM 0\n").unwrap();
        assert_eq!(p.stages[1].base, Base::Stage(0));
        let p = plan2("FROM 1\n", "FROM debian AS base\n").unwrap();
        assert_eq!(p.stages[0].base, Base::Image("1".into()));
    }

    #[test]
    fn stages_carry_their_files_context() {
        let p = plan2("FROM debian AS a\n", "FROM a AS b\n").unwrap();
        assert_eq!(p.stages[0].context, PathBuf::from("/ctx-a"));
        assert_eq!(p.stages[1].context, PathBuf::from("/ctx-b"));
    }

    #[test]
    fn instructions_never_leak_into_another_files_stage() {
        // b has content before its first FROM: error, not an append to a's last stage.
        let err = plan2("FROM debian AS a\n", "RUN oops\nFROM debian AS b\n").unwrap_err();
        assert!(
            format!("{err:#}").contains("before the first FROM in b/Dockerfile"),
            "{err:#}"
        );
    }

    #[test]
    fn global_args_interpolate_file_locally_and_merge_equal_or_error() {
        // identical re-declarations are fine, and each file's FROM sees its own args.
        let p = plan2(
            "ARG ver=9\nFROM img:${ver} AS a\n",
            "ARG ver=9\nFROM img:${ver} AS b\n",
        )
        .unwrap();
        assert_eq!(p.stages[0].base, Base::Image("img:9".into()));
        assert_eq!(p.stages[1].base, Base::Image("img:9".into()));
        // a file does not see another file's ARGs.
        let p = plan2("ARG ver=9\nFROM a-${ver} AS a\n", "FROM b-${ver} AS b\n").unwrap();
        assert_eq!(p.stages[1].base, Base::Image("b-".into()));
        // conflicting defaults are ambiguous for merged lookups -> error naming both.
        let err = plan2("ARG ver=8\nFROM x AS a\n", "ARG ver=9\nFROM y AS b\n").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("ARG ver"), "{msg}");
        assert!(
            msg.contains("a/Dockerfile") && msg.contains("b/Dockerfile"),
            "{msg}"
        );
        // ... and --build-arg overrides both sides, unifying them.
        let mut ba = Vars::new();
        ba.insert("ver".into(), "7".into());
        let file = |src: &str, name: &str| PlanInput {
            dockerfile: parse(src).unwrap(),
            origin: format!("{name}/Dockerfile").into(),
            context: "/nonexistent".into(),
        };
        let p = Plan::from_dockerfiles(
            &[
                file("ARG ver=8\nFROM x:${ver} AS a\n", "a"),
                file("ARG ver=9\nFROM y:${ver} AS b\n", "b"),
            ],
            &ba,
        )
        .unwrap();
        assert_eq!(p.stages[0].base, Base::Image("x:7".into()));
        assert_eq!(p.stages[1].base, Base::Image("y:7".into()));
    }

    #[test]
    fn within_file_arg_redeclaration_last_wins() {
        // compat pin: re-declaring a global ARG in one file keeps Docker's rule.
        let p = plan2(
            "ARG ver=8\nARG ver=9\nFROM img:${ver} AS a\n",
            "FROM debian AS b\n",
        )
        .unwrap();
        assert_eq!(p.stages[0].base, Base::Image("img:9".into()));
        // ... and a later file conflicting with the re-declared value still errors.
        let err = plan2(
            "ARG ver=8\nARG ver=9\nFROM x AS a\n",
            "ARG ver=8\nFROM y AS b\n",
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("ARG ver"), "{err:#}");
    }

    #[test]
    fn stage_ref_resolves_merged_global_args_across_files() {
        // COPY --from=builder-${ver}: the ARG comes from file a, the stage from file b.
        let p = plan2(
            "ARG ver=9\nFROM debian AS a\n",
            "FROM alpine AS builder-9\n",
        )
        .unwrap();
        assert_eq!(p.stage_ref("builder-${ver}"), Some(1));
    }

    #[test]
    fn cycle_is_rejected() {
        // hand-craft a cycle: stage 0 COPY --from a stage that depends back on it is
        // not expressible via FROM (forward-only), so force it through the resolver.
        let mut p = plan("FROM debian AS x\nFROM x AS y\n");
        // make x depend on y (index 1) via a synthetic COPY --from
        p.stages[0]
            .instructions
            .push(Instruction::Copy(crate::build::parser::Copy {
                sources: vec!["/a".into()],
                dest: "/a".into(),
                from: Some("y".into()),
                chown: None,
                chmod: None,
                link: false,
            }));
        assert!(p.build_order(1).is_err());
    }
}
