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
use std::path::PathBuf;

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
    /// Instructions after the `FROM`, in order (the `FROM` itself excluded).
    pub instructions: Vec<Instruction>,
    /// Build-context root the stage's `COPY` (no `--from`) resolves against — the
    /// context of the [`PlanInput`] that declared the stage. The path itself never
    /// enters cache keys (only context-relative names + file content do), so where a
    /// context lives cannot bust the cache.
    pub context: PathBuf,
}

/// One Dockerfile going into a [`Plan`], with the paths its stages resolve against.
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
    by_name: BTreeMap<String, usize>,
}

impl Plan {
    /// Build the plan from parsed Dockerfiles: split into stages and resolve each
    /// `FROM` base + the name index. `FROM` images are interpolated against the global
    /// `ARG`s (with `build_args` overriding declared defaults). References resolve in
    /// source order, so a `FROM <name>` only sees stages declared before it.
    pub fn from_dockerfiles(inputs: &[PlanInput], build_args: &Vars) -> Result<Plan> {
        let mut stages: Vec<Stage> = Vec::new();
        let mut by_name: BTreeMap<String, usize> = BTreeMap::new();
        let mut global_args: Vars = Vars::new();

        for input in inputs {
            // Per-file boundary: "before the first FROM" means *this* file's first FROM,
            // so a later file's leading ARGs stay global and its stray instructions
            // can't silently attach to the previous file's last stage.
            let file_start = stages.len();
            for instr in &input.dockerfile.instructions {
                match instr {
                    Instruction::From(f) => {
                        // expand ${ARG} in the image ref against the global args.
                        let image = interp::interpolate(&f.image, &global_args);
                        let index = stages.len();
                        let base = if image.eq_ignore_ascii_case("scratch") {
                            Base::Scratch
                        } else if let Some(&i) = by_name.get(&image) {
                            Base::Stage(i)
                        } else if let Ok(i) = image.parse::<usize>() {
                            // `FROM 0` — a stage by numeric index (rare but valid)
                            if i < index {
                                Base::Stage(i)
                            } else {
                                Base::Image(image.clone())
                            }
                        } else {
                            Base::Image(image)
                        };
                        if let Some(name) = &f.as_name {
                            by_name.insert(name.clone(), index);
                        }
                        stages.push(Stage {
                            index,
                            name: f.as_name.clone(),
                            base,
                            instructions: Vec::new(),
                            context: input.context.clone(),
                        });
                    }
                    // Global ARG before the file's first stage: resolve it (build-arg
                    // override, else its interpolated default, else empty) into the
                    // global scope.
                    Instruction::Arg { name, default } if stages.len() == file_start => {
                        let value = build_args.get(name).cloned().unwrap_or_else(|| {
                            default
                                .as_deref()
                                .map(|d| interp::interpolate(d, &global_args))
                                .unwrap_or_default()
                        });
                        global_args.insert(name.clone(), value);
                    }
                    other => {
                        if stages.len() == file_start {
                            bail!(
                                "instruction before the first FROM in {}: {other:?}",
                                input.origin.display()
                            );
                        }
                        let stage = stages.last_mut().expect("guarded above");
                        stage.instructions.push(other.clone());
                    }
                }
            }
        }
        if stages.is_empty() {
            bail!("no FROM / no stages in the Dockerfile");
        }
        Ok(Plan {
            stages,
            global_args,
            by_name,
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

    /// Topological build order for `target` and its transitive dependencies only.
    /// Errors on a dependency cycle.
    pub fn build_order(&self, target: usize) -> Result<Vec<usize>> {
        let mut order = Vec::new();
        // 0 = unvisited, 1 = on stack (visiting), 2 = done
        let mut state = vec![0u8; self.stages.len()];
        self.visit(target, &mut state, &mut order)?;
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
    fn global_arg_interpolates_into_from() {
        let p = plan("ARG ver=bookworm\nFROM debian:${ver} AS base\nRUN x\n");
        assert_eq!(p.stages[0].base, Base::Image("debian:bookworm".into()));
        assert_eq!(
            p.global_args.get("ver").map(String::as_str),
            Some("bookworm")
        );
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
    fn default_target_is_last_stage() {
        let p = plan("FROM a\nFROM b\nFROM c\n");
        assert_eq!(p.resolve_target(None).unwrap(), 2);
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
