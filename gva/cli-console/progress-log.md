# Progress log

## 2026-11-18

- Explored vms.rs (registry, Selector, list), run.rs (registration), dev/{list,cli,plan,boot}.rs,
  vk-hub ui/{dev,actions,local}.rs. Wrote SPEC.md.
- `./dev.sh` hung: it loops on `mkdir -p` of its VM state dir under the read-only
  `~/.local/state`. Switched to the host toolchain (1.99.1) offline, gnu target, own target dir;
  fetched the crates the lockfile wanted into the repo's cargo home.
- Steps 1–5 implemented and committed together (they share main.rs and vms.rs). Old `vk list`
  table/JSON view code and its tests removed; `--field` tests now run on literal JSON.
- Legacy dev dir names must not follow symlinks (`named_stop_needs_neither…` caught it).
- Steps 6–7, then 8 (hub lockstep), then 9 (docs) committed.
- Consolidation: clippy found an unused `published_cell` and `Index::remove`; the latter now
  serves `vk rm` of a name whose dir is gone. Two full runs: only the 12 baseline failures.
- Smoke test with the debug binary and XDG dirs under /tmp: all verbs behave on fake state;
  `vk run`/`vk start` reach the boot and stop at the missing `/dev/kvm`.

## 2026-11-18 (later)

- Found that compose up (`--compose` with no primary) got a name and `run.json` when
  detached but never registers: listed stopped while running, and `vk start` would boot a
  second fleet. It is now never named.
- vmlist agent (another session, same worktree): on a real host `vk list` showed a row for
  every declared service, including services never built. Rows now require a VM, with
  `console.log` as the marker, because `svc-<name>/` is created for every declared service.
  Coordination moved to `agent-hub.md` (flock for short reads/appends).
- Decided with the user: `down` = `stop`; no option to also remove images or storage; verbs
  take service names; `--service`/`--name` disambiguate; `vk dev` refuses VMs of other
  workspaces and names the global command on a terminal; the run-as-supervisor idea is an
  open question.
- `start` without building: `units::BuildOpts` carries no `require_cached`, and threading
  one through ten construction sites was not worth it; the manager checks the unit's
  build-tier image path instead (`build_unit_ext4`, a pure function of the stage key).
- `boots()` decides the detach fork before dispatch, so a `vk dev up NAME…` that booted
  in-process would boot the current environment even for another's name. With NAMEs the
  command boots nothing itself and runs a child `vk dev --environment E up|start`.
- Removed tests that pinned the host-wide `vk dev stop NAME` / `gc NAME`; replaced by
  scope tests.
- vmlist agent: `vk rm` became `vk delete` (aliases `rm`, `remove`): it resolves and plans
  every REF first, then lists, asks on a terminal, and refuses without `-y`/`-f` otherwise;
  `-n/--dry-run` only lists. `vk ls` aliases `vk list`. Committed as 0f5921f6, with the
  `vk list` service rows as dfeb30f9. The session then handed off: main is the only agent.
  Smoke-tested there: `ls`, `-n`, refusal without a tty, the prompt through script(1), `-y`.
