# Steps

Each step is verified by unit tests in the module named; the whole `vk-driver`, `vk-hub` and
`vk-hub-proto` suites pass except the 12 `vk-driver` tests that fail in this sandbox on the
untouched tree too (see papercuts.md).

1. **Name index** — `vk-driver/src/names.rs`: grammar (`validate`, `sanitize`), the symlink
   index with `claim` (base, `-2`, `-3`…), `claim_exact`, `lookup`, `name_of`, `rename`,
   `release`, `remove`, and `resolve` (index, then a dev state dir's own name, never through a
   symlink). Tests: `names::tests`. Status: done.
2. **Dev names** — `dev::list::name_unnamed[_in]` names every dev dir with a `dev.json`,
   oldest boot first; `default_name`; `vk dev list` rows carry `name` and `dir_name`;
   `dev stop/gc/prune NAME` accept either; `remove` releases the name.
   Tests: `dev::list::tests::unnamed_environments_get_names_oldest_boot_first…`,
   `dev::cli::tests::named_stop_needs_neither…`. Status: done.
3. **REF selector** — `vms::Ref`, `Selector::{parse, parse_below, from_ref}`, `resolve_ref`,
   exact directory match with `--recursive`; wired into list, stop, reboot, pause, resume,
   snapshot, exec, ping, console, cp, logs (a stopped VM's console by name), publish, atop,
   ssh, ssh-config. Tests: `vms::tests::a_ref_reads…`, `…a_selector_matches…`. Status: done.
4. **Run names and recipe** — `vk run --name`; `prepare_run_name` before the detach fork
   names `--name`/`--state-dir`/`--detach` runs, makes managed dirs under
   `$XDG_STATE_HOME/virtkit/run`, writes `run.json` (`names::Recipe`); registration writes
   `.virtkit-last.json`; `Run` takes the last of a repeated option.
   Tests: `names::tests::a_replay_puts…`, `tests::an_unnamed_run_is_named…`,
   `tests::run_takes_name_and_the_last…`. Status: done.
5. **Unified `vk list`** — `vk-driver/src/vmlist.rs` (`rows`, `Filter`, `render`) fed by
   `vms::list_report(ListOpts)`; JSON and `--field` on rows; full record kept.
   A compose service gets a row only once it has a VM (running, or `svc-<name>/console.log`).
   Tests: `vmlist::tests` (`a_service_without_a_vm_gets_no_row`), `vms::tests::field_*`.
   Status: done.
6. **Lifecycle verbs** — `vk-driver/src/lifecycle.rs`: pure `plan` per verb, kind and state;
   `vk start | restart | rm | reset | rename`; `vk stop NAME` through it.
   Tests: `lifecycle::tests`. Status: done.
7. **Vocabulary** — `vk ping` (alias `status`), `publish --service` (alias `--via`),
   `vk paths` data dir and VM state. Tests: `tests::ping_is_the_probe…`,
   `tests::paths_report_names_the_data_dir…`, `tests::everyday_help_is_curated`. Status: done.
8. **Hub lockstep** — `Workload.name` (optional, `is_vm_name`, dropped by
   `make_display_safe`); `vk workloads` fills it; vk-hub `dev_name` prefers it.
   Tests: `vk-hub-proto tests::a_workload_name_is_kept…`,
   `vk-hub ui::dev::tests::an_environment_is_named_as_vk_names_it`. Status: done.
8b. **Compose up stays unnamed** — `boots_no_primary`; `prepare_run_name` skips compose up
   and refuses `--name` on it. Test: `tests::compose_up_is_never_named`. Status: done.
8c. **`vk dev` verbs, cached start, workspace scope** — `dev/targets.rs` (`pick`, `scope`);
   `vk dev up|start|stop(down)|restart [NAME…] [--service S] [--name N]`; `Overrides.no_build`
   → `--require-cached`; `fleetctl::Request::Start { cached }` and `Manager::built`;
   `vk start --build`; `gc NAME`/`prune NAME` scoped; vk-hub on `vk stop` / `vk rm --yes`.
   Tests: `dev::targets::tests`, `dev::cli::tests::{lifecycle_verbs_take_names…,
   a_named_stop_stays_in_its_workspace, bare_gc_removes…_a_named_gc_stays_in_it,
   every_action_says_whether_it_boots…}`, `fleetctl::tests::a_start_is_cached_only…`,
   vk-hub `dev_environments_are_started_stopped_and_cleaned_up`. Status: done; not verified
   against a booting VM.
8d. **`vk delete`** — `Cmd::Delete` (aliases `rm`, `remove`), `-n/--dry-run`, `-y`, `-f`;
   every REF is resolved and planned before anything goes (`lifecycle::delete`, pure `gate`,
   `Step::describe`); `vk ls` aliases `vk list`; vk-hub runs `vk delete --yes`.
   Tests: `lifecycle::tests` (gate, describe). Status: done.
9. **Docs** — README VM section (table pinned by `vmlist::tests::readme_table_sample…`),
   overview rows, docs/dev.md, CHANGELOG, `tests/dev-e2e.sh` (`vk list --running`).
   Status: done.
10. **Consolidation** — rustfmt, clippy clean on the three crates, suites run twice with no
    new failure, smoke test of the built binary against fake state under `/tmp`
    (list, rename, stop, rm of a dev env, a service and a run, `run.json` replay).
    Not verified here: anything that boots a VM (no `/dev/kvm` in this sandbox).
