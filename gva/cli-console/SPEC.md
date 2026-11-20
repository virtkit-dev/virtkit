# VM names, one selector, one list, symmetric lifecycle verbs

## Goal

Give every VM `vk` knows a short, stable **name**, accept the same **REF** in every command
that acts on a VM, list every known VM — running or stopped, primary or compose service — in
one `vk list`, and offer `vk start | stop | restart | delete REF` at the top level so a name shown
by `vk list` works with all of them.

## Context

- A run is tracked only while it runs: the VM registry (`$XDG_DATA_HOME/virtkit/vms/`) holds
  one entry per live `--state-dir` run and drops it when the run exits.
- A dev environment keeps a durable state dir (`$XDG_STATE_HOME/virtkit/dev/<ws>[-<env>]-<hash>`)
  with a `dev.json` identity; it is registered like any run while it runs.
- Compose services run in `svc-<name>/` inside their primary's state dir and are reached through
  the run's control socket.
- Commands selected VMs by PID, by project directory (prefix match), by exact state dir, or (dev
  only) by state-dir basename, each command accepting a different subset.
- `vk list` output is not a contract. vk-hub local is released in lockstep with `vk`. The fleet
  `Workload` wire type takes optional field additions only.

## Constraints

- No new dependency.
- Follow the existing `*_in(base)` pattern so unit tests never touch the real XDG dirs.
- Never delete a directory `vk` did not create (a user-chosen `--state-dir`).
- Foreground runs without `--state-dir` stay unregistered and unnamed.

## Design

### Names (`vk-driver/src/names.rs`)

- Grammar: `[a-z0-9][a-z0-9._-]{0,39}`, not all digits. No `/`, `:`, `@` (reserved: `/` for
  services, `:`/`@` for later use).
- Index: `$XDG_STATE_HOME/virtkit/names/<name>`, a symlink to the absolute state dir. Claiming
  a name is `symlink(2)`, atomic, `EEXIST` meaning taken. The index is the single source of
  truth: dir → name is a scan of the index (tens of entries). A `names/.lock` flock serializes
  claims so one directory never gets two names.
- A name is chosen once and kept. On collision the base gets `-2`, `-3`, …
- `vk rename OLD NEW` moves the link. `delete` releases it. A link whose target is gone is skipped
  by readers and removed by `vk delete NAME`.

Default names:

| VM | Default |
|---|---|
| dev environment `dev` | workspace basename (`wab-wt1`) |
| dev environment `E` | `<basename>-E` |
| `vk run --name X` | `X` |
| any other registered `vk run` (`--state-dir`, or `--detach`) | from its label: image basename without tag, compose primary, or Dockerfile target |
| compose service | not named: `<vm>/<service>` |

A dev environment is named when its boot records its identity (`dev.json`). Environments
from before names existed are named by the tidy pass below, oldest boot first.

Commands that only read (`vk list`, `vk dev list`, `vk exec NAME`, …) write nothing. Where
a record is out of date — a registry entry or a transient state its run left behind, a name
whose state dir was removed, an environment not named yet — `vk list` works the row out
again, marks its STATUS with `*` (`stale_record` in `--json`) and says on stderr how many
records are out of date. The commands that start or stop a VM (`vk run`, `vk dev up` and the
other booting `vk dev` actions, `vk start`, `vk stop`, `vk restart`, `vk delete`) run a tidy
pass (`tidy.rs`) that puts them right: it forgets removed names, clears lapsed transient
states, drops dead registry entries and names unnamed environments.

A transient state whose deadline passed while its process is still there — a stop that
timed out — is not stale: nothing settles it but the user. Its record stays until the run
is gone or a stop succeeds; `vk list` keeps the STATUS its record words (`stopping`), marks the row `!`, carries the reason in `--json`'s
`attention`, and says on stderr what can be done (`vk logs`, `vk stop` again, `kill`). It
neither asks nor acts. `vk list --problems` keeps only the `!` and `*` rows. `vk stop --tidy` is where it is settled:
the tidy pass with no budget, then, on a terminal, a question per overdue run — end it with
SIGKILL, or leave it; it exits 1 while one is left. The pass checks a 10 ms
budget between items and leaves the rest to the next command. Ephemeral task dirs (no `dev.json`) get no name. A dev dir's
basename (the former name) keeps resolving as an alias.

### REF (S1)

Read in this order:

1. contains `://` → raw agent address (only where it was accepted before: exec, ping, publish);
2. all digits → PID;
3. starts with `/`, `./`, `../`, `~`, or is `.`/`..` → path: a project dir or state dir, **exact**
   match; `--recursive` (list, stop, reboot, pause, resume) restores "every VM below";
4. otherwise `NAME` or `NAME/SERVICE`: a name from the index, else a dev state-dir basename.
   During the transition a bare word that is no name but an existing directory is taken as a
   path with a note on stderr. A word that is both is the name — a dev environment is named
   after its checkout, so from the directory above both exist — and `./word` is the directory.

For `start`, `stop`, `restart`, `delete` and `reset` a REF is one VM at most, running or
not. A state directory is its VM. A project directory is the project's VM, never its
compose services: the only named VM of that project, else — for `start`, `stop` and
`restart` — its `dev` environment when there is exactly one; several VMs are otherwise
refused, with their names.

No REF means the current directory, exact project match. `--service S` stays and is the same as
`REF/S`; giving both is an error.

### Runs: `--name`, managed dirs, recipe (S2, S5)

- `vk run --name X`: without `--state-dir`, the state dir is a managed
  `$XDG_STATE_HOME/virtkit/run/X-<8 hex>`. With `--state-dir D`, `X` names `D`.
  `X` already naming another dir is an error (`vk start X` or `vk delete X`).
- `vk run --detach` with neither `--name` nor `--state-dir` gets an automatic name and a managed
  dir, so every background VM is registered.
- Compose up (`--compose` with no image, `-f` or `--primary`) registers no VM, so it is never
  named: a name would list it stopped while it runs and `vk start` would boot a second
  fleet. `--name` on it is refused.
- `vk run --state-dir D` without `--name` gets an automatic name unless `D` has one.
- The CLI `vk run` path (not `vk dev`, not the executor) writes `<state dir>/run.json`: the
  argv after `run`, the working directory and the project directory. `vk start` replays it
  in that directory with `--detach --state-dir D --name N` appended before `--`
  (`Run` sets `args_override_self`, so the appended flags win) and the env
  `VIRTKIT_FROM_RECIPE=1`, which keeps the recipe from being rewritten.
- Registration also writes `<state dir>/.virtkit-last.json`, a copy of the registry entry, so a
  stopped VM can still be listed with its label, project and compose services.

### `vk list` (S3)

One row per VM: every running registered VM, every named VM that is stopped, and each
compose service of either that has a VM. A service has a VM when its primary reports it in a
state other than `stopped`, or when its `svc-<name>/console.log` exists (it booted at least
once). The state comes from the control socket when the primary runs, `stopped` otherwise. A
declared service that never booted (profiled out, or a `build:` service never started) gets
no row; `vk start VM/SERVICE` still accepts it.

- Columns: `NAME` (the REF), `KIND` (`dev`, `run`, `service`), `STATUS`, `PID`, `UPTIME`, `MEM`,
  `IMAGE`, `PROJECT`, `PUBLISHED`; `--wide` adds `EXEC ADDRESS` and the full project path;
  `--stale` adds `STALE`.
- Order: grouped by project (dev: workspace; run: project dir), groups by path; within a group
  dev environments then runs, each primary followed by its services by name.
- `--running` / `--stopped` (conflicting) filter rows; `--kind dev|run|service`.
- `--json` is an array of these rows; `--field` selects from them. `vk ls` is an alias.
- The output's shape follows the flags alone: a table, `--json`, `--field`, or with
  `--detail` a full record per VM (a short one for a VM that is not running). A REF never
  changes the shape.
- An unnamed running dev environment (first boot, or a task's throwaway one) shows its
  state dir's own name, which every command takes; a run registered before this change
  shows its PID. `PID/SERVICE` is a REF, so every NAME printed is one.
- STATUS is `running` or `stopped`, and says what is in between: `starting` from the moment
  a run takes its state dir until its VM is registered, `stopping` while a stop waits for it
  to go. Both are recorded in `<state dir>/.virtkit-state.json` (state, pid and its start
  time, since when, and for a stop the time its timeout lapses); a record whose process is
  gone or whose deadline passed is stale and ignored. A dev state dir that recorded no boot
  lists under its directory's name with `-` for STATUS (`never booted` in `--json`). `--stopped` keeps `stopped` and
  `never booted`, `--running` everything else.
- `vk dev list` stays the per-environment storage view (sizes, flags, `gc` staleness); its
  NAME is the environment's name (dir basename when unnamed) and its JSON gains `dir_name`.
  It lists this workspace's environments; `--all` lists every workspace's. For its own
  workspace it follows the config: every declared environment, one never brought up
  included, and under each a line per compose service (`NAME/SERVICE`). What is not built
  reads `-` in STATUS, CREATED BY, LAST BOOT and ON DISK. WORKSPACE is the directory
  name, with as many parents as tell it from the others listed; `--wide` shows the path. `vk list` keeps listing a service
  only once it has a VM.

### Lifecycle verbs (S4)

| Verb | dev | run | service |
|---|---|---|---|
| `start` | `vk dev --workspace W --dev-config C --environment E start` (child process; `C` as `dev.json` recorded it) | replay `run.json` with `--require-cached` | start the primary if stopped, then control-socket `Start { cached }` (dev: `vk dev start --service S`) |
| `stop` | `dev::stop` (as `vk dev stop`) | existing `stop_one` | control-socket `Stop` (dev: `vk dev stop --service S`) |
| `stop REF…` | every VM is told to stop at once; `--timeout SECS` (off by default: wait until down) bounds the whole command, not each VM | same | one after the other, within the same bound |
| `stop --force` / `--kill` | SIGTERM to the run once a second for 5 s, then kill / kill at once. A kill is SIGKILL first to every VMM under the run — the VM's and its services', found among the run's descendants by the boot spec in their environment, each VM before its keeper; the run tears the rest down itself, and is sent SIGKILL only if still there 5 s later | same | refused: a service is stopped by its manager |
| `restart` | stop, then start | same | same |
| `delete [-f]` (aliases `rm`, `remove`) | `dev::list::remove` (as `vk dev gc`) | delete a managed dir; for a user dir delete `run.json` and `.virtkit-last.json` only | delete `svc-<name>/` while stopped |
| `reset` | `vk dev prune` options | refused | refused |

`start` boots only what is built; `vk start --build` builds what is missing, as `up` does.
`delete` refuses a running VM unless `-f`, which stops it first, and releases the name. It
asks before it removes anything when on a terminal and fails otherwise, unless `-y` or `-f`;
`-n/--dry-run` lists what it would remove. Every REF is resolved and planned first: if one
fails, none is deleted.
`vk dev gc NAME` and `vk dev prune NAME` keep working and also accept names; they print a note
pointing to `vk delete` / `vk reset`.

### `vk dev` verbs and workspace scope (S7)

- `vk dev up | start | stop | restart` pair as up/down and start/stop. `down` is a visible
  alias of `stop`: in vk a stopped service loses its root disk at its next start anyway, so
  there is no container-like state for `down` to remove that `stop` keeps.
- `up` builds what is needed, then boots. `start` never builds: the boot runs with
  `--require-cached` (restore from the cache, exit 3 on a miss) and freshness `reuse`, so a
  running environment is left as it is; an environment with no `dev.json` (no finished
  boot) fails, `up` creates it. `restart` is `stop` then `start`.
- A compose service's start is the control protocol's `Start { unit, cached }`. `cached` is
  optional on the wire (left out when false, default false), so older peers keep working.
  The manager refuses a cached start of a `build:` unit whose build-tier image is absent.
- The verbs take NAMEs (`dev/targets.rs`, pure `pick`): a compose service of the current
  environment (its primary's service name is the environment), an environment of this
  workspace (its VM name or state-dir name), or `ENV/SERVICE`. A name that is both a
  service and an environment is refused until `--service NAME` or `--name NAME` (both
  repeatable) says which.
- `vk dev` acts on its workspace only. A name that is a VM of another workspace is refused
  (exit 2); on a terminal the error names the global command (`vk stop NAME`, `vk start
  NAME`, `vk start --build NAME`, `vk restart NAME`, `vk delete NAME`, `vk reset NAME`).
  `vk dev gc NAME` and `vk dev prune NAME` follow the same rule; `gc --all-stale` stays
  host-wide.
- With NAMEs the command boots nothing in its own process: an environment that has to come
  up does so in a child `vk dev --environment E up|start`, so one command can bring up
  several.
- `vk dev service up|down|reboot|status` stays.
- The workspace is `--workspace`, else `$VIRTKIT_WORKSPACE`, else found from the current
  directory. A command that needs one and has none exits 5, and on a terminal says how one
  is chosen and which command works from anywhere.



- `vk publish --service` is the option's name; `--via` stays as an alias.
- `vk ping [REF]` is the agent probe; `vk status` stays as an alias.
- `vk paths` calls the root the **data dir** and also lists the dev base, the run base, the
  name index and the `runs/` ledger.

### Hub (lockstep)

- `Workload` gains an optional `name`. vk fills it; the hub keys dev rows by `name`, falling
  back to the state-dir basename.
- `vk dev list --json` `name` is the environment name; the hub passes it to `vk stop` and
  `vk delete --yes`, which accept it from anywhere (`vk dev stop/gc` are scoped to a workspace).

## Rejected alternatives

- **Names computed from paths at lookup time**: the first `app` would be renamed the moment a
  second `app` appears.
- **A name file inside each state dir as the source of truth**: a stopped user `--state-dir`
  could then not be found from its name without scanning the disk.
- **Name in `.virtkit/config.toml`**: committed, so every worktree would claim the same name.
- **`vk dev list` as an alias of `vk list --kind dev`**: it reports disk sizes and staleness
  that per-VM rows do not carry; it stays the environment storage view.
- **A `down` that removes more than `stop`** (images, storage): nothing `stop` keeps is
  worth removing by default, and `vk dev prune` / `vk reset` already remove images and
  storage on request.
- **`start` booting exactly the image that last ran**, as `docker start` does: images live
  in a shared, garbage-collected cache, so that image may be gone; `start` boots what the
  current config resolves to, from the cache.

## Acceptance criteria

1. names: validate, claim with suffixes, lookup, dir → name, rename, release, dangling links
   (unit tests in `names.rs`).
2. REF parsing covers every case of the grammar (unit tests).
3. A path REF matches exactly; `--recursive` matches below (unit tests).
4. Dev dirs get names lazily, oldest first, ephemeral dirs skipped; basenames still resolve.
5. `vk run --name` / `--detach` / `--state-dir` naming and `run.json` contents (unit tests on
   the preparation function).
6. `vk list` rows: grouping, order, services, stopped VMs, filters, services without a VM
   left out (unit tests on the pure row builder).
7. start/stop/delete planning per kind (unit tests on the pure planner); `delete` never deletes an
   unmanaged dir.
8. `vk ping`, `vk status` alias, `publish --service`, `vk paths` lines (CLI parse tests).
9. vk-hub keys a dev environment by `Workload.name`, falling back to its state dir's own
   name, and the proto drops a `name` that is not one (unit tests in both crates).
10. `vk dev` names: services, environments, `ENV/SERVICE`, the primary's service name,
    ambiguity, `--service`/`--name`, outside the workspace, unknown (unit tests on `pick`);
    a named stop or gc of another workspace's VM is refused (CLI tests); `down` parses as
    `stop`; only a bare `up`/`start` boots in-process (`boots()` table).
11. `Start.cached` is left out when false and defaults to false (vk-core test).
12. vk-hub runs `vk stop` and `vk delete --yes` for dev environments (vk-hub tests).
12b. `vk delete` gate: dry run, ask, go, refuse, for each combination of `-y`/`-f`/`-n` and
    terminal (unit tests on the pure gate); step descriptions (unit tests).
13. `cargo build`, `cargo clippy`, `cargo test` for vk-driver, vk-hub, vk-hub-proto pass.

## Open questions

- Should a run keep supervising its services (and its control socket) after its primary
  stops, so the primary can be rebuilt or replaced without restarting them? That makes the
  primary a unit the manager starts like the services, and registers compose up (a
  supervisor with no primary) too. Not done: `vk reboot` already restarts a primary in
  place with its services up.

- Should unnamed foreground runs be registered under an automatic name later?
- A dev environment stopped before this change lists no compose services until its next
  boot writes `.virtkit-last.json`; reading them from `dev.json`'s compose manifest would fill
  the gap.
- A `vk run` that fails before its VM boots still leaves a named, stopped VM (as
  `docker create` would); `vk delete` removes it.
