# GitLab CI executor

virtkit ships a GitLab [custom executor](https://docs.gitlab.com/runner/executors/custom.html)
that runs each CI job in a throwaway microVM: a fresh guest per job, destroyed
when the job ends, with its own kernel and no shared state between jobs.
Concurrent jobs each get their own VM. This guide covers configuring the runner,
selecting the job image, sizing the guest, keeping the host inside its memory,
controlling egress, and attaching services.

For the host-side setup mechanics (runner wiring, state layout, exit codes) see
also the [driver README](../vk-driver/README.md#gitlab-ci-executor); the full
config reference is [`config.example.toml`](../vk-driver/config.example.toml).

## Runner wiring

Point the runner's custom-executor stages at `vk` in
`/etc/gitlab-runner/config.toml`:

```toml
[[runners]]
  [runners.custom]
    config_exec  = "/usr/local/bin/vk"
    config_args  = ["gitlab", "config"]
    prepare_exec = "/usr/local/bin/vk"
    prepare_args = ["gitlab", "prepare"]
    run_exec     = "/usr/local/bin/vk"
    run_args     = ["gitlab", "run"]
    cleanup_exec = "/usr/local/bin/vk"
    cleanup_args = ["gitlab", "cleanup"]
```

The executor reads its host configuration from the usual virtkit config file
(`$VIRTKIT_CONFIG` or `/etc/virtkit/config.toml`). Everything below that a job
controls is set through `.gitlab-ci.yml` **job variables**.

### Host-side checkouts

A host-side checkout — which `dockerfile:` and `compose:` job images need — clones the
sources on the runner instead of in the guest. Point `checkout_dir` at the runner's builds
tmpfs when the state disk is too slow:

```toml
[gitlab]
host_checkout = true
checkout_dir = "/builds"
checkout_cache_idle_secs = 1800
```

A tree is reused by concurrent slot and project, so a second job on the same slot fetches
rather than re-clones. Before each checkout, and during `vk gc`, trees unused for longer than
this are removed — which is what keeps a tmpfs `checkout_dir` from filling with the
repositories of jobs that have moved on. Unset, checkouts inherit `image_cache_idle_secs`
(30 minutes by default). A tree a prepare or a running guest is using is never removed.

Under an explicit `checkout_dir`, virtkit keeps its trees in
`<checkout_dir>/vk/<slot>/<project>`, so the sweep walks only its own — a sibling tree from
another GitLab executor is outside the root it reads, and only trees virtkit created are
eligible within it. Each tree also records which directory it is, rechecked immediately before
removal, so bookkeeping left behind by a tree removed from outside cannot stand in for whatever
appears at that path next. The configured root must still be writable **only** by the runner
user: anyone who can replace the private subtree can interfere with the runner's checkouts.

Releases up to 0.31.0 put their checkouts directly under an explicit `checkout_dir`, which
leaves them outside the new root, so an upgrade neither migrates nor reclaims them: remove the
old `<checkout_dir>/<slot>` directories once no runner from before the upgrade is using them.
The first job per slot and project after the upgrade clones instead of fetching, since its tree
has moved. Under the default `<state_dir>/checkouts` root the trees keep their paths and are
still fetched into, but carry no identity record until the same slot and project is checked out
again, which is when they become reclaimable.

## Job variables

Job variables are read once per job, at the job level. GitLab passes them to the
executor prefixed with `CUSTOM_ENV_`; set them under a job's (or the pipeline's)
`variables:`. An **empty string is treated exactly like an unset variable** — it
does not override the host default.

| Variable | Effect |
| --- | --- |
| `MICROVM_IMAGE` | Guest image (prefix-based source; see below). Unset → `local/default`. |
| `MICROVM_CPUS` | vCPU count, clamped to the host `[vm] max_cpus` ceiling. |
| `MICROVM_MEM` | Guest RAM as `<n>G`, clamped to `[vm] max_mem`. |
| `MICROVM_USER` | User to run the job as inside the guest. |
| `MICROVM_EGRESS_ALLOW_IP` / `_ALLOW_NAME` / `_AUDIT` | Narrow the run-phase egress cap (see [Egress](#egress-control)). |
| `MICROVM_BUILD_EGRESS_ALLOW_IP` / `_ALLOW_NAME` / `_AUDIT` | Narrow the build-phase egress cap. |
| `MICROVM_USAGE_REPORT` | End this job's trace with what every job of its project has been using (see [Sizing a project](#sizing-a-project)). |

### Image selection

`MICROVM_IMAGE` is prefix-based — the prefix names the source (when unset, the
job's plain GitLab `image:` is read the same way):

- unset → `local/default` (the baked default bundle);
- `local/<name>` — a bundle directory under `[local] dir`;
- `virtkit/<name>[:tag|@sha256:…]` — a bundle in the `[registry]` repo;
- `docker/<name>[:tag|@sha256:…]` — an OCI image from the `[docker]` repo, booted
  directly (embedded kernel + agent);
- `dockerfile:<path>[?context=<dir>&buildcontext=NAME=DIR&arg=NAME=VALUE][#<stage>]` — a
  **git-defined** image: virtkit builds the Dockerfile from the job's own checkout (each
  `RUN` in a microVM, no Docker involved) and boots the result, so the job image lives in
  the repo instead of a registry. `<path>` is relative to the repo root; the build
  context defaults to the Dockerfile's directory (`?context=.` for the repo root),
  `?arg=` supplies a `--build-arg` (repeatable), `?buildcontext=NAME=DIR` (repeatable)
  declares an extra repo-root-relative directory a `COPY --from=NAME` or
  `RUN --mount=…,from=NAME` may read, and `#<stage>` selects a stage. Every path stays
  inside the checkout. Built images are cached and shared across
  jobs and runners. Requires `[gitlab] host_checkout`;
- `compose:<file>#<primary>` — a whole fleet from a compose file in the checkout:
  boots `<primary>` as the job VM and the other services (built or pulled the
  same way) as siblings on the job network. Same `host_checkout` requirement.
  A service sizes its own guest with an `x-virtkit: { cpus:, mem: }` marker
  (default 2 vCPUs / 1G), clamped to the host `[vm] max_cpus`/`max_mem` ceilings
  like the job's own `MICROVM_CPUS`/`MICROVM_MEM`; the primary keeps following
  those job variables.

```yaml
my-job:
  variables:
    MICROVM_IMAGE: virtkit/myimage      # :tag (default latest) or @sha256:…

test-in-repo-image:
  variables:
    MICROVM_IMAGE: dockerfile:ci/Dockerfile#test   # built from this checkout, then booted
```

## Resource usage

Each phase reports what it cost the runner. A job that builds its own image
(`image: dockerfile:…` / `compose:…`) gets the build figures as the build ends, next to
its timing breakdown — a job whose image is already built runs no build and reports none:

```
virtkit: build resource usage: cpu 8m12s, peak memory 3.2 GiB (largest process 1.2 GiB), read 1.8 GiB, written 4.1 GiB, sent 12 MiB, received 2.7 GiB
```

and the run figures come at the very end of the trace:

```
virtkit: job resource usage: cpu 2m14s, peak memory 1.6 GiB, overlay 1.2 GiB of 16.0 GiB, read 3.4 GiB, written 812 MiB, sent 3 MiB, received 941 MiB
```

`cpu` is all the CPU time the phase burned on the host, the guests' own execution
included — for the build, the stage guests plus vk's own work assembling and caching the
image; for the run, the job's microVM plus the host processes around it (the switch, the
virtio-fs daemons, any service VM). Against the phase's own duration it gives the
parallelism it reached: a ceiling for sizing one guest's vCPUs, since the total also
carries the host helpers and every sibling VM.

`peak memory` is the most the phase held at one time, not the memory left at the end: a
guest hands freed RAM straight back to the host, so its live figure says little about the
peak it passed through. A build reports its largest single process as well, because the
two size different knobs:

- the **total** is what the host had to have free while the phase ran — for a build,
  several stage guests at once, so lower it with `[build] jobs`; for a job, the run VM and
  its helpers together, i.e. `MICROVM_MEM` plus the VMM's own overhead.
- the **largest process** — a stage guest, or vk itself — is what `[build] mem` has to
  cover for one stage.

The two are measured as their processes allow, and err in opposite directions. A build's
guests are gone by the time it reports, so both its memory figures are sampled while it
runs — a spike shorter than a tenth of a second can be missed, and longer than that on a
host where reading the process tree is expensive, since the sampler backs off from its own
cost. Each sweep totals and ranks the same reads, so the total always covers the largest
process reported beside it. A job's VM is read in one pass instead, summing the high-water
mark of every process still running at the end: marks that never coincided both count, while
a helper that peaked and exited earlier contributes its CPU time but no memory. Read either
figure as a ceiling — pages the VMM shares with its virtio-fs daemons count in each — and for
a job with services it spans every service VM, not just the one the stages run in.

Either line is omitted rather than guessed at when the figures cannot be had: the run ones
for a job whose guest died and took the supervisor with it, the build ones for a build that
shared the host process with another (both would be charged for each other's guests) or that
the host could spare no sampler thread for.

`overlay` is how full the job filled its **writable layer**, against what that layer held.
With `[gitlab] checkout_overlay` (the default) a job builds on an overlay above its checkout
whose upper layer is a tmpfs inside the VM, so every write under `CI_PROJECT_DIR` — the build
tree, a package cache pointed there, an unpacked archive — is guest RAM, capped at
`[gitlab] checkout_overlay_size` (80% of the VM's memory by default). That cap is a wall a job
can hit: it fails with `ENOSPC` while every disk on the host sits empty, and the `written`
figure beside it says the job wrote nothing at all, because none of those pages ever reached a
block device. Read the pair as the room the job had left — `4.2 GiB of 16.0 GiB` has plenty,
`15.9 GiB of 16.0 GiB` is a job about to fail on space — and raise `MICROVM_MEM` when a build
tree needs more, since the capacity follows it.

The figure is the high-water mark, not what the layer held at the end: a job that unpacks an
archive and deletes it would otherwise read as having needed nothing. It comes from the guest,
which is the only place a tmpfs can be seen from, so a job with no overlaid checkout reports
none — as does one on a guest whose agent is older than the figure.

### Sizing the writable layer

`[gitlab] checkout_overlay_size` is where the two failures either side of that wall are traded
off, and the mark above is what to size it from:

- **too low** and a job dies for want of a partition on a VM that had the memory for it — the
  build tree hits the cap while gigabytes of guest RAM sit unused;
- **too near 100%** and the layer starves the job's own processes instead. Compilers spike late
  (linking), so the failure lands as an OOM kill of whatever the kernel picks — far harder to
  read than a filesystem reporting itself full.

It costs nothing below the cap: tmpfs pages are allocated on use, so a job that never fills the
layer is unaffected by how large it was allowed to grow. Nor does raising it commit host memory
— `[schedule]` admission reserves `MICROVM_MEM` either way, so the host is already sized for a
job that uses all of its VM.

The default is 80% rather than the kernel's own 50% tmpfs default. That default exists to keep
an unevictable tmpfs from starving the long-lived services of a general-purpose machine; a
one-shot job guest has no such services, and the tree it is there to build is the legitimate
main consumer of its memory. Set `"50%"` to restore the kernel's behaviour, or an absolute
`"12G"` where every job on the runner is the same shape.

`read` and `written` are what the phase cost the runner's **storage**, not what its programs
asked for: `read` is what was actually fetched from the block layer, so a guest re-reading a
file it has already pulled into its own page cache costs nothing here, and `written` is what
was handed over to be written out. Two consequences are worth expecting rather than
discovering:

- work that never reaches a disk is not counted, because there is nothing to count: a
  `[gitlab] checkout_dir` pointed at the runner's builds tmpfs, or a guest write absorbed by
  its overlay, is RAM, and a tmpfs page never reaches the block layer;
- a job re-run on a warm host reads far less than the same job on a cold one, which is the
  cache doing its job rather than the measurement wavering.

`sent` and `received` are what the phase's guests moved **in and out of the host**, counted
by the switch that forwards it — payload from the guests' side, so the framing around it and
any retransmit under it are the host's traffic rather than the job's. What the guests send
each other is switched between them without ever being forwarded, so it is not in the figure.
Each phase counts its own: what a `dockerfile:` build's `RUN` steps fetched is on the build
line, the packages the job's steps installed and the artifacts they uploaded on the job line.
Only what a guest pulled is in either: `vk` resolves and pulls a base image itself, on the
host and outside the switch, so those layers are in neither figure. A job
on `net.mode = "tap"` has no switch in its path, so it reports no network at all rather than
zero.

A measured zero is printed — `read 0 B` says this job touched no disk, which is a fact
about the job. The clause is left off only where the figure could not be taken at all: a
kernel built without `CONFIG_TASK_IO_ACCOUNTING`, or a network nothing counted. The history
keeps the two apart as well, so a host that cannot measure never leaves a job remembered as
having moved nothing, and `vk check` says whether this kernel accounts block I/O:

```
ok   usage    block I/O accounted, process tree from the kernel's child lists
```

### What the job did, second by second

The figures above are one number per phase. For the shape of a job over time — which step
saturated the CPUs, when memory climbed, what process was running while nothing else moved —
each job's guest also records itself: every 10 seconds it samples its own `/proc` and appends
a sample to a log the host keeps after the VM is gone.

```
<state_dir>/atop/2026-08-11/42137-acme-web-test_unit/atop.log
```

The last line of the job's trace names the file:

```
virtkit: atop log: /var/lib/virtkit/atop/2026-08-11/42137-acme-web-test_unit/atop.log
```

On the runner, `vk gitlab atop` finds one again from a job id, or from any part of a recorded
job's name — the newest run answering — printing just the path, so it composes with whatever
reads it. Nothing matching means an empty stdout and a non-zero exit:

```sh
vk gitlab atop 42137                # that run
less $(vk gitlab atop test_unit)    # the last run of this job
```

The name to give is the one in the directory, which is the job's name with anything outside
`[A-Za-z0-9._-]` replaced — a `test:unit` job is recorded as `test_unit`. A job id matches only
the id a directory name leads with, so `42` never answers for job `42137`.

`--summary` reads the log for you instead, accounting the whole job — what its guest did with
its processors and memory, what it moved, where it was held up, and which of its processes the
time went to:

```
$ vk gitlab atop 42137 --summary
virtkit: 42137-acme-web-test_unit — what its guest did:
  recorded         2026/08/12 07:21:49 → 07:21:59 UTC (10s), 11 samples at 1s, the first
                   covering the guest's boot (counted in the totals, not the rates)
  guest            runner on 2 cpus, 988 MiB memory, no swap
  cpu              1.7s of cpu time — 0.2s user, 0.9s system, 0.6s stolen by the host; 0.1s
                   waiting for disk; 16% busy at peak, 5% on average, cpu 1 busiest at 22%
                   of its own time
  load             0.00 at peak, 0.00 / 0.00 / 0.00 at the end (1m / 5m / 15m); 285 context
                   switches a second at peak
  memory           63 MiB held at peak (6% of the VM), 146 MiB of cache at peak
  pressure         cpu 182ms, 0.9% at 07:21:51; io 50ms, 0.3% at 07:21:55
  disk             2 MiB read, 92 KiB written — vda busiest, 96ms busy
  network          eth0 received 42 B, sent 714 B
  cpu over time    ▁▁▁▁▁▁▁▁▁▂  (peak 16%)
  memory over time ▁▁▁▁▁▁▁▁▁▁  (peak 6%)

  what ran — the 10 of 61 that used the most cpu
  command                                   pid   cpu  peak rss    read  written
  /init tsi_hijack                            1  0.3s    11 MiB   2 MiB   20 KiB
  …
```

(Wrapped here to fit the page — the real output is one line per label.)


Totals cover every sample, including the first — a job's VM boot is part of what the job cost.
A figure computed *over* an interval — the cpu percentages, the rate of context switching, the
sparklines — leaves that first sample out, because it covers however long the guest had been up
rather than one interval, and averaging a boot into the picture flattens everything after it. A
figure that was simply the reading at a moment — the load, the memory held, a pressure average
— comes from every sample, the first included, so a peak the guest reached while booting is
still reported as one. `pressure` is the line to read when a job is slow for no
visible reason: it is time the guest spent *waiting* for a processor, for memory or for its
disk, which no total of what it used can show. A figure the kernel could not measure prints as
`-`, never as a zero.

`--json` writes the samples themselves, one object per line, for anything that would rather
compute than read. The units are the log's own: pages, with their `pagesize` beside them;
ticks, with their `hertz` beside them; 512-byte sectors; and KiB for a process's resident size
(`rsize_kib`). A counter the guest's kernel does not have is `null` rather than a zero — as is
a scale whose record a sample did not carry, so check `hertz` and `pagesize` before dividing by
one. A log with no complete sample writes nothing and exits 0, where `--summary` reports that
there is nothing to account yet:

```sh
vk gitlab atop 42137 --json | jq -c '{t: .epoch, user_sys: (.cpu.user + .cpu.system)}'
vk gitlab atop 42137 --json | jq '.procs | max_by(.rsize_kib) | {name, rsize_kib}'
```

The format is the text `atop -P` prints, pinned to the field order of atop 2.8.1 (what Debian
12 ships), so anything that already reads that — a parser, or plain `grep`/`awk` — reads these
logs. Each line is one record: a label, this guest's name, the epoch, the date and time, the
seconds the sample covers, then the label's own fields. A `SEP` line closes each sample, and a
`RESET` line opens the first one, whose counters cover the guest's whole boot. Counter labels
carry per-interval differences; size labels carry the value as it stood.

The system labels are `CPU`, `cpu` (per processor), `CPL`, `MEM`, `SWP`, `PAG`, `PSI`, `DSK` and
`NET`; every process gets a `PRG`, `PRC`, `PRM` and `PRD` line. So the busiest samples of a job
are one sort away:

```sh
awk '$1 == "CPU" { print $5, $9 + $10 }' atop.log | sort -k2 -n | tail   # time, busy ticks
grep '^PRM ' atop.log | sort -k12 -n | tail   # largest processes (column 12 only while no
                                              # process name holds a space — see below)
```

Worth knowing before reading a log:

- it is the **job's own VM**, not the fleet: a `compose:` job's service VMs are not sampled;
- a process that starts *and* exits between two samples is not in the log at all. Real atop
  catches those through process accounting; a `/proc` sweep cannot;
- there are no per-process network figures (`PRN`), which real atop needs a kernel module for.
  What the job moved in and out of the host is already on its resource line above;
- a disk that moved nothing in a sample gets no `DSK` line in it: the guest kernel carries
  sixteen ramdisks and eight loop devices that never see a sector;
- a field this guest cannot source carries the value atop itself prints when it has no answer
  — CPU frequency, cgroup limits and the proportional set size are the ones to ignore rather
  than read;
- a process's name and command line are parenthesised and may hold spaces, so column numbers
  shift on the `PR*` labels: `awk`/`sort -k` are safe on the system labels, and a `PRG`/`PRM`
  line has to be split on its parentheses first;
- the timestamps and the date directory are UTC.

Recording is not free, and it is on by default. Each job's guest gets a read-write virtio-fs
share of its own archive directory — the one directory it can write, and it can write anything
and any amount into it until the job ends — and it boots with `psi=1`, which its own scheduler
pays for in exchange for the `PSI` label. `atop = false` gives up all three.

Set `[gitlab] atop_interval_secs` for a finer or coarser resolution, and `atop = false` to
record nothing:

```toml
[gitlab]
atop = true                # default
atop_interval_secs = 10    # default; at least 1
atop_retention_days = 14   # default; 0 keeps only today's jobs
```

The archive is kept for `atop_retention_days` and then reclaimed: each day past the window is
dropped whole by the first job recorded the following day — once a day, not once a job — so the
directory stays bounded on a runner nobody visits. The window is counted in whole UTC days
beside today's, so `14` leaves fifteen date directories. Only a directory whose name is a date
in that `YYYY-MM-DD` form is ever dropped: a file, a symlink, or anything else an operator
leaves in the archive is never touched, so a log worth keeping can simply be renamed.

Two things to know before setting it. A day goes even if a guest is still recording into it, so
a job that outlives the window has its log unlinked while it is still writing — the guest keeps
appending to a file nobody can open again. With `0` that is any job running past midnight, and
with a short window any job outliving it. And the reclamation belongs to the recording:
`atop = false` stops both, so an archive already on disk stays at the size it reached and has to
be removed by hand.

### Sizing the two phases

The phases are sized independently, and by different people: the run VM by the job, the
build by the host.

| | Run phase | Build phase |
| --- | --- | --- |
| vCPUs | `[vm] cpus`, per job `MICROVM_CPUS` (capped by `[vm] max_cpus`) | `[build] cpus`, per stage guest — unset = the host's CPU count, capped at 16 |
| RAM | `[vm] mem`, per job `MICROVM_MEM` (capped by `[vm] max_mem`) | `[build] mem`, per stage guest — unset = `4G` |
| Concurrency | one VM per job (the runner's own `concurrent`) | `[build] jobs` stages at once — unset = 80% of host `MemAvailable` divided by `[build] mem`, capped at 16 |

Build sizing is host configuration only — there are no `MICROVM_*` equivalents, because
built images are cached and shared across jobs and runners, so no single job owns the
build guest it happens to trigger. Raising `[build] mem` lowers the derived `jobs` count
unless you also set it: per-stage headroom and stage concurrency trade against each other.

### Keeping the host inside its memory

gitlab-runner decides how many jobs to take with `concurrent`, a count that knows nothing
about what those jobs boot. Past the host's RAM the OOM killer arbitrates — it takes a
VMM, and that job dies mid-stage with no explanation in its trace.

Set a **memory budget** and a job instead claims the guest RAM it is about to boot, and
waits when the host is full:

```toml
[schedule]
mem_budget = "50%"        # total guest RAM admitted at once; exact "48G" also works
wait_timeout_secs = 600   # then the job gives up
```

A percentage is resolved from this host's `MemTotal`, so one config scales across runners of
different sizes. It is rounded **up** to the whole-GiB unit job sizes come in — a runner's
`MemTotal` always reads somewhat under its nominal size, and rounding down there would cost a
whole job's worth of budget — and any percentage is capped at the whole GiB the host actually
reports, so `100%` cannot round past the machine. A
host whose `/proc/meminfo` cannot be read fails a percentage budget rather than guessing one.

The budget stays a **guest RAM** ceiling either way, not a host one: leave enough of the host
outside it for the VMMs, a tmpfs-backed checkout, and anything else the box runs. Unset,
admission is disabled (the default).

A job that waits says so in its trace, and says so again when it gets in:

```
virtkit: waiting for 8192 MiB of the host's 49152 MiB memory budget (45056 MiB reserved, 1 job(s) asked first)
virtkit: admitted after waiting 34s for memory
```

Claims are held for the job's whole life and released at cleanup — or by the kernel, if
the job dies, so a crash frees its memory rather than leaking the budget. Jobs are
admitted **oldest request first**, so a large job cannot be starved by a stream of small
ones; the cost is that a small job may queue behind a large one it would have fit
alongside. Several runner processes on one host share the ledger as long as they share a
`state_dir` and run as the same user.

A job that gives up waiting exits a **system** failure, which GitLab retries only for jobs
that ask for it:

```yaml
heavy-job:
  retry:
    max: 2
    when: runner_system_failure
```

A `MICROVM_MEM` above the whole budget is clamped to it, the same way `[vm] max_mem` clamps
one: a job asking for more than the host can ever admit would otherwise fail every attempt.
Keep `[vm] mem` itself at or under the budget, though — a *default* no job can fit in makes
every job on the host fail admission.

By default the budget counts what a job **declares** (`MICROVM_MEM`, or `[vm] mem`), which
is nearly always far more than it uses — so a runner gated this way runs fewer jobs than it
could.

### Reserving what jobs actually use

Turn on `from_history` and a job is instead admitted against its own recent peaks — the
same figures its trace reports:

```toml
[schedule]
mem_budget = "50%"
from_history = true
```

```
virtkit: reserving 531 MiB from what this job has been using (it declares 2048 MiB)
```

Runs are remembered per project and job name, under
`<state_dir>/history/<project id>-<slug>/<job name>-<digest>`, so `test:unit` is predicted
from `test:unit`, not from the heavy `build` beside it. The project's own id scopes it, since
two projects can share a slug; the digest of the job's name as written keeps two names that
reduce to the same filename — `test:unit` and `test/unit` — from sharing a history.

Every job records its run, whether or not this setting is on, so turning it on has something
to work from. Each file keeps at most its thousand most recent runs, but there is one file per
job name a project has ever run and nothing prunes them, so the directory grows slowly with
the job names a host has seen. It holds no state anything else depends on: delete it, or any
file in it, whenever you like — the jobs it covered fall back to their declared size for one
run and start again.

A reservation is the **largest** run of the last **14 days** plus 25% — the largest, because
a job that peaks one run in five needs room for that run — never below 512 MiB and never
above what the job declares. A job with no history yet falls back to its declared size, as
does a job whose name changed.

A job's runs also count only while its **memory ceiling** is the one they ran under. Raise
`MICROVM_MEM` from 4G to 16G and the job is treated as unknown again for one run: what it
reached pressed against 4 GiB says nothing about what it reaches given 16, and predicting
the new job from the old one is how a host ends up overcommitted the moment someone widens a
job that needed it. Lowering the ceiling starts it again for the same reason, and putting a
ceiling back finds the earlier runs still there — they are set aside, not discarded, for as long
as the file's thousand-run cap has not pushed them out behind the newer ceiling's runs.

The window is days rather than a count of runs, because what changes a job's appetite — a
dependency, a fixture, the code — changes on calendar time, while the same number of runs
spans half an hour on a busy merge queue and most of a year on a release job. A job too
quiet to have anything inside the window keeps its **last five runs** however old they are,
so a monthly release job is still estimated from what it did rather than from what it asks
for. A spike therefore stops being believed by ageing out, not by being outvoted.

Every job trace says where it stands, whether or not the host reserves this way — reading it
is how you decide to:

```
virtkit: job resource usage: cpu 2m14s, peak memory 1.6 GiB, overlay 1.2 GiB of 16.0 GiB, read 3.4 GiB, written 812 MiB, sent 3 MiB, received 941 MiB
virtkit: most this job has used lately: memory 2.1 GiB, overlay 1.9 GiB of 16.0 GiB, read 12.0 GiB, written 3.1 GiB, sent 40 MiB, received 4.2 GiB over 37 runs; the next run reserves 2.6 GiB
```

Only the memory is reserved against; the writable layer and the traffic ride along because a
job that fills its overlay or pulls 4 GiB in and out of the host every run is a fact about the
host worth knowing. Each figure is its own maximum over the window, so they need not all come
from the same run.

The run count is what the estimate rests on: the runs of the last 14 days, or the last five
however old for a job too quiet to have that many. The `; the next run reserves …` clause
appears only where the host really does reserve that way.

The VM is still *given* the memory it declares; only the reservation shrinks. That is the
point: guest RAM is faulted in on use and handed back when freed, so a generous declared
size costs nothing at runtime, while an honest reservation is what lets the host run more
than a handful of jobs.

The trade is real, though: a job that suddenly needs much more than it ever has — a new
dependency, a bigger fixture — is admitted against the old figure, and the host can be
overcommitted for that one run. The 25% headroom and the fortnight window absorb drift, not
a step change. Leave it off until a few pipelines have been measured.

### Sizing a project

One job's trace says what that job needs. `vk gitlab usage` says what a whole project does —
every job this host remembers, heaviest first, with what its next run would reserve and what
the lot would reserve if they all ran at once, which is the figure `[schedule] mem_budget` has
to cover:

```console
$ vk gitlab usage acme
virtkit: 42-acme — what its jobs have been using lately:
  job         memory            overlay  ceiling  reserves  runs     read  written   sent  received
  build      5.9 GiB  3.9 GiB / 4.0 GiB  8.0 GiB   7.3 GiB    24  3.4 GiB  812 MiB  3 MiB   941 MiB
  test_unit  500 MiB                  -  2.0 GiB   625 MiB    37        -        -  2 MiB    88 MiB
virtkit: 2 jobs; all at once they would reserve 7.9 GiB, against a budget of 16.0 GiB
```

The argument is any part of a project's `<id>-<slug>` directory name, so the slug alone will
do; without one it reports every project on the host. `reserves` is what each job's next run
would claim: its declared size, or — with `[schedule] from_history` on, as above — what its
history says it needs. `overlay` is the writable layer against its capacity, the one column
holding a figure a job can *fail* against rather than merely be sized by: `build` above has
150 MiB of room left. A `-` is a figure no run could measure
— an unaudited kernel for the disk columns, a `net.mode = "tap"` job for the network ones, a
job with no overlaid checkout for `overlay` — which is not the same as a job that moved nothing.

A job can ask for its own project's report and get it in its trace, for an operator with the
GitLab UI but no shell on the runner:

```yaml
project-sizing:
  when: manual
  variables:
    MICROVM_USAGE_REPORT: "1"           # 1/true/yes/on
  script:
    - echo sizing
```

It reports that job's project and no other, whatever else this host has run — matched
exactly, so a project whose directory name merely contains another's is not confused with
it. Which project a job belongs to is taken from the runner's own account of the job, not
from the `CI_*` variables beside it, so it is not something a job can name for itself — and on
a runner old enough not to write that account, the report is refused rather than answered from
what the job claims.

### What admission does not do

A waiting job has already been assigned by GitLab: it holds a `concurrent` slot and its own
timeout runs while it waits. Admission keeps a host from overcommitting; it does not keep
work out of the runner. For that, see below.

Nor does it cover everything a job boots. The claim is taken at the start of prepare, so a
job that builds its own image holds its full guest RAM across that build — and the build's
own stage guests (`[build] mem` × `[build] jobs`) are outside the budget entirely. A host
has to leave room for both.

## Throttling a busy runner

`concurrent` decides how many jobs gitlab-runner *accepts*. Sized by hand it is a guess
that has to hold for the worst pipeline, so it is usually set low — and a job it turns away
stays **pending in GitLab**, holding no slot, running no timeout, free to land on another
runner. That is the one thing admission cannot do for a job already assigned.

gitlab-runner re-reads `config.toml` when it changes, so `concurrent` can follow the host.
Two pieces do that, split along the privilege line:

| | Runs as | Does |
| --- | --- | --- |
| `vk tune` | the runner user | Reads the ledger, works out how many jobs fit, writes that one number to `<state_dir>/schedule/desired-concurrency` |
| `vk-runnerctl` | root | Reads that number, clamps it into a range **it** configures, edits `concurrent`, puts the file back atomically |

The split is the point: `config.toml` is root's, and granting `vk` the right to write it
would grant root outright — `vk run` boots VMs with arbitrary mounts. `vk-runnerctl` instead
takes **no arguments and no paths**; everything it touches is named in its own root-owned
config. The worst an attacker who owns the runner user can do is ask for a concurrency an
administrator already allowed.

```toml
# /etc/virtkit/runnerctl.toml — root-owned, 0644
runner_config = "/etc/gitlab-runner/config.toml"
desired_file  = "/var/lib/virtkit/schedule/desired-concurrency"
min = 1
max = 12                  # never exceeded, whatever is requested
cooldown_secs = 60        # shortest interval between two writes
stale_secs = 300          # a request older than this is treated as gone
# reload_command = ["systemctl", "kill", "-s", "HUP", "gitlab-runner"]
```

Run the measuring half from a user timer every half minute (`vk tune`), and the privileged
half either from a **root timer** — nothing is granted to anyone — or from the runner user
through a sudoers rule that allows no arguments:

```
gitlab-runner ALL=(root) NOPASSWD: /usr/local/lib/vk/vk-runnerctl ""
```

What it does with the file is deliberately narrow: it rewrites the single `concurrent` line
and proves the result differs from the original at that key alone before installing it, so
comments, key order and registration tokens survive untouched, and the original is kept once
as `config.toml.vk-orig`. Lowering the number never disturbs a running job — it only stops
new ones being taken.

The number itself is "the jobs running now, plus what both the budget and the host still have
room for", at the size a job on this host typically reserves:

```
virtkit: runner concurrency 2 (6144 of 8192 MiB committed by 1 job(s), typical job 2048 MiB, 23040 of 32768 MiB host memory available)
```

It falls the moment the host fills and climbs back one step at a time, because a job that
has just started has not yet reached its real size. Alongside the ledger, `MemAvailable`
limits how many typical jobs fit after keeping 15% of physical RAM free. A tmpfs-backed
repository checkout therefore lowers the offered slots by its actual allocated size, as does
an unrelated service on the box, without a guessed per-repository reserve; reclaimable page
cache does not, since `MemAvailable` already counts it as available. Below that 15% floor the
runner takes nothing beyond what it is already running, whatever the ledger says. One slot is
always offered even then, since `concurrent = 0` is not a setting gitlab-runner has and a
runner that accepted nothing at all would never pick up again. And if `vk tune` stops writing,
the runner is not left throttled: `vk-runnerctl` walks `concurrent` back up to `max` a step at
a time.

A host whose `/proc/meminfo` cannot be read reports `host memory unreadable` and schedules on
the budget alone.

Getting the number wrong is cheap on purpose. It decides what the runner *accepts*, never
what is committed: too high and the extra jobs queue at the admission gate exactly as
before, too low and the host idles until the next run. The gate is the guarantee; this is
the throughput.

## Egress control

A job's networking is governed by the host `[egress]` configuration. virtkit runs
**one userspace switch per job**; the booted job guest and every [service](#services)
VM share that switch, each with its own address. By default they all share the run
policy, but a service may narrow itself further with its own allowlist (see
[per-service egress](#per-service-egress)) — the switch enforces the policy per
source VM, so one VM cannot use another's.

There are two independent phases, each with its own host cap:

- **`[egress]`** — the **run** phase: the booted job guest and its service VMs.
- **`[egress.build]`** — the **build** phase: the `RUN` steps of a git-defined
  image (`image: dockerfile:…`) or a compose `build:` service. Absent by default,
  meaning the build runs unrestricted, like `docker build`.

### Host caps

Each phase has two dimensions — `allow_ip` (direct, non-DNS egress) and
`allow_name` (DNS suffixes) — set in the host config:

```toml
[egress]
# DNS suffixes, dot-anchored: "corp.example.com" also matches *.corp.example.com
allow_name = ["corp.example.com", "crates.io", "debian.org"]
# Direct-IP egress as CIDRs, optionally port-scoped as CIDR:port (else any port).
# Needed only for a destination a job reaches by literal IP (no DNS name).
allow_ip = ["10.10.140.49/32"]
```

The list semantics are the load-bearing part:

- an **absent** list is **unrestricted** for that dimension;
- an **explicit empty** list (`allow_name = []`) **denies** that dimension;
- a phase is unrestricted only when **both** its lists are absent;
- consequently, once **either** dimension is present the phase is a restricted
  allowlist and the **other, omitted dimension is deny-all**. For example, with
  `allow_name` set but `allow_ip` absent, all direct-IP egress is denied — a job
  reaching a host by literal IP needs that IP added to `allow_ip`.

### Narrowing from a job

A job may **narrow** its egress to a subset of the host cap, never widen it. Each
variable is a **list** — one or more entries separated by spaces, commas, tabs, or
newlines (empty entries are ignored). A `#` begins an end-of-line comment, so a
block-scalar list can document each entry inline:

```yaml
least-privilege-job:
  variables:
    # Any of these separators work; mix freely.
    MICROVM_EGRESS_ALLOW_NAME: "crates.io debian.org github.com"
    # equivalently: "crates.io,debian.org,github.com"
    MICROVM_EGRESS_ALLOW_IP: "10.0.0.0/8 192.168.5.10/32"
```

The value is always a **string**, never a YAML sequence — a GitLab variable value
cannot be a list. Use the separators above, or a block scalar (`|`) to keep a long
list readable one-per-line (newlines are valid separators):

```yaml
  variables:
    MICROVM_EGRESS_ALLOW_NAME: |      # a string, split on newlines — not a YAML list
      crates.io          # Rust registry
      static.crates.io   # crate downloads
      index.crates.io    # sparse index
      debian.org         # apt mirrors (also covers deb./security.)
```

```yaml
  variables:
    MICROVM_EGRESS_ALLOW_NAME:        # ✗ invalid — a variable value cannot be a sequence
      - crates.io
      - debian.org
```

(A genuine list is only used in the host `[egress]` config — `allow_name =
["crates.io", "debian.org"]` — not in a job variable.)

You can also reference other CI/CD variables — GitLab expands `$VAR` / `${VAR}` in
the value before the executor sees it, so a shared list defined once expands into
the list virtkit parses:

```yaml
variables:
  COMMON_EGRESS: "crates.io debian.org github.com"   # define once (group/project/pipeline)

rust-job:
  variables:
    # Reference the shared list, and add a job-specific host.
    MICROVM_EGRESS_ALLOW_NAME: "$COMMON_EGRESS internal.corp.example.com"
```

- Against an **unconstrained** (absent) cap dimension, the variable defines the
  list freely.
- Against a **restricted** cap, every requested entry must fall within it
  (a suffix of some `allow_name`, or a subset of some `allow_ip` CIDR). A request
  outside the cap **fails the job** with a job-visible error.
- Against a **deny-all** (empty, or omitted-while-restricted) dimension, a job can
  add nothing.

The same applies to the build phase via `MICROVM_BUILD_EGRESS_ALLOW_IP` /
`_ALLOW_NAME`.

### Per-service egress

A `services:` entry can carry its own `MICROVM_EGRESS_ALLOW_IP` /
`MICROVM_EGRESS_ALLOW_NAME` in its `variables:` to get an egress allowlist
**distinct from the primary and from other services**. The rules are the same as a
job-level request — it narrows the host `[egress]` cap, never widens it — with one
addition: for a service, a *present-but-empty* value denies that dimension (e.g.
`MICROVM_EGRESS_ALLOW_NAME: ""` gives the service no external DNS egress). A service
that sets neither variable shares the run policy.

A per-service value is the same kind of **list** (space/comma/newline-separated)
and supports the same `$VAR` references:

```yaml
variables:
  MIRROR_EGRESS: "registry.corp.example.com mirror.corp.example.com"

job-with-services:
  services:
    - name: postgres:16
      alias: db
      variables:
        MICROVM_EGRESS_ALLOW_NAME: ""            # db gets no external egress
    - name: registry-proxy:latest
      alias: proxy
      variables:
        # A list, via a shared variable plus an extra host.
        MICROVM_EGRESS_ALLOW_NAME: "$MIRROR_EGRESS cache.corp.example.com"
    - name: fetcher:latest
      alias: fetch
      variables:
        MICROVM_EGRESS_ALLOW_NAME: "crates.io,pypi.org,files.pythonhosted.org"
```

The switch enforces each policy against the flow's **source VM** — authenticated by
the per-VM socket it arrives on, not by any address the guest writes into its
packets — so a service cannot borrow another VM's (looser) policy. Requests are
validated at job prepare, so a per-service value outside the host cap fails the job
with a visible error before anything boots.

### What a job contacts

Every job trace names what that job is known to reach out to, just before what it cost:

```
virtkit: names this job has contacted under unrestricted egress: deb.debian.org, github.com
```

This is the standing list, not this run's: each run adds what its guests resolved in the
**run phase** to what the job has resolved before, so a nightly step's host is on it even in
a pipeline that did not run one. Write an `allow_name` from it and the job keeps working — bar
any entry showing `?`, which is a name the guest sent outside the characters a hostname is
spelled with, kept only to show that it happened. A
`dockerfile:` build's own resolutions are not on it — those are the build phase's, and
`[egress.build]` is a separate cap with its own audit.

The list belongs to the **policy**, not to the job. Narrowing an allowlist starts it again
and the line then names the policy the list was gathered under
(`under egress policy a379a6f61c4b8e02`) — what a job reached while it could reach anything
says nothing about the same job once an allowlist is in force, and those names would
otherwise linger as if it still needed them. It is kept per job under `<state_dir>/sites/`,
keyed exactly as the run history is, and capped: past a couple of hundred names the line
says how many more it is not showing, because a list that long is no longer an allowlist
anyone would paste.

### Audit mode

Audit mode adds the counts for **one run**: every resolution that run made, plus the
external IPs it dialed without a resolution behind them, printed where the job can see it
(at the end of the job trace for the run phase, after the build for the build phase). Turn
it on when the standing list above is not enough — to see how often a name is reached, or
to catch a step talking to a literal IP.

```toml
[egress]
audit = true          # host-wide, for every job's run phase

[egress.build]
audit = true          # for the build phase
```

A job can enable it for itself even when the host default is off:

```yaml
discover-egress-job:
  variables:
    MICROVM_EGRESS_AUDIT: "1"           # 1/true/yes/on
    MICROVM_BUILD_EGRESS_AUDIT: "1"
```

### On the command line

Outside CI, the same controls are CLI flags on `vk run` / `vk build`:
`--audit-egress` audits the booted guest and `--build-audit-egress` a build's
`RUN` steps (mirroring the `--net` / `--build-net` phase split).

## Services

CI `services:` run as **sibling microVMs** on the per-job switch, each resolvable
by its `alias` over the switch's DNS. The `[services]` section being present in
the host config enables them; vk pulls each service image host-side (registry
credentials never enter a guest) into a shared content-addressed store.

```yaml
integration-test:
  services:
    - name: mysql:8
      alias: db
    - name: redis:7
      alias: cache
  script:
    - ./run-tests.sh                    # reaches the DB at host `db`
```

### Per-service networking

Each service is a real VM with its own address on the shared switch, so a service
can carry its own egress allowlist in its `variables:` — see
[per-service egress](#per-service-egress) for the semantics and an example. A
service that sets no egress variable shares the job's run policy.
