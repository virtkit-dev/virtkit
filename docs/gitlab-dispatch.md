# GitLab dispatch: the contract

Status: experimental; `vk-gitlab`, `vk-hub` and `vk node` implement it. `vk-hub-proto`
defines the wire types: `client` for the hub's client API, `dispatch` for session job
messages, and `job` for the job spec. Serde tests pin their JSON. See
[GitLab jobs](fleet-design.md#gitlab-jobs) for the design and rationale.

Three parties take part:

- **`vk-gitlab`** — a daemon that is gitlab-runner's GitLab-facing side: it holds the runner
  tokens, asks GitLab for jobs, writes their traces and states, and submits each job to the
  hub as a [job spec](#the-job-spec).
- **`vk-hub`** — reserves capacity on nodes, places jobs, relays and stores their output, and
  reports how they ended.
- **`vk node`** — runs each job in microVMs, stage by stage, and talks to GitLab directly for
  the job's own transfers: the clone, dependency artifacts, artifact uploads.

## Tokens

| Credential | Held by | Used for |
|---|---|---|
| runner authentication token (`glrt-…`) | `vk-gitlab` alone | `POST /api/v4/jobs/request`, `/runners/verify` |
| hub API key | `vk-gitlab` alone | every [client API](#daemon--hub-the-client-api) request |
| `CI_JOB_TOKEN` (the job response's `token`) | `vk-gitlab`; the job's node, in the spec | the daemon: trace, state; the node: clone, artifact upload |
| dependency tokens (`dependencies[].token`) | the job's node | downloading that dependency's artifacts |
| registry credentials (`credentials`) | the job's node | pulling the job's images |
| node key | the node | its session, nothing else |

gitlab-runner sends the job token, not the runner token, on every per-job endpoint —
`PUT /jobs/:id`, `PATCH /jobs/:id/trace`, `POST /jobs/:id/artifacts` — so a node holding
the job token holds nothing the job itself does not. The hub sees a spec's secrets in
transit and keeps them in memory only, until the node has accepted the job; its records
and audit log hold the spec redacted (`CiJob::redacted`).

## Job flow

1. `vk-gitlab` asks the hub whether the runner's [placement](#placement) has room
   (`POST /v1/capacity`), long-polling until it does.
2. It reserves one envelope on a node (`POST /v1/reservations`); the hub offers it to nodes
   until one accepts.
3. It asks GitLab for a job (`POST /api/v4/jobs/request`), renewing the reservation while the
   request is outstanding. On 204 it renews and asks again.
4. On 201 it writes the job to its state file, translates the response into a spec and
   submits it on the reservation (`POST /v1/jobs`).
5. The hub sends the node `start`; the node journals the job, converts the reservation into
   the job's ledger entry and answers `accepted`.
6. Seeing the job accepted, `vk-gitlab` sends GitLab `PUT /jobs/:id` `state=running` — the
   commit of a job taken under `two_phase_job_commit`.
7. The node runs the stages, streaming masked output to the hub, which stores it and acks.
   `vk-gitlab` reads it from its GitLab offset and patches the trace.
8. The node uploads the artifacts to GitLab itself, then sends its result once its output
   is all acked.
9. `vk-gitlab` patches the rest of the trace, sends the final `PUT /jobs/:id`, settles the
   job with the hub (`POST /v1/jobs/<id>/settle`) and drops it from its state file.

## Admission and reservations

GitLab hands a runner a job only when the runner asks, and a job it has handed over cannot
move to another runner. So the daemon holds capacity before it asks, never after:

- **Capacity first.** `POST /v1/capacity` is advisory: the hub's count, from heartbeats less
  the reservations and starting jobs they do not show yet, of how many envelopes of the
  placement its ready nodes could take, each node at most what its concurrency ceiling leaves
  past the reservations and jobs it holds.
  The daemon does not poll GitLab for a runner while it is 0, so a fleet with no room leaves
  the job pending in GitLab for another runner.
- **Then a reservation.** Before each job request the daemon holds a reservation. The node
  decides it through its admission ledger at once — a reservation never waits in the
  ledger's queue — and counts it as granted memory and disk while it lasts.
- **Then the job request.** The reservation's lease covers the request: a lease of
  `lease_secs` (default 90) against a job request the daemon times out at 60 seconds,
  renewed every `lease_secs / 3` while the request is outstanding. A request in flight is
  never aborted: GitLab may already have assigned the job.
- **Then the job.** The job is submitted on the reservation at once. The node sizes the job by
  its own rules — `MICROVM_CPUS`, `MICROVM_MEM`, the script's `# vk:` hint, history — and
  returns what the job does not need to the ledger; a job needing more than its reservation
  waits for the rest in the ledger, as an executor job waits today.

Idle reservations are bounded: one per outstanding job request, so one per runner at the
default `request_concurrency` of 1, each held for at most one request plus a renewal. A
reservation that ends mid-request — its node lost, or the node's clock ran its lease out —
leaves a job that arrives meanwhile without one; the hub then places it afresh within its
`place_within_secs` (vk-gitlab asks for 300 seconds), and failing that ends it `no_capacity`,
which the daemon reports as `runner_system_failure`. That window is the only way a job taken
from GitLab waits for capacity.

The lease is a duration on the node's monotonic clock from its acceptance; no wall-clock time
crosses the wire. The daemon counts it from when it sent its request, so it always believes the
lease ends earlier than the node does.

## Placement

A runner in `vk-gitlab`'s configuration names its placement:

```toml
[[runners]]
name = "ci"
url = "https://gitlab.example.com"
token_file = "/etc/vk-gitlab/runner-ci.token"   # glrt-…
pool = "ci"
labels = ["large-memory"]
envelope = { mem = "16G", cpus = 8, disk = "16G" }
request_concurrency = 1
```

GitLab's job response does not carry the job's tags, and GitLab only gives a runner jobs
whose tags it has, so placement is per runner: one runner per class of work, with the tags
of that class registered in GitLab and its pool and labels here. A pool is a set of nodes the
hub's operator names (`vk-hub nodes pools <id> <a,b>`); a label is one a node declares in its
own configuration and reports in its inventory's `labels`, absent from an older node's. The API key's
policy on the hub decides the pools the daemon may use and the largest envelope it may ask
for.

A node's concurrency ceiling (`vk-hub nodes ceiling`) caps its placed work: the hub offers and
starts nothing on a node whose reservations and jobs not finished reach it, and the node
refuses `ceiling` past it by its own count. Running jobs above a lowered ceiling carry on.

A host runs its own gitlab-runner with the vk executor or takes placed jobs, never both. A node
that finds such a runner on its host says so in its report and refuses with `runner` every new
offer and every start without a reservation (a reservation it already holds is renewed and
started on); the hub places nothing on it and counts it in no capacity.

## Daemon ↔ hub: the client API

HTTP/1.1 and JSON over TLS 1.3, on the hub's node listener (`addr`), under `/v1/`. Every
request carries `authorization: Bearer <api key>`. Bodies are `vk_hub_proto::client`'s.

| Request | Body | Answer |
|---|---|---|
| `POST /v1/capacity` | `CapacityRequest` | 200 `Capacity` |
| `POST /v1/reservations` | `ReservationRequest` | 201 `ReservationGrant` |
| `POST /v1/reservations/<id>/renew` | `RenewRequest` | 200 `ReservationGrant` |
| `DELETE /v1/reservations/<id>` | — | 204 |
| `POST /v1/jobs` | `JobSubmission` | 201 `JobView` |
| `GET /v1/jobs/<id>?after=<revision>&wait=<secs>` | — | 200 `JobView` |
| `GET /v1/jobs/<id>/output?offset=<n>&wait=<secs>` | — | 200 bytes |
| `POST /v1/jobs/<id>/cancel` | `CancelRequest` | 202 `JobView` |
| `POST /v1/jobs/<id>/settle` | — | 204 |

**Long polls.** `wait` on the two `GET`s, and `wait_secs` in a capacity request, hold a
request for at most 60 seconds: a capacity answer until its `revision` passes `after`, a job
view until its `revision` passes `after`, an output read until there are bytes past `offset`
or the output is complete. A long poll that times out answers as a plain request would.

**Capacity.** `{placement, after, wait_secs}` → `{revision, fits}`. `fits` counts envelopes,
not nodes: a node with room for two counts two.

**Reservations.** `{request_id, placement, lease_secs, wait_secs}` → `{reservation, node,
envelope, lease_secs}`. The hub filters the pool's nodes on labels, readiness and headroom,
and offers the envelope to one at a time, most headroom first, until one accepts or
`wait_secs` runs out (503 `no_capacity`). `renew` extends a lease from now and answers the
lease the node granted; a reservation that lapsed, was released or whose node was lost
answers 410 `reservation_gone`. `DELETE` releases it, and answers 204 for one already gone.

**Jobs.** `{request_id, placement, reservation, place_within_secs, spec}` → `JobView`. The hub
starts the job on the reservation's node; with no reservation, or one that is gone, it
places the job as it places a reservation, for up to `place_within_secs`. A node that refuses
the start leaves the job free to place again; a start the node may have taken is never
placed twice — see [failures](#failures). The spec is at most 512 KiB serialized (413
`too_large`).

`JobView` is `{id, revision, state, node, stage, output_len, cancel, result}`: `state` is
`queued`, `starting`, `running` or `finished`, and `result` is present once finished, with the
node's `usage` when it sent one (see [Result](#hub--node-protocol-version-3)).
`revision` moves with every change but the output's length.

**Output.** The answer's body is the output from `offset`, at most 1 MiB, with
`vk-output-offset` (its first byte's offset), `vk-output-length` (the output's length so
far) and `vk-output-complete: true` when the job has ended and the body reaches its end. An
`offset` past the end answers 416 with `vk-output-length`. The hub keeps a job's whole
output until it is settled, so the daemon can read from any offset — whatever GitLab says it
holds.

**Cancellation.** `{mode}`: `graceful` or `immediate`. A later immediate overrides a graceful;
cancelling a finished job changes nothing and answers its view.

**Settle.** The daemon has delivered the outcome to GitLab; the hub drops the job's output and
keeps its record.

**Idempotency and retries.** `request_id` — 16 random bytes, hex — makes a create
idempotent for a day: the same ID with the same body answers the first answer again, or 410
`not_found` once the hub has dropped that job from its history; with another body, 409
`conflict`. Renew, release, cancel and settle are idempotent by nature.
The daemon retries transport errors and every retryable code with backoff from 1 to 30
seconds and jitter, honouring `retry_after_secs`, and never retries another 4xx.

| Status | `code` | Meaning | Retry |
|---|---|---|---|
| 400 | `invalid` | unparseable body, malformed ID | no |
| 401 | `unauthorized` | no key, or expired or revoked | no |
| 403 | `forbidden` | pool or envelope outside the key's policy | no |
| 404 | `not_found` | no such job or reservation of this key's | no |
| 409 | `conflict` | `request_id` reused with another body | no |
| 410 | `reservation_gone` | lapsed, released, or its node lost | reserve again |
| 410 | `not_found` | a create retried after its job left the hub's history | no |
| 413 | `too_large` | spec over 512 KiB | no |
| 500 | `internal` | — | yes |
| 503 | `no_capacity` | no node accepted in time | yes, after `retry_after_secs` |
| 503 | `unavailable` | hub busy or starting | yes, after `retry_after_secs` |

An error body is `{error, code, retry_after_secs?}`; a code the client does not know reads as
`other`.

## Hub ↔ node: protocol version 3

Version 3 (`JOBS`) adds one message type each way to the existing session, `{"type": "job",
"kind": …}`, whose payloads are `vk_hub_proto::dispatch`'s. A job message in a session below 3
is a protocol error. `PROTOCOL` stays at 1 to 2; each side that implements version 3 negotiates
from a range of its own reaching it: the hub accepts 1 to 3, so a node offering 3 gets it, and
one offering at most 2 is steered and never offered a job.

| Hub → node | Answer | Meaning |
|---|---|---|
| `offer {reservation, envelope, lease_secs}` | `offer_reply` | set the envelope aside |
| `renew {reservation, lease_secs}` | `lease` | extend the lease from now |
| `release {reservation}` | `lease` `gone` | give it back |
| `start {job, reservation?, envelope, spec}` | `job` | run a job |
| `output_ack {job, offset}` | — | output stored durably up to `offset` |
| `cancel {job, mode}` | `job`, then `result` | stop a job |
| `recorded {job}` | — | result stored; stop repeating it |

| Node → hub | Meaning |
|---|---|
| `held {reservations, jobs}` | everything the node holds, once per session after its report |
| `offer_reply {reservation, reply}` | `accepted {lease_secs}` or `refused {reason, message?}` |
| `lease {reservation, state}` | `held {remaining_secs}` or `gone {why}`: `expired`, `released`, `started`, `unknown` |
| `job {job, state}` | `accepted`, `refused {reason, message?}`, `running {stage}`, `finished` |
| `output {job, offset, data}` | output bytes from `offset`, base64, at most 256 KiB |
| `result {job, result}` | how the job ended; repeated until `recorded` |

Refusal reasons are `memory`, `disk`, `cpus`, `not_ready` (draining, drained, quarantined, in
maintenance), `policy`, `no_reservation`, `invalid`, `ceiling` (the node's placed jobs not
finished and reservations held reach the hub's ceiling, as the node last applied it) and
`runner` (the host runs its own gitlab-runner with the vk executor); one the hub does not know
reads as `other`, as `ceiling` and `runner` do on a hub older than them.

**Reservations.** A node answers an offer at once from its ledger: granted, or refused with
the resource that is short. It holds the entry in the ledger itself, with no job process
behind it, and drops it when the lease runs out on its monotonic clock, telling the hub
`lease gone expired`. A lease is at most 600 seconds. A drain refuses new offers and lets
held reservations lapse; a quarantine releases them.

**Start.** The node journals the job before answering `accepted`, so a start redelivered after
a reconnect is answered from the journal and not run twice. A start naming a reservation the
node does not hold is admitted like any other ask, without waiting: `refused no_reservation`
when it does not fit.

**Output.** Offsets count bytes of the output as GitLab will hold it: masked, with section
markers, timestamped (unless the job sets `FF_TIMESTAMPS` false), cut at the trace limit. A
stamp is when the node read the line (its start, for a line that spans reads), however late
the daemon reads it from the hub. The node sends at most 4 MiB past the last ack, keeps every
byte past it on disk, and after a reconnect resends from the offset the hub acked. The hub
appends each chunk to the job's output file and acks once it is synced; a chunk overlapping
what it holds is trimmed, one leaving a gap is a protocol error.

**Result.** `{failure?, exit_code?, message?, output_len, artifacts, usage?}`, sent once every
byte up to `output_len` is acked. `artifacts` gives each upload's outcome: `uploaded`, `skipped`,
`too_large` or `failed`. `usage` is what the job used on the node, `{wall_ms, cpu_ms?,
peak_mem_bytes?, cpus?, mem_mib?}`:

- `wall_ms`: from the driver's start to the job's end, cleanup included;
- `cpu_ms` and `peak_mem_bytes`: the job's VM supervisor and every process under it — the VMM
  and its vCPUs, service VMs, the switch, the forwards — read from `/proc` after the last stage
  and before cleanup, using the same measurement as the executor's `job resource usage` trace. CPU
  time is user plus system, guest execution included. Peak memory is each process's `VmHWM`
  summed: an upper bound where they did not peak together. Host-side cache and artifact
  transfers, and a host checkout, are not counted. Both are absent when no VM was up to read;
- `cpus` and `mem_mib`: the guest's size, from the job's `MICROVM_CPUS` and `MICROVM_MEM`
  clamped by the node's ceilings.

`usage` is optional, as are all its fields except `wall_ms`.

**Reconnects.** After its report, a version-3 node sends `held`. The hub releases each
reservation it does not know, cancels `immediate` each job it has given up on, and answers
each job it follows with `output_ack` at the offset it holds.

## Daemon ↔ GitLab

`vk-gitlab` speaks GitLab's runner API as gitlab-runner 19.5 does
(`network/gitlab.go`, `network/trace.go`):

- **Runners.** `POST /api/v4/runners/verify` at start with the `glrt-` token and a `system_id`
  of the daemon's own, persisted.
- **Job requests.** `POST /api/v4/jobs/request` with `RUNNER-TOKEN`, `info` and `last_update`
  — the `X-GitLab-Last-Update` of the previous answer, which lets GitLab hold the request
  until its queue changes. 201 is a job, 204 none, 403 a token GitLab refuses (the runner
  stops), 429 and 503 back off as `Retry-After` says.
- **Features.** `info.features` advertises `variables`, `image`, `services`, `artifacts`,
  `cache`, `fallback_cache_keys`, `upload_multiple_artifacts`, `upload_raw_artifacts`,
  `refspecs`, `masking`, `raw_variables`, `artifacts_exclude`, `multi_build_steps`,
  `trace_reset`, `trace_checksum`, `trace_size`, `cancelable`, `cancel_gracefully`,
  `return_exit_code`, `service_variables` and `two_phase_job_commit`. Not `session`,
  `terminal`, `proxy`, `shared`, `vault_secrets`, `service_multiple_aliases` (a node's
  executor takes one alias per service), `image_executor_opts`, `service_executor_opts`,
  `native_steps_integration` or `job_inputs`. `info.executor` is `vk`, `info.shell` `bash`.
- **Commit.** `PUT /jobs/:id` `state=running` once the node has accepted the job. A job
  that cannot be placed is failed instead (`runner_system_failure`).
- **Trace.** `PATCH /jobs/:id/trace?debug_trace=<CI_DEBUG_TRACE>` with `JOB-TOKEN` and
  `Content-Range: <start>-<end>` (inclusive, no unit), at most 1 MiB a patch, every
  `X-GitLab-Trace-Update-Interval` seconds (3 by default, capped at 15 minutes). 202 moves the
  offset on; 416 moves it to the end of the response's `Range: 0-<n>`, which is also how
  a restarted daemon finds where to resume; 404 or 403 abort the job. The trace preserves the
  node's output byte for byte. Errors for jobs the daemon refuses or cannot decode, submit
  or place use gitlab-runner's logger timestamp format (stream `00`, stdout), unless the
  job's `FF_TIMESTAMPS` is false. The state file preserves this flag across restarts.
- **Keep-alive.** With no new output for 30 seconds, `PUT /jobs/:id` `state=running` with the
  trace's `crc32:<hex>` checksum and byte size.
- **Final update.** Once the hub reports the job finished and its output complete and every
  byte is patched: `PUT /jobs/:id` with `state` `success` or `failed`, `failure_reason`,
  `exit_code` and `output {checksum, bytesize}`. 202 and 412 are asked again after the
  update interval, with backoff up to an hour, as gitlab-runner's final update does.
- **Cancellation.** Every PATCH and PUT answer carries `Job-Status`. `canceling` asks the hub
  for a graceful cancel; `canceled` or `failed`, or a 403, an immediate one, after which the
  daemon writes nothing more for the job.

The daemon keeps one state file per runner, `0600`, recording each job it has taken — GitLab
job ID, job token, hub job ID, `request_id`s — before it submits or commits it. A restarted
daemon resumes each from the hub's view and GitLab's trace offset; a job it had not yet
submitted is submitted with the same `request_id`.

The state file is `<state_dir>/<runner name>.json`. `state_dir` defaults to
`/var/lib/vk-gitlab` and is created `0700`; the daemon refuses to start when group or others
can access it. A daemon run as an unprivileged service user cannot create the default, so
create it for that user before the first start:
`install -d -m 0700 -o <user> -g <group> /var/lib/vk-gitlab`. A record stays until the hub
has settled its job, including a job already reported to GitLab or abandoned before
submission. A runner's `name` defaults to its token's short form, so a runner whose token may
change needs an explicit `name`, or the new token starts an empty file and the old one's jobs
are never resumed; the daemon warns at start about state files no configured runner owns.

Hub jobs and reservations belong to the API key that created them, and the hub answers
`not_found` for them to any other key. The state file records a fingerprint of the key, and a
daemon started with another key refuses to start while the file holds jobs. Before rotating
the key, stop the daemon (SIGTERM) and let its running jobs finish within
`shutdown_timeout`; a job still recorded then keeps the new key from starting until the old
key resumes it or the file is removed, which gives the job up to GitLab's timeout. A key
expires (`--ttl`, 90 days by default, at most a year), and the hub does not tell the daemon
when: its rotation is the operator's to schedule.

The daemon does not rotate runner tokens. It verifies the token at start and daily, warns
from a week before GitLab's `token_expires_at`, and logs an error once it has expired.

## Failures

The hub never retries a GitLab job. It places a job again only while no node can have
started it: after a `refused` start, or when the reservation it was sent to is gone and no
start went out. A start whose answer was lost waits for the node's `held` to say whether it
took it.

| How it ended | `JobResult.failure` | GitLab `failure_reason` | Older GitLab |
|---|---|---|---|
| success | — | — | — |
| a step's non-zero exit | `script` | `script_failure` | |
| past `timeout_secs` | `timeout` | `job_execution_timeout` | |
| image or service image not pulled or built | `image_pull` | `image_pull_failure` | `runner_system_failure` |
| unsupported job, refused by node policy | `configuration` | `runner_configuration_error` | `script_failure` |
| clone, artifact or cache transfer failed | `external_dependency` | `runner_external_dependency_failure` | `runner_system_failure` |
| VM, agent or host failure | `system` | `runner_system_failure` | |
| node stopped or drained hard mid-job | `interrupted` | `runner_interrupted` | `unknown_failure` |
| canceled | `canceled` | `unknown_failure`: GitLab keeps the job canceled | |
| not placed within `place_within_secs` | `no_capacity` | `runner_system_failure` | |
| node lost | `lost` | `runner_system_failure` | |

"Older GitLab" applies when the job's `features.failure_reasons` lacks the reason; the
fallback follows gitlab-runner's `common/failure_reason_mapper.go`
(`job::gitlab_failure_reason`). GitLab's `retry:` rules then decide whether the job runs
again, on whichever runner asks.

A node is **lost** for a job once it has been unreachable for `job_lost_after` (default 5
minutes) past the hub's unreachable threshold. The hub ends the job `lost`; the daemon
reports it; when the node comes back, its `held` names the job and the hub cancels it
`immediate`, and its later uploads fail on a token GitLab has invalidated. A node out of
touch for less keeps running the job and buffering its output, which the trace catches up
on.

A **hub restart** keeps job records, outputs and offsets, and loses specs and reservations:
a job not yet accepted by a node ends `lost`, and a reservation the hub no longer knows is
released when its node reports it. A **daemon restart** loses nothing it had written to its
state file.

## Artifacts and caches

**Artifact uploads go from the node to GitLab**, with the job token, as gitlab-runner's
`artifacts-uploader` does from inside the build environment. Relaying them through the hub
and the daemon would put every byte through two more hops, through a session that carries
control and telemetry only and whose messages are capped at 1 MiB, for no gain in trust: the
node already holds the token that authorizes the upload. The cost is that the node, not the
daemon, sees GitLab's answer, so it reports each upload's outcome in the result and in the
trace. The node follows gitlab-runner's upload rules: `POST /jobs/:id/artifacts` multipart
with the archive in field `file`, query `artifact_format`, `artifact_type` and `expire_in`,
a 307's `Location` followed, 413 not retried, 503 retried after `Retry-After`. Unlike
gitlab-runner, it refuses a 307 from https to http and sends the job token after a 307 only
to GitLab's own origin.

**Dependency artifacts** come from GitLab to the node: `GET /jobs/<dependency id>/artifacts`
with that dependency's token.

**Caches go to the registry** the node already uses. A cache is an OCI artifact with one
`tar+zstd` layer, in repository `ci-cache/<gitlab host>[/<gitlab path>]/<project id>`,
tagged with the sha256 of its key and the protection of the job's ref, so a protected and an
unprotected job never share one, as with gitlab-runner. The last archive written wins; content addressing
makes an unchanged cache's upload a blob probe. Caches are not shared with gitlab-runner's
`cache.zip`s: a project moving to the fleet starts cold.

Archiving and extracting run in the guest, in `vk-agent`, on the job's tree as the job left
it, with the bytes streamed over vsock; the node does the network transfers. No archiver
needs to be in the job's image. On the node, an archive is converted as it streams; only
what a format needs whole touches the job's disk — a downloaded zip, a cache layer, an
artifact's archive before its upload — each capped at 10 GiB, so a job cannot fill the disk
other jobs share. A request to the cache's registry is bounded by `CACHE_REQUEST_TIMEOUT`
(minutes, 10 by default), as gitlab-runner bounds its cache transfers.

## The job spec

`JobSpec` is tagged by `kind`; `gitlab_ci` is the only kind. `vk-gitlab` translates
GitLab's job response into a `CiJob`, normalizing what the node would otherwise interpret:
defaults are filled in, cache keys are expanded and sanitized (`cache/cachekey`), aliases are
split, empty formats become `zip`. What only concerns the conversation with GitLab stays with
the daemon.

Every field of the response, from gitlab-runner 19.5's `common/spec/spec.go`:

| GitLab field | In the spec | Notes |
|---|---|---|
| `id` | `job.id` | |
| `token` | `token` | |
| `allow_git_fetch` | `sources.allow_fetch` | |
| `job_info.name`, `.stage`, `.pipeline_id`, `.project_id`, `.project_name`, `.project_full_path`, `.namespace_id`, `.root_namespace_id`, `.user_id` | `job.*` | `project_full_path` as `project_path` |
| `job_info.organization_id`, `.instance_id`, `.instance_uuid`, `.scoped_user_id` | — | ignored: already among the job's variables where the job needs them |
| `job_info.time_in_queue_seconds`, `.project_jobs_running_on_instance_runners_count`, `.queue_size`, `.queue_depth` | — | daemon only: queue metrics |
| `git_info.repo_url` | `sources.repo_url` | credentials stripped; the node adds the job token through a credential helper |
| `git_info.repo_object_format`, `.ref`, `.sha`, `.before_sha`, `.ref_type`, `.refspecs`, `.depth`, `.protected` | `sources.*` | |
| `runner_info.timeout` | `timeout_secs` | |
| `runner_info.uuid` | — | daemon only: logs |
| `inputs` | — | `job_inputs` is not advertised |
| `variables[]` `key`, `value`, `public`, `file`, `masked`, `raw` | `variables` | the daemon appends the runner's own (`CI_RUNNER_VERSION`, …); the node adds the environment's (`CI_BUILDS_DIR`, `CI_PROJECT_DIR`, `CI_JOB_STATUS`, `CI_SERVER_TLS_CA_FILE`, …) |
| `steps[]` `name`, `script`, `timeout`, `when`, `allow_failure` | `steps` | |
| `image` `name`, `alias`, `command`, `entrypoint`, `ports`, `variables`, `pull_policy` | `image` | resolved under the node's image rules |
| `image.executor_opts.docker.platform`, `.docker.user`, `.kubernetes.user` | `image.platform`, `image.user` | `image_executor_opts` is not advertised; when GitLab sends them anyway, these are honoured |
| `services[]` | `services` | as `image`; run as a compose group beside the job VM, on one node |
| `artifacts[]` `name`, `untracked`, `paths`, `exclude`, `when`, `artifact_type`, `artifact_format`, `expire_in` | `artifacts` | |
| `cache[]` `key`, `untracked`, `policy`, `paths`, `when`, `fallback_keys` | `caches` | keys expanded against the job's and the runner's variables, as gitlab-runner expands them; variables only the node sets (`CI_PROJECT_DIR`, `CI_CONCURRENT_ID`, …) expand to nothing |
| `credentials[]` of type `registry` | `registry_credentials` | other types are ignored, as by gitlab-runner |
| `dependencies[]` `id`, `token`, `name`, `artifacts_file` | `dependencies` | |
| `features.trace_sections`, `.token_mask_prefixes` | `trace` | `trace.limit_bytes` is the runner's `output_limit`, 4 MiB by default |
| `features.failure_reasons` | — | daemon only: [failure mapping](#failures) |
| `features.tracing` | — | ignored: no OpenTelemetry export |
| `secrets` | — | `vault_secrets` is not advertised; a job with secrets fails `runner_configuration_error` |
| `hooks[]` | `hooks` | `pre_get_sources_script` and `post_get_sources_script`, run in the guest around the checkout |
| `run` | — | `native_steps_integration` is not advertised; a job with `run` fails `runner_configuration_error` |
| `policy_options` | — | the daemon writes gitlab-runner's "Job triggered by policy" line to the trace |
| `suspend_options` | — | ignored: no suspended environments |
| the runner's `tls_ca_file` | `server_ca_pem` | its contents, when set, for `CI_SERVER_TLS_CA_FILE`; without it `CI_SERVER_TLS_CA_FILE` is not set |

`server_url` is the runner's configured URL; `job.runner_id` the ID `/runners/verify`
returned.

## Stages

The node runs gitlab-runner's stage order (`common/build.go`): `prepare_executor` (admission,
image, boot, services), `prepare_script`, `get_sources`, `restore_cache`,
`download_artifacts`, each `step_<name>`, `after_script`, `archive_cache` or
`archive_cache_on_failure`, `upload_artifacts_on_success` or `_on_failure`, then cleanup.
`get_sources` uses the host-side checkout the executor already has, honouring `GIT_STRATEGY`,
`GIT_DEPTH`, `GIT_SUBMODULE_STRATEGY`, `GIT_CHECKOUT` and `GIT_CLEAN_FLAGS`; the other stages
reuse the executor's VM, exec and cleanup code. Step scripts are generated as gitlab-runner's
bash shell generates them (`shells/abstract.go`, `shells/bash.go`), and output is masked and
timestamped as its `common/buildlogger` masks and stamps it: each stream on its own — the
node's lines and `vk gitlab prepare` as stream `00`, `vk gitlab run` as `01`, stdout `O` and
stderr `E` apart — masked before it is stamped, the stamps counted in the trace limit.
`FF_TIMESTAMPS` is read from the job's variables only, on by default as in gitlab-runner 19.5;
a runner's `[runners.feature_flags]` has no equivalent here. Those ports keep gitlab-runner's
MIT notice.

## Compatibility fixtures

Ported from gitlab-runner v19.5.0 (MIT; the notice is in `NOTICE`), as tests of the
`vk-gitlab` crate unless noted:

| Upstream | Ported as |
|---|---|
| `network/gitlab_test.go` `getRequestJobResponse` | a JobResponse JSON fixture; parse it and translate it to a `CiJob`, checking every field the table above maps |
| `common/support.go` `GetSuccessfulBuild`, `GetRemoteSuccessfulMultistepBuild`, `GetFailedBuild`, `getBuildResponse`, `getStepsBuildResponse` | JobResponse fixtures for multi-step, failing and `run` jobs |
| `common/network_test.go` `Test_Image_ExecutorOptions_UnmarshalJSON`, `TestFeaturesInfo_JSONMarshaling` | executor options and the `info.features` body |
| `network/gitlab_test.go` `TestGitLabClient_RequestJob`, `TestSetLastUpdate`, `…_TransmitsTwoPhaseJobCommit`, `TestVerifyRunner`, `TestTokenIsCreatedRunnerToken` | request, long-poll and verify against a fake GitLab |
| `TestUpdateJob`, `TestUpdateJobAsKeepAlive` | state updates and `Job-Status` handling |
| `TestPatchTrace`, `TestRangeMismatchPatchTrace`, `TestPatchTraceContentRangeAndLength`, `TestPatchTraceContentRangeHeaderValues`, `TestPatchTraceUrlParams`, `TestUpdateIntervalHeaderHandling`, `TestAbortedPatchTrace`, `TestJobFailedStatePatchTrace` | trace patching, offsets and intervals |
| `network/trace_test.go` (`TestJobFinishTraceUpdateRetry`, `TestJobDelayedTraceProcessingWithRejection`, `TestJobMaxTracePatchSize`, `TestCancelingJobIncrementalUpdate`, `TestJobChecksum`, `TestJobBytesize`) | the trace loop and final update |
| `checkTestArtifactsUploadHandlerContent`, `TestArtifactsUpload`, `TestArtifactsDownload` | upload and download expectations, in `vk-driver`'s node job tests |
| `common/failure_reason_mapper_test.go` | `vk-hub-proto` `job::tests` (built) |
| `cache/cachekey` tests | key sanitizing, in `vk-gitlab` |
| `helpers/archives` zip tests, `helpers/trace` masker tests | archive and masking, in `vk-driver` |

## Open questions

- **Uncommitted jobs.** What GitLab does with a job taken under `two_phase_job_commit` that is
  never committed — whether it returns it to the queue, and after how long — decides whether
  a job the fleet cannot place should be failed or left uncommitted.
- **Registry scopes.** A cache write needs a token scoped to the project's cache repository;
  `vk-registry` grants per-account read and write, not per-repository scopes, so caches start
  with the node's own registry credential.
- **Secrets through the hub.** The hub sees a spec's secrets in memory. Encrypting them to the
  reserved node's pinned key would keep them from the hub, at the cost of the hub no longer
  placing a job on another node than the one reserved.
