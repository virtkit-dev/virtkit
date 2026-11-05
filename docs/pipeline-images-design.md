# Pipeline images: built from a job, booted by its pipeline

Status: step 1 implemented.

A job builds an image from a Dockerfile and a context it produced itself, and later jobs of
the same pipeline boot it. The case: a packaging job ends with its `.deb`s in a directory,
builds a runner image that installs them, and the pipeline's test jobs run in that image.

`dockerfile:` does not cover it: it builds from the job's git checkout only, before the job
starts (`vm.rs`, `build_git_image`), and the packages are not in the checkout.

This design covers jobs placed by the hub. It builds on
[the disk images design](disk-images-design.md) §3 (pipeline scope, publication) and on
[the registry hub design](registry-hub.md#4c-pipeline-caches-and-captures) (the
`ci-pipeline` namespace, job tokens).

## Interface

In the producer job:

```sh
ref=$(vk-agent build -f docker/runner.Dockerfile --target runner \
        --build-arg VERSION="$VERSION" --as runner ./out)
echo "RUNNER_IMAGE=$ref" >> build.env
```

```yaml
build-debs:
  script: [./debbuild.sh]
  artifacts:
    reports: { dotenv: build.env }

test:
  needs: [build-debs]
  variables:
    MICROVM_IMAGE: $RUNNER_IMAGE    # pipeline/build/runner:job-1234@sha256:…
```

- `vk-agent build [-f FILE] [--target STAGE] [--build-arg NAME=VALUE]… --as NAME CONTEXT`.
  `-f` defaults to `CONTEXT/Dockerfile` and may lie outside the context, as with
  `docker build`. `NAME` is one repository name component.
- Build output goes to stderr. On success, stdout is one line:
  `pipeline/build/<name>:job-<job id>@sha256:…`, the published bundle's tag and digest.
- A consumer names that reference, or `pipeline/build/<name>` for the last one published in
  the pipeline. The full form is the one to pass along: a retried producer publishes a new
  image under its own job ID, and a consumer holding the old reference keeps the old image.
- `pipeline/build/` is apart from `pipeline/<name>`, which names a service capture
  (disk images §3), so a build and a capture of the same name never meet.

## Host side

The request travels over the job VM's host command channel (`/run/vk/host.sock`, served by
`vk-agent serve` with a forced wrapper; `vm.rs`, `spawn_service_exec_serve_at`). Today the
channel exists only for jobs with services, its wrapper allows `vk exec --service` and
nothing else, and `[executor] guest_service_exec` decides only whether the channel is served.

- **Forms the wrapper allows.** The node passes the wrapper the forms the job may use, as
  trusted arguments before the `--` (`vk service-exec <dir> --allow exec,build -- …`). The
  wrapper checks each request against them, so serving the channel for `build` does not
  bring back `exec --service` where `guest_service_exec = false`. The channel is served
  when at least one form is allowed. A `vk` rolled back to a release without `--allow`
  while a job runs refuses every request on that job's channel, exec included, until the
  job ends.
- **Credential precondition.** A proxy lending the node's credential (`proxy_guests`)
  gives every guest on that node the registry as the node sees it, past any resolver, so no
  pipeline's images are out of its reach. Isolation therefore holds only on a registry whose
  nodes all lend job tokens (`[registry] guest_credential = "job"`) or no proxy at all.
  That is the operator's to keep. The node refuses at config load a `guest_build` beside a
  node-credential proxy, so a node offering builds is not the one leaking them.

A build runs in four steps.

1. **Context.** The guest sends the context as a tar on the request's stdin, followed by the
   Dockerfile as a separate entry. The agent applies the context's `.dockerignore` before
   sending (`vk-core`'s `dockerignore`), so excluded files never cross. The host unpacks into
   a fresh private directory, `<job dir>/guest-build/<n>/`, created through `vk-fs` and
   walked by descriptor:
   - regular files and directories only: symlinks, hard links, device nodes and FIFOs are
     refused, and no ownership or setuid bits are taken from the tar. With no links in the
     tree, nothing the host later reads under the root can lead out of it;
   - an entry's path is relative, with no empty, `.` or `..` component, and no path is
     named twice;
   - every component is opened with `O_NOFOLLOW` under the root, which a racing writer
     cannot defeat since the guest has no access to the directory;
   - the Dockerfile and `.dockerignore` are regular files of the tree like the others;
   - the stream is capped while it is read, in bytes (`[executor] guest_build_max_context`,
     default `8G`) and in entries (`guest_build_max_entries`, default `1000000`); crossing
     either stops the transfer and the build.
2. **Build.** The same path a `dockerfile:` image takes: the build tier, the
   `[build] cache_registry` layer cache, the build phase's egress rules, the build figures
   in the job's events. `build_git_image` splits into resolving sources (checkout and
   `dockerfile:` spec, or the unpacked guest context) and building them, so both callers
   share the second half.
3. **Publication.** The bundle goes to `<pipeline prefix>/builds/<name>`, under the prefix
   the hub sent in `JobRegistry.pipeline_prefix`, whatever path the operator gave the
   `ci-pipeline` namespace. The push uses the job's registry token, which reaches only that
   pipeline's namespace and those the hub grants it. It tags `job-<job id>`, then moves
   `current`, the publication of disk images §3. A job publishes a name once: when
   `job-<job id>` already exists under it, the build is refused before the context is read,
   so a returned reference never changes and its digest keeps its root. A job without a
   pipeline prefix is refused the same way.
4. **Reply and cleanup.** The reference, as `pipeline/build/<name>:job-<job id>@sha256:…`.
   The context directory is removed when the build ends, whether it succeeds, fails or the
   guest disconnects, and with the job dir in any case.

Limits:

- One build at a time per job; a second waits up to 10 s for the first, and its context's
  removal, then is refused. With the cleanup above, a job holds at most one context on the
  host.
- The build runs inside the job's time budget: cancelling or timing out the job stops it.
- `[executor] guest_build = false` turns the form off.

## Resolution

`pipeline/build/<name>[:job-<id>][@sha256:…]` resolves to `<pipeline prefix>/builds/<name>`,
by tag: `job-<id>` when given, else `current`. A digest given alongside must equal the
tag's, or the job fails. The prefix comes from the job's start as the node received it,
never from the guest or the job's variables. Any reference written directly into the
pipeline namespace's path on the host of a section whose credential the pull sends, by tag
or by digest, is refused, so a job reaches another pipeline's images only by naming them,
and cannot name them. The comparison is by host name: another name for the registry's host
is not refused, and pulls anonymously or through the relay under its origin's name. The
node refuses everything under its `[registry] pipeline_root` (default `ci-pipeline`), which the operator sets to the root of
the namespace's path, for every job, and under the first component of a job's prefix. Every
other `pipeline/` name is reserved: disk images §3's capture resolver adds `pipeline/<name>`
beside it.

Resolution always asks the registry for the tag, even when the bundle is in the node's
cache: the registry dates a tag's last use when it is read by tag (`Store::get_manifest`),
not when its digest is read, and the request is one small manifest.

The node's bundle cache is keyed by name and digest, not by repository: once a node holds
`runner@sha256:…`, `virtkit/runner@sha256:…` boots it there without the registry being asked.
That is no wider than the registry's own reads, under which a digest is readable by the
fleet's jobs (below).

The job's token also lets its guest push to `builds/` directly through the proxy, tags
included, bypassing `vk-agent build`. That stays within the pipeline, whose jobs already
share its namespace with write (registry hub 4c): a pipeline's images are as trusted as its
jobs, and no more.

Pulls keep the node's credential until image pulls use the job's token; until then the
resolver is a consumer's only guard. The resolver guards names, not digests: a digest is
readable through any repository the caller may read, held there or not, as long as the
caller may read some repository that holds it, and through any repository at all when the
credential has no per-repository scopes (`vk-registry`'s `readable_through`). A node
credential that reads the pipeline namespace therefore lets a job that learns another
pipeline's digest boot it through any `virtkit/` reference the node may read. Until pulls use the job's token, a pipeline image's digest
must be treated as readable by the fleet's jobs, and an image must not hold secrets the
pipeline's jobs would not share. Captures are in the same position.

## Lifetime

The hub does not see a pipeline end, so expiry is by time: the window on the pipeline
namespace's path. The registry has none by default, and a prefix without one takes the
store-wide window. The operator sets it in the registry's config, `[[gc.prefix]] path =
"ci-pipeline", retention_days = 2`, matching the namespace's path. The hub cannot shorten it:
it may only lengthen a window the config sets, and a prefix the config leaves without one
takes no hub window below `[hub] min_retention_days` (7 by default).

A consumer resolving a reference keeps its tag alive (see above). One starting after expiry
fails with a message naming the image and, from the reference's `job-<id>`, the producer job
to rerun; a bare `pipeline/build/<name>` names the image only.

Layers shared with the build cache stay as long as the cache keeps them; only the bundle's
own blobs go with the pipeline.

## Plan

| Step | Content | Done when |
| --- | --- | --- |
| 1 | Pipeline scope on the node: read `pipeline_prefix`, `pipeline/build/` resolution by tag, refusal of direct references into the namespace, the `job-<id>`/`current` publication helper | a bundle pushed by hand under a pipeline's `builds/` boots from `pipeline/build/<name>` in that pipeline only |
| 2 | Split `build_git_image` into source resolution and build | `dockerfile:` jobs unchanged; the build half takes any source directory |
| 3 | The wrapper's `--allow`, with `exec` alone reproducing today's channel | `guest_service_exec = false` with `build` allowed refuses `exec --service` |
| 4 | The `build` form: context transfer and unpacking, `vk-agent build`, `[executor] guest_build*`, the credential precondition | `vk-agent build` in a job prints a reference the next job boots |
| 5 | End-to-end in `tests/gitlab/scenarios.sh` | build in job A, boot in job B of the same pipeline; refused from another pipeline and another project; a second build of one name in a job, a context over either cap, a tar entry escaping its root and a symlinked Dockerfile are refused; a digest-pinned consumer keeps the tag alive |

## Alternatives considered

- **Building in the guest with a nested `vk`.** Needs nested KVM, which is the runner's
  decision, and loses the shared build cache.
- **Uploading the context to the pipeline's files and booting a lazy `dockerfile:`-like
  reference.** No new channel, but every consumer pays for the build or waits on its lock,
  and the producer cannot report a digest.
- **`docker build` and `docker push` in the guest.** Needs a Docker daemon in the job image
  and a registry credential in the guest, and builds outside virtkit's cache.
- **One `pipeline/<name>` for builds and captures.** Shorter, but a build and a capture of
  the same name would overwrite each other's `current`, and publication would need a lock
  across both kinds to refuse the clash.

## Open questions

- Whether `--as` may be omitted, naming the image after the job.
- A retention for pipeline images shorter than for captures: `[[gc.prefix]]` counts whole
  days, so less than a day needs a finer unit.
