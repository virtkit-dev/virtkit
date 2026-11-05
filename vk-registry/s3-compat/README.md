# S3 compatibility, correctness and performance suites

External test suites pointed at this registry's S3 view (`/s3/`, see `DESIGN.md`'s "S3
view"): the S3 equivalent of running Autobahn against a WebSocket server. Nothing here is
part of the build or of `cargo test`; each suite is fetched at a pinned version on first
use and run from a shell against a throwaway server.

| directory | what | how it reaches the server |
|---|---|---|
| `s3-tests/` | [ceph's s3-tests](https://github.com/ceph/ceph/tree/main/src/test/rgw/s3-tests), the broadest S3 conformance suite (boto3, ~800 tests of buckets, objects, listing, multipart, copies, conditional requests, versioning, ACLs, policies...) | through the proxy (host and port only) |
| `msst-s3/` | [MSST-S3](https://github.com/linux-kdevops/msst-s3) (boto3, ~600 tests mostly ported from versitygw's, in separable groups: basic, multipart, edge, batch...) | directly, SigV4 |
| `versitygw/` | [versitygw's integration tests](https://github.com/versity/versitygw) (`versitygw test full-flow`, aws-sdk-go-v2: the strictest on headers, error codes and messages, checksums, conditional writes, streaming signatures) | directly, SigV4 |
| `warp/` | [MinIO warp](https://github.com/minio/warp), the S3 benchmark (mixed, get, put, list, stat, delete, multipart) | through the proxy |
| `smoke/` | the AWS CLI and rclone doing what their users do: make a bucket, upload small and large (multipart) objects, list, sync, download in ranges, compare, delete | directly, SigV4 |

## Running

Prerequisites: `git`, `curl`, `python3`, `tar`, `unzip`, [`uv`](https://docs.astral.sh/uv/)
(the Python suites' environments and the AWS CLI come through it), and network access to
github.com and pypi.org the first time. No Docker, no Go, no system Python packages: every
download is pinned to a version and a sha256 (`lib.sh`'s `s3c_fetch`, `s3c_clone`).

```sh
cd vk-registry/s3-compat
./serve.sh start            # a vk-registry on 127.0.0.1:5300 with S3 on, plus the proxy on :5301
./smoke/run.sh              # the AWS CLI and rclone, a few seconds
./s3-tests/run.sh           # ceph's suite: all of test_s3.py less markers.txt, minutes
./msst-s3/run.sh            # MSST-S3's basic, multipart, edge and batch groups
./versitygw/run.sh          # versitygw's full-flow
./warp/run.sh mixed         # a minute of mixed GET/PUT/DELETE/LIST/STAT at 1 MiB objects
./serve.sh stop
```

`serve.sh` takes the binary from `dist/vk-registry` (`./build.sh --fast --only=vk-registry`),
else the debug build `cargo test` leaves in `target/`, else `VK_REGISTRY`. The server runs
in shared-secret mode with one Basic user, `s3compat`, and a random password, so the SigV4
access key id is `s3compat` and the secret is the password (`DESIGN.md`, "Credentials");
its store, config, logs and pids are under `.state/` (`serve.sh start --fresh` wipes the
store). `.state/env.sh` holds the endpoints and credentials every `run.sh` sources;
`eval "$(./serve.sh env)"` loads them into a shell for the AWS CLI or rclone by hand.

To run a suite against another server, say AWS or MinIO for a side-by-side reading of a
failure, export `S3C_ENDPOINT` (the S3 API's URL), `S3C_ROOT_ENDPOINT` (the same API with
no path, for s3-tests and warp), `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` before
the `run.sh`; `.state/env.sh` is then not read.

Each run writes `results/<time>/` in its suite's directory, with `results/latest` pointing
at it: the suite's own output, its log, and `outcomes.txt` (one `PASS|FAIL|SKIP<tab>id`
line per test). `results/`, `upstream/`, `.venv/` and `.state/` are ignored by git.

## Holding a baseline

A suite written for S3 as AWS serves it will fail here wherever this registry serves
less (no versioning, ACLs, policies, lifecycle, tagging, object lock or encryption; keys
restricted to `[A-Za-z0-9._-]` components) or answers differently on purpose (every object
is `application/octet-stream`; presigned URLs refused). The point is not to reach zero
failures but to know the set and watch it shrink. So each conformance suite keeps
`expected-failures.txt`, and its `run.sh` ends by comparing the run with it
(`outcomes.py compare`):

- a failure the baseline does not expect is a regression, or work still to do: listed,
  and the run exits 1;
- an expected failure that now passes is progress: listed, with a hint to drop it from
  the baseline;
- `run.sh --accept` rewrites the baseline from the run's failures.

The baselines start empty: once the server is where it should be, run each suite,
read its failures, and `--accept` what is understood. From then on a run that exits 0 means
"no worse than the baseline". `s3-tests/markers.txt` lists the pytest markers left out
entirely, for the tests that are slow (lifecycle tests sleep for minutes) or need another
service (IAM, STS, SNS, Keycloak); tests of unserved features that fail fast stay in, so
the day a feature is served its tests start passing without a change here.

## The proxy, and why

Some clients take an endpoint URL and keep its path: boto3 and the AWS CLI, rclone and the
Go SDK send `/s3/<bucket>/<key>` when told `http://host:5300/s3`. Ceph's s3-tests take a
host and a port and warp takes `--host`, so they can only send `/<bucket>/<key>`.
`proxy.py` (standard library, started by `serve.sh`) listens on the second port, prepends
`/s3` and forwards to the registry. A SigV4 signature covers the path, so the client's
cannot be kept; the registry takes its other credentials on `/s3/` too, so the proxy
replaces the SigV4 header with the Basic user when the access key id is its name, and with
a bearer holding the access key id otherwise (an API key or a hub token is both id and
secret). `aws-chunked` bodies pass through: under such a credential the registry decodes
them without checking chunk signatures.

Consequences: through the proxy, signatures are not what is tested (the registry's own
e2e tests cover SigV4 against AWS's published examples, and versitygw's authentication
tests reach it directly); and the proxy opens one connection per request, which is part of
what warp measures, so warp numbers compare one build with another rather than this
registry with a server addressed at its root.

## Pins

| tool | version | from |
|---|---|---|
| ceph/ceph `src/test/rgw/s3-tests` | commit `1cfa9f84f53c4ffd25ff92fe5e0b56154eaf0bfb` (main, 2026-11-05) | sparse, blobless clone (6 MB) |
| linux-kdevops/msst-s3 | commit `b84a323cca5ee862e87677043f672f156c46b448` (main, 2025-12-04) | clone |
| versitygw | 1.10.0 (2026-10-22), `versitygw_v1.10.0_Linux_x86_64.tar.gz` | GitHub release, sha256 pinned |
| warp | 1.8.2 (2026-09-24), `warp-rdma_linux_amd64.tar.gz` (the release's only Linux build; dynamically linked, its library beside it) | GitHub release, sha256 pinned |
| rclone | 1.75.2 (2026-10-09), `rclone-v1.75.2-linux-amd64.zip` | GitHub release, sha256 pinned |
| awscli | 1.46.2 (2026-10-21) | PyPI, through `uvx` |

The old `ceph/s3-tests` repository was archived in October 2026 and its tests moved into
`ceph/ceph`; MinIO's `mint` was archived in March 2026 and is not used here. To move a
pin, change the version and sha256 (or commit) at the top of the suite's `run.sh`.

## What the suites need from the server

Found while bringing the harness up against a build in progress (November 2026):

- **s3-tests cannot run at all without ListObjectVersions.** Its per-test setup and
  teardown empty every test bucket with `list_object_versions`, so a 501 there makes every
  test error before it starts. An unversioned bucket's answer (each key once, `VersionId`
  `null`, `IsLatest` true, no delete markers) is what AWS gives for a bucket that was never
  versioned.
- **A ranged GET that carries the whole object's `x-amz-checksum-sha256` fails the AWS
  CLI's downloads.** The CLI fetches anything past 8 MiB as parallel ranges, validates each
  206 response's body against the checksum header it carries, and the whole object's does
  not match a part. The smoke test's 20 MiB download and `s3 sync` down fail that way.
- **versitygw's `full-flow` can crash mid-way** on an answer it did not expect (a Go
  panic in the client), in which case `run.sh` reports what ran; the rest is reachable one
  test at a time (`./versitygw/run.sh <TestName>`, names from `versitygw test --help`).

## Layout

```text
serve.sh        the throwaway server and the proxy: start [--fresh] | stop | status | env
lib.sh          shared by the run.sh scripts: env, pinned downloads and clones, venvs, results
proxy.py        /<bucket>/<key> on one port -> /s3/<bucket>/<key> on the registry's
outcomes.py     junit or versitygw output -> outcomes; outcomes vs expected-failures.txt
<suite>/run.sh  fetch, configure, run, compare; see each one's header for its arguments
```
