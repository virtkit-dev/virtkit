# GitLab CI executor

virtkit ships a GitLab [custom executor](https://docs.gitlab.com/runner/executors/custom.html)
that runs each CI job in a throwaway microVM: a fresh guest per job, destroyed
when the job ends, with its own kernel and no shared state between jobs.
Concurrent jobs each get their own VM. This guide covers configuring the runner,
selecting the job image, sizing the guest, controlling egress, and attaching
services.

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

### Image selection

`MICROVM_IMAGE` is prefix-based — the part before the first `/` names the source:

- unset → `local/default` (the baked default bundle);
- `local/<name>` — a bundle directory under `[local] dir`;
- `virtkit/<name>[:tag|@sha256:…]` — a bundle in the `[registry]` repo;
- `docker/<name>[:tag|@sha256:…]` — an OCI image from the `[docker]` repo, booted
  directly (embedded kernel + agent).

```yaml
my-job:
  variables:
    MICROVM_IMAGE: virtkit/myimage      # :tag (default latest) or @sha256:…
```

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
newlines (empty entries are ignored):

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
      crates.io
      static.crates.io
      index.crates.io
      debian.org
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

### Audit mode

Audit mode records every external domain a job resolves and prints a
"domains contacted" summary — each domain with its contact count — where the job
can see it (at the end of the job trace for the run phase, after the build for the
build phase). It is independent of the allowlist, so it also works with
unrestricted egress: leave the lists absent and turn audit on to discover the
allowlist a job actually needs before locking it down.

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
