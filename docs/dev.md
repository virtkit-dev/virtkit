# Project development environments

`vk dev` runs a project's development environment in microVMs, using a tracked
`.virtkit/config.toml`. The same configuration drives command execution, interactive
shells, VS Code, services, published ports, lifecycle hooks and project tasks.
The environment stays running between commands; each worktree and named environment
has its own state and identity.

This guide covers setup, daily use and the configuration reference, with examples of a development VM and on-demand services. For the underlying compose dialect,
see [Run compose services](../README.md#run-compose-services). The machine-wide
virtkit config is a separate file: `--dev-config` selects a project config,
whereas `--config` selects virtkit's host configuration.

## Contents

- [Quick start](#quick-start)
- [Configuration and local overrides](#configuration-and-local-overrides)
- [Images, builds and resources](#images-builds-and-resources)
- [Daily workflow and freshness](#daily-workflow-and-freshness)
- [Compose services and endpoints](#compose-services-and-endpoints)
- [Workspace, mounts and storage](#workspace-mounts-and-storage)
- [VS Code and SSH](#vs-code-and-ssh)
- [Lifecycle hooks](#lifecycle-hooks)
- [Project tasks](#project-tasks)
- [Host integration](#host-integration)
- [Importing a devcontainer](#importing-a-devcontainer)
- [Troubleshooting](#troubleshooting)
- [Command reference](#command-reference)

## Quick start

Install `vk` following the [installation instructions](../README.md#install).
You need an x86-64 Linux host and read/write access to `/dev/kvm`. Pulling images
requires network access. Using an installed `vk` does not require Docker.

From a trusted project checkout:

```sh
vk dev init
vk dev plan
vk dev doctor
vk dev shell
```

`init` validates an existing config, including its local overrides. Otherwise it
looks for a devcontainer definition, a root compose file, then a Dockerfile;
without any of these it writes a stock-image template. It reports what it
translated and what needs attention. A draft requiring an essential decision is
still written, but the command exits 1. Review and complete it before booting.
Importing runs no hooks, downloads nothing and boots nothing.

To start explicitly from an image:

```sh
vk dev init --from image --image docker.io/library/debian:13
```

A minimal standalone config is:

```toml
schema = 1

[requires]
min-version = "0.64.0"

[dev]
image = "docker.io/library/debian:13"
workspace = "/workdir"
user = "root"
```

This gives you the image's tools and the checkout at `/workdir`. Add your project's
toolchain to a Dockerfile or use an image that already contains it.

```sh
vk dev exec -- sh -lc 'pwd; ls'
vk dev status
vk dev stop
```

Exiting a shell or finishing an `exec` command leaves the environment up.
`stop` shuts it down while retaining its state for the next start.

## Configuration and local overrides

Keep the shared environment in version control and personal values beside it:

| File | Purpose |
| --- | --- |
| `.virtkit/config.toml` | Tracked project configuration; requires `schema = 1`. |
| `.virtkit/local.toml` | Machine-specific overrides, in the same shape. |
| `.virtkit/local.env` | Optional `KEY=value` data for `${localEnv:NAME}`. |
| `.virtkit/toolchain.lock` | Optional tracked pin for the team's virtkit release and artifacts. |

Add `.virtkit/local.toml` and `.virtkit/local.env` to the project's `.gitignore`.
Also ignore any additional personal env files or disk images you place in the
checkout. `init` does not manage your local files.

Commands discover the config by walking toward the current Git checkout's root,
stopping at its `.git` boundary. You can address a checkout from elsewhere:

```sh
vk dev --workspace /path/to/project status
vk dev --dev-config /path/to/project/.virtkit/config.toml plan
vk dev --environment hook plan
```

`[dev]` is the default environment. Additional `[environments.NAME]` tables are
independent configurations: they inherit nothing from `[dev]`, including its
user, mounts and environment variables.

### Layering

Local tables merge recursively; scalars and arrays replace the tracked values.
An empty array clears a list. Named mounts, endpoints and tasks accept
`enabled = false`. Only `local.toml` accepts top-level `remove` and `env-files`:

```toml
# .virtkit/local.toml
remove = ["dev.host.git-gui"]
env-files = [".virtkit/private.env"]

[dev]
cpus = 4
mem = "8G"
profiles = []

[dev.mounts.gitconfig]
enabled = false
```

`remove` drops dotted paths before the other overrides apply. Extra env-file paths
are relative to the workspace and must stay within it. They are read after
`local.env`, with later files overriding earlier ones. The process environment
has precedence over all of these files. An exported empty value is still a value;
it does not fall back to the file or substitution default.

Env files are data, not shell scripts: shell commands and variable references in
them are not evaluated. Loading `local.env` does not inject every entry into the
guest; reference the values you need in the config.

### Substitutions and environment

Supported substitutions in expanded values such as mount paths, build arguments
and environment values are:

| Expression | Value |
| --- | --- |
| `~`, `${HOME}` | Host user's home directory (`~` at the start of a path). |
| `${workspace}` | Host workspace directory. |
| `${state}` | This worktree/environment's state directory. |
| `${VK_UID}`, `${VK_GID}` | Host user's numeric IDs. |
| `${localEnv:NAME}` | Process environment, then local env files; required if no default. |
| `${localEnv:NAME:default}` | Same lookup with a fallback; `${localEnv:NAME:}` permits absence. |

Other `${…}` names are rejected. Compose files have their own interpolation
syntax and reserved `${VK_WORKSPACE}`, `${VK_STATE_DIR}` and `${VK_SELF}` names;
see [Compose interpolation](../README.md#environment-and-interpolation).

Use `exec-env` for development sessions and guest lifecycle hooks, and
`container-env` for the guest's processes at boot:

```toml
[dev.exec-env]
PROJECT_TOKEN = "${localEnv:PROJECT_TOKEN:}"
BUILD_MODE = "debug"

[dev.container-env]
LANG = "C.UTF-8"
```

`vk dev plan` redacts environment values and build arguments by default, including
in `--explain` output. `--show-secrets` reveals them. Keep secrets in local files
or the process environment rather than the tracked config.

### Validation and version requirements

Unknown configuration keys and unsupported values produce errors. Hook groups
are the exception to ordinary key checking: arbitrary member names are allowed,
so a misspelled `run` can look like a group member.

`init` adds a `#:schema` directive for editor completion and validation. The
[JSON Schema](schema/virtkit-config.schema.json) is also available from
`vk dev schema`. Use `[requires].min-version` for the compatibility floor and
`[requires].features` for feature names understood by `vk check --feature`.

A toolchain lock pins the team's chosen release independently of that floor:
`vk toolchain lock` writes it, `vk toolchain install` downloads its artifacts to
a versioned cache, and `vk toolchain status` reports the pin and installation.
Installing a locked toolchain does not replace the `vk` on `PATH`; scripts can
use `vk toolchain export` to obtain its paths.

## Images, builds and resources

Each environment selects exactly one of `image`, `build` or `compose`.
A compose source also requires `service`, naming the primary VM you work in.

For a project Dockerfile, replace the image source with:

```toml
[dev]
workspace = "/workdir"
user = "dev"
cpus = "host"
mem = "8G"
nested = "auto"

[dev.build]
context = "."
dockerfile = "Dockerfile"
target = "dev"

[dev.build.args]
DEVUSER_UID = "${VK_UID}"
DEVUSER_GID = "${VK_GID}"
```

The context is relative to the workspace; the Dockerfile is relative to that
context and defaults to `Dockerfile`. Omitting `target` selects the final stage.
The image must provide the configured user. Pass UID/GID build arguments only
when your Dockerfile consumes them to create the development user.

`cpus` accepts a positive integer or `"host"`. `mem` uses sizes such as `8G`.
When unset for compose, they inherit the primary service's `x-virtkit` settings,
then virtkit's defaults. `nested = true` requires nested virtualization and
fails if the host cannot provide it; `"auto"` uses it when available. The default
is off. Use it when the guest itself needs to boot microVMs.

### Build cache

```toml
[dev.cache]
registry = "http://127.0.0.1:5000"
insecure = true
```

The registry setting accepts a cache reference, local directory or `none`.
`insecure` permits a plain HTTP registry. For one invocation, override these with
`--cache-registry REF|DIR|none` and `--cache-insecure`.

```sh
vk dev build
vk dev build --service runner
```

These build into the cache without starting or stopping the development
environment. `cached-only = true` is available for a `build` source: it requires
a cache hit unless `fallback = { target = "smaller-stage" }` names a stage to
build on a miss. The fallback responds to a cache miss, not a failed guest boot
or command. An ephemeral task whose environment has no cache registry uses the
calling environment's cache settings. See [Project tasks](#project-tasks) for an example.

## Daily workflow and freshness

```sh
vk dev up
vk dev shell
vk dev exec -- make test
vk dev exec -t -- sh
vk dev exec --dir /workdir/subproject -- make test
vk dev exec --user root -- id
```

`up` builds and boots in the foreground, then returns once the environment is
ready. Concurrent callers join an in-flight boot; `up --no-wait` fails promptly
instead. Primary `exec`, `shell` and `code` bring the environment up when needed.
Commands use the configured user and `exec-env`; a host working directory inside
the checkout maps to its corresponding guest directory. `--dir` overrides that
mapping. `exec` passes arguments directly and reproduces the command's exit
status; use `sh -lc '…'` explicitly for shell syntax.

A matching running environment is reused. When its recorded configuration differs
from the current plan, `freshness` controls the next attachment:

| Policy | Behavior |
| --- | --- |
| `ask` (default) | Offer refresh on a terminal; declining or having no terminal reuses with a note. |
| `reuse` | Reuse the recorded environment and report differences. |
| `refresh` | Rebuild and replace the environment. |
| `require-current` | Fail with the differences and the command to reconcile them. |

Override the project policy for an invocation with `--freshness POLICY`.
Inspect a change before applying it:

```sh
vk dev status
vk dev plan --diff
vk dev refresh --dry-run
vk dev refresh
```

The diff classifies changes as requiring a new session, a host-side step, a
restart or an image rebuild. It compares the resolved plan with the boot record;
it is not a watcher of every file in the build context. Use `refresh` after
changing Dockerfile contents or when you explicitly want a rebuild even though
the configuration still matches.

`refresh` unconditionally rebuilds and restarts without confirmation. The build
runs while the current environment remains available; a failed build leaves it
running. The restart interrupts existing sessions. Durable data follows the
storage rules below.

## Compose services and endpoints

A project can combine a primary development service with database dependencies
and profiled test appliances. Give each appliance its own disk and published
ports, and use a separate environment for pre-commit checks so checking a commit
does not start the whole LAN.

Here is a smaller version of that pattern. Save this as `.virtkit/compose.yaml`;
the example assumes a project Dockerfile with `dev` and `runner` stages:

```yaml
services:
  devcontainer:
    build:
      context: ..
      dockerfile: Dockerfile
      target: dev
    entrypoint: []
    command: sleep infinity
    depends_on:
      - redis
    volumes:
      - ${VK_WORKSPACE}:/workdir
      - ${VK_SELF}:/usr/local/bin/vk:ro
  redis:
    image: docker.io/library/redis:7
  runner:
    build:
      context: ..
      dockerfile: Dockerfile
      target: runner
    profiles:
      - runner
    volumes:
      - ${VK_WORKSPACE}:/workdir:ro
      - ${VK_WORKSPACE}/.virtkit/runner-data.qcow2:/var/lib/runner:disk
```

Select the primary and describe a runner endpoint in `.virtkit/config.toml`:

```toml
schema = 1

[dev]
compose = ".virtkit/compose.yaml"
service = "devcontainer"
workspace = "/workdir"
user = "dev"

[dev.endpoints."runner.https"]
service = "runner"
target = 443
host-port = 8443
address = "auto"
scheme = "https"
path = "/ui"
```

The compose build context is relative to the compose file. Dependencies start
with the primary; profiled services remain on demand unless selected through
`[dev].profiles`. Services resolve each other over the shared LAN by service name
and hostname. The runner image in this example must provide its own server on
port 443; declaring an endpoint does not install or start an application.

```sh
vk dev service status
vk dev service up runner
vk dev endpoints --service runner
vk dev open runner.https
vk dev exec --service runner --user root -- id
vk dev logs --service runner -f
vk dev service reboot runner
vk dev service down runner
```

`service up` brings up the environment if needed and builds the requested service
on first use. `reboot` restarts the guest in place without rebuilding its image.
Other service commands do not boot the environment. Service `exec` requires a
running service and does not inherit the primary's user, workspace directory or
`exec-env`; pass `--user` and `--dir` when needed.

### Endpoint fields

| Field | Meaning |
| --- | --- |
| `target` | Required guest TCP port. |
| `service` | Compose service; omit for the primary. |
| `host-port` | Host port; defaults to `target`. |
| `address` | `auto` (default) for stable loopback allocation, or an explicit address. |
| `scheme`, `path` | URL components for `vk dev open`; `scheme` is required to open a URL. |
| `required` | Default false; when true, readiness requires publication. |
| `enabled` | Default true; false disables the declaration. |

Automatic allocation gives each environment a loopback block and each service
its own address, allowing multiple worktrees to use the same port numbers.
Addresses are retained with environment state. Use an unprivileged host port,
such as 8443 for guest port 443, unless the host permits low-port binding.

`vk dev endpoints` reads existing allocations and publication state without
allocating or booting. `--primary`, `--service NAME` and `--json` filter or format
the output. `vk dev open NAME --print` prints the URL; without `--print`, it uses
`xdg-open` when available and prints otherwise. It does not start the service.

Development egress defaults to unrestricted. `[dev.network] egress = "restricted"`
is currently rejected; it is not an implemented development allowlist.

## Workspace, mounts and storage

`workspace` names the guest path for the host checkout. Normal development
sessions write through to the host files. Linked Git worktrees receive the Git
metadata mapping needed to use the checkout from the guest.

Additional mounts are named entries:

```toml
[dev.mounts.gitconfig]
source = "~/.gitconfig"
to = "/home/dev/.gitconfig"
read-only = true
optional = true

[dev.mounts.package-cache]
source = "${state}/package-cache"
to = "/home/dev/.cache/project"
```

A mount requires `source` and `to`. It is writable by default; `read-only = true`
prevents guest writes through that mount. `optional = true` skips an absent
source. Directories under `${state}` are managed storage, created at boot and
kept across refreshes. Use individual data directories there, not the entire
state directory or its reserved control files.

### Data lifetime

| Storage | Lifetime |
| --- | --- |
| Host checkout and ordinary bind mounts | Host files; guest writes persist independently of VM lifetime. |
| Compose `disk` volume | Durable service data, retained across refreshes until explicitly reset. |
| `${state}` managed directory | Retained across stop/start and refresh; removed with its environment state. |
| Persistent VS Code server | Managed editor data retained across refreshes. |
| Compose persistent root or persistent overlay | Bound to the image generation; recreated when its image changes. |
| Ephemeral task checkout overlay | Writes discarded when the task VM is removed. |

See [Compose volumes](../README.md#volumes-and-persistent-state) for disk and root
configuration. The inventory comes from these declarations; there is no second
storage configuration to maintain.

```sh
vk dev storage list --sizes
vk dev storage list --json
vk dev storage reset 'runner:/var/lib/runner'
```

Use the exact item name printed by `list`. Reset destroys a durable item's data,
with its owner stopped first; `--yes` authorizes stopping and removal without a
prompt. The next start recreates the item empty. Reset refuses image-generation
storage owned by refresh and storage owned by the editor adapter.

### Environment state and cleanup

State is stored under `$XDG_STATE_HOME/virtkit/dev`, falling back to
`~/.local/state/virtkit/dev`. Separate worktrees and environment names have
separate state, SSH identities and endpoint allocations.

```sh
vk dev list
vk dev list --sizes --json
vk dev gc --all-stale
vk dev gc ENVIRONMENT_NAME --yes
```

`list` and `gc` work from anywhere without a project config. Copy names from
`list`; they identify state directories, not just the config's `dev` or `hook`
selector. `gc` refuses running environments. `--all-stale` selects stopped state
whose workspace is gone or which never recorded a boot, including leftovers
from throwaway tasks. It does not mean every stopped development environment.

Without `--yes`, GC asks on a terminal; without a terminal it only lists what
would be removed. GC deletes state directories, including managed data inside
them. It does not delete external disk backings merely because the environment
referenced them. Reset durable external data explicitly before discarding its
configuration if you no longer need it.

## VS Code and SSH

Install a local VS Code-compatible editor and its Remote-SSH extension, then:

```sh
vk dev code
vk dev editor status
vk dev editor log
```

`code` finds `code`, `code-insiders`, `codium`, `vscodium` or `code-oss` on `PATH`,
in that order; `--editor BIN` chooses explicitly. It boots the environment and
opens the workspace over the run's own SSH setup, without modifying your SSH
identities or using your personal keys for the connection.

Under WSL2, a VS Code found under `/mnt/<drive>/` is a Windows one: its Remote-SSH
runs on Windows and reads `%USERPROFILE%\.ssh\config`, which knows nothing of the
distro's setup. For that case `code` also writes `%USERPROFILE%\.ssh\vk\<alias>.conf`,
a host block whose `ProxyCommand` re-enters the distro through `wsl.exe`, next to
`<alias>.key`, a copy of the run's managed key — Windows OpenSSH cannot read a key
at a Linux path. `%USERPROFILE%\.ssh` has to exist already, because the copy inherits
its permissions. The host block is rewritten on every launch and the key refreshed
only when it changed, and `Include vk/*.conf` is added once at the top of
`%USERPROFILE%\.ssh\config`. `vk dev ssh-config --windows` prints the same block
without writing anything. Remote-SSH asks which platform a host it has not seen runs
and waits for the answer before installing its server;
`"remote.SSH.remotePlatform": { "vk-*": "linux" }` in the Windows VS Code user
settings answers it once for every environment, and `code` says so while it is missing.

```toml
[dev.editor.vscode]
state = "persistent"
home = "/home/dev"
extensions = ["rust-lang.rust-analyzer"]
reconcile = ["/workdir/scripts/editor-setup.sh"]

[dev.editor.vscode.settings]
"editor.formatOnSave" = true
```

`state` defaults to `persistent`; `ephemeral` ties editor storage to the
environment generation. `home` defaults to `/root` for root or `/home/<user>`.
For an image or build source, persistent mode supplies managed server storage;
do not also mount the same guest directory. For a compose source, declare the
server mount explicitly:

```toml
[dev.mounts.vscode-server]
source = "${state}/vscode-server"
to = "/home/dev/.vscode-server"
```

After Remote-SSH installs the guest server, a detached reconciliation installs
configured extensions, applies settings while preserving unrelated preferences,
and runs `reconcile` in the guest. Project reconciliation scripts can use
`VK_VSCODE_CLI` to address the installed server CLI. Reconciliation is separate
from VM readiness: check its status and log if the editor opens before extensions
are ready. `vk dev editor retry [--editor BIN]` retries in the foreground; the
environment must be up and the editor connected or connecting.

For other SSH clients and editors:

```sh
vk dev up
vk dev ssh
vk dev ssh -- uname -a
vk dev ssh-config
```

`ssh` does not boot the environment. `ssh-config` prints the run's stanza for an
editor, rsync or an `Include` in your own SSH config. It refers to keys and sockets
in the state directory, so removing that state invalidates it. Use `shell` when
you want an interactive session that also starts the environment.

## Lifecycle hooks

| Hook | Where and when |
| --- | --- |
| `init` | Host workspace, before a build or start attempt. |
| `create` | Guest, once per materialized environment generation. |
| `start` | Guest, each actual boot; not on reuse of a running environment. |

Guest hooks use the configured user, workspace and `exec-env`. `create` runs before
`start`. A successful required `create` is stamped for its generation; a failed
one is not. Recreating an image or its writable storage can create a new generation,
so `create` does not mean once forever for a checkout.

```toml
[dev.hooks]
init = ["./scripts/prepare-host.sh"]
create = { run = ["./scripts/setup.sh"], timeout = "10m" }
start = { run = "./scripts/start-dev.sh", cwd = "/workdir", required = true }
```

A hook may be a shell string, a direct argv array, a table with `run`, `cwd`,
`timeout` and `required`, or a table of named hooks. Named members execute
sequentially in name order, not in parallel. The default working directory is
the workspace. Timeouts accept seconds, `s`, `m` or `h`, for example `90s` or `10m`.
A required failure fails the operation. `required = false` reports the failure
and continues; a best-effort `create` is stamped even if it fails.

There is no attach hook. Put editor setup in `editor.vscode.reconcile` and ordinary
project commands in tasks. Review host `init` commands before running a newly
cloned config: they execute as your host user.

## Project tasks

Tasks declare a command and how it obtains an environment:

```toml
[dev.tasks.test]
run = ["make", "test"]
policy = "require"

[dev.tasks.test.env]
TEST_MODE = "local"
```

```sh
vk dev task test -- VERBOSE=1
```

Arguments after `--` are appended to the task command, and its exit status is
returned to the caller. An argv list avoids shell interpretation; a shell string
is also accepted. Tasks run from the guest workspace, with their `env` added to
the selected environment's `exec-env`.

| `policy` | Placement |
| --- | --- |
| `reuse` | Attach to an already running environment; fail if absent. |
| `require` | Bring up the selected environment first and leave it running. |
| `ephemeral` | Boot a throwaway VM for this command and tear it down afterwards. |
| `reuse-or-ephemeral` (default) | Use a running environment if available, otherwise a throwaway VM. |

`environment` defaults to `dev`. `reuse` may name a different environment for the
two reusing policies, allowing a small standalone fallback when the full
development environment is absent. `checkout` defaults to `shared`, which writes
through to the host checkout.

### Isolated pre-commit checks

For pre-commit checks, use a cached development build if it exists, otherwise
build a smaller checking stage, and discard file normalization performed by the
checks.

```toml
[dev.tasks.pre-commit]
run = ["./scripts/pre-commit"]
environment = "hook"
policy = "ephemeral"
checkout = "overlay"

[environments.hook]
build = { context = ".", dockerfile = "Dockerfile", target = "dev" }
cached-only = true
fallback = { target = "precommit" }
workspace = "/workdir"
user = "dev"

[environments.hook.exec-env]
PRE_COMMIT_ISOLATED = "1"

[environments.hook.mounts.gitconfig]
source = "~/.gitconfig"
to = "/home/dev/.gitconfig"
read-only = true
optional = true
```

The Dockerfile must supply both stages and the script must exist in the project.
A host hook or wrapper can invoke it with:

```sh
vk dev task pre-commit -- "$@"
```

If the same script is the guest task, make its guest path run the checks directly
rather than dispatching itself into `vk dev` again. An environment flag such as
`PRE_COMMIT_ISOLATED` can distinguish that path.

`checkout = "overlay"` requires `policy = "ephemeral"`; configurations that could
attach to a shared running VM are rejected. The checkout gets a tmpfs overlay,
so its writes disappear with the VM. This does not make additional writable host
mounts disposable; declare those separately and read-only where appropriate.
Ephemeral tasks boot no service LAN and publish no endpoints. Use a standalone
image or build environment for them, and `require` when a task needs the normal
service environment.

## Host integration

Host integration is off by default:

```toml
[dev.host]
git-gui = true
```

`git-gui` enables the built-in policy for running `gitk` and `git gui` on the host
against the mapped workspace, with argument and environment filtering.

For other host commands, `wrapper` names a project dispatcher relative to the
workspace and `wrapper-env` lists environment-variable patterns it accepts.
`git-gui` and a custom `wrapper` cannot both be configured; a custom dispatcher
can call `vk host-policy git-gui` itself.

These are explicit host capabilities. A strict config schema does not sandbox a
host hook or custom dispatcher, and a writable host mount lets guest code modify
that data. Keep the shared config's mounts and host commands reviewable.

### SSH agent forwarding

A present `[dev.ssh]` forwards the host SSH agent into the guest and writes a
matching guest `~/.ssh/config`:

```toml
[dev.ssh]
keys = ["work"]

[dev.ssh.host."gitlab.example.com"]
user = "git"
key = "work"
```

Only the agent socket crosses into the guest — no private keys and no `~/.ssh`.
List `keys` (and/or a host's `key`) to restrict which identities the agent offers;
with none listed, the whole agent is forwarded. The whitelist is the union of
`keys` and every host's `key`, and each token is a key comment, a `SHA256:…`
fingerprint (as `ssh-add -l` prints), or a `.pub` path or `~/.ssh` basename.

The generated config sets `IdentityAgent` on `Host *` and on each listed host, so
`git` and `ssh` authenticate in both shell sessions and Remote-SSH / `vk dev ssh`
sessions (where `SSH_AUTH_SOCK` is not set). `IdentityAgent` needs an **OpenSSH**
client in the image; busybox and dropbear ignore it, though exec-session
forwarding through `SSH_AUTH_SOCK` still works with them.

Forwarding needs a running host agent — check with `ssh-add -l` — and takes effect
on the next boot, so run `vk dev refresh` after enabling it.

## Importing a devcontainer

```sh
vk dev init --from devcontainer
vk dev init --from compose
vk dev init --from dockerfile
```

These produce a starting config from the project's existing files. An existing
config is not silently overwritten: `--force` replaces the tracked config while
preserving its local files. Review the import report before using the result.

The importer translates supported sources, session settings, mounts, editor
settings and lifecycle commands. The main hook mapping is:

| Devcontainer field | virtkit field |
| --- | --- |
| `initializeCommand` | `dev.hooks.init` |
| `postCreateCommand` | `dev.hooks.create` |
| `postStartCommand` | `dev.hooks.start` |

Dev Container Features are not installed automatically; bake them into the image
or Dockerfile. Fold `onCreateCommand` and `updateContentCommand` into `create`
as appropriate. Move editor work from `postAttachCommand` to
`editor.vscode.reconcile`. Docker privilege and capability settings do not carry
over as equivalent microVM settings. Review ports as named endpoints and any
reported source/service/stage decisions rather than treating the import as full
devcontainer compatibility.

## Troubleshooting

Start with read-only diagnostics:

```sh
vk dev doctor
vk dev plan --explain
vk dev status --json
vk dev plan --diff
vk dev logs -n 100
```

`doctor` checks version/feature requirements, KVM and the VMM, external tools,
source and mount paths, endpoint ports, state access and referenced host variables.
It exits 1 when a check fails. `plan --format shell` shows the underlying run
shape for inspection, not a complete script to execute.

| Symptom | Next step |
| --- | --- |
| No config found | Run `init` at the checkout root or pass `--workspace DIR`. |
| Unknown key or invalid source combination | Check the error's file location, local overrides and schema; select one source. |
| Missing `${localEnv:NAME}` | Export it, add it to `local.env`, or declare an intentional default. |
| Wrong files or permissions in the guest | Inspect `workspace`, mount paths, the image's user and UID/GID build arguments. |
| Environment is out of date | Inspect `plan --diff`; use `refresh` to rebuild and restart. |
| Upgrade causes guest protocol/image incompatibility | Refresh the environment so its guest components match the current `vk`. |
| Runner endpoint is unpublished | Check `service status`, start the service, then inspect `endpoints` and `doctor`. |
| Editor opens without extensions | Inspect `editor status` and `editor log`, then `editor retry` with the editor connected. |
| Editor stuck on "Copying VS Code Server to host with scp" | Add GNU `wget` or `curl` to the image—BusyBox's `wget` rejects Remote-SSH's flags—then run `refresh`. |
| "The remote host does not meet the prerequisites for running VS Code Server", or extension installs fail with "Signature verification failed with 'ENOENT'" | Nix images lack the loader and libraries VS Code needs. Link the loader at `/lib64/ld-linux-x86-64.so.2`, add `libstdc++.so.6` under `/usr/lib64`, and set `LD_LIBRARY_PATH` in `exec-env`; see this repo's `.devcontainer/Dockerfile` and `.virtkit/config.toml`. |
| Startup hook fails | Read its output and guest logs; fix the command, user or working directory before retrying. |
| Pre-commit overlay is refused | Pair `checkout = "overlay"` with `policy = "ephemeral"`. |
| Disk use keeps growing | Inspect `storage list --sizes` and host-wide `list --sizes`; reset or GC only data you intend to discard. |

Logs remain readable after exit. Filter with `--kernel`, `--agent`, `--guest` or
`--level warn`, and follow with `-f`. Use `--service NAME` for a service console.

## Command reference

All project commands accept `--workspace DIR`, `--dev-config FILE`,
`--environment NAME`, `--freshness POLICY`, `--cache-registry REF|DIR|none` and
`--cache-insecure` as global `vk dev` options. Use `vk dev COMMAND --help` for
individual options.

| Command | Purpose |
| --- | --- |
| `init` | Import or validate a config; `--from`, `--image`, `--force`. |
| `up` | Ensure the environment is ready; `--no-wait`. |
| `exec -- ARG…` | Run a command; `--dir`, `--user`, `--service`, `-t`. |
| `shell` | Boot if needed and open an interactive shell. |
| `code` | Boot if needed and open VS Code; `--editor`. |
| `editor status`, `editor log`, `editor retry` | Follow or retry editor reconciliation without booting. |
| `build` | Build the primary or `--service NAME` into cache. |
| `service up/down/reboot NAME`, `service status [NAME]` | Control compose services. |
| `endpoints` | Show publication state; `--primary`, `--service`, `--json`. |
| `open NAME` | Open an endpoint URL, or `--print` it. |
| `task NAME -- ARG…` | Run a declared project task. |
| `ssh -- ARG…`, `ssh-config` | Connect through or print the run's SSH setup; `--windows` for a Windows client. |
| `refresh` | Rebuild and restart; `--dry-run` only reports changes. |
| `status` | Running state and configuration match; `--json`. |
| `logs` | Read or follow primary/service console output. |
| `doctor` | Check the host and resolved requirements. |
| `plan` | Inspect the resolved config; `--explain`, `--diff`, `--format`, `--show-secrets`. |
| `stop` | Stop the environment and publishers; `--timeout SECONDS`. |
| `storage list`, `storage reset NAME` | Inspect storage or destroy a durable item's data. |
| `list` | Host-wide environment inventory; `--sizes`, `--json`. |
| `gc [NAME…]` | Remove stopped state; `--all-stale`, `--yes`. |
| `schema` | Print the configuration JSON Schema. |
