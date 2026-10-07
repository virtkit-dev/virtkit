# GitLab end to end

`tests/gitlab-e2e.sh` tests `vk-gitlab` against a real GitLab CE and fleet on one host:
GitLab in a vk microVM, then `vk-hub` (TLS, with a CA made for the run), a
`vk-registry` for caches, one `vk node run` enrolled in pool `e2e` with label `e2e`, and
`vk-gitlab run`. Each scenario pushes a branch with its own `.gitlab-ci.yml` and checks the
outcome through GitLab's API.

It is not part of the release gate: `tests/release-e2e.sh` lists it as not run unless
`E2E_GITLAB=1` is set or the script is named on its command line.

```bash
./build.sh --fast                                 # dist/vk, vk-hub, vk-registry, vk-gitlab
tests/gitlab-e2e.sh                               # every scenario
tests/gitlab-e2e.sh --scenario cache,cancel --keep
tests/gitlab-e2e.sh --stop-gitlab                 # stop a GitLab left up by --keep
```

- **Binaries.** The node runs `--vk` (default `$VK`, else `dist/vk`); `vk-hub`,
  `vk-registry` and `vk-gitlab` default to the ones beside it, and `--vk-hub`,
  `--vk-registry` and `--vk-gitlab` override each. Without a `vk-registry` the `cache`
  scenario is skipped. GitLab boots with the `vk` on `PATH`, else `--vk` (`--vk-boot`).
- **Scenarios.** `basic`, `scripts` (before/after_script), `variables` (masked, file),
  `exit_codes` (`allow_failure: exit_codes`), `artifacts` (upload, exclude, dependency
  download), `cache` (miss then hit across two pipelines), `services`, `timeout`, `cancel`,
  `restart` (vk-gitlab killed with SIGKILL mid-job, then resumed). All but `restart` run
  concurrently; `restart` runs alone after them.
- **GitLab.** `gitlab/gitlab-ce`, pinned by digest in `tests/gitlab/images.env` (which says
  how to bump it), boots with its own `/assets/init-container` as the command of a detached
  `vk run` under vk-agent. Its three volumes are `:disk` qcow2 files under
  `~/.cache/vk-gitlab-e2e/gitlab-<digest>/` (`VK_GITLAB_E2E_CACHE`), where the instance — root
  token, project, variables — is kept across runs; `--reset-gitlab` discards it. GitLab
  listens on the host's own address, since the job VMs' egress refuses loopback, on a port
  chosen once per instance; `GL_HOST` overrides the address.
- **Timings.** About 11 minutes cold (GitLab up and seeded in 5–6, image conversion
  included), 9 from the cached instance (GitLab in 3–4: vk rebuilds the boot rootfs, then
  `gitlab-ctl reconfigure` runs), and 5 against a GitLab still up from `--keep`, which is
  reused at once. `GL_BOOT_TIMEOUT` (1500 s) bounds GitLab's boot.
- **Resources.** KVM; `curl`, `jq`, `git`, `openssl`, `ss`, `ip`, `shuf`; access to Docker
  Hub. About 9 GiB of free memory — GitLab's VM 6 GiB (`GL_MEM`, with `GL_CPUS` 4), each job
  VM 1 GiB, up to four at once — and 15 GiB of disk for the GitLab image and its state.
- **Evidence.** Everything lands in `target/e2e/<timestamp>/` (`--run-dir`, which must be
  absent or empty): `logs/` (GitLab console, hub, node, registry, vk-gitlab at debug level,
  one log per scenario), `jobs/` (each job's JSON and trace), and the components' configs.
  The run prints a result table and exits non-zero when a scenario fails.
