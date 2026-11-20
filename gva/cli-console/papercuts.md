# Papercuts

- `vk stop` already stops a VM's publishers (`vms::stop_one` → `publish::stop_all_quietly`).
- `vk publish --via` already has `--service` as a visible alias.
- Unit tests must not touch real XDG dirs: use the `*_in(base)` variants (as `vms::record_in`).
- In this sandbox `~/.local/state` and `~/.rustup` are read-only: `./dev.sh` loops forever on
  `mkdir -p $STATE_DIR` (its `lock_state_dir` retries on any failure), and the pinned toolchain
  (1.100.0) cannot be installed. Workaround: the host toolchain with the repo's cargo home, its
  own target dir, and the glibc target (`.cargo/config.toml` defaults to musl, whose cross gcc
  the host lacks). Fetch once (`cargo fetch`: the cache lacked crates the lockfile pins), then
  build offline:
  `CARGO_HOME=$PWD/target/.cargo-home RUSTUP_TOOLCHAIN=1.99.1-x86_64-unknown-linux-gnu CARGO_TARGET_DIR=$PWD/target/host cargo test --offline --target x86_64-unknown-linux-gnu -p vk-driver --bin vk …`
- Baseline: 12 `vk-driver` unit tests fail in this sandbox on the untouched tree too: the 9
  `vm::tests::*share_root*`, 2 `check::tests` (share root, gitlab tools dir) and
  `node::tools::tests::the_managed_tools_dir_resolves_as_a_job_would_and_counts_as_in_use`.
  The cause is `/`, owned by `nobody:nogroup` here (the user namespace leaves real root
  unmapped): the path walk that guards share roots and tools dirs refuses any directory another
  user could write — `refusing to walk through /tmp: / lets other users replace it` — and these
  tests build their fixtures under `/tmp`. Expected behaviour, not a bug; compare against a
  baseline list rather than expecting a clean run.
- The wrapper script must put `--offline --target …` right after the cargo subcommand: after
  `--` they reach the test binary instead.
- `vk`'s help test (`tests::help_summaries_stay_short`) caps each arg's first paragraph at 84
  columns.
- No `/dev/kvm` in this sandbox: a smoke test reaches the boot and stops there. Point
  `XDG_STATE_HOME`/`XDG_DATA_HOME` at /tmp to exercise names, list, rename, stop and rm on
  fake state dirs (a `dev.json`, a `.virtkit-last.json`).
- `cargo fmt` with the host toolchain only reformatted files this branch touched.
