# Releasing

A release is cut by CI from the `release` branch. Nobody pushes a tag or `main` by hand,
so a tag is never moved: a candidate that fails is fixed and pushed again, and the tag
only ever appears once the pipeline has passed.

## Prerequisites

The pipeline pushes `main` and the tag with the workflow's own token, so `github-actions[bot]`
has to be allowed to: `main` must carry no branch protection or ruleset the bot cannot
bypass, and no tag protection rule may match `v*`. A rule that refuses it fails the publish
after the whole pipeline has run.

## Cut a release

1. On top of the commits to ship (rebased onto `main`), add the release commit:
   `all: release X.Y.Z` — bump `version` in `Cargo.toml` (and `Cargo.lock` with it), and
   turn the CHANGELOG's `## [Unreleased]` section into `## [X.Y.Z] - YYYY-MM-DD` with a
   fresh empty `## [Unreleased]` above it, and add the matching `[X.Y.Z]: …compare/…` link
   definition beside the others at the end of the file.
2. Push it to the integration branch:

   ```sh
   git push -f origin HEAD:release
   ```

   `-f` is fine here — `release` is a scratch ref; only its pipeline's writes matter.
3. Watch the `Release` workflow. When it passes, `main` has been fast-forwarded to the
   candidate, `vX.Y.Z` points at it, and the GitHub release carries the binaries with
   the CHANGELOG section as its notes.

If it fails, fix the candidate, rebase, push to `release` again. The newest push wins: a
pipeline still running for the previous push is cancelled — including one inside publish's
writes, which then needs **Re-run failed jobs** on the cancelled run to finish (below). Do
that first: a new push to `release` cancels the re-run in turn.

## What the pipeline checks

In `release.yml`, prepare runs first, then quality and build run in parallel.
e2e follows both, and publish waits on all of them:

- **prepare** (seconds): the tag `v<Cargo.toml version>` does not exist yet, the
  CHANGELOG has a dated `## [X.Y.Z]` section and it is not empty, and `origin/main` is an
  ancestor of the candidate. A stale or unbumped candidate fails here, before anything
  compiles.
- **quality**: rustfmt, clippy, the test suite, cargo-audit — the same jobs CI runs.
- **build**: the kernel and the binaries, as `build.sh --bootstrap-check`, so the released
  bytes are reproduced from scratch in a vk microVM before they are accepted.
- **e2e**: `tests/release-e2e.sh` on the built `vk` — the sha256 sidecars of every binary,
  the version against the tag, `vk check`, a plain boot, then every end-to-end script in
  `tests/`.
- **publish**: refuses if `main` moved since prepare; then fast-forwards `main`, pushes
  the tag, creates the release. Each step is idempotent, so a publish that failed half-way
  (a GitHub hiccup) is finished with **Re-run failed jobs** on that run — *not* "Re-run all
  jobs", which re-runs prepare and fails on the tag it just pushed. The artifacts it
  publishes are kept for a day, so a run left unfinished longer than that has to be pushed
  to `release` again — unless its tag was already pushed, which prepare now refuses: finish
  that one by hand with `gh release create vX.Y.Z …` from a local `./build.sh` build.

The pushes are made with the workflow's own token, which triggers no other workflow:
`main` gets no second CI run for a sha that just passed the same checks, and the tag
push cannot re-trigger a release.
