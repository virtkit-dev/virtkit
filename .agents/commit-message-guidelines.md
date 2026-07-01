# Commit Message Guidelines

These rules describe how commits in this repository are structured. They apply to
humans and AI assistants alike.

## Granularity

Decide commit boundaries before writing the message. Each commit should be:

- Small and focused on a single concern.
- Free of mixed change types — split refactor + feature, or rename + logic change, into separate commits.
- Independently buildable and deployable; the tree should be green at every commit.

Tests for a feature belong in the same commit as the feature itself; do not split them off.
The same goes for the changelog: a commit with a user-visible change updates
`CHANGELOG.md` in that commit (see [Changelog](#changelog) below).

## Format

```
<scope>: <imperative summary>

[optional body, wrapped at ~72 columns]
```

A single-line summary (no trailing period) is enough for most commits. Add a body only
when the diff does not speak for itself — keep it to a short paragraph or a few bullets
(~5 lines). The scope prefix is optional when a change is genuinely repo-wide.

Examples (from this repo's history):

```
ci: add GitHub Actions release, CI and shared quality workflows
build-kernel.sh: write a reproducible kernel build manifest
audit: ignore three warning-level advisories locked by virtiofsd
add update-kernel.sh to bump the pinned guest kernel
apply cargo fmt across the workspace
```

## Summary line rules

1. Imperative mood, present tense ("add", "fix", "update", "remove").
2. ≤ 72 characters preferred (hard cap 80). Shorten if longer.
3. No trailing period; lowercase unless it starts with a proper noun.
4. Avoid vague verbs: "remove dead code", not "cleanup"; "refactor X to Y", not "refactor".
5. Security fixes: reference the advisory ID in parentheses, e.g. `(due to RUSTSEC-2025-0047)`.

## Scope

Pick one lowercase scope matching the component touched. Common scopes here:

- `vk-driver`, `vk-agent` — the two crates (use a module subscope for precision, e.g. `vk-driver/net:`).
- `kernel` — the guest kernel config / build.
- `ci` — GitHub Actions or GitLab CI.
- A script's basename when the change is to that script, e.g. `build.sh:`, `build-kernel.sh:`, `update-kernel.sh:`.
- `doc` — documentation. `tests` — test-only changes. `rust` — cross-cutting language/toolchain or dependency updates.

For a change spanning two or three components, list them comma-separated
(`build.sh, build-kernel.sh: …`); for more, use `all:` or pick the dominant scope.

## When to add a body

Add a body if any apply: a non-trivial behavior change or refactor; a subtle bug whose
root cause isn't obvious from the diff (note the failure mode and how the fix addresses
it); a performance fix where the measurement matters; a security fix (note risk/impact);
or a decision involving trade-offs a reviewer needs to understand.

Body content rules:

- **Self-contained.** A reader must understand the change without following links.
- **Faithful to the diff.** Every behavior or mechanism described must be verifiable in the actual changes; do not reference code that isn't there.
- **High-level.** Explain *what* changed and *why*. Do not dive into technical
  detail unless it is strictly necessary to understand the change — fine-grained
  mechanics (algorithm choice, data-structure invariants, line-level rationale)
  belong in code comments next to the code, not the commit body. If the body
  reads like a file-by-file walkthrough of the diff, it is too detailed.

When in doubt, ship the shorter message.

## Changelog

A commit that changes user-visible behavior — a feature, a fix, a change in how
`vk` is invoked or behaves — must update `CHANGELOG.md` under `[Unreleased]` in
the same commit. Purely internal changes (refactors, tests, CI, build tooling,
docs) do not get an entry.

Changelog entries are pitched one level higher than the commit message: describe
what a user gains or what now behaves differently, in their terms. No internal
mechanisms, module or crate names, or implementation detail — if a sentence only
makes sense to someone reading the source, it belongs in the commit message or a
code comment, not the changelog.

## Diff → verb cues

| Change pattern | Verb |
|----------------|------|
| Added file(s) / capability | `add` |
| Removed file / code | `remove` / `drop` |
| Modified logic path | `update` / `adjust` |
| Fixing a bug | `fix` |
| Performance work | `optimize` / `speed up` |
| Behavior-preserving restructure | `refactor` |
| Dependency / toolchain version | `bump` / `upgrade` |
| Tests only | `tests:` scope |
| Docs only | `doc:` scope |

## Don't

- No "WIP" / "work in progress" commits on shared branches.
- No redundant phrasing: "fix", not "fix bug in"; drop "update code".
- No `Co-Authored-By` or `Signed-off-by` trailers, and no AI-assistant attribution.
- Do not write a message for an empty, whitespace-only, or lockfile-only-with-no-source diff — there is nothing to commit.
