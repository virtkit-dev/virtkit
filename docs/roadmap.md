# Roadmap: registry isolation, disk images and trust

Status: A1 to A4 and A6a to A6e are built; the rest is proposed. Build order for [the
registry hub design](registry-hub.md) (step 4), [job egress from the
hub](fleet-design.md#job-egress-from-the-hub), [the disk images design](disk-images-design.md)
and [the trust model](trust-model.md). Each milestone is a series of releases, ships on its
own, and is opt-in; together they follow the migration tables of those designs.

Three tracks: **A**, registry isolation and egress, is the critical path; **B**, disk images,
runs beside it; **C**, the trust model, starts once A3 has shipped.

## Track A: registry isolation and egress

| Milestone | Content | For users | Size |
|---|---|---|---|
| A1. Foundations | failure memos keyed by name and pipeline; GitLab instances on the hub, and jobs keys bound to one with ceilings by project ID and path, refusing a bound key's jobs outside them; a subject matcher shared by namespaces and egress rules; `[[gc.prefix]]` retention on the registry | ceilings bound vk-gitlab's claims to a project list; retention by prefix works without a hub | M |
| A2. Token plumbing | the token codec crate; the hub's signing keys, with rotation that waits for registries; the protocol fields (`token_keys`, per-prefix retention, `tokens` in the inventory, the URL bound at enrollment and `set-url`, the node's `[registry]` URL); token checks in the registry, both modes, grants on `/v2/` and `/dav/files/`, no whole-store lookup when mounting for a token; the admin mint (`vk-hub registries token`) and the audit of issued tokens; namespaces store and CLI | nothing yet, behind `[hub] tokens = true` | L |
| A3. Job tokens (4a) | minting at placement, `JobStart`'s field, `guest_credential`, the CI cache in `ci-cache/{gitlab}/{project_id}/{protection}`, end-to-end refusals | guests use job-scoped credentials; CI caches miss once | M |
| A4. In-job access (4b) | the proxy forwarding `/lock/` and `/dav/files/`; lock grants, the pipeline check, locks bounded by the token's lifetime; `VK_REGISTRY` and `VK_REGISTRY_NAMESPACES` | in-job tools take locks; task-rs prefixes its lock names with a namespace | M |
| A5. Pipeline caches (4c) | `vk-pipeline/` cache keys, the `services/` layout, the namespaces page | caches per pipeline | S–M |
| A6a. Egress reports | the node's structured, bounded report per job (denials with their deciding layer, phase and VM, declaration refusals, contacts, coverage) in `JobResult`, build-phase denials and contacts recorded without audit, the reporting capability in the inventory; the Egress page's Blocked tab with triage and mutes, the job list's Network column, the job page's Network access | egress refusals caught and triaged on the hub, before any hub rule | M |
| A6b. Live reports | revisioned snapshots during the job, kept across reconnects; running jobs update | refusals seen while the job runs | S |
| A6c. Observed traffic | usage history per project by phase, protection, ref and day, with coverage; the Observed traffic tab | what each project reaches | M |
| A6d. Hub rules | egress rules (store, CLI, Rules tab with Preview → Save), `JobStart`'s field, the enforcing capability that gates placement, dry-run in both phases, Test a job; Observed traffic compared with the rules, no observed use for rule entries, and for node caps reported versioned | egress by project and ref, and which entries a project does not use | M |
| A6e. Rules from reports | prefilled proposals from Blocked rows, promotion previews, rollout guidance | rules written from evidence | S |

A6a needs no other milestone; A6b to A6e build on it in that order, A6d also on A1's matcher and
A3's `JobStart` field.

## Track B: disk images

| Milestone | Content | Needs |
|---|---|---|
| B0 | the prototype by hand: the oldest ISO, the medium on virtio-blk, the installer hooks | — |
| B1 | vk-agent in disk guests: the agent disk, the launcher, `"agent"` in `vm.json` | — |
| B2 | capture and publication of a stopped disk | B1 |
| B3 | pipeline scope for captures, without a hub first | B2, A1; A5 for the hub |
| B4 | `FROM debiso:` | B1; helper images pinned, to become recipes in C4 |
| B5 | measurements | B2 to B4 |

## Track C: trust model

| Milestone | Content | Size |
|---|---|---|
| C1. Registry prerequisites | the referrers API, gc keeping referrers, the tools packer on ustar | S |
| C2. Root | the root's tooling, `--root` and `--checkpoint`, checkpoints with revocations, reported and not yet enforced | M |
| C3. Bundles | the routine field list, addressing and counters, local ceilings, root-signed sensitive fields, `min_enforcing`; split by config section | L |
| C4. Recipes | the tar format and its extractor, `recipes/` as a ledger, maintainer signatures, grants | M |
| C5. Builders | builder certificates, builds as typed operations, the signed trusted cache, provenance, helper images as recipes | L |
| C6. Registry enforcement | trusted namespaces and tag moves | M |
| C7. Node admission | per-namespace policy, checks before boot and when caching, stale checkpoints, CI tools from builders | M |

C1 deliberately pulls the referrers API and gc keeping referrers ahead of the trust model's
migration step 6, where they belong to registry enforcement.

## Order

A1 to A4 and A6a to A6e are built. B0 and B1 next; then A5 with B2 and B3; C1 and C2 now that A3
has shipped; C3 beside B4; C4 to C7 last.

## Checks before a milestone

| Before | Check |
|---|---|
| A5 | what GitLab sends a child pipeline's jobs about their parent |
| A6d | whether a pipeline's `variables:` override predefined ones such as `CI_PROJECT_PATH`, which decides whether gitlab-runner jobs can ever get per-project egress rules |
| C5 | a pinned cosign version, tested against the DSSE and referrer formats |
