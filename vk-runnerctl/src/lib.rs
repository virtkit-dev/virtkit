//! The part of `vk-runnerctl` that needs no privilege: the surgical edit of gitlab-runner's
//! `concurrent` ([`edit`]). A library so unprivileged `vk` can apply the same edit to a
//! runner config its own user owns, with the same proof that nothing else changed — the
//! root binary links exactly this code, and gains no dependency or input by sharing it.

pub mod edit;
