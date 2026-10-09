//! vk-gitlab: the GitLab-facing side of a runner whose jobs run on a vk fleet.
//!
//! It speaks GitLab's runner API as gitlab-runner v19.5.0 does: runner verification, the job
//! request long poll, job updates, and the incremental job log, forwarded byte for byte.

pub mod api;
pub mod backoff;
pub mod failure;
pub mod job;
pub mod secret;
pub mod system_id;
pub mod trace;
