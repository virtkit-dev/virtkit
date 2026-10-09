//! vk-gitlab: the GitLab-facing side of a runner whose jobs run on a vk fleet.
//!
//! It speaks GitLab's runner API as gitlab-runner v19.5.0 does — job requests, job updates,
//! the incremental job log — and hands each job to a [`dispatch::Dispatcher`], from whose
//! events it reports the job's log and final state. The fleet node masks and caps the log
//! and transfers artifacts; vk-gitlab forwards the log byte for byte.

pub mod api;
pub mod backoff;
pub mod config;
pub mod dispatch;
pub mod failure;
pub mod job;
pub mod logging;
pub mod poll;
pub mod secret;
pub mod system_id;
pub mod trace;
