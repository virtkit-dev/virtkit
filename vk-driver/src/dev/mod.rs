//! `vk dev`: work in the environment a workspace's `.virtkit/config.toml` describes.
//!
//! [`config`] is that file — how it is found, how `.virtkit/local.toml` layers over it, and
//! what each key means, every one of them checked — and [`schema`] publishes the same shape
//! as JSON Schema, for an editor or a project that vendors its own copy. [`plan`] resolves
//! the two against this host into the [`Plan`](plan::Plan) every `vk dev` command works from.

pub mod cli;
pub mod config;
pub mod plan;
pub mod schema;
