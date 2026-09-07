//! `vk dev`: work in the environment a workspace's `.virtkit/config.toml` describes.
//!
//! [`config`] reads that file and the `.virtkit/local.toml` layered over it, [`schema`]
//! publishes its shape as JSON Schema, and [`plan`] resolves the two against this host
//! into the [`Plan`](plan::Plan) every [`cli`] action works from.

pub mod cli;
pub mod config;
pub mod plan;
pub mod schema;
