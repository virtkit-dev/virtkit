//! `vk dev`: work in the environment a workspace's `.virtkit/config.toml` describes.
//!
//! [`config`] reads that file and the `.virtkit/local.toml` layered over it, [`schema`]
//! publishes its shape as JSON Schema, and [`plan`] resolves the two against this host
//! into the [`Plan`](plan::Plan) every [`cli`] action works from. [`init`] writes a first
//! config by translating what the project already has — a devcontainer.json
//! ([`devcontainer`]), a compose file, a Dockerfile.

pub mod cli;
pub mod config;
pub mod devcontainer;
pub mod init;
pub mod plan;
pub mod schema;
