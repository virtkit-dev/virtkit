//! `vk-agent build`: a guest building an image from a context it sends its host over the host
//! command channel, as `vk build …` with a tar on stdin. The tar holds two names at its root:
//! [`CONTEXT`], the build context, and [`DOCKERFILE`], the Dockerfile, kept apart so a
//! Dockerfile from outside the context never lands in it.

/// The tar directory holding the build context. The host makes it itself, so the tar names
/// only what is below it.
pub const CONTEXT: &str = "context";

/// The tar entry holding the Dockerfile: a regular file, beside [`CONTEXT`].
pub const DOCKERFILE: &str = "Dockerfile";

/// The guest kernel cmdline setting, `=1` when the VM's host serves `vk-agent build` over its
/// host command channel.
pub const CMDLINE_KEY: &str = "VIRTKIT_GUEST_BUILD";
