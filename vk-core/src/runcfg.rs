//! The runtime configuration of an image: what a container runtime would take from
//! the OCI image config (`Env`/`User`/`WorkingDir`/`Entrypoint`/`Cmd`).
//!
//! The builder exports it as a JSON sidecar next to a built ext4 (the image itself
//! stays byte-clean — config is supplied at boot, compose-style, never baked in), and
//! the host hands the merged result (image defaults + per-service overrides) to the
//! guest agent through the boot initramfs.

use serde::{Deserialize, Serialize};

/// Name of the boot-time config entry in the agent initramfs — the agent (as
/// initramfs `/init`) reads it at `/virtkit-service.json` *before* pivoting into the
/// real root (the pivot hides the initramfs).
pub const INITRAMFS_PATH: &str = "virtkit-service.json";

/// Who becomes PID 1 once the preinit hands the guest over, named on the guest kernel
/// cmdline in `VIRTKIT_INIT`. The driver writes the token and the guest agent reads it
/// back, both through this enum, so neither side spells a token of its own — a boot whose
/// axis one of them silently did not recognize is then not expressible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageInit {
    /// The image's own init: `VIRTKIT_HANDOFF` when the host named one, else `/sbin/init`.
    Init,
    /// The image's ENTRYPOINT+CMD, from its [`RunConfig`], exec'd as PID 1.
    Entrypoint,
}

impl ImageInit {
    /// Every axis, so a cmdline token can be resolved back to one. Keep it complete:
    /// [`ImageInit::from_token`] resolves only what is listed here.
    pub const ALL: [ImageInit; 2] = [ImageInit::Init, ImageInit::Entrypoint];

    /// This axis's `VIRTKIT_INIT` token, which is also its `--init` / `x-virtkit.init` value.
    pub fn token(self) -> &'static str {
        match self {
            ImageInit::Init => "image",
            ImageInit::Entrypoint => "entrypoint",
        }
    }

    /// The axis a `VIRTKIT_INIT` token names, or `None` when nothing does.
    pub fn from_token(token: &str) -> Option<ImageInit> {
        ImageInit::ALL.into_iter().find(|i| i.token() == token)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RunConfig {
    /// Environment, in declaration order (later keys override earlier ones).
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// User to run as (name or uid[:gid]); empty = root.
    #[serde(default)]
    pub user: String,
    /// Working directory; empty = `/`.
    #[serde(default)]
    pub workdir: String,
    /// Entrypoint argv (a shell-form ENTRYPOINT is already wrapped as
    /// `["/bin/sh", "-c", …]`).
    #[serde(default)]
    pub entrypoint: Vec<String>,
    /// Default arguments appended to the entrypoint (or the full argv when the
    /// entrypoint is empty).
    #[serde(default)]
    pub cmd: Vec<String>,
    /// TCP ports the image declares via `EXPOSE` (the OCI config's `ExposedPorts`),
    /// deduplicated. A CI `services:` guest gates its readiness on these: it does not
    /// advertise itself as up until each is accepting connections, so the job never
    /// races a still-initializing database. UDP ports are dropped (not probeable this
    /// way); empty = no port gate (readiness is just "the guest booted").
    #[serde(default)]
    pub exposed_ports: Vec<u16>,
}

impl RunConfig {
    /// The effective argv a service runs: entrypoint then cmd (Docker semantics).
    pub fn argv(&self) -> Vec<String> {
        self.entrypoint.iter().chain(&self.cmd).cloned().collect()
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("RunConfig always serializes")
    }

    pub fn from_json(json: &str) -> Result<RunConfig, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_init_round_trips_through_its_cmdline_token() {
        for axis in ImageInit::ALL {
            assert_eq!(ImageInit::from_token(axis.token()), Some(axis));
        }
        assert_eq!(ImageInit::from_token("default"), None);
        assert_eq!(ImageInit::from_token(""), None);
    }

    #[test]
    fn argv_chains_entrypoint_and_cmd() {
        let c = RunConfig {
            entrypoint: vec!["redis-server".into()],
            cmd: vec!["--appendonly".into(), "yes".into()],
            ..Default::default()
        };
        assert_eq!(c.argv(), ["redis-server", "--appendonly", "yes"]);
    }

    #[test]
    fn json_roundtrip_and_missing_fields_default() {
        let c = RunConfig {
            env: vec![("PATH".into(), "/bin".into())],
            user: "app".into(),
            ..Default::default()
        };
        let j = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<RunConfig>(&j).unwrap(), c);
        // forward compat: absent fields default rather than erroring.
        let c: RunConfig = serde_json::from_str(r#"{"user":"app"}"#).unwrap();
        assert_eq!(c.user, "app");
        assert!(c.env.is_empty() && c.argv().is_empty());
    }
}
