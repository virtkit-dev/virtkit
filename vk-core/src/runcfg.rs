//! The runtime configuration of an image: what a container runtime would take from
//! the OCI image config (`Env`/`User`/`WorkingDir`/`Entrypoint`/`Cmd`).
//!
//! The builder exports it as a JSON sidecar next to a built ext4 (the image itself
//! stays byte-clean — config is supplied at boot, compose-style, never baked in), and
//! fleet hands the merged result (image defaults + per-service overrides) to the
//! guest agent through the boot initramfs.

use serde::{Deserialize, Serialize};

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
}

impl RunConfig {
    /// The effective argv a service runs: entrypoint then cmd (Docker semantics).
    pub fn argv(&self) -> Vec<String> {
        self.entrypoint.iter().chain(&self.cmd).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
