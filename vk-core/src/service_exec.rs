//! Service exec: a guest running commands in its compose services through its host — a CI
//! job VM, a `vk run --compose` primary, a `vk dev` environment. The host turns it on with
//! [`CMDLINE_KEY`] on the guest kernel command line; the guest agent's `exec --service` reads
//! it back.

/// The guest kernel cmdline setting, `=1` when the VM's host serves `vk exec --service` into
/// the VM's services over its host command channel.
pub const CMDLINE_KEY: &str = "VIRTKIT_SERVICE_EXEC";

/// Why a vk guest without [`CMDLINE_KEY`] has no service exec.
pub const NO_SERVICE_EXEC: &str = "this VM has no service exec: its host turned it off \
     (`vk run --no-service-exec`, `[executor] guest_service_exec = false`), opened the host \
     command channel whole (`vk run --host-exec` without a wrapper), booted the image's own \
     init, or gave it no compose services";

/// Whether a [`CMDLINE_KEY`] value turns service exec on: `1`, exactly.
pub fn enabled(value: Option<&str>) -> bool {
    value == Some("1")
}

/// Whether the guest whose kernel command line is `cmdline` has service exec, or `None` when
/// it is not a vk guest: vk boots every guest with `VIRTKIT_*` settings. The last
/// [`CMDLINE_KEY`] wins, as in the agent's reading of the cmdline.
pub fn from_cmdline(cmdline: &str) -> Option<bool> {
    let words = cmdline.split_ascii_whitespace();
    if !words.clone().any(|w| w.starts_with("VIRTKIT_")) {
        return None;
    }
    Some(enabled(
        words
            .filter_map(|w| w.strip_prefix(CMDLINE_KEY)?.strip_prefix('='))
            .next_back(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A vk guest is one booted with `VIRTKIT_*` settings; it has service exec with
    /// `VIRTKIT_SERVICE_EXEC=1` exactly, the last one on the line.
    #[test]
    fn a_vk_guest_has_service_exec_when_its_cmdline_says_so() {
        assert_eq!(
            from_cmdline("BOOT_IMAGE=/vmlinuz root=/dev/sda1 quiet"),
            None
        );
        assert_eq!(from_cmdline(""), None);
        assert_eq!(
            from_cmdline("console=ttyS0 VIRTKIT_VSOCK_PORT=4444\n"),
            Some(false)
        );
        assert_eq!(
            from_cmdline("VIRTKIT_VSOCK_PORT=4444 VIRTKIT_SERVICE_EXEC=1\n"),
            Some(true)
        );
        assert_eq!(from_cmdline("VIRTKIT_SERVICE_EXEC=0"), Some(false));
        assert_eq!(from_cmdline("VIRTKIT_SERVICE_EXEC=10"), Some(false));
        assert_eq!(from_cmdline("VIRTKIT_SERVICE_EXEC"), Some(false));
        assert_eq!(from_cmdline("VIRTKIT_SERVICE_EXECX=1"), Some(false));
        assert_eq!(
            from_cmdline("VIRTKIT_SERVICE_EXEC=1 VIRTKIT_SERVICE_EXEC=0"),
            Some(false)
        );
    }
}
