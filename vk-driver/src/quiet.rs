//! `vk run --quiet` suppresses status notes process-wide, from image pull through build,
//! boot and teardown. Guest output, warnings and errors still print, as do the `--ssh`
//! command, `--audit-egress` summary and `--detach` PID. A failed build prints its log tail.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

static QUIET: AtomicBool = AtomicBool::new(false);

/// [`crate::vmm`] sets this only on the VMM boot child. A `--host-exec` command that runs
/// `vk` uses its own quiet setting.
pub(crate) const ENV: &str = "VIRTKIT_QUIET";

/// Silence this process's status notes from here on.
pub(crate) fn set() {
    QUIET.store(true, Ordering::Relaxed);
}

/// Take the setting the parent `vk` passed this VMM boot child, if any.
pub(crate) fn inherit() {
    if std::env::var_os(ENV).is_some() {
        QUIET.store(true, Ordering::Relaxed);
    }
}

/// Whether status notes are silenced.
pub(crate) fn on() -> bool {
    QUIET.load(Ordering::Relaxed)
}

/// `println!` a status note, unless silenced.
macro_rules! note {
    ($($arg:tt)*) => {
        if !$crate::quiet::on() {
            println!($($arg)*);
        }
    };
}

/// `eprintln!` a status note, unless silenced.
macro_rules! enote {
    ($($arg:tt)*) => {
        if !$crate::quiet::on() {
            eprintln!($($arg)*);
        }
    };
}

pub(crate) use {enote, note};

/// Maximum number of recent build log lines to print on failure.
const HELD_LINES: usize = 1000;

/// A quiet build's progress log, buffered until failure.
#[derive(Clone, Default)]
pub(crate) struct Held(Arc<Mutex<VecDeque<String>>>);

impl Held {
    /// The progress sink that holds each line, dropping the oldest past [`HELD_LINES`].
    pub(crate) fn sink(&self) -> crate::build::ProgressSink {
        let lines = Arc::clone(&self.0);
        Arc::new(move |line: &str| {
            let mut lines = lines.lock().unwrap();
            if lines.len() == HELD_LINES {
                lines.pop_front();
            }
            lines.push_back(line.to_string());
        })
    }

    /// Print what was held, to stderr.
    pub(crate) fn dump(&self) {
        let lines = std::mem::take(&mut *self.0.lock().unwrap());
        for line in lines {
            eprintln!("{line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn held_keeps_the_end_of_the_log() {
        let held = Held::default();
        let sink = held.sink();
        for i in 0..HELD_LINES + 5 {
            sink(&format!("#{i}"));
        }
        let lines = held.0.lock().unwrap();
        assert_eq!(lines.len(), HELD_LINES);
        assert_eq!(lines.front().map(String::as_str), Some("#5"));
        assert_eq!(
            lines.back().map(String::as_str),
            Some(format!("#{}", HELD_LINES + 4).as_str())
        );
    }
}
