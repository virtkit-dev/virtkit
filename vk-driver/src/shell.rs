//! Writing a value as one POSIX shell word, and finding a program on the host's `PATH`.
//!
//! `quote` is the injection boundary for the guest scripts this crate assembles: its
//! output is interpolated straight into an `sh -c` body.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// A value as one POSIX shell word: single-quoted, with any quote of its own closed,
/// escaped and reopened. Everything is literal inside single quotes — `\` included, which
/// is what makes the idiom total — so this is lossless whatever the value contains. It
/// always quotes, which is what a caller whose output is parsed back (`VAR='…'`) needs.
///
/// The word is for whichever shell reads it; most callers here build a script for the
/// guest's `/bin/sh`.
pub fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Quote an argument for readable POSIX `sh` commands, leaving literal words bare.
/// Use only for arguments: a bare `a=b` in command position is an assignment, whereas
/// [`quote`]'s `'a=b'` is a command name.
pub fn quote_word(value: &str) -> String {
    match !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@%+=:,./-_".contains(c))
    {
        true => value.to_string(),
        false => quote(value),
    }
}

/// Find every executable `name` on `path` in `PATH` order. Skip `skip_dir` and its aliases
/// by filesystem identity. Filesystem checks are lazy: callers can stop at the first
/// match or keep looking for a path they can resolve.
///
/// An empty `PATH` entry means the current directory, as in a shell. `None` searches only
/// the current directory.
pub fn which_all(
    name: &str,
    path: Option<&OsStr>,
    skip_dir: Option<&Path>,
) -> impl Iterator<Item = PathBuf> + use<> {
    let name = name.to_string();
    let skip = skip_dir.and_then(|d| std::fs::canonicalize(d).ok());
    // Collect because `split_paths` borrows `path`, while the returned iterator's
    // `use<>` captures no lifetimes.
    std::env::split_paths(path.unwrap_or(OsStr::new("")))
        .collect::<Vec<_>>()
        .into_iter()
        .filter(move |dir| skip.is_none() || std::fs::canonicalize(dir).ok() != skip)
        .map(move |dir| dir.join(&name))
        .filter(|candidate| executable(candidate))
}

/// Check for a regular file with any execute bit set, regardless of the caller's rights.
/// This distinguishes programs on `PATH` from data files.
pub fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TmpDir(PathBuf);
    impl Drop for TmpDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    fn tmpdir(tag: &str) -> TmpDir {
        let dir = std::env::temp_dir().join(format!("vk-shell-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        TmpDir(dir)
    }

    /// Everything a value might hold that a shell could otherwise reinterpret.
    const HOSTILE: &[&str] = &[
        "",
        "plain",
        "'",
        "a'b",
        "a''b",
        "$(rm -rf /)",
        "`id`",
        "${HOME}",
        "a\"b",
        "a\\b",
        "a\nb",
        "a b",
        "*",
        "?",
        "[a-z]",
        "-x",
        "!x",
        "a|b;c&d",
        "#c",
        "~",
    ];

    #[test]
    fn a_word_is_quoted_only_where_a_shell_would_read_it_otherwise() {
        assert_eq!(quote_word("plain/path-1.2"), "plain/path-1.2");
        assert_eq!(quote_word("two words"), "'two words'");
        assert_eq!(quote_word(""), "''");
        // Lossless whatever it holds: the quote is closed, escaped and reopened.
        assert_eq!(quote_word("a'b"), "'a'\\''b'");
        // `quote` always quotes, for output that is parsed back.
        assert_eq!(quote("plain"), "'plain'");
        // Values without single quotes are wrapped verbatim, including metacharacters.
        assert_eq!(quote("$(rm -rf /)"), "'$(rm -rf /)'");
        // Close the quoted segment, escape the single quote, and reopen the segment.
        assert_eq!(quote("a'b"), "'a'\\''b'");
        assert_eq!(quote("'"), "''\\'''");
        // Empty is still a word, not a dropped argument.
        assert_eq!(quote(""), "''");
    }

    /// Verify with a real shell that `printf %s <quoted>` reproduces the exact bytes.
    #[test]
    fn a_real_shell_parses_a_quoted_value_back_to_itself() {
        for value in HOSTILE {
            let out = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("printf %s {}", quote(value)))
                .output()
                .unwrap();
            assert!(out.status.success(), "sh rejected {value:?}");
            assert_eq!(
                out.stdout,
                value.as_bytes(),
                "{value:?} did not round-trip through sh"
            );
        }
    }

    /// One word, whatever it holds: a quoted value never splits into two arguments.
    #[test]
    fn a_quoted_value_stays_one_argument() {
        for value in HOSTILE {
            let out = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("set -- {}; echo $#", quote(value)))
                .output()
                .unwrap();
            assert_eq!(
                String::from_utf8_lossy(&out.stdout).trim(),
                "1",
                "{value:?}"
            );
        }
    }

    /// Words the allowlist leaves bare.
    const BARE: &[&str] = &[
        "plain",
        "-x",
        "+x",
        "a=b",
        "%1",
        "..",
        "//",
        "./x",
        "@%+=:,./-_",
        "a,b",
        "a@b",
    ];

    /// The allowlist is only sound if a real shell reads each bare word as itself.
    #[test]
    fn a_bare_word_survives_a_real_shell_as_one_argument() {
        for value in HOSTILE.iter().chain(BARE) {
            let out = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!(
                    "set -- {}; printf '%s|%s' \"$#\" \"$1\"",
                    quote_word(value)
                ))
                .output()
                .unwrap();
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                format!("1|{value}"),
                "{value:?} did not survive sh as one word"
            );
        }
        // What stays bare is the allowlist; everything else falls back to `quote`.
        for value in BARE {
            assert_eq!(&quote_word(value), value);
        }
        for value in HOSTILE.iter().filter(|v| !BARE.contains(v)) {
            assert!(quote_word(value).starts_with('\''), "{value:?} stayed bare");
        }
    }

    #[test]
    fn a_lookup_takes_path_order_and_skips_a_directory_by_identity() {
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = tmpdir("lookup");
        let root = &tmp.0;
        let (first, second) = (root.join("a"), root.join("b"));
        for dir in [&first, &second] {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o755)
                .open(dir.join("tool"))
                .unwrap();
        }
        // On PATH, and with no execute bit for anyone.
        std::fs::write(first.join("other"), "").unwrap();
        // A directory of that name is not a program either.
        std::fs::create_dir_all(first.join("adir")).unwrap();
        let path = std::env::join_paths([&first, &second]).unwrap();

        let found: Vec<PathBuf> = which_all("tool", Some(&path), None).collect();
        assert_eq!(found, [first.join("tool"), second.join("tool")]);
        assert!(which_all("other", Some(&path), None).next().is_none());
        assert!(which_all("adir", Some(&path), None).next().is_none());
        // The skip is by identity, so a link to the directory is skipped as well.
        let alias = root.join("link-to-a");
        std::os::unix::fs::symlink(&first, &alias).unwrap();
        let found: Vec<PathBuf> = which_all("tool", Some(&path), Some(&alias)).collect();
        assert_eq!(found, [second.join("tool")]);
    }
}
