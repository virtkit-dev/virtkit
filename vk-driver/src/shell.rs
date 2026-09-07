//! Two facts about the host's shell that several modules need: how to write a value as one
//! word it will not reinterpret, and how it finds a program on `PATH`.
//!
//! Both were re-derived at each call site — four spellings of the quoting rule, two of the
//! lookup — and both are the kind of thing that is either exactly right or a bug nobody
//! notices until a path has a space in it.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// A value as one POSIX shell word: single-quoted, with any quote of its own closed,
/// escaped and reopened. Everything is literal inside single quotes, so this is lossless
/// whatever the value contains — and it always quotes, which is what a caller whose output
/// is parsed back (`VAR='…'`) needs.
pub fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// [`quote`], except that a word no shell would treat specially is left as it is: for a
/// command line meant to be read rather than parsed.
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

/// Every `name` on `path` that a shell would run, in `PATH` order, skipping anything in
/// `skip_dir` — compared by filesystem identity, so an alias of that directory is skipped
/// too. Lazy: a caller that wants the first one stops there, and one that needs a path it
/// can also resolve keeps looking.
pub fn which_all(
    name: &str,
    path: Option<&OsStr>,
    skip_dir: Option<&Path>,
) -> impl Iterator<Item = PathBuf> + use<> {
    let name = name.to_string();
    let skip = skip_dir.and_then(|d| std::fs::canonicalize(d).ok());
    std::env::split_paths(path.unwrap_or(OsStr::new("")))
        .collect::<Vec<_>>()
        .into_iter()
        .filter(move |dir| skip.is_none() || std::fs::canonicalize(dir).ok() != skip)
        .map(move |dir| dir.join(&name))
        .filter(|candidate| executable(candidate))
}

/// Whether `path` is a regular file somebody may execute.
pub fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_word_is_quoted_only_where_a_shell_would_read_it_otherwise() {
        assert_eq!(quote_word("plain/path-1.2"), "plain/path-1.2");
        assert_eq!(quote_word("two words"), "'two words'");
        assert_eq!(quote_word(""), "''");
        // Lossless whatever it holds: the quote is closed, escaped and reopened.
        assert_eq!(quote_word("a'b"), "'a'\\''b'");
        // `quote` always quotes, for output that is parsed back.
        assert_eq!(quote("plain"), "'plain'");
        assert_eq!(quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn a_lookup_takes_path_order_and_skips_a_directory_by_identity() {
        use std::os::unix::fs::OpenOptionsExt;
        let root = std::env::temp_dir().join(format!("vk-shell-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
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
        // Not executable: on PATH, and still not what a shell would run.
        std::fs::write(root.join("a/other"), "").unwrap();
        let path = std::env::join_paths([&first, &second]).unwrap();

        let found: Vec<PathBuf> = which_all("tool", Some(&path), None).collect();
        assert_eq!(found, [first.join("tool"), second.join("tool")]);
        assert!(which_all("other", Some(&path), None).next().is_none());
        // The skip is by identity, so a link to the directory is skipped as well.
        let alias = root.join("link-to-a");
        std::os::unix::fs::symlink(&first, &alias).unwrap();
        let found: Vec<PathBuf> = which_all("tool", Some(&path), Some(&alias)).collect();
        assert_eq!(found, [second.join("tool")]);
        let _ = std::fs::remove_dir_all(&root);
    }
}
