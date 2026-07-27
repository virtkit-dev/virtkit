//! The surgical edit of gitlab-runner's `config.toml`: set the top-level `concurrent` and
//! leave every other line byte for byte as it was. Only the matched line is rewritten, and
//! then only its value — its indentation and trailing comment come through unchanged, though
//! the spacing around the `=` is normalised.
//!
//! Parsing the file and serializing it back would be shorter and is not an option — the
//! file is written and maintained by an operator, and a round trip loses their comments,
//! key order and formatting from a file that also holds registration tokens. So the edit
//! is done on the text, and the parse is used the other way round: to *check* the result,
//! by proving that the document changed at exactly one key ([`verify`]).

use anyhow::{Result, bail};

/// Set the top-level `concurrent` key in `text` to `value`, returning the new text.
///
/// Only a key before the first table header counts: a `concurrent` inside a `[[runners]]`
/// block is a different setting (a per-registration one virtkit does not touch), and a
/// substring of some other key is not a key at all. An absent key is inserted ahead of the
/// first table, where a hand-written config carries it. Two top-level `concurrent` keys are
/// a config gitlab-runner itself would read ambiguously: refuse rather than pick one.
pub fn set_concurrent(text: &str, value: u32) -> Result<String> {
    let mut out = String::with_capacity(text.len() + 24);
    let mut top_level = true;
    let mut edited = false;
    let mut insert_before: Option<usize> = None;

    for line in text.split_inclusive('\n') {
        let (body, eol) = split_eol(line);
        let trimmed = body.trim_start();
        if top_level && trimmed.starts_with('[') {
            // The first table header ends the top-level section; note where to insert if the
            // key turns out to be absent.
            top_level = false;
            insert_before.get_or_insert(out.len());
        }
        match top_level.then(|| concurrent_value(body)).flatten() {
            Some(comment) => {
                if edited {
                    bail!("two top-level `concurrent` keys — refusing to guess which one counts");
                }
                edited = true;
                let indent = &body[..body.len() - trimmed.len()];
                out.push_str(&format!("{indent}concurrent = {value}{comment}{eol}"));
            }
            None => out.push_str(line),
        }
    }
    if !edited {
        // No key to replace: put one where the file's own top-level keys live, before the
        // first table (or at the end of a file that has none). Appending to a file whose last
        // line has no ending needs one added first, or the two assignments splice into one.
        let at = match insert_before {
            Some(at) => at,
            None => {
                if !out.is_empty() && !out.ends_with('\n') {
                    out.push('\n');
                }
                out.len()
            }
        };
        out.insert_str(at, &format!("concurrent = {value}\n"));
    }
    Ok(out)
}

/// The trailing comment of `body` when it is a `concurrent = <integer>` assignment, else
/// `None`. The comment is kept so an operator's note survives the rewrite.
fn concurrent_value(body: &str) -> Option<&str> {
    let rest = body.trim_start().strip_prefix("concurrent")?;
    let rest = rest.trim_start().strip_prefix('=')?.trim_start();
    let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    if digits == 0 {
        return None; // `concurrent` set to something that is not a plain integer
    }
    let after = &rest[digits..];
    match after.trim_start() {
        "" => Some(""),                               // nothing but the value
        rest if rest.starts_with('#') => Some(after), // the gap and the comment, kept
        _ => None,                                    // trailing junk: not an assignment
    }
}

/// Split a line into its content and its line ending, so a rewritten line keeps the file's
/// own endings (a CRLF config stays CRLF).
fn split_eol(line: &str) -> (&str, &str) {
    let body = line.trim_end_matches('\n');
    let body = body.trim_end_matches('\r');
    (body, &line[body.len()..])
}

/// Prove that `after` is `before` with `concurrent` set to `value` and nothing else touched:
/// both parse, the key reads back, and the two documents are equal once it is removed.
///
/// This is what makes a text edit safe to run as root against someone's runner config — a
/// mistake in [`set_concurrent`] becomes a refusal rather than a mangled file.
pub fn verify(before: &str, after: &str, value: u32) -> Result<()> {
    // The message and the offset, never the offending line. A TOML error's own `Display`
    // quotes the source it failed on, and this file holds the runner's registration token —
    // while whoever reads this program's stderr may be exactly who is not allowed to read it.
    let quoteless = |what: &str, e: toml::de::Error| {
        anyhow::anyhow!("{what} at {:?}: {}", e.span(), e.message())
    };
    let mut old: toml::Table = before
        .parse()
        .map_err(|e| quoteless("the runner config does not parse", e))?;
    let mut new: toml::Table = after
        .parse()
        .map_err(|e| quoteless("the edit would not parse", e))?;
    if new.get("concurrent").and_then(|v| v.as_integer()) != Some(i64::from(value)) {
        bail!("the edit did not set concurrent = {value}");
    }
    old.remove("concurrent");
    new.remove("concurrent");
    if old != new {
        bail!("the edit changed more than `concurrent` — refusing to install it");
    }
    Ok(())
}

/// The current top-level `concurrent`, or `None` when the config has none (gitlab-runner
/// then defaults to 1, but say nothing rather than guess its version's default).
pub fn current_concurrent(text: &str) -> Option<u32> {
    let table: toml::Table = text.parse().ok()?;
    table.get("concurrent")?.as_integer()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config in the shape operators actually keep them: comments, a token, several
    /// registrations, and a `limit` that must survive untouched.
    const CONFIG: &str = "\
# managed by ansible — do not edit\n\
concurrent = 4   # host capacity\n\
check_interval = 3\n\
\n\
[session_server]\n\
  session_timeout = 1800\n\
\n\
[[runners]]\n\
  name = \"vk-small\"\n\
  token = \"glrt-SECRET\"\n\
  limit = 6\n\
  [runners.custom]\n\
    run_exec = \"/usr/local/bin/vk\"\n\
";

    #[test]
    fn sets_the_key_and_leaves_everything_else_byte_identical() {
        let out = set_concurrent(CONFIG, 7).unwrap();
        verify(CONFIG, &out, 7).unwrap();
        assert!(out.contains("concurrent = 7   # host capacity"), "{out}");
        // Every other line survives exactly, comments and secret included.
        for line in CONFIG.lines().filter(|l| !l.contains("concurrent")) {
            assert!(out.contains(line), "lost line {line:?}");
        }
        assert_eq!(current_concurrent(&out), Some(7));
    }

    /// The per-registration `limit` shares nothing with the top-level key but its purpose:
    /// a `concurrent` inside a table must not be mistaken for the one we set.
    #[test]
    fn ignores_a_concurrent_inside_a_table() {
        let cfg = "[[runners]]\n  name = \"a\"\n  concurrent = 2\n";
        let out = set_concurrent(cfg, 9).unwrap();
        assert!(out.starts_with("concurrent = 9\n"), "{out}");
        assert!(out.contains("  concurrent = 2\n"), "{out}");
        // The inserted key is top level and the table's own is untouched.
        let table: toml::Table = out.parse().unwrap();
        assert_eq!(table["concurrent"].as_integer(), Some(9));
    }

    /// A file whose last line has no ending must not have the key appended onto it — that
    /// would splice two assignments into one and produce something that does not parse.
    #[test]
    fn inserts_after_a_missing_final_newline() {
        let edited = set_concurrent("check_interval = 3", 5).unwrap();
        assert_eq!(edited, "check_interval = 3\nconcurrent = 5\n");
        verify("check_interval = 3", &edited, 5).unwrap();
        // An empty file is not a missing newline: nothing to separate from.
        assert_eq!(set_concurrent("", 5).unwrap(), "concurrent = 5\n");
    }

    #[test]
    fn inserts_the_key_where_a_config_without_one_would_carry_it() {
        let out = set_concurrent("check_interval = 3\n\n[[runners]]\n  name = \"a\"\n", 5).unwrap();
        assert_eq!(
            out,
            "check_interval = 3\n\nconcurrent = 5\n[[runners]]\n  name = \"a\"\n"
        );
        // A file with no tables at all still gets one.
        assert_eq!(set_concurrent("", 2).unwrap(), "concurrent = 2\n");
    }

    #[test]
    fn keeps_the_file_endings_it_was_given() {
        let out = set_concurrent("concurrent = 1\r\n[[runners]]\r\n", 3).unwrap();
        assert_eq!(out, "concurrent = 3\r\n[[runners]]\r\n");
    }

    #[test]
    fn refuses_what_it_cannot_read_unambiguously() {
        // Two top-level keys: gitlab-runner would read one of them, and guessing which is
        // how a tool silently sets the wrong thing.
        let twice = "concurrent = 1\nconcurrent = 2\n";
        assert!(set_concurrent(twice, 5).is_err());

        // A key whose value is not a plain integer is left alone, so the insert path runs
        // and the result no longer parses — caught by verify rather than installed.
        let odd = "concurrent = \"4\"\n";
        let out = set_concurrent(odd, 5).unwrap();
        assert!(verify(odd, &out, 5).is_err(), "{out}");
    }

    /// verify is the backstop for the editor: a rewrite that touched anything else must not
    /// be installable, however it came about.
    #[test]
    fn verify_rejects_an_edit_that_changed_anything_else() {
        let sneaky = CONFIG.replace("glrt-SECRET", "glrt-STOLEN");
        let sneaky = set_concurrent(&sneaky, 7).unwrap();
        let err = verify(CONFIG, &sneaky, 7).unwrap_err().to_string();
        assert!(err.contains("more than `concurrent`"), "{err}");

        // And a value that did not land is caught too.
        let unchanged = set_concurrent(CONFIG, 4).unwrap();
        assert!(verify(CONFIG, &unchanged, 7).is_err());
    }

    /// A parse failure is reported to whoever invoked this program — which, under the sudoers
    /// form, is the unprivileged runner user. It must say where the file is wrong without
    /// quoting the line, since that line may be the one holding the registration token.
    #[test]
    fn a_parse_failure_does_not_quote_the_config() {
        // An unterminated string on the token line: the offending line *is* the secret.
        let broken = CONFIG.replace("\"glrt-SECRET\"", "\"glrt-SECRET");
        let err = verify(&broken, &broken, 4).unwrap_err().to_string();
        assert!(err.contains("does not parse"), "{err}");
        assert!(
            !err.contains("glrt-SECRET"),
            "the error quoted the token: {err}"
        );

        // The same for the edited side, which is derived from the same file.
        let err = verify(CONFIG, &broken, 4).unwrap_err().to_string();
        assert!(
            !err.contains("glrt-SECRET"),
            "the error quoted the token: {err}"
        );
    }

    #[test]
    fn reads_the_current_value() {
        assert_eq!(current_concurrent(CONFIG), Some(4));
        assert_eq!(current_concurrent("[[runners]]\n"), None);
        assert_eq!(current_concurrent("not = = toml"), None);
    }
}
