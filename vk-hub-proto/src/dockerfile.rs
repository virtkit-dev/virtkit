//! Dockerfile instruction lines for `vk build` and the hub's egress reader.
//! Both follow BuildKit's `frontend/dockerfile/parser` `Parse` rules for directives,
//! comments and continuations. A `# vk:` comment above an instruction supplies its hints.

/// Prefix for stage hints. BuildKit's `# syntax=` and `# check=` directives are file-scoped.
pub const HINT_PREFIX: &str = "vk:";

/// One instruction line, with the `# vk:` lines gathered above it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalLine {
    /// Continuation pieces join without a separator, preserving words split across lines.
    /// Each continuation escape and the spaces or tabs after it are removed.
    pub text: String,
    /// The bodies of the `# vk:` lines above it, trimmed.
    pub hints: Vec<String>,
}

/// Return the hint body for a case-insensitive `# vk:` prefix. A second `#` disables the hint.
fn hint_body(comment: &str) -> Option<&str> {
    let rest = comment.strip_prefix('#')?.trim_start();
    let (prefix, body) = rest.split_at_checked(HINT_PREFIX.len())?;
    prefix.eq_ignore_ascii_case(HINT_PREFIX).then_some(body)
}

/// The parser directives buildkit knows. A line naming another key ends the directives.
const DIRECTIVES: [&str; 3] = ["syntax", "escape", "check"];

/// Reads the opening directives after BOM removal. The default escape is `\`.
/// BuildKit's directive pattern is `^#\s*([a-zA-Z][a-zA-Z0-9]*)\s*=\s*(.+?)\s*$`.
/// This parser strips leading indentation and matches known keys case-insensitively.
/// A blank line, ordinary comment or instruction ends the directives. A repeated
/// directive or an escape other than `\` or `` ` `` is an error.
fn detect_escape(src: &str) -> Result<char, String> {
    let mut seen = [false; DIRECTIVES.len()];
    let mut escape = '\\';
    for (n, line) in src.lines().enumerate() {
        let Some((i, value)) = directive(line) else {
            break;
        };
        let line = n + 1;
        if std::mem::replace(&mut seen[i], true) {
            return Err(format!(
                "parser directive on line {line}: only one {} parser directive can be used",
                DIRECTIVES[i]
            ));
        }
        if DIRECTIVES[i] == "escape" {
            escape = match value {
                "`" => '`',
                "\\" => '\\',
                other => {
                    return Err(format!(
                        "parser directive on line {line}: invalid escape token {other:?}: \
                         expected ` or \\"
                    ));
                }
            };
        }
    }
    Ok(escape)
}

fn strip_bom(src: &str) -> &str {
    src.strip_prefix('\u{feff}').unwrap_or(src)
}

/// Returns a recognized directive's index in [`DIRECTIVES`] and its value.
fn directive(line: &str) -> Option<(usize, &str)> {
    let rest = line.trim_start().strip_prefix('#')?;
    let (key, value) = rest.split_once('=')?;
    let key = key.trim_matches(|c: char| c.is_ascii_whitespace());
    // `(.+?)\s*$` after `=\s*`: a value of whitespace alone is still one character of it.
    let value = match value.trim_matches(|c: char| c.is_ascii_whitespace()) {
        "" => value.char_indices().last().map_or("", |(i, _)| &value[i..]),
        trimmed => trimmed,
    };
    let mut chars = key.chars();
    let well_formed = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric())
        && !value.is_empty();
    let i = DIRECTIVES
        .iter()
        .position(|d| d.eq_ignore_ascii_case(key))?;
    well_formed.then_some((i, value))
}

/// Returns the instructions and any trailing `# vk:` hints without an instruction.
/// A duplicate parser directive or invalid escape token is an error.
pub fn logical_lines(src: &str) -> Result<(Vec<LogicalLine>, Vec<String>), String> {
    let src = strip_bom(src);
    let escape = detect_escape(src)?;
    let mut out = Vec::new();
    let mut hints: Vec<String> = Vec::new();
    let mut lines = src.split_inclusive('\n');
    while let Some(raw) = lines.next() {
        let first = raw.trim_end();
        if first.trim_start().starts_with('#') {
            if let Some(body) = hint_body(first.trim_start()) {
                hints.push(body.trim().to_string());
            }
            continue;
        }
        if first.trim().is_empty() {
            continue;
        }
        let mut joined = String::new();
        let mut piece = strip_newline(raw).trim_start();
        loop {
            let (content, more) = trim_continuation(piece, escape);
            joined.push_str(content);
            if !more {
                break;
            }
            let next = lines.by_ref().find(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#')
            });
            match next {
                Some(l) => piece = strip_newline(l),
                None => break,
            }
        }
        // An escape token alone on the first line, continued into nothing, is no instruction.
        let text = joined.trim_end();
        if text.is_empty() {
            continue;
        }
        out.push(LogicalLine {
            text: text.to_string(),
            hints: std::mem::take(&mut hints),
        });
    }
    Ok((out, hints))
}

/// Strips trailing CR and LF characters.
fn strip_newline(line: &str) -> &str {
    line.trim_end_matches(['\r', '\n'])
}

/// A line ending in the escape token, then only spaces and tabs, continues: strip both. As in
/// buildkit (`([^\\])\\[ \t]*$|^\\[ \t]*$`), the token must follow a character other than
/// itself or stand alone on its line, so an escaped escape token does not continue.
fn trim_continuation(line: &str, escape: char) -> (&str, bool) {
    match line.trim_end_matches([' ', '\t']).strip_suffix(escape) {
        Some(before) if !before.ends_with(escape) => (before, true),
        _ => (line, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(src: &str) -> Vec<String> {
        logical_lines(src)
            .unwrap()
            .0
            .into_iter()
            .map(|l| l.text)
            .collect()
    }

    #[test]
    fn continuations_skip_blank_and_comment_lines() {
        assert_eq!(
            texts("RUN a \\\n\n  # c\n  b\nCMD c\n"),
            ["RUN a   b", "CMD c"]
        );
        // pieces join as written: a quoted value split mid-word stays whole
        assert_eq!(
            texts("RUN curl \"https://example.org/\\\nfile\"\n"),
            ["RUN curl \"https://example.org/file\""]
        );
        // a doubled escape does not continue
        assert_eq!(texts("RUN echo \\\\\nCMD y\n"), ["RUN echo \\\\", "CMD y"]);
        assert_eq!(
            texts("# escape=`\nRUN echo ``\nCMD y\n"),
            ["RUN echo ``", "CMD y"]
        );
        // a byte-order mark is not part of the first instruction, and only one is dropped
        assert_eq!(texts("\u{feff}FROM x\n"), ["FROM x"]);
        assert_eq!(texts("\u{feff}# escape=`\nRUN a `\nb\n"), ["RUN a b"]);
        assert_eq!(
            texts("\u{feff}\u{feff}# escape=`\nRUN a `\n"),
            ["\u{feff}# escape=`", "RUN a `"]
        );
    }

    #[test]
    fn continuations_follow_buildkit_at_the_edges() {
        // CRLF line ends
        assert_eq!(texts("RUN a \\\r\n b\r\nCMD c\r\n"), ["RUN a  b", "CMD c"]);
        assert_eq!(texts("# escape=`\r\nRUN a `\r\nb\r\n"), ["RUN a b"]);
        // an escape token ending the file continues into nothing
        assert_eq!(texts("RUN a \\"), ["RUN a"]);
        // a line of spaces and tabs inside a continuation is skipped like a blank one
        assert_eq!(texts("RUN a \\\n \t \nb\n"), ["RUN a b"]);
        // a `# vk:` line inside a continuation is a comment, not a hint
        let (lines, trailing) = logical_lines("RUN a \\\n# vk: x=1\nb\n").unwrap();
        assert_eq!(lines[0].text, "RUN a b");
        assert!(lines[0].hints.is_empty() && trailing.is_empty());
        // an escape token alone on its line continues it, contributing nothing
        assert_eq!(texts("RUN a \\\n\\\nb\n"), ["RUN a b"]);
        assert_eq!(texts("   \\\nRUN b\n"), ["RUN b"]);
        assert_eq!(texts("RUN a \\\n  \\\nb\n"), ["RUN a   b"]);
        // and one that continues into nothing is no instruction, its hints left over
        let (lines, trailing) = logical_lines("# vk: x=1\n\\\n").unwrap();
        assert!(lines.is_empty());
        assert_eq!(trailing, ["x=1"]);
    }

    #[test]
    fn directives_open_the_file_in_any_case_and_spacing() {
        let e = |s| detect_escape(s).unwrap();
        assert_eq!(e("# Escape = `\nFROM x\n"), '`');
        assert_eq!(e("# syntax=docker/dockerfile:1\n#escape=`\n"), '`');
        assert_eq!(e("# a comment\n# escape=`\n"), '\\');
        assert_eq!(e("\n# escape=`\n"), '\\');
        assert_eq!(e("FROM x\n# escape=`\n"), '\\');
        assert!(detect_escape("# escape=x\n").is_err());
        assert!(detect_escape("# escape=`\n# ESCAPE=\\\n").is_err());
        assert!(logical_lines("# syntax=a\n# syntax=b\nFROM x\n").is_err());
        // a value of spaces is an escape token buildkit refuses; no value is no directive
        assert!(detect_escape("# escape= \nFROM x\n").is_err());
        assert_eq!(e("# escape=\n# escape=`\n"), '\\');
        assert_eq!(e("  # escape=`\n"), '`');
        // an unknown key ends the directives
        assert_eq!(e("# foo=bar\n# escape=`\n"), '\\');
        // the value runs to the end of the line, `=` and all
        assert_eq!(e("# check=skip=all\n# escape=`\n"), '`');
        let twice = detect_escape("# check=skip=all\n# Check=error=true\n").unwrap_err();
        assert_eq!(
            twice,
            "parser directive on line 2: only one check parser directive can be used"
        );
        // a `# vk:` comment ends the directives
        assert_eq!(e("# vk: mem=1G\n# escape=`\n"), '\\');
    }
}
