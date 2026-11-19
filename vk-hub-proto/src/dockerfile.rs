//! Dockerfile instruction lines for `vk build` and the hub's egress reader.
//! Both follow BuildKit's `frontend/dockerfile/parser` `Parse` rules for directives,
//! comments, continuations and the bodies of the heredocs a `RUN`, `COPY` or `ADD` line
//! opens (`<<EOF`, `<<-'EOF'`), which are data rather than instructions. A `# vk:` comment
//! above an instruction supplies its hints.

/// Prefix for stage hints. BuildKit's `# syntax=` and `# check=` directives are file-scoped.
pub const HINT_PREFIX: &str = "vk:";

/// One instruction line, with the `# vk:` lines gathered above it and the heredocs it opens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalLine {
    /// Continuation pieces join without a separator, preserving words split across lines.
    /// Each continuation escape and the spaces or tabs after it are removed.
    pub text: String,
    /// The bodies of the `# vk:` lines above it, trimmed.
    pub hints: Vec<String>,
    /// The heredocs it opens, in order.
    pub heredocs: Vec<Heredoc>,
}

/// A heredoc an instruction line opens, with the body read from the lines after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Heredoc {
    /// The terminator word, unquoted.
    pub name: String,
    /// `<<-`: leading tabs are stripped from the terminator line, and from the body for a
    /// `RUN` made of the heredoc alone.
    pub chomp: bool,
    /// Every body line as written, line ending included; the terminator line excluded.
    pub content: String,
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
/// A duplicate parser directive, an invalid escape token, a heredoc with no terminator or a
/// heredoc word that does not lex is an error.
pub fn logical_lines(src: &str) -> Result<(Vec<LogicalLine>, Vec<String>), String> {
    let src = strip_bom(src);
    let escape = detect_escape(src)?;
    let mut out = Vec::new();
    let mut hints: Vec<String> = Vec::new();
    // Physical lines with their endings, which a heredoc body keeps, counted for errors.
    let read = std::cell::Cell::new(0usize);
    let mut lines = src
        .split_inclusive('\n')
        .inspect(|_| read.set(read.get() + 1));
    while let Some(raw) = lines.next() {
        let start = read.get();
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
        let heredocs = read_heredocs(text, &mut lines).map_err(|e| format!("line {start}: {e}"))?;
        out.push(LogicalLine {
            text: text.to_string(),
            hints: std::mem::take(&mut hints),
            heredocs,
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

/// The keywords whose line buildkit reads heredocs for, alone or after `ONBUILD`.
const HEREDOC_KEYWORDS: [&str; 3] = ["RUN", "COPY", "ADD"];

/// Read bodies in opener order, preserving comments, blank lines, escapes and line endings.
/// Each terminator must match the whole line, ignoring leading tabs for `<<-`.
fn read_heredocs<'a>(
    line: &str,
    lines: &mut impl Iterator<Item = &'a str>,
) -> Result<Vec<Heredoc>, String> {
    if !line.contains("<<") || !opens_heredocs(line) {
        return Ok(Vec::new());
    }
    // A line buildkit's lexer fails on yields no words, so no heredocs.
    let Some(words) = raw_words(line) else {
        return Ok(Vec::new());
    };
    let mut docs = Vec::new();
    for word in words {
        let Some((name, chomp)) = heredoc_word(&word)? else {
            continue;
        };
        let mut content = String::new();
        let mut terminated = false;
        for body in lines.by_ref() {
            let candidate = strip_newline(body);
            let candidate = if chomp {
                candidate.trim_start_matches('\t')
            } else {
                candidate
            };
            if candidate == name {
                terminated = true;
                break;
            }
            content.push_str(body);
        }
        if !terminated {
            return Err(format!(
                "unterminated heredoc <<{name} in `{}`",
                line.trim()
            ));
        }
        docs.push(Heredoc {
            name,
            chomp,
            content,
        });
    }
    Ok(docs)
}

/// Whether `line` is an instruction buildkit reads heredocs for: a RUN, COPY or ADD, alone or
/// after ONBUILD, whose arguments are not a JSON array (the exec form).
fn opens_heredocs(line: &str) -> bool {
    let mut rest = line.trim_start();
    let keyword = |rest: &mut &str| -> String {
        let s = rest.trim_start();
        let end = s.find(char::is_whitespace).unwrap_or(s.len());
        *rest = &s[end..];
        s[..end].to_ascii_uppercase()
    };
    let mut kw = keyword(&mut rest);
    if kw == "ONBUILD" {
        kw = keyword(&mut rest);
    }
    if !HEREDOC_KEYWORDS.contains(&kw.as_str()) {
        return false;
    }
    // Past the leading `--flag` words, an array is the exec form, which holds no heredocs.
    let Some(words) = raw_words(rest) else {
        return false;
    };
    let flags = words.iter().take_while(|w| w.starts_with("--")).count();
    let args = words[flags..].join(" ");
    !(args.starts_with('[') && serde_json::from_str::<Vec<String>>(&args).is_ok())
}

/// Split at unquoted whitespace, preserving quotes, escapes and the gap in `<< EOF`.
/// Keep `${…}` whole, including any quoted text. BuildKit can also split an unquoted
/// default value at spaces. An unclosed quote or a parameter rejected by [`take_param`]
/// suppresses heredocs for the whole line.
fn raw_words(line: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            '\'' => {
                in_word = true;
                cur.push(c);
                loop {
                    let q = chars.next()?;
                    cur.push(q);
                    if q == '\'' {
                        break;
                    }
                }
            }
            '"' => {
                in_word = true;
                cur.push(c);
                loop {
                    let q = chars.next()?;
                    cur.push(q);
                    match q {
                        '"' => break,
                        '\\' if matches!(chars.peek(), Some('"' | '$' | '\\')) => {
                            cur.extend(chars.next());
                        }
                        '$' if chars.peek() == Some(&'{') && !take_param(&mut chars, &mut cur) => {
                            return None;
                        }
                        _ => {}
                    }
                }
            }
            '\\' => {
                in_word = true;
                cur.push(c);
                cur.extend(chars.next());
            }
            '$' if chars.peek() == Some(&'{') => {
                in_word = true;
                cur.push(c);
                if !take_param(&mut chars, &mut cur) {
                    return None;
                }
            }
            '<' if chars.peek() == Some(&'<') => {
                in_word = true;
                cur.push_str("<<");
                chars.next();
                while let Some(&w) = chars.peek().filter(|w| matches!(w, ' ' | '\t' | '\r')) {
                    cur.push(w);
                    chars.next();
                }
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    Some(out)
}

/// With `$` already in `cur`, copy through the matching `}`, preserving nested `${…}`,
/// quotes and escapes. A missing brace, empty `${}` or unsupported operator such as `=`
/// or `:#` returns `false` and suppresses heredocs for the line.
fn take_param(chars: &mut std::iter::Peekable<std::str::Chars<'_>>, cur: &mut String) -> bool {
    cur.extend(chars.next()); // the `{`
    match chars.peek() {
        None | Some('{' | '}' | ':') => return false,
        Some(c) if c.is_ascii_digit() => {
            while let Some(&d) = chars.peek().filter(|c| c.is_ascii_digit()) {
                cur.push(d);
                chars.next();
            }
        }
        Some(&s @ ('@' | '*' | '#' | '?' | '-' | '$' | '!')) => {
            cur.push(s);
            chars.next();
        }
        Some(_) => {
            while let Some(&n) = chars
                .peek()
                .filter(|c| c.is_ascii_alphanumeric() || **c == '_')
            {
                cur.push(n);
                chars.next();
            }
        }
    }
    let Some(op) = chars.next() else {
        return false;
    };
    cur.push(op);
    match op {
        '}' => return true,
        ':' => match chars.next() {
            None | Some('#' | '%') => return false,
            Some(c) => cur.push(c),
        },
        '+' | '-' | '?' | '#' | '%' | '/' => {}
        _ => return false,
    }
    // The operand, through the closing brace.
    while let Some(c) = chars.next() {
        cur.push(c);
        match c {
            '}' => return true,
            '$' if chars.peek() == Some(&'{') => {
                if !take_param(chars, cur) {
                    return false;
                }
            }
            '\\' => cur.extend(chars.next()),
            '\'' | '"' => loop {
                let Some(q) = chars.next() else {
                    return false;
                };
                cur.push(q);
                if q == c {
                    break;
                }
                if q == '\\' && c == '"' {
                    cur.extend(chars.next());
                }
            },
            _ => {}
        }
    }
    false
}

/// Parse BuildKit's `^(\d*)<<(-?)\s*([^<]*)$`. The delimiter must lex to one nonempty
/// word. Return its unquoted name and the `<<-` flag, `None` for other words, or an
/// error for an unclosed quote in the delimiter.
pub fn heredoc_word(word: &str) -> Result<Option<(String, bool)>, String> {
    let rest = word.trim_start_matches(|c: char| c.is_ascii_digit());
    let Some(rest) = rest.strip_prefix("<<") else {
        return Ok(None);
    };
    let (chomp, rest) = match rest.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, rest),
    };
    let rest = rest.trim_start_matches([' ', '\t', '\r', '\n', '\x0c']);
    if rest.is_empty() || rest.contains('<') {
        return Ok(None);
    }
    let mut words = lex_words(rest).map_err(|e| format!("heredoc {word:?}: {e}"))?;
    // An empty word, `<<''`, is no word at all to buildkit's lexer.
    Ok(match (words.pop(), words.is_empty()) {
        (Some(name), true) if !name.is_empty() => Some((name, chomp)),
        _ => None,
    })
}

/// Split `s` into words with their quoting removed, as buildkit's shell lexer does: `'…'` is
/// literal, inside `"…"` a backslash escapes only `"`, `$` and itself, and an unquoted one
/// escapes any character.
fn lex_words(s: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(q) => cur.push(q),
                        None => return Err("unterminated single quote".into()),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') if matches!(chars.peek(), Some('"' | '$' | '\\')) => {
                            cur.extend(chars.next());
                        }
                        Some(q) => cur.push(q),
                        None => return Err("unterminated double quote".into()),
                    }
                }
            }
            '\\' => {
                in_word = true;
                cur.extend(chars.next());
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    Ok(out)
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
    fn heredoc_words_lex_as_buildkit_s() {
        let w = |s| heredoc_word(s).unwrap();
        assert_eq!(w("<<EOF"), Some(("EOF".into(), false)));
        assert_eq!(w("2<<-'E O'"), Some(("E O".into(), true)));
        assert_eq!(w("<< EOF"), Some(("EOF".into(), false)));
        assert_eq!(w(r#"<<"E\OF""#), Some((r"E\OF".into(), false)));
        assert_eq!(w(r#"<<"E\"OF""#), Some((r#"E"OF"#.into(), false)));
        assert_eq!(w(r"<<E\OF"), Some(("EOF".into(), false)));
        assert_eq!(w("<<EOF cat"), None);
        assert_eq!(w("<<"), None);
        assert_eq!(w("<<<EOF"), None);
        assert_eq!(w("cat<<EOF"), None);
        assert!(heredoc_word("<<'EOF").is_err());
        assert_eq!(
            raw_words(r#"cat << EOF "a b" 'c d'<<X e\ f"#).unwrap(),
            ["cat", "<< EOF", r#""a b""#, "'c d'<<X", r"e\ f"]
        );
    }

    #[test]
    fn heredoc_bodies_are_data() {
        let (lines, _) = logical_lines(
            "FROM x\nRUN cat <<A >/a && \\\n  cat << 'B' >/b\r\n# vk: no\r\nFROM y\r\nA\nb\r\n B\nB\n",
        )
        .unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1].text, "RUN cat <<A >/a &&   cat << 'B' >/b");
        assert_eq!(lines[1].heredocs[0].content, "# vk: no\r\nFROM y\r\n");
        assert_eq!(lines[1].heredocs[1].content, "b\r\n B\n");
        // A delimiter split over a continuation is read whole.
        assert_eq!(
            texts("RUN cat <<EO\\\nF\nx\nEOF\nCMD y\n"),
            ["RUN cat <<EOF", "CMD y"]
        );
        assert_eq!(
            texts("# escape=`\nRUN cat <<EO`\nF\nx\nEOF\nCMD y\n"),
            ["RUN cat <<EOF", "CMD y"]
        );
        // ONBUILD reads its nested instruction's heredocs; exec form and other keywords none.
        assert_eq!(texts("ONBUILD RUN <<E\nENV A=B\nE\n"), ["ONBUILD RUN <<E"]);
        assert_eq!(
            texts("RUN [\"sh\", \"-c\", \"<<E\"]\nE\nENV X <<E\n"),
            ["RUN [\"sh\", \"-c\", \"<<E\"]", "E", "ENV X <<E"]
        );
        let unterminated = logical_lines("FROM x\n\nRUN cat <<E\nno end\n").unwrap_err();
        assert!(
            unterminated.starts_with("line 3: unterminated heredoc <<E"),
            "{unterminated}"
        );
        // a quote never closed fails buildkit's lexer, which leaves the line without heredocs
        assert_eq!(texts("RUN cat <<'EOF\nx\n"), ["RUN cat <<'EOF", "x"]);
        assert_eq!(
            texts("RUN cat <<EOF > it's\nx\nEOF\n"),
            ["RUN cat <<EOF > it's", "x", "EOF"]
        );
        // `<<- EOF` and a bare `<<-` are no heredoc words, as in buildkit: the lines after them
        // stay instructions, so `vk build` rejects `x`.
        assert_eq!(
            texts("RUN cat > /f <<- EOF\nx\nRUN echo ok # <<-\nCMD y\n"),
            ["RUN cat > /f <<- EOF", "x", "RUN echo ok # <<-", "CMD y"]
        );
        // a `{` in a `${…}` default is literal: the heredoc after it opens
        let (lines, _) = logical_lines("RUN echo ${x:-{} && cat >f <<EOF\nbody\nEOF\n").unwrap();
        assert_eq!(lines[0].heredocs[0].content, "body\n");
        // a doubled escape ends the opener: the next line is the body
        assert_eq!(
            texts("RUN cat <<E && echo \\\\\nx\nE\nCMD y\n"),
            ["RUN cat <<E && echo \\\\", "CMD y"]
        );
        assert_eq!(
            texts("# escape=`\nRUN cat <<E && echo ``\nx\nE\nCMD y\n"),
            ["RUN cat <<E && echo ``", "CMD y"]
        );
        // a `${…}` buildkit's lexer fails on leaves the line without heredocs; one it takes
        // does not
        assert_eq!(
            texts("RUN : \"${MODE=release}\" && cat <<EOF\npayload\nEOF\n"),
            ["RUN : \"${MODE=release}\" && cat <<EOF", "payload", "EOF"]
        );
        assert_eq!(
            texts("RUN : \"${MODE:=release}\" && cat <<EOF\npayload\nEOF\nCMD y\n"),
            ["RUN : \"${MODE:=release}\" && cat <<EOF", "CMD y"]
        );
        // a `${…}` default value holds no heredoc; nor does an empty delimiter
        assert_eq!(
            texts("RUN echo \"${x:-\"a <<EOF b\"}\"\nENV A=B\nRUN cat <<''\nENV C=D\n"),
            [
                "RUN echo \"${x:-\"a <<EOF b\"}\"",
                "ENV A=B",
                "RUN cat <<''",
                "ENV C=D"
            ]
        );
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
