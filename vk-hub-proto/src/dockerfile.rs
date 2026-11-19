//! Dockerfile instruction lines for `vk build` and the hub's egress reader.
//! Lines ending in the escape character continue the instruction. Full-line comments
//! are skipped, except for `# vk:` hints between instructions.

/// Prefix for stage hints. BuildKit's `# syntax=` and `# check=` directives are file-scoped.
pub const HINT_PREFIX: &str = "vk:";

/// One instruction line, with the `# vk:` lines gathered above it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalLine {
    /// The instruction, its continuation pieces each trimmed and joined with one space.
    /// buildkit concatenates them as written; normalizing keeps the instruction stable
    /// whatever the indentation around the escape token.
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

/// The escape character an `# escape=` parser directive sets, before the first instruction:
/// `` ` `` for that value, `\` for any other or none.
fn detect_escape(src: &str) -> char {
    for raw in src.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let Some(rest) = line.strip_prefix('#') else {
            break;
        };
        if let Some(value) = rest.trim().strip_prefix("escape=") {
            return if value.trim() == "`" { '`' } else { '\\' };
        }
    }
    '\\'
}

/// Return instruction lines and any trailing hints that have no instruction.
pub fn logical_lines(src: &str) -> (Vec<LogicalLine>, Vec<String>) {
    let escape = detect_escape(src);
    let mut out = Vec::new();
    let mut hints: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut continuing = false;
    for raw in src.lines() {
        let trimmed = raw.trim_end();
        if trimmed.trim_start().starts_with('#') {
            // Comments are dropped, inside a continuation too, but a `# vk:` one outside it is
            // held for the coming instruction.
            if !continuing && let Some(body) = hint_body(trimmed.trim_start()) {
                hints.push(body.trim().to_string());
            }
            continue;
        }
        if !continuing {
            if trimmed.trim().is_empty() {
                continue;
            }
            cur.clear();
        }
        let (content, more) = match trimmed.strip_suffix(escape) {
            Some(stripped) => (stripped, true),
            None => (trimmed, false),
        };
        let piece = content.trim();
        if !piece.is_empty() {
            if !cur.is_empty() {
                cur.push(' ');
            }
            cur.push_str(piece);
        }
        continuing = more;
        if !continuing && !cur.trim().is_empty() {
            out.push(LogicalLine {
                text: cur.trim().to_string(),
                hints: std::mem::take(&mut hints),
            });
        }
    }
    if continuing && !cur.trim().is_empty() {
        out.push(LogicalLine {
            text: cur.trim().to_string(),
            hints: std::mem::take(&mut hints),
        });
    }
    (out, hints)
}
