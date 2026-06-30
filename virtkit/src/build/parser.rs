//! Dockerfile → instruction stream.
//!
//! Lexing mirrors buildkit's `frontend/dockerfile/parser` (moby/buildkit, ref:
//! `Parse` in frontend/dockerfile/parser/parser.go): a default `\` escape token
//! overridable by a leading `# escape=` parser directive, `#` full-line comments,
//! and continuation lines joined when a (comment-stripped) line ends with the escape
//! token — comment-only lines inside a continuation are skipped. We model the
//! instruction subset our images use (FROM/RUN/COPY/ARG/ENV/WORKDIR/USER/LABEL/
//! ENTRYPOINT/CMD/…); anything else is kept verbatim as `Other` rather than erroring,
//! since the planner/executor only act on the ones they understand. No heredocs/ADD/
//! ONBUILD (none appear in our Dockerfiles — see the feature survey).

use anyhow::{Result, bail};

/// A parsed Dockerfile: its instruction stream in source order.
#[derive(Debug, Clone)]
pub struct Dockerfile {
    pub instructions: Vec<Instruction>,
}

/// One instruction. `Other` carries any keyword we do not model (kept verbatim).
#[derive(Debug, Clone, PartialEq)]
pub enum Instruction {
    From(From),
    Run(Run),
    Copy(Copy),
    Arg {
        name: String,
        default: Option<String>,
    },
    Env(Vec<(String, String)>),
    Workdir(String),
    User(String),
    Label(Vec<(String, String)>),
    Entrypoint(Cmdline),
    Cmd(Cmdline),
    Other {
        name: String,
        args: String,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct From {
    pub image: String,
    pub as_name: Option<String>,
    pub platform: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Run {
    pub cmd: Cmdline,
    pub mounts: Vec<Mount>,
    pub network: Option<String>,
    pub security: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Copy {
    pub sources: Vec<String>,
    pub dest: String,
    /// `--from=<stage|image>` (a build stage by name/index, or an external image).
    pub from: Option<String>,
    pub chown: Option<String>,
    pub chmod: Option<String>,
    pub link: bool,
}

/// A `RUN --mount=…` entry (we keep the raw key/values; the executor interprets them).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Mount {
    pub typ: String,
    pub from: Option<String>,
    pub source: Option<String>,
    pub target: Option<String>,
    pub readonly: bool,
}

/// Shell form (`RUN foo`) vs exec form (`RUN ["foo","bar"]`, a JSON array).
#[derive(Debug, Clone, PartialEq)]
pub enum Cmdline {
    Shell(String),
    Exec(Vec<String>),
}

const DEFAULT_ESCAPE: char = '\\';

/// Parse a Dockerfile's text into its instruction stream.
pub fn parse(src: &str) -> Result<Dockerfile> {
    let escape = detect_escape(src);
    let logical = logical_lines(src, escape);
    let mut instructions = Vec::new();
    for line in logical {
        instructions.push(parse_instruction(&line)?);
    }
    Ok(Dockerfile { instructions })
}

/// `# escape=<char>` must precede any instruction (and any non-directive comment).
/// Mirrors buildkit's `possibleParserDirective`: only `\` or `` ` `` are accepted.
fn detect_escape(src: &str) -> char {
    for raw in src.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('#') {
            let rest = rest.trim();
            if let Some(val) = rest.strip_prefix("escape=") {
                return match val.trim() {
                    "`" => '`',
                    _ => DEFAULT_ESCAPE,
                };
            }
            // a non-directive comment ends the directive window only if it is not the
            // first thing; buildkit allows the escape directive only before any
            // instruction, so we keep scanning comments but stop at an instruction.
            continue;
        }
        break; // first instruction: no (more) directives
    }
    DEFAULT_ESCAPE
}

/// Join physical lines into logical instruction lines per buildkit's rules: strip
/// `#` comment-only lines, and continue across lines whose comment-stripped content
/// ends with the escape token (skipping comment-only lines inside a continuation).
fn logical_lines(src: &str, escape: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut continuing = false;
    for raw in src.lines() {
        let trimmed = raw.trim_end();
        let is_comment = trimmed.trim_start().starts_with('#');
        if is_comment {
            // comment-only lines are dropped, both standalone and inside a continuation
            continue;
        }
        if !continuing {
            if trimmed.trim().is_empty() {
                continue;
            }
            cur.clear();
        }
        let (content, cont) = trim_continuation(trimmed, escape);
        // Join continuation pieces with a single space, each piece trimmed — buildkit
        // concatenates raw bytes, but normalizing whitespace here keeps the joined
        // instruction stable regardless of indentation around the escape.
        let piece = content.trim();
        if !piece.is_empty() {
            if !cur.is_empty() {
                cur.push(' ');
            }
            cur.push_str(piece);
        }
        continuing = cont;
        if !continuing {
            let line = cur.trim().to_string();
            if !line.is_empty() {
                out.push(line);
            }
        }
    }
    if continuing && !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// Strip a trailing escape token (with optional trailing whitespace) → continuation.
fn trim_continuation(line: &str, escape: char) -> (&str, bool) {
    let t = line.trim_end();
    if let Some(stripped) = t.strip_suffix(escape) {
        (stripped, true)
    } else {
        (line, false)
    }
}

/// Split `<KEYWORD> <rest>` and dispatch. Keyword match is case-insensitive.
fn parse_instruction(line: &str) -> Result<Instruction> {
    let (kw, rest) = match line.split_once(char::is_whitespace) {
        Some((k, r)) => (k, r.trim()),
        None => (line, ""),
    };
    Ok(match kw.to_ascii_uppercase().as_str() {
        "FROM" => Instruction::From(parse_from(rest)?),
        "RUN" => Instruction::Run(parse_run(rest)?),
        "COPY" => Instruction::Copy(parse_copy(rest)?),
        "ARG" => {
            let (name, default) = match rest.split_once('=') {
                Some((n, v)) => (n.trim().to_string(), Some(unquote(v.trim()))),
                None => (rest.trim().to_string(), None),
            };
            Instruction::Arg { name, default }
        }
        "ENV" => Instruction::Env(parse_kv(rest)),
        "LABEL" => Instruction::Label(parse_kv(rest)),
        "WORKDIR" => Instruction::Workdir(rest.to_string()),
        "USER" => Instruction::User(rest.to_string()),
        "ENTRYPOINT" => Instruction::Entrypoint(parse_cmdline(rest)),
        "CMD" => Instruction::Cmd(parse_cmdline(rest)),
        other => Instruction::Other {
            name: other.to_string(),
            args: rest.to_string(),
        },
    })
}

fn parse_from(rest: &str) -> Result<From> {
    let (flags, words) = split_flags(rest);
    let mut platform = None;
    for (k, v) in flags {
        if k == "platform" {
            platform = Some(v);
        }
    }
    // <image> [AS <name>]
    let mut it = words.into_iter();
    let image = it.next().context_msg("FROM needs an image")?;
    let mut as_name = None;
    if let Some(w) = it.next()
        && w.eq_ignore_ascii_case("as")
    {
        as_name = it.next();
    }
    if image.is_empty() {
        bail!("FROM needs an image");
    }
    Ok(From {
        image,
        as_name,
        platform,
    })
}

fn parse_run(rest: &str) -> Result<Run> {
    let (flags, _words) = split_flags(rest);
    let mut mounts = Vec::new();
    let mut network = None;
    let mut security = None;
    for (k, v) in &flags {
        match k.as_str() {
            "mount" => mounts.push(parse_mount(v)),
            "network" => network = Some(v.clone()),
            "security" => security = Some(v.clone()),
            _ => {}
        }
    }
    // the command is everything after the leading flags, verbatim (shell form) or a
    // JSON array (exec form).
    let after = strip_leading_flags(rest);
    Ok(Run {
        cmd: parse_cmdline(after),
        mounts,
        network,
        security,
    })
}

fn parse_copy(rest: &str) -> Result<Copy> {
    let (flags, words) = split_flags(rest);
    let mut from = None;
    let mut chown = None;
    let mut chmod = None;
    let mut link = false;
    for (k, v) in flags {
        match k.as_str() {
            "from" => from = Some(v),
            "chown" => chown = Some(v),
            "chmod" => chmod = Some(v),
            "link" => link = true,
            _ => {}
        }
    }
    // exec (JSON-array) form: COPY ["src", ..., "dest"]
    let after = strip_leading_flags(rest);
    let mut paths = if after.trim_start().starts_with('[') {
        parse_json_array(after.trim()).unwrap_or(words)
    } else {
        words
    };
    if paths.len() < 2 {
        bail!("COPY needs at least one source and a dest ({rest:?})");
    }
    let dest = paths.pop().unwrap();
    Ok(Copy {
        sources: paths,
        dest,
        from,
        chown,
        chmod,
        link,
    })
}

/// `type=bind,from=builder,source=/a,target=/b,ro` → a [`Mount`].
fn parse_mount(spec: &str) -> Mount {
    let mut m = Mount::default();
    for part in spec.split(',') {
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        match k.trim() {
            "type" => m.typ = v.trim().to_string(),
            "from" => m.from = Some(v.trim().to_string()),
            "source" | "src" => m.source = Some(v.trim().to_string()),
            "target" | "dst" | "destination" => m.target = Some(v.trim().to_string()),
            "ro" | "readonly" => m.readonly = true,
            _ => {}
        }
    }
    if m.typ.is_empty() {
        m.typ = "bind".into();
    }
    m
}

fn parse_cmdline(rest: &str) -> Cmdline {
    let t = rest.trim();
    if t.starts_with('[')
        && let Some(v) = parse_json_array(t)
    {
        return Cmdline::Exec(v);
    }
    Cmdline::Shell(t.to_string())
}

/// Parse leading `--key=value` flags off the front; return (flags, remaining words).
fn split_flags(rest: &str) -> (Vec<(String, String)>, Vec<String>) {
    let mut flags = Vec::new();
    let mut words = Vec::new();
    let mut seen_nonflag = false;
    for tok in tokenize(rest) {
        if !seen_nonflag && tok.starts_with("--") {
            let kv = &tok[2..];
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            flags.push((k.to_string(), v.to_string()));
        } else {
            seen_nonflag = true;
            words.push(tok);
        }
    }
    (flags, words)
}

/// The substring after the leading `--flag` tokens (for verbatim command bodies).
fn strip_leading_flags(rest: &str) -> &str {
    let mut s = rest.trim_start();
    while let Some(stripped) = s.strip_prefix("--") {
        // advance past one flag token
        let end = stripped
            .find(char::is_whitespace)
            .map(|i| i + 2)
            .unwrap_or(s.len());
        let after = s[end..].trim_start();
        // only treat as a flag if it looked like --k or --k=v
        if s[..end].contains(' ') {
            break;
        }
        s = after;
    }
    s
}

/// Whitespace tokenizer that keeps quoted spans together (single + double quotes).
fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut any = false;
    for c in s.chars() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else {
                    cur.push(c);
                }
            }
            None => {
                if c == '"' || c == '\'' {
                    quote = Some(c);
                    any = true;
                } else if c.is_whitespace() {
                    if any {
                        out.push(std::mem::take(&mut cur));
                        any = false;
                    }
                } else {
                    cur.push(c);
                    any = true;
                }
            }
        }
    }
    if any {
        out.push(cur);
    }
    out
}

/// `k=v k2="v 2"` pairs, or the legacy single `KEY value` form (ENV/LABEL).
fn parse_kv(rest: &str) -> Vec<(String, String)> {
    if !rest.contains('=') {
        return Vec::new();
    }
    // legacy `ENV KEY rest of line` (no '=' in the key position)
    let first = rest.split_whitespace().next().unwrap_or("");
    if !first.contains('=')
        && let Some((k, v)) = rest.split_once(char::is_whitespace)
    {
        return vec![(k.to_string(), unquote(v.trim()))];
    }
    let mut out = Vec::new();
    for tok in tokenize(rest) {
        if let Some((k, v)) = tok.split_once('=') {
            out.push((k.to_string(), v.to_string()));
        }
    }
    out
}

fn parse_json_array(s: &str) -> Option<Vec<String>> {
    serde_json::from_str::<Vec<String>>(s).ok()
}

fn unquote(s: &str) -> String {
    let b = s.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Small helper so `Option::context_msg` reads like anyhow's `.context` on results.
trait ContextMsg<T> {
    fn context_msg(self, msg: &'static str) -> Result<T>;
}
impl<T> ContextMsg<T> for Option<T> {
    fn context_msg(self, msg: &'static str) -> Result<T> {
        self.ok_or_else(|| anyhow::anyhow!(msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_continuation_joins_across_comments() {
        // buildkit: a comment line inside a continuation is skipped, the join holds.
        let df = parse("RUN echo a \\\n  # a comment in the middle\n  && echo b\n").unwrap();
        assert_eq!(df.instructions.len(), 1);
        let Instruction::Run(r) = &df.instructions[0] else {
            panic!("expected RUN, got {:?}", df.instructions[0])
        };
        assert_eq!(r.cmd, Cmdline::Shell("echo a && echo b".into()));
    }

    #[test]
    fn escape_directive_switches_continuation_char() {
        let df = parse("# escape=`\nRUN echo a `\n  echo b\n").unwrap();
        let Instruction::Run(r) = &df.instructions[0] else {
            panic!()
        };
        assert_eq!(r.cmd, Cmdline::Shell("echo a echo b".into()));
    }

    #[test]
    fn multistage_from_as_and_base() {
        let df = parse("FROM debian AS base\nFROM base\n").unwrap();
        assert_eq!(
            df.instructions[0],
            Instruction::From(From {
                image: "debian".into(),
                as_name: Some("base".into()),
                platform: None,
            })
        );
        assert_eq!(
            df.instructions[1],
            Instruction::From(From {
                image: "base".into(),
                as_name: None,
                platform: None
            })
        );
    }

    #[test]
    fn run_mount_bind_from_stage() {
        let df = parse("RUN --mount=type=bind,from=builder,source=/o,target=/i make\n").unwrap();
        let Instruction::Run(r) = &df.instructions[0] else {
            panic!()
        };
        assert_eq!(r.mounts.len(), 1);
        assert_eq!(
            r.mounts[0],
            Mount {
                typ: "bind".into(),
                from: Some("builder".into()),
                source: Some("/o".into()),
                target: Some("/i".into()),
                readonly: false,
            }
        );
        assert_eq!(r.cmd, Cmdline::Shell("make".into()));
    }

    #[test]
    fn copy_flags_and_exec_form() {
        let df = parse("COPY --from=build --chown=1000:1000 --link /src /dst\n").unwrap();
        let Instruction::Copy(c) = &df.instructions[0] else {
            panic!()
        };
        assert_eq!(c.from.as_deref(), Some("build"));
        assert_eq!(c.chown.as_deref(), Some("1000:1000"));
        assert!(c.link);
        assert_eq!(c.sources, vec!["/src".to_string()]);
        assert_eq!(c.dest, "/dst");

        let df = parse("COPY [\"a b\", \"c\"]\n").unwrap();
        let Instruction::Copy(c) = &df.instructions[0] else {
            panic!()
        };
        assert_eq!(c.sources, vec!["a b".to_string()]);
        assert_eq!(c.dest, "c");
    }

    #[test]
    fn run_exec_form_and_cmdline() {
        let df = parse("RUN [\"/bin/sh\", \"-c\", \"echo hi\"]\n").unwrap();
        let Instruction::Run(r) = &df.instructions[0] else {
            panic!()
        };
        assert_eq!(
            r.cmd,
            Cmdline::Exec(vec!["/bin/sh".into(), "-c".into(), "echo hi".into()])
        );
    }

    #[test]
    fn arg_env_and_unknown_kept_verbatim() {
        let df = parse("ARG debversion=bookworm-20231120\nENV A=1 B=2\nEXPOSE 8080\n").unwrap();
        assert_eq!(
            df.instructions[0],
            Instruction::Arg {
                name: "debversion".into(),
                default: Some("bookworm-20231120".into())
            }
        );
        assert_eq!(
            df.instructions[1],
            Instruction::Env(vec![("A".into(), "1".into()), ("B".into(), "2".into())])
        );
        assert_eq!(
            df.instructions[2],
            Instruction::Other {
                name: "EXPOSE".into(),
                args: "8080".into()
            }
        );
    }
}
