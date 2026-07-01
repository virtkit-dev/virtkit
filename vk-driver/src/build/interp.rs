//! Dockerfile variable interpolation: expand `$VAR` / `${VAR}` (and the
//! `${VAR:-word}` / `${VAR:+word}` and no-colon `-`/`+` forms) in instruction text
//! using the in-scope ARG + ENV values. `\$` is a literal `$`; an unset variable
//! expands to empty. Mirrors buildkit's `frontend/dockerfile/shell` expansion for the
//! forms our Dockerfiles use (no nested `${...}` inside a modifier word, no `${#x}` /
//! pattern ops — none appear in the survey).

use std::collections::BTreeMap;

use super::parser::{self, Cmdline, Instruction};

/// In-scope variables for interpolation (ARG ∪ ENV, ENV taking precedence on insert).
pub type Vars = BTreeMap<String, String>;

fn is_name_start(c: char) -> bool {
    c == '_' || c.is_ascii_alphabetic()
}

fn is_name_char(c: char) -> bool {
    c == '_' || c.is_ascii_alphanumeric()
}

/// Expand variable references in `s`.
pub fn interpolate(s: &str, vars: &Vars) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            // `\$` is a literal `$`; any other `\x` is kept verbatim.
            if chars.peek() == Some(&'$') {
                out.push('$');
                chars.next();
            } else {
                out.push('\\');
            }
            continue;
        }
        if c != '$' {
            out.push(c);
            continue;
        }
        match chars.peek().copied() {
            Some('{') => {
                chars.next(); // consume '{'
                // scan to the matching '}', tracking nesting so a `${VAR:-${X}}` word
                // keeps its inner reference intact.
                let mut inner = String::new();
                let mut depth = 1u32;
                let mut closed = false;
                for ch in chars.by_ref() {
                    if ch == '{' {
                        depth += 1;
                    } else if ch == '}' {
                        depth -= 1;
                        if depth == 0 {
                            closed = true;
                            break;
                        }
                    }
                    inner.push(ch);
                }
                if closed {
                    out.push_str(&expand_braced(&inner, vars));
                } else {
                    out.push('$');
                    out.push('{');
                    out.push_str(&inner);
                }
            }
            Some(ch) if is_name_start(ch) => {
                let mut name = String::new();
                while let Some(&ch) = chars.peek() {
                    if is_name_char(ch) {
                        name.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                out.push_str(vars.get(&name).map(String::as_str).unwrap_or(""));
            }
            _ => out.push('$'),
        }
    }
    out
}

/// Expand the inside of a `${…}`: a bare name, or `name`+op+`word` where op is one of
/// `:-` `:+` `-` `+`. The `word` is itself interpolated.
fn expand_braced(inner: &str, vars: &Vars) -> String {
    let name_end = inner
        .find(|c: char| !is_name_char(c))
        .unwrap_or(inner.len());
    let name = &inner[..name_end];
    let rest = &inner[name_end..];
    let val = vars.get(name).cloned();
    if rest.is_empty() {
        return val.unwrap_or_default();
    }
    let (colon, op_rest) = match rest.strip_prefix(':') {
        Some(r) => (true, r),
        None => (false, rest),
    };
    let (op, raw_word) = match op_rest.split_at(op_rest.chars().next().map_or(0, char::len_utf8)) {
        (op @ ("-" | "+"), word) => (op, word),
        _ => return val.unwrap_or_default(), // unknown modifier: treat as a plain ref
    };
    let word = interpolate(raw_word, vars);
    let set = val.is_some();
    let nonempty = val.as_deref().is_some_and(|v| !v.is_empty());
    match op {
        "-" => {
            let use_word = if colon { !nonempty } else { !set };
            if use_word {
                word
            } else {
                val.unwrap_or_default()
            }
        }
        "+" => {
            let present = if colon { nonempty } else { set };
            if present { word } else { String::new() }
        }
        _ => val.unwrap_or_default(),
    }
}

/// Return `instr` with every interpolatable string expanded against `vars`. `FROM` is
/// not expanded here — its base is resolved at plan time against the global ARGs.
pub fn expand_instruction(instr: &Instruction, vars: &Vars) -> Instruction {
    let e = |s: &str| interpolate(s, vars);
    match instr {
        Instruction::Run(r) => Instruction::Run(parser::Run {
            cmd: expand_cmd(&r.cmd, vars),
            mounts: r.mounts.iter().map(|m| expand_mount(m, vars)).collect(),
            network: r.network.clone(),
            security: r.security.clone(),
        }),
        Instruction::Copy(c) => Instruction::Copy(parser::Copy {
            sources: c.sources.iter().map(|s| e(s)).collect(),
            dest: e(&c.dest),
            from: c.from.as_deref().map(e),
            chown: c.chown.as_deref().map(e),
            chmod: c.chmod.as_deref().map(e),
            link: c.link,
        }),
        Instruction::Env(kvs) => {
            Instruction::Env(kvs.iter().map(|(k, v)| (k.clone(), e(v))).collect())
        }
        Instruction::Workdir(w) => Instruction::Workdir(e(w)),
        Instruction::User(u) => Instruction::User(e(u)),
        Instruction::Arg { name, default } => Instruction::Arg {
            name: name.clone(),
            default: default.as_deref().map(e),
        },
        Instruction::Label(kvs) => {
            Instruction::Label(kvs.iter().map(|(k, v)| (k.clone(), e(v))).collect())
        }
        Instruction::Entrypoint(c) => Instruction::Entrypoint(expand_cmd(c, vars)),
        Instruction::Cmd(c) => Instruction::Cmd(expand_cmd(c, vars)),
        Instruction::Other { name, args } => Instruction::Other {
            name: name.clone(),
            args: e(args),
        },
        Instruction::From(_) => instr.clone(),
    }
}

fn expand_cmd(cmd: &Cmdline, vars: &Vars) -> Cmdline {
    match cmd {
        Cmdline::Shell(s) => Cmdline::Shell(interpolate(s, vars)),
        Cmdline::Exec(v) => Cmdline::Exec(v.iter().map(|a| interpolate(a, vars)).collect()),
    }
}

fn expand_mount(m: &parser::Mount, vars: &Vars) -> parser::Mount {
    parser::Mount {
        typ: m.typ.clone(),
        from: m.from.as_deref().map(|s| interpolate(s, vars)),
        source: m.source.as_deref().map(|s| interpolate(s, vars)),
        target: m.target.as_deref().map(|s| interpolate(s, vars)),
        readonly: m.readonly,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> Vars {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn simple_and_braced() {
        let v = vars(&[("FOO", "bar"), ("N", "3")]);
        assert_eq!(interpolate("$FOO/x", &v), "bar/x");
        assert_eq!(interpolate("${FOO}baz", &v), "barbaz");
        assert_eq!(interpolate("v$N.$MISSING.end", &v), "v3..end");
        assert_eq!(interpolate(r"a\$FOO", &v), "a$FOO"); // escaped
    }

    #[test]
    fn modifiers() {
        let v = vars(&[("SET", "x"), ("EMPTY", "")]);
        assert_eq!(interpolate("${SET:-d}", &v), "x");
        assert_eq!(interpolate("${EMPTY:-d}", &v), "d"); // empty -> default with :-
        assert_eq!(interpolate("${EMPTY-d}", &v), ""); // empty is "set" for -
        assert_eq!(interpolate("${MISSING:-d}", &v), "d");
        assert_eq!(interpolate("${SET:+yes}", &v), "yes");
        assert_eq!(interpolate("${MISSING:+yes}", &v), "");
        assert_eq!(interpolate("${MISSING:-${SET}}", &v), "x"); // word interpolated
    }

    /// Cases ported from buildkit's shell lexer tests
    /// (moby/buildkit `frontend/dockerfile/shell/lex_test.go`), restricted to plain
    /// variable substitution — the part that applies to Dockerfile interpolation. The
    /// quote/word-splitting and pattern-op (`${v/a/b}`, `${#v}`, `${v##p}`) behaviours
    /// there are out of scope: a RUN's shell form is parsed by the guest shell, not here.
    #[test]
    fn buildkit_lex_cases() {
        let v = vars(&[("FOO", "bar"), ("BAR", "baz"), ("EMPTY", "")]);
        let cases: &[(&str, &str)] = &[
            ("$FOO", "bar"),
            ("${FOO}", "bar"),
            ("${FOO}x", "barx"),
            ("$FOO/x", "bar/x"),
            ("$NOPE", ""),
            ("${NOPE}", ""),
            (r"\$FOO", "$FOO"),
            ("$", "$"),
            ("foo$", "foo$"),
            ("${FOO:-def}", "bar"),
            ("${EMPTY:-def}", "def"),
            ("${NOPE:-def}", "def"),
            ("${EMPTY-def}", ""),
            ("${NOPE-def}", "def"),
            ("${FOO:+set}", "set"),
            ("${EMPTY:+set}", ""),
            ("${NOPE:+set}", ""),
            ("${FOO+set}", "set"),
            ("${EMPTY+set}", "set"),
            ("${NOPE+set}", ""),
            ("${FOO:-${BAR}}", "bar"),
            ("${NOPE:-${BAR}}", "baz"),
            ("a $FOO b ${BAR} c", "a bar b baz c"),
        ];
        for (input, want) in cases {
            assert_eq!(&interpolate(input, &v), want, "input {input:?}");
        }
    }

    #[test]
    fn expand_run_and_copy() {
        let v = vars(&[("UID", "1000"), ("D", "bookworm")]);
        let run = Instruction::Run(parser::Run {
            cmd: Cmdline::Shell("useradd -u ${UID} dev".into()),
            mounts: vec![],
            network: None,
            security: None,
        });
        match expand_instruction(&run, &v) {
            Instruction::Run(r) => assert_eq!(r.cmd, Cmdline::Shell("useradd -u 1000 dev".into())),
            _ => panic!(),
        }
        let copy = Instruction::Copy(parser::Copy {
            sources: vec!["a-$D".into()],
            dest: "/x/$D/".into(),
            from: Some("stage-$D".into()),
            chown: Some("$UID:$UID".into()),
            chmod: None,
            link: true,
        });
        match expand_instruction(&copy, &v) {
            Instruction::Copy(c) => {
                assert_eq!(c.sources, vec!["a-bookworm".to_string()]);
                assert_eq!(c.dest, "/x/bookworm/");
                assert_eq!(c.from.as_deref(), Some("stage-bookworm"));
                assert_eq!(c.chown.as_deref(), Some("1000:1000"));
            }
            _ => panic!(),
        }
    }
}
