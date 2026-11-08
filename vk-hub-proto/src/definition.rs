//! What a CI tools definition's Dockerfile declares its build reaches: each stage's
//! `# vk: allow-name=… allow-ip=…` lines, which a node holds the stage's RUN steps to. The hub
//! reads them to show an operator, from the definition it holds, where its builds may go; the
//! node's own build reads the same lines with `vk build`'s parser, which this reading agrees
//! with (vk-driver's tests check it does) and which alone validates them.

/// The comment prefix of a stage's `# vk:` lines.
const HINT_PREFIX: &str = "vk:";

/// A stage of a Dockerfile, and the egress its `# vk:` lines declare.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeclaredStage {
    /// Its `AS` name, or its index from 0 when it has none.
    pub name: String,
    /// What it declares, `None` when it declares nothing: then its RUN steps reach no network.
    pub egress: Option<DeclaredEgress>,
}

/// What a stage declares its RUN steps reach, each list in the order given.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeclaredEgress {
    /// Addresses and networks, `allow-ip=`.
    pub ips: Vec<String>,
    /// Host names, `allow-name=`.
    pub names: Vec<String>,
}

/// Every stage of `dockerfile`, in order, with what it declares; why not, for a file whose
/// `# vk:` lines are not about a stage, or are not `key=value` lists.
pub fn declared_egress(dockerfile: &str) -> Result<Vec<DeclaredStage>, String> {
    let escape = detect_escape(dockerfile);
    let mut stages = Vec::new();
    let mut hints: Vec<&str> = Vec::new();
    let mut line = String::new();
    let mut continuing = false;
    let mut instructions: Vec<(String, Vec<&str>)> = Vec::new();
    for raw in dockerfile.lines() {
        let trimmed = raw.trim_end();
        if trimmed.trim_start().starts_with('#') {
            // Comments are dropped, inside a continuation too, but a `# vk:` one outside it is
            // held for the coming instruction.
            if !continuing && let Some(body) = hint_body(trimmed.trim_start()) {
                hints.push(body.trim());
            }
            continue;
        }
        if !continuing {
            if trimmed.trim().is_empty() {
                continue;
            }
            line.clear();
        }
        let (content, more) = match trimmed.strip_suffix(escape) {
            Some(stripped) => (stripped, true),
            None => (trimmed, false),
        };
        let piece = content.trim();
        if !piece.is_empty() {
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(piece);
        }
        continuing = more;
        if !continuing && !line.trim().is_empty() {
            instructions.push((line.trim().to_string(), std::mem::take(&mut hints)));
        }
    }
    if continuing && !line.trim().is_empty() {
        instructions.push((line.trim().to_string(), std::mem::take(&mut hints)));
    }
    if !hints.is_empty() {
        return Err(format!(
            "`# {HINT_PREFIX}` at the end of the file is about no stage"
        ));
    }
    for (text, hints) in instructions {
        let mut words = text.split_whitespace();
        let keyword = words.next().unwrap_or_default();
        if !keyword.eq_ignore_ascii_case("FROM") {
            if !hints.is_empty() {
                return Err(format!(
                    "`# {HINT_PREFIX}` is about a stage, so it must precede a FROM; this one \
                     precedes {}",
                    keyword.to_ascii_uppercase()
                ));
            }
            continue;
        }
        let words: Vec<&str> = words.collect();
        let name = match words.as_slice() {
            [.., as_, name] if as_.eq_ignore_ascii_case("as") => (*name).to_string(),
            _ => stages.len().to_string(),
        };
        stages.push(DeclaredStage {
            name,
            egress: egress_of(&hints)?,
        });
    }
    Ok(stages)
}

/// What a stage's `# vk:` lines, `hints`, declare; other keys are `vk build`'s to read.
fn egress_of(hints: &[&str]) -> Result<Option<DeclaredEgress>, String> {
    let mut egress: Option<DeclaredEgress> = None;
    for field in hints.iter().flat_map(|h| h.split_whitespace()) {
        let Some((key, value)) = field.split_once('=') else {
            return Err(format!("`# {HINT_PREFIX} {field}`: expected key=value"));
        };
        let list = match key {
            "allow-ip" => &mut egress.get_or_insert_with(DeclaredEgress::default).ips,
            "allow-name" => &mut egress.get_or_insert_with(DeclaredEgress::default).names,
            _ => continue,
        };
        list.extend(
            value
                .split(',')
                .filter(|v| !v.is_empty())
                .map(str::to_string),
        );
    }
    Ok(egress)
}

/// The body of a `# vk:` line, or `None` for any other comment: one `#` stripped, so `## vk:`
/// is commented out, and the prefix in any case.
fn hint_body(comment: &str) -> Option<&str> {
    let rest = comment.strip_prefix('#')?.trim_start();
    let (prefix, body) = rest.split_at_checked(HINT_PREFIX.len())?;
    prefix.eq_ignore_ascii_case(HINT_PREFIX).then_some(body)
}

/// The escape character an `# escape=` parser directive sets, before the first instruction.
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

/// Dockerfiles whose declarations vk-driver's tests check `vk build` reads alike.
#[doc(hidden)]
pub const SAMPLES: [&str; 6] = [
    "FROM alpine AS offline\n\
     # vk: allow-name=cache.nixos.org,github.com mem=2G\n\
     # vk: allow-ip=10.0.0.0/8:443 allow-name=codeload.github.com\n\
     FROM alpine AS online\n\
     # vk: allow-name=\n\
     FROM alpine AS sealed\n",
    "# escape=`\n# vk: allow-name=a.example\nFROM alpine AS a\nRUN echo `\n  # vk: allow-name=b.example\n  done\n",
    "FROM alpine\n## vk: allow-name=off.example\nFROM alpine\n# VK: allow-name=up.example\nFROM --platform=linux/amd64 alpine as Up\n",
    "# vk: allow-ip=192.0.2.1 cpus=2\nFROM alpine \\\n  AS fetch\nRUN wget x\nFROM scratch AS tools\nCOPY --from=fetch /x /x\n",
    "FROM alpine AS one\n\n# vk: allow-name=x.example\n\n# a comment\nFROM alpine AS two\n",
    "",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn stage(name: &str, ips: &[&str], names: &[&str]) -> DeclaredStage {
        DeclaredStage {
            name: name.into(),
            egress: Some(DeclaredEgress {
                ips: ips.iter().map(|s| s.to_string()).collect(),
                names: names.iter().map(|s| s.to_string()).collect(),
            }),
        }
    }

    fn bare(name: &str) -> DeclaredStage {
        DeclaredStage {
            name: name.into(),
            egress: None,
        }
    }

    #[test]
    fn each_stage_declares_what_its_hints_list() {
        assert_eq!(
            declared_egress(SAMPLES[0]).unwrap(),
            [
                bare("offline"),
                stage(
                    "online",
                    &["10.0.0.0/8:443"],
                    &["cache.nixos.org", "github.com", "codeload.github.com"]
                ),
                // Declared, and empty: no network at all.
                stage("sealed", &[], &[]),
            ]
        );
        // A hint inside a continuation is a comment, as is `## vk:`; the prefix in any case.
        assert_eq!(
            declared_egress(SAMPLES[1]).unwrap(),
            [stage("a", &[], &["a.example"])]
        );
        assert_eq!(
            declared_egress(SAMPLES[2]).unwrap(),
            [bare("0"), bare("1"), stage("Up", &[], &["up.example"])]
        );
        assert_eq!(
            declared_egress(SAMPLES[3]).unwrap(),
            [stage("fetch", &["192.0.2.1"], &[]), bare("tools")]
        );
        assert_eq!(
            declared_egress(SAMPLES[4]).unwrap(),
            [bare("one"), stage("two", &[], &["x.example"])]
        );
        assert_eq!(declared_egress(SAMPLES[5]).unwrap(), []);
    }

    #[test]
    fn a_hint_about_no_stage_is_refused() {
        let err = |src: &str| declared_egress(src).unwrap_err();
        assert!(err("# vk: allow-name=a\nRUN a\n").contains("must precede a FROM"));
        assert!(err("FROM a\n# vk: allow-name=a\n").contains("about no stage"));
        assert!(err("# vk: allow-name\nFROM a\n").contains("expected key=value"));
    }
}
