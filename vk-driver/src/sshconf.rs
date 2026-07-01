//! A small `~/.ssh/config` reader: resolve a chosen set of `Host` aliases to their
//! `HostName`/`User`/`Port`/`IdentityFile`, so `vk launch --ssh-host <alias>` can
//! expose only those targets to the guest (a minimal injected config + an agent filtered
//! to just those keys). Deliberately narrow: exact-alias `Host` blocks with the four keys
//! above — no `Match`, `Include`, or wildcard pattern matching.

use std::path::{Path, PathBuf};

/// A resolved `Host` alias from `~/.ssh/config`.
#[derive(Debug, Clone, PartialEq)]
pub struct HostEntry {
    pub alias: String,
    /// real host to connect to (defaults to the alias if no `HostName`)
    pub hostname: String,
    pub user: Option<String>,
    pub port: Option<u16>,
    /// `IdentityFile`s, `~`-expanded — the private keys; their `.pub` siblings drive the
    /// agent key filter.
    pub identity_files: Vec<PathBuf>,
}

impl HostEntry {
    /// A minimal guest stanza: the alias mapped to its host/user/port. No `IdentityFile`
    /// (the keys reach the guest through the forwarded agent, not as files).
    pub fn stanza(&self) -> String {
        let mut s = format!("Host {}\n    HostName {}\n", self.alias, self.hostname);
        if let Some(u) = &self.user {
            s.push_str(&format!("    User {u}\n"));
        }
        if let Some(p) = self.port {
            s.push_str(&format!("    Port {p}\n"));
        }
        s
    }
}

/// Expand a leading `~` in an ssh-config path against `home`.
fn expand_home(value: &str, home: &Path) -> PathBuf {
    if let Some(rest) = value.strip_prefix("~/") {
        home.join(rest)
    } else if value == "~" {
        home.to_path_buf()
    } else {
        PathBuf::from(value)
    }
}

/// Split an ssh-config line into `(keyword, value)`. ssh accepts `Key value` and
/// `Key=value`; the keyword is case-insensitive. Returns `None` for blank/comment lines.
fn split_kv(line: &str) -> Option<(String, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (k, v) = line
        .split_once(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or((line, ""));
    Some((
        k.to_ascii_lowercase(),
        v.trim_start_matches(['=', ' ', '\t']),
    ))
}

/// Resolve each requested alias to a [`HostEntry`] from `config` text. An alias matches a
/// `Host` block listing it as an exact token; the first such block wins and later keys for
/// the same alias are ignored (first-match, like ssh). Unknown aliases are skipped.
pub fn resolve(config: &str, aliases: &[String], home: &Path) -> Vec<HostEntry> {
    aliases
        .iter()
        .filter_map(|alias| resolve_one(config, alias, home))
        .collect()
}

fn resolve_one(config: &str, alias: &str, home: &Path) -> Option<HostEntry> {
    let mut in_block = false;
    let mut entry: Option<HostEntry> = None;
    for line in config.lines() {
        let Some((key, value)) = split_kv(line) else {
            continue;
        };
        if key == "host" {
            if entry.is_some() {
                break; // reached the next Host block — first match is done
            }
            in_block = value.split_whitespace().any(|p| p == alias);
            if in_block {
                entry = Some(HostEntry {
                    alias: alias.to_string(),
                    hostname: alias.to_string(),
                    user: None,
                    port: None,
                    identity_files: Vec::new(),
                });
            }
            continue;
        }
        if !in_block {
            continue;
        }
        let e = entry.as_mut().expect("in_block implies entry");
        match key.as_str() {
            "hostname" if !value.is_empty() => e.hostname = value.to_string(),
            "user" if !value.is_empty() => e.user = Some(value.to_string()),
            "port" => e.port = value.parse().ok(),
            "identityfile" if !value.is_empty() => e.identity_files.push(expand_home(value, home)),
            _ => {}
        }
    }
    entry
}

#[cfg(test)]
mod tests {
    use super::*;

    const CFG: &str = "\
# personal hosts
Host github
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_github

Host corp prod
    HostName server.corp.example.com
    Port 2222
    IdentityFile ~/.ssh/id_corp
    IdentityFile ~/.ssh/id_corp_backup

Host nokey
    HostName plain.example.com
";

    #[test]
    fn resolves_a_simple_host() {
        let home = Path::new("/home/u");
        let got = resolve(CFG, &["github".into()], home);
        assert_eq!(
            got,
            vec![HostEntry {
                alias: "github".into(),
                hostname: "github.com".into(),
                user: Some("git".into()),
                port: None,
                identity_files: vec![PathBuf::from("/home/u/.ssh/id_github")],
            }]
        );
    }

    #[test]
    fn matches_alias_among_multiple_patterns_and_multiple_keys() {
        let home = Path::new("/home/u");
        let got = resolve(CFG, &["prod".into()], home);
        let e = &got[0];
        assert_eq!(e.hostname, "server.corp.example.com");
        assert_eq!(e.port, Some(2222));
        assert_eq!(
            e.identity_files,
            vec![
                PathBuf::from("/home/u/.ssh/id_corp"),
                PathBuf::from("/home/u/.ssh/id_corp_backup"),
            ]
        );
    }

    #[test]
    fn host_with_no_hostname_defaults_to_alias_and_no_keys() {
        let got = resolve(CFG, &["nokey".into()], Path::new("/home/u"));
        assert_eq!(got[0].hostname, "plain.example.com");
        assert!(got[0].identity_files.is_empty());
        // unknown alias yields nothing
        assert!(resolve(CFG, &["missing".into()], Path::new("/home/u")).is_empty());
    }

    #[test]
    fn stanza_omits_identityfile_and_optional_fields() {
        let e = resolve(CFG, &["github".into()], Path::new("/home/u"))
            .pop()
            .unwrap();
        assert_eq!(
            e.stanza(),
            "Host github\n    HostName github.com\n    User git\n"
        );
        let n = resolve(CFG, &["nokey".into()], Path::new("/home/u"))
            .pop()
            .unwrap();
        assert_eq!(n.stanza(), "Host nokey\n    HostName plain.example.com\n");
    }

    #[test]
    fn accepts_equals_separator() {
        let cfg = "Host x\nHostName=example.net\nPort=22\n";
        let e = resolve(cfg, &["x".into()], Path::new("/h")).pop().unwrap();
        assert_eq!(e.hostname, "example.net");
        assert_eq!(e.port, Some(22));
    }
}
