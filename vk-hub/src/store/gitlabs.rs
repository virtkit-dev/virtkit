//! The GitLab instances the hub takes jobs from, each under a short name the hub gives it. A
//! jobs key bound to one may submit only that instance's jobs, and only those of the projects
//! its ceiling lists; the name is what registry namespaces call `{gitlab}`.

use anyhow::{Context, Result};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use super::keys::{API_KEYS, KeyRow};
use super::{Db, append_audit, decode, encode};

/// Key: the instance's name. Value: JSON [`GitlabRow`].
pub(super) const GITLABS: TableDefinition<&str, &[u8]> = TableDefinition::new("gitlabs");

/// The longest an instance's name may be.
pub const MAX_GITLAB_NAME: usize = 32;

/// A GitLab instance as stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitlabRow {
    /// Its URL as [`normalize_gitlab_url`] writes it.
    pub url: String,
    pub created_at: u64,
    pub created_by: String,
}

/// A project a jobs key may submit jobs of: by GitLab's ID, with the path it has there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectCeiling {
    pub id: u64,
    pub path: String,
}

impl ProjectCeiling {
    /// `<id>:<path>`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let (id, path) = s
            .split_once(':')
            .ok_or_else(|| format!("{s:?}: expected <project id>:<project path>"))?;
        let id: u64 = id
            .parse()
            .ok()
            .filter(|id| *id > 0)
            .ok_or_else(|| format!("{id:?} is not a project ID"))?;
        if !valid_project_path(path) {
            return Err(format!("{path:?} is not a project path"));
        }
        Ok(ProjectCeiling {
            id,
            path: path.to_string(),
        })
    }
}

impl std::fmt::Display for ProjectCeiling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.id, self.path)
    }
}

/// Whether `s` is a GitLab project's full path: `/`-separated components of letters, digits,
/// `_`, `.` and `-`, as GitLab allows them.
pub fn valid_project_path(s: &str) -> bool {
    s.len() <= 255
        && s.split('/').all(|c| {
            !c.is_empty()
                && c.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
        })
}

/// Whether `s` may name an instance: a repository path component, as registry namespaces
/// put it in paths: lowercase letters and digits, with `-` inside.
pub fn valid_gitlab_name(s: &str) -> bool {
    let b = s.as_bytes();
    let alnum = |x: &u8| x.is_ascii_lowercase() || x.is_ascii_digit();
    s.len() <= MAX_GITLAB_NAME
        && b.first().is_some_and(alnum)
        && b.last().is_some_and(alnum)
        && b.iter().all(|x| alnum(x) || *x == b'-')
}

/// `url` as the hub compares instance URLs: `http` or `https`, lowercase scheme and host, no
/// default port, no trailing `/`, no query, fragment nor credentials. `None` for anything else.
pub fn normalize_gitlab_url(url: &str) -> Option<String> {
    let url = url.trim();
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() || authority.contains(['@', '?', '#']) || path.contains(['?', '#']) {
        return None;
    }
    let mut authority = authority.to_ascii_lowercase();
    let default = if scheme == "https" { ":443" } else { ":80" };
    if let Some(host) = authority.strip_suffix(default) {
        authority = host.to_string();
    }
    let path = path.trim_end_matches('/');
    Some(if path.is_empty() {
        format!("{scheme}://{authority}")
    } else {
        format!("{scheme}://{authority}/{path}")
    })
}

impl Db {
    /// Add instance `name` at `url`, audited as `actor`'s.
    pub fn add_gitlab(&self, name: &str, url: &str, actor: &str, now: u64) -> Result<GitlabRow> {
        if !valid_gitlab_name(name) {
            anyhow::bail!(
                "{name:?}: an instance's name is 1 to {MAX_GITLAB_NAME} lowercase letters, \
                 digits and '-', starting and ending with a letter or digit"
            );
        }
        let Some(url) = normalize_gitlab_url(url) else {
            anyhow::bail!("{url:?} is not an http(s) URL");
        };
        let txn = self.db.begin_write().context("starting a write")?;
        let row = {
            let mut table = txn.open_table(GITLABS)?;
            if table.get(name)?.is_some() {
                anyhow::bail!("there is already an instance named {name}");
            }
            for entry in table.iter()? {
                let (other, value) = entry?;
                if decode::<GitlabRow>(value.value())?.url == url {
                    anyhow::bail!("{url} is instance {} already", other.value());
                }
            }
            let row = GitlabRow {
                url,
                created_at: now,
                created_by: actor.to_string(),
            };
            table.insert(name, encode(&row)?.as_slice())?;
            row
        };
        let event = format!("{actor} added GitLab instance {name} at {}", row.url);
        append_audit(&txn, None, actor, &event, now)?;
        txn.commit().context("adding a GitLab instance")?;
        Ok(row)
    }

    pub fn gitlab(&self, name: &str) -> Result<Option<GitlabRow>> {
        let txn = self.db.begin_read().context("starting a read")?;
        txn.open_table(GITLABS)?
            .get(name)?
            .map(|g| decode(g.value()))
            .transpose()
    }

    /// Every instance, by name.
    pub fn gitlabs(&self) -> Result<Vec<(String, GitlabRow)>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(GITLABS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (name, value) = entry?;
            out.push((name.value().to_string(), decode(value.value())?));
        }
        Ok(out)
    }

    /// Remove instance `name`, audited as `actor`'s, and return whether it existed.
    /// Refused while a working key is bound to it.
    pub fn remove_gitlab(&self, name: &str, actor: &str, now: u64) -> Result<bool> {
        let txn = self.db.begin_write().context("starting a write")?;
        {
            let keys = txn.open_table(API_KEYS)?;
            for entry in keys.iter()? {
                let row = decode::<KeyRow>(entry?.1.value())?;
                if row.gitlab.as_deref() == Some(name) && row.live(now) {
                    anyhow::bail!(
                        "key {} is bound to instance {name}; revoke it first",
                        row.name
                    );
                }
            }
        }
        let removed = txn.open_table(GITLABS)?.remove(name)?.is_some();
        if removed {
            append_audit(
                &txn,
                None,
                actor,
                &format!("{actor} removed GitLab instance {name}"),
                now,
            )?;
        }
        txn.commit().context("removing a GitLab instance")?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_normalize_to_one_form() {
        for (url, want) in [
            (
                "https://GitLab.Example.com/",
                Some("https://gitlab.example.com"),
            ),
            (
                "https://gitlab.example.com:443",
                Some("https://gitlab.example.com"),
            ),
            ("http://gl:8080/sub/", Some("http://gl:8080/sub")),
            ("HTTPS://gl/a/b", Some("https://gl/a/b")),
            ("ftp://gl", None),
            ("https://u:p@gl", None),
            ("https://gl/?x", None),
            ("gl", None),
            ("https:///x", None),
            ("https://gl/a b", None),
            ("https://gl/a\u{1b}b", None),
        ] {
            assert_eq!(normalize_gitlab_url(url).as_deref(), want, "{url}");
        }
    }

    #[test]
    fn names_are_path_components() {
        assert!(valid_gitlab_name("gl"));
        assert!(valid_gitlab_name("gitlab-2"));
        for bad in ["", "-gl", "gl-", "GL", "g_l", "g.l", &"a".repeat(33)] {
            assert!(!valid_gitlab_name(bad), "{bad}");
        }
    }

    #[test]
    fn project_ceilings_parse() {
        let p = ProjectCeiling::parse("42:wab/core").unwrap();
        assert_eq!((p.id, p.path.as_str()), (42, "wab/core"));
        assert_eq!(p.to_string(), "42:wab/core");
        assert!(ProjectCeiling::parse("x:wab").is_err());
        assert!(ProjectCeiling::parse("42").is_err());
        assert!(ProjectCeiling::parse("42:").is_err());
        assert!(ProjectCeiling::parse("0:wab").is_err());
        assert!(ProjectCeiling::parse("42:wab/\u{7}x").is_err());
        assert!(ProjectCeiling::parse("42:wab//x").is_err());
        assert!(ProjectCeiling::parse("42:wab/ x").is_err());
    }
}
