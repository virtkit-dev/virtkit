//! The GitLab instances the hub takes jobs from, each under a short name the hub gives it: an
//! approved server, whose relays submit its jobs ([`super::relays`]). The name is what registry
//! namespaces call `{gitlab}`.

use anyhow::{Context, Result};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use super::approvals::{REJECTED_GITLABS, forget_projects_of};
use super::egress::{EGRESS_MUTES, EGRESS_SUBJECT_ORDER, Mute};
use super::observed::OBSERVED_SUBJECTS;
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

/// A refusal from [`Db::add_gitlab`] or [`Db::remove_gitlab`] — a bad name or URL, one taken, a
/// relay bound to the instance, or one changed since asked — or from a decision on a server or
/// its projects ([`super::approvals`]). Its message can be shown to the user.
#[derive(Debug)]
pub struct GitlabRefused(pub String);

impl std::fmt::Display for GitlabRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for GitlabRefused {}

pub(super) fn refused(why: impl Into<String>) -> anyhow::Error {
    GitlabRefused(why.into()).into()
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

/// Whether egress rows, live mutes or Observed traffic are kept for instance `name`'s
/// projects at `now`: keyed by its name, they would be taken for those of a new instance of
/// that name.
fn egress_of(txn: &redb::WriteTransaction, name: &str, now: u64) -> Result<bool> {
    // Subjects `gitlab:<name>:<project ID>`, `;` sorting right after `:`.
    let (lo, hi) = (format!("gitlab:{name}:"), format!("gitlab:{name};"));
    let (lo, hi) = (lo.as_str(), hi.as_str());
    if txn
        .open_table(EGRESS_SUBJECT_ORDER)?
        .range((lo, "", "", 0, "")..(hi, "", "", 0, ""))?
        .next()
        .is_some()
        || txn
            .open_table(OBSERVED_SUBJECTS)?
            .range(lo..hi)?
            .next()
            .is_some()
    {
        return Ok(true);
    }
    for entry in txn.open_table(EGRESS_MUTES)?.range(lo..hi)? {
        let mute = decode::<Mute>(entry?.1.value())?;
        if mute.live(now) {
            return Ok(true);
        }
    }
    Ok(false)
}

impl Db {
    /// Add instance `name` at `url`, audited as `actor`'s; refused while egress records of
    /// an earlier instance of that name remain.
    pub fn add_gitlab(&self, name: &str, url: &str, actor: &str, now: u64) -> Result<GitlabRow> {
        if !valid_gitlab_name(name) {
            return Err(refused(format!(
                "{name:?}: an instance's name is 1 to {MAX_GITLAB_NAME} lowercase letters, \
                 digits and '-', starting and ending with a letter or digit"
            )));
        }
        let Some(url) = normalize_gitlab_url(url) else {
            return Err(refused(format!("{url:?} is not an http(s) URL")));
        };
        let txn = self.db.begin_write().context("starting a write")?;
        let row = {
            let mut table = txn.open_table(GITLABS)?;
            if table.get(name)?.is_some() {
                return Err(refused(format!(
                    "there is already an instance named {name}"
                )));
            }
            if egress_of(&txn, name, now)? {
                return Err(refused(format!(
                    "the egress records of an earlier instance named {name} remain, until its \
                     jobs leave the history and its projects' mutes end; name this one otherwise"
                )));
            }
            for entry in table.iter()? {
                let (other, value) = entry?;
                if decode::<GitlabRow>(value.value())?.url == url {
                    return Err(refused(format!(
                        "{url} is instance {} already",
                        other.value()
                    )));
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
        // Approving a server rejected before ends its rejection.
        txn.open_table(REJECTED_GITLABS)?.remove(row.url.as_str())?;
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

    /// Remove instance `name` and forget its projects, audited as `actor`'s, and return
    /// whether it existed. Refused while a relay is bound to it.
    pub fn remove_gitlab(&self, name: &str, actor: &str, now: u64) -> Result<bool> {
        self.remove_gitlab_if(name, None, actor, now)
    }

    /// [`Db::remove_gitlab`], refused unless instance `name` is still `seen`: a namesake
    /// added since is not the one an operator was asked about.
    pub fn remove_gitlab_as_seen(
        &self,
        name: &str,
        seen: &GitlabRow,
        actor: &str,
        now: u64,
    ) -> Result<bool> {
        self.remove_gitlab_if(name, Some(seen), actor, now)
    }

    fn remove_gitlab_if(
        &self,
        name: &str,
        seen: Option<&GitlabRow>,
        actor: &str,
        now: u64,
    ) -> Result<bool> {
        let txn = self.db.begin_write().context("starting a write")?;
        if let Some(seen) = seen
            && let Some(now_row) = txn.open_table(GITLABS)?.get(name)?
            && decode::<GitlabRow>(now_row.value())? != *seen
        {
            return Err(refused(format!(
                "instance {name} changed since you were asked; look again"
            )));
        }
        let url = txn
            .open_table(GITLABS)?
            .get(name)?
            .map(|g| decode::<GitlabRow>(g.value()))
            .transpose()?
            .map(|row| row.url);
        if let Some(url) = &url
            && let Some(relay) = super::relays::relay_bound_to(&txn, url)?
        {
            return Err(refused(format!(
                "relay {relay} is bound to instance {name}; remove it first"
            )));
        }
        let removed = txn.open_table(GITLABS)?.remove(name)?.is_some();
        if removed {
            forget_projects_of(&txn, name)?;
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
    fn a_name_is_not_reused_while_its_egress_records_remain() {
        use crate::egress::blocked::Subject;
        let db = Db::open_memory().unwrap();
        db.add_gitlab("gl", "https://a.example", "u", 1).unwrap();
        let subject = Subject::Gitlab {
            instance: "gl".into(),
            project_id: 4,
        };
        db.egress_mute(&subject, "p", "noisy", None, "u", 1)
            .unwrap();
        assert!(db.remove_gitlab("gl", "u", 2).unwrap());
        let err = db
            .add_gitlab("gl", "https://b.example", "u", 3)
            .unwrap_err();
        assert!(
            err.to_string().contains("earlier instance named gl"),
            "{err:#}"
        );
        assert!(db.egress_unmute(&subject, "u", 4).unwrap());
        // A mute that has ended holds nothing back.
        db.egress_mute(&subject, "p", "noisy", Some(6), "u", 5)
            .unwrap();
        db.add_gitlab("gl", "https://b.example", "u", 6).unwrap();
    }

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
}
