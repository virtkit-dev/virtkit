//! The install media the hub uploaded to its registries ([`crate::media`]): what each is,
//! where it came from and under which licence, as the operators describe it, and which
//! registries hold it. Whether jobs may use one is the fleet-wide `executor.windows_media`
//! setting, read rather than kept twice.

use anyhow::{Context, Result, bail};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::settings::{SETTINGS, fleet_value, set_in};
use super::{Db, append_audit, decode, encode, short};

/// Key: the medium's sha256, hex. Value: JSON [`MediumRow`].
pub(super) const MEDIA: TableDefinition<&str, &[u8]> = TableDefinition::new("media");

/// The setting that approves media for jobs.
pub const APPROVAL_KEY: &str = "executor.windows_media";

/// The longest a one-line field may be.
pub const MAX_LINE: usize = 256;
/// The longest a free-text field may be.
pub const MAX_TEXT: usize = 8 * 1024;
/// The most media the hub keeps: as many as the fleet-wide approval list may name.
pub const MAX_MEDIA: usize = vk_hub_proto::settings::MAX_DIGESTS;
/// The most places a medium is recorded at, registries and repository paths.
pub const MAX_LOCATIONS: usize = 32;
/// The most source URLs a medium lists, and the longest each may be.
pub const MAX_SOURCES: usize = 8;
pub const MAX_URL: usize = 2048;

/// What a medium is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MediumKind {
    /// Windows installation media.
    Windows,
    /// Drivers for Windows guests, such as virtio-win.
    Drivers,
    #[default]
    Other,
}

impl MediumKind {
    pub const ALL: [MediumKind; 3] = [MediumKind::Windows, MediumKind::Drivers, MediumKind::Other];

    pub fn name(self) -> &'static str {
        match self {
            MediumKind::Windows => "windows",
            MediumKind::Drivers => "drivers",
            MediumKind::Other => "other",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            MediumKind::Windows => "Windows installation",
            MediumKind::Drivers => "Drivers",
            MediumKind::Other => "Other",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.name() == s)
            .with_context(|| format!("{s:?}: a medium's kind is windows, drivers or other"))
    }
}

/// The licence a medium is used under.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LicenseKind {
    #[default]
    Unknown,
    Evaluation,
    Volume,
    Retail,
    Oem,
    OpenSource,
    Other,
}

impl LicenseKind {
    pub const ALL: [LicenseKind; 7] = [
        LicenseKind::Unknown,
        LicenseKind::Evaluation,
        LicenseKind::Volume,
        LicenseKind::Retail,
        LicenseKind::Oem,
        LicenseKind::OpenSource,
        LicenseKind::Other,
    ];

    pub fn name(self) -> &'static str {
        match self {
            LicenseKind::Unknown => "unknown",
            LicenseKind::Evaluation => "evaluation",
            LicenseKind::Volume => "volume",
            LicenseKind::Retail => "retail",
            LicenseKind::Oem => "oem",
            LicenseKind::OpenSource => "open-source",
            LicenseKind::Other => "other",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            LicenseKind::Unknown => "Not stated",
            LicenseKind::Evaluation => "Evaluation",
            LicenseKind::Volume => "Volume licensing",
            LicenseKind::Retail => "Retail",
            LicenseKind::Oem => "OEM",
            LicenseKind::OpenSource => "Open source",
            LicenseKind::Other => "Other",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.name() == s)
            .with_context(|| {
                format!(
                    "{s:?}: a licence is one of {}",
                    Self::ALL.map(|k| k.name()).join(", ")
                )
            })
    }
}

fn is_empty(s: &str) -> bool {
    s.is_empty()
}

/// What operators say of a medium: editable after upload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediumInfo {
    #[serde(default)]
    pub kind: MediumKind,
    /// Where it was downloaded from, the first the page it was found on or the link followed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    /// When it was downloaded, `YYYY-MM-DD`.
    #[serde(default, skip_serializing_if = "is_empty")]
    pub obtained: String,
    /// What it installs: `Windows Server 2025`, `virtio-win`.
    #[serde(default, skip_serializing_if = "is_empty")]
    pub product: String,
    #[serde(default, skip_serializing_if = "is_empty")]
    pub edition: String,
    #[serde(default, skip_serializing_if = "is_empty")]
    pub version: String,
    #[serde(default, skip_serializing_if = "is_empty")]
    pub build: String,
    #[serde(default, skip_serializing_if = "is_empty")]
    pub language: String,
    #[serde(default, skip_serializing_if = "is_empty")]
    pub arch: String,
    #[serde(default)]
    pub license: LicenseKind,
    /// What the licence allows and requires.
    #[serde(default, skip_serializing_if = "is_empty")]
    pub license_terms: String,
    /// How to renew or replace it.
    #[serde(default, skip_serializing_if = "is_empty")]
    pub renewal: String,
    /// When it must be renewed or replaced by, `YYYY-MM-DD`.
    #[serde(default, skip_serializing_if = "is_empty")]
    pub expires: String,
    #[serde(default, skip_serializing_if = "is_empty")]
    pub notes: String,
}

/// A change to a [`MediumInfo`]: each field given replaces the one held, an empty one
/// clearing it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediumEdit {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<MediumKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obtained: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<LicenseKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_terms: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl MediumEdit {
    /// `info` with this change, checked; the names of the fields it changed.
    pub fn apply(&self, info: &MediumInfo) -> Result<(MediumInfo, Vec<&'static str>)> {
        let mut out = info.clone();
        let mut changed = Vec::new();
        macro_rules! set {
            ($($field:ident),*) => {$(
                if let Some(v) = &self.$field && *v != out.$field {
                    out.$field = v.clone();
                    changed.push(stringify!($field));
                }
            )*};
        }
        set!(
            kind,
            sources,
            obtained,
            product,
            edition,
            version,
            build,
            language,
            arch,
            license,
            license_terms,
            renewal,
            expires,
            notes
        );
        out.check()?;
        Ok((out, changed))
    }
}

/// Whether `s` is a date of the Gregorian calendar, `YYYY-MM-DD`.
pub fn valid_date(s: &str) -> bool {
    let b = s.as_bytes();
    if !(b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && [0..4, 5..7, 8..10]
            .iter()
            .all(|r| b[r.clone()].iter().all(u8::is_ascii_digit)))
    {
        return false;
    }
    let (Ok(year), Ok(month), Ok(day)) = (
        s[0..4].parse::<u32>(),
        s[5..7].parse::<u32>(),
        s[8..10].parse::<u32>(),
    ) else {
        return false;
    };
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

/// Whether `url` is an `http` or `https` URL naming a host, with no whitespace or control
/// character, of at most [`MAX_URL`] bytes.
fn valid_source(url: &str) -> bool {
    let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    url.len() <= MAX_URL
        && !host.is_empty()
        && !host.starts_with(':')
        && !url.chars().any(|c| c.is_whitespace() || c.is_control())
}

impl MediumInfo {
    /// That every field is within its bounds and shape.
    pub fn check(&self) -> Result<()> {
        let line = |name: &str, v: &str| -> Result<()> {
            if v.chars().count() > MAX_LINE || v.chars().any(char::is_control) {
                bail!("{name}: at most {MAX_LINE} characters, on one line");
            }
            Ok(())
        };
        let text = |name: &str, v: &str| -> Result<()> {
            if v.len() > MAX_TEXT || v.chars().any(|c| c.is_control() && c != '\n') {
                bail!("{name}: at most {MAX_TEXT} bytes of text");
            }
            Ok(())
        };
        for (name, v) in [
            ("product", &self.product),
            ("edition", &self.edition),
            ("version", &self.version),
            ("build", &self.build),
            ("language", &self.language),
            ("arch", &self.arch),
        ] {
            line(name, v)?;
        }
        for (name, v) in [
            ("license terms", &self.license_terms),
            ("renewal", &self.renewal),
            ("notes", &self.notes),
        ] {
            text(name, v)?;
        }
        for (name, v) in [("obtained", &self.obtained), ("expires", &self.expires)] {
            if !v.is_empty() && !valid_date(v) {
                bail!("{name}: {v:?} is not a date, YYYY-MM-DD");
            }
        }
        if self.sources.len() > MAX_SOURCES {
            bail!("at most {MAX_SOURCES} sources");
        }
        for url in &self.sources {
            if !valid_source(url) {
                bail!(
                    "{:?}: a source is an http(s) URL of at most {MAX_URL} bytes",
                    vk_hub_proto::display_safe(url)
                );
            }
        }
        Ok(())
    }
}

/// Where a registry holds a medium, as it confirmed when the hub uploaded it there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    /// The registry's ID.
    pub registry: String,
    /// The repository path its `files/` are under, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub under: Option<String>,
    /// Its tag in [`crate::media::DIR`].
    pub name: String,
    /// The manifest's digest, `sha256:<hex>`.
    pub manifest: String,
    pub at: u64,
    pub by: String,
}

/// A medium the hub uploaded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediumRow {
    /// The name it was uploaded under.
    pub file_name: String,
    pub size: u64,
    /// Its ISO 9660 volume label, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_label: Option<String>,
    pub added_at: u64,
    pub added_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edited_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edited_by: Option<String>,
    #[serde(flatten)]
    pub info: MediumInfo,
    /// Where registries hold it, one per registry and repository path, oldest first.
    #[serde(default)]
    pub locations: Vec<Location>,
}

/// A medium as the CLI shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Medium {
    pub sha256: String,
    #[serde(flatten)]
    pub row: MediumRow,
    /// Whether the fleet-wide `executor.windows_media` lists it.
    pub approved: bool,
}

/// What [`Db::add_medium`] did.
#[derive(Debug)]
pub struct Added {
    pub medium: Medium,
    /// Whether the hub knew it already, from another upload.
    pub known: bool,
    /// The nodes the approval steered.
    pub steered: Vec<String>,
}

/// The fleet-wide approved digests in `txn`.
fn approved_in(txn: &redb::ReadTransaction) -> Result<Vec<String>> {
    Ok(digests(fleet_value(
        &txn.open_table(SETTINGS)?,
        APPROVAL_KEY,
    )?))
}

fn digests(value: Option<Value>) -> Vec<String> {
    match value {
        Some(Value::Array(a)) => a
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// Approve `sha256` for jobs fleet-wide, or not, in `txn`, as `actor`: the nodes it steered,
/// `None` when it changed nothing.
fn approve_in(
    txn: &redb::WriteTransaction,
    sha256: &str,
    approve: bool,
    actor: &str,
    now: u64,
) -> Result<Option<Vec<String>>> {
    let mut list = digests(fleet_value(&txn.open_table(SETTINGS)?, APPROVAL_KEY)?);
    let had = list.iter().any(|d| d == sha256);
    if had == approve {
        return Ok(None);
    }
    if approve {
        if list.len() >= vk_hub_proto::settings::MAX_DIGESTS {
            bail!(
                "{APPROVAL_KEY} lists {} media already, the most it may; withdraw one first, or \
                 upload without approving",
                list.len()
            );
        }
        list.push(sha256.to_string());
    } else {
        list.retain(|d| d != sha256);
    }
    let value = (!list.is_empty()).then(|| Value::from(list));
    let (_, steered) = set_in(txn, None, APPROVAL_KEY, value, actor, now)?;
    Ok(Some(steered))
}

impl Db {
    /// Record medium `sha256` at `location`, audited as `location.by`. New media use `row`;
    /// known media keep their metadata and add or replace the matching location.
    /// With `approve`, also approve it for jobs fleet-wide, in the same transaction.
    pub fn add_medium(
        &self,
        sha256: &str,
        row: MediumRow,
        location: Location,
        approve: bool,
    ) -> Result<Added> {
        let (actor, now) = (location.by.clone(), location.at);
        let actor = actor.as_str();
        row.info.check()?;
        let txn = self.db.begin_write().context("starting a write")?;
        let (row, known) = {
            let mut table = txn.open_table(MEDIA)?;
            let existing = table
                .get(sha256)?
                .map(|g| decode::<MediumRow>(g.value()))
                .transpose()?;
            let known = existing.is_some();
            if !known && table.len()? >= MAX_MEDIA as u64 {
                bail!(
                    "the hub holds {MAX_MEDIA} media already, the most it keeps; remove one first"
                );
            }
            let mut row = existing.unwrap_or(row);
            row.locations
                .retain(|l| (&l.registry, &l.under) != (&location.registry, &location.under));
            if row.locations.len() >= MAX_LOCATIONS {
                bail!(
                    "medium {sha256} is recorded at {MAX_LOCATIONS} places already, the most it may"
                );
            }
            row.locations.push(location.clone());
            table.insert(sha256, encode(&row)?.as_slice())?;
            (row, known)
        };
        let event = format!(
            "{actor} uploaded medium {} ({}, {} bytes) to registry {}",
            short(sha256),
            row.file_name,
            row.size,
            location.registry
        );
        append_audit(&txn, None, actor, &event, now)?;
        let steered = if approve {
            approve_in(&txn, sha256, true, actor, now)?.unwrap_or_default()
        } else {
            Vec::new()
        };
        let approved = digests(fleet_value(&txn.open_table(SETTINGS)?, APPROVAL_KEY)?)
            .iter()
            .any(|d| d == sha256);
        txn.commit().context("recording a medium")?;
        Ok(Added {
            medium: Medium {
                sha256: sha256.to_string(),
                row,
                approved,
            },
            known,
            steered,
        })
    }

    /// Check room in the fleet-wide approval list when `approve` is set. The digest is not
    /// known before uploading, so a full list rejects even media it already approves.
    /// Uploading without approval bypasses this check.
    pub fn media_room(&self, approve: bool) -> Result<()> {
        let txn = self.db.begin_read().context("starting a read")?;
        let approved = approved_in(&txn)?.len();
        if approve && approved >= vk_hub_proto::settings::MAX_DIGESTS {
            bail!(
                "{APPROVAL_KEY} lists {approved} media already, the most it may; withdraw one \
                 first, or upload without approving"
            );
        }
        Ok(())
    }

    pub fn medium(&self, sha256: &str) -> Result<Option<Medium>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let approved = approved_in(&txn)?;
        let Some(row) = txn
            .open_table(MEDIA)?
            .get(sha256)?
            .map(|g| decode::<MediumRow>(g.value()))
            .transpose()?
        else {
            return Ok(None);
        };
        Ok(Some(Medium {
            sha256: sha256.to_string(),
            approved: approved.iter().any(|d| d == sha256),
            row,
        }))
    }

    /// Every medium, newest first.
    pub fn media(&self) -> Result<Vec<Medium>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let approved = approved_in(&txn)?;
        let mut out = Vec::new();
        for entry in txn.open_table(MEDIA)?.iter()? {
            let (key, value) = entry?;
            let sha256 = key.value().to_string();
            out.push(Medium {
                approved: approved.contains(&sha256),
                sha256,
                row: decode(value.value())?,
            });
        }
        out.sort_by(|a, b| (b.row.added_at, &b.sha256).cmp(&(a.row.added_at, &a.sha256)));
        Ok(out)
    }

    /// The one medium whose sha256 starts with `prefix`, of at least 8 lowercase hex digits.
    pub fn resolve_medium(&self, prefix: &str) -> Result<Medium> {
        if prefix.len() < 8
            || !prefix
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            bail!(
                "{}: name a medium by its sha256, or at least its first 8 hex digits",
                vk_hub_proto::display_safe(prefix)
            );
        }
        let mut found = self
            .media()?
            .into_iter()
            .filter(|m| m.sha256.starts_with(prefix));
        match (found.next(), found.next()) {
            (Some(m), None) => Ok(m),
            (None, _) => bail!("there is no medium {prefix}"),
            (Some(_), Some(_)) => bail!("{prefix} names more than one medium; give more digits"),
        }
    }

    /// Change what is said of medium `sha256` with `edit`, as `actor`, audited: the medium,
    /// `None` when there is none.
    pub fn edit_medium(
        &self,
        sha256: &str,
        edit: &MediumEdit,
        actor: &str,
        now: u64,
    ) -> Result<Option<Medium>> {
        let txn = self.db.begin_write().context("starting a write")?;
        {
            let mut table = txn.open_table(MEDIA)?;
            let Some(mut row) = table
                .get(sha256)?
                .map(|g| decode::<MediumRow>(g.value()))
                .transpose()?
            else {
                return Ok(None);
            };
            let (info, changed) = edit.apply(&row.info)?;
            if changed.is_empty() {
                drop(table);
                txn.abort().context("dropping a write")?;
                return self.medium(sha256);
            }
            row.info = info;
            row.edited_at = Some(now);
            row.edited_by = Some(actor.to_string());
            table.insert(sha256, encode(&row)?.as_slice())?;
            let event = format!(
                "{actor} edited medium {} ({}): {}",
                short(sha256),
                row.file_name,
                changed.join(", ")
            );
            append_audit(&txn, None, actor, &event, now)?;
        }
        txn.commit().context("editing a medium")?;
        self.medium(sha256)
    }

    /// Approve medium `sha256` for jobs fleet-wide, or withdraw it, as `actor`: whether it
    /// changed, and the nodes it steered.
    pub fn approve_medium(
        &self,
        sha256: &str,
        approve: bool,
        actor: &str,
        now: u64,
    ) -> Result<(bool, Vec<String>)> {
        let txn = self.db.begin_write().context("starting a write")?;
        if txn.open_table(MEDIA)?.get(sha256)?.is_none() {
            bail!("there is no medium {sha256}");
        }
        match approve_in(&txn, sha256, approve, actor, now)? {
            Some(steered) => {
                txn.commit().context("approving a medium")?;
                Ok((true, steered))
            }
            None => {
                txn.abort().context("dropping a write")?;
                Ok((false, Vec::new()))
            }
        }
    }

    /// Forget medium `sha256` and withdraw its fleet-wide approval, as `actor`, audited; the
    /// registries keep their copies. The medium, and the nodes it steered.
    pub fn remove_medium(
        &self,
        sha256: &str,
        actor: &str,
        now: u64,
    ) -> Result<Option<(Medium, Vec<String>)>> {
        let Some(medium) = self.medium(sha256)? else {
            return Ok(None);
        };
        let txn = self.db.begin_write().context("starting a write")?;
        if txn.open_table(MEDIA)?.remove(sha256)?.is_none() {
            txn.abort().context("dropping a write")?;
            return Ok(None);
        }
        let event = format!(
            "{actor} removed medium {} ({})",
            short(sha256),
            medium.row.file_name
        );
        append_audit(&txn, None, actor, &event, now)?;
        let steered = approve_in(&txn, sha256, false, actor, now)?.unwrap_or_default();
        txn.commit().context("removing a medium")?;
        Ok(Some((medium, steered)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "d0ef4502e350e3c6c53c15b1b3020d38a5ded011bf04998e950720ac8579b23d";
    const B: &str = "303f7ae40dad495d6ae474fdc571df58958a4dbc5c37a522d80f9a203867949d";

    fn row(name: &str) -> MediumRow {
        MediumRow {
            file_name: name.into(),
            size: 6_014_152_704,
            volume_label: Some("SSS_X64FREE_EN-US_DV9".into()),
            added_at: 1,
            added_by: "uid 1".into(),
            edited_at: None,
            edited_by: None,
            info: MediumInfo {
                kind: MediumKind::Windows,
                sources: vec!["https://go.microsoft.com/fwlink/?linkid=2293312".into()],
                obtained: "2026-11-09".into(),
                product: "Windows Server 2025".into(),
                build: "26100.1742".into(),
                license: LicenseKind::Evaluation,
                ..MediumInfo::default()
            },
            locations: Vec::new(),
        }
    }

    fn at(registry: &str, by: &str, at: u64) -> Location {
        Location {
            registry: registry.into(),
            under: None,
            name: "ws2025.iso".into(),
            manifest: format!("sha256:{B}"),
            at,
            by: by.into(),
        }
    }

    fn approved(db: &Db) -> Vec<String> {
        digests(
            db.settings_layers()
                .unwrap()
                .fleet
                .get(APPROVAL_KEY)
                .cloned(),
        )
    }

    #[test]
    fn a_medium_is_recorded_approved_edited_and_removed() {
        let db = Db::open_memory().unwrap();
        db.set_setting(None, APPROVAL_KEY, Some(Value::from(vec![B])), "op", 1)
            .unwrap();
        let added = db
            .add_medium(A, row("ws2025.iso"), at("r1", "uid 1", 2), true)
            .unwrap();
        assert!(!added.known && added.medium.approved);
        assert_eq!(approved(&db), vec![B.to_string(), A.to_string()]);

        // Uploaded again elsewhere: what was said of it stays, the registry is added.
        let again = db
            .add_medium(A, row("other.iso"), at("r2", "uid 2", 3), false)
            .unwrap();
        assert!(again.known);
        assert_eq!(again.medium.row.file_name, "ws2025.iso");
        assert_eq!(
            again
                .medium
                .row
                .locations
                .iter()
                .map(|l| l.registry.as_str())
                .collect::<Vec<_>>(),
            ["r1", "r2"]
        );

        let edit = MediumEdit {
            notes: Some("activated at build; 180 days".into()),
            build: Some("26100.1742".into()),
            ..MediumEdit::default()
        };
        let edited = db.edit_medium(A, &edit, "uid 3", 4).unwrap().unwrap();
        assert_eq!(edited.row.info.notes, "activated at build; 180 days");
        assert_eq!(edited.row.edited_by.as_deref(), Some("uid 3"));
        let bad = MediumEdit {
            expires: Some("someday".into()),
            ..MediumEdit::default()
        };
        assert!(db.edit_medium(A, &bad, "uid 3", 5).is_err());

        assert!(db.approve_medium(A, false, "uid 4", 6).unwrap().0);
        assert!(!db.approve_medium(A, false, "uid 4", 6).unwrap().0);
        assert!(!db.medium(A).unwrap().unwrap().approved);
        assert!(db.approve_medium(B, true, "uid 4", 6).is_err());
        assert_eq!(db.resolve_medium(&A[..8]).unwrap().sha256, A);

        db.approve_medium(A, true, "uid 4", 7).unwrap();
        let (removed, _) = db.remove_medium(A, "uid 5", 8).unwrap().unwrap();
        assert_eq!(removed.sha256, A);
        assert!(db.medium(A).unwrap().is_none());
        assert_eq!(approved(&db), vec![B.to_string()]);
        let audit = db.audits(None, 100).unwrap();
        for want in [
            "uploaded medium d0ef4502",
            "edited medium",
            "removed medium",
        ] {
            assert!(audit.iter().any(|e| e.event.contains(want)), "{want}");
        }
    }

    #[test]
    fn a_full_approval_list_records_nothing() {
        let db = Db::open_memory().unwrap();
        let full: Vec<String> = (0..vk_hub_proto::settings::MAX_DIGESTS)
            .map(|i| format!("{i:064x}"))
            .collect();
        db.set_setting(None, APPROVAL_KEY, Some(Value::from(full.clone())), "op", 1)
            .unwrap();
        let audits = db.audits(None, 1000).unwrap().len();
        assert!(db.media_room(true).is_err());
        let err = db
            .add_medium(A, row("ws2025.iso"), at("r1", "uid 1", 2), true)
            .unwrap_err();
        assert!(format!("{err:#}").contains("the most it may"), "{err:#}");
        // Neither the medium, nor its audit, nor a change to the setting.
        assert!(db.medium(A).unwrap().is_none());
        assert_eq!(db.audits(None, 1000).unwrap().len(), audits);
        assert_eq!(approved(&db), full);
        // Without approving, it is recorded.
        db.add_medium(A, row("ws2025.iso"), at("r1", "uid 1", 2), false)
            .unwrap();
    }

    #[test]
    fn a_full_catalogue_still_takes_known_media() {
        let db = Db::open_memory().unwrap();
        for i in 0..MAX_MEDIA {
            db.add_medium(
                &format!("{i:064x}"),
                row("x.iso"),
                at("r1", "uid 1", 1),
                false,
            )
            .unwrap();
        }
        let err = db
            .add_medium(A, row("new.iso"), at("r1", "uid 1", 2), false)
            .unwrap_err();
        assert!(format!("{err:#}").contains("the most it keeps"), "{err:#}");
        let known = format!("{:064x}", 0);
        let again = db
            .add_medium(&known, row("x.iso"), at("r2", "uid 1", 3), false)
            .unwrap();
        assert!(again.known);
        assert_eq!(again.medium.row.locations.len(), 2);

        // Places are capped too.
        for i in 3..=MAX_LOCATIONS {
            db.add_medium(
                &known,
                row("x.iso"),
                at(&format!("r{i}"), "uid 1", 4),
                false,
            )
            .unwrap();
        }
        assert!(
            db.add_medium(&known, row("x.iso"), at("r-last", "uid 1", 5), false)
                .is_err()
        );
        // The same place again replaces it.
        db.add_medium(&known, row("x.iso"), at("r1", "uid 1", 6), false)
            .unwrap();
    }

    #[test]
    fn approvals_at_once_keep_each_other() {
        let db = std::sync::Arc::new(Db::open_memory().unwrap());
        for sha in [A, B] {
            db.add_medium(sha, row("x.iso"), at("r1", "uid 1", 1), false)
                .unwrap();
        }
        let threads: Vec<_> = [A, B]
            .map(|sha| {
                let db = db.clone();
                std::thread::spawn(move || db.approve_medium(sha, true, "op", 2).unwrap())
            })
            .into_iter()
            .collect();
        for t in threads {
            assert!(t.join().unwrap().0);
        }
        let mut both = approved(&db);
        both.sort();
        assert_eq!(both, [B.to_string(), A.to_string()]);
    }

    #[test]
    fn dates_and_fields_are_checked() {
        assert!(valid_date("2026-11-09"));
        assert!(valid_date("2024-02-29"));
        assert!(valid_date("2000-02-29"));
        for bad in [
            "2026-13-01",
            "2026-1-01",
            "26-11-09",
            "2026-11-00",
            "2026-02-29",
            "1900-02-29",
            "2026-04-31",
            "2026-02-31",
        ] {
            assert!(!valid_date(bad), "{bad}");
        }
        for bad in [
            "ftp://x",
            "https://",
            "https:///path",
            "http://:80/",
            "https://u@/x",
        ] {
            let info = MediumInfo {
                sources: vec![bad.into()],
                ..MediumInfo::default()
            };
            assert!(info.check().is_err(), "{bad}");
        }
        let mut info = MediumInfo {
            sources: vec!["ftp://x".into()],
            ..MediumInfo::default()
        };
        assert!(info.check().is_err());
        info.sources = vec!["https://x/y".into()];
        info.product = "a\nb".into();
        assert!(info.check().is_err());
        info.product = String::new();
        info.notes = "a\nb".into();
        assert!(info.check().is_ok());
    }
}
