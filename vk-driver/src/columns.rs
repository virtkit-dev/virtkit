//! The columns `vk list` and `vk dev list` print, chosen with `--columns`: one name per
//! column across both commands, the same defaults in both, and a way to pick any set in any
//! order.

use anyhow::{Result, bail};

/// A column of `vk list` or `vk dev list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Col {
    Name,
    Status,
    Pid,
    Mem,
    OnDisk,
    CreatedBy,
    Workspace,
    LastBoot,
    Kind,
    Env,
    Image,
    Ip,
    Published,
    Flags,
    ExecAddress,
    Stale,
}

impl Col {
    const EVERY: [Col; 16] = [
        Col::Name,
        Col::Status,
        Col::Pid,
        Col::Mem,
        Col::OnDisk,
        Col::CreatedBy,
        Col::Workspace,
        Col::LastBoot,
        Col::Kind,
        Col::Env,
        Col::Image,
        Col::Ip,
        Col::Published,
        Col::Flags,
        Col::ExecAddress,
        Col::Stale,
    ];

    /// The column's title, one word as every cell is.
    pub fn title(self) -> &'static str {
        match self {
            Col::Name => "NAME",
            Col::Status => "STATUS",
            Col::Pid => "PID",
            Col::Mem => "MEM",
            Col::OnDisk => "ON_DISK",
            Col::CreatedBy => "CREATED_BY",
            Col::Workspace => "WORKSPACE",
            Col::LastBoot => "LAST_BOOT",
            Col::Kind => "KIND",
            Col::Env => "ENV",
            Col::Image => "IMAGE",
            Col::Ip => "IP",
            Col::Published => "PUBLISHED",
            Col::Flags => "FLAGS",
            Col::ExecAddress => "EXEC_ADDRESS",
            Col::Stale => "STALE",
        }
    }

    /// A column by its title, in any case, `-` standing for `_` (`on-disk`, `CREATED_BY`).
    fn parse(word: &str) -> Option<Col> {
        let word = word.to_ascii_uppercase().replace('-', "_");
        Col::EVERY.into_iter().find(|c| c.title() == word)
    }
}

/// The defaults both commands share: what a VM is, whether it runs, and what it costs.
pub const DEFAULTS: &[Col] = &[
    Col::Name,
    Col::Status,
    Col::Pid,
    Col::Mem,
    Col::OnDisk,
    Col::CreatedBy,
];

/// The columns to print, from a command's `offer` — every column it can show, in the order
/// `all` lists them — its `defaults`, a `--columns` spec, and the columns other flags add
/// (`--published`, `--wide`'s EXEC_ADDRESS, `--stale`).
///
/// The spec is a comma-separated list of column names: plain names set the columns and
/// their order, `+NAME` adds a column to the defaults (or to the plain names given), `all`
/// stands for every column offered. With no spec, the defaults.
pub fn choose(
    offer: &[Col],
    defaults: &[Col],
    spec: Option<&str>,
    added: &[Col],
) -> Result<Vec<Col>> {
    let mut base: Vec<Col> = Vec::new();
    let mut plus: Vec<Col> = Vec::new();
    let mut plain = false;
    for word in spec.unwrap_or_default().split(',').map(str::trim) {
        if word.is_empty() {
            continue;
        }
        let (into, word) = match word.strip_prefix('+') {
            Some(w) => (&mut plus, w.trim()),
            None => {
                plain = true;
                (&mut base, word)
            }
        };
        if word.eq_ignore_ascii_case("all") {
            into.extend_from_slice(offer);
            continue;
        }
        let Some(col) = Col::parse(word) else {
            bail!("no column {word:?}: the columns are {}", titles(offer));
        };
        if !offer.contains(&col) {
            bail!(
                "this listing has no {} column: its columns are {}",
                col.title(),
                titles(offer)
            );
        }
        into.push(col);
    }
    if !plain {
        base = defaults.to_vec();
    }
    let mut out: Vec<Col> = Vec::new();
    for col in base.into_iter().chain(plus).chain(added.iter().copied()) {
        if offer.contains(&col) && !out.contains(&col) {
            out.push(col);
        }
    }
    Ok(out)
}

/// Whether a spec names the columns outright, rather than only adding to the defaults: a
/// column a command shows by itself when it has something to say (FLAGS) is then left to it.
pub fn explicit(spec: Option<&str>) -> bool {
    spec.is_some_and(|s| {
        s.split(',')
            .map(str::trim)
            .any(|w| !w.is_empty() && !w.starts_with('+'))
    })
}

fn titles(cols: &[Col]) -> String {
    cols.iter()
        .map(|c| c.title().to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const OFFER: &[Col] = &[
        Col::Name,
        Col::Status,
        Col::Pid,
        Col::Mem,
        Col::OnDisk,
        Col::CreatedBy,
        Col::LastBoot,
        Col::Published,
    ];

    #[test]
    fn a_spec_sets_adds_to_or_expands_the_columns() {
        let c = |spec: Option<&str>, added: &[Col]| choose(OFFER, DEFAULTS, spec, added);
        assert_eq!(c(None, &[]).unwrap(), DEFAULTS);
        assert_eq!(
            c(Some("mem,NAME,on-disk"), &[]).unwrap(),
            [Col::Mem, Col::Name, Col::OnDisk]
        );
        let mut plus = DEFAULTS.to_vec();
        plus.push(Col::LastBoot);
        assert_eq!(c(Some("+last_boot"), &[]).unwrap(), plus);
        assert_eq!(c(Some("all"), &[]).unwrap(), OFFER);
        // A flag's column joins whatever is chosen, once.
        assert_eq!(
            c(Some("name,published"), &[Col::Published]).unwrap(),
            [Col::Name, Col::Published]
        );
        let err = c(Some("name,size"), &[]).unwrap_err().to_string();
        assert!(
            err.contains("no column \"size\"") && err.contains("on_disk"),
            "{err}"
        );
        let err = c(Some("flags"), &[]).unwrap_err().to_string();
        assert!(err.contains("no FLAGS column"), "{err}");
        assert!(explicit(Some("name,+pid")) && !explicit(Some("+pid")) && !explicit(None));
    }
}
