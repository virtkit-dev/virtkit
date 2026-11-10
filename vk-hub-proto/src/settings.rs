//! The node settings a fleet hub may set ([`crate::DesiredState::settings`]): every key, by
//! dotted name, with the type a value of it takes. A node refuses any other key, and checks
//! each value against these same checks, then against its own configuration; the hub checks
//! them first, so an operator hears of a mistake when making it.

use serde_json::Value;

/// What a setting's value is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A size in whole GiB, `"<n>G"`, `n` from 1 to [`MAX_GIB`].
    Gib,
    /// A memory budget: a [`Kind::Gib`], or `"<n>%"` of the host's memory, 1 to 100.
    Budget,
    Bool,
    /// A count, at least 1, that fits a `u32`.
    Count,
    /// A VM's vCPUs, 1 to [`MAX_VCPUS`].
    Vcpus,
    /// A number of seconds, at most [`MAX_SECS`].
    Secs,
    /// A number of seconds, from 1 to [`MAX_SECS`].
    PositiveSecs,
    /// A positive ratio, at most [`MAX_RATIO`].
    Ratio,
    /// A `[registry]` table of [`REGISTRY_KEYS`].
    Registry,
    /// At most [`MAX_DIGESTS`] distinct sha256 digests, each 64 lowercase hex digits.
    /// Empty means none. A node's own file allows duplicates and has no count limit.
    Digests,
}

/// Every key the hub may set, and its kind.
pub const KEYS: &[(&str, Kind)] = &[
    ("executor.schedule.mem_budget", Kind::Budget),
    ("executor.schedule.from_history", Kind::Bool),
    ("executor.schedule.disk_admission", Kind::Bool),
    ("executor.schedule.disk_default", Kind::Gib),
    ("executor.schedule.cpu_overcommit", Kind::Ratio),
    ("executor.schedule.wait_timeout_secs", Kind::Secs),
    ("executor.vm.cpus", Kind::Vcpus),
    ("executor.vm.mem", Kind::Gib),
    ("executor.vm.max_cpus", Kind::Count),
    ("executor.vm.max_mem", Kind::Gib),
    ("image_cache_idle_secs", Kind::Secs),
    ("executor.windows_cache_idle_secs", Kind::PositiveSecs),
    ("executor.windows_media", Kind::Digests),
    ("registry", Kind::Registry),
];

/// The `[registry]` keys the hub may name: the registry and how to reach it, never a path or a
/// credential of the node's. `ca_pem` is the CA as PEM content, which the node pins.
pub const REGISTRY_KEYS: &[&str] = &[
    "repo",
    "ca_pem",
    "insecure",
    "transparent_zstd",
    "proxy_guests",
    "guest_credential",
    "pipeline_root",
];

/// The largest size a setting may name, in GiB: 1 PiB.
pub const MAX_GIB: u64 = 1 << 20;
/// The most vCPUs a VM may have.
pub const MAX_VCPUS: u64 = 255;
/// The longest a setting may name, in seconds: ten years.
pub const MAX_SECS: u64 = 10 * 365 * 24 * 3600;
/// The largest ratio a setting may name.
pub const MAX_RATIO: f64 = 64.0;

/// The most digests a [`Kind::Digests`] setting may list.
pub const MAX_DIGESTS: usize = 256;

/// The most a registry's `ca_pem` may hold.
pub const MAX_CA_PEM: usize = 256 * 1024;

/// The `guest_credential` a registry the hub names has by default: the job's token, and nothing
/// for a job the hub did not place.
pub const GUEST_CREDENTIAL: &str = "job";

/// The `guest_credential` the hub names to a node from protocol version
/// [`crate::REGISTRY_ACCESS`]: the job's token for a job it placed, as [`GUEST_CREDENTIAL`]; the
/// token the hub gives the node for its runner's guests for any other.
pub const GUEST_CREDENTIAL_JOB_OR_NODE: &str = "job-or-node";

/// `key`'s kind; `None` for a key the hub may not set.
pub fn kind(key: &str) -> Option<Kind> {
    KEYS.iter().find(|(k, _)| *k == key).map(|(_, kind)| *kind)
}

impl Kind {
    /// What a value of the kind looks like, in words.
    pub fn describe(self) -> &'static str {
        match self {
            Kind::Gib => "a size, <n>G, from 1G to 1048576G",
            Kind::Budget => {
                "a size, <n>G, from 1G to 1048576G, or a share of the host's memory, <n>%, \
                 from 1 to 100"
            }
            Kind::Bool => "true or false",
            Kind::Count => "a whole number, at least 1",
            Kind::Vcpus => "a whole number, from 1 to 255",
            Kind::Secs => "a number of seconds, at most 315360000 (ten years)",
            Kind::PositiveSecs => "a number of seconds, from 1 to 315360000 (ten years)",
            Kind::Ratio => "a positive number, at most 64",
            Kind::Registry => "a registry",
            Kind::Digests => {
                "distinct sha256 digests (64 hex digits), at most 256, separated by commas or \
                 spaces, or none"
            }
        }
    }

    /// Parse operator input as this kind, returning the reason on failure.
    /// Registries cannot be parsed from text.
    pub fn parse(self, text: &str) -> Result<Value, String> {
        let text = text.trim();
        let value = match self {
            Kind::Gib | Kind::Budget => Value::from(text),
            Kind::Bool => match text {
                "true" => Value::Bool(true),
                "false" => Value::Bool(false),
                _ => Value::Null,
            },
            Kind::Count | Kind::Vcpus | Kind::Secs | Kind::PositiveSecs => {
                text.parse::<u64>().map_or(Value::Null, Value::from)
            }
            Kind::Ratio => text.parse::<f64>().map_or(Value::Null, Value::from),
            Kind::Registry => return Err("a registry is named by the registry's ID".to_string()),
            Kind::Digests if text == "none" => Value::Array(Vec::new()),
            Kind::Digests => {
                let digests: Vec<Value> = text
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .filter(|d| !d.is_empty())
                    .map(|d| Value::from(d.to_ascii_lowercase()))
                    .collect();
                // Require `none` for an empty list to reject accidental blank input.
                if digests.is_empty() {
                    Value::Null
                } else {
                    Value::Array(digests)
                }
            }
        };
        self.check(&value).map(|()| value)
    }

    /// That `value` is one of the kind.
    pub fn check(self, value: &Value) -> Result<(), String> {
        let ok = match self {
            Kind::Gib => value.as_str().is_some_and(is_gib),
            Kind::Budget => value.as_str().is_some_and(|s| {
                is_gib(s)
                    || s.strip_suffix('%')
                        .filter(|n| digits(n))
                        .and_then(|n| n.parse::<u64>().ok())
                        .is_some_and(|n| (1..=100).contains(&n))
            }),
            Kind::Bool => value.is_boolean(),
            Kind::Count => value
                .as_u64()
                .is_some_and(|n| n >= 1 && u32::try_from(n).is_ok()),
            Kind::Vcpus => value.as_u64().is_some_and(|n| (1..=MAX_VCPUS).contains(&n)),
            Kind::Secs => value.as_u64().is_some_and(|n| n <= MAX_SECS),
            Kind::PositiveSecs => value.as_u64().is_some_and(|n| (1..=MAX_SECS).contains(&n)),
            Kind::Ratio => value
                .as_f64()
                .is_some_and(|r| r.is_finite() && r > 0.0 && r <= MAX_RATIO),
            Kind::Registry => return check_registry(value),
            Kind::Digests => return check_digests(value),
        };
        if ok {
            Ok(())
        } else {
            Err(format!("expected {}", self.describe()))
        }
    }
}

/// Whether `n` is nonempty and contains only ASCII digits.
fn digits(n: &str) -> bool {
    !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())
}

/// `s` is `"<n>G"`, `n` a whole number from 1 to [`MAX_GIB`].
fn is_gib(s: &str) -> bool {
    s.strip_suffix('G')
        .filter(|n| digits(n))
        .and_then(|n| n.parse::<u64>().ok())
        .is_some_and(|n| (1..=MAX_GIB).contains(&n))
}

/// That `value` is a [`Kind::Digests`]: a list of distinct sha256 digests in lowercase hex.
fn check_digests(value: &Value) -> Result<(), String> {
    let Value::Array(digests) = value else {
        return Err(format!("expected {}", Kind::Digests.describe()));
    };
    if digests.len() > MAX_DIGESTS {
        return Err(format!("expected at most {MAX_DIGESTS} digests"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for (i, digest) in digests.iter().enumerate() {
        let Some(d) = digest
            .as_str()
            .filter(|d| d.len() == 64 && d.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        else {
            // Not echoed: it may be anything, of any length.
            return Err(format!(
                "entry {} is not a sha256 digest (64 lowercase hex digits)",
                i + 1
            ));
        };
        if !seen.insert(d) {
            return Err(format!("{d} is listed twice"));
        }
    }
    Ok(())
}

/// That `value` is a `[registry]` the hub may send: a table of [`REGISTRY_KEYS`] naming a
/// remote registry in `repo`, whose guests get the job's token alone, with a `pipeline_root` in
/// the repository grammar. That `ca_pem` holds certificates is left to the caller, which can
/// parse them.
fn check_registry(value: &Value) -> Result<(), String> {
    let Value::Object(table) = value else {
        return Err("expected a table".to_string());
    };
    if let Some(key) = table.keys().find(|k| !REGISTRY_KEYS.contains(&k.as_str())) {
        return Err(format!(
            "`{key}` is the node's own to set: the hub may name only {}",
            REGISTRY_KEYS.join(", ")
        ));
    }
    let Some(repo) = table.get("repo").and_then(Value::as_str) else {
        return Err("`repo` must name the registry".to_string());
    };
    if repo.starts_with('/') || repo.starts_with("file://") {
        return Err("`repo` names a store on the host, not a registry".to_string());
    }
    let authority = repo
        .strip_prefix("https://")
        .or_else(|| repo.strip_prefix("http://"))
        .unwrap_or(repo);
    if authority.split('/').next().is_none_or(str::is_empty) {
        return Err("`repo` names no registry host".to_string());
    }
    if table.get("guest_credential").is_some_and(|v| {
        !matches!(
            v.as_str(),
            Some(GUEST_CREDENTIAL | GUEST_CREDENTIAL_JOB_OR_NODE)
        )
    }) {
        return Err(format!(
            "`guest_credential` may only be {GUEST_CREDENTIAL:?} or \
             {GUEST_CREDENTIAL_JOB_OR_NODE:?}: guests never get the node's own credential"
        ));
    }
    for key in ["ca_pem", "pipeline_root"] {
        if table.get(key).is_some_and(|v| !v.is_string()) {
            return Err(format!("`{key}` must be a string"));
        }
    }
    if table
        .get("ca_pem")
        .and_then(Value::as_str)
        .is_some_and(|pem| pem.len() > MAX_CA_PEM)
    {
        return Err(format!("`ca_pem` is over {MAX_CA_PEM} bytes"));
    }
    if let Some(root) = table.get("pipeline_root").and_then(Value::as_str)
        && !crate::token::valid_prefix(root)
    {
        return Err(format!(
            "`pipeline_root` {root:?} is not a repository path: lowercase components \
             separated by `/`"
        ));
    }
    for key in ["insecure", "transparent_zstd", "proxy_guests"] {
        if table.get(key).is_some_and(|v| !v.is_boolean()) {
            return Err(format!("`{key}` must be true or false"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn values_are_parsed_and_checked_by_kind() {
        let parse = |key: &str, text: &str| kind(key).unwrap().parse(text);
        assert_eq!(parse("executor.vm.mem", "8G"), Ok(json!("8G")));
        assert!(parse("executor.vm.mem", "0G").is_err());
        assert!(parse("executor.vm.mem", "+8G").is_err());
        assert!(parse("executor.vm.mem", "8").is_err());
        assert_eq!(parse("executor.vm.mem", "1048576G"), Ok(json!("1048576G")));
        assert!(parse("executor.vm.mem", "1048577G").is_err());
        assert!(parse("executor.vm.max_mem", "18014398509481984G").is_err());
        assert!(parse("executor.schedule.disk_default", "99999999999999999999G").is_err());
        assert!(parse("executor.schedule.mem_budget", "18014398509481984G").is_err());
        assert_eq!(
            parse("executor.schedule.mem_budget", "50%"),
            Ok(json!("50%"))
        );
        assert!(parse("executor.schedule.mem_budget", "101%").is_err());
        assert_eq!(parse("executor.vm.cpus", " 4 "), Ok(json!(4)));
        assert!(parse("executor.vm.cpus", "0").is_err());
        assert_eq!(parse("executor.vm.cpus", "255"), Ok(json!(255)));
        assert!(parse("executor.vm.cpus", "256").is_err());
        assert_eq!(parse("executor.vm.max_cpus", "512"), Ok(json!(512)));
        assert!(parse("executor.vm.max_cpus", "4294967296").is_err());
        assert_eq!(parse("image_cache_idle_secs", "0"), Ok(json!(0)));
        assert_eq!(
            parse("executor.windows_cache_idle_secs", "3600"),
            Ok(json!(3600))
        );
        assert_eq!(parse("executor.windows_cache_idle_secs", "1"), Ok(json!(1)));
        assert_eq!(
            parse("executor.windows_cache_idle_secs", "315360000"),
            Ok(json!(MAX_SECS))
        );
        assert!(parse("executor.windows_cache_idle_secs", "0").is_err());
        assert!(parse("executor.windows_cache_idle_secs", "315360001").is_err());
        assert_eq!(
            parse("executor.schedule.wait_timeout_secs", "315360000"),
            Ok(json!(315_360_000))
        );
        assert!(
            parse(
                "executor.schedule.wait_timeout_secs",
                "18446744073709551615"
            )
            .is_err()
        );
        assert_eq!(
            parse("executor.schedule.cpu_overcommit", "1.5"),
            Ok(json!(1.5))
        );
        assert!(parse("executor.schedule.cpu_overcommit", "0").is_err());
        assert!(parse("executor.schedule.cpu_overcommit", "inf").is_err());
        assert_eq!(
            parse("executor.schedule.cpu_overcommit", "64"),
            Ok(json!(64.0))
        );
        assert!(parse("executor.schedule.cpu_overcommit", "64.5").is_err());
        assert_eq!(
            parse("executor.schedule.from_history", "true"),
            Ok(json!(true))
        );
        assert!(parse("executor.schedule.from_history", "yes").is_err());
        assert!(parse("registry", "r").is_err());
        assert_eq!(kind("state_dir"), None);
        let a = "ab".repeat(32);
        let b = "CD".repeat(32);
        assert_eq!(
            parse("executor.windows_media", &format!(" {a}, {b}\n")),
            Ok(json!([a, b.to_ascii_lowercase()]))
        );
        assert_eq!(parse("executor.windows_media", " none "), Ok(json!([])));
        assert!(parse("executor.windows_media", "").is_err());
        assert!(parse("executor.windows_media", " , ,").is_err());
        assert!(parse("executor.windows_media", &format!("{a},{a}")).is_err());
        assert!(parse("executor.windows_media", &a[1..]).is_err());
        assert!(parse("executor.windows_media", &"g".repeat(64)).is_err());
        assert!(Kind::Digests.check(&json!(a)).is_err());
        assert!(Kind::Digests.check(&json!([b])).is_err());
        assert!(Kind::Digests.check(&json!([null])).is_err());
        assert!(Kind::Digests.check(&json!([42])).is_err());
        let lower = b.to_ascii_lowercase();
        assert!(parse("executor.windows_media", &format!("{b} {lower}")).is_err());
        let distinct: Vec<String> = (0..=MAX_DIGESTS).map(|n| format!("{n:064x}")).collect();
        assert_eq!(Kind::Digests.check(&json!(distinct[..MAX_DIGESTS])), Ok(()));
        let err = Kind::Digests.check(&json!(distinct)).unwrap_err();
        assert!(err.contains("at most"), "{err}");
        // A whole ratio, as JSON may carry it.
        assert_eq!(Kind::Ratio.check(&json!(2)), Ok(()));
    }

    #[test]
    fn a_registry_names_a_repo_and_nothing_of_the_nodes() {
        let check = |v: Value| Kind::Registry.check(&v);
        assert_eq!(
            check(
                json!({"repo": "reg:5000", "ca_pem": "x", "pipeline_root": "ci",
                         "insecure": false, "guest_credential": "job"})
            ),
            Ok(())
        );
        assert!(check(json!({"ca_pem": "x"})).is_err());
        assert!(check(json!({"repo": "r", "token_file": "/t"})).is_err());
        assert!(check(json!({"repo": "r", "guest_credential": "node"})).is_err());
        check(json!({"repo": "r", "guest_credential": "job-or-node"})).unwrap();
        assert!(check(json!({"repo": "r", "insecure": "yes"})).is_err());
        assert!(check(json!("r")).is_err());
        for (registry, why) in [
            (json!({"repo": "/srv/store"}), "store on the host"),
            (json!({"repo": "file:///srv/store"}), "store on the host"),
            (json!({"repo": ""}), "no registry host"),
            (json!({"repo": "https:///ci"}), "no registry host"),
            (json!({"repo": "r", "pipeline_root": "A"}), "pipeline_root"),
            (json!({"repo": "r", "pipeline_root": ""}), "pipeline_root"),
            (
                json!({"repo": "r", "ca_pem": "x".repeat(MAX_CA_PEM + 1)}),
                "over",
            ),
        ] {
            let err = check(registry).unwrap_err();
            assert!(err.contains(why), "{err}");
        }
    }
}
