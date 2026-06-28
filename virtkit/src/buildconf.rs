//! `virtkit.conf` — the project build manifest. Declares the Dockerfiles, the named
//! build targets (stage + version-tag template), and the static build args a CI build
//! needs, so `virtkit build --conf` produces a bundle with no external driver: the
//! stage hash + layer args come from [`crate::dockerhash`] (byte-for-byte matching the
//! tags an existing pipeline stamps), the rest is declared here.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::Deserialize;

/// Parsed `virtkit.conf`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildConf {
    /// Dockerfiles to analyze (paths relative to the conf's directory), merged so
    /// cross-file stage dependencies resolve.
    pub dockerfiles: Vec<PathBuf>,
    /// Build context dir (relative to the conf's directory). Defaults to the first
    /// Dockerfile's directory, matching `virtkit build`'s own default.
    #[serde(default)]
    pub context: Option<PathBuf>,
    /// Static build args applied to every target (e.g. the uid/gid quartet). The
    /// per-stage `DOCKER_STAGE_HASH` args are synthesized by `dockerhash`, not here.
    #[serde(default)]
    pub build_args: BTreeMap<String, String>,
    /// Named build targets, keyed by the name used on the CLI and in the version tag.
    pub targets: BTreeMap<String, Target>,
}

/// One `[targets.<name>]` entry.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// Dockerfile stage to build.
    pub stage: String,
    /// Version-tag template. Tokens: `{name}`, `{hash}` (the dockerhash), and
    /// `{ARG[<arg>]}` (the effective value of build arg `<arg>` — a passed/conf build
    /// arg, else the `ARG <arg>=<default>` declared in the dockerfiles). An `{ARG[...]}`
    /// may carry a bash-style strip transform — `%%<sep>*`/`%<sep>*` (keep before the
    /// first/last `sep`) or `##*<sep>`/`#*<sep>` (keep after the last/first `sep`) — so
    /// `"{name}-{ARG[debversion]%%-*}:{hash}"` with `ARG debversion=bookworm-20231120…`
    /// renders `appbuilder-bookworm:abc1234`.
    pub version: String,
}

/// A target resolved to everything `build::run` needs, plus the rendered version tag.
pub struct Resolved {
    pub dockerfiles: Vec<PathBuf>,
    /// Build context dir (the conf's `context`, or the first Dockerfile's parent).
    pub context: PathBuf,
    pub stage: String,
    pub name: String,
    pub version: String,
    pub build_args: BTreeMap<String, String>,
}

impl BuildConf {
    pub fn load(path: &Path) -> Result<BuildConf> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    /// Resolve a target to its build inputs and rendered version tag. Dockerfile
    /// paths are taken relative to `base` (the conf's directory). `overrides` are the
    /// CLI `--build-arg`s: they win over the conf `[build_args]` and feed both the
    /// stage hash and the `{ARG[...]}` version tokens, so the published tag reflects
    /// the args actually built (not just the conf defaults).
    pub fn resolve(
        &self,
        name: &str,
        base: &Path,
        overrides: &BTreeMap<String, String>,
    ) -> Result<Resolved> {
        let t = self
            .targets
            .get(name)
            .with_context(|| format!("target {name:?} is not declared in virtkit.conf"))?;
        let dockerfiles: Vec<PathBuf> = self.dockerfiles.iter().map(|d| base.join(d)).collect();
        let context = match &self.context {
            Some(c) => base.join(c),
            None => dockerfiles
                .first()
                .and_then(|d| d.parent())
                .unwrap_or(base)
                .to_path_buf(),
        };
        let mut build_args = self.build_args.clone();
        build_args.extend(overrides.iter().map(|(k, v)| (k.clone(), v.clone())));
        let hash = stage_hash(&dockerfiles, &t.stage, &build_args)?;
        let version = render_version(&t.version, name, &hash, &dockerfiles, &build_args)?;
        Ok(Resolved {
            dockerfiles,
            context,
            stage: t.stage.clone(),
            name: name.to_string(),
            version,
            build_args,
        })
    }

    /// `(name, version)` for every target, sorted by name — the build's
    /// already-built / out.env source. Analyzes the dockerfiles once, then renders
    /// each target's tag.
    pub fn versions(&self, base: &Path) -> Result<Vec<(String, String)>> {
        let dockerfiles: Vec<PathBuf> = self.dockerfiles.iter().map(|d| base.join(d)).collect();
        let analysis = crate::dockerhash::merge_analyses(&dockerfiles, &[])?;
        let hashes = crate::dockerhash::hash_all(&analysis, &self.build_args)?;
        let mut out = Vec::with_capacity(self.targets.len());
        for (name, t) in &self.targets {
            let hash = hashes
                .get(&t.stage)
                .with_context(|| format!("stage {:?} not found in {dockerfiles:?}", t.stage))?;
            out.push((
                name.clone(),
                render_version(&t.version, name, hash, &dockerfiles, &self.build_args)?,
            ));
        }
        Ok(out)
    }
}

/// The dockerhash of `stage` — the same value `build::run` recomputes for its
/// fingerprint, and the value an existing pipeline stamps into the image tag.
fn stage_hash(
    dockerfiles: &[PathBuf],
    stage: &str,
    build_args: &BTreeMap<String, String>,
) -> Result<String> {
    let analysis = crate::dockerhash::merge_analyses(dockerfiles, &[])?;
    let hashes = crate::dockerhash::hash_all(&analysis, build_args)?;
    hashes
        .get(stage)
        .cloned()
        .with_context(|| format!("stage {stage:?} not found in {dockerfiles:?}"))
}

/// Substitute the version-template tokens `{name}`, `{hash}`, and `{ARG[<arg>]}` (the
/// effective value of build arg `<arg>`, via [`arg_value`]). An `{ARG[...]}` may carry
/// a bash-style strip transform `<arg><op><sep>*` / `<arg><op>*<sep>` (see
/// [`apply_transform`]), e.g. `{ARG[debversion]%%-*}` -> the part before the first `-`.
/// Errors on an `{ARG[...]}` whose value can't be resolved, an unsupported transform,
/// or any leftover unsubstituted token.
fn render_version(
    template: &str,
    name: &str,
    hash: &str,
    dockerfiles: &[PathBuf],
    build_args: &BTreeMap<String, String>,
) -> Result<String> {
    let mut out = template.replace("{name}", name).replace("{hash}", hash);
    // name, then an optional strip transform (%%/%/##/# + pattern) up to the `}`.
    let re = Regex::new(r"\{ARG\[([A-Za-z_][A-Za-z0-9_]*)\]((?:%%|%|##|#)[^}]*)?\}").unwrap();
    let subs: Vec<(String, String, String)> = re
        .captures_iter(&out)
        .map(|c| {
            (
                c[0].to_string(),
                c[1].to_string(),
                c.get(2).map_or("", |m| m.as_str()).to_string(),
            )
        })
        .collect();
    for (full, arg, transform) in subs {
        let mut val = arg_value(dockerfiles, build_args, &arg)?;
        if !transform.is_empty() {
            val = apply_transform(&val, &transform)?;
        }
        out = out.replace(&full, &val);
    }
    if let Some(i) = out.find('{') {
        bail!(
            "unresolved token in version template {template:?} at {:?}",
            &out[i..]
        );
    }
    Ok(out)
}

/// Apply a bash-parameter-expansion-style strip to `val`. `sep` is a literal; `*` is
/// the only wildcard and sits where bash puts it:
///   `%%<sep>*`  longest suffix from the *first* `sep`  -> keep before first `sep`
///   `%<sep>*`   shortest suffix from the *last* `sep`   -> keep before last `sep`
///   `##*<sep>`  longest prefix to the *last* `sep`      -> keep after last `sep`
///   `#*<sep>`   shortest prefix to the *first* `sep`    -> keep after first `sep`
/// A `sep` not present in `val` leaves it unchanged (as bash does).
fn apply_transform(val: &str, transform: &str) -> Result<String> {
    let bad = || {
        anyhow::anyhow!(
            "unsupported version transform {transform:?} (want %%/%/##/# with a `<sep>*` or `*<sep>` pattern)"
        )
    };
    let (keep_after, longest, pat) = if let Some(p) = transform.strip_prefix("%%") {
        (false, true, p)
    } else if let Some(p) = transform.strip_prefix('%') {
        (false, false, p)
    } else if let Some(p) = transform.strip_prefix("##") {
        (true, true, p)
    } else if let Some(p) = transform.strip_prefix('#') {
        (true, false, p)
    } else {
        return Err(bad());
    };
    // suffix ops take `<sep>*`; prefix ops take `*<sep>`.
    let sep = if keep_after {
        pat.strip_prefix('*').ok_or_else(bad)?
    } else {
        pat.strip_suffix('*').ok_or_else(bad)?
    };
    if sep.is_empty() {
        return Err(bad());
    }
    let result = match (keep_after, longest) {
        (false, true) => val.split_once(sep).map_or(val, |(a, _)| a),
        (false, false) => val.rsplit_once(sep).map_or(val, |(a, _)| a),
        (true, true) => val.rsplit_once(sep).map_or(val, |(_, b)| b),
        (true, false) => val.split_once(sep).map_or(val, |(_, b)| b),
    };
    Ok(result.to_string())
}

/// The effective value of build arg `arg`: a passed/conf build arg if set, else the
/// default from the first `ARG <arg>=<default>` across the dockerfiles. Errors when
/// neither provides one — a version template referenced it but nothing defines it.
fn arg_value(
    dockerfiles: &[PathBuf],
    build_args: &BTreeMap<String, String>,
    arg: &str,
) -> Result<String> {
    if let Some(v) = build_args.get(arg) {
        return Ok(v.clone());
    }
    for df in dockerfiles {
        let Ok(text) = std::fs::read_to_string(df) else {
            continue;
        };
        for line in text.lines() {
            let Some(rest) = line.trim().strip_prefix("ARG ") else {
                continue;
            };
            // require the arg name then `=` (after optional spaces), so `ARG FOO`
            // does not match a request for `FO`, and `ARG FOOBAR=` not for `FOO`.
            if let Some(after) = rest.trim_start().strip_prefix(arg)
                && let Some(default) = after.trim_start().strip_prefix('=')
            {
                let v = default.trim().trim_matches('"');
                if !v.is_empty() {
                    return Ok(v.to_string());
                }
            }
        }
    }
    bail!(
        "version template references {{ARG[{arg}]}} but neither a build arg nor an \
         `ARG {arg}=<default>` in the dockerfiles provides a value"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf() -> BuildConf {
        toml::from_str(
            r#"
            dockerfiles = ["Dockerfile", "Dockerfile.cypress"]
            [build_args]
            WABUSER_UID = "1000"
            WABUSER_GID = "1000"
            [targets.appbuilder]
            stage = "bastion-builder"
            version = "{name}-{ARG[debversion]}:{hash}"
            [targets.apptest-cypress]
            stage = "apptest-cypress"
            version = "{name}:{hash}"
            "#,
        )
        .unwrap()
    }

    #[test]
    fn parses_dockerfiles_args_and_targets() {
        let c = conf();
        assert_eq!(c.dockerfiles.len(), 2);
        assert_eq!(c.build_args.get("WABUSER_UID").unwrap(), "1000");
        assert_eq!(
            c.targets.get("appbuilder").unwrap().stage,
            "bastion-builder"
        );
    }

    #[test]
    fn renders_version_with_arg_token_and_plain() {
        let mut args = BTreeMap::new();
        args.insert("debversion".to_string(), "bookworm-20260101".to_string());
        // {ARG[..]} substitutes the full build-arg value (no codename truncation)
        assert_eq!(
            render_version(
                "{name}-{ARG[debversion]}:{hash}",
                "appbuilder",
                "abc1234",
                &[],
                &args
            )
            .unwrap(),
            "appbuilder-bookworm-20260101:abc1234"
        );
        // a plain template with no ARG token
        assert_eq!(
            render_version(
                "{name}:{hash}",
                "apptest-cypress",
                "deadbee",
                &[],
                &BTreeMap::new()
            )
            .unwrap(),
            "apptest-cypress:deadbee"
        );
        // an {ARG[..]} with no build arg and no dockerfile default is a hard error
        assert!(
            render_version(
                "{name}-{ARG[debversion]}:{hash}",
                "x",
                "h",
                &[],
                &BTreeMap::new()
            )
            .is_err()
        );
    }

    #[test]
    fn arg_token_strip_transforms() {
        // the codename case: debversion carries a date+digest suffix; %%-* keeps the
        // part before the first '-' -> the bare codename.
        let mut args = BTreeMap::new();
        args.insert(
            "debversion".to_string(),
            "bookworm-20231120@sha256:133a".to_string(),
        );
        assert_eq!(
            render_version(
                "{name}-{ARG[debversion]%%-*}:{hash}",
                "appbuilder",
                "09cf393",
                &[],
                &args
            )
            .unwrap(),
            "appbuilder-bookworm:09cf393"
        );
    }

    #[test]
    fn transform_operators() {
        // %% before first sep, % before last sep; ## after last sep, # after first sep
        assert_eq!(apply_transform("a-b-c", "%%-*").unwrap(), "a");
        assert_eq!(apply_transform("a-b-c", "%-*").unwrap(), "a-b");
        assert_eq!(apply_transform("a-b-c", "##*-").unwrap(), "c");
        assert_eq!(apply_transform("a-b-c", "#*-").unwrap(), "b-c");
        // a sep absent from the value leaves it unchanged (bash semantics)
        assert_eq!(apply_transform("plain", "%%-*").unwrap(), "plain");
        // multi-char separator
        assert_eq!(apply_transform("x@@y@@z", "%%@@*").unwrap(), "x");
        // malformed patterns are rejected
        assert!(apply_transform("a-b", "%%-").is_err()); // suffix op needs trailing '*'
        assert!(apply_transform("a-b", "##-").is_err()); // prefix op needs leading '*'
        assert!(apply_transform("a-b", "%%*").is_err()); // empty separator
        assert!(apply_transform("a-b", "@x").is_err()); // unknown operator
    }

    #[test]
    fn arg_value_reads_dockerfile_default_with_build_arg_override() {
        let dir = std::env::temp_dir().join(format!("virtkit-buildconf-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let df = dir.join("Dockerfile");
        std::fs::write(
            &df,
            "FROM scratch\nARG debversion=bookworm-20260101\nRUN true\n",
        )
        .unwrap();
        // default comes from the dockerfile, full value (no truncation)
        assert_eq!(
            arg_value(std::slice::from_ref(&df), &BTreeMap::new(), "debversion").unwrap(),
            "bookworm-20260101"
        );
        // a build arg overrides the dockerfile default
        let mut args = BTreeMap::new();
        args.insert("debversion".to_string(), "trixie".to_string());
        assert_eq!(arg_value(&[df], &args, "debversion").unwrap(), "trixie");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_target_errs() {
        assert!(
            conf()
                .resolve("nope", Path::new("."), &BTreeMap::new())
                .is_err()
        );
    }

    #[test]
    fn arg_value_requires_exact_arg_name() {
        let dir = std::env::temp_dir().join(format!("virtkit-buildconf-x-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let df = dir.join("Dockerfile");
        // a longer ARG declared first must not be matched by a shorter request: a
        // request for `debversion` skips `debversionx` and resolves the real line.
        std::fs::write(
            &df,
            "FROM scratch\nARG debversionx=nope\nARG debversion=bookworm\n",
        )
        .unwrap();
        assert_eq!(
            arg_value(&[df], &BTreeMap::new(), "debversion").unwrap(),
            "bookworm"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_version_and_hash_reflect_build_arg_override() {
        let dir = std::env::temp_dir().join(format!("virtkit-buildconf-o-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("Dockerfile"),
            "ARG flavor=base\nFROM alpine:3.20 AS app\nARG flavor\nRUN echo $flavor\n",
        )
        .unwrap();
        let bc: BuildConf = toml::from_str(
            r#"
            dockerfiles = ["Dockerfile"]
            [targets.app]
            stage = "app"
            version = "{name}-{ARG[flavor]}:{hash}"
            "#,
        )
        .unwrap();
        let base = dir.as_path();
        let default = bc.resolve("app", base, &BTreeMap::new()).unwrap();
        let mut ovr = BTreeMap::new();
        ovr.insert("flavor".to_string(), "custom".to_string());
        let overridden = bc.resolve("app", base, &ovr).unwrap();
        // the {ARG[flavor]} token reflects the override...
        assert!(
            default.version.starts_with("app-base:"),
            "{}",
            default.version
        );
        assert!(
            overridden.version.starts_with("app-custom:"),
            "{}",
            overridden.version
        );
        // ...and so does the {hash}: overriding a declared+referenced ARG changes the
        // stage hash, so the published tag matches what is actually built (Fix-1).
        let dh = default.version.rsplit(':').next().unwrap();
        let oh = overridden.version.rsplit(':').next().unwrap();
        assert_ne!(
            dh, oh,
            "stage hash must change when a build-arg override does"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn render_version_is_token_exact() {
        // guards the byte-for-byte contract with the legacy `<name>-<value>:<hash>`
        let mut args = BTreeMap::new();
        args.insert("debversion".to_string(), "bookworm".to_string());
        assert_eq!(
            render_version(
                "{name}-{ARG[debversion]}:{hash}",
                "appmysql",
                "0a1b2c3",
                &[],
                &args
            )
            .unwrap(),
            "appmysql-bookworm:0a1b2c3"
        );
    }
}
