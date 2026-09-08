//! The JSON Schema for `.virtkit/config.toml`, so an editor completes and checks the file
//! as it is typed rather than at the next `vk dev`.
//!
//! The schema lives in the repository at `docs/schema/virtkit-config.schema.json` and is
//! embedded here, so a `vk` hands out the schema it reads, whatever the checkout beside
//! it says. A TOML editor that speaks JSON Schema (taplo, VS Code's Even Better TOML)
//! picks it up from the [`DIRECTIVE`] comment `vk dev init` writes on the first line; a
//! checkout can point at its own copy instead, and either way the directive is a comment
//! TOML ignores.
//!
//! [`crate::dev::config`] is the source of truth: the tests below derive every struct's field
//! names and every enum's variants from serde itself, and fail when the two drift apart.

/// A literal for [`crate::dev::config::TEMPLATE`]'s `concat!`, avoiding a duplicate URL
/// on its first line.
macro_rules! directive {
    () => {
        "#:schema https://raw.githubusercontent.com/virtkit-dev/virtkit/main/docs/schema/virtkit-config.schema.json"
    };
}
pub(crate) use directive;

/// The first line of an initialized config; also suitable for handwritten configs.
pub const DIRECTIVE: &str = directive!();

/// The schema itself, as shipped in the repository, and what `vk dev schema` prints.
pub const SCHEMA_JSON: &str = include_str!("../../../docs/schema/virtkit-config.schema.json");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::config::{
        Build, Cache, CheckoutMode, Editor, EditorState, Egress, Endpoint, Environment, Fallback,
        Freshness, HookSpec, Hooks, Host, Mount, Network, Policy, Requires, Schema, Ssh, SshHost,
        Task, VsCode,
    };
    use serde::de::DeserializeOwned;
    use serde_json::Value as Json;
    use std::collections::BTreeSet;

    /// A key no struct has, to make serde name the keys they do have.
    const UNKNOWN: &str = "zz-not-a-key = 1\n";

    /// A variant no enum has, to make serde name the variants they do have.
    const UNKNOWN_VARIANT: &str = "zz-not-a-variant";

    /// Every `#[serde(deny_unknown_fields)]` struct in [`crate::dev::config`], with the
    /// definition of the schema that describes it. `#` is the schema's root.
    #[allow(clippy::type_complexity)]
    fn structs() -> Vec<(&'static str, fn() -> BTreeSet<String>)> {
        vec![
            ("#", || rust_fields::<Schema>()),
            ("requires", || rust_fields::<Requires>()),
            ("environment", || rust_fields::<Environment>()),
            ("build", || rust_fields::<Build>()),
            ("fallback", || rust_fields::<Fallback>()),
            ("task", || rust_fields::<Task>()),
            ("mount", || rust_fields::<Mount>()),
            ("editor", || rust_fields::<Editor>()),
            ("vscode", || rust_fields::<VsCode>()),
            ("host", || rust_fields::<Host>()),
            ("ssh", || rust_fields::<Ssh>()),
            ("ssh-host", || rust_fields::<SshHost>()),
            ("cache", || rust_fields::<Cache>()),
            ("endpoint", || rust_fields::<Endpoint>()),
            ("network", || rust_fields::<Network>()),
            ("hooks", || rust_fields::<Hooks>()),
            ("hook-spec", || rust_fields::<HookSpec>()),
        ]
    }

    /// Derive `T`'s fields from serde's error: "unknown field `zz-not-a-key`, expected one of
    /// `a`, `b`". This includes new fields in `config.rs` without maintaining a second list.
    fn rust_fields<T: DeserializeOwned>() -> BTreeSet<String> {
        let err = toml::from_str::<T>(UNKNOWN)
            .err()
            .unwrap_or_else(|| panic!("{} accepts unknown keys", std::any::type_name::<T>()))
            .to_string();
        backticked(&err)
    }

    /// The variants serde accepts for `T`, read out of the error a variant it does not
    /// accept produces: "unknown variant `zz-not-a-variant`, expected one of `a`, `b`".
    fn rust_variants<T: DeserializeOwned>() -> BTreeSet<String> {
        let err = toml::Value::String(UNKNOWN_VARIANT.to_string())
            .try_into::<T>()
            .err()
            .unwrap_or_else(|| panic!("{} accepts unknown variants", std::any::type_name::<T>()))
            .to_string();
        backticked(&err)
    }

    /// The backticked names serde listed after "expected".
    ///
    /// This reads serde's English: it panics with the message it could not parse rather than
    /// returning an empty set, which would pass every comparison below.
    fn backticked(err: &str) -> BTreeSet<String> {
        let at = err
            .find("expected")
            .unwrap_or_else(|| panic!("no list in: {err}"));
        let mut rest = &err[at..];
        let mut out = BTreeSet::new();
        while let Some(open) = rest.find('`') {
            let after = &rest[open + 1..];
            let close = after
                .find('`')
                .unwrap_or_else(|| panic!("unbalanced list in: {err}"));
            out.insert(after[..close].to_string());
            rest = &after[close + 1..];
        }
        assert!(!out.is_empty(), "no list in: {err}");
        out
    }

    fn schema() -> Json {
        serde_json::from_str(SCHEMA_JSON).expect("the schema parses as JSON")
    }

    /// One schema definition, `#` being the root.
    fn def_node<'a>(root: &'a Json, def: &str) -> &'a Json {
        match def {
            "#" => root,
            name => root["$defs"]
                .get(name)
                .unwrap_or_else(|| panic!("the schema has no {name} definition")),
        }
    }

    /// The property names one schema definition describes.
    fn schema_fields(root: &Json, def: &str) -> BTreeSet<String> {
        def_node(root, def)["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{def} describes no properties"))
            .keys()
            .cloned()
            .collect()
    }

    /// Keywords [`Check`] implements; only [`ANNOTATIONS`] may be ignored.
    /// `the_schema_uses_only_what_is_checked` rejects new keywords until they are checked.
    const IMPLEMENTED: [&str; 15] = [
        "$ref",
        "type",
        "enum",
        "const",
        "pattern",
        "properties",
        "additionalProperties",
        "propertyNames",
        "items",
        "anyOf",
        "not",
        "minimum",
        "maximum",
        "required",
        "dependentRequired",
    ];

    /// Keywords that describe rather than constrain, and are the reader's business.
    const ANNOTATIONS: [&str; 6] = ["$schema", "$id", "title", "description", "$defs", "default"];

    /// Check the schema's draft 2020-12 subset (see [`IMPLEMENTED`]) against the TOML files
    /// `vk` reads. Record exercised properties to keep the examples complete.
    struct Check<'a> {
        root: &'a Json,
        errs: Vec<String>,
        seen: BTreeSet<String>,
    }

    impl<'a> Check<'a> {
        fn new(root: &'a Json) -> Self {
            Self {
                root,
                errs: Vec::new(),
                seen: BTreeSet::new(),
            }
        }

        /// A node with its `$ref` followed, and the name of the definition it landed in.
        ///
        /// The siblings of a `$ref` go with it, so they must all be annotations.
        fn resolve(&self, def: &str, node: &'a Json) -> (String, &'a Json) {
            let Some(r) = node.get("$ref").and_then(Json::as_str) else {
                return (def.to_string(), node);
            };
            for key in node.as_object().into_iter().flatten().map(|(k, _)| k) {
                assert!(
                    key == "$ref" || ANNOTATIONS.contains(&key.as_str()),
                    "{r} is joined by {key}, which following the $ref would drop"
                );
            }
            let name = r
                .strip_prefix("#/$defs/")
                .unwrap_or_else(|| panic!("unsupported $ref {r}"));
            let target = self.root["$defs"]
                .get(name)
                .unwrap_or_else(|| panic!("dangling $ref {r}"));
            (name.to_string(), target)
        }

        fn check(&mut self, def: &str, node: &'a Json, value: &toml::Value, path: &str) {
            let (def, node) = self.resolve(def, node);
            if let Some(forms) = node.get("anyOf").and_then(Json::as_array) {
                for form in forms {
                    let mut trial = Check::new(self.root);
                    trial.check(&def, form, value, path);
                    if trial.errs.is_empty() {
                        self.seen.extend(trial.seen);
                        return;
                    }
                }
                self.errs.push(format!("{path}: no accepted form of {def}"));
                return;
            }
            if let Some(want) = node.get("type").and_then(Json::as_str) {
                let got = kind(value);
                if got != want {
                    self.errs
                        .push(format!("{path}: expected {want}, found {got}"));
                    return;
                }
            }
            if let Some(allowed) = node.get("enum").and_then(Json::as_array)
                && !allowed.iter().any(|a| same(a, value))
            {
                self.errs
                    .push(format!("{path}: {value} is not one of {allowed:?}"));
            }
            if let Some(want) = node.get("const")
                && !same(want, value)
            {
                self.errs.push(format!("{path}: expected {want}"));
            }
            if let Some(pattern) = node.get("pattern").and_then(Json::as_str)
                && let Some(text) = value.as_str()
                && !matches_pattern(pattern, text)
            {
                self.errs
                    .push(format!("{path}: {text:?} does not match {pattern}"));
            }
            if let Some(refused) = node.get("not") {
                let mut trial = Check::new(self.root);
                trial.check(&def, refused, value, path);
                if trial.errs.is_empty() {
                    self.errs.push(format!("{path}: {value} is refused here"));
                }
            }
            match value {
                toml::Value::Table(table) => {
                    let dependent = node
                        .get("dependentRequired")
                        .and_then(Json::as_object)
                        .into_iter()
                        .flatten()
                        .filter(|(key, _)| table.contains_key(*key))
                        .filter_map(|(_, wanted)| wanted.as_array());
                    for want in node
                        .get("required")
                        .and_then(Json::as_array)
                        .into_iter()
                        .chain(dependent)
                        .flatten()
                    {
                        let key = want.as_str().unwrap_or_default();
                        if !table.contains_key(key) {
                            self.errs
                                .push(format!("{} is required", key_path(path, key)));
                        }
                    }
                    for (key, value) in table {
                        let at = key_path(path, key);
                        if let Some(names) = node.get("propertyNames") {
                            let mut trial = Check::new(self.root);
                            trial.check("", names, &toml::Value::String(key.clone()), &at);
                            if !trial.errs.is_empty() {
                                self.errs.push(format!("{at}: not a name this table takes"));
                            }
                        }
                        if let Some(property) = node.get("properties").and_then(|p| p.get(key)) {
                            self.seen.insert(format!("{def}.{key}"));
                            self.check("", property, value, &at);
                        } else if let Some(extra) = node.get("additionalProperties") {
                            match extra.as_bool() {
                                Some(false) => self.errs.push(format!("{at}: unknown key")),
                                _ => self.check("", extra, value, &at),
                            }
                        }
                    }
                }
                toml::Value::Array(items) => {
                    if let Some(schema) = node.get("items") {
                        for (i, value) in items.iter().enumerate() {
                            self.check("", schema, value, &format!("{path}[{i}]"));
                        }
                    }
                }
                toml::Value::Integer(n) => {
                    if let Some(min) = node.get("minimum").and_then(Json::as_i64)
                        && *n < min
                    {
                        self.errs.push(format!("{path}: {n} is below {min}"));
                    }
                    if let Some(max) = node.get("maximum").and_then(Json::as_i64)
                        && *n > max
                    {
                        self.errs.push(format!("{path}: {n} is above {max}"));
                    }
                }
                _ => {}
            }
        }
    }

    /// A TOML value's JSON Schema type. A datetime is its own name, one no schema node
    /// uses, because serde reads every string-typed key as a string.
    fn kind(value: &toml::Value) -> &'static str {
        match value {
            toml::Value::String(_) => "string",
            toml::Value::Datetime(_) => "datetime",
            toml::Value::Integer(_) => "integer",
            toml::Value::Float(_) => "number",
            toml::Value::Boolean(_) => "boolean",
            toml::Value::Array(_) => "array",
            toml::Value::Table(_) => "object",
        }
    }

    /// A schema literal and a TOML value being the same scalar.
    fn same(want: &Json, got: &toml::Value) -> bool {
        match got {
            toml::Value::String(s) => want.as_str() == Some(s.as_str()),
            toml::Value::Integer(n) => want.as_i64() == Some(*n),
            toml::Value::Boolean(b) => want.as_bool() == Some(*b),
            _ => false,
        }
    }

    /// `pattern`, for the anchored literal prefixes the schema uses. vk-driver does not
    /// depend on `regex`, so anything else panics rather than quietly matching everything.
    fn matches_pattern(pattern: &str, value: &str) -> bool {
        let prefix = pattern
            .strip_prefix('^')
            .filter(|p| !p.contains(|c| "\\.[]()*+?{}|$".contains(c)))
            .unwrap_or_else(|| panic!("{pattern} is not an anchored literal prefix"));
        value.starts_with(prefix)
    }

    /// `path.key`, or `key` at the root.
    fn key_path(path: &str, key: &str) -> String {
        match path.is_empty() {
            true => key.to_string(),
            false => format!("{path}.{key}"),
        }
    }

    /// Check one document, returning what it exercised.
    fn against_schema(root: &Json, text: &str) -> BTreeSet<String> {
        let doc: toml::Value = toml::from_str(text).expect("the example is TOML");
        let mut check = Check::new(root);
        check.check("#", root, &doc, "");
        assert!(check.errs.is_empty(), "{:#?}", check.errs);
        check.seen
    }

    /// Every key of every environment, spread over the three sources so the whole document
    /// is a config `vk dev` would accept.
    const EVERY_KEY: &str = r#"
schema = 1

[requires]
min-version = "0.62.0"
features = ["entrypoint"]

[dev]
compose = ".virtkit/compose.yaml"
service = "devcontainer"
workspace = "/workdir"
user = "dev"
freshness = "ask"
profiles = ["tools"]
cpus = "host"
mem = "8G"
nested = "auto"

[dev.exec-env]
GITLAB_TOKEN = "x"

[dev.container-env]
TZ = "UTC"

[dev.mounts.gitconfig]
source = "~/.gitconfig"
to = "/home/dev/.gitconfig"
read-only = true
optional = true
enabled = true

[dev.editor.vscode]
state = "persistent"
home = "/home/dev"
reconcile = ["./install-extensions.sh"]
extensions = ["rust-lang.rust-analyzer"]

[dev.editor.vscode.settings]
"editor.formatOnSave" = true

[dev.host]
git-gui = false
wrapper = "dev/tools/host.sh"
wrapper-env = ["DISPLAY"]

[dev.ssh]
keys = ["work"]

[dev.ssh.host."gitlab.example.com"]
hostname = "gitlab.internal"
user = "git"
port = 2222
key = "work"

[dev.cache]
registry = "https://vk-registry.corp:5000"
insecure = false

[dev.endpoints."runner.https"]
service = "runner"
target = 443
host-port = 8443
address = "auto"
scheme = "https"
path = "/ui"
required = true
enabled = true

[dev.network]
egress = "unrestricted"

[dev.hooks]
init = "./dev/tools/prepare.sh"
start = ["./dev/tools/start.sh", "--quiet"]

[dev.hooks.create]
run = "./dev/tools/create.sh"
cwd = "/workdir"
timeout = "10m"
required = false

[dev.tasks.pre-commit]
run = ["./hooks/pre-commit"]
environment = "built"
reuse = "dev"
policy = "reuse-or-ephemeral"
checkout = "overlay"
enabled = true

[dev.tasks.pre-commit.env]
CI = "1"

[environments.built]
workspace = "/workdir"
cached-only = true

[environments.built.build]
context = "."
dockerfile = "docker/Dockerfile"
target = "dev"

[environments.built.build.args]
VK_UID = "1000"

[environments.built.fallback]
target = "hook"

[environments.built.hooks.start]
lint = "./dev/tools/lint.sh"
test = ["./dev/tools/test.sh"]

[environments.stock]
image = "docker.io/library/debian:13"
cpus = 4
"#;

    /// The keys only a local layer may carry.
    const LOCAL_LAYER: &str = r#"
remove = ["dev.compose", "dev.service"]
env-files = [".virtkit/ci.env"]

[dev]
image = "docker.io/library/debian:13"
"#;

    #[test]
    fn schema_and_rust_describe_the_same_keys() {
        /// Every object shape lives in `$defs`: nothing reached through `properties` describes
        /// properties of its own.
        fn defs_hold_every_object(node: &Json, at: &str, under_properties: bool) {
            let Some(object) = node.as_object() else {
                return;
            };
            assert!(
                !(under_properties && object.contains_key("properties")),
                "{at} describes properties inline; give it a $defs definition"
            );
            for (key, value) in object {
                match key.as_str() {
                    "properties" | "$defs" => {
                        for (name, sub) in value.as_object().into_iter().flatten() {
                            let at = format!("{at}/{key}/{name}");
                            defs_hold_every_object(sub, &at, key == "properties");
                        }
                    }
                    "additionalProperties" | "items" | "propertyNames" | "not" => {
                        defs_hold_every_object(value, &format!("{at}/{key}"), under_properties);
                    }
                    "anyOf" => {
                        for (i, sub) in value.as_array().into_iter().flatten().enumerate() {
                            defs_hold_every_object(
                                sub,
                                &format!("{at}/anyOf/{i}"),
                                under_properties,
                            );
                        }
                    }
                    _ => {}
                }
            }
        }

        let root = schema();
        for (def, fields) in structs() {
            assert_eq!(
                schema_fields(&root, def),
                fields(),
                "{def} and its devconfig struct disagree"
            );
        }
        // And no definition describes keys nothing reads.
        let described: BTreeSet<&str> = structs().into_iter().map(|(def, _)| def).collect();
        for (name, def) in root["$defs"].as_object().expect("$defs is an object") {
            if def.get("properties").is_some() {
                assert!(
                    described.contains(name.as_str()),
                    "{name} describes properties no devconfig struct has"
                );
            }
        }
        // Both halves look definitions up by name, so an object written inline under
        // `properties` would escape them.
        defs_hold_every_object(&root, "#", false);
    }

    #[test]
    fn the_examples_check_out_and_cover_every_key() {
        let root = schema();
        let mut seen = against_schema(&root, EVERY_KEY);
        seen.extend(against_schema(&root, LOCAL_LAYER));

        let config: Schema = toml::from_str(EVERY_KEY).expect("devconfig reads the example");
        config.validate().expect("the example is a valid config");
        toml::from_str::<Schema>(LOCAL_LAYER).expect("devconfig reads the local layer");

        let expected: BTreeSet<String> = structs()
            .into_iter()
            .flat_map(|(def, _)| {
                schema_fields(&root, def)
                    .into_iter()
                    .map(move |k| format!("{def}.{k}"))
            })
            .collect();
        assert_eq!(expected, seen, "the examples do not exercise every key");
    }

    #[test]
    fn schema_and_rust_describe_the_same_variants() {
        let root = schema();
        #[allow(clippy::type_complexity)]
        let enums: [(&str, fn() -> BTreeSet<String>); 5] = [
            ("/$defs/policy", || rust_variants::<Policy>()),
            ("/$defs/checkout-mode", || rust_variants::<CheckoutMode>()),
            ("/$defs/freshness", || rust_variants::<Freshness>()),
            ("/$defs/vscode/properties/state", || {
                rust_variants::<EditorState>()
            }),
            ("/$defs/network/properties/egress", || {
                rust_variants::<Egress>()
            }),
        ];
        for (pointer, variants) in enums {
            let node = root
                .pointer(pointer)
                .unwrap_or_else(|| panic!("the schema has no {pointer}"));
            let described: BTreeSet<String> = node["enum"]
                .as_array()
                .unwrap_or_else(|| panic!("{pointer} lists no variants"))
                .iter()
                .map(|v| {
                    v.as_str()
                        .unwrap_or_else(|| panic!("{pointer} lists {v}, which is not a string"))
                        .to_string()
                })
                .collect();
            assert_eq!(
                described,
                variants(),
                "{pointer} and its devconfig enum disagree"
            );
        }
    }

    #[test]
    fn every_described_struct_refuses_unknown_keys() {
        let root = schema();
        for (def, _) in structs() {
            assert_eq!(
                def_node(&root, def).get("additionalProperties"),
                Some(&Json::Bool(false)),
                "{def} takes keys its devconfig struct denies"
            );
        }
    }

    #[test]
    fn the_template_carries_the_directive_and_checks_out() {
        let root = schema();
        let template = crate::dev::config::TEMPLATE;
        assert_eq!(
            template.lines().next(),
            Some(DIRECTIVE),
            "`vk dev init`'s template must point editors at the schema"
        );
        against_schema(&root, template);
        toml::from_str::<Schema>(template).expect("devconfig reads its own template");
        assert!(
            SCHEMA_JSON.contains(&DIRECTIVE["#:schema ".len()..]),
            "the schema's $id is not where the directive sends editors"
        );
    }

    #[test]
    fn the_schema_uses_only_what_is_checked() {
        /// Every keyword the schema uses, walking into the places a schema node can hold
        /// another one rather than treating property names as keywords.
        fn keywords(node: &Json, out: &mut BTreeSet<String>) {
            let Some(object) = node.as_object() else {
                return;
            };
            for (key, value) in object {
                out.insert(key.clone());
                match key.as_str() {
                    "properties" | "$defs" => {
                        for (_, v) in value.as_object().into_iter().flatten() {
                            keywords(v, out);
                        }
                    }
                    "additionalProperties" | "items" | "propertyNames" | "not" => {
                        keywords(value, out);
                    }
                    "anyOf" => {
                        for v in value.as_array().into_iter().flatten() {
                            keywords(v, out);
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut used = BTreeSet::new();
        keywords(&schema(), &mut used);
        let known: BTreeSet<String> = IMPLEMENTED
            .iter()
            .chain(&ANNOTATIONS)
            .map(|k| (*k).to_string())
            .collect();
        let unchecked: Vec<&String> = used.difference(&known).collect();
        assert!(
            unchecked.is_empty(),
            "the schema uses {unchecked:?}, which the check above would ignore"
        );
    }

    /// The document describes both files, and a local layer states no version, so a missing
    /// `schema` is `vk`'s to report.
    #[test]
    fn the_document_leaves_the_schema_version_to_vk() {
        let text = "[dev]\nimage = \"x\"\n";
        against_schema(&schema(), text);

        let config: Schema = toml::from_str(text).expect("devconfig reads it");
        let err = format!("{:#}", config.validate().expect_err("but vk does not"));
        assert!(err.contains("`schema = 1`"), "{err}");
    }

    /// `restricted` parses, so `vk` refuses it with an explanation rather than an editor
    /// reporting a value the schema has never heard of.
    #[test]
    fn the_document_takes_the_egress_vk_refuses_by_name() {
        let text = "schema = 1\n[dev]\nimage = \"x\"\n[dev.network]\negress = \"restricted\"\n";
        against_schema(&schema(), text);

        let config: Schema = toml::from_str(text).expect("devconfig reads it");
        let err = format!(
            "{:#}",
            config.validate().expect_err("but vk does not run it")
        );
        assert!(err.contains("not implemented"), "{err}");
    }

    /// The constraints the document states itself, rather than leaving to `vk dev`.
    #[test]
    fn the_documents_own_constraints_are_refused_on_both_sides() {
        let image = "schema = 1\n[dev]\nimage = \"x\"\n";
        for (text, err) in [
            (
                format!("{image}workspace = \"workdir\"\n"),
                "dev.workspace: \"workdir\" does not match ^/",
            ),
            (
                format!("{image}[dev.mounts.home]\nsource = \"~\"\nto = \"rel\"\n"),
                "dev.mounts.home.to: \"rel\" does not match ^/",
            ),
            (
                format!("{image}[dev.editor.vscode]\nhome = \"dev\"\n"),
                "dev.editor.vscode.home: \"dev\" does not match ^/",
            ),
            (
                "schema = 1\n[dev]\ncompose = \"c.yaml\"\n".to_string(),
                "dev.service is required",
            ),
        ] {
            let root = schema();
            let doc: toml::Value = toml::from_str(&text).expect("TOML");
            let mut check = Check::new(&root);
            check.check("#", &root, &doc, "");
            assert_eq!(check.errs, vec![err.to_string()]);

            let config: Schema = toml::from_str(&text).expect("devconfig reads it");
            assert!(config.validate().is_err(), "{text}");
        }
    }

    #[test]
    fn an_unknown_key_is_refused_on_both_sides() {
        let base = "schema = 1\n[dev]\nimage = \"x\"\n";
        for (extra, err) in [
            (
                "[environments.stock]\nimage = \"y\"\n[environments.stock.typo]\nwhat = 1\n",
                "environments.stock.typo: unknown key",
            ),
            // A typo in an option of a hook must not read as a group of two named hooks.
            (
                "[dev.hooks.create]\nrun = \"x\"\ntimout = \"10m\"\n",
                "dev.hooks.create: no accepted form of hook",
            ),
        ] {
            let root = schema();
            let text = format!("{base}{extra}");
            let doc: toml::Value = toml::from_str(&text).expect("TOML");
            let mut check = Check::new(&root);
            check.check("#", &root, &doc, "");
            assert_eq!(check.errs, vec![err.to_string()]);
            assert!(toml::from_str::<Schema>(&text).is_err(), "{text}");
        }
    }
}
