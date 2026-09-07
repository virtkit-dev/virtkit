//! The JSON Schema for `.virtkit/config.toml`, so an editor completes and checks the file
//! as it is typed rather than at the next `vk dev`.
//!
//! The schema lives in the repository at `docs/schema/virtkit-config.schema.json` and is
//! embedded here, so a `vk` can hand out the schema it actually reads. A TOML editor that
//! speaks JSON Schema (taplo, VS Code's Even Better TOML) picks it up from the [`DIRECTIVE`]
//! comment `vk dev init` writes on the first line; a checkout can point at its own copy
//! instead, and `.virtkit/config.toml` is an ordinary comment either way.
//!
//! [`crate::dev::config`] is the source of truth: the tests below derive every struct's field
//! names from serde itself and fail when the two drift apart.

/// The directive as a literal, so [`crate::dev::config::TEMPLATE`] can `concat!` it into its
/// own first line rather than spelling the URL a second time.
macro_rules! directive {
    () => {
        "#:schema https://raw.githubusercontent.com/virtkit-dev/virtkit/main/docs/schema/virtkit-config.schema.json"
    };
}
pub(crate) use directive;

/// The line `vk dev init` writes at the top of a config, and what to paste into one written
/// by hand.
pub const DIRECTIVE: &str = directive!();

/// The schema itself, as shipped in the repository, and what `vk dev schema` prints.
// Embedded so the binary can hand out the schema for the config format it reads, whatever
// the checkout beside it says.
pub const SCHEMA_JSON: &str = include_str!("../../../docs/schema/virtkit-config.schema.json");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::config::{
        Build, Cache, Editor, Endpoint, Environment, Fallback, HookSpec, Hooks, Host, Mount,
        Network, Requires, Schema, Task, VsCode,
    };
    use serde::de::DeserializeOwned;
    use serde_json::Value as Json;
    use std::collections::BTreeSet;

    /// A key no struct has, to make serde name the keys they do have.
    const UNKNOWN: &str = "zz-not-a-key = 1\n";

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
            ("cache", || rust_fields::<Cache>()),
            ("endpoint", || rust_fields::<Endpoint>()),
            ("network", || rust_fields::<Network>()),
            ("hooks", || rust_fields::<Hooks>()),
            ("hook-spec", || rust_fields::<HookSpec>()),
        ]
    }

    /// The field names serde accepts for `T`, read out of the error a key it does not accept
    /// produces: "unknown field `zz-not-a-key`, expected one of `a`, `b`". Derived rather
    /// than listed, so a field added to the Rust cannot go missing here.
    ///
    /// This reads serde's English, and is one wording change upstream away from finding no
    /// list at all — which is why it panics with the message it could not parse rather than
    /// returning an empty set that would pass every comparison below.
    fn rust_fields<T: DeserializeOwned>() -> BTreeSet<String> {
        let err = toml::from_str::<T>(UNKNOWN)
            .err()
            .unwrap_or_else(|| panic!("{} accepts unknown keys", std::any::type_name::<T>()))
            .to_string();
        let at = err
            .find("expected")
            .unwrap_or_else(|| panic!("no field list in: {err}"));
        let mut rest = &err[at..];
        let mut out = BTreeSet::new();
        while let Some(open) = rest.find('`') {
            let after = &rest[open + 1..];
            let close = after
                .find('`')
                .unwrap_or_else(|| panic!("unbalanced field list in: {err}"));
            out.insert(after[..close].to_string());
            rest = &after[close + 1..];
        }
        assert!(!out.is_empty(), "no field list in: {err}");
        out
    }

    fn schema() -> Json {
        serde_json::from_str(SCHEMA_JSON).expect("the schema parses as JSON")
    }

    /// The property names one schema definition describes.
    fn schema_fields(root: &Json, def: &str) -> BTreeSet<String> {
        let node = match def {
            "#" => root,
            name => root["$defs"]
                .get(name)
                .unwrap_or_else(|| panic!("the schema has no {name} definition")),
        };
        node["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{def} describes no properties"))
            .keys()
            .cloned()
            .collect()
    }

    /// The JSON Schema keywords [`Check`] implements, over the annotations it may ignore.
    /// `the_schema_uses_only_what_is_checked` holds the schema to this list, so a keyword
    /// added to the schema cannot be "checked" by being skipped.
    const IMPLEMENTED: [&str; 11] = [
        "$ref",
        "type",
        "enum",
        "const",
        "properties",
        "additionalProperties",
        "items",
        "anyOf",
        "minimum",
        "maximum",
        "required",
    ];

    /// Keywords that describe rather than constrain, and are the reader's business.
    const ANNOTATIONS: [&str; 5] = ["$schema", "$id", "title", "description", "$defs"];

    /// Checking a config against the schema: enough of draft 2020-12 for what the schema
    /// uses — see [`IMPLEMENTED`] — over TOML rather than JSON, so the documents it checks
    /// are the documents `vk` reads. It also records which properties a document exercised,
    /// so the examples below are kept complete.
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
        fn resolve(&self, def: &str, node: &'a Json) -> (String, &'a Json) {
            let Some(r) = node.get("$ref").and_then(Json::as_str) else {
                return (def.to_string(), node);
            };
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
            if let Some(allowed) = node.get("enum").and_then(Json::as_array) {
                let got = value.as_str().unwrap_or_default();
                if !allowed.iter().any(|a| a.as_str() == Some(got)) {
                    self.errs
                        .push(format!("{path}: {got:?} is not one of {allowed:?}"));
                }
            }
            if let Some(want) = node.get("const")
                && !matches!(value, toml::Value::String(s) if want.as_str() == Some(s.as_str()))
                && !matches!(value, toml::Value::Integer(n) if want.as_i64() == Some(*n))
            {
                self.errs.push(format!("{path}: expected {want}"));
            }
            match value {
                toml::Value::Table(table) => {
                    for want in node
                        .get("required")
                        .and_then(Json::as_array)
                        .unwrap_or(&Vec::new())
                    {
                        let key = want.as_str().unwrap_or_default();
                        if !table.contains_key(key) {
                            let at = match path.is_empty() {
                                true => key.to_string(),
                                false => format!("{path}.{key}"),
                            };
                            self.errs.push(format!("{at} is required"));
                        }
                    }
                    for (key, value) in table {
                        let at = match path.is_empty() {
                            true => key.clone(),
                            false => format!("{path}.{key}"),
                        };
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

    fn kind(value: &toml::Value) -> &'static str {
        match value {
            toml::Value::String(_) | toml::Value::Datetime(_) => "string",
            toml::Value::Integer(_) => "integer",
            toml::Value::Float(_) => "number",
            toml::Value::Boolean(_) => "boolean",
            toml::Value::Array(_) => "array",
            toml::Value::Table(_) => "object",
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

    /// The same, for a local layer: a partial document, so what the root requires of the
    /// tracked file does not apply to it.
    fn against_schema_layer(root: &Json, text: &str) -> BTreeSet<String> {
        let mut root = root.clone();
        root.as_object_mut()
            .expect("the schema is an object")
            .remove("required");
        against_schema(&root, text)
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
ssh-agent = true
wrapper = "dev/tools/host.sh"
wrapper-env = ["DISPLAY"]

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
    }

    #[test]
    fn the_examples_check_out_and_cover_every_key() {
        let root = schema();
        let mut seen = against_schema(&root, EVERY_KEY);
        seen.extend(against_schema_layer(&root, LOCAL_LAYER));

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
                    "additionalProperties" | "items" => keywords(value, out),
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

    #[test]
    fn a_config_with_no_schema_version_fails_the_schema_too() {
        let root = schema();
        let doc: toml::Value =
            toml::from_str("[dev]\nimage = \"x\"\n").expect("the example is TOML");
        let mut check = Check::new(&root);
        check.check("#", &root, &doc, "");
        assert_eq!(check.errs, vec!["schema is required".to_string()]);
    }

    #[test]
    fn an_unknown_key_is_refused_on_both_sides() {
        let root = schema();
        let text = format!("{EVERY_KEY}\n[environments.stock.typo]\nwhat = 1\n");
        let doc: toml::Value = toml::from_str(&text).expect("TOML");
        let mut check = Check::new(&root);
        check.check("#", &root, &doc, "");
        assert_eq!(
            check.errs,
            vec!["environments.stock.typo: unknown key".to_string()]
        );
        assert!(toml::from_str::<Schema>(&text).is_err());
    }
}
