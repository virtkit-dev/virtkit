//! A placed job's variables as gitlab-runner hands them to a job: the job's own, between the
//! ones the runner sets before and after them, every value but a raw one expanded against the
//! whole list, file variables standing for a file under the project's temporary dir.
//!
//! Ported from gitlab-runner v19.5's `common/build.go` (`GetAllVariables`,
//! `GetDefaultVariables`, `GetCITLSVariables`, `getBaseVariablesAfterJob`) and
//! `common/spec/variables.go`, with Go's `os.Expand` (MIT and BSD-3; the notices are in
//! `NOTICE`).

use vk_hub_proto::dispatch::JobRegistry;
use vk_hub_proto::job::{CiJob, Variable};

use crate::config::Config;

/// The variable holding the project's temporary dir (`spec.TempProjectDirVariableKey`).
pub const TEMP_PROJECT_DIR: &str = "RUNNER_TEMP_PROJECT_DIR";

/// Where the job runs, which the runner's variables describe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Place {
    /// `CI_BUILDS_DIR`, in the guest.
    pub builds_dir: String,
    /// `CI_PROJECT_DIR`, in the guest.
    pub project_dir: String,
    /// `CI_CONCURRENT_ID`: the job's slot among the node's.
    pub concurrent_id: u32,
    /// `CI_CONCURRENT_PROJECT_ID`: its slot among the node's jobs of the same project.
    pub concurrent_project_id: u32,
}

/// The job's variables, in gitlab-runner's order: a later one of a key overrides an earlier.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Vars(Vec<Variable>);

fn runner_var(key: &str, value: impl Into<String>) -> Variable {
    Variable {
        key: key.into(),
        value: value.into(),
        public: true,
        ..Variable::default()
    }
}

impl Vars {
    /// Every variable of `job` placed at `place`, expanded.
    #[cfg(test)]
    pub fn of(job: &CiJob, place: &Place) -> Vars {
        Vars::of_with(job, place, &[])
    }

    /// [`Vars::of`] for `job` at `place`, plus [`registry_vars`] for its hub-granted access
    /// under `[registry] guest_credential = "job"`. Used by the driver and later cleanup.
    pub fn of_placed(
        cfg: &Config,
        job: &CiJob,
        registry: Option<&JobRegistry>,
        place: &Place,
    ) -> Vars {
        let extra = guest_registry(cfg, registry)
            .map(registry_vars)
            .unwrap_or_default();
        Vars::of_with(job, place, &extra)
    }

    /// [`Vars::of`] with runner-set `extra` for this job. Added after job variables to take
    /// precedence, and before expansion so job variables can refer to them.
    fn of_with(job: &CiJob, place: &Place, extra: &[Variable]) -> Vars {
        let mut vars = Vec::new();
        if !job.image.name.is_empty() {
            vars.push(runner_var("CI_JOB_IMAGE", &job.image.name));
        }
        vars.push(runner_var("CI_BUILDS_DIR", &place.builds_dir));
        vars.push(runner_var("CI_PROJECT_DIR", &place.project_dir));
        vars.push(runner_var(
            "CI_CONCURRENT_ID",
            place.concurrent_id.to_string(),
        ));
        vars.push(runner_var(
            "CI_CONCURRENT_PROJECT_ID",
            place.concurrent_project_id.to_string(),
        ));
        vars.push(runner_var("CI_SERVER", "yes"));
        vars.push(runner_var("CI_JOB_STATUS", "running"));
        vars.push(runner_var("CI_JOB_TIMEOUT", job.timeout_secs.to_string()));
        if let Some(pem) = &job.server_ca_pem {
            vars.push(Variable {
                file: true,
                ..runner_var("CI_SERVER_TLS_CA_FILE", pem.as_str())
            });
        }
        vars.extend(job.variables.iter().cloned());
        vars.push(runner_var("CI_DISPOSABLE_ENVIRONMENT", "true"));
        vars.push(runner_var(
            TEMP_PROJECT_DIR,
            format!("{}.tmp", place.project_dir),
        ));
        vars.extend(extra.iter().cloned());
        Vars(vars).expanded()
    }

    /// Each value but a raw one expanded against the whole list (`Variables.Expand`).
    fn expanded(self) -> Vars {
        let out = self
            .0
            .iter()
            .map(|v| match v.raw {
                true => v.clone(),
                false => Variable {
                    value: self.expand(&v.value),
                    ..v.clone()
                },
            })
            .collect();
        Vars(out)
    }

    pub fn all(&self) -> &[Variable] {
        &self.0
    }

    fn last(&self, key: &str) -> Option<&Variable> {
        self.0.iter().rev().find(|v| v.key == key)
    }

    /// The value of `key`, or the path of its file for a file variable (`Variables.Get`).
    pub fn get(&self, key: &str) -> String {
        self.lookup(key, true)
    }

    /// The value of `key`, a file variable's content included (`Variables.Value`).
    pub fn value(&self, key: &str) -> String {
        self.lookup(key, false)
    }

    fn lookup(&self, key: &str, pathnames: bool) -> String {
        match key {
            "$" => return key.into(),
            "*" | "#" | "@" | "!" | "?" | "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8"
            | "9" => return String::new(),
            _ => {}
        }
        match self.last(key) {
            Some(v) if v.file && pathnames => self.tmp_file(&v.key),
            Some(v) => v.value.clone(),
            None => String::new(),
        }
    }

    /// Where a file variable's file is: under the project's temporary dir.
    pub fn tmp_file(&self, key: &str) -> String {
        format!(
            "{}/{key}",
            self.value(TEMP_PROJECT_DIR).trim_end_matches('/')
        )
    }

    /// `s` with `$NAME` and `${NAME}` replaced from the variables (`Variables.ExpandValue`).
    pub fn expand(&self, s: &str) -> String {
        expand(s, |name| self.get(name))
    }

    /// The masked variables' values, which the trace never shows.
    pub fn masked(&self) -> Vec<String> {
        self.0
            .iter()
            .filter(|v| v.masked)
            .map(|v| v.value.clone())
            .collect()
    }

    /// Set `key` where it first appears, as after_script's `CI_JOB_STATUS` is
    /// (`Variables.OverwriteKey`).
    pub fn overwrite(&mut self, key: &str, value: &str) {
        if let Some(v) = self.0.iter_mut().find(|v| v.key == key) {
            v.value = value.into();
        }
    }
}

/// Go's `os.Expand`.
pub fn expand(s: &str, mapping: impl Fn(&str) -> String) -> String {
    let b = s.as_bytes();
    let mut buf: Option<String> = None;
    let mut i = 0;
    let mut j = 0;
    while j < b.len() {
        if b[j] == b'$' && j + 1 < b.len() {
            let out = buf.get_or_insert_with(String::new);
            out.push_str(&s[i..j]);
            let (name, w) = shell_name(&s[j + 1..]);
            match (name, w) {
                ("", w) if w > 0 => {} // invalid syntax: eaten
                ("", _) => out.push('$'),
                (name, _) => out.push_str(&mapping(name)),
            }
            j += w;
            i = j + 1;
        }
        j += 1;
    }
    match buf {
        None => s.to_string(),
        Some(mut out) => {
            out.push_str(s.get(i..).unwrap_or_default());
            out
        }
    }
}

fn special(c: u8) -> bool {
    matches!(
        c,
        b'*' | b'#' | b'$' | b'@' | b'!' | b'?' | b'-' | b'0'..=b'9'
    )
}

fn alnum(c: u8) -> bool {
    c == b'_' || c.is_ascii_alphanumeric()
}

/// Go's `os.getShellName`: the name after a `$`, and how many bytes it took.
fn shell_name(s: &str) -> (&str, usize) {
    let b = s.as_bytes();
    if b[0] == b'{' {
        if b.len() > 2 && special(b[1]) && b[2] == b'}' {
            return (&s[1..2], 3);
        }
        for i in 1..b.len() {
            if b[i] == b'}' {
                if i == 1 {
                    return ("", 2);
                }
                return (&s[1..i], i + 1);
            }
        }
        return ("", 1);
    }
    if special(b[0]) {
        return (&s[0..1], 1);
    }
    let n = b.iter().take_while(|&&c| alnum(c)).count();
    (&s[..n], n)
}

/// The job's registry access when its guest's proxy injects it: `[registry] guest_credential
/// = "job"` on a remote registry, a token from the hub, and `net.mode = "switch"`, the only
/// network that serves `registry.vk`.
pub fn guest_registry<'a>(
    cfg: &Config,
    registry: Option<&'a JobRegistry>,
) -> Option<&'a JobRegistry> {
    cfg.registry
        .as_ref()
        .filter(|rg| rg.lends_job_token() && cfg.net.mode == "switch")
        .and(registry)
}

/// The variables that tell a job's steps where its registry is, and what they may do there:
/// `VK_REGISTRY`, the guest's proxy, and `VK_REGISTRY_NAMESPACES`, its grants as
/// `<prefix>=<rights>`, space-separated, raw: a grant whose prefix is not a repository name
/// is left out, so the hub cannot put a separator or a `$` reference in it. Never the token.
fn registry_vars(registry: &JobRegistry) -> Vec<Variable> {
    let namespaces = registry
        .grants
        .iter()
        .filter(|g| vk_hub_proto::token::valid_prefix(&g.prefix))
        .map(|g| format!("{}={}", g.prefix, g.rights()))
        .collect::<Vec<_>>()
        .join(" ");
    vec![
        runner_var(
            "VK_REGISTRY",
            format!("http://{}", crate::regproxy::GUEST_HOST),
        ),
        Variable {
            raw: true,
            ..runner_var("VK_REGISTRY_NAMESPACES", namespaces)
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use vk_hub_proto::job::Image;

    fn var(key: &str, value: &str) -> Variable {
        Variable {
            key: key.into(),
            value: value.into(),
            public: true,
            ..Variable::default()
        }
    }

    fn place() -> Place {
        Place {
            builds_dir: "/builds".into(),
            project_dir: "/builds/acme/web".into(),
            concurrent_id: 2,
            concurrent_project_id: 0,
        }
    }

    fn job_registry() -> JobRegistry {
        use vk_hub_proto::token::Grant;
        JobRegistry {
            registry_id: "9c2f4e1a7b3d5e60f1a2b3c4d5e6f708".into(),
            token: "vkt_x.y".into(),
            expires_at: 99,
            grants: vec![
                Grant {
                    prefix: "p/gl/42".into(),
                    read: true,
                    write: true,
                    lock: true,
                },
                Grant {
                    prefix: "images".into(),
                    read: true,
                    ..Grant::default()
                },
            ],
            cache_repo: None,
            pipeline_prefix: None,
        }
    }

    fn cfg(toml: &str) -> Config {
        toml::from_str(toml).unwrap()
    }

    const JOB: &str = "[net]\nmode = \"switch\"\n\
        [registry]\nrepo = \"reg.example/t\"\nguest_credential = \"job\"\n";

    /// Steps learn where the proxy is and what they may do there, never the token; a job's
    /// own variable of the same name does not override them, and one may refer to them.
    #[test]
    fn a_job_token_gives_the_steps_its_registry_and_namespaces() {
        let job = CiJob {
            variables: vec![
                var("VK_REGISTRY", "http://elsewhere"),
                var("PUSH_TO", "$VK_REGISTRY/v2/x"),
            ],
            ..CiJob::default()
        };
        let r = job_registry();
        let vars = Vars::of_placed(&cfg(JOB), &job, Some(&r), &place());
        assert_eq!(vars.get("VK_REGISTRY"), "http://registry.vk");
        assert_eq!(vars.get("VK_REGISTRY_NAMESPACES"), "p/gl/42=rwl images=r");
        assert_eq!(vars.get("PUSH_TO"), "http://registry.vk/v2/x");
        assert!(vars.0.iter().all(|v| !v.value.contains("vkt_")));
    }

    /// Only a node lending the job's token tells its steps of it.
    #[test]
    fn only_guest_credential_job_lends_the_token() {
        let r = job_registry();
        assert!(guest_registry(&cfg(JOB), Some(&r)).is_some());
        assert!(guest_registry(&cfg(JOB), None).is_none());
        let node = cfg("[registry]\nrepo = \"reg.example/t\"\nproxy_guests = true\n");
        assert!(guest_registry(&node, Some(&r)).is_none());
        let local = cfg("[registry]\nrepo = \"/srv/store\"\nguest_credential = \"job\"\n");
        assert!(guest_registry(&local, Some(&r)).is_none());
        // Only the switch serves registry.vk.
        let no_switch = cfg("[registry]\nrepo = \"reg.example/t\"\nguest_credential = \"job\"\n");
        assert!(guest_registry(&no_switch, Some(&r)).is_none());
        let vars = Vars::of_placed(&node, &CiJob::default(), Some(&r), &place());
        assert_eq!(vars.get("VK_REGISTRY"), "");
    }

    /// The namespaces are listed as the hub granted them, never expanded, and only grants
    /// whose prefix is a repository name.
    #[test]
    fn the_namespaces_are_raw_and_only_valid_prefixes() {
        use vk_hub_proto::token::Grant;
        let mut r = job_registry();
        for bad in ["$HOME", "a b", "a=b", "/abs", "UP", ""] {
            r.grants.push(Grant {
                prefix: bad.into(),
                read: true,
                ..Grant::default()
            });
        }
        let job = CiJob {
            variables: vec![var("HOME", "/root")],
            ..CiJob::default()
        };
        let vars = Vars::of_placed(&cfg(JOB), &job, Some(&r), &place());
        assert_eq!(vars.get("VK_REGISTRY_NAMESPACES"), "p/gl/42=rwl images=r");
        let ns = vars
            .0
            .iter()
            .find(|v| v.key == "VK_REGISTRY_NAMESPACES")
            .unwrap();
        assert!(ns.raw);
    }

    /// Go's `os.Expand` cases (`os/env_test.go` `expandTests`).
    #[test]
    fn expansion_follows_go() {
        let get = |name: &str| match name {
            "*" => "all the args".to_string(),
            "#" => "NARGS".to_string(),
            "$" => "PID".to_string(),
            "1" => "ARGUMENT1".to_string(),
            "HOME" => "/usr/gopher".to_string(),
            "H" => "(Value of H)".to_string(),
            "home_1" => "/usr/foo".to_string(),
            "_" => "underscore".to_string(),
            _ => String::new(),
        };
        let cases = [
            ("", ""),
            ("$*", "all the args"),
            ("$$", "PID"),
            ("${*}", "all the args"),
            ("$1", "ARGUMENT1"),
            ("${1}", "ARGUMENT1"),
            ("now is the time", "now is the time"),
            ("$HOME", "/usr/gopher"),
            ("$home_1", "/usr/foo"),
            ("${HOME}", "/usr/gopher"),
            ("${H}OME", "(Value of H)OME"),
            (
                "A$$$#$1$H$home_1*B",
                "APIDNARGSARGUMENT1(Value of H)/usr/foo*B",
            ),
            ("start$+middle$^end$", "start$+middle$^end$"),
            ("mixed$|bag$$$", "mixed$|bagPID$"),
            ("$", "$"),
            ("$}", "$}"),
            ("${", ""),
            ("${}", ""),
        ];
        for (input, want) in cases {
            assert_eq!(expand(input, get), want, "{input:?}");
        }
    }

    #[test]
    fn the_runner_variables_surround_the_jobs_and_values_expand() {
        let job = CiJob {
            image: Image {
                name: "rust:1".into(),
                ..Image::default()
            },
            timeout_secs: 600,
            variables: vec![
                var("GREETING", "hello $CI_PROJECT_DIR"),
                Variable {
                    raw: true,
                    ..var("RAW", "$CI_PROJECT_DIR")
                },
                // A job may override what the runner set before its variables...
                var("CI_SERVER", "maybe"),
                // ...but not what it sets after them.
                var("CI_DISPOSABLE_ENVIRONMENT", "false"),
                Variable {
                    file: true,
                    ..var("KEYFILE", "secret")
                },
                var("POINTS", "$KEYFILE"),
            ],
            ..CiJob::default()
        };
        let vars = Vars::of(&job, &place());
        assert_eq!(vars.get("CI_JOB_IMAGE"), "rust:1");
        assert_eq!(vars.get("GREETING"), "hello /builds/acme/web");
        assert_eq!(vars.get("RAW"), "$CI_PROJECT_DIR");
        assert_eq!(vars.get("CI_SERVER"), "maybe");
        assert_eq!(vars.get("CI_DISPOSABLE_ENVIRONMENT"), "true");
        assert_eq!(vars.get("CI_JOB_TIMEOUT"), "600");
        assert_eq!(vars.get("CI_CONCURRENT_ID"), "2");
        assert_eq!(vars.get("KEYFILE"), "/builds/acme/web.tmp/KEYFILE");
        assert_eq!(vars.value("KEYFILE"), "secret");
        assert_eq!(vars.get("POINTS"), "/builds/acme/web.tmp/KEYFILE");
    }

    #[test]
    fn masked_values_are_listed_and_tls_is_a_file_variable() {
        let job = CiJob {
            server_ca_pem: Some("PEM".into()),
            variables: vec![Variable {
                masked: true,
                ..var("TOKEN", "s3cr3t-token")
            }],
            ..CiJob::default()
        };
        let vars = Vars::of(&job, &place());
        assert_eq!(vars.masked(), vec!["s3cr3t-token".to_string()]);
        assert_eq!(
            vars.get("CI_SERVER_TLS_CA_FILE"),
            "/builds/acme/web.tmp/CI_SERVER_TLS_CA_FILE"
        );
    }
}
