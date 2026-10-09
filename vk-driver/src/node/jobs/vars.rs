//! A placed job's variables as gitlab-runner hands them to a job: the job's own, between the
//! ones the runner sets before and after them, every value but a raw one expanded against the
//! whole list, file variables standing for a file under the project's temporary dir.
//!
//! Ported from gitlab-runner v19.5's `common/build.go` (`GetAllVariables`,
//! `GetDefaultVariables`, `GetCITLSVariables`, `getBaseVariablesAfterJob`) and
//! `common/spec/variables.go`, with Go's `os.Expand` (MIT and BSD-3; the notices are in
//! `NOTICE`).

use vk_hub_proto::job::{CiJob, Variable};

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
    pub fn of(job: &CiJob, place: &Place) -> Vars {
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
