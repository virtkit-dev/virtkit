//! The scripts a placed job's guest runs, stage by stage, written as gitlab-runner's bash shell
//! writes them: every variable exported, the project dir entered, each command echoed before
//! it runs, and the whole body `eval`ed in a subshell under `errexit` and `pipefail`, so the
//! first failing command ends the stage with its exit code.
//!
//! The stages a node runs on the host — caches and artifacts — have no script here; the git
//! checkout has one only when the node does not check the sources out on the host.
//!
//! Ported from gitlab-runner v19.5's `shells/bash.go` (`BashWriter`, `BashShell`),
//! `shells/abstract.go` (`writeExports`, `writeUserScript`, `writeCommands`,
//! `writeAfterScript`, `writePrepareScript`, `writeGetSourcesScript` and the git commands under
//! it, `writeCleanupScript`) and `helpers/shell_escape.go` (MIT; see [`super::mask`] for the
//! notice).

#[cfg(test)]
use vk_hub_proto::job::Variable;
use vk_hub_proto::job::{CiJob, HookName, ObjectFormat, Step};

use super::settings::{GitStrategy, Settings, Submodules};
use super::trace::{ANSI_BOLD_GREEN, ANSI_BOLD_RED, ANSI_RESET, ANSI_YELLOW};
use super::vars::Vars;

const GITLAB_ENV_FILE: &str = "gitlab_runner_env";
const EXTERNAL_GIT_CONFIG: &str = ".gitlab-runner.ext.conf";
const GIT_TEMPLATE_DIR: &str = "git-template";
const EXT_CONFIG_VAR: &str = "GLR_EXT_GIT_CONFIG_PATH";
const BUILD_UID_GID_FILE: &str = ".gitlab-build-uid-gid";

/// `credHelperCommand`: git asks it for the password, and it answers with the job token from
/// the environment, so the token is never written into a git config or a URL.
const CRED_HELPER: &str =
    r#"!f(){ if [ "$1" = "get" ] ; then echo "password=${CI_JOB_TOKEN}" ; fi ; } ; f"#;

/// `bashExitOnScriptTerminationSignal`.
const EXIT_ON_TERM: &str = "trap 'exit 1' TERM";

/// `bashCPUInfoScript`.
const CPU_INFO: &str = r#"(
  model=$(awk -F ': *' '/^model name/ { print $2; exit }' /proc/cpuinfo 2>/dev/null)
  [ -n "$model" ] || model=$(LC_ALL=C lscpu 2>/dev/null | awk -F ': *' '/^Model name/ { print $2; exit }')
  [ "$model" != "-" ] || model=
  flags=$(awk '/^flags/ { print; exit }' /proc/cpuinfo 2>/dev/null)
  isa=
  for f in avx avx2 avx512f; do
    case " $flags " in *" $f "*) isa="$isa${isa:+, }$f" ;; esac
  done
  echo "Running on CPU: ${model:-unknown}${isa:+ ($isa)}"
) || true"#;

/// What every stage script is written from.
pub struct Info<'a> {
    pub job: &'a CiJob,
    pub vars: &'a Vars,
    pub settings: &'a Settings,
    /// `CI_PROJECT_DIR`, in the guest.
    pub project_dir: &'a str,
    /// `CI_BUILDS_DIR`, in the guest.
    pub builds_dir: &'a str,
    /// The guest has no bash: POSIX quoting (`FF_POSIXLY_CORRECT_ESCAPES`).
    pub posix: bool,
    /// The node's name, for the prepare stage's `Running on … via …` line.
    pub hostname: &'a str,
    /// The node checked the sources out on the host and shares them in.
    pub host_checkout: bool,
}

impl Info<'_> {
    fn writer(&self) -> Writer {
        Writer {
            buf: String::new(),
            indent: 0,
            posix: self.posix,
            tmp: format!("{}.tmp", self.project_dir),
        }
    }

    fn finish(&self, w: Writer) -> String {
        w.finish(self.settings.debug_trace)
    }
}

/// `prepare_script`: where the job runs, and a clean slate for its environment file.
pub fn prepare(info: &Info<'_>) -> String {
    let mut w = info.writer();
    w.line(&format!(
        "echo {}",
        go_quote(&format!("Running on $(hostname) via {}...", info.hostname))
    ));
    for line in CPU_INFO.lines() {
        w.line(line);
    }
    let env = w.tmp_file(GITLAB_ENV_FILE);
    w.rm_file(&env);
    let masking = w.tmp_file("masking.db");
    w.rm_file(&masking);
    info.finish(w)
}

/// `get_sources`: the hooks around the checkout, and the checkout itself in the guest unless
/// the node made it on the host.
pub fn get_sources(info: &Info<'_>) -> String {
    let mut w = info.writer();
    exports(&mut w, info.vars, false);
    w.variable("GIT_TERMINAL_PROMPT", "0", false);
    w.variable("GCM_INTERACTIVE", "Never", false);
    let s = info.settings;
    if s.submodules == Submodules::Invalid {
        // gitlab-runner fails to write the stage's script at all.
        w.error("unknown GIT_SUBMODULE_STRATEGY");
        w.line("exit 1");
        return info.finish(w);
    }
    let with_sources = !matches!(s.git_strategy, GitStrategy::None | GitStrategy::Empty);
    if with_sources && !info.host_checkout {
        git_ssl_config(&mut w, info);
    }
    if with_sources {
        let pre = hook(info.job, HookName::PreGetSourcesScript);
        commands(&mut w, &pre);
    }
    if info.host_checkout {
        host_checkout_notice(&mut w, info);
    } else {
        clone_fetch(&mut w, info);
        submodules(&mut w, info);
    }
    if with_sources {
        let post = hook(info.job, HookName::PostGetSourcesScript);
        commands(&mut w, &post);
    }
    if !info.host_checkout {
        clear_git_credentials(&mut w, info);
    }
    info.finish(w)
}

/// `step_<name>`.
pub fn step(info: &Info<'_>, step: &Step) -> String {
    let mut w = info.writer();
    exports(&mut w, info.vars, false);
    w.cd(info.project_dir);
    // GitLab turns `release:` into a step whose commands are expanded by the runner.
    let script: Vec<String> = match step.name.as_str() {
        "release" => step.script.iter().map(|s| info.vars.expand(s)).collect(),
        _ => step.script.clone(),
    };
    commands(&mut w, &script);
    info.finish(w)
}

/// `after_script`, or `None` when the job has none.
pub fn after_script(info: &Info<'_>, step: Option<&Step>) -> Option<String> {
    let step = step.filter(|s| !s.script.is_empty())?;
    let mut w = info.writer();
    exports(&mut w, info.vars, false);
    w.cd(info.project_dir);
    w.notice("Running after script...");
    commands(&mut w, &step.script);
    Some(info.finish(w))
}

/// `cleanup_file_variables`: the files the job's variables and git credentials left behind.
pub fn cleanup(info: &Info<'_>) -> String {
    let mut w = info.writer();
    exports(&mut w, info.vars, true);
    w.variable("GIT_TERMINAL_PROMPT", "0", false);
    w.variable("GCM_INTERACTIVE", "Never", false);
    if !info.host_checkout {
        clear_git_credentials(&mut w, info);
    }
    for name in [
        GITLAB_ENV_FILE,
        "masking.db",
        EXTERNAL_GIT_CONFIG,
        ".glr.gconf",
    ] {
        let path = w.tmp_file(name);
        w.rm_file(&path);
    }
    let mut seen = std::collections::BTreeSet::new();
    for v in info
        .vars
        .all()
        .iter()
        .filter(|v| v.file && file_key_ok(&v.key))
    {
        if seen.insert(v.key.as_str()) {
            let path = w.tmp_file(&v.key);
            w.rm_file(&path);
        }
    }
    if !info.host_checkout {
        git_cleanup(&mut w, info);
    }
    w.rm_file(&join(info.builds_dir, BUILD_UID_GID_FILE));
    info.finish(w)
}

/// The script lines of a hook, in GitLab's order.
fn hook(job: &CiJob, name: HookName) -> Vec<String> {
    job.hooks
        .iter()
        .filter(|h| h.name == name)
        .flat_map(|h| h.script.iter().cloned())
        .collect()
}

/// `exportVariables`: every variable, the job's environment file and its contents. With
/// `env_only`, file variables export their path alone: earlier stages wrote the files.
/// A file variable whose key is no shell name is skipped: its key names its file.
fn exports(w: &mut Writer, vars: &Vars, env_only: bool) {
    for v in vars.all() {
        if v.file && !file_key_ok(&v.key) {
            continue;
        }
        if env_only && v.file {
            let path = w.tmp_file(&v.key);
            w.variable(&v.key, &path, false);
        } else {
            w.variable(&v.key, &v.value, v.file);
        }
    }
    let env = w.tmp_file(GITLAB_ENV_FILE);
    w.variable("GITLAB_ENV", &env, false);
    w.source_env(&env);
}

/// `writeCommands`: each command echoed, then run.
fn commands(w: &mut Writer, script: &[String]) {
    for command in script {
        let command = command.trim();
        if command.is_empty() {
            w.empty_line();
        } else {
            match command.split_once('\n') {
                None => w.notice(&format!("$ {command}")),
                Some((first, _)) => w.notice(&format!("$ {first} # collapsed multi-line command")),
            }
        }
        w.line(command);
    }
}

fn host_checkout_notice(w: &mut Writer, info: &Info<'_>) {
    let s = info.settings;
    match s.git_strategy {
        GitStrategy::None => w.notice("Skipping Git repository setup"),
        GitStrategy::Empty => {
            w.notice("Skipping Git repository setup and creating an empty build directory")
        }
        GitStrategy::Clone | GitStrategy::Fetch => {
            let sources = &info.job.sources;
            let short = sources.sha.get(..8).unwrap_or(&sources.sha);
            w.notice(&format!(
                "Checked out {short} on the node and shared into the VM (ref is {})",
                sources.git_ref
            ));
        }
    }
}

/// A URL's scheme, its `host[:port]` without user info, and the rest from the path on.
pub(super) fn url_parts(url: &str) -> Option<(&str, &str, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    Some((scheme, host, path))
}

/// The repository's `scheme://host[:port]`, which credentials and TLS settings are scoped to.
fn remote_host(url: &str) -> Option<String> {
    let (scheme, host, _) = url_parts(url)?;
    (!host.is_empty()).then(|| format!("{scheme}://{host}"))
}

/// `writeGitSSLConfig` with `--global`: GitLab's CA for git's requests to it.
fn git_ssl_config(w: &mut Writer, info: &Info<'_>) {
    if info.job.server_ca_pem.is_none() {
        return;
    }
    let Some(host) = remote_host(&info.job.sources.repo_url) else {
        w.warning("git SSL config: Can't get repository host.");
        return;
    };
    w.command_arg_expand(
        "git",
        &[
            "config",
            "--global",
            &format!("http.{host}.sslCAInfo"),
            "$CI_SERVER_TLS_CA_FILE",
        ],
    );
}

/// `handleGetSourcesStrategy` and `writeCloneFetchCmds`, with the credential helper in an
/// external config the template and the repository include (`setupTemplateDir`,
/// `setupExternalGitConfig`).
fn clone_fetch(w: &mut Writer, info: &Info<'_>) {
    let s = info.settings;
    let project = info.project_dir;
    if !s.lfs_skip_smudge {
        w.variable("GIT_LFS_SKIP_SMUDGE", "1", false);
    }
    match s.git_strategy {
        GitStrategy::None => {
            w.notice("Skipping Git repository setup");
            w.mkdir(project);
        }
        GitStrategy::Empty => {
            w.notice("Skipping Git repository setup and creating an empty build directory");
            w.rmdir(project);
            w.mkdir(project);
        }
        GitStrategy::Clone | GitStrategy::Fetch => {
            git_cleanup(w, info);
            let template = w.tmp_file(GIT_TEMPLATE_DIR);
            w.mkdir(&template);
            let template_config = join(&template, "config");
            for (key, value) in [
                ("init.defaultBranch", "none"),
                ("fetch.recurseSubmodules", "false"),
                ("credential.interactive", "never"),
                ("gc.autoDetach", "false"),
            ] {
                w.command("git", &["config", "-f", &template_config, key, value]);
            }
            let ext = w.tmp_file(EXTERNAL_GIT_CONFIG);
            w.rm_file(&ext);
            if let Some(host) = remote_host(&info.job.sources.repo_url) {
                w.cred_helper(&ext, &format!("credential.{host}"), "gitlab-ci-token");
                if info.job.server_ca_pem.is_some() {
                    w.command_arg_expand(
                        "git",
                        &[
                            "config",
                            "--file",
                            &ext,
                            &format!("http.{host}.sslCAInfo"),
                            "$CI_SERVER_TLS_CA_FILE",
                        ],
                    );
                }
            }
            w.export_raw(EXT_CONFIG_VAR, &ext);
            include_config(w, &template_config, &ext);
            if s.git_strategy == GitStrategy::Clone {
                w.rmdir(project);
            }
            fetch(w, info, &template);
        }
    }
    if s.git_checkout {
        let sources = &info.job.sources;
        let short = sources.sha.get(..8).unwrap_or(&sources.sha);
        w.notice(&format!(
            "Checking out {short} as detached HEAD (ref is {})...",
            sources.git_ref
        ));
        w.command(
            "git",
            &[
                "-c",
                "submodule.recurse=false",
                "checkout",
                "-f",
                "-q",
                &sources.sha,
            ],
        );
        if !s.clean_flags.is_empty() {
            let mut args = vec!["clean"];
            args.extend(s.clean_flags.iter().map(String::as_str));
            w.command("git", &args);
        }
        if !s.lfs_skip_smudge {
            w.if_cmd("git", &["lfs", "version"]);
            w.command("git", &["lfs", "pull"]);
            w.empty_line();
            w.end_if();
        }
    } else {
        w.notice("Skipping Git checkout");
    }
}

/// `includeExternalGitConfig`.
fn include_config(w: &mut Writer, target: &str, include: &str) {
    let pattern = format!("{}$", regex_quote(EXTERNAL_GIT_CONFIG));
    w.command_arg_expand(
        "git",
        &[
            "config",
            "--file",
            target,
            "--replace-all",
            "include.path",
            include,
            &pattern,
        ],
    );
}

/// `writeRefspecFetchCmd`.
fn fetch(w: &mut Writer, info: &Info<'_>, template: &str) {
    let sources = &info.job.sources;
    let project = info.project_dir;
    let depth = sources.depth;
    if depth > 0 {
        w.notice(&format!(
            "Fetching changes with git depth set to {depth}..."
        ));
    } else {
        w.notice("Fetching changes...");
    }
    match sources.object_format {
        ObjectFormat::Sha1 => w.command("git", &["init", project, "--template", template]),
        ObjectFormat::Sha256 => w.command(
            "git",
            &[
                "init",
                project,
                "--template",
                template,
                "--object-format",
                "sha256",
            ],
        ),
    }
    w.cd(project);
    w.if_cmd("git", &["remote", "add", "origin", &sources.repo_url]);
    w.notice("Created fresh repository.");
    w.else_();
    w.command("git", &["remote", "set-url", "origin", &sources.repo_url]);
    let ext = format!("${EXT_CONFIG_VAR}");
    include_config(w, ".git/config", &ext);
    w.end_if();
    let agent = format!(
        "http.userAgent=vk {} linux/{}",
        env!("CARGO_PKG_VERSION"),
        go_arch()
    );
    let mut args: Vec<String> = vec![
        "-c".into(),
        agent,
        "fetch".into(),
        "origin".into(),
        "--no-recurse-submodules".into(),
    ];
    args.extend(sources.refspecs.iter().cloned());
    if depth > 0 {
        args.push("--depth".into());
        args.push(depth.to_string());
    }
    args.extend(info.settings.fetch_flags.iter().cloned());
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    if depth == 0 {
        let mut unshallow = args.clone();
        unshallow.push("--unshallow");
        w.if_file(".git/shallow");
        w.command("git", &unshallow);
        w.else_();
        w.command("git", &args);
        w.end_if();
    } else {
        w.command("git", &args);
    }
}

/// `writeSubmoduleUpdateCmds`.
fn submodules(w: &mut Writer, info: &Info<'_>) {
    let s = info.settings;
    let recursive = match s.submodules {
        // get_sources refuses to run with it.
        Submodules::Invalid => return,
        Submodules::None => {
            if !matches!(s.git_strategy, GitStrategy::None | GitStrategy::Empty) {
                w.notice("Skipping Git submodules setup");
            }
            return;
        }
        Submodules::Normal => false,
        Submodules::Recursive => true,
    };
    let depth = s.submodule_depth;
    w.notice(&match (recursive, depth) {
        (true, 0) => "Updating/initializing submodules recursively...".to_string(),
        (true, d) => {
            format!("Updating/initializing submodules recursively with git depth set to {d}...")
        }
        (false, 0) => "Updating/initializing submodules...".to_string(),
        (false, d) => format!("Updating/initializing submodules with git depth set to {d}..."),
    });
    let mut paths: Vec<String> = Vec::new();
    if !s.submodule_paths.is_empty() {
        paths.push("--".into());
        paths.extend(s.submodule_paths.iter().cloned());
    }
    let mut sync: Vec<String> = vec!["submodule".into(), "sync".into()];
    let mut update: Vec<String> = vec!["submodule".into(), "update".into(), "--init".into()];
    let mut foreach: Vec<String> = vec!["submodule".into(), "foreach".into()];
    if recursive {
        sync.push("--recursive".into());
        update.push("--recursive".into());
        foreach.push("--recursive".into());
    }
    sync.extend(paths.iter().cloned());
    w.command("git", &["submodule", "init"]);
    w.command("git", &refs(&sync));
    if depth > 0 {
        update.push("--depth".into());
        update.push(depth.to_string());
    }
    update.extend(s.submodule_update_flags.iter().cloned());
    update.extend(paths.iter().cloned());
    let clean_flags: Vec<String> = match s.clean_flags.is_empty() {
        true => vec!["-ffdx".into()],
        false => s.clean_flags.clone(),
    };
    let mut clean = foreach.clone();
    clean.push("git".into());
    clean.push("clean".into());
    clean.extend(clean_flags);
    let mut reset = foreach.clone();
    reset.extend(["git".into(), "reset".into(), "--hard".into()]);
    let with_creds = |args: &[String]| -> Vec<String> {
        let mut out = vec!["-c".to_string(), format!("include.path=${EXT_CONFIG_VAR}")];
        out.extend(args.iter().cloned());
        out
    };
    w.command("git", &refs(&clean));
    w.command("git", &refs(&reset));
    w.if_cmd_with_output_arg_expand("git", &refs(&with_creds(&update)));
    w.notice("Updated submodules");
    w.command("git", &refs(&sync));
    w.else_();
    w.warning("Updating submodules failed. Retrying...");
    if s.submodule_update_flags
        .iter()
        .any(|f| f.eq_ignore_ascii_case("--remote"))
    {
        // A `.gitmodules` branch other than the default is found only among all the heads.
        let mut fetch = foreach.clone();
        fetch.extend([
            "git".into(),
            "fetch".into(),
            "origin".into(),
            "+refs/heads/*:refs/remotes/origin/*".into(),
        ]);
        w.command_arg_expand("git", &refs(&with_creds(&fetch)));
    }
    w.command("git", &refs(&sync));
    w.command_arg_expand("git", &refs(&with_creds(&update)));
    w.command("git", &refs(&reset));
    w.end_if();
    w.command("git", &refs(&clean));
    w.notice("Configuring submodules to use parent git credentials...");
    let mut configure = foreach.clone();
    if !recursive {
        configure.push("--recursive".into());
    }
    configure.extend([
        "git".into(),
        "config".into(),
        "--replace-all".into(),
        "include.path".into(),
        format!("${EXT_CONFIG_VAR}"),
    ]);
    w.command_arg_expand("git", &refs(&configure));
    if !s.lfs_skip_smudge {
        w.if_cmd("git", &["lfs", "version"]);
        w.notice("Pulling LFS files...");
        let mut lfs = foreach.clone();
        lfs.extend(["git".into(), "lfs".into(), "pull".into()]);
        w.command_arg_expand("git", &refs(&with_creds(&lfs)));
        w.end_if();
    }
}

/// `writeGitCleanup`: stale locks and every config a previous job could have planted hooks in.
fn git_cleanup(w: &mut Writer, info: &Info<'_>) {
    let project = info.project_dir;
    let for_submodules = info.settings.submodules != Submodules::None;
    let git = join(project, ".git");
    for f in [
        "index.lock",
        "shallow.lock",
        "HEAD.lock",
        "hooks/post-checkout",
        "config.lock",
    ] {
        w.rm_file(&join(&git, f));
        if for_submodules {
            let base = f.rsplit('/').next().unwrap_or(f);
            w.rm_files_recursive(&join(&git, "modules"), base);
        }
    }
    w.rm_files_recursive(&join(&git, "refs"), "*.lock");
    if info.settings.git_strategy == GitStrategy::None {
        return;
    }
    let template = w.tmp_file(GIT_TEMPLATE_DIR);
    for dir in [template, git.clone()] {
        w.rm_file(&join(&dir, "config"));
        w.rmdir(&join(&dir, "hooks"));
    }
    if for_submodules {
        let modules = join(&git, "modules");
        w.rm_files_recursive(&modules, "config");
        w.rm_dirs_recursive(&modules, "hooks");
    }
}

/// `writeClearGitCredentials`: whatever credential store the image's git has forgets the
/// job token.
fn clear_git_credentials(w: &mut Writer, info: &Info<'_>) {
    let Some(host) = remote_host(&info.job.sources.repo_url) else {
        return;
    };
    if !(host.starts_with("http://") || host.starts_with("https://") || host.starts_with("ssh://"))
    {
        return;
    }
    // Guarded, unlike gitlab-runner's, whose builds always have git: a job image without
    // it would otherwise print `git: not found` into every trace.
    w.line("if command -v git >/dev/null 2>&1; then");
    w.indent += 1;
    w.command_with_stdin(
        true,
        &format!("url={host}\nusername=gitlab-ci-token"),
        "git",
        &["-c", "credential.interactive=never", "credential", "reject"],
    );
    w.end_if();
}

fn refs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

/// Whether a file variable's key can name its file and its variable: `[A-Za-z_][A-Za-z0-9_]*`.
pub(super) fn file_key_ok(key: &str) -> bool {
    let mut bytes = key.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn join(dir: &str, name: &str) -> String {
    format!("{}/{name}", dir.trim_end_matches('/'))
}

/// `regexp.QuoteMeta`.
fn regex_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if r"\.+*?()|[]{}^$".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn go_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// `BashWriter`: a script body built line by line, finished into the `eval`ed form.
struct Writer {
    buf: String,
    indent: usize,
    posix: bool,
    /// The project's temporary dir.
    tmp: String,
}

impl Writer {
    fn line(&mut self, text: &str) {
        for _ in 0..self.indent {
            self.buf.push_str("  ");
        }
        self.buf.push_str(text);
        self.buf.push('\n');
    }

    fn escape(&self, s: &str) -> String {
        match self.posix {
            true => posix_escape(s),
            false => shell_escape(s),
        }
    }

    fn build(&self, quote: fn(&Writer, &str) -> String, cmd: &str, args: &[&str]) -> String {
        let mut out = self.escape(cmd);
        for a in args {
            out.push(' ');
            out.push_str(&quote(self, a));
        }
        out
    }

    fn command(&mut self, cmd: &str, args: &[&str]) {
        let line = self.build(Writer::escape, cmd, args);
        self.line(&line);
    }

    fn command_arg_expand(&mut self, cmd: &str, args: &[&str]) {
        let line = self.build(|_, a| format!("\"{a}\""), cmd, args);
        self.line(&line);
    }

    fn command_with_stdin(&mut self, best_effort: bool, stdin: &str, cmd: &str, args: &[&str]) {
        let producer = format!("{} {}", self.echo_cmd(), self.escape(stdin));
        let consumer = self.build(Writer::escape, cmd, args);
        let line = format!("{producer} | {consumer}");
        match best_effort {
            true => self.line(&format!("{line} || true")),
            false => self.line(&line),
        }
    }

    /// `SetupGitCredHelper`.
    fn cred_helper(&mut self, conf: &str, section: &str, user: &str) {
        let helper = self.escape(&format!("{section}.helper"));
        let username = self.escape(&format!("{section}.username"));
        let command = self.escape(CRED_HELPER);
        let conf = format!("\"{conf}\"");
        self.line(&format!(
            "git config -f {conf} --replace-all {helper} \"\" && git config -f {conf} --add \
             {helper} {command} && git config -f {conf} {username} {user}"
        ));
    }

    fn tmp_file(&self, name: &str) -> String {
        join(&self.tmp, name)
    }

    /// `BashWriter.Variable`.
    fn variable(&mut self, key: &str, value: &str, file: bool) {
        let path = self.tmp_file(key);
        let key = self.escape(key);
        if file {
            self.line(&format!("mkdir -p {}", go_quote(&self.tmp)));
            let value = self.escape(value);
            self.line(&format!("printf '%s' {value} > {}", go_quote(&path)));
            self.line(&format!("export {key}={}", go_quote(&path)));
        } else {
            let value = self.escape(value);
            self.line(&format!("export {key}={value}"));
        }
    }

    fn export_raw(&mut self, name: &str, value: &str) {
        let name = self.escape(name);
        self.line(&format!("export {name}=\"{value}\""));
    }

    fn source_env(&mut self, path: &str) {
        self.line(&format!("mkdir -p {}", go_quote(&self.tmp)));
        self.line(&format!("touch {}", go_quote(path)));
        self.line(&format!(
            "while read -r line; do export \"$line\"; done < {}",
            go_quote(path)
        ));
    }

    fn if_directory(&mut self, path: &str) {
        self.line(&format!("if [ -d {} ]; then", go_quote(path)));
        self.indent += 1;
    }

    fn if_file(&mut self, path: &str) {
        self.line(&format!("if [ -e {} ]; then", go_quote(path)));
        self.indent += 1;
    }

    fn if_cmd(&mut self, cmd: &str, args: &[&str]) {
        let line = self.build(Writer::escape, cmd, args);
        self.line(&format!("if {line} >/dev/null 2>&1 ; then"));
        self.indent += 1;
    }

    fn if_cmd_with_output_arg_expand(&mut self, cmd: &str, args: &[&str]) {
        let line = self.build(|_, a| format!("\"{a}\""), cmd, args);
        self.line(&format!("if {line} ; then"));
        self.indent += 1;
    }

    fn else_(&mut self) {
        self.indent = self.indent.saturating_sub(1);
        self.line("else");
        self.indent += 1;
    }

    fn end_if(&mut self) {
        self.indent = self.indent.saturating_sub(1);
        self.line("fi");
    }

    fn cd(&mut self, path: &str) {
        self.command("cd", &[path]);
    }

    fn mkdir(&mut self, path: &str) {
        self.command("mkdir", &["-p", path]);
    }

    fn rmdir(&mut self, path: &str) {
        self.if_directory(path);
        self.command_arg_expand("chmod", &["-R", "u+rwX", path]);
        self.end_if();
        self.command_arg_expand("rm", &["-r", "-f", path]);
    }

    fn rm_file(&mut self, path: &str) {
        self.command_arg_expand("rm", &["-f", path]);
    }

    fn rm_files_recursive(&mut self, path: &str, name: &str) {
        self.if_directory(path);
        self.line(&format!(
            "et='+' ; find /dev/null -exec true {{}} + 2>/dev/null || et=';' ; find {} -name {} \
             -type f -exec rm -f {{}} \"${{et}}\"",
            go_quote(path),
            go_quote(name)
        ));
        self.end_if();
    }

    fn rm_dirs_recursive(&mut self, path: &str, name: &str) {
        self.if_directory(path);
        self.line(&format!(
            "et='+' ; find /dev/null -exec true {{}} + 2>/dev/null || et=';' ; find {} -name {} \
             -type d -depth -exec rm -rf -- {{}} \"${{et}}\"",
            go_quote(path),
            go_quote(name)
        ));
        self.end_if();
    }

    /// bash's `echo` prints its argument as is; a POSIX `sh`'s may interpret backslashes.
    fn echo_cmd(&self) -> &'static str {
        match self.posix {
            true => "printf '%s\\n'",
            false => "echo",
        }
    }

    fn echo(&mut self, text: String) {
        let line = format!("{} {}", self.echo_cmd(), self.escape(&text));
        self.line(&line);
    }

    fn notice(&mut self, text: &str) {
        self.echo(format!("{ANSI_BOLD_GREEN}{text}{ANSI_RESET}"));
    }

    fn warning(&mut self, text: &str) {
        self.echo(format!("{ANSI_YELLOW}{text}{ANSI_RESET}"));
    }

    fn error(&mut self, text: &str) {
        self.echo(format!("{ANSI_BOLD_RED}{text}{ANSI_RESET}"));
    }

    fn empty_line(&mut self) {
        self.line("echo");
    }

    /// `BashWriter.Finish`.
    fn finish(self, trace: bool) -> String {
        let mut out = String::from("#!/usr/bin/env bash\n\n");
        out.push_str(EXIT_ON_TERM);
        out.push_str("\n\n");
        if trace {
            out.push_str("set -o xtrace\n");
        }
        out.push_str(
            "case \"$(set -o)\" in *\"pipefail\"*) set -o pipefail;; esac; set -o errexit\n",
        );
        out.push_str("set +o noclobber\n");
        let body = self.escape(&self.buf);
        out.push_str(&format!("({EXIT_ON_TERM}; eval {body}) < /dev/null\n"));
        out.push_str("exit 0\n");
        out
    }
}

/// `helpers.ShellEscape`: the string as is when it needs no quoting, else ANSI-C quoted
/// (`$'…'`), control characters escaped and every non-ASCII byte as `\xNN`.
fn shell_escape(input: &str) -> String {
    if input.is_empty() {
        return "''".into();
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(input.len() * 2);
    let mut quote = false;
    for &c in input.as_bytes() {
        match c {
            b'\x07' => out.push_str("\\a"),
            b'\x08' => out.push_str("\\b"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\x0b' => out.push_str("\\v"),
            b'\x0c' => out.push_str("\\f"),
            b'\r' => out.push_str("\\r"),
            b'\'' => out.push_str("\\'"),
            b'\\' => out.push_str("\\\\"),
            b',' | b'-' | b'.' | b'/' | b'@' | b'_' => {
                out.push(c as char);
                continue;
            }
            c if c.is_ascii_alphanumeric() => {
                out.push(c as char);
                continue;
            }
            b' ' | b'!' | b'"' | b'#' | b'$' | b'%' | b'&' | b'(' | b')' | b'*' | b'+' | b':'
            | b';' | b'<' | b'=' | b'>' | b'?' | b'[' | b']' | b'^' | b'`' | b'{' | b'|' | b'}'
            | b'~' => out.push(c as char),
            c => {
                out.push('\\');
                out.push('x');
                out.push(HEX[usize::from(c >> 4)] as char);
                out.push(HEX[usize::from(c & 0x0f)] as char);
            }
        }
        quote = true;
    }
    match quote {
        true => format!("$'{out}'"),
        false => out,
    }
}

/// POSIX quoting, for a guest without bash: the string as is when it is made of characters no
/// shell gives a meaning to, else single-quoted. gitlab-runner's `helpers.PosixShellEscape`
/// leaves `;`, `'`, newlines and more unquoted, which `eval` would run.
fn posix_escape(input: &str) -> String {
    let plain = |b: u8| b.is_ascii_alphanumeric() || b",-./@_:+%".contains(&b);
    if !input.is_empty() && input.bytes().all(plain) {
        return input.into();
    }
    format!("'{}'", input.replace('\'', r"'\''"))
}

/// Go's `%q`: a double-quoted string with Go's escapes.
fn go_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x0b' => out.push_str("\\v"),
            c if c.is_ascii_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if c.is_control() => match c as u32 {
                n if n <= 0xffff => out.push_str(&format!("\\u{n:04x}")),
                n => out.push_str(&format!("\\U{n:08x}")),
            },
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A variable for a script built in tests.
#[cfg(test)]
fn var(key: &str, value: &str) -> Variable {
    Variable {
        key: key.into(),
        value: value.into(),
        public: true,
        ..Variable::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::jobs::vars::Place;
    use vk_hub_proto::job::{Hook, Sources, When};

    /// gitlab-runner's `helpers/shell_escape_test.go` cases.
    #[test]
    fn shell_escape_matches_gitlab_runner() {
        let cases = [
            ("", "''"),
            ("foo", "foo"),
            ("foo bar", "$'foo bar'"),
            ("foo'bar", "$'foo\\'bar'"),
            ("foo\\bar", "$'foo\\\\bar'"),
            ("foo\nbar", "$'foo\\nbar'"),
            ("\u{1b}[0;m", "$'\\x1b[0;m'"),
            ("été", "$'\\xc3\\xa9t\\xc3\\xa9'"),
            ("/builds/acme-web/x.tmp", "/builds/acme-web/x.tmp"),
            ("a=b", "$'a=b'"),
        ];
        for (input, want) in cases {
            assert_eq!(shell_escape(input), want, "{input:?}");
        }
        let posix = [
            ("", "''"),
            ("foo", "foo"),
            ("/builds/acme-web/x.tmp", "/builds/acme-web/x.tmp"),
            ("foo bar", "'foo bar'"),
            ("$HOME", "'$HOME'"),
            ("it's", "'it'\\''s'"),
            ("a;id", "'a;id'"),
            ("a\nb", "'a\nb'"),
            ("a\tb", "'a\tb'"),
            ("{a,b}", "'{a,b}'"),
            ("~", "'~'"),
        ];
        for (input, want) in posix {
            assert_eq!(posix_escape(input), want, "{input:?}");
        }
    }

    fn job() -> CiJob {
        CiJob {
            job: vk_hub_proto::job::CiJobInfo {
                id: 7,
                name: "test".into(),
                ..Default::default()
            },
            token: "glcbt-64_tok".into(),
            sources: Sources {
                repo_url: "https://gitlab.example.com/acme/web.git".into(),
                git_ref: "main".into(),
                sha: "0123456789abcdef0123456789abcdef01234567".into(),
                refspecs: vec!["+refs/heads/main:refs/remotes/origin/main".into()],
                depth: 20,
                ..Sources::default()
            },
            variables: vec![
                var("CI_JOB_TOKEN", "glcbt-64_tok"),
                Variable {
                    file: true,
                    ..var("KUBECONFIG", "apiVersion: v1\n")
                },
            ],
            steps: vec![
                Step {
                    name: "script".into(),
                    script: vec![
                        "echo hello".into(),
                        "".into(),
                        "for i in 1 2; do\n  echo $i\ndone".into(),
                    ],
                    timeout_secs: 3600,
                    when: When::OnSuccess,
                    allow_failure: false,
                },
                Step {
                    name: "after_script".into(),
                    script: vec!["echo bye".into()],
                    timeout_secs: 300,
                    when: When::Always,
                    allow_failure: false,
                },
            ],
            hooks: vec![Hook {
                name: HookName::PreGetSourcesScript,
                script: vec!["echo pre".into()],
            }],
            ..CiJob::default()
        }
    }

    fn with_info<R>(job: &CiJob, host_checkout: bool, f: impl FnOnce(&Info<'_>) -> R) -> R {
        with_info_at(job, host_checkout, false, "/builds", f)
    }

    /// With the project at `<builds_dir>/acme/web`.
    fn with_info_at<R>(
        job: &CiJob,
        host_checkout: bool,
        posix: bool,
        builds_dir: &str,
        f: impl FnOnce(&Info<'_>) -> R,
    ) -> R {
        let project_dir = format!("{builds_dir}/acme/web");
        let place = Place {
            builds_dir: builds_dir.into(),
            project_dir: project_dir.clone(),
            concurrent_id: 0,
            concurrent_project_id: 0,
        };
        let vars = Vars::of(job, &place);
        let settings = Settings::of(job, &vars);
        let info = Info {
            job,
            vars: &vars,
            settings: &settings,
            project_dir: &project_dir,
            builds_dir,
            posix,
            hostname: "node-1",
            host_checkout,
        };
        f(&info)
    }

    /// The `eval`ed body of a finished script, unquoted.
    fn body(script: &str) -> String {
        let start = script.find("eval $'").expect("an eval") + "eval $'".len();
        let end = script.rfind("') < /dev/null").expect("the eval's end");
        let quoted = &script[start..end];
        let mut out = String::new();
        let mut chars = quoted.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('\'') => out.push('\''),
                Some('\\') => out.push('\\'),
                Some('x') => {
                    let hex: String = chars.by_ref().take(2).collect();
                    out.push(char::from(u8::from_str_radix(&hex, 16).unwrap()));
                }
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        }
        out
    }

    /// The frame every script has, as `BashWriter.Finish` writes it.
    #[test]
    fn a_script_is_framed_as_gitlab_runners_bash_shell_frames_it() {
        let job = job();
        let script = with_info(&job, false, |info| step(info, &job.steps[0]));
        assert!(script.starts_with(
            "#!/usr/bin/env bash\n\ntrap 'exit 1' TERM\n\ncase \"$(set -o)\" in \
             *\"pipefail\"*) set -o pipefail;; esac; set -o errexit\nset +o noclobber\n\
             (trap 'exit 1' TERM; eval $'"
        ));
        assert!(script.ends_with("') < /dev/null\nexit 0\n"));
    }

    #[test]
    fn a_step_exports_cds_and_echoes_each_command() {
        let job = job();
        let script = with_info(&job, false, |info| step(info, &job.steps[0]));
        let body = body(&script);
        let lines: Vec<&str> = body.lines().collect();
        // Every variable, the file one written to its file first.
        assert!(lines.contains(&"export CI_JOB_TOKEN=glcbt-64_tok"));
        assert!(lines.contains(&"mkdir -p \"/builds/acme/web.tmp\""));
        assert!(
            lines.contains(
                &"printf '%s' $'apiVersion: v1\\n' > \"/builds/acme/web.tmp/KUBECONFIG\""
            )
        );
        assert!(lines.contains(&"export KUBECONFIG=\"/builds/acme/web.tmp/KUBECONFIG\""));
        assert!(lines.contains(&"export GITLAB_ENV=/builds/acme/web.tmp/gitlab_runner_env"));
        assert!(lines.contains(
            &"while read -r line; do export \"$line\"; done < \"/builds/acme/web.tmp/gitlab_runner_env\""
        ));
        let cd = lines
            .iter()
            .position(|l| *l == "cd /builds/acme/web")
            .unwrap();
        assert_eq!(
            &lines[cd + 1..],
            &[
                "echo $'\\x1b[32;1m$ echo hello\\x1b[0;m'",
                "echo hello",
                "echo",
                "",
                "echo $'\\x1b[32;1m$ for i in 1 2; do # collapsed multi-line command\\x1b[0;m'",
                "for i in 1 2; do",
                "  echo $i",
                "done",
            ]
        );
    }

    #[test]
    fn after_script_announces_itself() {
        let job = job();
        let script = with_info(&job, false, |info| after_script(info, job.steps.get(1))).unwrap();
        let body = body(&script);
        assert!(body.contains("echo $'\\x1b[32;1mRunning after script...\\x1b[0;m'\n"));
        assert!(body.ends_with("echo bye\n"));
        let none = with_info(&job, false, |info| after_script(info, None));
        assert!(none.is_none());
    }

    #[test]
    fn the_guest_checkout_fetches_with_a_credential_helper_and_no_token_in_urls() {
        let job = job();
        let script = with_info(&job, false, get_sources);
        let body = body(&script);
        assert!(!body.contains("glcbt-64_tok@"), "{body}");
        assert!(
            body.contains(
                "git init /builds/acme/web --template /builds/acme/web.tmp/git-template\n"
            )
        );
        assert!(body.contains("if git remote add origin $'https://gitlab.example.com/acme/web.git' >/dev/null 2>&1 ; then\n"));
        assert!(body.contains(
            "fetch origin --no-recurse-submodules $'+refs/heads/main:refs/remotes/origin/main' --depth 20 --prune --quiet\n"
        ));
        assert!(body.contains("git -c $'submodule.recurse=false' checkout -f -q 0123456789abcdef0123456789abcdef01234567\n"));
        assert!(body.contains("git clean -ffdx\n"));
        assert!(body.contains("credential.https://gitlab.example.com.helper"));
        // The pre-clone hook runs before the fetch.
        let pre = body.find("echo pre\n").unwrap();
        assert!(pre < body.find("git init").unwrap());
        assert!(
            body.contains(
                "echo $'\\x1b[32;1mFetching changes with git depth set to 20...\\x1b[0;m'"
            )
        );
    }

    #[test]
    fn a_host_checkout_runs_only_the_hooks_in_the_guest() {
        let job = job();
        let script = with_info(&job, true, get_sources);
        let body = body(&script);
        assert!(!body.contains("git init") && !body.contains("credential reject"));
        assert!(body.contains("echo pre\n"));
        assert!(body.contains("Checked out 01234567 on the node"));
    }

    #[test]
    fn git_strategy_none_skips_the_repository() {
        let mut job = job();
        job.variables.push(var("GIT_STRATEGY", "none"));
        let script = with_info(&job, false, get_sources);
        let body = body(&script);
        assert!(body.contains("Skipping Git repository setup"));
        assert!(body.contains("mkdir -p /builds/acme/web\n"));
        assert!(!body.contains("git init") && !body.contains("echo pre\n"));
        assert!(body.contains("Skipping Git checkout"));
    }

    #[test]
    fn cleanup_removes_the_file_variables() {
        let job = job();
        let script = with_info(&job, false, cleanup);
        let body = body(&script);
        assert!(body.contains("rm \"-f\" \"/builds/acme/web.tmp/KUBECONFIG\"\n"));
        assert!(body.contains("export KUBECONFIG=/builds/acme/web.tmp/KUBECONFIG\n"));
        assert!(!body.contains("printf '%s'"));
        assert!(body.contains("rm \"-f\" \"/builds/.gitlab-build-uid-gid\"\n"));
    }

    #[test]
    fn prepare_says_where_it_runs() {
        let job = job();
        let script = with_info(&job, false, prepare);
        let body = body(&script);
        assert!(body.starts_with("echo \"Running on $(hostname) via node-1...\"\n(\n"));
        assert!(body.ends_with("rm \"-f\" \"/builds/acme/web.tmp/masking.db\"\n"));
    }

    #[test]
    fn a_debug_trace_turns_xtrace_on() {
        let mut job = job();
        job.variables.push(var("CI_DEBUG_TRACE", "true"));
        let script = with_info(&job, false, prepare);
        assert!(script.contains("\nset -o xtrace\n"));
    }

    /// Hostile values, through the shells a bash-less guest has.
    #[test]
    fn a_posix_script_survives_hostile_values_in_sh() {
        let values = [
            "a;id",
            "it's",
            "two\nlines",
            "$(id)",
            "`id`",
            "tab\there",
            "back\\slash\\n",
            "{a,b} ~ * ?",
            "\"quoted\" & | > <",
            "",
        ];
        let root = std::env::temp_dir().join(format!("vk-posix-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("acme/web")).unwrap();
        let builds = root.to_str().unwrap();
        let mut job = job();
        // Raw: the runner expands nothing in them.
        for (i, v) in values.iter().enumerate() {
            job.variables.push(Variable {
                raw: true,
                ..var(&format!("HOSTILE_{i}"), v)
            });
        }
        job.variables.push(Variable {
            file: true,
            raw: true,
            ..var("HOSTILE_FILE", "it's;$(id)\n`id`\\")
        });
        let names: Vec<String> = (0..values.len())
            .map(|i| format!("\"$HOSTILE_{i}\""))
            .collect();
        job.steps[0].script = vec![
            format!("printf '%s\\0' {} > values", names.join(" ")),
            "cat \"$HOSTILE_FILE\" > file".into(),
            ": 'a\\nb'".into(),
        ];
        let script = with_info_at(&job, false, true, builds, |info| step(info, &job.steps[0]));
        let path = root.join("step.sh");
        std::fs::write(&path, &script).unwrap();
        let shells: Vec<&str> = ["sh", "dash", "bash"]
            .into_iter()
            .filter(|sh| {
                std::process::Command::new(sh)
                    .args(["-c", "true"])
                    .status()
                    .is_ok_and(|s| s.success())
            })
            .collect();
        assert!(!shells.is_empty());
        for sh in shells {
            let project = root.join("acme/web");
            let _ = std::fs::remove_file(project.join("values"));
            let out = std::process::Command::new(sh).arg(&path).output().unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(
                out.status.success(),
                "{sh}: {}\n{stdout}",
                String::from_utf8_lossy(&out.stderr)
            );
            let got = std::fs::read(project.join("values")).unwrap();
            let got: Vec<&[u8]> = got.split(|&b| b == 0).collect();
            for (i, v) in values.iter().enumerate() {
                assert_eq!(got[i], v.as_bytes(), "{sh}: HOSTILE_{i}");
            }
            assert_eq!(
                std::fs::read(project.join("file")).unwrap(),
                b"it's;$(id)\n`id`\\",
                "{sh}"
            );
            // A command's notice is printed as written, backslashes included.
            assert!(stdout.contains("$ : 'a\\nb'"), "{sh}: {stdout}");
        }
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_file_variable_with_no_shell_name_is_skipped() {
        let mut job = job();
        job.variables.push(Variable {
            file: true,
            ..var("BAD$(id)", "x")
        });
        for script in [
            with_info(&job, false, |info| step(info, &job.steps[0])),
            with_info(&job, false, cleanup),
        ] {
            assert!(!body(&script).contains("BAD"), "{script}");
        }
        let warned = with_info(&job, false, |info| info.settings.warnings.clone());
        assert!(warned.iter().any(|w| w.contains("BAD")), "{warned:?}");
    }

    #[test]
    fn a_release_step_is_expanded_by_the_runner() {
        let mut job = job();
        job.variables.push(var("TAG", "v1.2"));
        let release = Step {
            name: "release".into(),
            script: vec!["release-cli create --tag-name $TAG".into()],
            ..Step::default()
        };
        let script = with_info(&job, false, |info| step(info, &release));
        assert!(body(&script).contains("\nrelease-cli create --tag-name v1.2\n"));
        let script = with_info(&job, false, |info| step(info, &job.steps[0]));
        assert!(body(&script).contains("\n  echo $i\n"));
    }

    #[test]
    fn git_strategy_empty_starts_from_an_empty_dir() {
        let mut job = job();
        job.variables.push(var("GIT_STRATEGY", "empty"));
        let body = body(&with_info(&job, false, get_sources));
        assert!(body.contains("creating an empty build directory"));
        assert!(
            body.contains("rm \"-r\" \"-f\" \"/builds/acme/web\"\nmkdir -p /builds/acme/web\n")
        );
        assert!(!body.contains("git init") && !body.contains("echo pre\n"));
    }

    #[test]
    fn a_sha256_repository_is_initialised_as_one() {
        let mut job = job();
        job.sources.object_format = ObjectFormat::Sha256;
        let body = body(&with_info(&job, false, get_sources));
        assert!(body.contains(
            "git init /builds/acme/web --template /builds/acme/web.tmp/git-template \
             --object-format sha256\n"
        ));
    }

    #[test]
    fn a_full_depth_fetch_unshallows_a_shallow_clone() {
        let mut job = job();
        job.sources.depth = 0;
        let body = body(&with_info(&job, false, get_sources));
        assert!(body.contains("Fetching changes...") && !body.contains("--depth"));
        assert!(body.contains("if [ -e \".git/shallow\" ]; then\n"));
        assert!(body.contains("--prune --quiet --unshallow\n"));
    }

    #[test]
    fn lfs_files_are_pulled_unless_smudging_is_skipped() {
        let job = job();
        let pulled = body(&with_info(&job, false, get_sources));
        assert!(pulled.contains("export GIT_LFS_SKIP_SMUDGE=1\n"));
        assert!(pulled.contains("if git lfs version >/dev/null 2>&1 ; then\n  git lfs pull\n"));
        let mut job = job.clone();
        job.variables.push(var("GIT_LFS_SKIP_SMUDGE", "true"));
        let skipped = body(&with_info(&job, false, get_sources));
        assert!(!skipped.contains("lfs pull") && !skipped.contains("GIT_LFS_SKIP_SMUDGE=1"));
    }

    #[test]
    fn gitlabs_ca_is_set_for_the_repository_host() {
        let mut job = job();
        job.server_ca_pem = Some("-----BEGIN CERTIFICATE-----".into());
        let body = body(&with_info(&job, false, get_sources));
        assert!(body.contains(
            "git \"config\" \"--global\" \"http.https://gitlab.example.com.sslCAInfo\" \
             \"$CI_SERVER_TLS_CA_FILE\"\n"
        ));
        assert!(body.contains(
            "\"--file\" \"/builds/acme/web.tmp/.gitlab-runner.ext.conf\" \
             \"http.https://gitlab.example.com.sslCAInfo\" \"$CI_SERVER_TLS_CA_FILE\"\n"
        ));
        assert!(body.contains(
            "export CI_SERVER_TLS_CA_FILE=\"/builds/acme/web.tmp/CI_SERVER_TLS_CA_FILE\"\n"
        ));
    }

    #[test]
    fn cleanup_after_a_host_checkout_leaves_git_alone() {
        let job = job();
        let host = body(&with_info(&job, true, cleanup));
        assert!(!host.contains("credential reject") && !host.contains(".git/index.lock"));
        assert!(host.contains("rm \"-f\" \"/builds/acme/web.tmp/KUBECONFIG\"\n"));
        let guest = body(&with_info(&job, false, cleanup));
        assert!(guest.contains("credential reject") && guest.contains(".git/index.lock"));
    }

    fn submodule_job(vars: &[(&str, &str)]) -> CiJob {
        let mut job = job();
        job.variables.extend(vars.iter().map(|(k, v)| var(k, v)));
        job
    }

    #[test]
    fn submodules_are_initialised_synced_and_updated() {
        let job = submodule_job(&[("GIT_SUBMODULE_STRATEGY", "normal")]);
        let body = body(&with_info(&job, false, get_sources));
        let start = body
            .find("Updating/initializing submodules with git depth set to 20...")
            .unwrap();
        let lines: Vec<&str> = body[start..].lines().skip(1).take(12).collect();
        assert_eq!(
            lines,
            [
                "git submodule init",
                "git submodule sync",
                "git submodule foreach git clean -ffdx",
                "git submodule foreach git reset --hard",
                "if git \"-c\" \"include.path=$GLR_EXT_GIT_CONFIG_PATH\" \"submodule\" \"update\" \
                 \"--init\" \"--depth\" \"20\" ; then",
                "  echo $'\\x1b[32;1mUpdated submodules\\x1b[0;m'",
                "  git submodule sync",
                "else",
                "  echo $'\\x1b[0;33mUpdating submodules failed. Retrying...\\x1b[0;m'",
                "  git submodule sync",
                "  git \"-c\" \"include.path=$GLR_EXT_GIT_CONFIG_PATH\" \"submodule\" \"update\" \
                 \"--init\" \"--depth\" \"20\"",
                "  git submodule foreach git reset --hard",
            ]
        );
        assert!(body.contains(
            "git \"submodule\" \"foreach\" \"--recursive\" \"git\" \"config\" \"--replace-all\" \
             \"include.path\" \"$GLR_EXT_GIT_CONFIG_PATH\"\n"
        ));
        assert!(!body.contains("fetch\" \"origin\" \"+refs/heads/*"));
    }

    #[test]
    fn recursive_submodules_with_paths_and_depth() {
        let job = submodule_job(&[
            ("GIT_SUBMODULE_STRATEGY", "recursive"),
            ("GIT_SUBMODULE_DEPTH", "0"),
            ("GIT_SUBMODULE_PATHS", "lib/a lib/b"),
            ("GIT_SUBMODULE_UPDATE_FLAGS", "--remote --jobs 4"),
        ]);
        let body = body(&with_info(&job, false, get_sources));
        assert!(body.contains("Updating/initializing submodules recursively...\\x1b"));
        assert!(
            body.contains("git submodule init\ngit submodule sync --recursive -- lib/a lib/b\n")
        );
        assert!(body.contains(
            "\"submodule\" \"update\" \"--init\" \"--recursive\" \"--remote\" \"--jobs\" \"4\" \
             \"--\" \"lib/a\" \"lib/b\""
        ));
        assert!(!body.contains("\"--depth\""));
        assert!(body.contains("git submodule foreach --recursive git reset --hard\n"));
        // `--remote` fetches every head before the retry.
        let retry = body.find("Retrying...").unwrap();
        let fetch = body
            .find(
                "  git \"-c\" \"include.path=$GLR_EXT_GIT_CONFIG_PATH\" \"submodule\" \"foreach\" \
                 \"--recursive\" \"git\" \"fetch\" \"origin\" \"+refs/heads/*:refs/remotes/origin/*\"\n",
            )
            .unwrap();
        assert!(retry < fetch);
        // Recursive already: the credentials' config is not made recursive twice.
        assert!(body.contains("\"foreach\" \"--recursive\" \"git\" \"config\""));
        assert!(!body.contains("\"--recursive\" \"--recursive\""));
    }

    #[test]
    fn an_unknown_submodule_strategy_fails_get_sources() {
        let job = submodule_job(&[("GIT_SUBMODULE_STRATEGY", "deep")]);
        for host_checkout in [false, true] {
            let body = body(&with_info(&job, host_checkout, get_sources));
            assert!(
                body.ends_with("unknown GIT_SUBMODULE_STRATEGY\\x1b[0;m'\nexit 1\n"),
                "{body}"
            );
            assert!(!body.contains("git init") && !body.contains("echo pre"));
        }
        // No sources, no submodules: nothing to fail.
        let job = submodule_job(&[("GIT_SUBMODULE_STRATEGY", "deep"), ("GIT_STRATEGY", "none")]);
        let body = body(&with_info(&job, false, get_sources));
        assert!(!body.contains("exit 1"));
    }

    #[test]
    fn go_quote_matches_strconv_quote() {
        assert_eq!(go_quote("a b"), "\"a b\"");
        assert_eq!(go_quote("say \"hi\"\n"), "\"say \\\"hi\\\"\\n\"");
        assert_eq!(go_quote("\u{1b}"), "\"\\x1b\"");
    }
}
