//! The built-in host-command policies a dev environment can turn on.
//!
//! `[dev.host] git-gui = true` publishes a generated wrapper that runs `vk host-policy
//! git-gui`, so every command the guest sends over the exec channel arrives here first.
//! The policy decides on argv alone and hands back a command with an environment rebuilt
//! from nothing; nothing the client sent selects what runs.
//!
//! This is not a sandbox. Git still reads the repository's own configuration and hooks,
//! which can name host programs — the policy keeps the guest from *choosing* the host
//! command, not from a hostile checkout.

use std::path::Path;

use anyhow::{Context, Result};

/// The host PATH programs resolve against. Fixed, so a guest-supplied one never applies.
const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Display, session and locale handles: settings the GUI needs, not code it runs. `LC_*`
/// matches by prefix, as the exec channel's own locale filter does.
const PASSTHROUGH: [&str; 8] = [
    "DISPLAY",
    "XAUTHORITY",
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
    "LANG",
    "LANGUAGE",
    "TZ",
];

/// Revision selectors that only ever reach `git rev-list`. Options that load code — `gitk
/// --argscmd` hands its value to a host shell — are refused by not being here, and a new
/// one is reviewed before it is added. `--` is here because the allowlist applies to every
/// word that starts with `-`, wherever it sits: see [`git_gui`].
const ALLOWED_EXACT: [&str; 15] = [
    "--",
    "--all",
    "--branches",
    "--tags",
    "--remotes",
    "--date-order",
    "--topo-order",
    "--author-date-order",
    "--first-parent",
    "--merge",
    "--reverse",
    "--left-right",
    "--boundary",
    "--full-history",
    "--simplify-merges",
];

const ALLOWED_PREFIX: [&str; 6] = [
    "--branches=",
    "--tags=",
    "--remotes=",
    "--since=",
    "--until=",
    "--max-count=",
];

/// What the policy made of one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// why the command does not run; the caller prints it and exits 126
    Refused(String),
    Run {
        program: String,
        args: Vec<String>,
        /// the complete environment of the command — it inherits nothing else
        env: Vec<(String, String)>,
    },
}

fn refuse(why: impl Into<String>) -> Result<Decision> {
    Ok(Decision::Refused(why.into()))
}

/// The subcommands `git gui` has of its own. Without this only `argv[1] == "gui"` is
/// checked, and `git gui blame` — or anything else `git-gui` grows — arrives with just the
/// revision-selector table applied to its options.
const GIT_GUI_SUBCOMMANDS: [&str; 4] = ["blame", "browser", "citool", "version"];

/// `gitk` and `git gui` over the environment's workspace, and nothing else.
///
/// Every word that starts with `-` has to be in the allowlist, wherever it sits in argv:
/// `--` does not end the scan, since it is gitk's own option parser — not this one — that
/// would have to stop there for that to be safe. A pathspec that starts with `-` is spelled
/// `./-x`, which is not an option to anything.
///
/// `env` is the serving process's own environment, `passwd` the name and home directory of
/// the uid it runs as — taken from the passwd database rather than the environment, so a
/// client cannot point HOME at another configuration tree.
pub fn git_gui(
    workspace: &Path,
    cwd: &Path,
    argv: &[String],
    env: &[(String, String)],
    passwd: (&str, &str),
) -> Result<Decision> {
    let root = std::fs::canonicalize(workspace)
        .with_context(|| format!("resolving the workspace {}", workspace.display()))?;
    // The exec channel maps `--dir` under the workspace; anything else is a request to work
    // on a tree this environment does not own.
    match std::fs::canonicalize(cwd) {
        Ok(here) if here.starts_with(&root) => {}
        Ok(here) => {
            return refuse(format!(
                "working directory {} is outside the workspace {}",
                here.display(),
                root.display()
            ));
        }
        // Not the same problem, and saying "outside the workspace" sends the reader after
        // the wrong one: this is a directory that is gone, or that cannot be resolved.
        Err(e) => {
            return refuse(format!(
                "cannot resolve the working directory {}: {e}",
                cwd.display()
            ));
        }
    }

    let command = argv.first().map(String::as_str).unwrap_or("");
    if command.contains('/') {
        return refuse(format!(
            "path-qualified commands are not allowed: {command}"
        ));
    }
    // `opts` is what the user chose; the words before it are the command itself.
    let (program, opts): (&str, &[String]) = match command {
        "gitk" => ("gitk", &argv[1..]),
        "git" => {
            let sub = argv.get(1).map(String::as_str).unwrap_or("<none>");
            if sub != "gui" {
                return refuse(format!("only 'git gui' is allowed, not 'git {sub}'"));
            }
            // `git gui` has subcommands of its own, and they are not options: the word
            // after `gui` is one of them or nothing.
            if let Some(word) = argv.get(2)
                && !word.starts_with('-')
                && !GIT_GUI_SUBCOMMANDS.contains(&word.as_str())
            {
                return refuse(format!(
                    "'git gui {word}' is not allowed on the host (allowed: {})",
                    GIT_GUI_SUBCOMMANDS.join(", ")
                ));
            }
            ("git", &argv[2..])
        }
        other => {
            let shown = if other.is_empty() { "<none>" } else { other };
            return refuse(format!("command not allowed on the host: {shown}"));
        }
    };
    for a in opts {
        if a.starts_with('-') && !option_allowed(a) {
            return refuse(format!("option not allowed on the host: {a}"));
        }
    }

    let (user, home) = passwd;
    if home.is_empty() {
        return refuse("the serving user has no home directory in the passwd database");
    }
    let mut out = vec![
        ("PATH".to_string(), SAFE_PATH.to_string()),
        ("HOME".to_string(), home.to_string()),
        ("USER".to_string(), user.to_string()),
        ("LOGNAME".to_string(), user.to_string()),
    ];
    let mut copied: Vec<(String, String)> = env
        .iter()
        .filter(|(k, _)| PASSTHROUGH.contains(&k.as_str()) || k.starts_with("LC_"))
        .cloned()
        .collect();
    copied.sort();
    out.extend(copied);
    Ok(Decision::Run {
        program: program.to_string(),
        args: argv[1..].to_vec(),
        env: out,
    })
}

fn option_allowed(opt: &str) -> bool {
    if ALLOWED_EXACT.contains(&opt) || ALLOWED_PREFIX.iter().any(|p| opt.starts_with(p)) {
        return true;
    }
    // `-<n>`: git's shorthand for --max-count=<n>.
    matches!(opt.strip_prefix('-'), Some(n) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// The name and home directory of the uid this process runs as.
///
/// Both become environment values of the command that runs, so a field that is not UTF-8 is
/// an error rather than something to replace characters in: `HOME` half-transliterated would
/// name a directory that is not the user's.
pub fn self_passwd() -> Result<(String, String)> {
    // SAFETY: `getuid` takes no arguments, cannot fail, and touches nothing of ours.
    let uid = unsafe { libc::getuid() };
    // SAFETY: `passwd` is a plain C struct of pointers and integers, for which all-zero is
    // a valid (empty) value; `getpwuid_r` fills it in before anything reads it.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    // `c_char` is `i8` on x86-64 and `u8` on aarch64, so let the cast follow the target.
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `pwd`, `buf` and `result` are live and exclusively borrowed for the call, and
    // `buf.len()` is exactly the buffer's size; the entry's strings point into `buf`, which
    // outlives the reads below.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc))
            .with_context(|| format!("looking up the passwd entry for uid {uid}"));
    }
    anyhow::ensure!(!result.is_null(), "no passwd entry for uid {uid}");
    let text = |p: *const libc::c_char, field: &str| -> Result<String> {
        if p.is_null() {
            return Ok(String::new());
        }
        // SAFETY: a non-null field of a filled-in `passwd` is a NUL-terminated string in
        // `buf`, which is still alive here.
        let bytes = unsafe { std::ffi::CStr::from_ptr(p) }.to_bytes().to_vec();
        String::from_utf8(bytes)
            .with_context(|| format!("the {field} of the passwd entry for uid {uid} is not UTF-8"))
    };
    Ok((
        text(pwd.pw_name, "name")?,
        text(pwd.pw_dir, "home directory")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn workspace() -> PathBuf {
        std::fs::canonicalize(std::env::temp_dir()).unwrap()
    }

    fn decide(argv: &[&str]) -> Decision {
        decide_in(&workspace(), argv, &[])
    }

    fn decide_in(cwd: &Path, argv: &[&str], env: &[(&str, &str)]) -> Decision {
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        let env: Vec<(String, String)> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        git_gui(&workspace(), cwd, &argv, &env, ("dev", "/home/dev")).unwrap()
    }

    fn refused(argv: &[&str]) -> String {
        match decide(argv) {
            Decision::Refused(why) => why,
            other => panic!("{argv:?} was not refused: {other:?}"),
        }
    }

    fn ran(argv: &[&str]) -> (String, Vec<String>) {
        match decide(argv) {
            Decision::Run { program, args, .. } => (program, args),
            other => panic!("{argv:?} did not run: {other:?}"),
        }
    }

    #[test]
    fn options_that_load_code_are_refused() {
        assert!(refused(&["gitk", "--argscmd=touch /tmp/PWNED"]).contains("--argscmd"));
        assert!(refused(&["gitk", "--argscmd", "touch /tmp/PWNED"]).contains("--argscmd"));
    }

    #[test]
    fn only_the_two_git_guis_are_commands() {
        assert!(refused(&["rm", "-rf", "/"]).contains("command not allowed"));
        assert!(refused(&[]).contains("<none>"));
        assert!(refused(&[""]).contains("<none>"));
        assert!(refused(&["/workdir/evil/gitk"]).contains("path-qualified"));
        assert!(refused(&["./gitk"]).contains("path-qualified"));
        assert!(refused(&["git", "status"]).contains("not 'git status'"));
        assert!(refused(&["git"]).contains("only 'git gui' is allowed"));
        assert!(refused(&["git", "guix"]).contains("not 'git guix'"));
        assert!(refused(&["sh", "-c", "id"]).contains("command not allowed"));
    }

    #[test]
    fn git_guis_own_subcommands_are_an_allowlist_too() {
        for sub in GIT_GUI_SUBCOMMANDS {
            assert!(
                matches!(decide(&["git", "gui", sub]), Decision::Run { .. }),
                "git gui {sub} should be allowed"
            );
        }
        assert!(refused(&["git", "gui", "cola"]).contains("'git gui cola' is not allowed"));
        // The options of an allowed subcommand still go through the same table.
        assert!(refused(&["git", "gui", "blame", "--argscmd=id"]).contains("--argscmd"));
    }

    #[test]
    fn options_are_an_allowlist() {
        assert!(refused(&["gitk", "--ext-diff"]).contains("option not allowed"));
        assert!(refused(&["gitk", "-d"]).contains("option not allowed"));
        assert!(refused(&["gitk", "--all", "--argscmd=id"]).contains("--argscmd"));
        assert!(refused(&["git", "gui", "--argscmd=id"]).contains("--argscmd"));
    }

    #[test]
    fn the_git_guis_and_their_selectors_keep_working() {
        assert_eq!(ran(&["gitk"]), ("gitk".into(), vec![]));
        assert_eq!(
            ran(&["gitk", "--all"]),
            ("gitk".into(), vec!["--all".into()])
        );
        assert_eq!(ran(&["git", "gui"]), ("git".into(), vec!["gui".into()]));
        assert_eq!(
            ran(&["gitk", "--", "src/x.py"]),
            ("gitk".into(), vec!["--".into(), "src/x.py".into()])
        );
        // `--` does not end the scan: gitk's own option loop is not guaranteed to stop
        // there, so a word that looks like an option is still one here.
        assert!(refused(&["gitk", "--", "--argscmd=id"]).contains("--argscmd"));
        // A pathspec that starts with `-` goes through as a path.
        assert_eq!(
            ran(&["gitk", "--", "./-x"]),
            ("gitk".into(), vec!["--".into(), "./-x".into()])
        );
        for opt in [
            "--branches",
            "--branches=next",
            "--tags",
            "--tags=v1*",
            "--remotes",
            "--remotes=origin",
            "--since=yesterday",
            "--max-count=20",
            "-5",
        ] {
            assert!(
                matches!(decide(&["gitk", opt]), Decision::Run { .. }),
                "{opt} should be allowed"
            );
        }
    }

    #[test]
    fn the_environment_is_rebuilt_from_the_passwd_entry() {
        let env = [
            ("HOME", "/evil"),
            ("PATH", "/evil"),
            ("LD_PRELOAD", "/evil.so"),
            ("LD_AUDIT", "/evil.so"),
            ("GIT_EXEC_PATH", "/evil"),
            ("GIT_DIR", "/evil"),
            ("GIT_INDEX_FILE", "/evil"),
            ("GIT_EXTERNAL_DIFF", "/evil"),
            ("GIT_ASKPASS", "/evil"),
            ("GIT_PROXY_COMMAND", "/evil"),
            ("TCLLIBPATH", "/evil"),
            ("BASH_ENV", "/evil"),
            ("ENV", "/evil"),
            ("PERL5LIB", "/evil"),
            ("PYTHONPATH", "/evil"),
            ("XDG_CONFIG_HOME", "/evil"),
            ("DISPLAY", ":0"),
            ("LC_TIME", "fr_FR.UTF-8"),
        ];
        let Decision::Run { env: got, .. } = decide_in(&workspace(), &["gitk"], &env) else {
            panic!("gitk was refused");
        };
        assert!(!got.iter().any(|(_, v)| v.contains("/evil")));
        let value = |name: &str| got.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
        assert_eq!(value("HOME"), Some("/home/dev"));
        assert_eq!(value("USER"), Some("dev"));
        assert_eq!(value("LOGNAME"), Some("dev"));
        assert_eq!(value("PATH"), Some(SAFE_PATH));
        assert_eq!(value("DISPLAY"), Some(":0"));
        assert_eq!(value("LC_TIME"), Some("fr_FR.UTF-8"));
    }

    #[test]
    fn the_passthrough_list_is_exactly_what_it_claims() {
        // Every name the policy documents, plus one `LC_*` and one near-miss each.
        let mut env: Vec<(&str, &str)> = PASSTHROUGH.iter().map(|k| (*k, "kept")).collect();
        env.extend([
            ("LC_ALL", "kept"),
            ("LC_MESSAGES", "kept"),
            ("LCFOO", "gone"),
            ("XDG_DATA_HOME", "gone"),
            ("DISPLAY_MANAGER", "gone"),
            ("SSH_AUTH_SOCK", "gone"),
            ("TERM", "gone"),
        ]);
        let Decision::Run { env: got, .. } = decide_in(&workspace(), &["gitk"], &env) else {
            panic!("gitk was refused");
        };
        let names: Vec<&str> = got.iter().map(|(k, _)| k.as_str()).collect();
        let mut want: Vec<&str> = PASSTHROUGH.to_vec();
        want.extend(["LC_ALL", "LC_MESSAGES", "PATH", "HOME", "USER", "LOGNAME"]);
        want.sort_unstable();
        let mut got_sorted = names.clone();
        got_sorted.sort_unstable();
        assert_eq!(got_sorted, want, "the environment is exactly this");
        assert!(!got.iter().any(|(_, v)| v == "gone"), "{got:?}");
    }

    #[test]
    fn a_symlinked_working_directory_inside_the_workspace_is_inside_it() {
        let root = workspace();
        let scratch = root.join(format!("vk-hostpolicy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(scratch.join("real")).unwrap();
        let link = scratch.join("link");
        std::os::unix::fs::symlink(scratch.join("real"), &link).unwrap();
        // The path resolves inside the workspace, which is what the check is about.
        assert!(matches!(
            decide_in(&link, &["gitk"], &[]),
            Decision::Run { .. }
        ));
        // One that points out of it does not, whatever its name suggests.
        let out = scratch.join("escape");
        std::os::unix::fs::symlink(root.parent().unwrap_or(Path::new("/")), &out).unwrap();
        match decide_in(&out, &["gitk"], &[]) {
            Decision::Refused(why) => assert!(why.contains("outside the workspace"), "{why}"),
            other => panic!("a symlink out of the workspace was allowed: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn a_working_directory_outside_the_workspace_is_refused() {
        let root = workspace();
        let outside = root.parent().unwrap_or(Path::new("/")).to_path_buf();
        match decide_in(&outside, &["gitk"], &[]) {
            Decision::Refused(why) => assert!(why.contains("outside the workspace"), "{why}"),
            other => panic!("running outside the workspace was allowed: {other:?}"),
        }
        // A directory that cannot be resolved is refused for that reason, not as one that
        // resolved somewhere else.
        match decide_in(&root.join("nope-does-not-exist"), &["gitk"], &[]) {
            Decision::Refused(why) => {
                assert!(
                    why.contains("cannot resolve the working directory"),
                    "{why}"
                );
                assert!(!why.contains("outside the workspace"), "{why}");
            }
            other => panic!("a missing working directory was allowed: {other:?}"),
        }
    }
}
