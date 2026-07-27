//! What each CI job reaches out to, remembered across runs: the external names its guests
//! resolved, kept per job for as long as its egress policy stays as it is.
//!
//! This is what an allowlist is written from. A job runs unrestricted, every run adds what it
//! contacted to the same list, and after a few pipelines the list is the `[egress] allow_name`
//! the job needs — including the host a nightly step reaches that no single run would show.
//! Recording it is not opt-in, unlike the audit summary of one run: the point is to have the
//! answer before anyone thinks to ask for it.
//!
//! The list belongs to a policy, not to a job: what a job contacted while it could reach
//! anything says nothing about the same job once an allowlist is in force — the names it
//! could no longer reach would linger as if it still used them. Each run therefore stamps
//! what it contacted with a fingerprint of the policy it ran under, and only the records of
//! the policy in force for this run are read back. Narrowing an allowlist starts the list
//! again; putting it back does not resurrect the old one, whose records the first
//! consolidation under the new policy has already dropped.

use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

// The run history's own path guard, not a second copy of it: both stores are keyed by a job
// name the project chooses, and a guard that exists twice is one that can be fixed once.
use crate::admit::under;

/// Records to keep before a file is consolidated. Each run appends one, so this is a fortnight
/// of a busy job — long enough that the rewrite is rare, small enough that reading it is free.
const TRIM_AT: usize = 500;
/// The most names one consolidated record holds, and the most a trace line shows. [`TRIM_AT`]
/// bounds the records, not what they carry: a job resolving a fresh name every run — a
/// per-build hostname, a random subdomain — would grow one record and one line without end.
/// Past this the list has stopped being something to paste into an allowlist, so it is cut,
/// and the line says how many it is not showing rather than reading as the whole of it.
const MAX_NAMES: usize = 200;
/// The longest name the store keeps — RFC 1035's presentation limit. Nothing upstream enforces
/// it: a guest frame carries up to 64 KiB of labels and `parse_question` concatenates them all,
/// so a job could otherwise write a single name of that size into a file every later run reads
/// and every trace line prints.
const MAX_NAME: usize = 253;

/// Note what one run contacted, under the policy it ran under, and return the whole list for
/// that policy — this run's names included. `None` when there is nothing to say: a job that
/// contacted nothing and has no list yet.
///
/// Best-effort throughout, like the run history beside it: a job's trace is worth no lost
/// work, so a store that cannot be written costs a line and nothing else.
pub fn remember(dir: &Path, key: &Path, policy: &str, contacted: &[String]) -> Option<Vec<String>> {
    let path = under(dir, key)?;
    // 0700 on create and on reuse, as the ledger and the run history beside it: this store
    // names the hosts a project's CI reaches, and a group-writable parent is somewhere another
    // local user can plant a symlink where the store file goes.
    let parent = path.parent()?;
    if std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .is_err()
    {
        return None;
    }
    for private in [dir, parent] {
        std::fs::set_permissions(private, std::fs::Permissions::from_mode(0o700)).ok()?;
    }
    // Held across the append and the consolidation under it, as the run history holds its
    // own: the consolidation rewrites the file whole, so a record appended between its read
    // and its write would be erased rather than merely delayed.
    let _dir_lock = crate::admit::lock_dir(dir).ok()?;
    if !contacted.is_empty() {
        append(&path, policy, contacted);
    }
    let text = std::fs::read_to_string(&path).ok()?;
    let known = under_policy(&text, policy);
    // Consolidate what has grown: every record of the current policy becomes one, and the
    // records of policies no longer in force go, since nothing will ever read them again.
    // Either bound consolidates. A job resolving a fresh name every run grows one record
    // without ever adding a line, so the record count alone does not hold the file down.
    if text.lines().count() > TRIM_AT || known.len() > MAX_NAMES {
        // Cut here rather than on the way out, so the caller still holds the whole list and
        // its line can say how much of it it is not showing.
        let mut kept = known.clone();
        kept.truncate(MAX_NAMES);
        let mut consolidated = String::new();
        record(&mut consolidated, policy, &kept);
        // Swapped in whole rather than truncated in place, as the run history's own trim does:
        // a write that fails partway — a runner out of disk — would otherwise leave the store
        // empty and lose the standing list, where a failed rename loses nothing.
        let staged = {
            let mut named = path.clone().into_os_string();
            named.push(".new");
            std::path::PathBuf::from(named)
        };
        let _ = std::fs::remove_file(&staged);
        let written = std::fs::File::options()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staged)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(consolidated.as_bytes())
            });
        if written.is_ok() {
            let _ = std::fs::rename(&staged, &path);
        } else {
            let _ = std::fs::remove_file(&staged);
        }
    }
    (!known.is_empty()).then_some(known)
}

/// The names recorded under `policy`, sorted, each once. Records of any other policy are
/// skipped: they were taken under rules that no longer apply.
fn under_policy(text: &str, policy: &str) -> Vec<String> {
    let mut names: Vec<String> = text
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .filter(|(stamp, _)| *stamp == policy)
        .flat_map(|(_, names)| names.split(' ').filter(|n| !n.is_empty()))
        .map(str::to_string)
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Append one run's contacts as a single record, so runs of the same job finishing together
/// cannot tear each other's — the same reason the run history appends whole lines.
fn append(path: &Path, policy: &str, contacted: &[String]) {
    let mut record_line = String::new();
    record(&mut record_line, policy, contacted);
    if let Ok(mut file) = std::fs::File::options()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
    {
        use std::io::Write;
        let _ = file.write_all(record_line.as_bytes());
    }
}

/// One record: the policy it was taken under, a tab, then the names space-separated. Each
/// name is reduced to the presentation charset on the way in, because a name is a guest's DNS
/// label and holds whatever bytes the job put there — only the control characters are taken
/// out upstream, and a space among them would split one name into two, letting a job forge
/// entries into the very list an operator writes an allowlist from.
fn record(out: &mut String, policy: &str, names: &[String]) {
    out.push_str(policy);
    out.push('\t');
    let safe: Vec<String> = names.iter().map(|n| sanitized(n)).collect();
    out.push_str(&safe.join(" "));
    out.push('\n');
}

/// A name as the store may hold it: anything outside a DNS presentation name becomes `?`, so
/// no name can carry this format's own separators.
fn sanitized(name: &str) -> String {
    name.chars()
        .take(MAX_NAME)
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '.' | '_' => c,
            _ => '?',
        })
        .collect()
}

/// A fingerprint of the egress policy a run was subject to, short enough for a trace and long
/// enough that two policies cannot collide by accident. `unrestricted` is spelled out rather
/// than hashed: it is the policy every job starts under, and reading it in the file says why
/// the list holds everything the job touched.
pub fn fingerprint(allow_ip: &[String], allow_name: &[String], restrict: bool) -> String {
    if !restrict {
        return "unrestricted".to_string();
    }
    // Each term carries its dimension: allowing the *address* 10.0.0.1 is not the policy that
    // allows a *name* spelled that way, and an unmarked join would fingerprint the two alike.
    // Sorted, so the same allowlist written in another order is the same policy and does not
    // throw the list away.
    // Normalised the way the switch normalises before enforcing (`Egress::restricted` trims a
    // leading dot and lower-cases), and deduped: two spellings of one enforced policy must not
    // fingerprint as two, or re-spelling an allowlist silently throws the job's list away.
    let mut terms: Vec<String> = allow_ip
        .iter()
        .map(|t| format!("ip:{}", t.trim()))
        .chain(allow_name.iter().map(|t| {
            format!(
                "name:{}",
                t.trim().trim_start_matches('.').to_ascii_lowercase()
            )
        }))
        .collect();
    terms.sort_unstable();
    terms.dedup();
    use sha2::{Digest, Sha256};
    // Eight bytes, as a job's own history key uses (see `jobctx::job_component`): a job
    // narrows its own policy through `MICROVM_EGRESS_ALLOW_*`, so it chooses both sides of a
    // collision, and six is within reach of anyone who wants one policy's list read back
    // under another.
    let digest = Sha256::digest(terms.join("\n").as_bytes());
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// The trace line naming what this job reaches out to. Says which policy the list belongs to,
/// because that is what makes it complete: under an allowlist it is what the job still
/// reaches, and unrestricted it is what an allowlist would have to hold.
pub fn summary(names: &[String], policy: &str) -> Option<String> {
    if names.is_empty() {
        return None;
    }
    let scope = match policy {
        "unrestricted" => "unrestricted egress".to_string(),
        fp => format!("egress policy {fp}"),
    };
    let (shown, rest) = names.split_at(names.len().min(MAX_NAMES));
    let more = match rest.len() {
        0 => String::new(),
        n => format!(" (and {n} more)"),
    };
    Some(format!(
        "virtkit: names this job has contacted under {scope}: {}{more}",
        shown.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-sites-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// Run after run the list grows, and each run sees everything the job has contacted —
    /// which is the point: an allowlist is written from the whole list, not from one run.
    #[test]
    fn each_run_adds_to_what_the_job_is_known_to_contact() {
        let dir = tmpdir("grows");
        let key = Path::new("7-acme/test-abc");
        assert_eq!(
            remember(&dir, key, "unrestricted", &names(&["deb.debian.org"])),
            Some(names(&["deb.debian.org"]))
        );
        assert_eq!(
            remember(&dir, key, "unrestricted", &names(&["github.com"])),
            Some(names(&["deb.debian.org", "github.com"]))
        );
        // A name contacted again is the same name, however many runs reach it.
        assert_eq!(
            remember(&dir, key, "unrestricted", &names(&["github.com"])),
            Some(names(&["deb.debian.org", "github.com"]))
        );
        // A run that contacted nothing still reads what the job is known to contact.
        assert_eq!(
            remember(&dir, key, "unrestricted", &[]),
            Some(names(&["deb.debian.org", "github.com"]))
        );
        // Another job of the same project keeps its own list.
        assert_eq!(
            remember(&dir, Path::new("7-acme/lint-def"), "unrestricted", &[]),
            None
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A policy change is what resets the list: names reached under the old rules are not
    /// evidence about the new ones, and would otherwise read as an allowlist that is still
    /// too wide.
    #[test]
    fn a_new_policy_starts_the_list_again() {
        let dir = tmpdir("policy");
        let key = Path::new("7-acme/test-abc");
        remember(
            &dir,
            key,
            "unrestricted",
            &names(&["deb.debian.org", "evil.example"]),
        );
        assert_eq!(
            remember(&dir, key, "abc123", &names(&["deb.debian.org"])),
            Some(names(&["deb.debian.org"])),
            "the narrowed policy knows only what it has seen"
        );
        // And going back to the old policy does not resurrect its list: those names were last
        // seen who knows when, under rules the job has since run without.
        assert_eq!(
            remember(&dir, key, "unrestricted", &names(&["deb.debian.org"])),
            Some(names(&["deb.debian.org", "evil.example"]))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The file cannot grow forever: once it does, what the current policy knows becomes one
    /// record and everything else goes.
    #[test]
    fn a_long_lived_list_is_consolidated() {
        let dir = tmpdir("trim");
        let key = Path::new("7-acme/test-abc");
        // A job's worth of runs, written as the runs themselves would have: one record each,
        // and an old policy's among them for the consolidation to drop rather than carry.
        std::fs::create_dir_all(dir.join(key).parent().unwrap()).unwrap();
        let mut history = "old\tgone.example\n".to_string();
        for _ in 0..TRIM_AT {
            history.push_str("unrestricted\tdeb.debian.org\n");
        }
        std::fs::write(dir.join(key), &history).unwrap();

        remember(&dir, key, "unrestricted", &names(&["deb.debian.org"]));
        let text = std::fs::read_to_string(dir.join(key)).unwrap();
        assert_eq!(text, "unrestricted\tdeb.debian.org\n");
        assert_eq!(
            remember(&dir, key, "unrestricted", &[]),
            Some(names(&["deb.debian.org"])),
            "consolidating keeps what the policy knows"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The same allowlist is the same policy however it is written, and any change to it is a
    /// different one.
    #[test]
    fn a_policy_is_fingerprinted_by_what_it_allows() {
        let one = fingerprint(
            &names(&["10.0.0.1", "10.0.0.2"]),
            &names(&["a.example", "deb.debian.org"]),
            true,
        );
        let reordered = fingerprint(
            &names(&["10.0.0.2", "10.0.0.1"]),
            &names(&["deb.debian.org", "a.example"]),
            true,
        );
        assert_eq!(one, reordered);
        assert_ne!(
            one,
            fingerprint(
                &names(&["10.0.0.1", "10.0.0.2"]),
                &names(&["a.example", "deb.debian.org", "b.example"]),
                true
            )
        );
        // A term moved between the two dimensions is a different policy: allowing an address
        // is not allowing a name that happens to be spelled the same way.
        assert_ne!(
            fingerprint(&names(&["10.0.0.1"]), &[], true),
            fingerprint(&[], &names(&["10.0.0.1"]), true)
        );
        // Unrestricted is a policy of its own, and says so in the file rather than as a hash.
        assert_eq!(fingerprint(&[], &[], false), "unrestricted");
        assert_ne!(fingerprint(&[], &[], true), "unrestricted");
    }

    /// A key that would climb out of the store writes nothing — a job name is chosen by the
    /// project, so it is never trusted as a path.
    #[test]
    fn a_key_outside_the_store_writes_nothing() {
        let dir = tmpdir("escape");
        assert_eq!(
            remember(
                &dir,
                Path::new("../elsewhere"),
                "unrestricted",
                &names(&["a.example"])
            ),
            None
        );
        // Asked of the guard directly as well, so the case is pinned without resting on
        // whether anything else on this host happens to have made the path beside the store.
        assert_eq!(under(&dir, Path::new("../elsewhere")), None);
        assert_eq!(under(&dir, Path::new("/etc/passwd")), None);
        assert!(!dir.exists(), "a refused key creates nothing at all");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A job chooses what its guests resolve, so a name is never trusted to be one: a label
    /// holding a space would otherwise land in the list as two names, one of them a host the
    /// job never reached and an operator might well allowlist.
    #[test]
    fn a_name_cannot_forge_a_second_one() {
        let dir = tmpdir("forge");
        let key = Path::new("7-acme/test-abc");
        assert_eq!(
            remember(
                &dir,
                key,
                "unrestricted",
                &names(&["deb.debian.org evil.example.com"])
            ),
            Some(names(&["deb.debian.org?evil.example.com"])),
            "one label is one name, whatever bytes the job put in it"
        );
        // Neither can it forge the policy field the records are keyed on.
        assert_eq!(
            remember(
                &dir,
                key,
                "unrestricted",
                &names(&["a.example\tabc123\tb.example"])
            ),
            Some(names(&[
                "a.example?abc123?b.example",
                "deb.debian.org?evil.example.com"
            ]))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A list too long to paste into an allowlist is cut where it is stored — and the line
    /// says how much it is not showing, rather than reading as the whole of what a job
    /// contacts.
    #[test]
    fn a_capped_list_says_how_much_it_is_not_showing() {
        let dir = tmpdir("cap");
        let key = Path::new("7-acme/test-abc");
        let many: Vec<String> = (0..MAX_NAMES + 5)
            .map(|i| format!("h{i:04}.example"))
            .collect();
        let known = remember(&dir, key, "unrestricted", &many).expect("the job has a list");
        assert_eq!(
            known.len(),
            MAX_NAMES + 5,
            "the caller is handed the whole list"
        );
        let line = summary(&known, "unrestricted").unwrap();
        assert!(line.ends_with("(and 5 more)"), "{line}");

        // Consolidation is what applies the cap to the store, so the names past it stop being
        // remembered — which the line above is what warns about.
        let mut history = String::new();
        for _ in 0..TRIM_AT {
            history.push_str("unrestricted\tfiller.example\n");
        }
        std::fs::write(dir.join(key), &history).unwrap();
        let after = remember(&dir, key, "unrestricted", &many).expect("the job has a list");
        assert_eq!(after.len(), many.len() + 1, "everything, filler included");
        let stored = std::fs::read_to_string(dir.join(key)).unwrap();
        assert_eq!(stored.lines().count(), 1, "consolidated to one record");
        assert_eq!(
            stored.split_whitespace().count() - 1,
            MAX_NAMES,
            "the record holds no more than the cap"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two runs of one job finishing together — two pipelines, a retry, two runners sharing
    /// the state dir — must not erase each other: the consolidation rewrites the file whole,
    /// so an append landing between its read and its write would otherwise be lost.
    ///
    /// The file is seeded past [`TRIM_AT`] first, so every call below really does consolidate;
    /// under the threshold the racers would only prove that `O_APPEND` writes do not interleave.
    /// The racing names are a small fixed set, well inside [`MAX_NAMES`], so consolidation
    /// keeping only that many cannot be what drops one.
    #[test]
    fn concurrent_runs_do_not_lose_each_others_names() {
        const THREADS: usize = 8;
        const EACH: usize = 20;
        let dir = tmpdir("concurrent");
        let key = Path::new("7-acme/test-abc");
        for i in 0..=TRIM_AT {
            remember(
                &dir,
                key,
                "unrestricted",
                &names(&[&format!("seed{i}.example")]),
            );
        }
        std::thread::scope(|s| {
            for t in 0..THREADS {
                let dir = &dir;
                s.spawn(move || {
                    for i in 0..EACH {
                        remember(
                            dir,
                            key,
                            "unrestricted",
                            &names(&[&format!("h{t}-{i}.example")]),
                        );
                    }
                });
            }
        });
        let known = remember(&dir, key, "unrestricted", &[]).expect("the job has a list");
        for t in 0..THREADS {
            for i in 0..EACH {
                let name = format!("h{t}-{i}.example");
                assert!(known.contains(&name), "{name} was lost");
            }
        }
        // And the consolidation really ran: the seeds are long gone from the file.
        assert!(
            std::fs::read_to_string(dir.join(key))
                .unwrap()
                .lines()
                .count()
                <= TRIM_AT,
            "the file was never consolidated, so the race was never run"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A guest chooses the names it resolves, and nothing upstream bounds them: `parse_question`
    /// concatenates the labels of a frame up to 64 KiB. Both the length of one name and the
    /// number a run can add have to be the store's problem, or a job writes a file every later
    /// run reads and every trace line prints.
    #[test]
    fn a_guest_cannot_grow_the_store_without_bound() {
        let dir = tmpdir("bounded");
        let key = Path::new("7-acme/greedy-abc");

        // One absurd name is cut to the presentation limit rather than stored whole.
        let huge = format!("{}.example", "a".repeat(60_000));
        let known = remember(&dir, key, "unrestricted", &names(&[&huge])).unwrap();
        assert_eq!(known.len(), 1);
        assert_eq!(known[0].len(), MAX_NAME);

        // And a single run of many fresh names consolidates on the spot, without waiting for
        // TRIM_AT records that a job like this never produces.
        let many: Vec<String> = (0..MAX_NAMES * 10)
            .map(|i| format!("h{i}.example"))
            .collect();
        let known = remember(&dir, key, "unrestricted", &many).unwrap();
        let on_disk = std::fs::read_to_string(dir.join(key)).unwrap();
        assert!(
            on_disk.len() < 32 * 1024,
            "the store kept {} bytes of a job's own choosing",
            on_disk.len()
        );
        // This run still gets the whole list — that is what lets its line say how many it is
        // not showing — but the file it left behind is cut, so every later run is bounded.
        assert!(known.len() > MAX_NAMES, "the caller sees what it contacted");
        let next = remember(&dir, key, "unrestricted", &[]).unwrap();
        assert!(next.len() <= MAX_NAMES, "the next run reads {}", next.len());
        // And the line is bounded either way: MAX_NAMES names of at most MAX_NAME each.
        let line = summary(&known, "unrestricted").unwrap();
        assert!(
            line.len() < MAX_NAMES * (MAX_NAME + 2) + 128,
            "{}",
            line.len()
        );
        assert!(
            line.contains("more)"),
            "the line says what it is not showing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two spellings of one enforced policy are one policy: the switch trims a leading dot and
    /// lower-cases before enforcing, so fingerprinting the raw strings would throw a job's
    /// standing list away for a purely cosmetic edit.
    #[test]
    fn a_respelled_allowlist_is_the_same_policy() {
        let base = fingerprint(&[], &names(&["github.com", "crates.io"]), true);
        assert_eq!(
            base,
            fingerprint(&[], &names(&["GitHub.com", ".crates.io"]), true),
            "case and a leading dot are not a different policy"
        );
        assert_eq!(
            base,
            fingerprint(
                &[],
                &names(&["crates.io", "github.com", "github.com"]),
                true
            ),
            "order and a repeat are not a different policy"
        );
        // A genuinely different allowlist still is one.
        assert_ne!(base, fingerprint(&[], &names(&["github.com"]), true));
    }

    #[test]
    fn the_summary_names_the_policy_the_list_belongs_to() {
        assert_eq!(
            summary(&names(&["a.example", "b.example"]), "unrestricted").unwrap(),
            "virtkit: names this job has contacted under unrestricted egress: a.example, b.example"
        );
        assert_eq!(
            summary(&names(&["a.example"]), "abc123").unwrap(),
            "virtkit: names this job has contacted under egress policy abc123: a.example"
        );
        assert_eq!(summary(&[], "unrestricted"), None);
    }
}
