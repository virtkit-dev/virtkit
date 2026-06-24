//! Content hashing of a `(Dockerfile, stage)` — computes a stable 7-char hash of a
//! Dockerfile stage and its build context, matching the scheme an external build
//! pipeline can stamp into image tags (`<name>-<codename>:<hash>`). Matching it
//! byte-for-byte is the point: it lets the executor resolve a stage to the image the
//! build pipeline already produced.
//!
//! Two phases mirror the shell:
//!   - analyze: parse the Dockerfile into stages, and per stage compute the
//!     closure's context files (sorted) + a minimal Dockerfile (just that
//!     stage's lines, since every other stage is an independent build target).
//!   - hash: sha256 over `minimal-Dockerfile \n {ctx-file sha256 \n} {provided
//!     build-arg value \n} {dep:dep-hash \n}`, in topological order so a
//!     dependency's hash folds into its dependents. Truncated to 7 hex chars.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use regex::Regex;
use sha2::{Digest, Sha256};

/// Result of analyzing one or more Dockerfiles.
pub struct Analysis {
    /// stage names in definition order (already topological)
    stages: Vec<String>,
    /// minimal Dockerfile per stage (comments/blank lines stripped)
    dockerfile: HashMap<String, String>,
    /// closure context files per stage, sorted (absolute paths)
    context: HashMap<String, Vec<PathBuf>>,
    /// parent stage of each stage (the `FROM <parent>` ref), stages only — the
    /// edge `build_args_for` walks to find the root-nearest DOCKER_STAGE_HASH.
    parent: HashMap<String, String>,
    /// every name that is a stage (so non-stage `FROM` refs like `scratch` or a
    /// registry image are excluded from the parent walk).
    is_stage: BTreeSet<String>,
    /// stage names reachable from each output stage (its build closure).
    closure: HashMap<String, BTreeSet<String>>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    let mut s = String::with_capacity(d.len() * 2);
    for b in d {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn is_blank(l: &str) -> bool {
    l.trim().is_empty()
}
fn is_comment(l: &str) -> bool {
    l.trim_start().starts_with('#')
}

/// docker-analyze.sh extract_val: value after `key`, leading `/` stripped, up to
/// the first comma or space.
fn extract_val(s: &str, key: &str) -> String {
    let Some(p) = s.find(key) else {
        return String::new();
    };
    let rest = &s[p + key.len()..];
    let rest = rest.strip_prefix('/').unwrap_or(rest);
    rest.split([',', ' ']).next().unwrap_or("").to_string()
}

/// docker-analyze.sh parse_line: collect cross-stage refs (FROM/COPY --from,
/// --mount=from) and context sources (COPY srcs, --mount=type=bind sources).
fn parse_line(line: &str, refs: &mut Vec<String>, srcs: &mut Vec<String>, flag_re: &Regex) {
    if line.contains("--from=") {
        let v = extract_val(line, "--from=");
        if !v.is_empty() {
            refs.push(v);
        }
    }
    // --mount options
    let mut rest = line.to_string();
    while let Some(pos) = rest.find("--mount=") {
        // opts = the --mount= token up to the first whitespace
        let after = &rest[pos..];
        let opts_full = after.split(char::is_whitespace).next().unwrap_or(after);
        let opts = opts_full.strip_prefix("--mount=").unwrap_or(opts_full);
        if opts.contains("from=") {
            let v = extract_val(opts, "from=");
            if !v.is_empty() {
                refs.push(v);
            }
        } else if opts.contains("type=bind") && opts.contains("source=") {
            let v = extract_val(opts, "source=");
            if !v.is_empty() {
                add_source(srcs, &v);
            }
        }
        // drop the first `--mount=<non-space>+` (awk: stops at a literal space)
        let token_len = after.find(' ').unwrap_or(after.len());
        rest.replace_range(pos..pos + token_len, "");
    }
    // COPY (without --from) and ADD: collect the local source into the context.
    // ADD also accepts URLs and git refs — skip those, they have no local file to hash.
    let (is_copy, is_add) = (
        line.starts_with("COPY ") && !line.contains("--from="),
        line.starts_with("ADD "),
    );
    if is_copy || is_add {
        let skip = if is_copy { "COPY".len() } else { "ADD".len() };
        let mut src = line[skip..].trim_start().to_string();
        src = flag_re.replace_all(&src, "").to_string();
        let first = src
            .split(char::is_whitespace)
            .next()
            .unwrap_or("")
            .to_string();
        if !first.starts_with("http://") && !first.starts_with("https://") {
            add_source(srcs, &first);
        }
    }
}

/// docker-analyze.sh add_source: leading `/` stripped, empties dropped.
fn add_source(srcs: &mut Vec<String>, src: &str) {
    let s = src.strip_prefix('/').unwrap_or(src);
    if !s.is_empty() {
        srcs.push(s.to_string());
    }
}

/// Translate one .dockerignore line into the anchored ERE docker-analyze.sh uses.
fn dockerignore_pattern(line: &str) -> Option<String> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    let mut p = line.to_string();
    p = p.strip_prefix('/').unwrap_or(&p).to_string();
    p = p.replace("**", "GLOBSTAR");
    p = p.replace('.', "\\.");
    p = p.replace('*', "[^/]*");
    p = p.replace("GLOBSTAR/", "(.*/)?");
    p = p.replace("/GLOBSTAR", "(/.*)?");
    p = p.replace("GLOBSTAR", ".*");
    Some(format!("^{p}(/|$)"))
}

struct Analyzer {
    basedir: PathBuf,
    ignore: Vec<Regex>,
    find_cache: HashMap<String, Vec<String>>,
}

impl Analyzer {
    /// resolve a source path to its file list (file → itself; dir → recursive
    /// listing, .dockerignore-filtered, sorted; missing → empty).
    fn resolve_source(&mut self, src: &str) -> Vec<String> {
        let abs = self.basedir.join(src);
        // test -f follows symlinks
        if abs.is_file() {
            return vec![src.to_string()];
        }
        self.find_files(src)
    }

    fn find_files(&mut self, dir: &str) -> Vec<String> {
        if let Some(c) = self.find_cache.get(dir) {
            return c.clone();
        }
        let prefix = dir.trim_end_matches('/');
        let mut out = Vec::new();
        let root = self.basedir.join(dir);
        self.walk(&root, prefix, &mut out);
        out.sort();
        self.find_cache.insert(dir.to_string(), out.clone());
        out
    }

    // find <dir> -type f : regular files only (symlinks excluded), recursive
    fn walk(&self, dir: &Path, rel_prefix: &str, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let name = e.file_name();
            let Some(name) = name.to_str() else { continue };
            let rel = format!("{rel_prefix}/{name}");
            // symlink_metadata: do not follow (find -type f skips symlinks)
            let Ok(md) = e.path().symlink_metadata() else {
                continue;
            };
            let ft = md.file_type();
            if ft.is_dir() {
                self.walk(&e.path(), &rel, out);
            } else if ft.is_file() {
                if self.ignore.iter().any(|re| re.is_match(&rel)) {
                    continue;
                }
                out.push(rel);
            }
        }
    }
}

pub fn analyze(dockerfile: &Path, blacklist: &[String]) -> Result<Analysis> {
    let dockerfile = dockerfile
        .canonicalize()
        .with_context(|| format!("resolving {}", dockerfile.display()))?;
    let basedir = dockerfile
        .parent()
        .context("Dockerfile has no parent dir")?
        .to_path_buf();
    let text = std::fs::read_to_string(&dockerfile)
        .with_context(|| format!("reading {}", dockerfile.display()))?;

    // raw lines; a trailing newline does not add an empty record (awk NR)
    let mut raw: Vec<String> = text.split('\n').map(str::to_string).collect();
    if raw.last().is_some_and(|l| l.is_empty()) {
        raw.pop();
    }
    let nraw = raw.len();

    let flag_re = Regex::new(r"--[a-z]+=?[^ ]* *").unwrap();

    // ---- preprocess: strip comments/blanks, join `\` continuations ----
    let mut pp: Vec<String> = Vec::new();
    let mut i = 0;
    while i < nraw {
        let mut line = raw[i].clone();
        if is_comment(&line) || is_blank(&line) {
            i += 1;
            continue;
        }
        while line.ends_with('\\') && i < nraw - 1 {
            line.pop();
            i += 1;
            let cont = raw[i].trim_start_matches([' ', '\t']);
            line.push(' ');
            line.push_str(cont);
        }
        pp.push(line);
        i += 1;
    }

    // ---- parse stages + global lines from preprocessed lines ----
    let mut stage_order: Vec<String> = Vec::new();
    let mut parent: HashMap<String, String> = HashMap::new();
    let mut is_stage: BTreeSet<String> = BTreeSet::new();
    let mut refs: HashMap<String, Vec<String>> = HashMap::new();
    let mut srcs: HashMap<String, Vec<String>> = HashMap::new();
    let mut global = String::new();
    let mut in_global = true;
    let mut cur = String::new();
    for line in &pp {
        if let Some(rest) = line.strip_prefix("FROM ") {
            in_global = false;
            let words: Vec<&str> = rest.split_whitespace().collect();
            let par = words.first().copied().unwrap_or("").to_string();
            let mut name = String::new();
            for (k, w) in words.iter().enumerate() {
                if w.eq_ignore_ascii_case("as") && k + 1 < words.len() {
                    name = words[k + 1].to_string();
                    break;
                }
            }
            if !name.is_empty() {
                stage_order.push(name.clone());
                parent.insert(name.clone(), par);
                is_stage.insert(name.clone());
                cur = name;
            }
            continue;
        }
        if in_global {
            if !global.is_empty() {
                global.push('\n');
            }
            global.push_str(line);
            continue;
        }
        if !cur.is_empty() {
            parse_line(
                line,
                refs.entry(cur.clone()).or_default(),
                srcs.entry(cur.clone()).or_default(),
                &flag_re,
            );
        }
    }

    // ---- raw line ranges per stage (0-based, inclusive) ----
    let mut lstart: HashMap<String, usize> = HashMap::new();
    let mut lend: HashMap<String, usize> = HashMap::new();
    let mut cur_name = String::new();
    for (idx, l) in raw.iter().enumerate() {
        if let Some(rest) = l.strip_prefix("FROM ") {
            if !cur_name.is_empty() {
                lend.insert(cur_name.clone(), idx - 1);
            }
            cur_name = String::new();
            let words: Vec<&str> = rest.split_whitespace().collect();
            for (k, w) in words.iter().enumerate() {
                if w.eq_ignore_ascii_case("as") && k + 1 < words.len() {
                    cur_name = words[k + 1].to_string();
                    break;
                }
            }
            if !cur_name.is_empty() {
                lstart.insert(cur_name.clone(), idx);
            }
        }
    }
    if !cur_name.is_empty() {
        lend.insert(cur_name.clone(), nraw - 1);
    }

    // ---- output stages (blacklist filter) ----
    let bl: Option<Regex> = if blacklist.is_empty() {
        None
    } else {
        Some(Regex::new(&format!("^({})$", blacklist.join("|")))?)
    };
    let mut is_output: BTreeSet<String> = BTreeSet::new();
    let mut out_stages: Vec<String> = Vec::new();
    for s in &stage_order {
        if let Some(re) = &bl
            && re.is_match(s)
        {
            continue;
        }
        out_stages.push(s.clone());
        is_output.insert(s.clone());
    }

    // ---- dockerignore filter ----
    let mut ignore = Vec::new();
    let ign_path = basedir.join(".dockerignore");
    if let Ok(txt) = std::fs::read_to_string(&ign_path) {
        for l in txt.split('\n') {
            if let Some(p) = dockerignore_pattern(l)
                && let Ok(re) = Regex::new(&p)
            {
                ignore.push(re);
            }
        }
    }
    let mut az = Analyzer {
        basedir: basedir.clone(),
        ignore,
        find_cache: HashMap::new(),
    };

    let arg_decl_re = Regex::new(r"^ARG[ \t]+[a-zA-Z_]").unwrap();

    let mut dockerfile_out: HashMap<String, String> = HashMap::new();
    let mut context_out: HashMap<String, Vec<PathBuf>> = HashMap::new();
    let mut closure_out: HashMap<String, BTreeSet<String>> = HashMap::new();

    for stage in &out_stages {
        // -- closure names (DFS over parent + refs, stages only) --
        let closure = walk_closure(stage, &parent, &refs, &is_stage, false, &mut az, &srcs).0;
        closure_out.insert(stage.clone(), closure.clone());

        // -- closure files --
        let mut all_f: BTreeSet<String> = BTreeSet::new();
        let (_, files) = walk_closure(stage, &parent, &refs, &is_stage, true, &mut az, &srcs);
        for f in files {
            all_f.insert(f);
        }
        let ctx: Vec<PathBuf> = all_f.into_iter().map(|f| basedir.join(f)).collect();

        // -- minimal Dockerfile: keep only this stage's lines --
        let mut skip = vec![false; nraw];
        for s in &stage_order {
            let do_skip = !closure.contains(s) || (s != stage && is_output.contains(s));
            if do_skip && let (Some(&a), Some(&b)) = (lstart.get(s), lend.get(s)) {
                for sk in skip.iter_mut().take(b + 1).skip(a) {
                    *sk = true;
                }
            }
        }
        let mut df: String = raw
            .iter()
            .enumerate()
            .filter(|(li, _)| !skip[*li])
            .map(|(_, l)| l.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        // -- prepend referenced global ARGs --
        if !global.is_empty() {
            let dfl: Vec<&str> = df.split('\n').collect();
            let first_from = dfl.iter().position(|l| l.starts_with("FROM ")).unwrap_or(0);
            let body = dfl[first_from..].join("\n");
            let mut fg = String::new();
            for gl in global.split('\n') {
                if !arg_decl_re.is_match(gl) {
                    continue;
                }
                let aname: String = gl[3..]
                    .trim_start_matches([' ', '\t'])
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                let pat = Regex::new(&format!(
                    r"[$][{{]?{}([^a-zA-Z0-9_]|$)",
                    regex::escape(&aname)
                ))
                .unwrap();
                if pat.is_match(&body) {
                    fg.push_str(gl);
                    fg.push('\n');
                }
            }
            df = format!("{fg}{body}");
        }

        // -- strip comments + blank lines --
        df = df
            .split('\n')
            .filter(|l| !is_blank(l) && !is_comment(l))
            .collect::<Vec<_>>()
            .join("\n");

        dockerfile_out.insert(stage.clone(), df);
        context_out.insert(stage.clone(), ctx);
    }

    Ok(Analysis {
        stages: out_stages,
        dockerfile: dockerfile_out,
        context: context_out,
        parent,
        is_stage,
        closure: closure_out,
    })
}

/// DFS over the stage graph (parent edge + `--from`/`--mount=from` refs, stages
/// only). Returns the set of reachable stage names, and — when `collect_files` —
/// the resolved context files of every visited stage.
fn walk_closure(
    start: &str,
    parent: &HashMap<String, String>,
    refs: &HashMap<String, Vec<String>>,
    is_stage: &BTreeSet<String>,
    collect_files: bool,
    az: &mut Analyzer,
    srcs: &HashMap<String, Vec<String>>,
) -> (BTreeSet<String>, Vec<String>) {
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut files: Vec<String> = Vec::new();
    let mut seen_files: BTreeSet<String> = BTreeSet::new();
    let mut stack = vec![start.to_string()];
    while let Some(s) = stack.pop() {
        if visited.contains(&s) {
            continue;
        }
        visited.insert(s.clone());
        if collect_files && let Some(list) = srcs.get(&s) {
            for src in list {
                if src.is_empty() {
                    continue;
                }
                for f in az.resolve_source(src) {
                    if !f.is_empty() && seen_files.insert(f.clone()) {
                        files.push(f);
                    }
                }
            }
        }
        if let Some(p) = parent.get(&s)
            && is_stage.contains(p)
        {
            stack.push(p.clone());
        }
        if let Some(rs) = refs.get(&s) {
            for r in rs {
                if is_stage.contains(r) {
                    stack.push(r.clone());
                }
            }
        }
    }
    (visited, files)
}

// ---- hashing ----

/// Per-stage cross-stage deps (copy_deps then bind_deps, in order, dups kept)
/// and declared ARG names (deduped, in order), parsed from the minimal Dockerfile.
fn stage_deps_and_args(
    df: &str,
    stage: &str,
    known: &BTreeSet<String>,
) -> (Vec<String>, Vec<String>) {
    let mut copy_deps = Vec::new();
    let mut bind_deps = Vec::new();
    let mut args = Vec::new();
    let mut seen_args: BTreeSet<String> = BTreeSet::new();
    let mut cur_instr = "";
    for line in df.split('\n') {
        if let Some(rest) = line.strip_prefix("FROM ") {
            cur_instr = "FROM";
            let word = rest.split(' ').next().unwrap_or("");
            if word != stage && known.contains(word) {
                copy_deps.push(word.to_string());
            }
        } else if line.starts_with("COPY ") || line.starts_with("ADD ") {
            cur_instr = "COPY";
        } else if line.starts_with("RUN ") {
            cur_instr = "RUN";
        } else if !line.starts_with([' ', '\t']) {
            cur_instr = "";
        }
        if cur_instr == "COPY" || cur_instr == "RUN" {
            for r in froms_in_line(line) {
                if r != stage && known.contains(&r) {
                    if cur_instr == "COPY" {
                        copy_deps.push(r);
                    } else {
                        bind_deps.push(r);
                    }
                }
            }
        }
        if let Some(rest) = line.strip_prefix("ARG ")
            && rest.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if seen_args.insert(name.clone()) {
                args.push(name);
            }
        }
    }
    copy_deps.extend(bind_deps);
    (copy_deps, args)
}

/// every `from=<ref>` occurrence in a line (ref = up to space/comma/tab)
fn froms_in_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(p) = rest.find("from=") {
        rest = &rest[p + "from=".len()..];
        let r: String = rest
            .chars()
            .take_while(|c| *c != ' ' && *c != ',' && *c != '\t')
            .collect();
        if !r.is_empty() {
            out.push(r);
        }
    }
    out
}

/// Compute the hash of every stage (topological), folding dependency hashes in.
pub fn hash_all(
    a: &Analysis,
    build_args: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let known: BTreeSet<String> = a.stages.iter().cloned().collect();

    // file content hashes (full sha256), one read per unique context file
    let mut file_hash: HashMap<PathBuf, String> = HashMap::new();
    for s in &a.stages {
        for f in &a.context[s] {
            if !file_hash.contains_key(f) {
                let bytes = std::fs::read(f)
                    .with_context(|| format!("reading context file {}", f.display()))?;
                file_hash.insert(f.clone(), sha256_hex(&bytes));
            }
        }
    }

    let mut hashes: BTreeMap<String, String> = BTreeMap::new();
    for stage in &a.stages {
        let df = &a.dockerfile[stage];
        let (deps, args) = stage_deps_and_args(df, stage, &known);

        let mut input = String::new();
        input.push_str(df);
        input.push('\n');
        for f in &a.context[stage] {
            input.push_str(&file_hash[f]);
            input.push('\n');
        }
        for arg in &args {
            if let Some(v) = build_args.get(arg)
                && !v.is_empty()
            {
                input.push_str(v);
                input.push('\n');
            }
        }
        for dep in &deps {
            if let Some(h) = hashes.get(dep) {
                input.push_str(dep);
                input.push(':');
                input.push_str(h);
                input.push('\n');
            }
        }
        let full = sha256_hex(input.as_bytes());
        hashes.insert(stage.clone(), full[..7].to_string());
    }
    Ok(hashes)
}

/// Analyze one or more Dockerfiles into a single merged [`Analysis`]: stages from
/// every file are merged (first definition wins) so cross-file stage deps fold
/// transitively. Shared by the `docker-hash` CLI and the `build` subcommand.
pub fn merge_analyses(dockerfiles: &[PathBuf], blacklist: &[String]) -> Result<Analysis> {
    if dockerfiles.len() == 1 {
        return analyze(&dockerfiles[0], blacklist);
    }
    let mut stages: Vec<String> = Vec::new();
    let mut dockerfile_map: HashMap<String, String> = HashMap::new();
    let mut context_map: HashMap<String, Vec<PathBuf>> = HashMap::new();
    let mut parent_map: HashMap<String, String> = HashMap::new();
    let mut is_stage: BTreeSet<String> = BTreeSet::new();
    let mut closure_map: HashMap<String, BTreeSet<String>> = HashMap::new();
    for df in dockerfiles {
        let mut part = analyze(df, blacklist)?;
        is_stage.extend(part.is_stage.iter().cloned());
        for (k, v) in part.parent.drain() {
            parent_map.entry(k).or_insert(v);
        }
        for s in part.stages {
            if !dockerfile_map.contains_key(&s) {
                stages.push(s.clone());
                if let (Some(d), Some(c), Some(cl)) = (
                    part.dockerfile.remove(&s),
                    part.context.remove(&s),
                    part.closure.remove(&s),
                ) {
                    dockerfile_map.insert(s.clone(), d);
                    context_map.insert(s.clone(), c);
                    closure_map.insert(s, cl);
                }
            }
        }
    }
    Ok(Analysis {
        stages,
        dockerfile: dockerfile_map,
        context: context_map,
        parent: parent_map,
        is_stage,
        closure: closure_map,
    })
}

/// Magic build-arg the build pipeline injects so a stage can stamp the content
/// hash of the core builder it descends from into its own tag.
const DOCKER_STAGE_HASH: &str = "DOCKER_STAGE_HASH";

/// Depth of a stage from the closure root: number of `FROM <parent-stage>` hops
/// until a parent that is not itself a stage (a real base image like `scratch` or
/// `debian:…`). Root stages are depth 0; their stage children depth 1; etc.
fn depth_from_root(stage: &str, a: &Analysis) -> usize {
    let mut depth = 0;
    let mut cur = stage.to_string();
    // bounded by the number of stages — the parent graph is a DAG, no cycles
    while let Some(p) = a.parent.get(&cur) {
        if !a.is_stage.contains(p) {
            break;
        }
        depth += 1;
        cur = p.clone();
    }
    depth
}

/// Project the build args to feed buildctl for `target`. For every `ARG` declared
/// anywhere in `target`'s closure: `DOCKER_STAGE_HASH` resolves to the hash of the
/// root-nearest closure stage that declares it (so it identifies the core builder
/// even when a deeper child is the target); a user-supplied arg passes through;
/// anything else is omitted so the Dockerfile default applies.
pub fn build_args_for(
    a: &Analysis,
    hashes: &HashMap<String, String>,
    target: &str,
    user_args: &BTreeMap<String, String>,
) -> Result<Vec<(String, String)>> {
    let known: BTreeSet<String> = a.stages.iter().cloned().collect();
    let closure = a
        .closure
        .get(target)
        .with_context(|| format!("stage '{target}' not found"))?;

    // declared ARG names per closure stage (deduped, union over the closure), and
    // for DOCKER_STAGE_HASH the root-nearest declaring stage.
    let mut declared: BTreeSet<String> = BTreeSet::new();
    let mut hash_stage: Option<(usize, String)> = None;
    for stage in closure {
        let Some(df) = a.dockerfile.get(stage) else {
            continue;
        };
        let (_, args) = stage_deps_and_args(df, stage, &known);
        for arg in args {
            if arg == DOCKER_STAGE_HASH {
                let d = depth_from_root(stage, a);
                // strictly-less keeps the first (definition order) on ties
                if hash_stage.as_ref().is_none_or(|(bd, _)| d < *bd) {
                    hash_stage = Some((d, stage.clone()));
                }
            }
            declared.insert(arg);
        }
    }

    let mut out: Vec<(String, String)> = Vec::new();
    for arg in &declared {
        if arg == DOCKER_STAGE_HASH {
            if let Some((_, stage)) = &hash_stage {
                let h = hashes.get(stage).with_context(|| {
                    format!("no hash computed for stage '{stage}' (DOCKER_STAGE_HASH source)")
                })?;
                out.push((DOCKER_STAGE_HASH.to_string(), h.clone()));
            }
        } else if let Some(v) = user_args.get(arg) {
            out.push((arg.clone(), v.clone()));
        }
        // else: omit — the Dockerfile default applies.
    }
    Ok(out)
}

/// CLI entry: print `stage:hash` for the requested stages (or all, in
/// definition order, if none requested). Accepts one or more Dockerfiles;
/// stages from all files are merged and cross-file deps fold transitively.
pub fn run(
    dockerfiles: &[PathBuf],
    build_args: &BTreeMap<String, String>,
    blacklist: &[String],
    requested: &[String],
) -> Result<()> {
    let a = merge_analyses(dockerfiles, blacklist)?;
    let hashes = hash_all(&a, build_args)?;
    let want: Vec<String> = if requested.is_empty() {
        a.stages.clone()
    } else {
        requested.to_vec()
    };
    for s in &want {
        let h = hashes.get(s).with_context(|| {
            format!(
                "stage '{s}' not found (files: {})",
                dockerfiles
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
        println!("{s}:{h}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pinned hashes on this exact fixture, so a drift from the canonical algorithm
    // fails here.
    const FIXTURE: &str = "# a comment\n\
ARG FOO=default\n\
ARG UNUSED=x\n\
FROM alpine:3.20 AS base\n\
ARG FOO\n\
COPY f1.txt /f1\n\
RUN echo building $FOO\n\
\n\
FROM base AS app\n\
COPY --from=base /f1 /f1b\n\
COPY dir /d\n\
RUN --mount=type=bind,source=f1.txt,target=/m true\n";

    #[test]
    fn matches_docker_tool_sh() {
        let dir = std::env::temp_dir().join(format!("vmx-dockerhash-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("dir")).unwrap();
        std::fs::write(dir.join("f1.txt"), "hello\n").unwrap();
        std::fs::write(dir.join("dir/a.txt"), "A\n").unwrap();
        std::fs::write(dir.join("dir/b.txt"), "B\n").unwrap();
        std::fs::write(dir.join("Dockerfile"), FIXTURE).unwrap();

        let a = analyze(&dir.join("Dockerfile"), &[]).unwrap();
        // closure context of `app` spans base too: f1.txt + dir/{a,b}.txt (absolute)
        assert_eq!(
            a.context["app"],
            [
                dir.join("dir/a.txt"),
                dir.join("dir/b.txt"),
                dir.join("f1.txt")
            ]
        );

        let mut args = BTreeMap::new();
        args.insert("FOO".to_string(), "custom".to_string());
        let h = hash_all(&a, &args).unwrap();
        assert_eq!(h["base"], "cf2f8b6");
        assert_eq!(h["app"], "ce54db3");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // An ancestor `builder` declares DOCKER_STAGE_HASH (consumed by a deeper target
    // `svc`), `svc` itself declares a user arg, and an unrelated `other` stage
    // (outside svc's closure) declares another user arg.
    const ARGS_FIXTURE: &str = "\
FROM alpine:3.20 AS builder\n\
ARG DOCKER_STAGE_HASH\n\
RUN echo $DOCKER_STAGE_HASH > /tag\n\
\n\
FROM builder AS mid\n\
RUN true\n\
\n\
FROM mid AS svc\n\
ARG IN_CLOSURE\n\
RUN echo $IN_CLOSURE\n\
\n\
FROM alpine:3.20 AS other\n\
ARG OUTSIDE\n\
RUN echo $OUTSIDE\n";

    #[test]
    fn build_args_for_projects_stage_hash_and_user_args() {
        let dir = std::env::temp_dir().join(format!("vmx-buildargs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Dockerfile"), ARGS_FIXTURE).unwrap();

        let a = analyze(&dir.join("Dockerfile"), &[]).unwrap();
        let hashes_b = hash_all(&a, &BTreeMap::new()).unwrap();
        let hashes: HashMap<String, String> = hashes_b.into_iter().collect();

        let mut user = BTreeMap::new();
        user.insert("IN_CLOSURE".to_string(), "yes".to_string());
        user.insert("OUTSIDE".to_string(), "no".to_string());

        let out = build_args_for(&a, &hashes, "svc", &user).unwrap();

        // DOCKER_STAGE_HASH resolves to the root-nearest declaring stage (`builder`,
        // depth 0), not `mid`/`svc`.
        assert_eq!(
            out.iter().find(|(k, _)| k == "DOCKER_STAGE_HASH"),
            Some(&("DOCKER_STAGE_HASH".to_string(), hashes["builder"].clone()))
        );
        // a user arg declared inside the closure passes through.
        assert_eq!(
            out.iter().find(|(k, _)| k == "IN_CLOSURE"),
            Some(&("IN_CLOSURE".to_string(), "yes".to_string()))
        );
        // a user arg declared only in `other` (outside svc's closure) is omitted.
        assert!(out.iter().all(|(k, _)| k != "OUTSIDE"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
