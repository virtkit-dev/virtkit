//! Shared caches: named caches in a content-addressed store of their own, which the guests
//! of `vk dev` environments and of `vk run --shared-cache` reach through their registry
//! proxy. `[dev.cache] shared` and `--shared-cache` select the names it serves ([`lend`]).
//!
//! To the proxy, each shared cache is an area, as a CI job's namespace alias is: its name is
//! the alias, its repositories those under `dev/<alias>`. Each run that asks for shared
//! caches serves the store itself, on a loopback port behind a credential made for that
//! run, and lends it to its guests through a proxy confined to the areas
//! ([`crate::regproxy::Scope::Areas`]). The proxy confines names only: a guest that
//! knows a digest reads it whichever area it was pushed to. So the store must hold nothing
//! but shared cache content — never the build cache — and is one `vk` made for the purpose and
//! this user alone can reach ([`open_store`]). The runs using a store share its build-once
//! locks ([`vk_registry::lock::LockManager::host_shared`]), so a task two environments want
//! can be built by one of them and restored by the other. sccache reads and writes an area's
//! plain files over the store's S3 view (`/s3/job/<alias>/…`).

use std::io::Write;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use vk_hub_proto::dispatch::Area;
use vk_hub_proto::token::{MAX_PREFIX_LEN, RESERVED_COMPONENTS, servable_prefix, valid_component};

use crate::oci::Creds;
use crate::regproxy::{GUEST_HOST, ProxyCfg};

/// The repository prefix every area of the store lies under, `<AREA_ROOT>/<alias>`.
const AREA_ROOT: &str = "dev";

/// The file that marks a directory as a shared cache store `vk` made: what tells it from a
/// store of anything else before it is served or collected.
const MARKER: &str = "vk-shared-cache";

/// The store: `shared-cache` under the scratch base ([`crate::run::default_scratch_base`]),
/// so `$XDG_CACHE_HOME/virtkit/shared-cache`, else `~/.cache/virtkit/shared-cache`, beside the
/// build cache's default store. Everything in it can be rebuilt.
pub fn store_root() -> Result<PathBuf> {
    Ok(crate::run::default_scratch_base()
        .context("resolving the shared cache store dir")?
        .join("shared-cache"))
}

/// Why `alias` cannot name an area, if it cannot: an area is the repositories under
/// `<AREA_ROOT>/<alias>`, so the alias is one repository name component and the prefix one
/// the registry serves ([`servable_prefix`], what the proxy holds it to at a boot).
pub fn check_alias(alias: &str) -> Result<(), String> {
    if !valid_component(alias) {
        return Err(
            "is not a repository name component (lowercase ASCII letters and digits, \
             separated by `.`, `_`, `__` or hyphens)"
                .into(),
        );
    }
    if RESERVED_COMPONENTS.contains(&alias) {
        return Err("is a name the registry keeps for its own layout".into());
    }
    let prefix = area(alias).prefix;
    if prefix.len() > MAX_PREFIX_LEN {
        return Err(format!(
            "is longer than {} bytes",
            MAX_PREFIX_LEN - AREA_ROOT.len() - 1
        ));
    }
    if !servable_prefix(&prefix) {
        return Err("names no repository prefix the registry serves".into());
    }
    Ok(())
}

/// `aliases` sorted, each once: their order means nothing, so an environment's identity and
/// what its guest is told do not change with it.
pub fn canonical(aliases: &[String]) -> Vec<String> {
    let mut aliases = aliases.to_vec();
    aliases.sort_unstable();
    aliases.dedup();
    aliases
}

/// The area `alias` names: the same repositories for every environment using the store.
fn area(alias: &str) -> Area {
    Area {
        alias: alias.to_string(),
        prefix: format!("{AREA_ROOT}/{alias}"),
    }
}

/// The variables that tell a guest's tools of its shared caches: `VK_REGISTRY_AREAS` is
/// the older name of `VK_REGISTRY_CACHES`, kept for the scripts CI jobs taught it to.
pub const GUEST_ENV: [&str; 3] = ["VK_REGISTRY", "VK_REGISTRY_CACHES", "VK_REGISTRY_AREAS"];

/// What tells a guest's tools of its shared caches: where the registry is, and each name
/// with what it may do there — read, write and lock.
pub fn guest_env(aliases: &[String]) -> Vec<(String, String)> {
    let caches: Vec<String> = canonical(aliases)
        .iter()
        .map(|a| format!("{a}=rwl"))
        .collect();
    let caches = caches.join(" ");
    let [registry, caches_var, areas_var] = GUEST_ENV;
    vec![
        (registry.to_string(), format!("http://{GUEST_HOST}")),
        (caches_var.to_string(), caches.clone()),
        (areas_var.to_string(), caches),
    ]
}

/// The config key that asks for shared caches, as diagnostics name it.
pub const DEV_SHARED: &str = "`[dev.cache] shared`";

/// The flag that asks for shared caches, as diagnostics name it.
pub const RUN_SHARED: &str = "--shared-cache";

/// With shared caches on, reserve the [`guest_env`] variables, so an override cannot point
/// guest tools at another registry or at caches the proxy does not serve. Errors name the
/// variable's source (`what`) and the flag or config key that asked for the caches
/// (`asked_as`).
pub fn refuse_guest_env<'a>(
    aliases: &[String],
    names: impl IntoIterator<Item = &'a str>,
    what: &str,
    asked_as: &str,
) -> Result<()> {
    if aliases.is_empty() {
        return Ok(());
    }
    if let Some(name) = names.into_iter().find(|n| GUEST_ENV.contains(n)) {
        bail!(
            "{what} sets {name}, which {asked_as} sets for the guest: remove it there, or \
             drop the shared caches"
        );
    }
    Ok(())
}

/// Have `args`'s run serve the shared caches `aliases` names at `registry.vk` and advertise
/// them in the guest's environment, which [`refuse_guest_env`] checks first.
pub fn lend(
    args: &mut crate::run::RunArgs,
    aliases: &[String],
    asked_as: &'static str,
    what: &str,
) -> Result<()> {
    if aliases.is_empty() {
        return Ok(());
    }
    for alias in aliases {
        if let Err(why) = check_alias(alias) {
            bail!("{asked_as} {alias:?} {why}");
        }
    }
    refuse_guest_env(
        aliases,
        args.env.iter().map(|(name, _)| name.as_str()),
        what,
        asked_as,
    )?;
    let aliases = canonical(aliases);
    args.env.extend(guest_env(&aliases));
    args.registry_proxy = Some(crate::run::RegistryProxy::Areas { aliases, asked_as });
    Ok(())
}

/// Serve the store at `root` on the current runtime, for as long as it runs, and return the
/// proxy configuration that lends it within `aliases`' areas. The server listens on a
/// loopback port of its own behind a bearer token made here, which the proxy presents for
/// its guests: they never see it.
pub async fn serve(root: &Path, aliases: &[String]) -> Result<ProxyCfg> {
    if aliases.is_empty() {
        bail!("the shared cache store is served for at least one shared cache");
    }
    let token = token()?;
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .context("binding the shared cache")?;
    let addr = listener
        .local_addr()
        .context("reading the shared cache's address")?;
    // Built before anything is served, so a bad alias leaves no server behind.
    let areas: Vec<Area> = canonical(aliases).iter().map(|a| area(a)).collect();
    let cfg = ProxyCfg::for_areas(
        &format!("http://{addr}"),
        Creds {
            token: Some(token.clone()),
            ..Creds::anonymous()
        },
        &areas,
    )?;
    let state = Arc::new(state(root, token)?);
    tokio::spawn(async move {
        if let Err(e) = vk_registry::serve_unannounced_on(listener, state).await {
            eprintln!("virtkit: the shared cache stopped serving: {e:#}");
        }
    });
    Ok(cfg)
}

/// The server's state over the store at `root`, made if absent ([`open_store`]): WebDAV off
/// but the S3 view on, the store's locks shared with every process serving it, and the
/// enabled API to whoever presents `token` — the guests' proxy forwards far less
/// ([`crate::regproxy::Scope::Areas`]).
fn state(root: &Path, token: String) -> Result<vk_registry::ServerState> {
    let root = open_store(root, Missing::Create)?.context("the shared cache store was not made")?;
    let mut cfg =
        vk_registry::ServerConfig::local((std::net::Ipv4Addr::LOCALHOST, 0).into(), root.clone());
    // The S3 view writes WebDAV's plain files even with WebDAV, and so its listings and
    // namespace verbs, off.
    cfg.webdav = false;
    cfg.s3 = true;
    let mut state = cfg
        .into_state()
        .with_context(|| format!("opening the shared cache store {}", root.display()))?;
    state.auth = vk_registry::Authenticator::Shared(vk_registry::auth::Auth::Bearer { token });
    state.locks = vk_registry::lock::LockManager::host_shared(&root)
        .with_context(|| format!("sharing the locks of {}", root.display()))?;
    Ok(state)
}

/// What [`open_store`] does where there is no store.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    /// Make one, private to this user and marked as the shared cache store's.
    Create,
    /// Leave things as they are: `Ok(None)`.
    Leave,
}

/// The shared cache store at `root`, checked: a directory of this user's that no other user
/// can reach, not a symbolic link, and one `vk` made for the shared cache ([`MARKER`]).
/// Anything else is refused rather than served or collected: a directory open to others is
/// not the private store the guests are promised, a link may lead a sweep to another store,
/// and a store of something else — a build cache, say — would be read by digest through the
/// areas and have its tags expired as a task's.
///
/// Owner, mode and contents are read through one descriptor on the directory, so they are
/// one directory's. The store is then used by path, which only this user can point
/// elsewhere, the directory and everything in it being theirs alone.
pub fn open_store(root: &Path, missing: Missing) -> Result<Option<PathBuf>> {
    let at = root.display();
    if missing == Missing::Create {
        if let Some(parent) = root.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        match std::fs::DirBuilder::new().mode(0o700).create(root) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).with_context(|| format!("creating {at}")),
        }
    }
    let dir = match vk_fs::open_dir_nofollow(root) {
        Ok(dir) => dir,
        Err(e) => {
            return match std::fs::symlink_metadata(root) {
                Err(gone) if gone.kind() == std::io::ErrorKind::NotFound => match missing {
                    Missing::Leave => Ok(None),
                    Missing::Create => {
                        Err(e.context(format!("opening the shared cache store {at}")))
                    }
                },
                Ok(m) if m.file_type().is_symlink() => Err(anyhow::anyhow!(
                    "the shared cache store {at} is a symbolic link: remove the link, and `vk` \
                     makes a store there"
                )),
                Ok(m) if !m.is_dir() => Err(anyhow::anyhow!(
                    "the shared cache store {at} is not a directory: move it away, and `vk` \
                     makes a store there"
                )),
                _ => Err(e.context(format!("opening the shared cache store {at}"))),
            };
        }
    };
    // SAFETY: `stat` is plain old data, for which all-zero bytes are a valid value.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `dir` is open and `st` is a writable `stat`.
    if unsafe { libc::fstat(dir.as_raw_fd(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("reading the shared cache store {at}"));
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    if st.st_uid != unsafe { libc::geteuid() } {
        bail!(
            "the shared cache store {at} belongs to another user (uid {}): move it away, and \
             `vk` makes a store of your own there",
            st.st_uid
        );
    }
    if st.st_mode & 0o077 != 0 {
        bail!(
            "the shared cache store {at} is open to other users (mode {:04o}): `chmod 700` it \
             if you trust what it holds, or remove it",
            st.st_mode & 0o7777
        );
    }
    let names = vk_fs::dir_names(dir.as_fd())
        .with_context(|| format!("reading the shared cache store {at}"))?;
    if names.iter().any(|n| n == MARKER) {
        return Ok(Some(root.to_path_buf()));
    }
    if !names.is_empty() {
        bail!(
            "{at} is not a shared cache store `vk` made (it has no `{MARKER}` file) and is not \
             empty: move it away, and `vk` makes a store there"
        );
    }
    if missing == Missing::Leave {
        // Nothing in it to collect, and looking at a store is not what makes one.
        return Ok(None);
    }
    match vk_fs::create_file_in(dir.as_fd(), MARKER.as_ref(), 0o600) {
        Ok(mut f) => f
            .write_all(b"virtkit shared cache store\n")
            .with_context(|| format!("writing {at}/{MARKER}"))?,
        // Another run marked it meanwhile.
        Err(e)
            if e.root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists) => {}
        Err(e) => return Err(e.context(format!("writing {at}/{MARKER}"))),
    }
    Ok(Some(root.to_path_buf()))
}

/// Whether `dir` is the shared cache store's directory, reached by whatever path: a build
/// cache must never be kept there ([`open_store`]). A directory that does not exist yet is
/// not; a build cache made there later is refused as the store's when the store is opened.
pub fn is_store(dir: &Path) -> bool {
    let Ok(root) = store_root() else {
        return false;
    };
    match (std::fs::metadata(dir), std::fs::metadata(&root)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// 256 random bits in hex: never mistaken for a hub token, which starts with a prefix of
/// its own.
fn token() -> Result<String> {
    let mut token = String::with_capacity(64);
    for _ in 0..4 {
        token.push_str(&crate::scratch::random_nonce()?);
    }
    debug_assert!(!token.starts_with(vk_hub_proto::token::TOKEN_PREFIX));
    Ok(token)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn the_store_is_a_cache() {
        let homes = crate::dev::testutil::Homes::new("sharedcache-root");
        assert_eq!(
            store_root().unwrap(),
            homes.dir().join("XDG_CACHE_HOME/virtkit/shared-cache")
        );
    }

    #[test]
    fn a_run_lent_areas_serves_them_and_names_them_to_its_guest() {
        let lent = |aliases: &[&str], env: &[&str]| {
            let mut args = crate::run::RunArgs {
                env: env.iter().map(|n| (n.to_string(), "x".into())).collect(),
                ..Default::default()
            };
            let aliases: Vec<String> = aliases.iter().map(|a| a.to_string()).collect();
            lend(&mut args, &aliases, RUN_SHARED, "--env").map(|()| args)
        };
        // Without shared caches the caller owns the registry variables.
        let args = lent(&[], &["VK_REGISTRY"]).unwrap();
        assert_eq!(args.registry_proxy, None);
        assert_eq!(args.env.len(), 1);

        let args = lent(&["task-cache", "other", "task-cache"], &["X"]).unwrap();
        assert_eq!(
            args.registry_proxy,
            Some(crate::run::RegistryProxy::Areas {
                aliases: vec!["other".into(), "task-cache".into()],
                asked_as: RUN_SHARED,
            })
        );
        let names: Vec<&str> = args.env.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            [
                "X",
                "VK_REGISTRY",
                "VK_REGISTRY_CACHES",
                "VK_REGISTRY_AREAS"
            ]
        );

        let err = format!(
            "{:#}",
            lent(&["task-cache"], &["VK_REGISTRY_AREAS"]).err().unwrap()
        );
        assert!(
            err.contains("--env sets VK_REGISTRY_AREAS, which --shared-cache sets"),
            "{err}"
        );
        let err = format!(
            "{:#}",
            lent(&["task-cache"], &["VK_REGISTRY_CACHES"])
                .err()
                .unwrap()
        );
        assert!(
            err.contains("--env sets VK_REGISTRY_CACHES, which --shared-cache sets"),
            "{err}"
        );
        let err = format!("{:#}", lent(&["Bad"], &[]).err().unwrap());
        assert!(err.starts_with("--shared-cache \"Bad\" is not"), "{err}");
    }

    #[test]
    fn a_guest_is_told_of_its_shared_caches_in_one_order() {
        let told = |aliases: &[&str]| {
            guest_env(&aliases.iter().map(|a| a.to_string()).collect::<Vec<_>>())
        };
        let env = told(&["task-cache", "other", "task-cache"]);
        assert_eq!(
            env,
            [
                ("VK_REGISTRY".to_string(), "http://registry.vk".to_string()),
                (
                    "VK_REGISTRY_CACHES".to_string(),
                    "other=rwl task-cache=rwl".to_string()
                ),
                (
                    "VK_REGISTRY_AREAS".to_string(),
                    "other=rwl task-cache=rwl".to_string()
                ),
            ]
        );
        assert_eq!(told(&["other", "task-cache"]), env);
    }

    #[test]
    fn an_alias_names_a_prefix_the_registry_serves() {
        let longest = "a".repeat(MAX_PREFIX_LEN - AREA_ROOT.len() - 1);
        for good in ["task-cache", "a.b", "a__b", "a--b", "0", longest.as_str()] {
            assert_eq!(check_alias(good), Ok(()), "{good:?}");
        }
        let too_long = format!("{longest}a");
        for (bad, why) in [
            ("", "repository name component"),
            ("A", "repository name component"),
            ("a/b", "repository name component"),
            ("a b", "repository name component"),
            ("..", "repository name component"),
            ("tags", "keeps for its own layout"),
            ("blobs", "keeps for its own layout"),
            ("manifests", "keeps for its own layout"),
            (too_long.as_str(), "longer than 251 bytes"),
        ] {
            let err = check_alias(bad).unwrap_err();
            assert!(err.contains(why), "{bad:?}: {err}");
        }
    }

    fn mode_of(dir: &Path) -> u32 {
        std::fs::symlink_metadata(dir).unwrap().mode() & 0o7777
    }

    fn set_mode(dir: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// A store is made private and marked; looked at, an absent or empty one is left alone.
    #[test]
    fn a_store_is_made_private_and_marked() {
        let dir = crate::testtmp::Scratch::dir("sharedcache-made");
        let root = dir.join("parent/task-cache");
        assert_eq!(open_store(&root, Missing::Leave).unwrap(), None);
        assert!(!root.exists(), "looking makes nothing");
        std::fs::create_dir_all(&root).unwrap();
        set_mode(&root, 0o700);
        assert_eq!(open_store(&root, Missing::Leave).unwrap(), None);
        assert!(!root.join(MARKER).exists(), "looking marks nothing");

        assert_eq!(
            open_store(&root, Missing::Create).unwrap(),
            Some(root.clone())
        );
        assert!(root.join(MARKER).is_file());
        assert_eq!(
            open_store(&root, Missing::Leave).unwrap(),
            Some(root.clone())
        );
        let fresh = dir.join("fresh");
        assert_eq!(
            open_store(&fresh, Missing::Create).unwrap(),
            Some(fresh.clone())
        );
        assert_eq!(mode_of(&fresh), 0o700);
    }

    /// Whatever is at the store's place and is not a private store `vk` made is refused,
    /// to serve and to collect alike, and left as it is.
    #[test]
    fn anything_but_a_private_store_of_its_own_is_refused() {
        let dir = crate::testtmp::Scratch::dir("sharedcache-refused");
        let refused = |root: &Path, why: &str| {
            for missing in [Missing::Create, Missing::Leave] {
                let err = open_store(root, missing).unwrap_err();
                assert!(format!("{err:#}").contains(why), "{why}: {err:#}");
            }
        };

        // Open to other users, even one `vk` made.
        let open = dir.join("open");
        open_store(&open, Missing::Create).unwrap();
        for mode in [0o750, 0o705, 0o770] {
            set_mode(&open, mode);
            refused(&open, "open to other users");
            assert_eq!(mode_of(&open), mode, "the mode is left as it is");
        }

        // A link, even to a store `vk` made.
        let store = dir.join("store");
        open_store(&store, Missing::Create).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&store, &link).unwrap();
        refused(&link, "symbolic link");
        let dangling = dir.join("dangling");
        std::os::unix::fs::symlink(dir.join("nowhere"), &dangling).unwrap();
        refused(&dangling, "symbolic link");
        assert!(!dir.join("nowhere").exists());

        // Not a directory.
        let file = dir.join("file");
        std::fs::write(&file, b"").unwrap();
        refused(&file, "not a directory");

        // A store of something else: never adopted, never marked.
        let other = dir.join("other");
        vk_registry::Store::new(other.clone()).unwrap();
        set_mode(&other, 0o700);
        refused(&other, "not a shared cache store");
        assert!(!other.join(MARKER).exists());
    }

    /// The proxy reaches the store it serves itself directly, whatever HTTP proxy the
    /// environment names: the request carries the store's credential.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_http_proxy_stands_between_the_proxy_and_the_store() {
        const CHILD: &str = "VK_TEST_TASKCACHE_HTTP_PROXY";
        const NAME: &str =
            "sharedcache::tests::no_http_proxy_stands_between_the_proxy_and_the_store";
        let Some(dir) = crate::dev::testutil::child_marker(CHILD).map(PathBuf::from) else {
            let _guard = crate::dev::testutil::env_guard();
            let dir = crate::testtmp::Scratch::dir("sharedcache-http-proxy");
            // A proxy nothing listens on: a request sent to it fails.
            let nowhere = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let proxy = format!("http://{}", nowhere.local_addr().unwrap());
            drop(nowhere);
            let mut cmd = crate::dev::testutil::child_test(NAME);
            for var in ["NO_PROXY", "no_proxy", "REQUEST_METHOD"] {
                cmd.env_remove(var);
            }
            for var in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
                cmd.env(var, &proxy);
            }
            let output = cmd.env(CHILD, &*dir).output().unwrap();
            crate::dev::testutil::ran_alone(NAME, &output);
            return;
        };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let socket = crate::regproxy::spawn(
            serve(&dir.join("task-cache"), &["task-cache".into()])
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        let (status, ping) = ask(&socket, request("GET", "/v2/", "", "")).await;
        assert_eq!(status, 200, "{ping}");
    }

    /// Dial `socket` once and send `req`, an HTTP/1.1 request closing its connection; return
    /// the status and the whole response.
    pub(crate) async fn ask(socket: &crate::regproxy::ProxySocket, req: String) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut conn = crate::regproxy::connect(
            socket,
            crate::regproxy::euid(),
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap();
        conn.write_all(req.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        conn.read_to_end(&mut out).await.unwrap();
        let out = String::from_utf8_lossy(&out).into_owned();
        let status = out
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("no status in {out:?}"));
        (status, out)
    }

    pub(crate) fn request(method: &str, target: &str, headers: &str, body: &str) -> String {
        format!(
            "{method} {target} HTTP/1.1\r\nhost: registry.vk\r\nconnection: close\r\n\
             content-length: {}\r\n{headers}\r\n{body}",
            body.len()
        )
    }

    /// What a run with areas sets up, short of a guest: two of them over one store, each its
    /// own server and proxy. Through one, a task's output is pushed and tagged by the alias;
    /// through the other, both are read, a lock the first took is found taken, and no name
    /// outside the areas is reached.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_runs_share_the_store_and_its_locks() {
        use sha2::Digest;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = crate::testtmp::Scratch::dir("sharedcache-serve");
        let root = dir.join("task-cache");
        let aliases = ["task-cache".to_string()];
        let one = crate::regproxy::spawn(serve(&root, &aliases).await.unwrap())
            .await
            .unwrap();
        let two = crate::regproxy::spawn(serve(&root, &aliases).await.unwrap())
            .await
            .unwrap();
        assert_eq!(mode_of(&root), 0o700, "the store is this user's alone");
        assert!(
            root.join(MARKER).is_file(),
            "and marked as the shared cache store's"
        );

        let (status, ping) = ask(&one, request("GET", "/v2/", "", "")).await;
        assert_eq!(status, 200, "{ping}");

        let chunk = "a task's output";
        let digest: String = sha2::Sha256::digest(chunk.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let digest = format!("sha256:{digest}");
        let (status, started) = ask(
            &one,
            request("POST", "/v2/job/task-cache/ns/blobs/uploads/", "", ""),
        )
        .await;
        assert_eq!(status, 202, "{started}");
        let location = started
            .lines()
            .find_map(|l| {
                let (name, value) = l.split_once(':')?;
                name.eq_ignore_ascii_case("location")
                    .then(|| value.trim().to_string())
            })
            .expect("an upload has a location");
        assert!(
            location.starts_with("/v2/dev/task-cache/ns/blobs/uploads/"),
            "{location}"
        );
        let sep = if location.contains('?') { '&' } else { '?' };
        let (status, pushed) = ask(
            &one,
            request(
                "PUT",
                &format!("{location}{sep}digest={digest}"),
                "content-type: application/octet-stream\r\n",
                chunk,
            ),
        )
        .await;
        assert_eq!(status, 201, "{pushed}");

        const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": MANIFEST,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": digest, "size": chunk.len(),
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar",
                "digest": digest, "size": chunk.len(),
            }],
        })
        .to_string();
        let tag = "/v2/job/task-cache/ns/manifests/key";
        let (status, put) = ask(
            &one,
            request(
                "PUT",
                tag,
                &format!("content-type: {MANIFEST}\r\n"),
                &manifest,
            ),
        )
        .await;
        assert_eq!(status, 201, "{put}");

        // The other run's guest reads what the first one wrote.
        let (status, got) = ask(&two, request("GET", tag, "", "")).await;
        assert_eq!(status, 200, "{got}");
        assert!(got.contains(&manifest), "{got}");
        let blob = format!("/v2/job/task-cache/ns/blobs/{digest}");
        let (status, got) = ask(&two, request("GET", &blob, "", "")).await;
        assert_eq!(status, 200, "{got}");
        assert!(got.contains(chunk), "{got}");

        // A lock taken through one run is taken for the other too.
        let acquire = request(
            "POST",
            "/lock/acquire?name=job/task-cache/ns:key&ttl=30&wait=0",
            "x-vk-lock-holder: a guest\r\n",
            "",
        );
        let (status, taken) = ask(&one, acquire.clone()).await;
        assert_eq!(status, 200, "{taken}");
        assert!(taken.contains("dev/task-cache/ns:key"), "{taken}");
        let (status, busy) = ask(&two, acquire).await;
        assert_eq!(status, 409, "{busy}");

        // Neither reaches a name outside its areas, nor the plain files.
        for (method, target) in [
            ("GET", "/v2/other/manifests/key".to_string()),
            ("GET", format!("/v2/other/blobs/{digest}")),
            ("POST", "/lock/acquire?name=other:key".to_string()),
            ("GET", "/dav/files/dev/task-cache/".to_string()),
        ] {
            let (status, refused) = ask(&two, request(method, &target, "", "")).await;
            assert_eq!(status, 403, "{method} {target}: {refused}");
        }
    }

    /// sccache's S3 requests reach an area's plain files by the alias a CI job uses: its
    /// startup probe and a sharded key are written, read and stated as tags under the area's
    /// prefix, and a missing key is `NoSuchKey`. Unconfigured areas, listings, multipart
    /// uploads, deletes and direct WebDAV access are refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sccache_reaches_an_areas_objects_over_s3() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = crate::testtmp::Scratch::dir("sharedcache-s3");
        let root = dir.join("task-cache");
        let aliases = ["sccache".to_string(), "task-cache".to_string()];
        let proxy = crate::regproxy::spawn(serve(&root, &aliases).await.unwrap())
            .await
            .unwrap();
        // An unsigned request may carry the UNSIGNED-PAYLOAD marker and a date, which the
        // proxy passes on.
        let amz = "x-amz-content-sha256: UNSIGNED-PAYLOAD\r\nx-amz-date: 20261125T000000Z\r\n";
        for (key, body) in [
            (".sccache_check", "Hello, World!"),
            ("a/b/c/0123abcd", "obj"),
        ] {
            let target = format!("/s3/job/sccache/{key}");
            let (status, put) = ask(&proxy, request("PUT", &target, amz, body)).await;
            assert_eq!(status, 200, "{put}");
            let (status, got) = ask(&proxy, request("GET", &target, amz, "")).await;
            assert_eq!(status, 200, "{got}");
            assert!(got.contains(body), "{got}");
            let (status, head) = ask(&proxy, request("HEAD", &target, "", "")).await;
            assert_eq!(status, 200, "{head}");
        }
        let (status, miss) = ask(&proxy, request("GET", "/s3/job/sccache/a/b/c/ff", "", "")).await;
        assert_eq!(status, 404, "{miss}");
        assert!(miss.contains("NoSuchKey"), "{miss}");
        for (repo, tag) in [
            ("dev/sccache", ".sccache_check"),
            ("dev/sccache/a/b/c", "0123abcd"),
        ] {
            let file = root.join("repos/files").join(repo).join("tags").join(tag);
            assert!(file.is_file(), "{}", file.display());
        }

        for (method, target) in [
            ("GET", "/s3/job/other/x"),
            ("GET", "/s3/dev/other/x"),
            ("PUT", "/s3/dev/x"),
            ("GET", "/s3/job/sccache/?list-type=2"),
            ("POST", "/s3/job/sccache/x?uploads"),
            ("DELETE", "/s3/job/sccache/.sccache_check"),
            ("GET", "/dav/files/dev/sccache/.sccache_check"),
        ] {
            let (status, refused) = ask(&proxy, request(method, target, "", "")).await;
            assert_eq!(status, 403, "{method} {target}: {refused}");
        }
    }

    #[tokio::test]
    async fn a_bad_alias_serves_nothing() {
        let dir = crate::testtmp::Scratch::dir("sharedcache-bad-alias");
        let root = dir.join("task-cache");
        assert!(serve(&root, &[]).await.is_err());
        let err = serve(&root, &["a/b".to_string()]).await.err().unwrap();
        assert!(format!("{err:#}").contains("a/b"), "{err:#}");
        assert!(!root.exists(), "no store is made for a refused run");
    }
}
