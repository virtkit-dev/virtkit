//! Server configuration: listen address, store root, relay upstreams, TLS, and client
//! auth.
//!
//! The listen address and store root usually come from the CLI; the TOML config file
//! carries the relay `[[upstream]]` entries, the TLS cert/key, and the client-auth model
//! — `mode` plus either the shared-secret credentials or `accounts_db` (and may name
//! addr/root, for the flags that were not passed). No upstreams ⇒ a plain local registry;
//! no TLS ⇒ plain HTTP; no auth ⇒ open. A central, network-exposed deployment sets all
//! three.

use std::fs::File;
use std::io::{BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tokio_rustls::TlsAcceptor;

use crate::accounts;
use crate::auth::Auth;
use crate::lock::LockManager;
use crate::oidc::{OidcClient, OidcConfig};
use crate::relay::Upstream;
use crate::{ServerState, Store};

mod help;
pub use help::config_file_help;

/// The client-auth model for the whole server — mutually exclusive, chosen once at
/// startup. See `DESIGN.md`'s "Accounts, OIDC, and scoped API keys".
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub enum AuthMode {
    /// One shared secret for every client (`token_file`/`username`+`password_file`),
    /// or none — today's model.
    #[default]
    SharedSecret,
    /// Per-user OIDC sessions + per-key scoped API keys, backed by an `accounts::Db`.
    Accounts,
}

/// Whether and where `serve` binds the accounts admin socket — the local operator
/// channel the `vk-registry accounts` CLI uses so it does not need the db to itself.
/// Only accounts mode has one; see `DESIGN.md`'s "the operator CLI".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AdminSocket {
    /// Nothing was said about it: `admin.sock` beside the accounts db in accounts mode, and
    /// nothing at all in shared-secret mode (there are no accounts to administer). Distinct
    /// from [`AdminSocket::Default`] only so that a file naming *any* of the three
    /// spellings outside accounts mode is refused the same way, rather than `true` alone
    /// being silently ignored.
    #[default]
    Unset,
    /// `true`: the default path, stated.
    Default,
    /// Bind nothing. The CLI then works only with the server stopped, as it once always
    /// did.
    Off,
    /// A path the operator named, rather than the one beside the db.
    At(PathBuf),
}

/// Resolved server configuration, ready to turn into a [`ServerState`] (+ a TLS acceptor).
pub struct ServerConfig {
    pub addr: SocketAddr,
    pub root: PathBuf,
    pub upstreams: Vec<UpstreamSpec>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// Static bearer token file; when set, clients authenticate with it.
    pub token_file: Option<PathBuf>,
    /// HTTP Basic username (+ `password_file`); an alternative to `token_file`.
    pub username: Option<String>,
    pub password_file: Option<PathBuf>,
    pub mode: AuthMode,
    /// Where the accounts db lives, in `mode = "accounts"`. Defaults to
    /// `<root>/accounts/accounts.db` when unset.
    pub accounts_db: Option<PathBuf>,
    /// Whether `serve` also listens on the accounts admin socket, in `mode = "accounts"`.
    pub admin_socket: AdminSocket,
    /// `[oidc]`, required in `mode = "accounts"` — it is the only login path that mode
    /// has.
    pub oidc: Option<OidcSpec>,
}

/// The `[oidc]` config table, as declared (before its client secret is read and checked
/// by [`ServerConfig::resolve_oidc`]).
pub struct OidcSpec {
    pub issuer: String,
    pub client_id: String,
    pub client_secret_file: PathBuf,
    pub public_url: String,
}

/// What a config file states about the server it would start, as stated — see
/// [`ServerConfig::file_view`].
pub struct FileView {
    /// the address it sets, if it sets one
    pub addr: Option<SocketAddr>,
    /// the store it names, if it names one
    pub root: Option<PathBuf>,
    /// whether it turns TLS on (both `tls_cert` and `tls_key`)
    pub tls: bool,
}

/// One upstream, as declared in the config file (before its HTTP client is built).
pub struct UpstreamSpec {
    pub prefix: String,
    pub url: String,
    pub username: Option<String>,
    pub password_file: Option<PathBuf>,
    pub ca_file: Option<PathBuf>,
}

/// `deny_unknown_fields` is load-bearing, not tidiness: `mode` selects the auth model,
/// so a misspelt or misplaced key (`[auth] mode = ...`, say) silently starting the server
/// in shared-secret mode would hand the operator the very auth they believed they had
/// replaced. An unknown key is an error instead.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    addr: Option<String>,
    root: Option<PathBuf>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    token_file: Option<PathBuf>,
    username: Option<String>,
    password_file: Option<PathBuf>,
    /// `"shared-secret"` (default) or `"accounts"` — a top-level key, like the
    /// credentials it chooses between.
    mode: Option<String>,
    accounts_db: Option<PathBuf>,
    /// `false` to bind no admin socket, a path to move it, `true` for the default one.
    admin_socket: Option<FileAdminSocket>,
    oidc: Option<FileOidc>,
    #[serde(default)]
    upstream: Vec<FileUpstream>,
}

/// What `admin_socket` accepts: a bool (`false` = bind none, `true` = the default path)
/// or a path. Untagged, and the bool first, so `admin_socket = false` reads as the switch
/// it looks like rather than failing as a path.
#[derive(Deserialize)]
#[serde(untagged)]
enum FileAdminSocket {
    Enabled(bool),
    Path(PathBuf),
}

/// `deny_unknown_fields` for the same reason `FileConfig` has it: this table configures
/// who may sign in, and a key silently dropped for a typo is not a diagnostic anyone gets.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileOidc {
    issuer: String,
    client_id: String,
    client_secret_file: PathBuf,
    public_url: String,
}

/// `deny_unknown_fields` here for the same reason as on [`FileConfig`], applied to the
/// same kind of mistake: a misspelt `username`/`password_file` would leave the relay
/// fetching from the upstream unauthenticated rather than say so.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileUpstream {
    /// repo-name prefix selecting this upstream; omitted/empty = catch-all
    #[serde(default)]
    prefix: String,
    url: String,
    username: Option<String>,
    password_file: Option<PathBuf>,
    ca_file: Option<PathBuf>,
}

/// Ceiling on the `[oidc]` client-secret file, trailing newline included — it is checked
/// against the bytes on disk, before the value is trimmed.
const MAX_CLIENT_SECRET_LEN: u64 = 4096;

/// The accounts db under a store root, when no `accounts_db` names one. A directory of
/// its own rather than the root itself: `Db::open` creates that one at 0700 whatever the
/// umask, whereas `Store::new` makes the root with `create_dir_all` and so leaves its mode
/// to the ambient umask — and a root a group member can write to lets them rename the db
/// aside and plant one naming themselves admin, `0600` on the file notwithstanding.
///
/// The single source of the default: `into_state` opens the db here, and the `vk-registry
/// accounts` CLI finds it here, so the two cannot drift onto different files.
pub fn default_accounts_db(root: &Path) -> PathBuf {
    root.join("accounts").join("accounts.db")
}

/// The admin socket beside an accounts db, in the db's own directory: filesystem access to
/// the socket is then the same access to the db the `vk-registry accounts` CLI has always
/// assumed, and one `0700` covers both wherever [`accounts::Db::open`] was the one that
/// created the directory. It is not where the socket's privacy comes from — see
/// [`admin::bind`](crate::admin::bind) and the peer-uid check on the other side of it — but
/// it is the placement that needs no extra configuration to be right.
pub fn default_admin_socket(accounts_db: &Path) -> PathBuf {
    // `parent()` is `Some("")` for a bare filename and `None` only for `/` and `""`; both
    // land on a socket the cwd resolves, which is where such a db file is too.
    accounts_db
        .parent()
        .unwrap_or(Path::new(""))
        .join("admin.sock")
}

/// Where the server listens when neither a flag nor a config file names an address.
/// Loopback: a store served to the world is a deliberate act, not a default.
pub const DEFAULT_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);

impl ServerConfig {
    /// A plain local registry: no upstreams, no TLS, no auth.
    pub fn local(addr: SocketAddr, root: PathBuf) -> Self {
        ServerConfig {
            addr,
            root,
            upstreams: Vec::new(),
            tls_cert: None,
            tls_key: None,
            token_file: None,
            username: None,
            password_file: None,
            mode: AuthMode::SharedSecret,
            accounts_db: None,
            admin_socket: AdminSocket::Unset,
            oidc: None,
        }
    }

    /// The store root alone, for the commands that operate on a store without serving it
    /// (`status`, `gc`). The root is resolved in [`ServerConfig::load`]'s order — an
    /// explicit `--root` first (for the `accounts` CLI, the flag or `VK_REGISTRY_ROOT`), then
    /// the config file's, then the shared default — so a store configured for the server is
    /// the one they report on and sweep, instead of a default store the server never touches.
    /// Only the root is taken: a file whose `addr`/TLS/auth keys `serve` would reject still
    /// answers where the store is.
    pub fn root_of(config: Option<&Path>, root: Option<PathBuf>) -> Result<PathBuf> {
        if let Some(r) = root {
            return Ok(r);
        }
        if let Some(path) = config
            && let Some(r) = read_file(path)?.root
        {
            return Ok(r);
        }
        crate::default_root()
    }

    /// Where the accounts db lives, resolved the same way [`ServerConfig::into_state`]
    /// would: an explicit `--accounts-db` first, then the config file's, else
    /// [`default_accounts_db`] under the resolved store root. For the `vk-registry
    /// accounts` CLI, which reads that db directly rather than through a running
    /// server — this is how it finds the same one `serve` would open.
    pub fn accounts_db_of(
        config: Option<&Path>,
        root: Option<PathBuf>,
        accounts_db: Option<PathBuf>,
    ) -> Result<PathBuf> {
        if let Some(p) = accounts_db {
            return Ok(p);
        }
        if let Some(path) = config
            && let Some(p) = read_file(path)?.accounts_db
        {
            return Ok(p);
        }
        Ok(default_accounts_db(&Self::root_of(config, root)?))
    }

    /// Where the admin socket of a server holding `accounts_db` is: an explicit
    /// `--admin-socket` overrides everything, otherwise the config file's `admin_socket`,
    /// else [`default_admin_socket`] beside `accounts_db` — which is what
    /// [`ServerConfig::resolved_admin_socket`] binds for the server. `None` when the file
    /// turns it off, and `None` outside accounts mode, where `serve` binds none whatever
    /// else the file says. (There is no server-side `--admin-socket`; that arm is a CLI
    /// override with nothing to mirror.)
    ///
    /// For the `vk-registry accounts` CLI. It takes the db already resolved — the same
    /// [`ServerConfig::accounts_db_of`] path it would open directly — rather than resolving
    /// one of its own, so the socket it dials cannot end up belonging to a different db than
    /// the one it would have read. A path it returns is where a socket *would* be; whether
    /// one is listening there is what connecting to it answers.
    pub fn admin_socket_of(
        config: Option<&Path>,
        accounts_db: &Path,
        admin_socket: Option<PathBuf>,
    ) -> Result<Option<PathBuf>> {
        if let Some(p) = admin_socket {
            return Ok(Some(p));
        }
        if let Some(path) = config {
            let f = read_file(path)?;
            // `serve` binds none outside accounts mode whatever else the file says, so a
            // CLI that resolved one here would probe a path nothing can ever answer at.
            if f.mode.as_deref() != Some("accounts") {
                return Ok(None);
            }
            match f.admin_socket {
                Some(FileAdminSocket::Enabled(false)) => return Ok(None),
                Some(FileAdminSocket::Path(p)) => return Ok(Some(p)),
                None | Some(FileAdminSocket::Enabled(true)) => {}
            }
        }
        Ok(Some(default_admin_socket(accounts_db)))
    }

    /// The accounts db this configuration's `serve` opens. The one resolution of it, because
    /// the admin socket sits beside the db the server actually holds — two copies of this
    /// rule could drift apart and put the socket next to a db nobody opened.
    pub fn resolved_accounts_db(&self) -> PathBuf {
        self.accounts_db
            .clone()
            .unwrap_or_else(|| default_accounts_db(&self.root))
    }

    /// The socket this configuration's `serve` binds: `None` outside accounts mode (there
    /// are no accounts to administer) and `None` when the operator turned it off.
    pub fn resolved_admin_socket(&self) -> Option<PathBuf> {
        if self.mode != AuthMode::Accounts {
            return None;
        }
        match &self.admin_socket {
            AdminSocket::Off => None,
            AdminSocket::Unset | AdminSocket::Default => {
                Some(default_admin_socket(&self.resolved_accounts_db()))
            }
            AdminSocket::At(p) => Some(p.clone()),
        }
    }

    /// What a `serve` config file states, for whoever has to describe the server it will
    /// start without starting one — `install-service`, building a unit around it. `None`
    /// where the file says nothing, so a caller can tell a setting it named from a default
    /// standing in for it, which [`ServerConfig::load`] deliberately cannot.
    ///
    /// One read, so an address and a store taken from the same file are taken from the same
    /// contents of it.
    pub fn file_view(path: &Path) -> Result<FileView> {
        let f = read_file(path)?;
        Ok(FileView {
            addr: parse_addr(f.addr)?,
            root: f.root,
            // Both keys, the pair `build_tls` insists on: a half-configured one is `serve`'s
            // error to raise, not this caller's.
            tls: f.tls_cert.is_some() && f.tls_key.is_some(),
        })
    }

    /// Load from a TOML file. An explicitly passed `addr`/`root` outranks the file's; the
    /// address falls back to [`DEFAULT_ADDR`] and the store root to the shared default when
    /// neither names one.
    pub fn load(path: &Path, addr: Option<SocketAddr>, root: Option<PathBuf>) -> Result<Self> {
        let f = read_file(path)?;
        // Parsed even when a flag outranks it: a typo in the key is worth an error rather
        // than silence, and the caller may have passed no flag on the next run.
        let file_addr = parse_addr(f.addr)?;
        let addr = addr.or(file_addr).unwrap_or(DEFAULT_ADDR);
        let root = match root.or(f.root) {
            Some(r) => r,
            None => crate::default_root()?,
        };
        let upstreams = f
            .upstream
            .into_iter()
            .map(|u| UpstreamSpec {
                prefix: u.prefix,
                url: u.url.trim_end_matches('/').to_string(),
                username: u.username,
                password_file: u.password_file,
                ca_file: u.ca_file,
            })
            .collect();
        let mode = match f.mode.as_deref() {
            None | Some("shared-secret") => AuthMode::SharedSecret,
            Some("accounts") => AuthMode::Accounts,
            Some(other) => {
                bail!("unknown auth mode {other:?} (expected \"shared-secret\" or \"accounts\")")
            }
        };
        let cfg = ServerConfig {
            addr,
            root,
            upstreams,
            tls_cert: f.tls_cert,
            tls_key: f.tls_key,
            token_file: f.token_file,
            username: f.username,
            password_file: f.password_file,
            mode,
            accounts_db: f.accounts_db,
            admin_socket: match f.admin_socket {
                None => AdminSocket::Unset,
                Some(FileAdminSocket::Enabled(true)) => AdminSocket::Default,
                Some(FileAdminSocket::Enabled(false)) => AdminSocket::Off,
                Some(FileAdminSocket::Path(p)) => AdminSocket::At(p),
            },
            oidc: f.oidc.map(|o| OidcSpec {
                issuer: o.issuer,
                client_id: o.client_id,
                client_secret_file: o.client_secret_file,
                public_url: o.public_url,
            }),
        };
        // Also here, not only in `build_auth`: `load` is where a file becomes a config, so
        // a contradictory file is refused by parsing it at all, not only by the path that
        // goes on to build the auth scheme. The serve path does both, so no message an
        // operator sees moves — what it buys is a file settled by `load` alone, as the
        // help examples' test does.
        cfg.check_auth_exclusions()?;
        Ok(cfg)
    }

    /// The auth keys that cannot be combined, refused before anything they name is read —
    /// so this is also what a config file can be checked against without the files, the
    /// store, or a listening socket existing.
    ///
    /// Every case is a silent auth *downgrade* if it is allowed through: a server that
    /// ignores half of what the operator configured is a server authenticating callers
    /// some other way than they believe.
    fn check_auth_exclusions(&self) -> Result<()> {
        if self.token_file.is_some() && self.username.as_ref().is_some_and(|u| !u.is_empty()) {
            bail!(
                "configure either token_file or username/password_file for client auth, not both"
            );
        }
        if self.mode == AuthMode::Accounts
            && (self.token_file.is_some()
                || self.password_file.is_some()
                || self.username.as_ref().is_some_and(|u| !u.is_empty()))
        {
            bail!(
                "mode = \"accounts\" is mutually exclusive with \
                 token_file/username/password_file — configure accounts_db instead"
            );
        }
        if self.mode == AuthMode::SharedSecret && self.oidc.is_some() {
            // The mirror image of the refusal above: silently ignoring a table the
            // operator wrote is how a server ends up in the mode they meant to replace.
            bail!("an [oidc] table needs mode = \"accounts\"; it is ignored otherwise");
        }
        // The more dangerous direction: nothing reads `accounts_db` in shared-secret mode,
        // so a file that configures one with `mode` forgotten would start wide open — the
        // same silent downgrade `deny_unknown_fields` exists to prevent, reached through a
        // key spelt right.
        if self.accounts_db.is_some() && self.mode != AuthMode::Accounts {
            bail!("accounts_db is set but mode is not \"accounts\", so it would be ignored");
        }
        // Same reasoning, one step milder: there is nothing to administer without an
        // accounts db, so a file that names the socket with `mode` forgotten has an
        // operator expecting a channel that would never be bound.
        if self.admin_socket != AdminSocket::Unset && self.mode != AuthMode::Accounts {
            bail!("admin_socket is set but mode is not \"accounts\", so it would be ignored");
        }
        Ok(())
    }

    /// Auth over plain HTTP on a routable address would put the bearer token / Basic
    /// password (or, in accounts mode, a session cookie / API key) on the wire in
    /// cleartext; refuse it rather than silently expose creds. Split out of
    /// [`ServerConfig::into_state`] for the same reason as [`Self::check_auth_exclusions`]:
    /// a config file can then be held to it without a store or a listening socket.
    fn check_no_cleartext_creds(&self) -> Result<()> {
        // The same condition `build_auth` selects a scheme on, without reading the files
        // it names — so no caller has to restate it to ask this question.
        let creds_in_play = self.token_file.is_some()
            || self.username.as_ref().is_some_and(|u| !u.is_empty())
            || self.mode == AuthMode::Accounts;
        if creds_in_play && self.tls_cert.is_none() && !self.addr.ip().is_loopback() {
            bail!(
                "client auth is enabled without TLS on non-loopback address {} — credentials \
                 would be sent in cleartext; set tls_cert/tls_key or bind a loopback address",
                self.addr
            );
        }
        Ok(())
    }

    /// Build the TLS acceptor from the configured cert/key, or `None` for plain HTTP.
    /// The two must be set together.
    pub fn build_tls(&self) -> Result<Option<TlsAcceptor>> {
        let (cert, key) = match (&self.tls_cert, &self.tls_key) {
            (Some(c), Some(k)) => (c, k),
            (None, None) => return Ok(None),
            _ => bail!("tls_cert and tls_key must be set together"),
        };
        let certs = load_certs(cert)?;
        let key = load_key(key)?;
        let mut sc = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("building the TLS server config")?;
        sc.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Some(TlsAcceptor::from(Arc::new(sc))))
    }

    /// The `[oidc]` table, resolved and checked, or `None` in shared-secret mode. Every
    /// endpoint the login flow uses comes out of the provider's discovery document, and
    /// the issuer is what says which document to trust — so it is checked here, before
    /// anything is opened or created.
    fn resolve_oidc(&self) -> Result<Option<OidcConfig>> {
        if self.mode == AuthMode::SharedSecret {
            // An `[oidc]` table here is refused by `check_auth_exclusions`, so shared-secret
            // mode simply has no provider.
            return Ok(None);
        }
        let spec = self
            .oidc
            .as_ref()
            .context("mode = \"accounts\" requires an [oidc] table naming the login provider")?;
        for (what, url) in [("issuer", &spec.issuer), ("public_url", &spec.public_url)] {
            // Both end up in a URL this server fetches or hands a browser as a `Location`,
            // and the issuer is also the identity namespace `validate_identity` refuses
            // control characters in — so they are refused here, at startup, rather than
            // as a 502 at the first login. `oidc::is_usable_endpoint` holds the endpoints
            // a discovery document names to the same two conditions.
            if url.chars().any(char::is_control) {
                bail!("[oidc] {what} may not contain control characters: {url:?}");
            }
            if !url.starts_with("https://") && !is_local_url(url) {
                bail!(
                    "[oidc] {what} must be https (or a loopback address): {url:?} would put \
                     the client secret and the session cookie on the wire in cleartext"
                );
            }
            if url.contains('?') || url.contains('#') {
                bail!("[oidc] {what} is a base URL, with no query or fragment: {url:?}");
            }
        }
        if spec.client_id.is_empty() {
            bail!("[oidc] client_id may not be empty");
        }
        // Open once, then check the mode of *that* descriptor: `warn_if_mode` would
        // resolve the path a second time, so the file it reported on need not be the one
        // read below. `O_NOFOLLOW` for the same reason `accounts::Db::open` uses it — a
        // credential is not read through someone else's symlink.
        let secret_file = {
            let mut opts = std::fs::OpenOptions::new();
            opts.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.custom_flags(libc::O_NOFOLLOW);
            }
            opts.open(&spec.client_secret_file)
                .with_context(|| format!("opening {}", spec.client_secret_file.display()))?
        };
        crate::warn_if_file_mode(
            &secret_file,
            &spec.client_secret_file,
            0o077,
            "OIDC client secret",
            "it is group/world-accessible — restrict it to 0600",
        );
        // Bounded: a client secret is tens of bytes, and a `client_secret_file` that is
        // not one at all (a device, a log) must not be read into memory unbounded. One
        // byte over the cap is an error rather than a silent truncation, which would
        // otherwise show up as an unexplained rejection at the token endpoint. Read as
        // bytes and length-checked before the UTF-8 decode, so an oversize file is
        // reported as oversize rather than as a decode failure at a cut codepoint.
        let mut raw = Vec::new();
        secret_file
            .take(MAX_CLIENT_SECRET_LEN + 1)
            .read_to_end(&mut raw)
            .with_context(|| format!("reading {}", spec.client_secret_file.display()))?;
        if raw.len() as u64 > MAX_CLIENT_SECRET_LEN {
            bail!(
                "{} is over {MAX_CLIENT_SECRET_LEN} bytes; that is not a client secret",
                spec.client_secret_file.display()
            );
        }
        let client_secret = std::str::from_utf8(&raw)
            .with_context(|| format!("{} is not text", spec.client_secret_file.display()))?
            .trim()
            .to_string();
        if client_secret.is_empty() {
            bail!("{} is empty", spec.client_secret_file.display());
        }
        Ok(Some(OidcConfig {
            issuer: spec.issuer.trim_end_matches('/').to_string(),
            client_id: spec.client_id.clone(),
            client_secret,
            public_url: spec.public_url.trim_end_matches('/').to_string(),
        }))
    }

    /// The client-auth scheme: a bearer token file takes precedence, else Basic from a
    /// username + password file, else open. `mode = "accounts"` replaces this scheme
    /// entirely (see `route`'s auth gate), so it is an error to also configure one.
    fn build_auth(&self) -> Result<Auth> {
        // Also checked at `load`, and still checked here: a `ServerConfig` can be built
        // in code as well as parsed, and this is the point where ignoring one of these
        // keys would actually happen.
        self.check_auth_exclusions()?;
        if let Some(tf) = &self.token_file {
            let token = std::fs::read_to_string(tf)
                .with_context(|| format!("reading {}", tf.display()))?
                .trim()
                .to_string();
            if token.is_empty() {
                bail!("token file {} is empty", tf.display());
            }
            return Ok(Auth::Bearer { token });
        }
        if let Some(user) = self.username.as_ref().filter(|u| !u.is_empty()) {
            let pf = self
                .password_file
                .as_ref()
                .context("username set but no password_file")?;
            let pass = std::fs::read_to_string(pf)
                .with_context(|| format!("reading {}", pf.display()))?
                .trim_end()
                .to_string();
            return Ok(Auth::Basic {
                user: user.clone(),
                pass,
            });
        }
        Ok(Auth::None)
    }

    /// Build the shared runtime state: open the store, build each upstream's HTTP client
    /// (reading its password file), the lock manager, and the auth scheme (or the
    /// accounts db + the OIDC client, in `mode = "accounts"`). TLS is set separately by
    /// the serve path.
    ///
    /// Nothing here touches the network: the OIDC provider is discovered lazily, at the
    /// first login, so a provider that is briefly unreachable cannot stop a server whose
    /// `/v2/` clients never touch OIDC from starting at all.
    pub fn into_state(self) -> Result<ServerState> {
        let auth = self.build_auth()?;
        self.check_no_cleartext_creds()?;
        // Everything the config can be wrong about is settled before anything is created:
        // a server that is going to refuse to start should not leave a db file behind.
        let oidc_cfg = self.resolve_oidc()?;
        // `Store::new` first: the store owns the root, so it is the one that gets to
        // create it — `Db::open` would otherwise bring it into being as a side effect of
        // making room for the db file under it.
        let db_path = self.resolved_accounts_db();
        let store = Arc::new(Store::new(self.root)?);
        // `resolve_oidc` yields `Some` exactly in accounts mode, so it selects the arm as
        // well as supplying the provider.
        let auth = match oidc_cfg {
            None => crate::Authenticator::Shared(auth),
            Some(cfg) => crate::Authenticator::Accounts {
                db: Arc::new(accounts::Db::open(&db_path)?),
                oidc: Arc::new(OidcClient::new(cfg)),
            },
        };
        let upstreams = self
            .upstreams
            .into_iter()
            .map(UpstreamSpec::build)
            .collect::<Result<Vec<_>>>()?;
        Ok(ServerState {
            store,
            upstreams,
            locks: LockManager::new(),
            auth,
            tls: None,
        })
    }
}

impl UpstreamSpec {
    fn build(self) -> Result<Upstream> {
        let mut b = reqwest::Client::builder();
        if let Some(ca) = &self.ca_file {
            let pem = std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?;
            b = b.add_root_certificate(
                reqwest::Certificate::from_pem(&pem).context("parsing an upstream CA")?,
            );
        }
        let client = b.build().context("building an upstream HTTP client")?;
        let password = match &self.password_file {
            Some(p) => Some(
                std::fs::read_to_string(p)
                    .with_context(|| format!("reading {}", p.display()))?
                    .trim_end()
                    .to_string(),
            ),
            None => None,
        };
        Ok(Upstream {
            prefix: self.prefix,
            base: self.url,
            username: self.username.filter(|u| !u.is_empty()),
            password,
            client,
        })
    }
}

/// The `addr` key of a config file, parsed. Shared by [`ServerConfig::load`] and
/// [`ServerConfig::file_view`], so a bad address reads the same whichever asks.
fn parse_addr(addr: Option<String>) -> Result<Option<SocketAddr>> {
    addr.map(|a| a.parse().with_context(|| format!("parsing addr {a:?}")))
        .transpose()
}

/// Read + parse a config file, named in the error whichever way it fails. Shared by
/// [`ServerConfig::load`] and [`ServerConfig::root_of`], so `serve` and the store commands
/// read the same file the same way.
fn read_file(path: &Path) -> Result<FileConfig> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// True for an `http://` URL whose host is loopback: plain HTTP does not leave the
/// machine there, so it is the one case this config accepts without TLS.
pub(crate) fn is_local_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // `http://[::1]@evil.example/` has host `evil.example`, not `::1`: a guard that can be
    // fooled by its own parsing is worse than none, so userinfo is simply refused.
    if authority.contains('@') {
        return false;
    }
    // A bracketed IPv6 literal keeps its colons; everything else splits on the port's.
    let host = match authority.strip_prefix('[') {
        // …and it must actually end at the bracket, with only a port after it.
        Some(v6) => match v6.split_once(']') {
            Some((host, after)) if after.is_empty() || after.starts_with(':') => host,
            _ => return false,
        },
        None => authority.split(':').next().unwrap_or(""),
    };
    host == "localhost" || host == "127.0.0.1" || host == "::1"
}

fn load_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let mut r =
        BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::CertificateDer::pem_reader_iter(&mut r)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("reading certificates from {}", path.display()))
}

fn load_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    crate::warn_if_file_mode(
        &file,
        path,
        0o077,
        "TLS private key",
        "it is group/world-accessible — restrict it to 0600",
    );
    let mut r = BufReader::new(file);
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::PrivateKeyDer::from_pem_reader(&mut r)
        .with_context(|| format!("reading a private key from {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a config file states, for a unit built around it: the address and store it
    /// names, and whether it turns TLS on. `None` where it says nothing, which is the part
    /// `load` cannot report — it substitutes the shared default and the caller can no longer
    /// tell the two apart.
    #[test]
    fn a_file_view_reports_what_the_file_states_and_what_it_leaves_open() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-view-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let write = |name: &str, body: &str| {
            let p = dir.join(name);
            std::fs::write(&p, body).unwrap();
            p
        };

        let tls = write(
            "tls.toml",
            "addr = \"0.0.0.0:443\"\ntls_cert = \"/c.pem\"\ntls_key = \"/k.pem\"\n",
        );
        let v = ServerConfig::file_view(&tls).unwrap();
        assert_eq!(v.addr, Some("0.0.0.0:443".parse().unwrap()));
        assert_eq!(v.root, None);
        assert!(v.tls);
        // and it agrees with the address `serve` itself will listen on
        assert_eq!(
            ServerConfig::load(&tls, None, None).unwrap().addr,
            v.addr.unwrap()
        );

        // a file that states neither: the view says so, where `load` would hand back the
        // built-in address and the shared default store as if the file had named them
        let bare = write("bare.toml", "username = \"ci\"\n");
        let v = ServerConfig::file_view(&bare).unwrap();
        assert_eq!((v.addr, v.root, v.tls), (None, None, false));
        assert_eq!(
            ServerConfig::load(&bare, None, None).unwrap().addr,
            DEFAULT_ADDR
        );

        // one TLS key without the other is not TLS here: `serve` is what refuses the pair,
        // so describing a unit must not be the thing that fails on it
        let half = write("half.toml", "tls_cert = \"/c.pem\"\n");
        assert!(!ServerConfig::file_view(&half).unwrap().tls);
        assert!(
            ServerConfig::load(&half, None, None)
                .unwrap()
                .build_tls()
                .is_err()
        );

        // an unreadable file is an error, not an empty view
        assert!(ServerConfig::file_view(&dir.join("absent.toml")).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An address passed on the command line outranks the config file's, the order
    /// `--root` already followed: the file is the standing configuration, a flag is this
    /// run's override of it.
    #[test]
    fn an_explicit_addr_outranks_the_config_file() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-addr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let write = |name: &str, body: &str| {
            let p = dir.join(name);
            std::fs::write(&p, body).unwrap();
            p
        };
        let flag: SocketAddr = "127.0.0.1:6000".parse().unwrap();

        let named = write("named.toml", "addr = \"0.0.0.0:443\"\n");
        assert_eq!(
            ServerConfig::load(&named, Some(flag), None).unwrap().addr,
            flag
        );
        // and the file still supplies it for the run that passes no flag
        assert_eq!(
            ServerConfig::load(&named, None, None).unwrap().addr,
            "0.0.0.0:443".parse::<SocketAddr>().unwrap()
        );

        // neither names one: the built-in default
        let bare = write("bare.toml", "username = \"ci\"\n");
        assert_eq!(
            ServerConfig::load(&bare, None, None).unwrap().addr,
            DEFAULT_ADDR
        );

        // an unparseable `addr` is an error even on the run whose flag outranks it, so a
        // typo in the file surfaces instead of waiting for the run that relies on it
        let bad = write("bad.toml", "addr = \"h:t:t:p\"\n");
        assert!(ServerConfig::load(&bad, Some(flag), None).is_err());
        assert!(ServerConfig::load(&bad, None, None).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The `vk-registry accounts` CLI opens whatever this resolves, so it has to resolve
    /// what `into_state` opens — otherwise the CLI reports truthfully about a file the
    /// server never touches. Same flag-then-file-then-default order as `root_of`.
    #[test]
    fn accounts_db_of_resolves_the_db_a_server_would_open() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-adb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // an explicit path wins over everything
        let path = dir.join("registry.toml");
        std::fs::write(
            &path,
            "root = \"/srv/store\"\naccounts_db = \"/srv/file.db\"\n",
        )
        .unwrap();
        assert_eq!(
            ServerConfig::accounts_db_of(
                Some(&path),
                Some(PathBuf::from("/flag")),
                Some(PathBuf::from("/explicit.db"))
            )
            .unwrap(),
            PathBuf::from("/explicit.db")
        );
        // then the file's
        assert_eq!(
            ServerConfig::accounts_db_of(Some(&path), None, None).unwrap(),
            PathBuf::from("/srv/file.db")
        );
        // then the default under the resolved root, which is what `into_state` opens
        let bare = dir.join("bare.toml");
        std::fs::write(&bare, "root = \"/srv/store\"\n").unwrap();
        assert_eq!(
            ServerConfig::accounts_db_of(Some(&bare), None, None).unwrap(),
            default_accounts_db(Path::new("/srv/store"))
        );
        assert_eq!(
            ServerConfig::accounts_db_of(None, Some(dir.join("s")), None).unwrap(),
            default_accounts_db(&dir.join("s"))
        );

        // and it agrees with the path a real `into_state` opens, not just with itself
        let secret = dir.join("oidc-secret");
        std::fs::write(&secret, "s3cr3t\n").unwrap();
        let root = dir.join("store");
        let mut cfg = ServerConfig::local("127.0.0.1:5000".parse().unwrap(), root.clone());
        cfg.mode = AuthMode::Accounts;
        cfg.oidc = Some(OidcSpec {
            issuer: "https://login.example.com".to_string(),
            client_id: "vk-registry".to_string(),
            client_secret_file: secret,
            public_url: "https://registry.internal".to_string(),
        });
        drop(cfg.into_state().expect("a valid accounts config starts"));
        let resolved = ServerConfig::accounts_db_of(None, Some(root), None).unwrap();
        assert!(
            resolved.is_file(),
            "the CLI must find the db `serve` created: {}",
            resolved.display()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The CLI dials whatever this resolves, so it has to resolve what `serve` binds —
    /// including the off switch, since a CLI that kept probing a socket nobody binds would
    /// report a missing server rather than falling back to the db.
    #[test]
    fn admin_socket_of_resolves_the_socket_a_server_would_bind() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let write = |name: &str, body: &str| {
            let p = dir.join(name);
            std::fs::write(&p, body).unwrap();
            p
        };
        // The db resolved the way the CLI would, then the socket beside it — the pairing
        // the signature exists to keep.
        let sock_of = |cfg: Option<&Path>, over: Option<PathBuf>| {
            let db = ServerConfig::accounts_db_of(cfg, None, None).unwrap();
            ServerConfig::admin_socket_of(cfg, &db, over).unwrap()
        };

        // an explicit path wins over everything, including a file that turns it off
        let off = write("off.toml", "mode = \"accounts\"\nadmin_socket = false\n");
        assert_eq!(
            sock_of(Some(&off), Some(PathBuf::from("/explicit.sock"))),
            Some(PathBuf::from("/explicit.sock"))
        );
        assert_eq!(sock_of(Some(&off), None), None, "the file's off switch");

        let named = write(
            "named.toml",
            "mode = \"accounts\"\nadmin_socket = \"/run/vkr/admin.sock\"\n",
        );
        assert_eq!(
            sock_of(Some(&named), None),
            Some(PathBuf::from("/run/vkr/admin.sock"))
        );

        // else beside the accounts db, wherever that resolved from
        let bare = write("bare.toml", "mode = \"accounts\"\nroot = \"/srv/store\"\n");
        assert_eq!(
            sock_of(Some(&bare), None),
            Some(default_admin_socket(&default_accounts_db(Path::new(
                "/srv/store"
            ))))
        );
        // An explicit accounts db carries the socket with it: the CLI that would have opened
        // *that* file has to dial the server holding it, not one beside a default root.
        let elsewhere = dir.join("elsewhere").join("a.db");
        assert_eq!(
            ServerConfig::admin_socket_of(None, &elsewhere, None).unwrap(),
            Some(default_admin_socket(&elsewhere))
        );

        // Shared-secret mode binds none whatever the file says about the socket, so a CLI
        // must not resolve a path it would then probe forever.
        let shared = write("shared.toml", "password_file = \"/etc/vkr.pw\"\n");
        assert_eq!(sock_of(Some(&shared), None), None, "no accounts, no socket");
        let shared_on = write(
            "shared-on.toml",
            "password_file = \"/etc/vkr.pw\"\nadmin_socket = true\n",
        );
        assert_eq!(sock_of(Some(&shared_on), None), None, "even asked for");

        let moved = write(
            "moved.toml",
            "mode = \"accounts\"\naccounts_db = \"/srv/elsewhere/a.db\"\n",
        );
        assert_eq!(
            sock_of(Some(&moved), None),
            Some(PathBuf::from("/srv/elsewhere/admin.sock")),
            "the socket follows the db, not the root"
        );

        // and the config a `serve` runs from agrees with all of that
        let cfg = |body: &str| ServerConfig::load(&write("s.toml", body), None, None).unwrap();
        let accounts = "mode = \"accounts\"\nroot = \"/srv/store\"\n\
                        [oidc]\nissuer = \"https://i\"\nclient_id = \"c\"\n\
                        client_secret_file = \"/s\"\npublic_url = \"https://p\"\n";
        assert_eq!(
            cfg(accounts).resolved_admin_socket(),
            sock_of(Some(&bare), None)
        );
        assert_eq!(
            cfg(&format!("admin_socket = false\n{accounts}")).resolved_admin_socket(),
            None
        );
        // Shared-secret mode has no accounts to administer, so it binds nothing at all…
        assert_eq!(
            ServerConfig::local(
                "127.0.0.1:5000".parse().unwrap(),
                PathBuf::from("/srv/store")
            )
            .resolved_admin_socket(),
            None
        );
        // …and a file that configures the socket without that mode is refused rather than
        // ignored, as `accounts_db` already is.
        let orphan = write("orphan.toml", "admin_socket = \"/run/a.sock\"\n");
        let err = match ServerConfig::load(&orphan, None, None) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("admin_socket without accounts mode must be refused"),
        };
        assert!(err.contains("admin_socket"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The store root `status`/`gc` resolve, in the order `serve` resolves it: an explicit
    /// `--root` first, then the config file's, then the shared default. The file is what
    /// used to be skipped — leaving those two commands on a default store the server never
    /// touches.
    #[test]
    fn root_of_prefers_the_flag_then_the_file() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("registry.toml");
        std::fs::write(&path, "root = \"/srv/store\"\n").unwrap();

        assert_eq!(
            ServerConfig::root_of(Some(&path), Some(PathBuf::from("/flag"))).unwrap(),
            PathBuf::from("/flag")
        );
        assert_eq!(
            ServerConfig::root_of(Some(&path), None).unwrap(),
            PathBuf::from("/srv/store")
        );
        // a file that sets no root falls through to the default, as it does for `serve`
        let bare = dir.join("bare.toml");
        std::fs::write(&bare, "addr = \"127.0.0.1:5001\"\n").unwrap();
        assert_eq!(
            ServerConfig::root_of(Some(&bare), None).unwrap(),
            crate::default_root().unwrap()
        );
        assert_eq!(
            ServerConfig::load(&bare, None, None).unwrap().root,
            ServerConfig::root_of(Some(&bare), None).unwrap()
        );
        assert_eq!(
            ServerConfig::root_of(None, None).unwrap(),
            crate::default_root().unwrap()
        );
        // and a config file that is not there is an error, not a silent default
        assert!(ServerConfig::root_of(Some(&dir.join("absent.toml")), None).is_err());

        // The same file resolves the same root through `serve`'s own loader, with and
        // without the flag: the two must not drift into sweeping different stores.
        assert_eq!(
            ServerConfig::load(&path, None, None).unwrap().root,
            ServerConfig::root_of(Some(&path), None).unwrap()
        );
        assert_eq!(
            ServerConfig::load(&path, None, Some(PathBuf::from("/flag")))
                .unwrap()
                .root,
            ServerConfig::root_of(Some(&path), Some(PathBuf::from("/flag"))).unwrap()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The auth model is chosen by one key, so each way of getting that key wrong has to
    /// be an error rather than a quiet fall back to shared-secret auth.
    #[test]
    fn the_auth_mode_is_parsed_and_every_wrong_way_to_write_it_is_an_error() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-mode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let write = |name: &str, body: &str| {
            let p = dir.join(name);
            std::fs::write(&p, body).unwrap();
            p
        };

        // the default, and the one alternative
        let bare = write("bare.toml", "root = \"/srv/reg\"\n");
        assert_eq!(
            ServerConfig::load(&bare, None, None).unwrap().mode,
            AuthMode::SharedSecret
        );
        let accounts = write(
            "accounts.toml",
            "root = \"/srv/reg\"\nmode = \"accounts\"\n",
        );
        let cfg = ServerConfig::load(&accounts, None, None).unwrap();
        assert_eq!(cfg.mode, AuthMode::Accounts);
        // and the db defaults to a directory of its own under the store it guards
        assert_eq!(cfg.accounts_db, None);

        // an unknown mode names the two that exist rather than picking one
        let load_err = |p: &Path| {
            ServerConfig::load(p, None, None)
                .map(|_| ())
                .unwrap_err()
                .to_string()
        };
        let bad = write("bad.toml", "mode = \"oidc\"\n");
        let err = load_err(&bad);
        assert!(err.contains("unknown auth mode"), "{err}");

        // the shape `DESIGN.md` used to suggest: a table, not a top-level key. Dropping it
        // silently would start the server in the mode the operator meant to replace.
        let table = write("table.toml", "[auth]\nmode = \"accounts\"\n");
        assert!(!load_err(&table).is_empty());
        let typo = write("typo.toml", "moed = \"accounts\"\n");
        assert!(!load_err(&typo).is_empty());
        // a key spelt right but unread: nothing consumes `accounts_db` in shared-secret
        // mode, so a file that sets one with `mode` forgotten would serve wide open
        let orphan = write("orphan.toml", "accounts_db = \"/srv/reg/a.db\"\n");
        let err = load_err(&orphan);
        assert!(err.contains("mode is not"), "{err}");
    }

    /// A key the file spells wrong is a key the server does not apply, and every key here
    /// is about how it authenticates — so it has to be an error rather than a default.
    #[test]
    fn a_config_file_key_that_is_not_recognised_is_an_error() {
        let dir = std::env::temp_dir().join(format!("vk-regserve-strict-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let load_err = |name: &str, body: &str| {
            let p = dir.join(name);
            std::fs::write(&p, body).unwrap();
            ServerConfig::load(&p, None, None).map(|_| ()).unwrap_err()
        };

        // a misspelt top-level credential would otherwise serve the store wide open
        assert!(
            !load_err("typo.toml", "tokenfile = \"/etc/t\"\n")
                .to_string()
                .is_empty()
        );
        // and one inside [[upstream]] would relay unauthenticated
        assert!(
            !load_err(
                "upstream.toml",
                "[[upstream]]\nurl = \"https://example\"\nusrname = \"ci\"\n",
            )
            .to_string()
            .is_empty()
        );
        // the keys it does know still load
        let good = dir.join("good.toml");
        std::fs::write(
            &good,
            "root = \"/srv/reg\"\ntoken_file = \"/etc/t\"\n\n[[upstream]]\nurl = \"https://example\"\n",
        )
        .unwrap();
        let cfg = ServerConfig::load(&good, None, None).unwrap();
        assert_eq!(cfg.token_file, Some(PathBuf::from("/etc/t")));
        assert_eq!(cfg.upstreams.len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Plain HTTP is a leak everywhere but loopback, and the loopback test has to cope
    /// with a bracketed IPv6 literal as well as a port. A guard that can be fooled by its
    /// own parsing is worse than none, so the URLs whose *real* host is not the one a
    /// naive split sees are in here too.
    #[test]
    fn only_loopback_counts_as_a_local_url() {
        for ok in [
            "http://localhost",
            "http://localhost:5000",
            "http://127.0.0.1",
            "http://127.0.0.1:5000/path",
            "http://[::1]",
            "http://[::1]:5000",
            "http://[::1]:5000/path",
        ] {
            assert!(is_local_url(ok), "{ok}");
        }
        for bad in [
            "http://login.example.com",
            "http://127.0.0.1.evil.example",
            "http://[::2]:5000",
            "https://localhost",
            "localhost",
            "",
            // userinfo: the host is whatever follows the `@`
            "http://127.0.0.1@evil.example/",
            "http://[::1]@evil.example/",
            "http://localhost:x@evil.example/",
            // a bracketed literal has to end at its bracket
            "http://[::1]evil.example",
            "http://[::1",
        ] {
            assert!(!is_local_url(bad), "{bad}");
        }
    }

    /// A temp dir of its own (two tests must not share one: the accounts db is
    /// single-writer and they run in parallel) holding a valid client-secret file, plus
    /// the fixtures every accounts-mode case needs.
    fn accounts_fixture(tag: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("vk-regserve-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let secret = dir.join("oidc-secret");
        std::fs::write(&secret, "s3cr3t\n").unwrap();
        (dir, secret)
    }

    fn oidc_spec(secret: &Path) -> OidcSpec {
        OidcSpec {
            issuer: "https://login.example.com".to_string(),
            client_id: "vk-registry".to_string(),
            client_secret_file: secret.to_path_buf(),
            public_url: "https://registry.internal".to_string(),
        }
    }

    fn accounts_cfg(addr: &str, root: PathBuf) -> ServerConfig {
        let mut c = ServerConfig::local(addr.parse().unwrap(), root);
        c.mode = AuthMode::Accounts;
        c
    }

    fn err_of(c: ServerConfig) -> String {
        c.into_state().map(|_| ()).unwrap_err().to_string()
    }

    /// `[oidc]` is the only login path accounts mode has, so a table that would put a
    /// credential on the wire, name something that is not a base URL, or authenticate as
    /// nobody is refused at startup rather than at the first login.
    #[test]
    fn a_bad_oidc_table_is_refused_at_startup() {
        let (dir, secret) = accounts_fixture("oidcbad");
        let root = dir.join("store");
        let spec = || oidc_spec(&secret);
        let with = |o: OidcSpec| {
            let mut cfg = accounts_cfg("127.0.0.1:5000", root.clone());
            cfg.oidc = Some(o);
            err_of(cfg)
        };

        // an IdP reached over plain HTTP off-loopback: the client secret and the session
        // cookie would both go out in the clear
        let err = with(OidcSpec {
            issuer: "http://login.example.com".to_string(),
            ..spec()
        });
        assert!(err.contains("must be https"), "{err}");

        // a base URL carrying a query or fragment: every endpoint is built by appending
        // to it, so it has to be a base and nothing more
        for bad in [
            "https://login.example.com/?tenant=a",
            "https://login.example.com/#x",
        ] {
            let err = with(OidcSpec {
                issuer: bad.to_string(),
                ..spec()
            });
            assert!(err.contains("base URL"), "{bad}: {err}");
        }

        // control characters: a `Location` header would refuse them at the first login,
        // and the issuer is also the identity namespace
        let err = with(OidcSpec {
            public_url: "https://registry.internal\r\nX: y".to_string(),
            ..spec()
        });
        assert!(err.contains("control characters"), "{err}");

        // no client_id to authenticate as
        let err = with(OidcSpec {
            client_id: String::new(),
            ..spec()
        });
        assert!(err.contains("client_id"), "{err}");

        // an empty secret file, and one far too large to be a secret at all
        std::fs::write(&secret, "\n").unwrap();
        let err = with(spec());
        assert!(err.contains("is empty"), "{err}");
        std::fs::write(&secret, "x".repeat(MAX_CLIENT_SECRET_LEN as usize + 1)).unwrap();
        let err = with(spec());
        assert!(err.contains("not a client secret"), "{err}");

        // and none of the refusals created the store
        assert!(!root.exists(), "a config that cannot start creates nothing");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Accounts mode replaces the shared secret rather than layering on it, it carries
    /// credentials, and it needs an IdP to issue them — so every guard that mode implies
    /// has to hold, and none of them may leave a half-built store behind.
    #[test]
    fn accounts_mode_refuses_a_shared_secret_cleartext_and_a_bad_idp() {
        let (dir, secret) = accounts_fixture("amode");
        let spec = || oidc_spec(&secret);

        // a shared secret beside it
        let mut cfg = accounts_cfg("127.0.0.1:5000", dir.join("store"));
        cfg.token_file = Some(PathBuf::from("/etc/vk-registry/token"));
        let err = cfg.build_auth().map(|_| ()).unwrap_err().to_string();
        assert!(err.contains("mutually exclusive"), "{err}");

        // credentials in cleartext on a routable address
        let mut cfg = accounts_cfg("0.0.0.0:5000", dir.join("store"));
        cfg.oidc = Some(spec());
        let err = err_of(cfg);
        assert!(err.contains("cleartext"), "{err}");

        // no IdP at all — and the refusal leaves nothing behind
        let root = dir.join("store");
        let err = err_of(accounts_cfg("127.0.0.1:5000", root.clone()));
        assert!(err.contains("[oidc]"), "{err}");
        assert!(
            !root.exists(),
            "a config that cannot start must not create the store"
        );

        // an [oidc] table under the mode that cannot use it
        let mut cfg = ServerConfig::local("127.0.0.1:5000".parse().unwrap(), root.clone());
        cfg.oidc = Some(spec());
        let err = err_of(cfg);
        assert!(err.contains("needs mode"), "{err}");

        // an admin socket under the mode that binds none — every spelling of it, since a
        // `true` silently ignored while `false` refused would be the confusing pair
        for stated in [
            AdminSocket::Default,
            AdminSocket::Off,
            AdminSocket::At(PathBuf::from("/run/vkr/admin.sock")),
        ] {
            let mut cfg = ServerConfig::local("127.0.0.1:5000".parse().unwrap(), root.clone());
            cfg.admin_socket = stated.clone();
            let err = err_of(cfg);
            assert!(err.contains("admin_socket is set"), "{stated:?}: {err}");
        }

        // and configured correctly it starts, with the db in a directory of its own under
        // the store — no network, because discovery is deferred to the first login
        let mut cfg = accounts_cfg("127.0.0.1:5000", root.clone());
        cfg.oidc = Some(spec());
        let state = cfg.into_state().expect("a valid accounts config starts");
        assert!(matches!(state.auth, crate::Authenticator::Accounts { .. }));
        assert!(root.join("accounts").join("accounts.db").exists());
        // that directory is `Db::open`'s to make, at 0700 whatever the umask, rather than
        // the store root whose mode the umask decides
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(root.join("accounts"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "the accounts dir: {mode:o}");
        }
        drop(state);

        // and a configured path is honoured instead
        let elsewhere = dir.join("elsewhere").join("ours.db");
        let mut cfg = accounts_cfg("127.0.0.1:5000", dir.join("store-two"));
        cfg.oidc = Some(spec());
        cfg.accounts_db = Some(elsewhere.clone());
        drop(
            cfg.into_state()
                .expect("a configured accounts_db is honoured"),
        );
        assert!(elsewhere.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
