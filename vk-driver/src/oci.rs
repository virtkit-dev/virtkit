//! Pull an OCI image's rootfs straight from a registry (no docker daemon) and
//! flatten its layers — applying whiteouts — into a single rootfs tar, the same
//! shape `docker export` produces, which the ext4/cpio builders consume. With
//! the native ext4 writer this lets the whole pipeline drop docker, leaving
//! cloud-hypervisor as the only external dependency.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use oci_client::Reference;
use oci_client::client::{Certificate, CertificateEncoding, ClientConfig, ClientProtocol};
use oci_client::manifest;
use oci_client::secrets::RegistryAuth;

use crate::config::{Build, Docker, Mirror, Registry};

/// A sink for the human-readable status lines a pull emits (`pulling …`, `flattened …`).
/// The caller supplies where they go: straight to stdout for a standalone pull, or a
/// no-op under the `vk build` dashboard — which owns the terminal, so a raw `println!`
/// there would corrupt indicatif's cursor accounting and re-print the whole live block.
/// `Sync` keeps the returned futures `Send`.
pub type Note<'a> = &'a (dyn Fn(&str) + Sync);

/// The parts of an OCI image's config a build inherits into a stage: environment
/// (notably `PATH`), default user and working directory, the runtime entrypoint/cmd,
/// and the exposed ports a service gates its readiness on (all carried through to the
/// exported runtime-config sidecar).
#[derive(Default, Debug, Clone)]
pub struct ImageConfig {
    pub env: Vec<(String, String)>,
    pub user: Option<String>,
    pub workdir: Option<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    /// TCP ports from the config's `ExposedPorts` (the guest gates readiness on them).
    pub exposed_ports: Vec<u16>,
}

impl From<ImageConfig> for vk_core::runcfg::RunConfig {
    fn from(c: ImageConfig) -> Self {
        Self {
            env: c.env,
            user: c.user.unwrap_or_default(),
            workdir: c.workdir.unwrap_or_default(),
            entrypoint: c.entrypoint,
            cmd: c.cmd,
            exposed_ports: c.exposed_ports,
        }
    }
}

/// What one registry conversation needs: the credential to authenticate with (a bearer
/// token or an HTTP Basic pair), the trust anchor its TLS certificate must chain to, and
/// whether it speaks plain HTTP.
/// One struct so a caller cannot transpose two arguments of the same type, and so the
/// `ClientConfig` assembly has a single home.
#[derive(Default, Clone)]
pub struct Creds {
    /// HTTP Basic username. `None` — or a `None` `password` — sends no `Authorization`,
    /// unless a `token` does.
    pub username: Option<String>,
    /// The Basic password: as `--password` gave it, or read from a config section's
    /// `password_file` by one of the `from_*` constructors. Sent only
    /// alongside a `username`.
    pub password: Option<String>,
    /// A static bearer token, for a registry gated by one rather than by a password (a
    /// `vk-registry` in `mode = "accounts"`, whose API keys are exactly that). Takes
    /// precedence over the Basic pair when both are set.
    pub token: Option<String>,
    /// PEM CA bundle the registry's TLS certificate chains to. `None` = the system roots.
    pub ca_pem: Option<Vec<u8>>,
    /// Plain HTTP (a local/insecure registry); TLS otherwise.
    pub insecure: bool,
}

/// Hand-written so no secret escapes through a `{:?}`: `Creds` is public and is carried
/// inside [`crate::source::Source`], so the day anything up that chain derives `Debug` the
/// password or token would otherwise land in a log or an `anyhow` context. The CA bundle
/// is public data but bulky, so it prints as its length.
impl std::fmt::Debug for Creds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted = |v: &Option<String>| v.as_ref().map(|_| "<redacted>");
        f.debug_struct("Creds")
            .field("username", &self.username)
            .field("password", &redacted(&self.password))
            .field("token", &redacted(&self.token))
            .field("ca_pem_len", &self.ca_pem.as_ref().map(Vec::len))
            .field("insecure", &self.insecure)
            .finish()
    }
}

/// The credential files one config section names, plus the section's own name for the
/// errors. Named fields rather than five positional arguments: three of them are
/// `Option<&Path>`, so a transposed pair would compile and surface much later as a 401.
struct CredFiles<'a> {
    /// Which section these came from (`[docker]`, `[registry]`, …), to name in an error.
    section: &'a str,
    ca_file: Option<&'a Path>,
    username: &'a str,
    password_file: Option<&'a Path>,
    token_file: Option<&'a Path>,
    insecure: bool,
}

impl Creds {
    /// Anonymous, over TLS verified against the system roots: what a pull from a registry
    /// nothing is configured for uses, and the spelling to prefer over `Creds::default()`.
    pub fn anonymous() -> Creds {
        Creds::default()
    }

    /// What `[docker]` names, for a bare image name routed onto the configured proxy repo.
    pub fn from_docker(dk: &Docker) -> Result<Creds> {
        Creds::from_files(CredFiles {
            section: "[docker]",
            ca_file: dk.ca_file.as_deref(),
            username: &dk.username,
            password_file: dk.password_file.as_deref(),
            token_file: dk.token_file.as_deref(),
            insecure: dk.insecure,
        })
    }

    /// What `[docker.mirror]` names, for a Docker Hub reference routed through the mirror.
    /// A mirror usually carries its own account, hence the second constructor.
    pub fn from_mirror(m: &Mirror) -> Result<Creds> {
        Creds::from_files(CredFiles {
            section: "[docker.mirror]",
            ca_file: m.ca_file.as_deref(),
            username: &m.username,
            password_file: m.password_file.as_deref(),
            token_file: m.token_file.as_deref(),
            insecure: m.insecure,
        })
    }

    /// What `[build]`'s `cache_*` keys name, for the vk-registry a runner is handed as its
    /// build cache — also the first server a job image that nothing routes is offered to.
    pub fn from_build_cache(b: &Build) -> Result<Creds> {
        Creds::from_files(CredFiles {
            section: "[build] cache_*",
            ca_file: b.cache_ca_file.as_deref(),
            username: &b.cache_username,
            password_file: b.cache_password_file.as_deref(),
            token_file: b.cache_token_file.as_deref(),
            insecure: b.cache_insecure,
        })
    }

    /// What `[registry]` names — the same credential `registry::cred` resolves for the
    /// bundle paths, in the shape the OCI client here takes.
    pub fn from_registry(rg: &Registry) -> Result<Creds> {
        Creds::from_files(CredFiles {
            section: "[registry]",
            ca_file: rg.ca_file.as_deref(),
            username: &rg.username,
            password_file: rg.password_file.as_deref(),
            token_file: rg.token_file.as_deref(),
            insecure: rg.insecure,
        })
    }

    /// The shared body of the four `from_*` constructors.
    ///
    /// The files are read here, once, rather than at each use: a pull that would fail for
    /// an unreadable 0600 file says so before the first request, naming the path. A
    /// `token_file` supersedes the Basic pair, so the password is not read at all when one
    /// is set — what [`Creds::auth`] would ignore, and what `vk check` skips validating.
    /// The trimming rules are `registry::cred`'s, so one credential file behaves the same
    /// whichever path reads it: a token loses whitespace at both ends, while a password is
    /// `trim_end`ed only — it may legitimately begin with whitespace.
    fn from_files(f: CredFiles<'_>) -> Result<Creds> {
        let token = f
            .token_file
            .map(|p| {
                let t = std::fs::read_to_string(p)
                    .map(|s| s.trim().to_string())
                    .with_context(|| format!("reading {}", p.display()))?;
                // An empty token_file is a misconfiguration, not a request to stay
                // anonymous: an empty `Bearer ` only ever 401s, so name the file to fix.
                if t.is_empty() {
                    bail!("{} token_file {} is empty", f.section, p.display());
                }
                Ok(t)
            })
            .transpose()?;
        let password = match (&token, f.password_file) {
            (None, Some(p)) => Some(
                std::fs::read_to_string(p)
                    .map(|s| s.trim_end().to_string())
                    .with_context(|| format!("reading {}", p.display()))?,
            ),
            _ => None,
        };
        Creds {
            username: (!f.username.is_empty()).then(|| f.username.to_string()),
            password,
            token,
            ca_pem: None,
            insecure: f.insecure,
        }
        .with_ca_file(f.ca_file)
    }

    /// Read `ca_file` into this credential's trust anchor — for the `--ca` flag, whose
    /// callers hold a path rather than the PEM. Reading it up front means an unreadable
    /// bundle fails naming the path instead of as an opaque TLS error mid-pull. `None`
    /// leaves the anchor as it was, so this only ever adds what a path names.
    pub fn with_ca_file(mut self, ca_file: Option<&Path>) -> Result<Creds> {
        if let Some(p) = ca_file {
            self.ca_pem =
                Some(std::fs::read(p).with_context(|| format!("reading {}", p.display()))?);
        }
        Ok(self)
    }

    /// The `Authorization` this sends: a bearer token when one is configured, else the
    /// Basic pair when both halves are set, else nothing — a username with no password
    /// authenticates as nobody, not as that user. A token wins over a password that is
    /// also set, the precedence `[registry] token_file` documents and `vk-registry`
    /// applies on the other side.
    fn auth(&self) -> RegistryAuth {
        match (&self.token, &self.username, &self.password) {
            (Some(t), _, _) => RegistryAuth::Bearer(t.clone()),
            (None, Some(u), Some(p)) => RegistryAuth::Basic(u.clone(), p.clone()),
            _ => RegistryAuth::Anonymous,
        }
    }

    /// Attach this credential to a raw HTTP request — the registry-proxy path, which
    /// forwards a guest's request upstream rather than going through the OCI client.
    ///
    /// Uses [`Creds::auth`] so request and client authentication share one precedence rule.
    pub fn apply(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.auth() {
            RegistryAuth::Bearer(t) => req.bearer_auth(t),
            RegistryAuth::Basic(u, p) => req.basic_auth(u, Some(p)),
            _ => req,
        }
    }

    /// A client configured for this registry's transport (scheme + trust anchor).
    fn client(&self) -> oci_client::Client {
        let mut cfg = ClientConfig::default();
        if self.insecure {
            cfg.protocol = ClientProtocol::Http;
        }
        if let Some(data) = &self.ca_pem {
            cfg.extra_root_certificates.push(Certificate {
                encoding: CertificateEncoding::Pem,
                data: data.clone(),
            });
        }
        oci_client::Client::new(cfg)
    }
}

/// Resolve `reference` to its manifest digest (`sha256:…`), anonymously — for the build
/// cache key, so a moved tag changes the key (and a stale cached base is not reused).
/// Errors (offline, private registry) propagate; the caller falls back to keying by ref.
pub async fn resolve_digest(reference: &str) -> Result<String> {
    let reference: Reference = reference
        .parse()
        .with_context(|| format!("parsing OCI reference {reference:?}"))?;
    // A digest-pinned ref (`name[:tag]@sha256:…`) already carries its manifest digest — it
    // is authoritative and cannot move, so return it without a registry round-trip. This is
    // what lets a fully-cached build of a digest-pinned base (the reproducible-build norm)
    // skip the network entirely: the digest feeds the cache key directly, identical to what
    // the fetch below would return.
    if let Some(digest) = reference.digest() {
        return Ok(digest.to_string());
    }
    let client = Creds::anonymous().client();
    client
        .fetch_manifest_digest(&reference, &RegistryAuth::Anonymous)
        .await
        .with_context(|| format!("resolving manifest digest for {reference}"))
}

/// Resolve `reference` to its manifest digest against an authenticated/TLS registry —
/// the executor keys its per-image cache on the digest, and a digest-pinned ref returns
/// without a round-trip. Mirrors [`resolve_digest`] but carries the `[docker]` creds so a
/// private corp registry answers.
pub async fn resolve_digest_auth(reference: &str, creds: &Creds) -> Result<String> {
    let parsed: Reference = reference
        .parse()
        .with_context(|| format!("parsing OCI reference {reference:?}"))?;
    if let Some(digest) = parsed.digest() {
        return Ok(digest.to_string());
    }
    creds
        .client()
        .fetch_manifest_digest(&parsed, &creds.auth())
        .await
        .with_context(|| format!("resolving manifest digest for {reference}"))
}

/// Whether `reference` resolves in its registry: `Ok(true)` if the manifest is present,
/// `Ok(false)` if the registry reports it unknown (name/manifest not found), and `Err`
/// for auth/network/other failures. Lets an `auto` source fall back to docker *only* when
/// the image truly is not in a registry, while surfacing auth errors instead of masking
/// them behind a docker fallback.
pub async fn manifest_exists(reference: &str, creds: &Creds) -> Result<bool> {
    Ok(resolve_digest_if_present(reference, creds).await?.is_some())
}

/// Whether `err` is a registry refusing the caller rather than failing: a 401/403, or an
/// OCI `UNAUTHORIZED`/`DENIED` envelope. Kept out of [`resolve_digest_if_present`]'s
/// not-found set on purpose — a caller that must surface an auth problem (an `auto` source
/// deciding whether to fall back to docker) still sees it as an error, while one that only
/// *offers* a ref to a registry, and pulls it elsewhere otherwise, can treat a key scoped
/// away from that namespace as ordinary as a 404.
pub fn is_access_denied(err: &anyhow::Error) -> bool {
    use oci_client::errors::{OciDistributionError, OciErrorCode};
    match err.downcast_ref::<OciDistributionError>() {
        // Deliberately not `AuthenticationFailure`: oci-client raises that for any non-200
        // from the token endpoint, so a 503 there would be silenced along with a refusal.
        Some(OciDistributionError::UnauthorizedError { .. }) => true,
        Some(OciDistributionError::ServerError { code, .. }) => matches!(code, 401 | 403),
        Some(OciDistributionError::RegistryError { envelope, .. }) => envelope
            .errors
            .iter()
            .any(|e| matches!(e.code, OciErrorCode::Unauthorized | OciErrorCode::Denied)),
        _ => false,
    }
}

/// `reference`'s manifest digest, or `None` when that registry does not hold it — the
/// same not-found/error split [`manifest_exists`] draws, keeping the digest the round
/// trip already fetched so a caller that wants both does not ask twice.
pub async fn resolve_digest_if_present(reference: &str, creds: &Creds) -> Result<Option<String>> {
    use oci_client::errors::{OciDistributionError, OciErrorCode};
    let parsed: Reference = reference
        .parse()
        .with_context(|| format!("parsing OCI reference {reference:?}"))?;
    // Deliberately no digest-pinned shortcut of the kind `resolve_digest_auth` takes: a
    // pinned ref carries its own digest but says nothing about whether *this* registry
    // holds it, which is the whole question here.
    let not_found = |c: &OciErrorCode| {
        matches!(
            c,
            OciErrorCode::ManifestUnknown | OciErrorCode::NameUnknown | OciErrorCode::NotFound
        )
    };
    match creds
        .client()
        .fetch_manifest_digest(&parsed, &creds.auth())
        .await
    {
        Ok(d) => Ok(Some(d)),
        Err(OciDistributionError::ImageManifestNotFoundError(_)) => Ok(None),
        Err(OciDistributionError::RegistryError { envelope, .. })
            if envelope.errors.iter().any(|e| not_found(&e.code)) =>
        {
            Ok(None)
        }
        Err(OciDistributionError::ServerError { code: 404, .. }) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("resolving {reference} in its registry")),
    }
}

/// Fetch `reference`'s image config (`Env`/`User`/`WorkingDir`), so a stage's `RUN`s
/// inherit the base image's environment. Cached on disk keyed by the reference, so it
/// is fetched at most once per ref (a warm build reads the cache, no network).
pub async fn pull_config(reference: &str, creds: &Creds) -> Result<ImageConfig> {
    if let Some(json) = read_cached_config(reference) {
        return Ok(parse_config(&json));
    }
    let parsed: Reference = reference
        .parse()
        .with_context(|| format!("parsing OCI reference {reference:?}"))?;
    let (_manifest, _digest, config_json) = creds
        .client()
        .pull_manifest_and_config(&parsed, &creds.auth())
        .await
        .with_context(|| format!("pulling the config of {reference}"))?;
    write_cached_config(reference, &config_json);
    Ok(parse_config(&config_json))
}

/// Parse an OCI image config JSON's `.config` into the fields a build inherits.
fn parse_config(json: &str) -> ImageConfig {
    let v: serde_json::Value = serde_json::from_str(json).unwrap_or(serde_json::Value::Null);
    let c = &v["config"];
    let env = c["Env"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str())
                .filter_map(|kv| kv.split_once('='))
                .map(|(k, val)| (k.to_string(), val.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let nonempty = |s: &serde_json::Value| s.as_str().filter(|x| !x.is_empty()).map(str::to_string);
    let argv = |v: &serde_json::Value| {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|e| e.as_str())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    ImageConfig {
        env,
        user: nonempty(&c["User"]),
        workdir: nonempty(&c["WorkingDir"]),
        entrypoint: argv(&c["Entrypoint"]),
        cmd: argv(&c["Cmd"]),
        exposed_ports: exposed_tcp_ports(&c["ExposedPorts"]),
    }
}

/// TCP ports from an OCI config's `ExposedPorts` — a set-valued object keyed by
/// `"<port>/<proto>"` (e.g. `{"3306/tcp": {}, "33060/tcp": {}}`). Only `tcp` ports are
/// kept (a readiness probe opens a TCP connection); entries without a proto default to
/// tcp, per the OCI/Docker convention. Deduplicated and sorted for a stable sidecar.
fn exposed_tcp_ports(v: &serde_json::Value) -> Vec<u16> {
    let mut ports: Vec<u16> = v
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(key, _)| {
            let (port, proto) = key.split_once('/').unwrap_or((key, "tcp"));
            (proto == "tcp").then(|| port.parse().ok()).flatten()
        })
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn config_cache_path(reference: &str) -> Option<PathBuf> {
    use sha2::{Digest, Sha256};
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?;
    let dir = base.join("virtkit/dfconfig");
    let _ = std::fs::create_dir_all(&dir);
    let mut h = Sha256::new();
    h.update(reference.as_bytes());
    let mut name = String::new();
    for b in h.finalize() {
        name.push_str(&format!("{b:02x}"));
    }
    name.push_str(".json");
    Some(dir.join(name))
}

fn read_cached_config(reference: &str) -> Option<String> {
    std::fs::read_to_string(config_cache_path(reference)?).ok()
}

fn write_cached_config(reference: &str, json: &str) {
    if let Some(p) = config_cache_path(reference) {
        let _ = std::fs::write(p, json);
    }
}

/// Pull `reference` and flatten it into a rootfs tar at `out_tar`.
pub async fn pull_flatten(
    reference: &str,
    creds: &Creds,
    out_tar: &Path,
    note: Note<'_>,
) -> Result<()> {
    // scratch next to the output tar, not $TMPDIR: a multi-GB image on a tmpfs
    // /tmp would land in RAM.
    let scratch_dir = match out_tar.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let (merger, layers) = pull_merged(reference, creds, scratch_dir, note).await?;
    let n = merger.finish(out_tar)?;
    note(&format!(
        "virtkit: flattened {layers} layers -> {n} entries"
    ));
    Ok(())
}

/// Pull `reference` and flatten its layers into a [`Merger`] (spilled to an unlinked
/// scratch file in `scratch_dir`), plus the layer count. The caller picks the output
/// form: `finish` to a tar file, or `finish_to` a writer to stream with no
/// intermediate tar.
pub(crate) async fn pull_merged(
    reference: &str,
    creds: &Creds,
    scratch_dir: &Path,
    note: Note<'_>,
) -> Result<(Merger, usize)> {
    let reference: Reference = reference
        .parse()
        .with_context(|| format!("parsing OCI reference {reference:?}"))?;
    let client = creds.client();
    let auth = creds.auth();
    let accepted = vec![
        manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
        manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
        manifest::IMAGE_LAYER_MEDIA_TYPE,
        manifest::IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
    ];
    note(&format!("virtkit: pulling OCI image {reference} ..."));
    let image = client
        .pull(&reference, &auth, accepted)
        .await
        .with_context(|| format!("pulling {reference}"))?;

    let mut merger = Merger::new(crate::scratch::scratch(scratch_dir, "oci-spill")?.file);
    for layer in &image.layers {
        merger.apply_layer(&layer.data[..], &layer.media_type)?;
    }
    Ok((merger, image.layers.len()))
}

struct Entry {
    header: tar::Header,
    /// (offset, len) in the spill blob for regular files
    data: Option<(u64, u64)>,
    /// full link target for hardlinks/symlinks — captured from the entry (which
    /// resolves PAX/GNU extensions), since the cloned fixed header truncates names
    /// over 100 bytes. Re-emitted via `append_link` so long targets survive.
    link: Option<PathBuf>,
    /// xattrs from the entry's PAX `SCHILY.xattr.*` records (e.g.
    /// /usr/bin/ping's security.capability). Captured here and re-emitted as a PAX
    /// header in `finish_to`, since the `tar` writer has no native xattr support and
    /// cloning the fixed header alone would drop them.
    xattrs: Vec<(String, Vec<u8>)>,
}

/// Accumulates OCI layers into a single flattened rootfs, applying whiteouts and
/// opaque dirs. Shared by the registry path (`pull_flatten`) and the local-archive
/// path (`mkoci`); `apply_layer` is reader-generic so callers feed it either an
/// in-memory layer slice or a seeked file range over an OCI tar.
pub(crate) struct Merger {
    entries: BTreeMap<String, Entry>,
    blob: std::fs::File,
    off: u64,
}

impl Merger {
    /// `blob` is the spill file for regular-file data: it must be open read+write
    /// (apply_layer appends, finish seeks back to read) — e.g. a `scratch()` file,
    /// which no aborted run can leak.
    pub(crate) fn new(blob: std::fs::File) -> Merger {
        Merger {
            entries: BTreeMap::new(),
            blob,
            off: 0,
        }
    }

    /// Apply one layer: collect its entries + whiteouts, remove whited-out paths
    /// from the accumulated set, then merge this layer's entries (override).
    pub(crate) fn apply_layer(&mut self, reader: impl Read, media_type: &str) -> Result<()> {
        let reader: Box<dyn Read> = if media_type.contains("gzip") {
            Box::new(GzDecoder::new(reader))
        } else {
            Box::new(reader)
        };
        let mut ar = tar::Archive::new(reader);
        let mut adds: Vec<(String, Entry)> = Vec::new();
        let mut whiteouts: Vec<String> = Vec::new();
        let mut opaque: Vec<String> = Vec::new();
        for entry in ar.entries()? {
            let mut e = entry?;
            let path = normalize(&e.path()?.to_string_lossy());
            if path.is_empty() {
                continue;
            }
            let (parent, base) = split(&path);
            if base == ".wh..wh..opq" {
                opaque.push(parent.to_string());
                continue;
            }
            if let Some(orig) = base.strip_prefix(".wh.") {
                whiteouts.push(join(parent, orig));
                continue;
            }
            let header = e.header().clone();
            let et = header.entry_type();
            // capture PAX xattrs before reading the data (pax_extensions reads the
            // already-parsed extension header, not the data stream).
            let xattrs = crate::ext4::tar_xattrs(&mut e);
            let mut data = None;
            let mut link = None;
            if et.is_file() {
                let start = self.off;
                self.off += std::io::copy(&mut e, &mut self.blob)?;
                data = Some((start, self.off - start));
            } else if et.is_hard_link() || et.is_symlink() {
                // capture the full (PAX/GNU-resolved) target; the fixed header alone
                // truncates targets over 100 bytes (e.g. uv's deep tool hardlinks).
                link = e.link_name()?.map(|p| p.into_owned());
            }
            adds.push((
                path,
                Entry {
                    header,
                    data,
                    link,
                    xattrs,
                },
            ));
        }
        for dir in opaque {
            let prefix = format!("{dir}/");
            self.entries.retain(|k, _| !k.starts_with(&prefix));
        }
        for w in whiteouts {
            let prefix = format!("{w}/");
            self.entries.remove(&w);
            self.entries.retain(|k, _| !k.starts_with(&prefix));
        }
        for (p, e) in adds {
            self.entries.insert(p, e);
        }
        Ok(())
    }

    /// Total file-content bytes accumulated in the spill (an upper bound on the
    /// rootfs data size, for sizing a streamed ext4).
    pub(crate) fn data_bytes(&self) -> u64 {
        self.off
    }

    /// Number of merged entries (files + dirs + links), for sizing the inode table.
    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Write the merged set as a single rootfs tar to `out_tar`; returns the entry
    /// count.
    pub(crate) fn finish(self, out_tar: &Path) -> Result<usize> {
        let file = std::fs::File::create(out_tar)
            .with_context(|| format!("creating {}", out_tar.display()))?;
        self.finish_to(file)
    }

    /// Write the merged set as a single rootfs tar to any writer; returns the entry
    /// count. Lets the caller stream the flattened rootfs straight into the ext4
    /// builder (via a pipe) instead of materialising an intermediate tar file.
    pub(crate) fn finish_to<W: Write>(mut self, w: W) -> Result<usize> {
        let mut builder = tar::Builder::new(w);
        let n = self.entries.len();
        // BTreeMap iterates in path order, so parents precede children
        let entries = std::mem::take(&mut self.entries);
        for (path, entry) in entries {
            // Preserve xattrs (e.g. /usr/bin/ping's security.capability): emit a PAX
            // extended-header entry just before this member, which the tar reader pairs
            // with it. The `tar` writer has no native xattr support, but a manually
            // appended `x` header is enough — no fork needed.
            if !entry.xattrs.is_empty() {
                append_xattr_header(&mut builder, &entry.xattrs)?;
            }
            let mut header = entry.header;
            match (entry.data, entry.link) {
                (Some((off, len)), _) => {
                    self.blob.seek(SeekFrom::Start(off))?;
                    let mut r = (&mut self.blob).take(len);
                    builder.append_data(&mut header, &path, &mut r)?;
                }
                // hardlink/symlink: append_link emits a GNU long-link extension when
                // the target exceeds the 100-byte header field, so it isn't truncated.
                (None, Some(target)) => {
                    builder.append_link(&mut header, &path, &target)?;
                }
                (None, None) => {
                    builder.append_data(&mut header, &path, std::io::empty())?;
                }
            }
        }
        builder.into_inner()?.flush()?;
        Ok(n)
    }
}

/// Append a PAX extended-header (`x`) entry carrying `xattrs` as `SCHILY.xattr.<name>`
/// records — the encoding `docker export` uses and `ext4::tar_xattrs` reads. The tar
/// reader applies a preceding `x` entry to the next member, so this restores the
/// file capabilities the layer carried (the `tar` writer has no xattr API of its own).
fn append_xattr_header<W: Write>(
    builder: &mut tar::Builder<W>,
    xattrs: &[(String, Vec<u8>)],
) -> Result<()> {
    let mut body = Vec::new();
    for (name, value) in xattrs {
        body.extend_from_slice(&pax_record(&format!("SCHILY.xattr.{name}"), value));
    }
    let mut h = tar::Header::new_gnu(); // GNU magic, so the reader recognizes the header
    h.set_entry_type(tar::EntryType::XHeader);
    h.set_size(body.len() as u64);
    h.set_mode(0o644);
    h.set_uid(0);
    h.set_gid(0);
    h.set_mtime(0);
    // the name is irrelevant to pairing (it's positional); a conventional short one
    // keeps it inside the 100-byte field (no GNU long-name entry).
    let _ = h.set_path("PaxHeaders.0/xattr");
    h.set_cksum();
    builder
        .append(&h, &body[..])
        .context("appending a PAX xattr header")?;
    Ok(())
}

/// Encode one PAX record: `"<len> key=value\n"`, where `len` is the total byte length
/// of the record *including its own decimal digits* (the standard self-referential
/// length). Binary-safe: the value bytes are written verbatim (readers length-prefix).
fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
    // bytes other than the leading length digits: ' ' + key + '=' + value + '\n'
    let fixed = 1 + key.len() + 1 + value.len() + 1;
    let mut len = fixed + 1;
    loop {
        let digits = len.to_string().len();
        if fixed + digits == len {
            break;
        }
        len = fixed + digits;
    }
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(len.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(key.as_bytes());
    out.push(b'=');
    out.extend_from_slice(value);
    out.push(b'\n');
    out
}

fn normalize(path: &str) -> String {
    path.trim_start_matches("./")
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_string()
}

fn split(path: &str) -> (&str, &str) {
    match path.rsplit_once('/') {
        Some((p, b)) => (p, b),
        None => ("", path),
    }
}

fn join(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A scratch dir for one test's credential files, named per test and process so
    /// concurrent runs never collide (the crate's idiom — see `config.rs`'s tests).
    fn creds_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vk-oci-creds-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("creating the scratch dir");
        d
    }

    fn docker_section(dir: &Path, username: &str, password_file: Option<PathBuf>) -> Docker {
        Docker {
            repo: None,
            ca_file: Some(dir.join("ca.pem")),
            username: username.to_string(),
            password_file,
            token_file: None,
            insecure: false,
            mirror: None,
        }
    }

    /// A `token_file` supersedes the Basic pair all the way through the constructors, and
    /// the superseded password is not even read — which is what lets `vk check` skip
    /// validating it. The unreadable `password_file` here would abort the pull otherwise.
    #[test]
    fn a_section_token_file_supersedes_its_password() {
        let dir = creds_dir("section-token");
        std::fs::write(dir.join("ca.pem"), b"pem").unwrap();
        let token = dir.join("token");
        std::fs::write(&token, "vkr_x\n").unwrap();

        let mut dk = docker_section(&dir, "ci", Some(dir.join("absent")));
        dk.token_file = Some(token.clone());
        let creds = Creds::from_docker(&dk).unwrap();
        assert_eq!(creds.password, None);
        assert!(matches!(creds.auth(), RegistryAuth::Bearer(t) if t == "vkr_x"));

        let m = crate::config::Mirror {
            repo: "hq-nexus.example.com:8440".to_string(),
            ca_file: None,
            username: "ci".to_string(),
            password_file: Some(dir.join("absent")),
            token_file: Some(token),
            insecure: false,
        };
        let creds = Creds::from_mirror(&m).unwrap();
        assert_eq!(creds.password, None);
        assert!(matches!(creds.auth(), RegistryAuth::Bearer(t) if t == "vkr_x"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn from_docker_reads_the_files_a_section_names() {
        let dir = creds_dir("read");
        std::fs::write(dir.join("ca.pem"), b"-----BEGIN CERTIFICATE-----\n").unwrap();
        let pw = dir.join("password");
        // Only the trailing newline goes: a password may legitimately begin with spaces.
        std::fs::write(&pw, "  s3cret \n").unwrap();

        let creds = Creds::from_docker(&docker_section(&dir, "bob", Some(pw))).unwrap();
        assert_eq!(creds.username.as_deref(), Some("bob"));
        assert_eq!(creds.password.as_deref(), Some("  s3cret"));
        assert_eq!(
            creds.ca_pem.as_deref(),
            Some(&b"-----BEGIN CERTIFICATE-----\n"[..])
        );
        assert!(!creds.insecure);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn from_docker_leaves_an_empty_username_anonymous() {
        let dir = creds_dir("anon");
        std::fs::write(dir.join("ca.pem"), b"pem").unwrap();
        let pw = dir.join("password");
        std::fs::write(&pw, "s3cret\n").unwrap();

        // The password file is still read (and still fails loudly if it cannot be), but
        // with nobody to send it as, `auth()` stays anonymous.
        let creds = Creds::from_docker(&docker_section(&dir, "", Some(pw))).unwrap();
        assert_eq!(creds.username, None);
        assert!(matches!(creds.auth(), RegistryAuth::Anonymous));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn from_docker_fails_naming_an_unreadable_file() {
        let dir = creds_dir("missing");
        std::fs::write(dir.join("ca.pem"), b"pem").unwrap();
        let pw = dir.join("absent");

        let err = Creds::from_docker(&docker_section(&dir, "bob", Some(pw.clone())))
            .expect_err("a missing password_file must abort the pull, not go anonymous");
        assert!(
            err.to_string().contains(&pw.display().to_string()),
            "the error must name the path, got {err}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn from_mirror_reads_its_own_account() {
        let dir = creds_dir("mirror");
        std::fs::write(dir.join("ca.pem"), b"pem").unwrap();
        let pw = dir.join("password");
        std::fs::write(&pw, "hub-token\n").unwrap();

        // A mirror's account is independent of `[docker]`'s, so it has its own reader.
        let m = crate::config::Mirror {
            repo: "hq-nexus.example.com:8440".to_string(),
            ca_file: Some(dir.join("ca.pem")),
            username: "alice".to_string(),
            password_file: Some(pw),
            token_file: None,
            insecure: true,
        };
        let creds = Creds::from_mirror(&m).unwrap();
        assert_eq!(creds.username.as_deref(), Some("alice"));
        assert_eq!(creds.password.as_deref(), Some("hub-token"));
        assert!(creds.insecure);
        assert!(matches!(
            creds.auth(),
            RegistryAuth::Basic(u, p) if u == "alice" && p == "hub-token"
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn auth_needs_both_halves_of_the_basic_pair() {
        // Half a pair authenticates as nobody rather than as that user — both directions.
        for (username, password) in [(Some("bob"), None), (None, Some("s3cret"))] {
            let creds = Creds {
                username: username.map(str::to_string),
                password: password.map(str::to_string),
                ..Default::default()
            };
            assert!(
                matches!(creds.auth(), RegistryAuth::Anonymous),
                "half a Basic pair must not authenticate: {creds:?}"
            );
        }
    }

    #[test]
    fn debug_redacts_the_secrets() {
        let creds = Creds {
            username: Some("bob".to_string()),
            password: Some("s3cret".to_string()),
            token: Some("vkr_x".to_string()),
            ca_pem: Some(b"pem".to_vec()),
            insecure: false,
        };
        let shown = format!("{creds:?}");
        assert!(
            !shown.contains("s3cret"),
            "password leaked into Debug: {shown}"
        );
        assert!(!shown.contains("vkr_x"), "token leaked into Debug: {shown}");
        assert!(shown.contains("bob"), "username should still show: {shown}");
    }

    /// A token wins over a password that is also configured, an absent one leaves the
    /// Basic pair — the precedence `[registry]` documents and `vk-registry` applies on
    /// the other side.
    #[test]
    fn a_bearer_token_supersedes_the_basic_pair() {
        let creds = |token: Option<&str>| Creds {
            username: Some("ci".to_string()),
            password: Some("pw".to_string()),
            token: token.map(str::to_string),
            ..Creds::anonymous()
        };
        assert!(matches!(
            creds(Some("vkr_x")).auth(),
            RegistryAuth::Bearer(t) if t == "vkr_x"
        ));
        assert!(matches!(
            creds(None).auth(),
            RegistryAuth::Basic(u, p) if u == "ci" && p == "pw"
        ));
    }

    /// An empty `token_file` is a misconfiguration, not a request to stay anonymous:
    /// sending `Bearer ` only ever 401s, and the path is what says which file to fix.
    #[test]
    fn an_empty_token_file_is_refused_by_name() {
        let dir = creds_dir("token");
        let token = dir.join("token");
        std::fs::write(&token, "  \n").unwrap();
        let files = |token_file| CredFiles {
            section: "[docker]",
            ca_file: None,
            username: "",
            password_file: None,
            token_file: Some(token_file),
            insecure: false,
        };
        let err = Creds::from_files(files(&token))
            .expect_err("an empty token_file must abort the pull, not go anonymous");
        let shown = err.to_string();
        assert!(
            shown.contains(&token.display().to_string()) && shown.contains("[docker]"),
            "the error must name the section and the path, got {err}"
        );

        // A token carries no meaningful surrounding whitespace, so both ends are trimmed.
        std::fs::write(&token, "  vkr_x\n").unwrap();
        let ok = Creds::from_files(files(&token)).unwrap();
        assert_eq!(ok.token.as_deref(), Some("vkr_x"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolve_digest_shortcircuits_a_pinned_ref() {
        // A digest-pinned ref resolves to its embedded digest with no registry round-trip —
        // this test runs offline, which is the whole point (it would otherwise need network).
        let digest = "sha256:865b95f46d98cf867a156fe4a135ad3fe50d2056aa3f25ed31662dff6da4eb62";
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        // Both the tag+digest and the tag-less digest-only forms short-circuit to the digest.
        for reference in [
            format!("alpine:3.23.2@{digest}"),
            format!("alpine@{digest}"),
        ] {
            let got = rt
                .block_on(resolve_digest(&reference))
                .expect("pinned ref must resolve offline");
            assert_eq!(got, digest);
        }
    }

    #[test]
    fn parse_image_config_fields() {
        let json = r#"{"architecture":"amd64","config":{
            "User":"app","WorkingDir":"/srv",
            "Env":["PATH=/usr/local/bin:/bin","LANG=C.UTF-8","BARE"]}}"#;
        let c = parse_config(json);
        assert_eq!(c.user.as_deref(), Some("app"));
        assert_eq!(c.workdir.as_deref(), Some("/srv"));
        assert_eq!(
            c.env,
            vec![
                ("PATH".to_string(), "/usr/local/bin:/bin".to_string()),
                ("LANG".to_string(), "C.UTF-8".to_string()),
            ]
        );
        // empty / missing fields -> None, malformed -> defaults
        let empty = parse_config(r#"{"config":{"User":"","WorkingDir":""}}"#);
        assert!(empty.user.is_none() && empty.workdir.is_none() && empty.env.is_empty());
        assert!(parse_config("not json").env.is_empty());
    }

    #[test]
    fn parse_exposed_ports_keeps_tcp_only_sorted_deduped() {
        // set-valued object keyed by "<port>/<proto>"; udp dropped, tcp (and a
        // proto-less entry, tcp by convention) kept, sorted and deduplicated.
        let json = r#"{"config":{"ExposedPorts":{
            "6379/tcp":{},"53/udp":{},"3306":{},"6379/tcp":{}}}}"#;
        assert_eq!(parse_config(json).exposed_ports, vec![3306, 6379]);
        // absent / empty -> no ports
        assert!(parse_config(r#"{"config":{}}"#).exposed_ports.is_empty());
    }

    #[test]
    fn pax_record_length_counts_itself() {
        assert_eq!(pax_record("k", b"v"), b"6 k=v\n");
        // a longer record whose length crosses a digit boundary still self-consistent:
        // the declared length equals the encoded record's total byte length.
        let r = pax_record("SCHILY.xattr.security.capability", &[0u8; 64]);
        let sp = r.iter().position(|&c| c == b' ').unwrap();
        let declared: usize = std::str::from_utf8(&r[..sp]).unwrap().parse().unwrap();
        assert_eq!(declared, r.len());
    }

    /// A file's `security.capability` xattr must survive the layer flatten: captured
    /// on input (PAX), re-emitted as a PAX header in the merged tar, and read back by
    /// the same reader the ext4 builder uses (`ext4::tar_xattrs`). This is the
    /// regression that broke `ping` (missing cap_net_raw).
    #[test]
    fn xattrs_survive_flatten() {
        // a realistic vfs_cap_data blob (magic/rev + cap_net_raw bit), any bytes do.
        let cap = vec![
            0x01, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // input layer: a PAX xattr header followed by /usr/bin/ping.
        let mut b = tar::Builder::new(Vec::new());
        append_xattr_header(&mut b, &[("security.capability".to_string(), cap.clone())]).unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_path("usr/bin/ping").unwrap();
        h.set_size(4);
        h.set_mode(0o755);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_cksum();
        b.append(&h, &b"ping"[..]).unwrap();
        let layer = b.into_inner().unwrap();

        let mut m = Merger::new(
            crate::scratch::scratch(&std::env::temp_dir(), "test-spill")
                .unwrap()
                .file,
        );
        m.apply_layer(
            Cursor::new(&layer),
            "application/vnd.oci.image.layer.v1.tar",
        )
        .unwrap();
        let mut out = Vec::new();
        m.finish_to(&mut out).unwrap();

        // read the merged tar back; the xattr must be present on the file.
        let mut ar = tar::Archive::new(Cursor::new(&out));
        let mut found = None;
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            if e.path().unwrap().to_string_lossy() == "usr/bin/ping" {
                found = Some(crate::ext4::tar_xattrs(&mut e));
            }
        }
        assert_eq!(
            found.expect("ping entry present in the merged tar"),
            vec![("security.capability".to_string(), cap)],
            "security.capability must survive the flatten"
        );
    }
}
