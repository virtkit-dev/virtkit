//! The `--config` file's key reference, rendered for `vk-registry serve --help`.
//!
//! Operator prose, but it lives beside the parser rather than in the binary for one
//! reason: it is generated from [`KEYS`], and the test below holds that table against the
//! field names `serde` will actually accept — in both directions. A key added to the
//! config without a line here fails the build's tests, and so does a line here naming a
//! key the parser would reject. This is the format's only complete reference, so "the
//! code is the reference" would otherwise leave operators reading `config.rs`.

use std::fmt::Write as _;
use std::sync::LazyLock;

/// Which table of the config file a key belongs to. Also its heading, and how the test
/// picks the field set to check a key against.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Table {
    /// the file's top level
    Top,
    /// `[oidc]`
    Oidc,
    /// `[[upstream]]`, repeatable
    Upstream,
}

/// One config-file key: where it lives, what it is called, and what it does. The order
/// here is the order it prints in, grouped by table.
struct Key {
    table: Table,
    name: &'static str,
    help: &'static str,
}

/// Every key the config file accepts. Kept in the parser's own order per table so a
/// reader comparing this against `FileConfig` sees the same sequence.
const KEYS: &[Key] = &[
    Key {
        table: Table::Top,
        name: "addr",
        help: "listen address; --addr wins [default: 127.0.0.1:5000]",
    },
    Key {
        table: Table::Top,
        name: "root",
        help: "store directory; --root wins [default: the shared store]",
    },
    Key {
        table: Table::Top,
        name: "tls_cert",
        help: "PEM certificate chain; with tls_key, serves HTTPS\n\
               (required once auth is configured on a non-loopback address)",
    },
    Key {
        table: Table::Top,
        name: "tls_key",
        help: "its PEM private key; set both or neither",
    },
    Key {
        table: Table::Top,
        name: "token_file",
        help: "file holding the one bearer token every client sends",
    },
    Key {
        table: Table::Top,
        name: "username",
        help: "HTTP Basic user, as an alternative to token_file",
    },
    Key {
        table: Table::Top,
        name: "password_file",
        help: "file holding that user's password",
    },
    Key {
        table: Table::Top,
        name: "mode",
        help: "\"shared-secret\" (default) or \"accounts\"",
    },
    Key {
        table: Table::Top,
        name: "accounts_db",
        help: "accounts database, in accounts mode only\n\
               [default: <root>/accounts/accounts.db]",
    },
    Key {
        table: Table::Top,
        name: "oidc",
        help: "the [oidc] table below; required in accounts mode",
    },
    Key {
        table: Table::Top,
        name: "upstream",
        help: "the [[upstream]] tables below; none = no relay",
    },
    Key {
        table: Table::Oidc,
        name: "issuer",
        help: "the provider's issuer URL; discovery is fetched from it",
    },
    Key {
        table: Table::Oidc,
        name: "client_id",
        help: "this server's client id at that provider",
    },
    Key {
        table: Table::Oidc,
        name: "client_secret_file",
        help: "file holding its client secret",
    },
    Key {
        table: Table::Oidc,
        name: "public_url",
        help: "this server's own base URL, for the redirect URI",
    },
    Key {
        table: Table::Upstream,
        name: "prefix",
        help: "repo-name prefix, longest match wins; omitted = catch-all",
    },
    Key {
        table: Table::Upstream,
        name: "url",
        help: "the upstream's base URL",
    },
    Key {
        table: Table::Upstream,
        name: "username",
        help: "HTTP Basic user for the upstream, if it wants one",
    },
    Key {
        table: Table::Upstream,
        name: "password_file",
        help: "file holding that password",
    },
    Key {
        table: Table::Upstream,
        name: "ca_file",
        help: "extra PEM CA certificate for the upstream's TLS",
    },
];

/// A shared-secret deployment, TLS terminated here, relaying what it does not hold.
/// Printed verbatim and parsed by the test, so it is an example that loads.
const EXAMPLE_SHARED: &str = "\
addr = \"0.0.0.0:5000\"
root = \"/srv/vk-registry\"
tls_cert = \"/etc/vk-registry/fullchain.pem\"
tls_key = \"/etc/vk-registry/privkey.pem\"
token_file = \"/etc/vk-registry/token\"

[[upstream]]
prefix = \"docker.io\"
url = \"https://registry-1.docker.io\"
username = \"ci\"
password_file = \"/etc/vk-registry/upstream-password\"
ca_file = \"/etc/vk-registry/upstream-ca.pem\"
";

/// The accounts model: people sign in through the identity provider, machines use
/// scoped API keys (`vk-registry accounts`). Also printed verbatim and parsed.
const EXAMPLE_ACCOUNTS: &str = "\
addr = \"0.0.0.0:5000\"
root = \"/srv/vk-registry\"
tls_cert = \"/etc/vk-registry/fullchain.pem\"
tls_key = \"/etc/vk-registry/privkey.pem\"
mode = \"accounts\"
accounts_db = \"/srv/vk-registry/accounts/accounts.db\"

[oidc]
issuer = \"https://id.example.com\"
client_id = \"vk-registry\"
client_secret_file = \"/etc/vk-registry/oidc-secret\"
public_url = \"https://registry.example.com\"
";

/// The `--config` reference, as `serve --help`'s trailing section.
///
/// Built rather than written out so [`KEYS`] stays the only place a key is named, behind
/// a `LazyLock` so the rendered text can be handed to `clap` as a `&'static str`; the cost
/// is one small `String` per process. The examples go in unindented so they can be pasted
/// straight into a file, with lines short enough that `clap`'s wrapping leaves them alone.
pub fn config_file_help() -> &'static str {
    static HELP: LazyLock<String> = LazyLock::new(render);
    &HELP
}

fn render() -> String {
    let mut out = String::from(
        "Config file (--config), TOML. Every top-level key is optional — with no config \
         file at all, `serve` listens on 127.0.0.1:5000, serves the shared store over \
         plain HTTP, authenticates nobody, and relays nothing. The keys inside [oidc] \
         are all required once that table is written; an [[upstream]] needs only url.\n",
    );
    // One column across all three tables, so the reference reads as one list rather than
    // three differently-indented ones. `fmt::Write` into a `String` cannot fail, which is
    // why every `write!` below discards its result.
    let width = KEYS.iter().map(|k| k.name.len()).max().unwrap_or(0);
    for (table, heading) in [
        (Table::Top, "Top-level keys:"),
        (
            Table::Oidc,
            "[oidc] — the login provider, required in accounts mode:",
        ),
        (
            Table::Upstream,
            "[[upstream]] — repeat one table per upstream registry:",
        ),
    ] {
        let _ = writeln!(out, "\n{heading}");
        for key in KEYS.iter().filter(|k| k.table == table) {
            // A multi-line `help` continues under the description column, not under the
            // key: the second line is the rest of a sentence, not another key.
            let mut lines = key.help.lines();
            let first = lines.next().unwrap_or("");
            let _ = writeln!(out, "  {:width$}  {first}", key.name);
            for cont in lines {
                let _ = writeln!(out, "  {:width$}  {cont}", "");
            }
        }
    }
    let _ = write!(
        out,
        "\nA shared-secret server that also relays:\n\n{EXAMPLE_SHARED}\
         \nOr with accounts and OIDC login instead of a shared secret \
         (mutually exclusive with token_file/username/password_file):\n\n{EXAMPLE_ACCOUNTS}"
    );
    out
}

#[cfg(test)]
mod tests {
    use super::super::{FileConfig, FileOidc, FileUpstream};
    use super::*;

    /// The field names a table will accept, taken from the parser itself: with
    /// `deny_unknown_fields`, `serde`'s error for an unknown key names every known one.
    /// Reading them out of the error rather than repeating them here is the point — a
    /// list repeated in the test would drift with the documentation, not against it.
    fn accepted(err: &str) -> Vec<String> {
        let (_, list) = err.split_once("expected one of ").unwrap_or_else(|| {
            panic!("no field list in the unknown-field error, so this test proves nothing: {err}")
        });
        list.split(',')
            .map(|f| f.trim().trim_matches('`').to_string())
            .filter(|f| !f.is_empty())
            .collect()
    }

    fn documented(table: Table) -> Vec<String> {
        KEYS.iter()
            .filter(|k| k.table == table)
            .map(|k| k.name.to_string())
            .collect()
    }

    /// Every key the config file accepts is documented, and every key documented is one
    /// it accepts — the second half is what catches a typo in the reference, which would
    /// otherwise send an operator to write a key the server refuses to start on.
    #[test]
    fn the_key_reference_matches_what_the_parser_accepts() {
        let top = toml::from_str::<FileConfig>("nope = 1\n").map(|_| ());
        let oidc = toml::from_str::<FileOidc>("nope = 1\n").map(|_| ());
        let upstream = toml::from_str::<FileUpstream>("nope = 1\n").map(|_| ());
        for (table, err) in [
            (Table::Top, top.unwrap_err()),
            (Table::Oidc, oidc.unwrap_err()),
            (Table::Upstream, upstream.unwrap_err()),
        ] {
            let mut accepted = accepted(&err.to_string());
            let mut documented = documented(table);
            assert!(!accepted.is_empty(), "{err}");
            accepted.sort();
            documented.sort();
            assert_eq!(documented, accepted, "in {err}");
        }
    }

    /// The examples are configs, not prose: they parse, and they parse as the tables they
    /// claim to be. A `serve --help` example an operator cannot paste is worse than none.
    #[test]
    fn both_examples_parse_and_are_printed_verbatim() {
        for example in [EXAMPLE_SHARED, EXAMPLE_ACCOUNTS] {
            toml::from_str::<FileConfig>(example)
                .unwrap_or_else(|e| panic!("example does not parse: {e}\n{example}"));
            // Printed unindented and unwrapped, so what parsed above is what is shown.
            assert!(config_file_help().contains(example), "{example}");
        }
    }

    /// Both examples have to be configs the server would actually start on, not just TOML
    /// it can parse: the auth keys' mutual exclusions are `load`'s check, and refusing
    /// credentials in cleartext is `into_state`'s. An example that trips either is an
    /// example nobody can use.
    #[test]
    fn both_examples_are_configs_the_server_would_start_on() {
        let dir = std::env::temp_dir().join(format!("vk-reg-help-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (name, example) in [
            ("shared.toml", EXAMPLE_SHARED),
            ("accounts.toml", EXAMPLE_ACCOUNTS),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, example).unwrap();
            let cfg = super::super::ServerConfig::load(&path, None, None)
                .unwrap_or_else(|e| panic!("{name} does not load: {e:#}"));
            // Checked without a store or a socket: an example that binds a routable
            // address with credentials in play and no TLS is one the server refuses,
            // whatever the parser makes of it.
            cfg.check_no_cleartext_creds()
                .unwrap_or_else(|e| panic!("{name} would not start: {e:#}"));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
