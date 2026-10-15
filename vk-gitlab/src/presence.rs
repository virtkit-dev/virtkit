//! Sends the hub this daemon's host, version and runners at startup and every minute,
//! for display beside its API key. Hello failures do not affect jobs. A hub without hello
//! support returns a 404 without a code; no further hellos are sent to it.
//! The hello excludes runner tokens and the hub's API key, and strips credentials, query
//! and fragment from runner URLs.

use std::sync::Arc;
use std::time::Duration;

use reqwest::Url;
use vk_hub_proto::client::{
    ClientHello, ClientRunner, MAX_CLIENT_RUNNER_LABELS, MAX_CLIENT_RUNNERS,
};

use crate::config::Config;
use crate::hub::HubClient;

/// Interval between hellos.
pub const HELLO_INTERVAL: Duration = Duration::from_secs(60);

/// Builds this daemon's hello as `instance`, omitting runners and labels beyond the hub's limits.
pub fn hello_for(cfg: &Config, instance: &str) -> ClientHello {
    ClientHello {
        instance: instance.to_owned(),
        program: "vk-gitlab".to_owned(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        hostname: hostname(),
        concurrent: Some(u32::try_from(cfg.concurrent).unwrap_or(u32::MAX)),
        runners: cfg
            .runners
            .iter()
            .take(MAX_CLIENT_RUNNERS)
            .map(|r| ClientRunner {
                name: r.name.clone(),
                url: public_url(&r.url),
                pool: r.pool.clone(),
                labels: r
                    .labels
                    .iter()
                    .take(MAX_CLIENT_RUNNER_LABELS)
                    .cloned()
                    .collect(),
                limit: (r.limit > 0).then(|| u32::try_from(r.limit).unwrap_or(u32::MAX)),
            })
            .collect(),
    }
}

/// Sends `hello` now and every `every`, until aborted or the hub reports no hello support.
/// Failures are logged, never returned.
pub async fn report(hub: Arc<HubClient>, hello: ClientHello, every: Duration) {
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut failing = false;
    loop {
        tick.tick().await;
        match hub.hello(&hello).await {
            Ok(()) => {
                if failing {
                    log::info!("The hub takes this daemon's hello again");
                }
                failing = false;
            }
            // The contract's sign of a hub without `/v1/clients`; a 404 with a code is
            // the hub's own answer, failed like any other. Hellos resume on restart.
            Err(e) if e.status == Some(404) && !e.coded => {
                log::info!(
                    "The hub predates client hellos; it is not told this daemon's host and runners until a restart"
                );
                return;
            }
            // Warned once per run of failures: the next tick tries again.
            Err(e) if failing => {
                log::debug!(error = e.to_string().as_str(); "Telling the hub about this daemon failed");
            }
            Err(e) => {
                failing = true;
                log::warn!(error = e.to_string().as_str(); "Telling the hub about this daemon failed; retrying");
            }
        }
    }
}

/// The host's name, as the hub lists the instance.
fn hostname() -> String {
    // If unreadable, send the informational hello with an empty hostname.
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_owned())
        .unwrap_or_default()
}

/// `url` without credentials, query or fragment; empty when it does not parse.
fn public_url(url: &str) -> String {
    let Ok(mut url) = Url::parse(url) else {
        return String::new();
    };
    // Both fail only for a URL without a host, which has no credentials to drop.
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.into()
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::path::Path;

    use super::*;

    const RUNNER_TOKEN: &str = "glrt-RUNNERSECRET-tail0123456789";

    fn hub_key() -> String {
        format!("vkk_{}", "5e".repeat(32))
    }

    #[test]
    fn hello_never_carries_a_credential() {
        let cfg = Config::parse(
            &format!(
                "concurrent = 4\n\
                 [hub]\nurl = \"https://hub:8443\"\napi_key = \"{}\"\n\
                 [[runners]]\nname = \"ci\"\n\
                 url = \"https://bob:PASSWORD@gitlab.example.com/sub/?private_token=QUERY#FRAGMENT\"\n\
                 token = \"{RUNNER_TOKEN}\"\npool = \"big\"\nlabels = [\"kvm\"]\nlimit = 2\n",
                hub_key()
            ),
            Path::new("/"),
        )
        .unwrap();
        let hello = hello_for(&cfg, "s_0123456789ab");
        let json = serde_json::to_string(&hello).unwrap();
        for secret in [
            "RUNNERSECRET",
            &hub_key(),
            "bob",
            "PASSWORD",
            "QUERY",
            "FRAGMENT",
        ] {
            assert!(!json.contains(secret), "{secret}: {json}");
        }
        assert_eq!(hello.instance, "s_0123456789ab");
        assert_eq!(hello.program, "vk-gitlab");
        assert_eq!(hello.concurrent, Some(4));
        assert_eq!(
            hello.runners,
            [ClientRunner {
                name: "ci".to_owned(),
                url: "https://gitlab.example.com/sub/".to_owned(),
                pool: "big".to_owned(),
                labels: vec!["kvm".to_owned()],
                limit: Some(2),
            }]
        );
    }

    #[test]
    fn hello_stays_within_the_hubs_limits() {
        let labels: Vec<String> = (0..40).map(|i| format!("\"l{i}\"")).collect();
        let mut text = String::new();
        for i in 0..70 {
            let _ = write!(
                text,
                "[[runners]]\nname = \"r{i}\"\nurl = \"https://g\"\ntoken = \"t{i}\"\n\
                 labels = [{}]\n",
                labels.join(", ")
            );
        }
        let cfg = Config::parse(&text, Path::new("/")).unwrap();
        let hello = hello_for(&cfg, "s_0123456789ab");
        assert_eq!(hello.runners.len(), MAX_CLIENT_RUNNERS);
        assert!(
            hello
                .runners
                .iter()
                .all(|r| r.labels.len() == MAX_CLIENT_RUNNER_LABELS && r.limit.is_none())
        );
        assert_eq!(hello.concurrent, Some(1));
    }

    #[test]
    fn unparsable_urls_go_empty() {
        assert_eq!(public_url("not a url"), "");
        assert_eq!(
            public_url("http://u@gitlab:8080/x#y"),
            "http://gitlab:8080/x"
        );
    }
}
