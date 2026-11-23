//! Online activation and the evaluation lifetime Windows reports for an image.
//!
//! Microsoft's evaluation terms: a Windows Server evaluation must be activated online within 10
//! days and then runs 180 days from activation; Windows 11 Enterprise's evaluation runs 90 days.
//! A generalized (sysprep) image restarts the 10-day activation grace at every machine's first
//! boot, so it carries no clock. A non-generalized one does: its machines inherit whatever its
//! build left, activation (and the 180 days counted from it) included. `vk build` records that
//! in the bundle, and runs of the bundle warn as its end nears. Only Windows on an evaluation
//! (`TIMEBASED_EVAL`) channel ends once activated; retail, volume and KMS activations do not.

use std::io::Write;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::qga::Client;

const DAY: u64 = 24 * 60 * 60;

/// How long before an evaluation ends a run starts warning.
const EVAL_WARN_BEFORE: u64 = 30 * DAY;

/// How long before an unactivated image's grace period ends a run starts warning.
const ACTIVATE_WARN_BEFORE: u64 = 3 * DAY;

/// Windows' licensing state, the minutes left of its grace or evaluation period and its
/// channel (`Description`, e.g. `Windows(R) Operating System, TIMEBASED_EVAL channel`), from
/// the Windows product (its application ID) that has a key. Without progress records:
/// powershell.exe writes them to stderr as CLIXML, after the answer.
const QUERY_PS1: &str = r#"$ProgressPreference = 'SilentlyContinue'; Get-CimInstance SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" | % { "$($_.LicenseStatus) $($_.GracePeriodRemaining) $($_.Description)" }"#;

/// How long [`query`] waits for Windows' answer.
const QUERY_TIMEOUT: Duration = Duration::from_secs(3 * 60);

/// `SoftwareLicensingProduct.LicenseStatus` of an activated Windows.
const LICENSED: u32 = 1;

/// Retry budget for an activation already in progress.
const ACTIVATE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Retry other CIM errors briefly while the guest network comes up.
const ACTIVATE_NET_WAIT: Duration = Duration::from_secs(60);

/// Give the script time to report the last error after its retry budget expires. Each call
/// uses the remaining budget with a five-second minimum, and retries sleep for ten seconds.
const ACTIVATE_MARGIN: Duration = Duration::from_secs(90);

/// Activate unlicensed Windows products with a key, excluding add-ons. Windows can start
/// activation when the network comes up. Retry its busy error (0xC004E028) for `@SECS@`
/// seconds and other caught errors for `@NET@`, sleeping ten seconds between attempts.
/// Recheck licensing after activation. Exit 0 when all products are licensed and print
/// [`ACTIVATED_EARLIER`] if the initial check detects a previously activated evaluation.
/// On failure, print a one-line reason. Exit 1 for failed or unconfirmed activation and 2
/// for no matching product. Keep the activation and status checks in `examples/windows/join.ps1`
/// consistent with these.
const ACTIVATE_PS1: &str = r#"$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'
$windowsFilter = "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL"
$clock = [Diagnostics.Stopwatch]::StartNew()
# A call's timeout: at most $max seconds, and what is left of @SECS@, but at least 5.
function Within([int] $max) { [int][Math]::Max(5, [Math]::Min($max, @SECS@ - $clock.Elapsed.TotalSeconds)) }
$first = $true
$activated = $false
while ($true) {
    try {
        $products = @(Get-CimInstance SoftwareLicensingProduct -Filter $windowsFilter -OperationTimeoutSec (Within 60) | Where-Object { -not $_.LicenseIsAddon })
        if (-not $products) { 'Windows has no product key installed'; exit 2 }
        $pending = @($products | Where-Object { $_.LicenseStatus -ne 1 })
        if (-not $pending) {
            if ($first) {
                # Activated before this boot when the minutes since activation, modulo a day,
                # exceed the uptime. Misses an activation made a whole number of days, plus less
                # than the uptime, before this boot.
                try {
                    $left = ($products | Where-Object { $_.Description -match 'TIMEBASED_EVAL' } | Measure-Object GracePeriodRemaining -Maximum).Maximum
                    $up = ((Get-Date) - (Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec (Within 60)).LastBootUpTime).TotalMinutes
                    if ($left -gt 0 -and (1440 - $left % 1440) % 1440 -gt $up + 1) { '@EARLIER@' }
                } catch {}  # Only a warning depends on it.
            }
            exit 0
        }
        if ($activated) { 'Windows is not activated: still unlicensed after a successful activation'; exit 1 }
        $first = $false
        foreach ($product in $pending) {
            $result = $product | Invoke-CimMethod -MethodName Activate -OperationTimeoutSec (Within 120)
            if ($result.ReturnValue) { throw ('Activate returned 0x{0:X8}' -f $result.ReturnValue) }
        }
        $activated = $true
        # The status read next tells whether the activation took.
        try {
            Get-CimInstance SoftwareLicensingService -OperationTimeoutSec (Within 60) | Invoke-CimMethod -MethodName RefreshLicenseStatus -OperationTimeoutSec (Within 60) | Out-Null
        } catch {}
        continue
    } catch {
        # CIM errors carry the HRESULT in their error id; the message alone can lack it.
        $why = "$($_.Exception.Message)".Trim() -replace '\s+', ' '
        if ("$($_.FullyQualifiedErrorId)" -match '0x[0-9A-F]{8}' -and $why -notmatch $Matches[0]) { $why = "$($Matches[0]): $why" }
        $limit = if ($why -match '0xC004E028') { @SECS@ } else { @NET@ }
        if ($clock.Elapsed.TotalSeconds -ge $limit) {
            if ($activated) { "Windows activation could not be confirmed: $why" } else { "Windows is not activated: $why" }
            exit 1
        }
    }
    Start-Sleep -Seconds 10
}
"#;

/// Marker for an evaluation the initial check identifies as activated before this boot.
const ACTIVATED_EARLIER: &str = "activated-earlier";

fn activate_script() -> String {
    ACTIVATE_PS1
        .replace("@SECS@", &ACTIVATE_TIMEOUT.as_secs().to_string())
        .replace("@NET@", &ACTIVATE_NET_WAIT.as_secs().to_string())
        .replace("@EARLIER@", ACTIVATED_EARLIER)
}

/// Activate Windows online. An already licensed evaluation keeps its original expiry.
/// Warn if the script detects an earlier activation. `allowlist` enables network guidance
/// for activation errors on a restricted build network.
pub(crate) fn activate(ga: &mut Client, allowlist: bool) -> Result<()> {
    let mut out = Bounded::within(ACTIVATE_TIMEOUT + ACTIVATE_MARGIN);
    let code = crate::winexec::powershell_output(ga, &activate_script(), &mut out)
        .context("activating Windows online")?;
    if activated_earlier(code, &String::from_utf8_lossy(&out.out), allowlist)? {
        eprintln!(
            "virtkit: warning: Windows was activated by an earlier step or image; its \
             evaluation runs from then, and this stage cannot renew it"
        );
    }
    Ok(())
}

/// Decode the script's earlier-activation marker or error. With `allowlist`, add network
/// guidance to exit 1 unless Windows was busy or the script reached status confirmation.
fn activated_earlier(code: i32, said: &str, allowlist: bool) -> Result<bool> {
    let said = said.trim();
    let reached = said.to_ascii_lowercase().contains("0xc004e028")
        || said.contains("after a successful activation")
        || said.contains("could not be confirmed");
    match code {
        0 => Ok(said.contains(ACTIVATED_EARLIER)),
        1 if allowlist && !reached => bail!(
            "{said}; activation must reach Microsoft's activation servers, which the build's \
             network allowlist has to let through"
        ),
        1 => bail!("{said}"),
        _ => bail!("activating Windows online: {said}"),
    }
}

/// Tell that Windows could not be asked, and why.
pub(crate) fn warn_unread(e: &anyhow::Error) {
    eprintln!(
        "virtkit: warning: could not read Windows' licensing ({e:#}); \
         the bundle records no evaluation end"
    );
}

/// When an image's Windows stops working unless something is done, in seconds since the epoch;
/// recorded in a bundle's layer record. Empty for a generalized image, one activated for good
/// (retail, volume, KMS), or when Windows could not be asked.
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Evaluation {
    /// An activated evaluation: when it ends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval_expires: Option<u64>,
    /// Not activated: when its activation grace period ends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activate_by: Option<u64>,
}

impl Evaluation {
    /// What a licensing `status` with `grace_minutes` left at `now` comes to, on a `timebased`
    /// (evaluation) channel or another.
    fn of(status: u32, grace_minutes: u64, timebased: bool, now: u64) -> Evaluation {
        let end = Some(now.saturating_add(grace_minutes.saturating_mul(60)));
        match status {
            LICENSED if timebased && grace_minutes > 0 => Evaluation {
                eval_expires: end,
                activate_by: None,
            },
            // Activated for good.
            LICENSED => Evaluation::default(),
            _ => Evaluation {
                eval_expires: None,
                activate_by: end,
            },
        }
    }

    /// The warning a run of the image gives at `now`, if any.
    pub(crate) fn warning(&self, now: u64) -> Option<String> {
        if let Some(end) = self.eval_expires
            && end < now.saturating_add(EVAL_WARN_BEFORE)
        {
            let expires = if end <= now { "expired" } else { "expires" };
            return Some(format!(
                "this image's evaluation {expires} on {}; rebuild it (`vk build`) if it is a \
                 Windows Server evaluation and a stage of it says `# vk: activate=online`, \
                 otherwise from the ISO \
                 (`vk build --reinstall`)",
                date(end)
            ));
        }
        let end = self
            .activate_by
            .filter(|end| *end < now.saturating_add(ACTIVATE_WARN_BEFORE))?;
        let ends = if end <= now { "ended" } else { "ends" };
        Some(format!(
            "this image was never activated and its activation grace period {ends} on {}; \
             activate it (`slmgr /ato`, with a network), rebuild it with \
             `# vk: activate=online` on a stage, or rebuild it from the ISO \
             (`vk build --reinstall`)",
            date(end)
        ))
    }
}

/// The UTC day of `secs` since the epoch, `YYYY-MM-DD` (the format atop names its archive
/// directories in).
fn date(secs: u64) -> String {
    vk_core::atop::date_dir(i64::try_from(secs).unwrap_or(i64::MAX))
}

/// Ask Windows behind `ga` how long it keeps working, within [`QUERY_TIMEOUT`]. On failure,
/// warn and return None: the image records nothing.
pub(crate) fn query(ga: &mut Client) -> Option<Evaluation> {
    match ask(ga) {
        Ok(evaluation) => Some(evaluation),
        Err(e) => {
            warn_unread(&e);
            None
        }
    }
}

/// [`query`], failing when Windows does not tell.
fn ask(ga: &mut Client) -> Result<Evaluation> {
    let mut out = Bounded::within(QUERY_TIMEOUT);
    let code = crate::winexec::powershell_output(ga, QUERY_PS1, &mut out)?;
    let out = String::from_utf8_lossy(&out.out);
    if code != 0 {
        bail!("exit {code}: {out}");
    }
    let (status, grace_minutes, timebased) =
        parse(&out).with_context(|| format!("unexpected answer {out:?}"))?;
    Ok(Evaluation::of(
        status,
        grace_minutes,
        timebased,
        crate::vms::unix_now(),
    ))
}

/// Buffers guest output until the deadline. Each poll calls `flush` to check
/// the deadline, so even a silent command can time out.
struct Bounded {
    out: Vec<u8>,
    deadline: Instant,
    /// Original timeout for the error message.
    timeout: Duration,
}

impl Bounded {
    fn within(timeout: Duration) -> Bounded {
        Bounded {
            out: Vec::new(),
            deadline: Instant::now() + timeout,
            timeout,
        }
    }

    fn check(&self) -> std::io::Result<()> {
        if Instant::now() < self.deadline {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("no answer within {}s", self.timeout.as_secs()),
            ))
        }
    }
}

impl Write for Bounded {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.check()?;
        self.out.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.check()
    }
}

/// Parse the last `<LicenseStatus> <GracePeriodRemaining> <Description>` line from
/// [`QUERY_PS1`]'s output, which includes stderr and CLIXML. Return the status, minutes left,
/// and whether the channel is an evaluation's.
fn parse(out: &str) -> Option<(u32, u64, bool)> {
    out.lines().rev().find_map(|line| {
        let mut words = line.trim().splitn(3, ' ');
        let status = words.next()?.parse().ok()?;
        let grace_minutes = words.next()?.parse().ok()?;
        let timebased = words.next().is_some_and(|d| d.contains("TIMEBASED_EVAL"));
        Some((status, grace_minutes, timebased))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVAL: &str = "Windows(R) Operating System, TIMEBASED_EVAL channel";

    #[test]
    fn the_answer_is_status_minutes_and_channel_on_the_last_line_that_is_one() {
        assert_eq!(
            parse(&format!("1 259200 {EVAL}\r\n")),
            Some((1, 259200, true))
        );
        assert_eq!(
            parse(
                "a warning\r\n2 14400 Windows(R) Operating System, VOLUME_KMSCLIENT channel\r\n\r\n"
            ),
            Some((2, 14400, false))
        );
        assert_eq!(parse("1 0\r\n"), Some((1, 0, false)));
        // powershell.exe's progress records, on stderr after the answer.
        assert_eq!(
            parse(&format!(
                "#< CLIXML\r\n1 259174 {EVAL}\r\n<Objs Version=\"1.1.0.1\" \
                 xmlns=\"http://schemas.microsoft.com/powershell/2004/04\"><Obj S=\"progress\">\
                 </Obj></Objs>"
            )),
            Some((1, 259174, true))
        );
        assert_eq!(parse(""), None);
        assert_eq!(parse("1\r\n"), None);
        assert_eq!(parse("1 -5\r\n"), None);
    }

    #[test]
    fn only_activated_evaluations_expire_and_unactivated_windows_must_activate() {
        let now = 1_000_000_000;
        // Windows Server evaluation after `slmgr /ato`: 180 days from now.
        assert_eq!(
            Evaluation::of(1, 259200, true, now),
            Evaluation {
                eval_expires: Some(now + 180 * DAY),
                activate_by: None,
            }
        );
        // Not activated: its 10-day grace, whatever the channel.
        let unactivated = Evaluation {
            eval_expires: None,
            activate_by: Some(now + 10 * DAY),
        };
        assert_eq!(Evaluation::of(2, 14400, true, now), unactivated);
        assert_eq!(Evaluation::of(2, 14400, false, now), unactivated);
        // Activated for good: an evaluation with no time left reported, or a KMS, volume or
        // retail activation, whatever grace it reports.
        assert_eq!(Evaluation::of(1, 0, true, now), Evaluation::default());
        assert_eq!(Evaluation::of(1, 259200, false, now), Evaluation::default());
    }

    #[test]
    fn a_run_warns_near_and_past_the_end_only() {
        let end = 1_000_000_000;
        let expiring = Evaluation {
            eval_expires: Some(end),
            activate_by: None,
        };
        assert_eq!(expiring.warning(end - 31 * DAY), None);
        let near = expiring.warning(end - 29 * DAY).unwrap();
        assert!(near.contains("evaluation expires on 2001-09-09"), "{near}");
        let past = expiring.warning(end + DAY).unwrap();
        assert!(past.contains("evaluation expired on 2001-09-09"), "{past}");

        let unactivated = Evaluation {
            eval_expires: None,
            activate_by: Some(end),
        };
        assert_eq!(unactivated.warning(end - 4 * DAY), None);
        let near = unactivated.warning(end - 2 * DAY).unwrap();
        assert!(near.contains("grace period ends on 2001-09-09"), "{near}");
        let past = unactivated.warning(end + DAY).unwrap();
        assert!(past.contains("grace period ended on 2001-09-09"), "{past}");

        // Nothing recorded: nothing to tell.
        assert_eq!(Evaluation::default().warning(end), None);
    }

    #[test]
    fn the_activation_script_has_no_placeholder_left() {
        let script = activate_script();
        // `@(` is PowerShell's array subexpression; a placeholder is `@NAME@`.
        assert!(
            script
                .match_indices('@')
                .all(|(i, _)| !script[i + 1..].starts_with(|c: char| c.is_ascii_uppercase())),
            "{script}"
        );
        assert!(script.contains("{ 300 } else { 60 }"), "{script}");
    }

    #[test]
    fn the_activation_outcome_follows_the_scripts_exit_code() {
        assert!(!activated_earlier(0, "\r\n", false).unwrap());
        assert!(activated_earlier(0, &format!("{ACTIVATED_EARLIER}\r\n"), false).unwrap());
        let refused = "Windows is not activated: 0xc004f074: no KMS";
        let err = activated_earlier(1, refused, false)
            .unwrap_err()
            .to_string();
        assert_eq!(err, refused);
        let err = activated_earlier(1, refused, true).unwrap_err().to_string();
        assert!(
            err.starts_with(refused) && err.contains("allowlist"),
            "{err}"
        );
        // Busy and post-activation errors omit the allowlist hint.
        for said in [
            "Windows is not activated: 0xc004e028: busy",
            "Windows is not activated: still unlicensed after a successful activation",
            "Windows activation could not be confirmed: 0x80041033: shutting down",
        ] {
            let err = activated_earlier(1, said, true).unwrap_err().to_string();
            assert_eq!(err, said);
        }
        let err = activated_earlier(2, "Windows has no product key installed", true)
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "activating Windows online: Windows has no product key installed"
        );
    }

    #[test]
    fn the_query_output_refuses_writes_after_its_deadline() {
        let mut out = Bounded::within(Duration::from_secs(60));
        out.write_all(b"1 0").unwrap();
        out.flush().unwrap();
        out.deadline = Instant::now();
        let e = out.flush().unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::TimedOut);
        assert!(e.to_string().contains("no answer within 60s"), "{e}");
        assert!(out.write_all(b"x").is_err());
        assert_eq!(out.out, b"1 0");
    }
}
