//! Configure a Windows guest on a host tap (`vk run --tap`, compose `x-virtkit.tap`) over
//! qemu-ga once it answers: Windows reads no kernel command line, so PowerShell through
//! [`crate::winexec`] applies its static address and the run's names in its hosts file.
//! Both scripts are idempotent for disks kept across runs (`--state-dir`) and restarted
//! guests. A DHCP tap turns DHCP back on if an earlier run left a static address on disk.

use anyhow::{Result, bail};

use crate::net::TapNet;
use crate::qga::Client;

/// The lines of the hosts file vk owns, between these markers.
const HOSTS_BEGIN: &str = "# BEGIN virtkit";
const HOSTS_END: &str = "# END virtkit";

/// `s` as a PowerShell single-quoted string.
fn quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// The PowerShell setting up the adapter with `tap`'s MAC: its static address, gateway and
/// nameservers with DHCP off, or for a DHCP tap, DHCP on with the nameservers it hands out. A
/// static address and default route are replaced only when they differ, since
/// `New-NetIPAddress` refuses an address the adapter already holds; DHCP is turned on only when
/// it is off.
pub(crate) fn address_script(tap: &TapNet) -> String {
    let mac = quoted(&tap.mac.replace(':', "-").to_ascii_uppercase());
    let head = format!(
        r#"$ErrorActionPreference = 'Stop'
$a = Get-NetAdapter | Where-Object MacAddress -eq {mac}
if (-not $a) {{ Write-Output "no network adapter has the tap's MAC {mac}"; exit 1 }}
$i = $a.ifIndex
$dhcp = (Get-NetIPInterface -InterfaceIndex $i -AddressFamily IPv4).Dhcp
"#
    );
    let Some((ip, prefix, gw, dns)) = &tap.addr else {
        return head
            + r#"if ($dhcp -eq 'Disabled') {
  Remove-NetRoute -InterfaceIndex $i -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue
  Remove-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
  Set-NetIPInterface -InterfaceIndex $i -AddressFamily IPv4 -Dhcp Enabled
  Set-DnsClientServerAddress -InterfaceIndex $i -ResetServerAddresses
}
"#;
    };
    let (ip, gw) = (quoted(&ip.to_string()), quoted(&gw.to_string()));
    let dns: Vec<String> = dns.iter().map(|d| quoted(&d.to_string())).collect();
    let dns = dns.join(",");
    head + &format!(
        r#"$ip = @(Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
$gw = @(Get-NetRoute -InterfaceIndex $i -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
if ($dhcp -ne 'Disabled' -or $ip.Count -ne 1 -or $ip[0].IPAddress -ne {ip} -or $ip[0].PrefixLength -ne {prefix} -or $gw.Count -ne 1 -or $gw[0].NextHop -ne {gw}) {{
  Set-NetIPInterface -InterfaceIndex $i -AddressFamily IPv4 -Dhcp Disabled
  Remove-NetRoute -InterfaceIndex $i -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue
  Remove-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
  New-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4 -IPAddress {ip} -PrefixLength {prefix} -DefaultGateway {gw} | Out-Null
}}
Set-DnsClientServerAddress -InterfaceIndex $i -ServerAddresses {dns}
"#
    )
}

/// PowerShell that pins `hosts` (name, ip) in the guest's hosts file, replacing the previous
/// run's block and preserving the rest of the file.
pub(crate) fn hosts_script(hosts: &[(String, String)]) -> String {
    let lines: Vec<String> = hosts
        .iter()
        .map(|(name, ip)| format!("$keep.Add({})", quoted(&format!("{ip} {name}"))))
        .collect();
    format!(
        r#"$ErrorActionPreference = 'Stop'
$f = "$env:SystemRoot\System32\drivers\etc\hosts"
$keep = New-Object System.Collections.Generic.List[string]
$mine = $false
foreach ($l in @(Get-Content -LiteralPath $f -ErrorAction SilentlyContinue)) {{
  if ($l -eq {begin}) {{ $mine = $true }} elseif ($l -eq {end}) {{ $mine = $false }} elseif (-not $mine) {{ $keep.Add($l) }}
}}
$keep.Add({begin})
{lines}
$keep.Add({end})
[IO.File]::WriteAllLines($f, $keep)
Clear-DnsClientCache
"#,
        begin = quoted(HOSTS_BEGIN),
        end = quoted(HOSTS_END),
        lines = lines.join("\n"),
    )
}

/// Configure the Windows guest behind `ga` for `tap`: its address ([`address_script`]),
/// then any `hosts` (name, ip) in its hosts file.
pub(crate) fn configure(ga: &mut Client, tap: &TapNet, hosts: &[(String, String)]) -> Result<()> {
    let code = crate::winexec::powershell(ga, &address_script(tap), "tap address")?;
    if code != 0 {
        bail!("setting the tap's address in the guest exited {code}");
    }
    if !hosts.is_empty() {
        let code = crate::winexec::powershell(ga, &hosts_script(hosts), "hosts file")?;
        if code != 0 {
            bail!("pinning the run's names in the guest's hosts file exited {code}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    fn static_tap() -> TapNet {
        TapNet::new(
            "vktap0",
            Some("52:54:00:AB:cd:01"),
            Some("192.168.77.10/24"),
            Some(Ipv4Addr::new(192, 168, 77, 1)),
            &[Ipv4Addr::new(192, 168, 77, 1), Ipv4Addr::new(9, 9, 9, 9)],
        )
        .unwrap()
    }

    #[test]
    fn a_static_tap_sets_the_address_of_the_adapter_with_its_mac() {
        let script = address_script(&static_tap());
        assert!(script.contains("Where-Object MacAddress -eq '52-54-00-AB-CD-01'"));
        assert!(script.contains("-Dhcp Disabled"));
        assert!(script.contains(
            "New-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4 -IPAddress '192.168.77.10' \
             -PrefixLength 24 -DefaultGateway '192.168.77.1'"
        ));
        assert!(script.contains("-ServerAddresses '192.168.77.1','9.9.9.9'"));
        // Replaced only when it differs: a second run finds it in place.
        assert!(script.contains("$ip[0].IPAddress -ne '192.168.77.10'"));
        assert!(script.contains("$gw[0].NextHop -ne '192.168.77.1'"));
    }

    #[test]
    fn a_dhcp_tap_turns_dhcp_back_on_only_where_it_is_off() {
        let tap = TapNet::new("vktap0", Some("52:54:00:00:00:02"), None, None, &[]).unwrap();
        let script = address_script(&tap);
        assert!(script.contains("Where-Object MacAddress -eq '52-54-00-00-00-02'"));
        assert!(script.contains(
            "if ($dhcp -eq 'Disabled') {\n  Remove-NetRoute -InterfaceIndex $i \
             -DestinationPrefix '0.0.0.0/0'"
        ));
        assert!(script.contains("-Dhcp Enabled"));
        assert!(
            script.contains("Set-DnsClientServerAddress -InterfaceIndex $i -ResetServerAddresses")
        );
        assert!(!script.contains("New-NetIPAddress"));
    }

    #[test]
    fn the_hosts_block_replaces_the_last_one_and_quotes_what_it_writes() {
        let script = hosts_script(&[
            ("web".into(), "192.168.127.3".into()),
            ("o'brien".into(), "192.168.127.4".into()),
        ]);
        assert!(script.contains("if ($l -eq '# BEGIN virtkit') { $mine = $true }"));
        assert!(script.contains("elseif ($l -eq '# END virtkit') { $mine = $false }"));
        assert!(script.contains(
            "$keep.Add('# BEGIN virtkit')\n$keep.Add('192.168.127.3 web')\n\
             $keep.Add('192.168.127.4 o''brien')\n$keep.Add('# END virtkit')"
        ));
    }

    /// Run [`configure`] against a fake agent on which every program exits `exit`; return the
    /// result and the PowerShell scripts it ran, in order.
    fn configure_with(
        tap: &TapNet,
        hosts: &[(String, String)],
        exit: i32,
    ) -> (Result<()>, Vec<String>) {
        use crate::qga::tests::{client, synced};
        let scripts = Arc::new(Mutex::new(Vec::new()));
        let seen = scripts.clone();
        // The file being written: whether it is a script, and its bytes.
        let writing = Arc::new(Mutex::new((false, Vec::new())));
        let mut ga = client(move |request| {
            let args = &request["arguments"];
            let reply = match request["execute"].as_str() {
                Some("guest-sync-delimited") => return synced(request),
                Some("guest-file-open") => {
                    let path = args["path"].as_str().unwrap();
                    if path.ends_with(".exit") {
                        serde_json::json!(2)
                    } else if path.ends_with(".seg") {
                        return b"{\"error\": {\"class\": \"GenericError\", \"desc\": \"no\"}}\n"
                            .to_vec();
                    } else {
                        *writing.lock().unwrap() = (path.ends_with(".ps1"), Vec::new());
                        serde_json::json!(1)
                    }
                }
                Some("guest-file-write") => {
                    let bytes =
                        crate::sshagent::b64_decode(args["buf-b64"].as_str().unwrap()).unwrap();
                    let count = bytes.len();
                    writing.lock().unwrap().1.extend(bytes);
                    serde_json::json!({ "count": count, "eof": false })
                }
                Some("guest-file-close") => {
                    if args["handle"] == 1 {
                        let (script, bytes) = std::mem::take(&mut *writing.lock().unwrap());
                        if script {
                            let text = String::from_utf8(bytes).unwrap();
                            seen.lock()
                                .unwrap()
                                .push(text.trim_start_matches('\u{feff}').into());
                        }
                    }
                    serde_json::json!({})
                }
                Some("guest-file-read") => {
                    let body = format!("{exit} 0");
                    let b64 = crate::sshagent::b64_encode(body.as_bytes());
                    serde_json::json!({ "count": body.len(), "buf-b64": b64, "eof": true })
                }
                Some("guest-exec") => serde_json::json!({ "pid": 1 }),
                Some("guest-exec-status") => serde_json::json!({ "exited": true, "exitcode": 0 }),
                _ => serde_json::json!({}),
            };
            format!("{}\n", serde_json::json!({ "return": reply })).into_bytes()
        });
        let result = configure(&mut ga, tap, hosts);
        let scripts = scripts.lock().unwrap().clone();
        (result, scripts)
    }

    #[test]
    fn configure_sets_the_address_then_the_hosts_through_powershell() {
        let tap = static_tap();
        let hosts = [("web".to_string(), "192.168.127.3".to_string())];
        let (result, scripts) = configure_with(&tap, &hosts, 0);
        result.unwrap();
        assert_eq!(scripts, [address_script(&tap), hosts_script(&hosts)]);
    }

    #[test]
    fn a_tap_without_siblings_runs_only_its_address_and_a_failure_is_an_error() {
        let dhcp = TapNet::new("vktap0", None, None, None, &[]).unwrap();
        let (result, scripts) = configure_with(&dhcp, &[], 0);
        result.unwrap();
        assert_eq!(scripts, [address_script(&dhcp)]);
        let (result, _) = configure_with(&static_tap(), &[], 1);
        let err = result.unwrap_err().to_string();
        assert!(err.contains("tap's address"), "{err}");
    }
}
