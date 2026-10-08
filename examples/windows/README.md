# Windows examples

Windows guests built by `vk build` from Microsoft's evaluation ISOs and brought up with
`vk run --compose`, from the simplest to the most involved. Every guest boots natively in vk's
VMM; the host needs only KVM.

The Windows Dockerfiles read these ISOs from this directory, pinned by digest:

| File | What | Where from |
|---|---|---|
| `ws2025-eval-en-us.iso` | Windows Server 2025 evaluation, en-us | Microsoft Evaluation Center |
| `virtio-win.iso` | virtio-win drivers and qemu-ga | fedorapeople.org, virtio-win direct downloads |
| `win11-ent-eval-en-us.iso` | Windows 11 Enterprise evaluation, en-us (`win11.Dockerfile` only) | Microsoft Evaluation Center |

Microsoft's evaluation terms: Server evaluations must be activated online within 10 days and
then run 180 days from activation; Windows 11 Enterprise evaluation 90 days. Evaluation media
is for evaluation only: see Microsoft's terms before sharing images built from it. A
generalized image (`generalize=on`) starts a new 10-day grace on each machine; one that is not
carries its build's licensing, and `vk run` and compose warn as its evaluation nears its end.
A lab member's provisioning (`join.ps1`) activates an unactivated Windows at every start when
the lab reaches the Internet: unactivated past its grace, a Windows 11 evaluation shuts down
every hour.
`vk build --reinstall` (with the same `-f` and `--target`) installs Windows again under new
cache keys and rebuilds the image; bundles built on the old install keep working until they
are rebuilt.

The first build installs Windows (about 20 minutes, 70 for Windows 11); every later step is a
cached layer, shared between the Dockerfiles that start the same way. Every lab password
(`secrets/`, and the DSRM password in `promote.ps1`) is public and an example only: never expose
a lab to a real network.

## 1. A web server — `iis.compose.yaml`

One Windows Server running IIS, and a Linux client on the same LAN that fetches its page by the
server's service name once the server's healthcheck passes.

```sh
vk build -f iis.Dockerfile --out ./iis-out
vk run --compose iis.compose.yaml
```

Shows: a Windows image from a Dockerfile (`RUN`, `COPY`), a Windows service with a
healthcheck, and a Linux service depending on it.

## 2. An Active Directory domain — `lab-ad.compose.yaml`

A domain controller for corp.lab (promoted at build), a Linux job that creates the domain's
users with samba-tool (`accounts.Dockerfile`), two generalized members that join the domain
under their service names at start and find those users, and a Linux job that signs in over RDP
(FreeRDP, Network Level Authentication) to every machine as the domain's admin
(`rdp-check.Dockerfile`).

```sh
vk build -f lab.Dockerfile --target dc --out ./dc-out
vk build -f lab.Dockerfile --target member --out ./member-out
vk run --compose lab-ad.compose.yaml
```

Shows: provisioning at each start (`CMD`, run through qemu-ga, with a restart after the join),
compose secrets, `depends_on` on a healthcheck and on a job's success, and `vk snapshot
--run-dir` to save the whole lab and bring it back in seconds. `tests/windows-ad-e2e.sh` runs
it end to end.

## 3. A Windows 11 member with a TPM and Secure Boot — `win11.Dockerfile`

Windows 11 Enterprise, generalized, joining corp.lab; each member has a TPM 2.0 of its own
(`# vk: tpm=on`) and boots with Secure Boot (`# vk: firmware=uefi-secboot`), so BitLocker works.

```sh
vk build -f win11.Dockerfile --target member11 --out ./member11-out
```

Add it to `lab-ad.compose.yaml` as the Dockerfile describes.

Secure Boot runs without SMM: vk keeps and checks the UEFI variables on the host, so PK, KEK, db
and dbx are out of the guest's reach and Windows applies Microsoft's updates to them (its
Secure-Boot-Update task), but the firmware itself runs unprotected from the guest's kernel
while it boots. See [how Windows guests work](../../docs/windows.md).

## 4. Two forests with a trust — `two-forests.compose.yaml`

corp.lab and partner.lab, each with its own DC, users, member server (Windows Server 2025) and
workstation (Windows 11), and a two-way forest trust that partner.lab's DC makes once
corp.lab's answers; every member reads its own forest's users and the other's across it. Each
workstation checks that its servers answer RDP with Network Level Authentication
(`rdp-probe.ps1`), and the RDP job signs in to every machine, across the trust too.

```sh
vk build -f lab.Dockerfile --target dc --out ./dc-out
vk build -f forests.Dockerfile --target dc-partner --out ./dc-partner-out
for m in srv-corp srv-partner; do vk build -f forests.Dockerfile --target $m --out ./$m-out; done
for m in ws-corp ws-partner; do vk build -f win11.Dockerfile --target $m --out ./$m-out; done
vk run --compose two-forests.compose.yaml
```

About 15 GiB of guest memory (DCs 2.5 GiB, servers 1.5 GiB, Windows 11 workstations 3.5 GiB): a
host of 24 GB or more.

Shows: several DCs on one LAN, conditional DNS forwarding between forests, a trust made at start,
and one image per machine: each server and workstation image boots the generalized member once
at build, so it has a machine SID of its own and Windows' first-boot setup is done before the
lab starts, which then only joins it to its domain.

## 5. A red forest — `red-forest.compose.yaml`

The enhanced security admin environment (ESAE): admin.lab, the bastion forest, holds the tier-0
admins; corp.lab, production, trusts it one way and makes its T0-Admins group administrators of
the domain. Each forest has a member server and a workstation; the bastion's workstation is the
privileged access workstation, which checks the model at start: the bastion's t0admin creates
and deletes an account in production, and a production user cannot sign in to the bastion.

```sh
vk build -f lab.Dockerfile --target dc --out ./dc-out
vk build -f forests.Dockerfile --target dc-admin --out ./dc-admin-out
for m in srv-admin srv-corp; do vk build -f forests.Dockerfile --target $m --out ./$m-out; done
for m in paw ws-corp; do vk build -f win11.Dockerfile --target $m --out ./$m-out; done
vk run --compose red-forest.compose.yaml
```

About 15 GiB of guest memory (DCs 2.5 GiB, servers 1.5 GiB, Windows 11 workstations 3.5 GiB): a
host of 24 GB or more.

Shows: a one-way forest trust, foreign security principals in a production group, and checks
run as other accounts from a member's provisioning.

## 6. A real Remote Desktop session — `rdp-session.compose.yaml`

A standalone Windows Server 2025 (no domain) with a local account, rdpuser, and a Linux client
that opens a full Remote Desktop session to it with FreeRDP (Network Level Authentication, not
only the authentication step), captures the sign-in and, a minute later, the desktop
(`rdp-out/session-logon.png`, `rdp-out/session.png`), and holds the session for five minutes.

```sh
vk build -f rdp.Dockerfile --target rdp-server --out ./rdp-server-out
vk run --compose rdp-session.compose.yaml --state-dir ./run
vk exec ./run --service rdp-server -- qwinsta     # rdpuser's session, active, on rdp-tcp#N
```

Shows: a Remote Desktop session into a vk guest end to end, and `vk exec --service` running a
command in a Windows service of a lab. `tests/windows-rdp-e2e.sh` runs it end to end.

## The pieces

| File | Role |
|---|---|
| `lab.Dockerfile`, `forests.Dockerfile` | the base image, the DCs (one stage per forest), the members, the labs' servers |
| `promote.ps1` | a DC's promotion at build, the first of its forest |
| `dc-boot.ps1` | a DC's provisioning: DNS, the lab's admin account, conditional forwarders, a trust |
| `join.ps1` | a member's provisioning: DNS, the join, the users it must find, an optional check |
| `accounts.Dockerfile`, `accounts.sh` | the Linux job that creates a domain's users and groups |
| `red-forest-check.ps1` | the red forest's checks, run on its workstation |
| `rdp-check.Dockerfile`, `rdp-check.sh` | the Linux job that signs in over RDP to the lab's machines |
| `rdp-probe.ps1` | a workstation's check that its servers answer RDP with NLA |
| `rdp.Dockerfile`, `rdp-user.ps1` | the standalone RDP server and its local account |
| `rdp-session.Dockerfile`, `rdp-session.sh` | the client that opens, captures and holds a full RDP session |
| `iis.Dockerfile`, `iis-index.html` | the web server |
| `win11.Dockerfile` | the Windows 11 workstation, and the labs' workstations |

The environment variables each script reads are listed at its top. The scripts retry what a
slow or loaded host makes late (a DC that answers its healthcheck before LDAP, a join that times
out after it went through, a trust the other DC is not ready for yet).

## Known issues

- **The multi-forest labs need about 15 GiB of guest memory**, and a domain controller at least
  2.5 GiB: at 1.5 GiB, under a trust being made and several joins at once, Active Directory
  ran short and answered in odd ways (an account it had "not found", "the directory service is
  busy", "not enough space on the disk" with most of the disk free). On a 16 GB host with other
  work running the labs do not fit; they have been run there with one workstation left out.
- **A slow or loaded host makes Windows late everywhere.** The scripts retry what this was seen
  to break (LDAP after the DC's healthcheck, a trust the other DC is not ready for, a join that
  timed out after it went through, its rename, a read across a trust right after the restart, an
  RDP negotiation); vk gives a Windows service 45 minutes to start. A step not listed can still
  time out on such a host.

## Tested, and what is left

Run end to end on a 40 GB host, from a clean cache (every image built from the ISOs): the two
multi-forest labs whole (both workstations, every check, the RDP job's sign-ins across the
trusts; about 7 minutes each once built), `tests/windows-ad-e2e.sh` (the lab
restored in 8 s), and `tests/windows-rdp-e2e.sh`.

