#!/usr/bin/env bash
# Check Ctrl-C / Ctrl-Z during a detaching run and signal isolation after detach.
# `vk run --detach` and the `vk dev` verbs that boot run the build + boot in the
# foreground and daemonize once the guest is up (vk-driver/src/detach.rs): the forked child
# stays in the terminal's foreground process group until readiness and `setsid`s only then.
# So while it is still building, the terminal must reach it like any foreground job — Ctrl-Z
# suspends it, Ctrl-C aborts it — which a child in a session of its own never is: a session
# cannot be the terminal's foreground group, and the kernel discards SIGTSTP for an orphaned
# group.
#
# `setsid` moves only its caller. The VMM/switch/virtiofsd the child spawns before readiness
# must therefore leave the terminal's group at spawn (vk-driver/src/spawn.rs, keyed on
# `detach::is_child`): left in it, a Ctrl-C aimed at that group after the run detached —
# `vk dev`'s post-boot work in the parent, a script run without job control — kills the VM.
#
# The test runs `vk run --file <Dockerfile> --detach` as a foreground job under an
# interactive shell on a real PTY, with a Dockerfile whose RUN step blocks, and while that
# build step is running it checks:
#   1. the process driving the build shares the shell's *session* (not off in its own);
#   1b. every helper it spawned leads a session of its own, so the Ctrl-C/Ctrl-Z the child
#      stops hearing at readiness never reaches them either;
#   2. a Ctrl-Z on the PTY *stops* it (process state T);
#   3. a Ctrl-C then tears the whole build down.
# Then a second run detaches for real, with job control off so the shell keeps the run's
# group in the foreground the way a script does, and it checks:
#   4. a Ctrl-C after the run detached leaves the detached child and every helper alive;
#   5. the SIGTERM `vk stop` sends still tears all of them down.
#
# Run:  VK=./dist/vk tests/detach-signals-e2e.sh
# Needs: a `vk` with an embedded kernel/agent, KVM, python3 (the PTY/job-control driver),
#        and network for the build base image.
set -euo pipefail

VK=$(command -v "${VK:-./dist/vk}" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "no usable vk (build one: ./build.sh --fast)"; exit 2; }
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")
IMAGE=${IMAGE:-docker.io/library/alpine:3.21}
[ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo "SKIP: no writable /dev/kvm"; exit 0; }
command -v python3 >/dev/null || { echo "SKIP: no python3 (drives the PTY/job control)"; exit 0; }

# Unix-socket paths under the state dir are capped at 108 bytes, so keep the root short.
base=${TMPDIR:-/tmp}
[ "${#base}" -le 40 ] || base=/tmp
WORK=$(mktemp -d "$base/vk-detach-sig-e2e.XXXXXX")
trap 'python3 - "$WORK" <<PYCLEAN 2>/dev/null || true
import os,signal,glob,sys
# best-effort: SIGKILL any vk process still holding this run scratch dir on its cmdline
# (both state dirs sit under it). The stage VMMs it spawned carry the dir in their env, not
# their cmdline, so they are not matched here — they fall to PR_SET_PDEATHSIG when their vk
# parent dies. Skip our own pid — this cmdline holds the dir too.
work=sys.argv[1]
for p in glob.glob("/proc/[0-9]*"):
    me=int(os.path.basename(p))==os.getpid()
    try:
        cl=open(p+"/cmdline").read()
    except OSError: continue
    if work in cl and "vk" in cl and not me:
        try: os.kill(int(os.path.basename(p)), signal.SIGKILL)
        except OSError: pass
PYCLEAN
rm -rf "$WORK"' EXIT

# A RUN that blocks gives a stable window to signal the build in. The marker is uncached
# (unique per run), so the base may be cached but this step always executes.
MARKER="VK_DETACH_SIGTEST_BUILDING_$$"
cat > "$WORK/Dockerfile" <<EOF
FROM $IMAGE
RUN echo $MARKER && sleep 600
EOF

# The second scenario wants a run that reaches readiness, so nothing blocks its build. Its
# state dir sits under the same scratch root, so one trap cleans up after both.
cat > "$WORK/Dockerfile.boot" <<EOF
FROM $IMAGE
EOF

# The PTY/job-control driver: run vk as a foreground job under bash -i on a pty, wait (via
# /proc) for the build's stage guest to come up, then check session membership, Ctrl-Z (stop)
# and Ctrl-C (abort); then let a second run detach and check that the terminal's Ctrl-C no
# longer reaches it. Reading the process table, not the progress TUI, keeps it robust.
python3 - "$VK" "$WORK/Dockerfile" "$WORK/state-a" "$WORK/Dockerfile.boot" "$WORK/state-b" <<'PY'
import os, pty, time, sys, threading, signal, shlex

VK, DOCKERFILE, STATE, DOCKERFILE2, STATE2 = sys.argv[1:6]
sys.stdout.reconfigure(line_buffering=True)   # `os._exit` skips the flush a pipe would need

def stat_of(pid):
    try:
        s = open(f"/proc/{pid}/stat").read()
    except OSError:
        return None
    rp = s.rindex(')')                       # comm can hold spaces/parens
    comm = s[s.index('(') + 1:rp]
    f = s[rp + 2:].split()                   # fields from #3 (state) on
    return {"comm": comm, "state": f[0], "ppid": f[1], "pgid": f[2], "sid": f[3]}

def all_stats():
    out = {}
    for p in os.listdir("/proc"):
        if p.isdigit() and (st := stat_of(p)):
            out[p] = st
    return out

def cmdline_has(pid, needle):
    try:
        return needle in open(f"/proc/{pid}/cmdline").read()
    except OSError:
        return False

def descendants(root, ps=None):
    """Every live process under `root`, by ppid chain — the helpers vk spawned and theirs.
    A helper that double-forked to init would escape the walk; vk keeps every helper a
    tracked child, so none do."""
    ps = ps or all_stats()
    found, wave = set(), {str(root)}
    while wave:
        wave = {p for p, s in ps.items() if s["ppid"] in wave and p not in found}
        found |= wave
    return found

def table(ps, pids):
    return "\n".join(f"    {p:>8} ppid={ps[p]['ppid']:>8} pgid={ps[p]['pgid']:>8} "
                     f"sid={ps[p]['sid']:>8} state={ps[p]['state']} {ps[p]['comm']}"
                     for p in sorted(pids, key=int) if p in ps)

pid, fd = pty.fork()
if pid == 0:
    os.environ["TERM"] = "dumb"
    os.execvp("bash", ["bash", "--norc", "--noprofile", "-i"])
    os._exit(127)

# Drain the pty in the background so vk's progress TUI never blocks on a full terminal buffer.
def drain():
    while True:
        try:
            if not os.read(fd, 65536):
                return
        except OSError:
            return
threading.Thread(target=drain, daemon=True).start()

def fail(msg):
    print("FAIL:", msg)
    ps = all_stats()
    vks = {p for p, s in ps.items() if s["comm"].startswith("vk")}
    print(f"  shell pid={pid} sid={(stat_of(str(pid)) or {}).get('sid')}\n"
          f"  live vk processes:\n{table(ps, vks)}")
    try: os.kill(pid, 9)
    except OSError: pass
    os._exit(1)

time.sleep(0.5)
os.write(fd, f"{shlex.quote(VK)} run --file {shlex.quote(DOCKERFILE)} --state-dir {shlex.quote(STATE)} --detach -- sleep 600\n".encode())

# Wait for the build to reach a stage guest: our two vk processes carry the --state-dir, and
# the build child is the vk whose parent is our other vk. A stage guest (vk:stageN /
# vk:build) coming up means the build is mid-stage and still in the foreground, before detach
# — the window this test needs. It does not prove a RUN instruction body is executing, only
# that this VMM has booted; the test checks signal delivery, not the RUN itself. It has to be
# *our* stage guest, i.e. a descendant of that child: another build may well be running on
# this host.
def staged_child(ps):
    ours = {p for p, s in ps.items() if s["comm"] == "vk" and cmdline_has(p, STATE)}
    for k in (p for p in ours if ps[p]["ppid"] in ours):
        if any(ps[h]["comm"].startswith("vk:stage") or ps[h]["comm"] == "vk:build"
               for h in descendants(k, ps)):
            return k
    return None

child = None
deadline = time.time() + 300
while time.time() < deadline and child is None:
    time.sleep(1)
    child = staged_child(all_stats())
if child is None:
    fail("build never reached a stage guest within the deadline (build/pull failure?)")

bash_sid = stat_of(str(pid))["sid"]

# (1) structural: the build child must live in the shell's session. A child that detached
#     at fork would lead its own (sid == pid), out of the terminal's reach.
csid = stat_of(child)["sid"]
if csid != bash_sid:
    fail(f"build child is not in the shell's session (sid={csid}, shell sid={bash_sid}) — "
         "it detached during the build, so terminal ^C/^Z cannot reach it")

# (1b) structural, the other way round: the helpers the child spawned (stage VMM, switch,
#      virtiofsd) must each lead a session of their own. The child `setsid`s alone at
#      readiness, so a helper left in the terminal's group would keep taking its ^C/^Z long
#      after the run detached.
ps = all_stats()
helpers = descendants(child, ps)
if not helpers:
    fail(f"the build child {child} has no helper processes — no stage VMM to check")
print(f"  build child {child} (sid={csid}, shell sid={bash_sid}), helpers:\n"
      f"{table(ps, helpers)}")
shared = {h for h in helpers if ps[h]["sid"] == bash_sid}
if shared:
    fail(f"{len(shared)} of the build child's helpers are in the shell's session "
         f"(sid={bash_sid}), where the terminal's ^C kills them once the run detaches:\n"
         f"{table(ps, shared)}")
# A helper's own children inherit its session, so a non-leader is only expected when its
# leader is another helper.
stray = {h for h in helpers if ps[h]["sid"] not in (h, *helpers)}
if stray:
    fail(f"helpers in a session led from outside the run:\n{table(ps, stray)}")

# (2) Ctrl-Z must stop it.
os.write(fd, b"\x1a")
st = None
for _ in range(40):
    time.sleep(0.5)
    st = stat_of(child)
    if st is None or st["state"] == "T":
        break
if st is None:
    fail("build child vanished on Ctrl-Z (expected: stopped)")
if st["state"] != "T":
    fail(f"Ctrl-Z did not stop the build (state={st['state']}, expected T)")

# (3) `fg` resumes it (Ctrl-Z handed the terminal back to the shell, so a Ctrl-C would
#     otherwise reach the shell alone), then Ctrl-C must tear the build down. In the build
#     phase this is the driver ending and its parent-death-tied helpers (the stage VMM
#     included) going with it, not the graceful power-off the guest-wait phase installs; the
#     check below is that they all disappear, not that the guest shut down cleanly. Teardown
#     still takes a moment, so give it time.
os.write(fd, b"fg\n")
for _ in range(20):
    time.sleep(0.5)
    if (st := stat_of(child)) is None or st["state"] != "T":
        break
if stat_of(child) is None:
    fail("build child vanished while being resumed")
os.write(fd, b"\x03")
for _ in range(120):
    time.sleep(0.5)
    if stat_of(child) is None:
        break
if stat_of(child) is not None:
    fail("Ctrl-C did not tear the build down")
for _ in range(60):                                  # the aborted run's helpers must go too
    ps = all_stats()
    if not any(p in ps for p in (child, *helpers)):
        break
    time.sleep(0.5)
ps = all_stats()
alive = {p for p in (child, *helpers) if p in ps}
if alive:
    fail(f"Ctrl-C did not tear the whole build down; {len(alive)} process(es) remain:\n"
         f"{table(ps, alive)}")
print("PASS: build child shares the shell session, its helpers do not; "
      "Ctrl-Z stops it; Ctrl-C aborts it")

# ---------------------------------------------------------------------------------------
# Second scenario: once the run has detached, the terminal's Ctrl-C must not reach it.
# Job control is switched off first, so the shell leaves the run in its own process group —
# the terminal's foreground group — exactly as a script or `vk dev`'s post-boot work does.
# With job control on, the shell takes the terminal back when the parent exits and a later
# Ctrl-C would never reach the run's group, bug or no bug.
# ---------------------------------------------------------------------------------------
os.write(fd, b"set +m\n")
time.sleep(0.5)
os.write(fd, f"{shlex.quote(VK)} run --file {shlex.quote(DOCKERFILE2)} --state-dir {shlex.quote(STATE2)} --detach -- sleep 600\n".encode())
# Wait for the run to start before reading the terminal's foreground group.
for _ in range(40):
    time.sleep(0.5)
    if any(cmdline_has(p, STATE2) for p in all_stats()):
        break
# The run must be in the shell's own group, and that group must hold the terminal: that is
# what puts the helpers of an unfixed build in reach of the Ctrl-C below.
bash_pgid = stat_of(str(pid))["pgid"]
if (fg := os.tcgetpgrp(fd)) != int(bash_pgid):
    fail(f"the second run is not in the terminal's foreground group (fg={fg}, "
         f"shell pgid={bash_pgid}) — job control is still on, so the check below proves nothing")

# The parent exits when the guest is ready, leaving the child alone with the state dir and,
# having `setsid`'d, leading its own session.
child2 = None
deadline = time.time() + 300
while time.time() < deadline and child2 is None:
    time.sleep(1)
    ps = all_stats()
    vks = {p for p, s in ps.items() if s["comm"] == "vk" and cmdline_has(p, STATE2)}
    if len(vks) == 1 and (c := next(iter(vks))) and ps[c]["sid"] == c and descendants(c, ps):
        child2 = c
if child2 is None:
    fail("the second run never detached within the deadline (build/pull failure?)")

ps = all_stats()
kids2 = descendants(child2, ps)
print(f"  detached child {child2} (sid={ps[child2]['sid']}), helpers:\n{table(ps, kids2)}")

# (4) None of the run's processes may share the shell's session, and a Ctrl-C on the
#     terminal must leave every one of them alive.
inshell = {p for p in (child2, *kids2) if ps[p]["sid"] == bash_sid}
if inshell:
    fail(f"the detached run still has processes in the shell's session (sid={bash_sid}):\n"
         f"{table(ps, inshell)}")
os.write(fd, b"\x03")
# A Ctrl-C wrongly reaching the group would kill within a beat; check twice, a few seconds
# apart, so a slow death cannot pass for survival.
dead = set()
for _ in range(2):
    time.sleep(3)
    ps = all_stats()
    dead = {p for p in (child2, *kids2) if p not in ps}
    if dead:
        break
if dead:
    fail(f"a Ctrl-C after the run detached killed {len(dead)} of its processes "
         f"(pids {' '.join(sorted(dead, key=int))}) — they were still in the terminal's group")
print(f"PASS: Ctrl-C after detaching left the child {child2} and its "
      f"{len(kids2)} helpers alive")

# (5) The SIGTERM `vk stop` sends must still take the whole run down.
os.kill(int(child2), signal.SIGTERM)
for _ in range(60):
    time.sleep(0.5)
    ps = all_stats()
    if not any(p in ps for p in (child2, *kids2)):
        break
ps = all_stats()
alive = {p for p in (child2, *kids2) if p in ps}
if alive:
    fail(f"SIGTERM left {len(alive)} of the detached run's processes behind:\n"
         f"{table(ps, alive)}")
print("PASS: SIGTERM tore the detached run down")

try: os.kill(pid, 9)
except OSError: pass
os._exit(0)
PY

echo "detach-signals-e2e: OK"
