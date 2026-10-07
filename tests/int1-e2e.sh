#!/usr/bin/env bash
# =====================================================================================
# A guest's `int1` (ICEBP) traps once, after the instruction.
# =====================================================================================
# Under Hyper-V's nested SVM (WSL2 or an Azure VM on AMD), an `int1` comes back to KVM with
# RIP still on it and the guest executes it again, forever; the VMM can take the guest's #DB
# exits and step over it (KRUN_INT1_WORKAROUND, on by default for a Windows guest on such a
# host). A Python program in a Linux guest runs `int1; ret` from executable memory under a
# SIGTRAP handler: one trap and it prints `traps 1`, a host that delivers the `int1` onto
# itself never returns from it.
#
# With the workaround forced on, every host must give one trap. Without it, the result says
# whether this host has the fault, for information only.
#
# Run:  VK=./dist/vk tests/int1-e2e.sh
# Needs: KVM, and network for the python image.
set -euo pipefail

VK="${VK:-vk}"
IMAGE="docker.io/library/python:3.13-alpine"
TIMEOUT="${INT1_TIMEOUT:-180}"
# The run without the workaround hangs for good on a faulty host: it gets less.
INFO_TIMEOUT="${INT1_INFO_TIMEOUT:-60}"
LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT
PROGRAM='
import ctypes, mmap, os, signal
# Counted in C, a byte per SIGTRAP: Python handlers run once for signals that came together.
r, w = os.pipe()
os.set_blocking(r, False)
os.set_blocking(w, False)
signal.signal(signal.SIGTRAP, lambda *_: None)
signal.set_wakeup_fd(w)
code = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
code.write(b"\xf1\xc3")  # int1; ret
ctypes.CFUNCTYPE(None)(ctypes.addressof(ctypes.c_char.from_buffer(code)))()
try:
    traps = len(os.read(r, 64))
except BlockingIOError:
    traps = 0
print("traps", traps)
'

# Prints the guest's `traps N`, or nothing if it never got there within $2 seconds; vk's own
# messages go to $LOG.
traps() { # $1: KRUN_INT1_WORKAROUND, $2: timeout
  KRUN_INT1_WORKAROUND="$1" timeout "$2" "$VK" run "$IMAGE" -- python3 -c "$PROGRAM" 2> "$LOG" |
    grep -o 'traps [0-9]*' || true
}

echo "== int1 with the VMM stepping over it (KRUN_INT1_WORKAROUND=1) =="
got=$(traps 1 "$TIMEOUT")
if [ "$got" != "traps 1" ]; then
  echo "FAIL: the guest's int1 gave '${got:-no answer within ${TIMEOUT}s}', not one trap" >&2
  cat "$LOG" >&2
  exit 1
fi
echo "ok: one trap, after the int1"

echo "== int1 left to KVM (KRUN_INT1_WORKAROUND=0), for information =="
got=$(traps 0 "$INFO_TIMEOUT")
case "$got" in
  "traps 1") echo "this host delivers int1 correctly" ;;
  "") echo "no answer within ${INFO_TIMEOUT}s: this host likely delivers int1 onto itself (Hyper-V's nested SVM)" ;;
  *) echo "this host gave '$got' without the workaround" ;;
esac
echo "PASS"
