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
IMAGE="docker.io/library/python:3-alpine"
TIMEOUT="${INT1_TIMEOUT:-180}"
PROGRAM='
import ctypes, mmap, signal
hits = []
signal.signal(signal.SIGTRAP, lambda *_: hits.append(1))
code = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
code.write(b"\xf1\xc3")  # int1; ret
ctypes.CFUNCTYPE(None)(ctypes.addressof(ctypes.c_char.from_buffer(code)))()
print("traps", len(hits))
'

# Prints the guest's `traps N`, or nothing if it never got there within the timeout.
traps() { # $1: KRUN_INT1_WORKAROUND
  KRUN_INT1_WORKAROUND="$1" timeout "$TIMEOUT" "$VK" run "$IMAGE" -- python3 -c "$PROGRAM" 2> /dev/null |
    grep -o 'traps [0-9]*' || true
}

echo "== int1 with the VMM stepping over it (KRUN_INT1_WORKAROUND=1) =="
got=$(traps 1)
if [ "$got" != "traps 1" ]; then
  echo "FAIL: the guest's int1 gave '${got:-no answer within ${TIMEOUT}s}', not one trap" >&2
  exit 1
fi
echo "ok: one trap, after the int1"

echo "== int1 left to KVM (KRUN_INT1_WORKAROUND=0), for information =="
got=$(traps 0)
case "$got" in
  "traps 1") echo "this host delivers int1 correctly" ;;
  "") echo "this host delivers int1 onto itself (Hyper-V's nested SVM): the workaround is needed" ;;
  *) echo "this host gave '$got' without the workaround" ;;
esac
echo "PASS"
