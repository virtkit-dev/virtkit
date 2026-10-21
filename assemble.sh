#!/bin/sh
# assemble.sh — append the guest kernel, vk-agent and UEFI firmware to a bare vk binary.
# It writes only <out>, the self-contained vk. build.sh runs it after compilation, then
# writes vk.sha256 and build-info.txt.
#
#   sh assemble.sh <out> <vk-bare> <name>=<file>...
#
# Each <name> is the blob's name in the payload index (vmlinux, vk-agent, CLOUDHV.fd, ...),
# appended in the order given. The layout, which vk-driver/src/embed.rs reads back:
#
#   <vk-bare> <blob>... <index> "VKPAYLOAD1 <index offset> <index length>\n"
#
# with one "<name> <offset> <size> <sha256>\n" index line per blob (decimal, offsets from the
# start of the file) and the trailer's numbers as 16 lowercase hex digits. Nothing in it
# depends on the host or the time, so the same parts always give the same bytes.
#
# POSIX sh: build.sh runs it on the host, vk-driver's tests in the build image.
set -eu

usage() {
  echo "usage: $0 <out> <vk-bare> <name>=<file>..." >&2
  exit 2
}
[ $# -ge 2 ] || usage
out=$1
bare=$2
shift 2
LC_ALL=C
export LC_ALL

tmp="$out.tmp.$$"
# Hash and append one snapshot of each blob, so concurrent changes to the input cannot
# make the index describe different bytes.
snap="$tmp.blob"
trap 'rm -f "$tmp" "$snap"' EXIT
trap 'exit 1' HUP INT TERM
# The bare vk is read once too; the checks look at the copy.
cat "$bare" > "$tmp"
[ -s "$tmp" ] || { echo "assemble.sh: $bare is empty" >&2; exit 1; }
# "VKPAYLOAD1 " in hex: a payload already there would be shadowed by the new one. dd reads a
# byte at a time, so a short read from the pipe cannot cut the magic.
magic=$(tail -c 45 "$tmp" | dd bs=1 count=11 2>/dev/null | od -An -tx1 | tr -d ' \n')
if [ "$magic" = 564b5041594c4f41443120 ]; then
  echo "assemble.sh: $bare already carries a payload; give it the bare vk" >&2
  exit 1
fi
# Track offsets from copied bytes without rereading the inputs.
off=$(($(wc -c < "$tmp")))
index=""
seen=" "
for arg in "$@"; do
  name=${arg%%=*}
  file=${arg#*=}
  [ "$name" != "$arg" ] || usage
  # The names vk reads back: Asset::filename in vk-driver/src/embed.rs.
  case $name in
    vmlinux | vk-agent | CLOUDHV.fd | CLOUDHV_VARS.fd | CLOUDHV_VARS.ms.fd) ;;
    *) echo "assemble.sh: unknown blob name '$name'" >&2; exit 2 ;;
  esac
  case $seen in
    *" $name "*) echo "assemble.sh: $name given twice" >&2; exit 2 ;;
  esac
  seen="$seen$name "
  [ -f "$file" ] || { echo "assemble.sh: $file is missing" >&2; exit 1; }
  cp "$file" "$snap"
  size=$(($(wc -c < "$snap")))
  [ "$size" -gt 0 ] || { echo "assemble.sh: $file is empty" >&2; exit 1; }
  sum=$(sha256sum < "$snap" | cut -d' ' -f1)
  cat "$snap" >> "$tmp"
  index="$index$name $off $size $sum
"
  off=$((off + size))
done
printf '%s' "$index" >> "$tmp"
printf 'VKPAYLOAD1 %016x %016x\n' "$off" "${#index}" >> "$tmp"
chmod 755 "$tmp"
mv -f "$tmp" "$out"
