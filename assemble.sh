#!/bin/sh
# assemble.sh — make the self-contained `vk`: a bare vk binary with the guest kernel,
# vk-agent and UEFI firmware appended as a payload. build.sh runs it after the compile;
# CI runs it (through build.sh --assemble) once every part has been built.
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
# POSIX sh: vk-driver's tests run it in the build image.
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

[ -s "$bare" ] || { echo "assemble.sh: $bare is missing or empty" >&2; exit 1; }
# "VKPAYLOAD1 " in hex: a payload already there would be shadowed by the new one.
magic=$(tail -c 45 "$bare" | dd bs=11 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
if [ "$magic" = 564b5041594c4f41443120 ]; then
  echo "assemble.sh: $bare already carries a payload; give it the bare vk" >&2
  exit 1
fi

tmp="$out.tmp.$$"
trap 'rm -f "$tmp"' EXIT
trap 'exit 1' HUP INT TERM
cat "$bare" > "$tmp"
off=$(($(wc -c < "$bare")))
index=""
seen=" "
for arg in "$@"; do
  name=${arg%%=*}
  file=${arg#*=}
  [ "$name" != "$arg" ] || usage
  case $name in
    '' | *[!A-Za-z0-9._-]*) echo "assemble.sh: bad blob name '$name'" >&2; exit 2 ;;
  esac
  case $seen in
    *" $name "*) echo "assemble.sh: $name given twice" >&2; exit 2 ;;
  esac
  seen="$seen$name "
  [ -s "$file" ] || { echo "assemble.sh: $file is missing or empty" >&2; exit 1; }
  size=$(($(wc -c < "$file")))
  sum=$(sha256sum < "$file" | cut -d' ' -f1)
  cat "$file" >> "$tmp"
  index="$index$name $off $size $sum
"
  off=$((off + size))
done
printf '%s' "$index" >> "$tmp"
printf 'VKPAYLOAD1 %016x %016x\n' "$off" "${#index}" >> "$tmp"
chmod 755 "$tmp"
mv -f "$tmp" "$out"
