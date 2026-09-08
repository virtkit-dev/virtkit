#!/usr/bin/env bash
# End-to-end filesystem-integrity gate for virtio-fs shares, across every data-path mode.
# A shared host directory is exercised from inside a microVM by two C programs, in each of
# the modes vk can serve a read-write share:
#
#   - libkrun, dax=off   — the in-process fs engine, plain FUSE_READ/WRITE.
#   - libkrun, dax=8G    — the same engine with a DAX window: reads and in-place writes go
#                          through host mappings set up per inode (FUSE_SETUPMAPPING).
#   - cloud-hypervisor   — the same engine behind the bundled `vk virtiofsd` vhost-user
#                          daemon (no DAX). Skipped when no cloud-hypervisor binary is found.
#
# The two programs:
#   - fsxmini: random pwrite / pread / mmap-write / mmap-read / ftruncate against an
#     in-memory model, aborting on the first byte that does not match. The mmap ops drive
#     the DAX mapping path; the model is the oracle, so no second filesystem is needed.
#   - perm: the git `odb_mkstemp` shape — a file created mode 0444 but held open writable,
#     rewritten in place through a shared mapping. A DAX backend that re-derived write
#     access from the 0444 mode turned this into EACCES/SIGBUS and broke `git fetch`.
#
# Both programs must exit 0 in every non-skipped mode.
#
# The programs are compiled on the host as static binaries and shipped into the share, so
# the guest needs neither a compiler nor network — any bootable image with a shell works.
#
# Run:  VK=./dist/vk tests/fsx-e2e.sh
# Needs: a `vk` with an embedded kernel/agent, KVM, network for the image pull, a host C
#        compiler that can link `-static`, and GNU-coreutils `timeout` (busybox's signals
#        only its own child, so a killed step could leak a microVM).
# Tunables: STEP_TIMEOUT caps each mode (seconds, default 600); FSX_OPS and FSX_MAXLEN size
#        the fsxmini run; FSX_IMAGE overrides the guest image; CC overrides the compiler.
set -euo pipefail

STEP_TIMEOUT=${STEP_TIMEOUT:-600}
FSX_OPS=${FSX_OPS:-50000}
FSX_MAXLEN=${FSX_MAXLEN:-262144}
FSX_IMAGE=${FSX_IMAGE:-docker.io/library/alpine:3.21}
CC=${CC:-cc}
for v in STEP_TIMEOUT FSX_OPS FSX_MAXLEN; do
  case ${!v} in *[!0-9]* | '' | 0) echo "fsx-e2e: $v must be a non-zero integer" >&2; exit 2 ;; esac
done

# Absolute, so the path survives the cd's below and matches how release-e2e.sh exports it.
asked=${VK:-./dist/vk}
VK=$(command -v "$asked" || true)
[ -n "$VK" ] && [ -x "$VK" ] || { echo "fsx-e2e: no executable vk at $asked (build one: ./build.sh --fast)" >&2; exit 2; }
VK=$(cd "$(dirname "$VK")" && pwd)/$(basename "$VK")
export VK

[ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo "fsx-e2e: no rw access to /dev/kvm" >&2; exit 2; }
command -v "$CC" >/dev/null || { echo "fsx-e2e: need a C compiler (set CC, or install one)" >&2; exit 2; }
command -v timeout >/dev/null || { echo "fsx-e2e: need GNU-coreutils timeout" >&2; exit 2; }

echo "fsx-e2e: testing $VK"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cat > "$work/fsxmini.c" <<'EOF'
// Compact fsx-style integrity exerciser: random pwrite / pread / mmap-write /
// mmap-read / ftruncate against an in-memory model, aborting on the first mismatch.
// The mmap ops drive the virtio-fs DAX setupmapping path. Deterministic per seed.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

static unsigned long s;
static unsigned r(void) { s = s * 6364136223846793005UL + 1442695040888963407UL; return (s >> 33) & 0xffffffff; }

static unsigned char *good;      // model of the file's contents
static long maxlen, size;        // capacity, current logical length
static int fd;
static long pagesz;

static void die(const char *what, long off, long len) {
    fprintf(stderr, "MISMATCH %s off=%ld len=%ld size=%ld\n", what, off, len, size);
    exit(1);
}

static void do_write(int viammap) {
    long off = r() % maxlen;
    long len = 1 + r() % (maxlen - off);
    unsigned char val = (unsigned char)(r());
    if (off + len > size) {                       // extend first: an mmap store past i_size faults
        if (ftruncate(fd, off + len)) { perror("ftruncate/extend"); exit(2); }
        memset(good + size, 0, off + len - size);
        size = off + len;
    }
    memset(good + off, val, len);
    if (viammap) {
        long pa = off & ~(pagesz - 1);
        long ml = off + len - pa;
        unsigned char *m = mmap(NULL, ml, PROT_READ | PROT_WRITE, MAP_SHARED, fd, pa);
        if (m == MAP_FAILED) { perror("mmap/w"); exit(2); }
        memset(m + (off - pa), val, len);
        if (msync(m, ml, MS_SYNC)) { perror("msync"); exit(2); }
        munmap(m, ml);
    } else if (pwrite(fd, good + off, len, off) != len) { perror("pwrite"); exit(2); }
}

static void do_read(int viammap) {
    if (size == 0) { do_write(0); return; }
    long off = r() % size;
    long len = 1 + r() % (size - off);
    if (viammap) {
        long pa = off & ~(pagesz - 1);
        long ml = off + len - pa;
        unsigned char *m = mmap(NULL, ml, PROT_READ, MAP_SHARED, fd, pa);
        if (m == MAP_FAILED) { perror("mmap/r"); exit(2); }
        if (memcmp(m + (off - pa), good + off, len)) { munmap(m, ml); die("mapread", off, len); }
        munmap(m, ml);
    } else {
        unsigned char *b = malloc(len);
        if (pread(fd, b, len, off) != len) { perror("pread"); exit(2); }
        if (memcmp(b, good + off, len)) { free(b); die("read", off, len); }
        free(b);
    }
}

static void do_trunc(void) {
    long ns = r() % maxlen;
    if (ftruncate(fd, ns)) { perror("ftruncate"); exit(2); }
    if (ns > size) memset(good + size, 0, ns - size);
    size = ns;
}

int main(int argc, char **argv) {
    if (argc != 5) { fprintf(stderr, "usage: %s <seed> <nops> <maxlen> <path>\n", argv[0]); return 2; }
    s = strtoul(argv[1], 0, 10);
    long nops = strtol(argv[2], 0, 10);
    maxlen = strtol(argv[3], 0, 10);
    pagesz = sysconf(_SC_PAGESIZE);
    good = calloc(1, maxlen);
    if (!good) { perror("calloc"); return 2; }
    fd = open(argv[4], O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open"); return 2; }
    for (long i = 0; i < nops; i++) {
        switch (r() % 5) {
            case 0: do_write(0); break;
            case 1: do_write(1); break;   // mmap write  -> DAX writable mapping
            case 2: do_read(0);  break;
            case 3: do_read(1);  break;   // mmap read   -> DAX read mapping
            case 4: do_trunc();  break;
        }
    }
    // Full read-back verify.
    unsigned char *b = malloc(size ? size : 1);
    if (pread(fd, b, size, 0) != size) { perror("pread/final"); return 2; }
    if (memcmp(b, good, size)) die("final", 0, size);
    printf("fsxmini OK: %ld ops seed %s final-size %ld\n", nops, argv[1], size);
    return 0;
}
EOF

cat > "$work/perm.c" <<'EOF'
// The specific regression: a file created read-only (0444) but held open writable,
// then rewritten in place through a shared mapping — git's odb_mkstemp temp pack, whose
// header fixup_pack_header_footer() rewrites on every incremental fetch. Under DAX this
// in-place store is serviced by a writable mapping the host must hand out for the open
// fd, not re-derive from the 0444 mode. Broken: EACCES on write, SIGBUS through the map.
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <path>\n", argv[0]); return 2; }
    int fd = open(argv[1], O_CREAT | O_RDWR, 0444);        // 0444 on disk, writable fd
    if (fd < 0) { perror("open"); return 1; }
    if (ftruncate(fd, 4096)) { perror("ftruncate"); return 1; }
    char *p = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) { perror("mmap"); return 1; }
    p[0] = (char)0xAB;                                     // in-place store inside i_size
    p[8] = (char)0xCD;
    if (msync(p, 4096, MS_SYNC)) { perror("msync"); return 1; }
    unsigned char b[9];
    if (pread(fd, b, 9, 0) != 9) { perror("pread"); return 1; }
    if (b[0] != 0xAB || b[8] != 0xCD) { fprintf(stderr, "perm: bytes did not reach the file\n"); return 1; }
    printf("perm OK\n");
    return 0;
}
EOF

# Static binaries need no guest libc, compiler, or network. If the toolchain cannot
# link -static, fail here rather than with "not found" inside the guest.
"$CC" -O2 -static -o "$work/fsxmini" "$work/fsxmini.c" \
  || { echo "fsx-e2e: static compile of fsxmini failed (need a -static-capable $CC)" >&2; exit 2; }
"$CC" -O2 -static -o "$work/perm" "$work/perm.c" \
  || { echo "fsx-e2e: static compile of perm failed" >&2; exit 2; }
chmod +x "$work/fsxmini" "$work/perm"
rm -f "$work"/*.c

# The guest command runs both programs on /work (the share under test): perm first (the
# targeted regression), then a fsxmini sweep. A fixed seed makes any failure reproducible.
guest="/work/perm /work/pk && /work/fsxmini 1 $FSX_OPS $FSX_MAXLEN /work/tf"

names=()
results=()
failed=0
mode() { # <label> <env assignment or ''> <extra vk run args...>
  local label=$1 envassign=$2
  shift 2
  names+=("$label")
  echo
  echo "################ $label"
  rm -f "$work"/tf "$work"/pk
  if timeout -k 30 "$STEP_TIMEOUT" env ${envassign:+"$envassign"} "$VK" run "$FSX_IMAGE" \
      --workdir "$work" "$@" -- sh -c "$guest"; then
    results+=("ok")
  else
    results+=("FAIL (rc $?)")
    failed=1
  fi
}

mode "libkrun dax=off"  ""                 --dax off
mode "libkrun dax=8G"   ""                 --dax 8G
if command -v cloud-hypervisor >/dev/null 2>&1; then
  mode "cloud-hypervisor" "VIRTKIT_VMM=ch"
else
  names+=("cloud-hypervisor")
  results+=("skip: no cloud-hypervisor on PATH")
  echo
  echo "################ cloud-hypervisor — skipped (no cloud-hypervisor on PATH)"
fi

echo
echo "################ results"
for i in "${!names[@]}"; do
  printf '  %-24s %s\n' "${names[$i]}" "${results[$i]}"
done
if [ "$failed" -ne 0 ]; then
  echo "FAIL: a filesystem mode did not pass"
  exit 1
fi
echo "PASS: all filesystem modes passed"
