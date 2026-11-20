/* Single-threaded libuuid shim for mkfs.btrfs. Require a hex VK_UUID_SEED
 * so unrelated inputs do not all share one counter sequence. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
typedef unsigned char uuid_t[16];
static uint64_t n;
static void fill(uuid_t out) {
    const char *s = getenv("VK_UUID_SEED");
    char *end;
    uint64_t seed = s ? strtoull(s, &end, 16) : 0;
    if (!s || !*s || *end) {
        fputs("libvkuuid: VK_UUID_SEED is not a hex number\n", stderr);
        abort();
    }
    uint64_t x = seed ^ (0x9e3779b97f4a7c15ULL * ++n);
    for (int i = 0; i < 16; i++) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; out[i] = (unsigned char)x; }
    out[6] = (out[6] & 0x0f) | 0x40; out[8] = (out[8] & 0x3f) | 0x80;
}
void uuid_generate(uuid_t out) { fill(out); }
void uuid_generate_random(uuid_t out) { fill(out); }
void uuid_generate_time(uuid_t out) { fill(out); }
int uuid_generate_time_safe(uuid_t out) { fill(out); return 0; }
