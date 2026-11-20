# mkfs.btrfs --rootdir runs in userspace on vk's pinned kernel, which lacks btrfs.
# uuidshim.c combines VK_UUID_SEED with a counter, and libfaketime freezes the clock.
# Reproducing an image requires the same source, size and converter build because
# the Debian base and packages are unpinned.
FROM debian:trixie AS converter
RUN apt-get update && apt-get install -y --no-install-recommends btrfs-progs e2fsprogs gcc libc6-dev faketime \
    && rm -rf /var/lib/apt/lists/*
COPY uuidshim.c /tmp/uuidshim.c
RUN printf 'UUID_1.0 { global: uuid_generate; uuid_generate_random; uuid_generate_time; };\nUUID_2.20 { global: uuid_generate_time_safe; } UUID_1.0;\n' > /tmp/uuid.map \
    && gcc -shared -fPIC -O2 -Wl,--version-script=/tmp/uuid.map -o /usr/local/lib/libvkuuid.so /tmp/uuidshim.c
