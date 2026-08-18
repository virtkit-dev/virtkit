# Target: an image whose ENTRYPOINT *prepares the machine* and only then execs the real
# init. `--init image` cannot boot this shape — it hands PID 1 straight to /sbin/init, so
# the preparation never runs and systemd comes up with none of the services it assembles.
#
# The image ships:
#   /prepare-machine.sh   -> the ENTRYPOINT: assembles a systemd service, then execs init
#   /sbin/init            -> systemd (PID 1 once the entrypoint execs it)
#   /boot/vmlinuz-<ver>   -> the Debian kernel (virtkit reads it host-side to boot)
#   /lib/modules/<ver>/   -> the matching modules for the preinit initramfs
FROM debian:bookworm

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        systemd systemd-sysv \
        linux-image-amd64 \
        iproute2 kmod; \
    rm -rf /var/lib/apt/lists/*

COPY prepare-machine.sh /prepare-machine.sh
RUN chmod +x /prepare-machine.sh

# Exec form, so the boot config carries the argv verbatim: virtkit execs ENTRYPOINT+CMD
# as PID 1 under `--init entrypoint`. The CMD is there to be passed on — the entrypoint
# forwards its own argv to the init it execs, so both halves have to arrive.
ENTRYPOINT ["/prepare-machine.sh"]
CMD ["--log-level=info"]
