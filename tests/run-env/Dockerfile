FROM debian:bookworm AS base
ENV PATH=/opt/image/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV IMAGE_ONLY=from-image
RUN mkdir -p /opt/image/bin && printf '#!/bin/sh\nprintf "image-path-ok\\n"\n' >/opt/image/bin/image-tool && chmod 755 /opt/image/bin/image-tool
RUN mkdir -p /etc/profile.d/private && chown root:nogroup /etc/profile.d /etc/profile.d/private && chmod 750 /etc/profile.d /etc/profile.d/private

FROM base AS nonroot
USER nobody

FROM base AS fullvm
# The preinit currently probes a version directory even with --kernel default.
RUN mkdir -p /lib/modules/test-kernel
ENTRYPOINT ["/bin/sleep", "infinity"]
