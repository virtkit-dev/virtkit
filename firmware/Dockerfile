# The UEFI firmware vk boots a Windows (UEFI) guest with: edk2's OvmfPkg/CloudHv platform
# (CLOUDHV.fd), an ELF with a PVH entry point. libkrun loads it like a kernel and hands it the
# memory map and its ACPI tables; it finds the virtio-blk disk and starts the guest's boot
# loader. The build is nixpkgs' OVMF-cloud-hypervisor at the rev .devcontainer/nix/flake.lock
# pins (the `firmware` flake output), so it comes from the same lock as the binaries, usually
# as a cache.nixos.org substitute: the recorded sha256 is that substitute's, and a local build
# may differ. build-firmware.sh builds virtkit-build first.
FROM virtkit-build AS build
USER root
# The output is OVMF's `fd` one, which a plain --out-link would name `<link>-fd`: print its
# store path instead, kept for build-firmware.sh's manifest. install, not cp: store files are
# 0444, which a rerun could not overwrite in dist/. Fail unless the result is an ELF.
RUN fw=$(nix build "path:/src/nix#firmware" --no-link --print-out-paths) \
 && mkdir -p /build && install -m 0644 "$fw/FV/CLOUDHV.fd" /build/CLOUDHV.fd \
 && echo "$fw" > /build/CLOUDHV.fd.storepath \
 && { [ "$(od -An -tx1 -N4 /build/CLOUDHV.fd | tr -d ' \n')" = 7f454c46 ] \
      || { echo "$fw/FV/CLOUDHV.fd is not an ELF" >&2; exit 1; }; }

FROM scratch AS artifact
COPY --from=build /build/CLOUDHV.fd /build/CLOUDHV.fd.storepath /
