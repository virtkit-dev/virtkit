# The UEFI firmware vk boots a Windows (UEFI) guest with: edk2's OvmfPkg/CloudHv platform
# (CLOUDHV.fd), an ELF with a PVH entry point. libkrun loads it like a kernel and hands it the
# memory map and its ACPI tables; it finds the virtio-blk disk and starts the guest's boot
# loader. Beside it, the templates of its variable store flash: CLOUDHV_VARS.fd empty,
# CLOUDHV_VARS.ms.fd with Microsoft's Secure Boot keys. The build is nixpkgs'
# OVMF-cloud-hypervisor (patched, with Secure Boot) and OVMFFull at the rev
# .devcontainer/nix/flake.lock pins (the `firmware` and `firmwareVars` flake outputs), so it
# comes from the same lock as the binaries. The patched firmware is no cache.nixos.org
# substitute and compiles locally; the templates usually download. build-firmware.sh builds
# virtkit-build first.
FROM virtkit-build AS build
USER root
# The output is OVMF's `fd` one, which a plain --out-link would name `<link>-fd`: print its
# store path instead, kept for build-firmware.sh's manifest. install, not cp: store files are
# 0444, which a rerun could not overwrite in dist/. Fail unless the result is an ELF and each
# template is the 528 KiB of the firmware's variable store flash (vk refuses any other length).
RUN fw=$(nix build "path:/src/nix#firmware" --no-link --print-out-paths) \
 && vars=$(nix build "path:/src/nix#firmwareVars" --no-link --print-out-paths) \
 && mkdir -p /build && install -m 0644 "$fw/FV/CLOUDHV.fd" /build/CLOUDHV.fd \
 && install -m 0644 "$vars/FV/OVMF_VARS.fd" /build/CLOUDHV_VARS.fd \
 && install -m 0644 "$vars/FV/OVMF_VARS.ms.fd" /build/CLOUDHV_VARS.ms.fd \
 && printf '%s\n' "$fw" "$vars" > /build/CLOUDHV.fd.storepath \
 && { [ "$(od -An -tx1 -N4 /build/CLOUDHV.fd | tr -d ' \n')" = 7f454c46 ] \
      || { echo "$fw/FV/CLOUDHV.fd is not an ELF" >&2; exit 1; }; } \
 && for v in CLOUDHV_VARS.fd CLOUDHV_VARS.ms.fd; do \
      [ "$(wc -c < /build/$v)" -eq 540672 ] || { echo "$v is not 540672 bytes" >&2; exit 1; }; \
    done

FROM scratch AS artifact
COPY --from=build /build/CLOUDHV.fd /build/CLOUDHV_VARS.fd /build/CLOUDHV_VARS.ms.fd \
  /build/CLOUDHV.fd.storepath /
