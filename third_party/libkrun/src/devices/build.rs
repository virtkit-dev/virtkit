// Link libtpms and the libcrypto it computes with, statically, for the `tpm` feature (local
// patch, see VENDOR.md). VK_LIBTPMS_DIR names a prefix with lib/libtpms.a and lib/libcrypto.a
// (the build image's /opt/tpm, nixpkgs' static musl builds).

fn main() {
    println!("cargo::rerun-if-env-changed=VK_LIBTPMS_DIR");
    if std::env::var_os("CARGO_FEATURE_TPM").is_none() {
        return;
    }
    let dir = std::env::var("VK_LIBTPMS_DIR").expect(
        "the `tpm` feature links libtpms: set VK_LIBTPMS_DIR to a prefix with lib/libtpms.a and \
         lib/libcrypto.a (the build image has them at /opt/tpm)",
    );
    let lib = std::path::Path::new(&dir).join("lib");
    for archive in ["libtpms.a", "libcrypto.a"] {
        let path = lib.join(archive);
        println!("cargo::rerun-if-changed={}", path.display());
        assert!(path.is_file(), "VK_LIBTPMS_DIR: no {}", path.display());
    }
    println!("cargo::rustc-link-search=native={}", lib.display());
    println!("cargo::rustc-link-lib=static=tpms");
    println!("cargo::rustc-link-lib=static=crypto");
}
