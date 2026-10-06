// For the test-only `libtpms` feature: find libtpms and the libcrypto it computes with in
// VK_LIBTPMS_DIR (the build image's /opt/tpm), as libkrun's `tpm` feature does. The differential
// test links them itself (tests/libtpms/mod.rs), statically.

fn main() {
    println!("cargo::rerun-if-env-changed=VK_LIBTPMS_DIR");
    if std::env::var_os("CARGO_FEATURE_LIBTPMS").is_none() {
        return;
    }
    let Some(dir) = std::env::var_os("VK_LIBTPMS_DIR") else {
        println!(
            "cargo::error=the `libtpms` feature needs VK_LIBTPMS_DIR (/opt/tpm in the build image)"
        );
        return;
    };
    let lib = std::path::Path::new(&dir).join("lib");
    for archive in ["libtpms.a", "libcrypto.a"] {
        let path = lib.join(archive);
        println!("cargo::rerun-if-changed={}", path.display());
        if !path.is_file() {
            println!("cargo::error=VK_LIBTPMS_DIR: no {}", path.display());
        }
    }
    println!("cargo::rustc-link-search=native={}", lib.display());
}
