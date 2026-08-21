use rustc_version::{version_meta, Channel};

fn main() {
    let async_feature = std::env::var_os("CARGO_FEATURE_ASYNC").is_some();
    let sync_feature = std::env::var_os("CARGO_FEATURE_SYNC").is_some();
    let sync_wrappers_feature = std::env::var_os("CARGO_FEATURE_SYNC_WRAPPERS").is_some();

    if !async_feature && !sync_feature {
        panic!("Either the `async` feature (included in defaults) or `sync` must be enabled!");
    }

    if sync_wrappers_feature && sync_feature {
        panic!("The `sync` feature conflicts with `sync-wrappers`. Consider using `sync` alone.");
    }

    if async_feature && sync_feature {
        panic!(
            "The `async` and `sync` features are mutually exclusive. \
            `async` is in defaults, so use `--no-default-features --features=sync` for sync mode."
        );
    }

    println!("cargo:rustc-check-cfg=cfg(nightly)");

    if version_meta().unwrap().channel == Channel::Nightly {
        println!("cargo:rustc-cfg=nightly");
    }
}
