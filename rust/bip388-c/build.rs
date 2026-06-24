//! Generates the C header (`include/bip388.h`) from the public `extern "C"`
//! surface using cbindgen. Runs on the host (build dependency), so it works
//! regardless of the eventual compilation target.

use std::path::PathBuf;

fn main() {
    let crate_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());

    // Re-run only when the sources or config that shape the header change.
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=build.rs");

    let config = cbindgen::Config::from_file(crate_dir.join("cbindgen.toml"))
        .expect("failed to read cbindgen.toml");

    match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => {
            // Committed copy for consumers that don't run the Rust build, plus a
            // copy in OUT_DIR for build-script-driven includes.
            bindings.write_to_file(crate_dir.join("include").join("bip388.h"));
            let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
            bindings.write_to_file(out_dir.join("bip388.h"));
        }
        // Don't fail the build (e.g. cross-compiles) on header-gen issues; the
        // committed header remains usable.
        Err(e) => println!("cargo:warning=cbindgen header generation skipped: {e}"),
    }
}
