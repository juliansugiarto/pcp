// Builds the guest in `guest/` for the zkVM target and writes
// `methods.rs` (PCP_GUEST_ELF, PCP_GUEST_ID) into OUT_DIR.
//
// Building the guest needs the RISC Zero toolchain (installed with `rzup`).
// Set RISC0_SKIP_BUILD=1 to type-check the host without a guest (the ELF is
// then empty and proving fails at run time).
//
// For an image id that a buyer on another machine can reproduce, build
// with Docker: `RISC0_USE_DOCKER=1 cargo build --release`. Without Docker,
// the image id depends on the local toolchain and two machines may disagree.
//
// risc0-build 3.0.6 does not read RISC0_USE_DOCKER itself (only
// `cargo risczero build` does), so this script maps it to `use_docker`.
// The Docker build context is the repository root (`../..` from here),
// because the guest depends on `../../../pcp`, outside `pcp-risc0/`. The
// guest is built `--locked` against `guest/Cargo.lock`, which is committed
// for that reason.
use std::collections::HashMap;

use risc0_build::{DockerOptionsBuilder, GuestOptionsBuilder};

fn main() {
    println!("cargo:rerun-if-env-changed=RISC0_USE_DOCKER");
    let use_docker = std::env::var("RISC0_USE_DOCKER")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false);
    if !use_docker {
        risc0_build::embed_methods();
        return;
    }
    let docker = DockerOptionsBuilder::default()
        .root_dir("../..")
        .build()
        .expect("docker options");
    let guest = GuestOptionsBuilder::default()
        .use_docker(docker)
        .build()
        .expect("guest options");
    risc0_build::embed_methods_with_options(HashMap::from([("pcp-guest", guest)]));
}
