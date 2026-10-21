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

/// The guest builder image (`risczero/risc0-guest-builder:<tag>`). risc0-build
/// 3.0.6 defaults to `r0.1.88.0` (Rust 1.88), whose guest needs 98,941 user
/// cycles for sudoku9 and so pads to 2^18; `rzup install` ships Rust 1.97 and
/// the same guest fits 2^17 (88,606 user cycles), proving about 1.55x faster
/// on the same runner with 0.6x the memory (COSTS.md). `r0.1.97.0` is the
/// builder with that toolchain. Changing this tag changes
/// the image id. (The RISC0_DOCKER_CONTAINER_TAG environment variable still
/// overrides it, as in risc0-build.)
const GUEST_BUILDER_TAG: &str = "r0.1.97.0";

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
        .docker_container_tag(GUEST_BUILDER_TAG)
        .build()
        .expect("docker options");
    let guest = GuestOptionsBuilder::default()
        .use_docker(docker)
        .build()
        .expect("guest options");
    risc0_build::embed_methods_with_options(HashMap::from([("pcp-guest", guest)]));
}
