// Builds the guest in `guest/` for the zkVM target and writes
// `methods.rs` (PCP_GUEST_ELF, PCP_GUEST_ID) into OUT_DIR.
//
// NOT COMPILED in the authoring environment: building the guest needs the
// RISC Zero toolchain (installed with `rzup`), whose downloads were blocked
// there. Set RISC0_SKIP_BUILD=1 to type-check the host without a guest
// (the ELF is then empty and proving fails at run time).
//
// For an image id that a buyer on another machine can reproduce, build
// with Docker: `RISC0_USE_DOCKER=1 cargo build --release`. Without Docker,
// the image id depends on the local toolchain and two machines may disagree.
fn main() {
    risc0_build::embed_methods();
}
