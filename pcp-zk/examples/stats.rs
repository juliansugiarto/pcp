//! Print the shape of the constraint system (used for COSTS.md).
use halo2_proofs::{pasta::Fp, plonk::{Circuit, ConstraintSystem}};
fn main() {
    let mut cs = ConstraintSystem::<Fp>::default();
    pcp_zk::circuit::SaleCircuit::configure(&mut cs);
    println!("degree {} blinding_factors {}", cs.degree(), cs.blinding_factors());
    println!("{:#?}", cs.pinned());
}
