//! PCP/0 guest: proves the statement core's relation inside the RISC Zero
//! zkVM and commits the public journal.
//!
//! Private input (one frame, `StatementInput::encode`): spec_hash, input,
//! result R, key k, ciphertext C, offer_id, buyer_nonce.
//! Public output (journal, `Journal::to_bytes`): the statement fields, whose
//! SHA-256 is `statement_hash`.
//!
//! The relation is `pcp::statement::evaluate`, the same function the
//! crate's dev backend runs in the clear. If it does not hold, the guest
//! panics and no receipt exists. The panic message names only the failed
//! relation, never R or k.
//!
//! NOT COMPILED in the authoring environment (no RISC Zero toolchain there).

use pcp::statement::{evaluate, StatementInput};
use risc0_zkvm::guest::env;

fn main() {
    // Read one frame as the host writes it with `ExecutorEnvBuilder::write_frame`:
    // a u32 length, then the bytes. (`env::read_frame` does the same but is
    // marked unstable in risc0-zkvm 3.0.)
    let mut len: u32 = 0;
    env::read_slice(core::slice::from_mut(&mut len));
    let mut bytes = vec![0u8; len as usize];
    env::read_slice(&mut bytes);

    let input = StatementInput::decode(&bytes).expect("PCP/0 guest: malformed input");
    let journal = match evaluate(&input) {
        Ok(j) => j,
        Err(e) => panic!("PCP/0 guest: relation does not hold: {e:?}"),
    };
    env::commit_slice(&journal.to_bytes());
}
