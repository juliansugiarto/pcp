//! The fuzz harnesses on stable: honest seeds, single-byte variations of
//! them, and pseudo-random inputs. libFuzzer (nightly, CI) goes further;
//! this keeps the harnesses compiled and catches the shallow bugs.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn inputs(n: usize, seed: u64) -> Vec<Vec<u8>> {
    let mut rng = StdRng::seed_from_u64(seed);
    let h = pcp_fuzz::honest();
    let seeds: Vec<Vec<u8>> = [
        &h.request,
        &h.offer,
        &h.bundle,
        &h.binding,
        &h.seller_snapshot,
        &h.buyer_snapshot,
    ]
    .iter()
    .map(|v| serde_json::to_vec(v).unwrap())
    .collect();
    let mut out = seeds.clone();
    for i in 0..n {
        let mut x = if i % 2 == 0 {
            seeds[i % seeds.len()].clone()
        } else {
            (0..rng.gen_range(0..256)).map(|_| rng.gen()).collect()
        };
        if !x.is_empty() {
            for _ in 0..rng.gen_range(1..4) {
                let j = rng.gen_range(0..x.len());
                x[j] = rng.gen();
            }
        }
        out.push(x);
    }
    out
}

macro_rules! run {
    ($name:ident, $n:expr) => {
        #[test]
        fn $name() {
            for (i, x) in inputs($n, stringify!($name).len() as u64)
                .iter()
                .enumerate()
            {
                let r = std::panic::catch_unwind(|| pcp_fuzz::$name(x));
                assert!(
                    r.is_ok(),
                    "{} panicked on input {i}: {:?}",
                    stringify!($name),
                    String::from_utf8_lossy(x)
                );
            }
        }
    };
}

run!(f1_messages, 2000);
run!(f2_seller, 1500);
run!(f3_buyer, 3000);
run!(f4_statement, 2000);
run!(f5_jobs, 1000);
run!(f6_restore, 2000);
run!(f7_lnd, 2000);

/// The F3 oracle is not vacuous: unchanged or harmlessly changed messages
/// reach InvoiceAccepted, and many inputs do change a bound field.
#[test]
fn f3_reaches_the_state_it_guards() {
    let (mut reached, mut changed) = (0, 0);
    for x in inputs(3000, 3) {
        let (c, r) = pcp_fuzz::f3_outcome(&x);
        reached += r as u32;
        changed += c as u32;
    }
    assert!(
        reached > 50,
        "only {reached} inputs reached InvoiceAccepted"
    );
    assert!(changed > 500, "only {changed} inputs changed a bound field");
}
