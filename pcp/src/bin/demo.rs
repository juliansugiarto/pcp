//! PCP/0 demo: verified exchange under a human mandate.
//!
//! Every agent acts for a principal who signed its mandate. Payouts land on
//! the principal's node; receipts and refusals go to the principal's log.
//!
//! Demo 1: a 9x9 sudoku solution (the 2016 ZKCP sale, re-enacted).
//! Demo 2: pay for a patch that passes the buyer's test suite.
//! Demo 3: the same buyer agent tries again with its cap used up, and is
//!         refused.
//!
//! Uses the INSECURE dev proof backend and a simulated Lightning ledger.

use pcp::encoding::Hash32;
use pcp::job::testsuite::RunReport;
use pcp::job::{JobClass, SudokuJob, TestSuiteJob};
use pcp::lightning::Ledger;
use pcp::mandate::{Agent, LogEntry, Mandate, MandateTerms, PublicKey, Role, SecretKey};
use pcp::proof::InsecureDevTransparentBackend;
use pcp::protocol::{
    Buyer, BuyerPolicy, BuyerProgress, PcpError, SaleOutcome, Seller, SellerConfig,
};
use rand::rngs::OsRng;

fn short(h: &Hash32) -> String {
    format!("{}..", &hex::encode(h)[..16])
}

fn step(n: &str, text: impl AsRef<str>) {
    println!("  [{n}] {}", text.as_ref());
}

fn banner() {
    println!("==============================================================================");
    println!(" PCP/0 demo: verified exchange under a human mandate");
    println!(" Every agent acts for a principal who signed its mandate (scope, cap,");
    println!(" per-deal max, expiry). Payouts land on the principal's node; receipts");
    println!(" and refusals go to the principal's log.");
    println!("------------------------------------------------------------------------------");
    println!(" WARNING: proof backend = InsecureDevTransparentBackend.");
    println!("          It is NOT zero knowledge: its 'proof' is the witness under a seal");
    println!("          whose key is in the source code. It exercises the protocol flow only.");
    println!(" WARNING: Lightning is simulated in memory. No network, no real sats.");
    println!("==============================================================================");
}

/// A principal: a key and a Lightning node. It never sends a PCP message.
struct Principal {
    name: &'static str,
    key: SecretKey,
    node: String,
}

impl Principal {
    fn new(name: &'static str, ledger: &mut Ledger, funds_msat: u64) -> Principal {
        let key = SecretKey::generate(&mut OsRng);
        let node = format!("{name}-node");
        ledger.open_principal_node(&node, key.public_key(), funds_msat);
        Principal { name, key, node }
    }

    fn pk(&self) -> PublicKey {
        self.key.public_key()
    }

    /// Sign a mandate for a fresh agent key.
    fn mandate(
        &self,
        agent_name: &str,
        role: Role,
        job: &dyn JobClass,
        cap_msat: u64,
        per_deal_max_msat: u64,
    ) -> Agent {
        let agent_key = SecretKey::generate(&mut OsRng);
        let m = Mandate::sign(
            &self.key,
            agent_key.public_key(),
            MandateTerms {
                role,
                scope: vec![job.spec_hash()],
                cap_msat,
                per_deal_max_msat,
                payout_node: self.node.clone(),
                expires_at: 86_400,
            },
            &mut OsRng,
        );
        println!(
            "  mandate: {} (principal {}) authorises {} (agent {}) as {}: scope [{}], cap {} msat, \
             per-deal max {} msat, payout node {}, expires t={}s, id {}",
            self.name,
            short(&self.pk()),
            agent_name,
            short(&agent_key.public_key()),
            role.as_str(),
            job.job_id(),
            m.cap_msat,
            m.per_deal_max_msat,
            m.payout_node,
            m.expires_at,
            short(&m.mandate_id())
        );
        Agent::new(agent_key, m).expect("mandate verifies")
    }
}

struct Sale<'a> {
    title: &'a str,
    buyer: &'a str,
    seller: &'a str,
    buyer_principal: &'a Principal,
    seller_principal: &'a Principal,
    buyer_agent: &'a Agent,
    seller_agent: &'a Agent,
    price_msat: u64,
    max_price_msat: u64,
}

fn balances(ledger: &Ledger, a: &Principal, b: &Principal) -> String {
    format!(
        "{} {} msat / {} {} msat",
        a.name,
        ledger.principal_balance(&a.pk()),
        b.name,
        ledger.principal_balance(&b.pk())
    )
}

/// Run one sale end to end. `work` is the seller's job: it returns candidate
/// results in order, and the seller offers the first one that passes its
/// own check.
#[allow(clippy::too_many_arguments)]
fn run<J: JobClass + Clone + 'static>(
    sale: Sale,
    ledger: &mut Ledger,
    job: J,
    input: Vec<u8>,
    show_input: impl Fn(&[u8]) -> String,
    work: impl Fn(&[u8]) -> Vec<Vec<u8>>,
    show_result: impl Fn(&[u8]) -> String,
) -> Result<(), PcpError> {
    println!();
    println!("### {}", sale.title);
    let (bp, sp) = (sale.buyer_principal, sale.seller_principal);
    println!(
        "  ledger (principals' nodes; agents hold no funds): {}",
        balances(ledger, bp, sp)
    );
    println!(
        "  job class: {}  spec_hash {}",
        job.job_id(),
        short(&job.spec_hash())
    );
    println!("  input:\n{}", indent(&show_input(&input)));

    // 1. Request
    let policy = BuyerPolicy {
        allow_insecure_dev_backend: true,
        ..BuyerPolicy::default()
    };
    let (mut buyer, req) = Buyer::new(
        sale.buyer_agent,
        Box::new(job.clone()),
        Box::new(InsecureDevTransparentBackend),
        policy,
        input.clone(),
        sale.max_price_msat,
        ledger.now(),
        &mut OsRng,
    )?;
    step(
        "1 request",
        format!(
            "{} -> {}: input_commitment {}, buyer_nonce {}, max {} msat, signed by the agent, \
             carries {}'s mandate (already spent {} msat)",
            sale.buyer,
            sale.seller,
            short(&req.input_commitment),
            short(&req.buyer_nonce),
            req.max_price_msat,
            bp.name,
            req.mandate_spent_msat
        ),
    );

    // 2. Offer
    let mut seller = Seller::new(
        sale.seller_agent,
        Box::new(job.clone()),
        Box::new(InsecureDevTransparentBackend),
        SellerConfig {
            price_msat: sale.price_msat,
            ..SellerConfig::default()
        },
    );
    let offer = match seller.make_offer(&req, ledger.now()) {
        Ok(o) => o,
        Err(e) => {
            step(
                "2 refused",
                format!("{} refuses the request: {}", sale.seller, e.code()),
            );
            step("2 refused", format!("    {e:?}"));
            let e2 = buyer.refused_by_seller(&e);
            step(
                "2 refused",
                format!(
                    "{} records the refusal for {}: {}. Nothing was offered, proven or paid.",
                    sale.buyer,
                    bp.name,
                    e2.code()
                ),
            );
            println!("  balances: {}", balances(ledger, bp, sp));
            return Err(e);
        }
    };
    step(
        "2 offer",
        format!(
            "{} -> {}: price {} msat, offer_id {}, expires t={}s, backend {}",
            sale.seller,
            sale.buyer,
            offer.price_msat,
            short(&offer.offer_id()),
            offer.offer_expires_at,
            offer.backend_id
        ),
    );
    buyer.accept_offer(&offer, ledger.now())?;
    step(
        "2 offer",
        format!(
            "{} accepts: {}'s mandate signature, agent signature, scope, expiry, per-deal max OK; \
             seller_node == payout node {}; own cap leaves {} msat",
            sale.buyer,
            sp.name,
            offer.seller_node,
            sale.buyer_agent.remaining_msat()
        ),
    );

    // 3. Work
    let candidates = work(&input);
    let mut chosen = None;
    for (i, cand) in candidates.into_iter().enumerate() {
        let ok = job.check(&input, &cand);
        step(
            "3 work",
            format!(
                "{} candidate #{}: {} -> local check {}",
                sale.seller,
                i + 1,
                show_result(&cand).lines().next().unwrap_or(""),
                if ok { "PASS" } else { "FAIL" }
            ),
        );
        if !ok {
            if let Some(why) = explain_failure(&job, &input, &cand) {
                step("3 work", format!("    {why}"));
            }
            // A seller who tries to sell it anyway gets nowhere:
            let r = seller.fulfil(&req, &offer, cand, ledger, &mut OsRng);
            step(
                "3 work",
                format!("    trying to sell it anyway: {:?}", r.err().unwrap()),
            );
            continue;
        }
        chosen = Some(cand);
        break;
    }
    let result = chosen.expect("seller found no passing result");

    // 4. Proof bundle + invoice
    let (bundle, binding) = seller.fulfil(&req, &offer, result, ledger, &mut OsRng)?;
    let st = &bundle.statement;
    step(
        "4 bundle",
        format!(
            "{} picks a fresh key k (kept secret), H = SHA256(k) = {}",
            sale.seller,
            short(&st.payment_hash)
        ),
    );
    step(
        "4 bundle",
        format!(
            "C = Enc_k(R): {} bytes, ciphertext_hash {}; proof {} bytes; bundle JSON {} bytes",
            bundle.ciphertext.len(),
            short(&st.ciphertext_hash),
            bundle.proof.len(),
            serde_json::to_string(&bundle).unwrap().len()
        ),
    );
    step(
        "4 invoice",
        format!(
            "invoice: payment_hash {}, {} msat, payee {}, expires in {}s, description_hash = statement_hash {}",
            short(&binding.invoice.payment_hash),
            binding.invoice.amount_msat,
            binding.invoice.payee,
            binding.invoice.expiry_secs,
            short(&binding.statement_hash)
        ),
    );

    // 5. Verify before paying
    step(
        "5 verify",
        format!(
            "{} result before paying: {:?}",
            sale.buyer,
            buyer.result().unwrap_err()
        ),
    );
    buyer.verify_bundle(&bundle)?;
    step(
        "5 verify",
        "proof OK: input_commitment, job_check(input, R), C = Enc_k(R), H = SHA256(k), bound to offer and nonce",
    );
    buyer.check_invoice(&binding, ledger.now())?;
    step("5 verify", format!("invoice OK: payment_hash == H, amount == price, payee == {}'s payout node, expiry and HTLC lock within policy", sp.name));

    // 6. Pay
    let htlc = buyer.pay(ledger)?;
    step(
        "6 pay",
        format!(
            "{} locks {} msat from {} in HTLC #{} to H. balances: {}",
            sale.buyer,
            sale.price_msat,
            buyer.node(),
            htlc,
            balances(ledger, bp, sp)
        ),
    );
    assert_eq!(buyer.poll(ledger)?, BuyerProgress::Waiting);
    ledger.advance(2);

    // 7. Settle: the seller reveals k to claim the payment
    for o in seller.settle_paid(ledger) {
        if let SaleOutcome::Settled { amount_msat, .. } = o {
            step(
                "7 settle",
                format!(
                    "{} reveals k to settle; {} msat land on {} ({}'s node)",
                    sale.seller,
                    amount_msat,
                    seller.node(),
                    sp.name
                ),
            );
        }
    }

    // 8. Buyer takes k, checks, decrypts, rechecks
    assert_eq!(buyer.poll(ledger)?, BuyerProgress::Delivered);
    let receipt = buyer.receipt()?.clone();
    step(
        "8 deliver",
        format!(
            "{} receives k = {}; SHA256(k) == H: yes",
            sale.buyer,
            short(&receipt.preimage)
        ),
    );
    step(
        "8 deliver",
        "C decrypted with k; job_check(input, R) re-run locally: PASS",
    );
    let r = buyer.result()?.to_vec();
    println!("  result R:\n{}", indent(&show_result(&r)));
    step(
        "9 receipt",
        format!(
            "both agents sign a receipt for offer {} and append it to their principal's log",
            short(&receipt.offer_id),
        ),
    );
    println!(
        "  final balances: {}. No escrow, no platform, no third account touched.",
        balances(ledger, bp, sp)
    );
    Ok(())
}

fn explain_failure<J: JobClass>(job: &J, input: &[u8], cand: &[u8]) -> Option<String> {
    if job.job_id() != TestSuiteJob.job_id() {
        return None;
    }
    match TestSuiteJob.run(input, cand) {
        RunReport::Fail {
            index,
            x,
            expected,
            got,
        } => Some(format!(
            "test #{index}: f({x}) expected {expected}, got {}",
            got.map(|g| g.to_string()).unwrap_or_else(|| "error".into())
        )),
        RunReport::ParseError(e) => Some(format!("parse error: {e}")),
        _ => None,
    }
}

fn indent(s: &str) -> String {
    s.lines()
        .map(|l| format!("      {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Print a principal's log and verify it the way the principal would.
fn print_log(p: &Principal, agent_name: &str, agent: &Agent, jobs: &[&dyn JobClass]) {
    let log = agent.log();
    println!(
        "  {}'s log for {} (mandate {}):",
        p.name,
        agent_name,
        short(&agent.mandate_id())
    );
    for e in log.entries() {
        match e {
            LogEntry::Deal { receipt: r, .. } => println!(
                "    receipt  {:<6} offer {}  {} msat at t={}s  counterparty principal {}  sig {:?}",
                r.role.as_str(),
                short(&r.offer_id),
                r.amount_msat,
                r.settled_at,
                short(&r.counterparty_principal_key),
                r.agent_sig
            ),
            LogEntry::Refusal(r) => println!(
                "    refusal  {:<6} {}  {} at t={}s  sig {:?}",
                r.role.as_str(),
                short(&r.subject_id),
                r.reason,
                r.at,
                r.agent_sig
            ),
        }
    }
    let text = log.to_jsonl();
    match log.verify(agent.mandate(), jobs) {
        Ok(s) => println!(
            "    {} verifies offline: {} deal(s) re-verified (preimage, decryption, job check), \
             {} refusal(s), all signed by the agent, total {} of cap {} msat. Export: {} JSON lines, {} bytes.",
            p.name,
            s.deals,
            s.refusals,
            s.total_msat,
            agent.mandate().cap_msat,
            text.lines().count(),
            text.len()
        ),
        Err(e) => println!("    VERIFICATION FAILED at entry {}: {:?}", e.index, e.error),
    }
}

fn main() {
    banner();
    let mut ledger = Ledger::new();

    // Demo 1: sudoku (the puzzle from the 2016 ZKCP demo is not reproduced;
    // this is a standard 9x9 instance).
    let sudoku = SudokuJob::nine();
    let puzzle = sudoku
        .parse_grid("53..7.... 6..195... .98....6. 8...6...3 4..8.3..1 7...2...6 .6....28. ...419..5 ....8..79")
        .unwrap();
    println!();
    println!("### Principals and mandates");
    let alice = Principal::new("alice", &mut ledger, 5_000_000);
    let budi = Principal::new("budi", &mut ledger, 0);
    let agent_a = alice.mandate("agent-A", Role::Buyer, &sudoku, 2_000_000, 1_500_000);
    let agent_b = budi.mandate("agent-B", Role::Seller, &sudoku, 50_000_000, 2_000_000);
    let citra = Principal::new("citra", &mut ledger, 5_000_000);
    let dewi = Principal::new("dewi", &mut ledger, 0);
    let ci_bot = citra.mandate("ci-bot", Role::Buyer, &TestSuiteJob, 3_000_000, 3_000_000);
    let coder = dewi.mandate(
        "coder-agent",
        Role::Seller,
        &TestSuiteJob,
        50_000_000,
        5_000_000,
    );

    let r1 = run(
        Sale {
            title: "Demo 1: a sudoku solution sold between two agents",
            buyer: "agent-A",
            seller: "agent-B",
            buyer_principal: &alice,
            seller_principal: &budi,
            buyer_agent: &agent_a,
            seller_agent: &agent_b,
            price_msat: 1_000_000,
            max_price_msat: 1_200_000,
        },
        &mut ledger,
        sudoku,
        puzzle,
        |g| sudoku.render(g),
        |input| vec![sudoku.solve(input).expect("solvable")],
        |g| sudoku.render(g),
    );

    // Demo 2: pay for a passing patch. The buyer's suite specifies
    // clamp(x) to [0, 100]. The seller's first attempt misses the upper bound.
    let suite_vectors = [
        (-5, 0),
        (0, 0),
        (42, 42),
        (100, 100),
        (101, 100),
        (i64::MAX, 100),
        (i64::MIN, 0),
    ];
    let suite = TestSuiteJob::encode_suite(&suite_vectors);
    let show_suite = |s: &[u8]| {
        TestSuiteJob::decode_suite(s)
            .unwrap()
            .iter()
            .map(|(x, y)| format!("assert f({x}) == {y}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let patch_sale = |title| Sale {
        title,
        buyer: "ci-bot",
        seller: "coder-agent",
        buyer_principal: &citra,
        seller_principal: &dewi,
        buyer_agent: &ci_bot,
        seller_agent: &coder,
        price_msat: 2_500_000,
        max_price_msat: 3_000_000,
    };
    let r2 = run(
        patch_sale("Demo 2: pay for a patch that passes the buyer's test suite"),
        &mut ledger,
        TestSuiteJob,
        suite.clone(),
        show_suite,
        |_| {
            vec![
                b"if(x < 0, 0, x)".to_vec(),
                b"if(x < 0, 0, if(x > 100, 100, x))".to_vec(),
            ]
        },
        |r| format!("f(x) = {}", String::from_utf8_lossy(r)),
    );

    // Demo 3: ci-bot wants a second patch. Its mandate cap is 3 000 000
    // msat and 2 500 000 is already spent, so the seller refuses.
    ledger.advance(60);
    let r3 = run(
        patch_sale("Demo 3: the same agent asks again with its cap used up"),
        &mut ledger,
        TestSuiteJob,
        suite,
        show_suite,
        |_| vec![b"if(x < 0, 0, if(x > 100, 100, x))".to_vec()],
        |r| format!("f(x) = {}", String::from_utf8_lossy(r)),
    );

    println!();
    println!("### Receipts: what each principal can read and verify");
    let jobs: [&dyn JobClass; 2] = [&sudoku, &TestSuiteJob];
    print_log(&alice, "agent-A", &agent_a, &jobs);
    print_log(&budi, "agent-B", &agent_b, &jobs);
    print_log(&citra, "ci-bot", &ci_bot, &jobs);
    print_log(&dewi, "coder-agent", &coder, &jobs);

    println!();
    let mut failed = false;
    for (name, r, expect_ok) in [
        ("Demo 1", r1, true),
        ("Demo 2", r2, true),
        ("Demo 3", r3, false),
    ] {
        match (r, expect_ok) {
            (Ok(()), true) => println!("{name}: settled."),
            (Err(e), false) => println!("{name}: refused as expected ({}).", e.code()),
            (Ok(()), false) => {
                println!("{name}: FAILED: expected a refusal");
                failed = true;
            }
            (Err(e), true) => {
                println!("{name}: FAILED: {e}");
                failed = true;
            }
        }
    }
    if failed {
        std::process::exit(1);
    }
}
