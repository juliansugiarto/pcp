//! End-to-end flows using only the public API, the way an outside agent
//! would use the crate. The adversarial tests that need crate internals are
//! in `src/tests.rs`; the "no public accessor for the sealed witness" check
//! is a `compile_fail` doctest on `InsecureDevTransparentBackend`.

use pcp::job::{JobClass, SudokuJob, TestSuiteJob};
use pcp::lightning::Ledger;
use pcp::mandate::{Agent, Mandate, MandateTerms, PrincipalLog, Role, SecretKey};
use pcp::proof::InsecureDevTransparentBackend;
use pcp::protocol::{
    Buyer, BuyerPolicy, BuyerProgress, PcpError, SaleOutcome, Seller, SellerConfig,
};
use rand::rngs::OsRng;

/// A principal signs a mandate for a fresh agent key.
fn agent_for(principal: &SecretKey, role: Role, scope: Vec<[u8; 32]>, node: &str) -> Agent {
    let key = SecretKey::generate(&mut OsRng);
    let m = Mandate::sign(
        principal,
        key.public_key(),
        MandateTerms {
            role,
            scope,
            cap_msat: 10_000_000,
            per_deal_max_msat: 2_000_000,
            payout_node: node.to_string(),
            expires_at: 86_400,
        },
        &mut OsRng,
    );
    Agent::new(key, m).unwrap()
}

fn sell<J: JobClass + Clone + 'static>(job: J, input: Vec<u8>, result: Vec<u8>) -> Vec<u8> {
    let alice = SecretKey::generate(&mut OsRng);
    let bob = SecretKey::generate(&mut OsRng);
    let buyer_agent = agent_for(&alice, Role::Buyer, vec![job.spec_hash()], "alice-node");
    let seller_agent = agent_for(&bob, Role::Seller, vec![job.spec_hash()], "bob-node");
    let mut ledger = Ledger::new();
    ledger.open_principal_node("alice-node", alice.public_key(), 5_000_000);
    ledger.open_principal_node("bob-node", bob.public_key(), 0);

    let policy = BuyerPolicy {
        allow_insecure_dev_backend: true,
        ..BuyerPolicy::default()
    };
    let (mut buyer, req) = Buyer::new(
        &buyer_agent,
        Box::new(job.clone()),
        Box::new(InsecureDevTransparentBackend),
        policy,
        input,
        2_000_000,
        ledger.now(),
        &mut OsRng,
    )
    .unwrap();
    let mut seller = Seller::new(
        &seller_agent,
        Box::new(job.clone()),
        Box::new(InsecureDevTransparentBackend),
        SellerConfig {
            price_msat: 1_500_000,
            ..SellerConfig::default()
        },
    );

    // Messages cross the wire as JSON.
    let req = serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
    let offer = seller.make_offer(&req, ledger.now()).unwrap();
    buyer
        .accept_offer(
            &serde_json::from_str(&serde_json::to_string(&offer).unwrap()).unwrap(),
            ledger.now(),
        )
        .unwrap();
    let (bundle, binding) = seller
        .fulfil(&req, &offer, result, &mut ledger, &mut OsRng)
        .unwrap();
    let bundle = serde_json::from_str(&serde_json::to_string(&bundle).unwrap()).unwrap();
    let binding = serde_json::from_str(&serde_json::to_string(&binding).unwrap()).unwrap();

    buyer.verify_bundle(&bundle).unwrap();
    buyer.check_invoice(&binding, ledger.now()).unwrap();
    assert_eq!(buyer.result(), Err(PcpError::NotPaid));
    buyer.pay(&mut ledger).unwrap();
    assert!(matches!(
        seller.settle_paid(&mut ledger).as_slice(),
        [SaleOutcome::Settled { .. }]
    ));
    assert_eq!(buyer.poll(&mut ledger).unwrap(), BuyerProgress::Delivered);
    // Money moved between the principals' nodes; the agents hold none.
    assert_eq!(ledger.principal_balance(&alice.public_key()), 3_500_000);
    assert_eq!(ledger.principal_balance(&bob.public_key()), 1_500_000);

    // Each principal reads its agent's log (as JSON lines) and re-verifies.
    for agent in [&buyer_agent, &seller_agent] {
        let log = PrincipalLog::from_jsonl(&agent.log().to_jsonl()).unwrap();
        let summary = log.verify(agent.mandate(), &[&job]).unwrap();
        assert_eq!((summary.deals, summary.total_msat), (1, 1_500_000));
    }
    buyer.result().unwrap().to_vec()
}

#[test]
fn public_sudoku_sale() {
    let job = SudokuJob::nine();
    let input = job
        .parse_grid("..9748... 7........ .2.1.9... ..7...24. .64.1.59. .98...3.. ...8.3.2. ........6 ...2759..")
        .unwrap();
    let sol = job.solve(&input).unwrap();
    assert_eq!(sell(job, input, sol.clone()), sol);
}

#[test]
fn public_patch_sale() {
    let suite = TestSuiteJob::encode_suite(&[(0, 1), (1, 2), (-1, 2), (10, 101), (-10, 101)]);
    let patch = b"x * x + 1".to_vec();
    assert_eq!(sell(TestSuiteJob, suite, patch.clone()), patch);
}

#[test]
fn seller_cannot_sell_a_failing_patch() {
    let suite = TestSuiteJob::encode_suite(&[(2, 4), (3, 9)]);
    let job = TestSuiteJob;
    let p = SecretKey::generate(&mut OsRng);
    let q = SecretKey::generate(&mut OsRng);
    let mut ledger = Ledger::new();
    ledger.open_principal_node("q-node", q.public_key(), 0);
    let (_b, req) = Buyer::new(
        &agent_for(&p, Role::Buyer, vec![job.spec_hash()], "p-node"),
        Box::new(job),
        Box::new(InsecureDevTransparentBackend),
        BuyerPolicy::default(),
        suite,
        10,
        0,
        &mut OsRng,
    )
    .unwrap();
    let seller_agent = agent_for(&q, Role::Seller, vec![job.spec_hash()], "q-node");
    let mut seller = Seller::new(
        &seller_agent,
        Box::new(job),
        Box::new(InsecureDevTransparentBackend),
        SellerConfig {
            price_msat: 10,
            ..Default::default()
        },
    );
    let offer = seller.make_offer(&req, 0).unwrap();
    let r = seller.fulfil(&req, &offer, b"x + x".to_vec(), &mut ledger, &mut OsRng);
    assert_eq!(r.err(), Some(PcpError::SellerResultInvalid));
    // The seller's principal sees the refusal, with its reason code.
    let log = seller_agent.log();
    let reasons: Vec<_> = log.refusals().map(|r| r.reason.as_str()).collect();
    assert_eq!(reasons, ["seller_result_invalid"]);
    assert_eq!(log.verify(seller_agent.mandate(), &[]).unwrap().refusals, 1);
}
