//! pcp-zk: prover and verifier CLI for the PCP/0 zk sudoku sale.
//!
//! ```text
//! pcp-zk prove   --puzzle P --solution S --binding HEX --out DIR --secret FILE
//! pcp-zk verify  --dir DIR --puzzle P --payment-hash HEX --binding HEX [--vk-fingerprint HEX]
//! pcp-zk vk-fingerprint
//! pcp-zk decrypt --dir DIR --key HEX
//! ```
//!
//! `prove` writes DIR/proof.bin and DIR/public.json; the key k goes only to
//! FILE (the seller keeps it until the payment settles). `verify` is the
//! buyer's check before paying: it rebuilds the public inputs from the buyer's
//! OWN puzzle, the invoice payment hash H and the offer binding (all required),
//! takes only the ciphertext C from the seller's public.json, and prints FAIL
//! if that file disagrees on givens, H or binding, or if the proof does not
//! verify (exit code 0 or 1). `decrypt` is the buyer's step after payment:
//! checks SHA256(k) = H, decrypts C and re-checks the sudoku.
//! `vk-fingerprint` prints the SHA-256 fingerprint of the verifying key that
//! this build computes from the circuit source; `verify --vk-fingerprint`
//! prints FAIL if the build's key differs from the one a bundle names.
//! Timings and peak memory go to stderr.

use std::{collections::HashMap, fs, path::PathBuf, process::exit, time::Instant};

use pcp_zk::{suite, PublicInputs};

fn args() -> (String, HashMap<String, String>) {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().unwrap_or_default();
    let mut map = HashMap::new();
    while let Some(k) = it.next() {
        let k = k.trim_start_matches("--").to_string();
        let v = it.next().unwrap_or_else(|| die(&format!("missing value for --{k}")));
        map.insert(k, v);
    }
    (cmd, map)
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    exit(2)
}

fn need<'a>(m: &'a HashMap<String, String>, k: &str) -> &'a str {
    m.get(k).map(String::as_str).unwrap_or_else(|| die(&format!("--{k} is required")))
}

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .unwrap_or_else(|| die("expected 32 bytes of hex"))
}

fn report(stage: &str, t: Instant) {
    eprintln!(
        "[pcp-zk] {stage}: {:.3} s, peak RSS so far {} KiB",
        t.elapsed().as_secs_f64(),
        pcp_zk::peak_rss_kib().unwrap_or(0)
    );
}

fn main() {
    let (cmd, m) = args();
    match cmd.as_str() {
        "prove" => {
            let givens = suite::parse_grid(&fs::read_to_string(need(&m, "puzzle")).unwrap())
                .unwrap_or_else(|e| die(&e));
            let solution =
                suite::parse_grid(&fs::read_to_string(need(&m, "solution")).unwrap())
                    .unwrap_or_else(|e| die(&e));
            let binding = hex32(need(&m, "binding"));
            let out = PathBuf::from(need(&m, "out"));
            fs::create_dir_all(&out).unwrap();

            let t = Instant::now();
            let params = pcp_zk::params_cached(&pcp_zk::default_params_path());
            report("params (transparent, cached if hash matches)", t);
            let t = Instant::now();
            let vk = pcp_zk::verifying_key(&params);
            let pk = pcp_zk::proving_key(&params, vk);
            report("keygen (vk + pk)", t);
            let t = Instant::now();
            // k is drawn inside `sell` from the OS CSPRNG: fresh for every offer.
            let (proof, public, key) = pcp_zk::sell(&params, &pk, &givens, &solution, &binding)
                .unwrap_or_else(|e| die(&format!("prove refused: {e:?}")));
            report("prove", t);

            fs::write(out.join("proof.bin"), &proof).unwrap();
            fs::write(out.join("public.json"), public.to_json()).unwrap();
            fs::write(need(&m, "secret"), hex::encode(key) + "\n").unwrap();
            eprintln!("[pcp-zk] proof size: {} bytes", proof.len());
            println!("wrote {}/proof.bin and public.json; H = {}", out.display(), hex::encode(public.payment_hash));
        }
        "verify" => {
            // The buyer builds the public inputs from values it already trusts:
            // its own puzzle, the payment hash from the invoice it is about to
            // pay, and the offer binding it computed. Only the ciphertext `C` is
            // taken from the seller's file. The seller's `public.json` is then
            // required to agree on `givens`, `H` and `binding`; if it does not,
            // the result is FAIL (H-2 fix).
            let dir = PathBuf::from(need(&m, "dir"));
            let givens = suite::parse_grid(&fs::read_to_string(need(&m, "puzzle")).unwrap())
                .unwrap_or_else(|e| die(&e));
            let payment_hash = hex32(need(&m, "payment-hash"));
            let binding = hex32(need(&m, "binding"));
            let ok = (|| {
                let seller =
                    PublicInputs::from_json(&fs::read_to_string(dir.join("public.json")).ok()?).ok()?;
                // Rebuild the public inputs; take only C from the seller.
                let public = PublicInputs {
                    givens,
                    ciphertext: seller.ciphertext.clone(),
                    payment_hash,
                    binding,
                };
                if seller.givens != public.givens {
                    eprintln!("public.json givens do not match the buyer's puzzle");
                    return Some(false);
                }
                if seller.payment_hash != public.payment_hash {
                    eprintln!("public.json H does not match the invoice payment hash");
                    return Some(false);
                }
                if seller.binding != public.binding {
                    eprintln!("public.json binding does not match the offer binding");
                    return Some(false);
                }
                let proof = fs::read(dir.join("proof.bin")).ok()?;
                let t = Instant::now();
                let params = pcp_zk::params_cached(&pcp_zk::default_params_path());
                report("params (transparent, cached if hash matches)", t);
                let t = Instant::now();
                let vk = pcp_zk::verifying_key(&params);
                report("keygen_vk (verifier computes its own key)", t);
                let fp = hex::encode(pcp_zk::vk_fingerprint(&vk));
                eprintln!("[pcp-zk] vk fingerprint: {fp}");
                if let Some(want) = m.get("vk-fingerprint") {
                    if want.trim() != fp {
                        eprintln!("this build's verifying key is not the one named (--vk-fingerprint)");
                        return Some(false);
                    }
                }
                let t = Instant::now();
                // Verify against the buyer-built public inputs, not the seller's.
                let ok = pcp_zk::verify(&params, &vk, &public, &proof);
                report("verify", t);
                Some(ok)
            })()
            .unwrap_or(false);
            println!("{}", if ok { "OK" } else { "FAIL" });
            exit(if ok { 0 } else { 1 });
        }
        "decrypt" => {
            let dir = PathBuf::from(need(&m, "dir"));
            let public = PublicInputs::from_json(&fs::read_to_string(dir.join("public.json")).unwrap())
                .unwrap_or_else(|e| die(&e));
            let key = hex32(need(&m, "key"));
            if suite::payment_hash(&key) != public.payment_hash {
                die("SHA256(k) != H");
            }
            let r = suite::decrypt(&public.ciphertext, &key).unwrap_or_else(|| die("decryption failed"));
            if !suite::sudoku_valid(&public.givens, &r) {
                die("decrypted result fails the sudoku check");
            }
            for row in r.chunks(9) {
                println!("{}", row.iter().map(|d| char::from(b'0' + d)).collect::<String>());
            }
        }
        "vk-fingerprint" => {
            let params = pcp_zk::params_cached(&pcp_zk::default_params_path());
            let vk = pcp_zk::verifying_key(&params);
            println!("{}", hex::encode(pcp_zk::vk_fingerprint(&vk)));
        }
        _ => die("usage: pcp-zk prove|verify|decrypt|vk-fingerprint ... (see source header)"),
    }
}
