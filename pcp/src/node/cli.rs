//! Shared command-line pieces for `pcp-setup`, `pcp-sell`, `pcp-buy` and
//! `pcp-audit`: argument parsing, the rail choice, the job choice.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::job::{JobClass, SudokuJob};
use crate::proof::ProofBackend;
use crate::protocol::BuyerPolicy;
use crate::rail::{Rail, RAIL_BOLT11};

use super::sim_file::SimFileRail;

/// `--key value` options and `--flag` switches.
pub struct Args {
    opts: BTreeMap<String, String>,
    flags: Vec<String>,
    usage: &'static str,
}

impl Args {
    /// Parse `std::env::args()`. Exits with code 2 and the usage text on
    /// `--help`, a malformed argument, or an option the usage text does not
    /// name (a typo such as `--image_id` must not fall back to a default).
    pub fn parse(usage: &'static str, flag_names: &[&str]) -> Args {
        Args::parse_from(usage, flag_names, std::env::args().skip(1))
            .unwrap_or_else(|e| fail(usage, &e))
    }

    /// [`Args::parse`] over given arguments; `Err` instead of exiting.
    pub fn parse_from(
        usage: &'static str,
        flag_names: &[&str],
        args: impl IntoIterator<Item = String>,
    ) -> Result<Args, String> {
        let known = option_names(usage);
        let mut opts = BTreeMap::new();
        let mut flags = Vec::new();
        let mut it = args.into_iter();
        while let Some(a) = it.next() {
            let Some(name) = a.strip_prefix("--") else {
                return Err(format!("unexpected argument {a}"));
            };
            if name == "help" {
                return Err(String::new());
            }
            if !known.iter().any(|k| k == name) {
                return Err(format!("unknown option --{name}"));
            }
            if flag_names.contains(&name) {
                flags.push(name.to_string());
            } else {
                match it.next() {
                    Some(v) => {
                        opts.insert(name.to_string(), v);
                    }
                    None => return Err(format!("--{name} needs a value")),
                }
            }
        }
        Ok(Args { opts, flags, usage })
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.opts.get(name).map(String::as_str)
    }

    pub fn req(&self, name: &str) -> &str {
        self.get(name)
            .unwrap_or_else(|| fail(self.usage, &format!("--{name} is required")))
    }

    pub fn path(&self, name: &str) -> PathBuf {
        PathBuf::from(self.req(name))
    }

    pub fn num(&self, name: &str, default: u64) -> u64 {
        match self.get(name) {
            None => default,
            Some(v) => v
                .parse()
                .unwrap_or_else(|_| fail(self.usage, &format!("--{name}: not a number"))),
        }
    }

    pub fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f == name)
    }
}

/// Every `--name` the usage text mentions.
fn option_names(usage: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = usage;
    while let Some(i) = rest.find("--") {
        rest = &rest[i + 2..];
        let n: String = rest
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
            .collect();
        if !n.is_empty() && !names.contains(&n) {
            names.push(n);
        }
    }
    names
}

/// Print the usage and an error, exit 2.
pub fn fail(usage: &str, msg: &str) -> ! {
    if !msg.is_empty() {
        eprintln!("error: {msg}");
    }
    eprintln!("{usage}");
    std::process::exit(2)
}

/// The classic 9x9 puzzle used by the demos and CI.
pub const DEFAULT_PUZZLE9: &str =
    "53..7.... 6..195... .98....6. 8...6...3 4..8.3..1 7...2...6 .6....28. ...419..5 ....8..79";

/// A sudoku job by name: `sudoku9` or `sudoku4`.
pub fn sudoku(name: &str) -> Option<SudokuJob> {
    match name {
        "sudoku9" => Some(SudokuJob::nine()),
        "sudoku4" => Some(SudokuJob::four()),
        _ => None,
    }
}

/// A rail from `--rail`:
///
/// - `sim:<file>:<node>`: the TEST-ONLY simulated network file, as `node`
///   (needs `--allow-sim`);
/// - `lnd`: an LND node from `PCP_LND_REST_URL`, `PCP_LND_MACAROON`,
///   `PCP_LND_TLS_CERT` (feature `lnd`).
pub fn rail(spec: &str, allow_sim: bool, usage: &str) -> Box<dyn Rail> {
    if let Some(rest) = spec.strip_prefix("sim:") {
        if !allow_sim {
            fail(usage, "the sim rail is for tests only: add --allow-sim");
        }
        let Some((file, node)) = rest.rsplit_once(':') else {
            fail(usage, "--rail sim:<file>:<node>");
        };
        return Box::new(SimFileRail::new(Path::new(file), node));
    }
    if spec == "lnd" {
        return lnd_rail(usage);
    }
    fail(usage, "--rail must be sim:<file>:<node> or lnd")
}

#[cfg(feature = "lnd")]
fn lnd_rail(usage: &str) -> Box<dyn Rail> {
    use crate::rail::lnd::{LndConfig, LndRail};
    let cfg = LndConfig::from_env("PCP_LND_").unwrap_or_else(|e| fail(usage, &e));
    Box::new(LndRail::connect(cfg).unwrap_or_else(|e| {
        eprintln!("cannot reach the LND node: {e:?}");
        std::process::exit(2)
    }))
}

#[cfg(not(feature = "lnd"))]
fn lnd_rail(usage: &str) -> Box<dyn Rail> {
    fail(usage, "built without the lnd feature")
}

/// Boxed job factory for the loops.
pub fn job_factory(job: SudokuJob) -> impl Fn() -> Box<dyn JobClass> {
    move || Box::new(job) as Box<dyn JobClass>
}

/// The wire from the options: `--listen ADDR` (seller, HTTP), `--seller-url
/// URL` (buyer, HTTP), or `--inbox DIR --peer-inbox DIR` (directory).
/// Flags: `--allow-public-bind` (seller), `--allow-insecure-transport`
/// (buyer, `http://` for tests).
pub fn wire(a: &Args, usage: &str) -> Box<dyn super::wire::Wire> {
    if let Some(addr) = a.get("listen") {
        return listen(a, addr, usage);
    }
    if let Some(url) = a.get("seller-url") {
        return connect(a, url, usage);
    }
    match super::wire::DirTransport::new(&a.path("inbox"), &a.path("peer-inbox")) {
        Ok(w) => Box::new(w),
        Err(e) => fail(usage, &e.to_string()),
    }
}

#[cfg(feature = "http")]
fn listen(a: &Args, addr: &str, usage: &str) -> Box<dyn super::wire::Wire> {
    let addr: std::net::SocketAddr = addr
        .parse()
        .unwrap_or_else(|_| fail(usage, "--listen: not an address like 127.0.0.1:8650"));
    let s = super::http::HttpSeller::start(addr, a.flag("allow-public-bind"))
        .unwrap_or_else(|e| fail(usage, &e));
    println!(
        "listening on http://{} (put a TLS proxy in front)",
        s.local_addr()
    );
    Box::new(s)
}

#[cfg(feature = "http")]
fn connect(a: &Args, url: &str, usage: &str) -> Box<dyn super::wire::Wire> {
    let ca = a.get("seller-ca-cert").map(|p| {
        std::fs::read(p).unwrap_or_else(|e| fail(usage, &format!("--seller-ca-cert {p}: {e}")))
    });
    Box::new(
        super::http::HttpBuyer::new(url, a.flag("allow-insecure-transport"), ca.as_deref())
            .unwrap_or_else(|e| fail(usage, &e)),
    )
}

#[cfg(not(feature = "http"))]
fn listen(_: &Args, _: &str, usage: &str) -> Box<dyn super::wire::Wire> {
    fail(usage, "built without the http feature")
}

#[cfg(not(feature = "http"))]
fn connect(_: &Args, _: &str, usage: &str) -> Box<dyn super::wire::Wire> {
    fail(usage, "built without the http feature")
}

/// Flags every role binary accepts (some are role-specific).
pub const FLAGS: &[&str] = &[
    "allow-sim",
    "tamper-accept",
    "allow-public-bind",
    "allow-insecure-transport",
];

/// A log line with a UTC time stamp (seconds), to stdout.
pub fn logger(role: &'static str) -> impl FnMut(&str) {
    move |l: &str| {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        println!("[{role} {t}] {l}");
    }
}

/// The whole buyer process for one sudoku purchase, shared by `pcp-buy`
/// (dev backend) and verify-only buyers with a real backend (e.g.
/// `pcp-buy-risc0`). Takes pcp-buy's options. Exits 0 delivered,
/// 10 refunded, 11 aborted, 1 stopped by an error or the deadline.
pub fn run_buy(
    a: &Args,
    usage: &'static str,
    make_backend: &dyn Fn() -> Box<dyn ProofBackend>,
    allow_insecure_dev_backend: bool,
) -> ! {
    let job = sudoku(a.get("job").unwrap_or("sudoku9")).unwrap_or_else(|| fail(usage, "--job"));
    let input = job
        .parse_grid(a.get("puzzle").unwrap_or(DEFAULT_PUZZLE9))
        .unwrap_or_else(|| fail(usage, "--puzzle does not parse"));
    let mut rail = rail(a.req("rail"), a.flag("allow-sim"), usage);
    let mut policy = if rail.rail_id() == RAIL_BOLT11 {
        BuyerPolicy::lightning()
    } else {
        BuyerPolicy::default()
    };
    policy.allow_insecure_dev_backend = allow_insecure_dev_backend;
    let wire = wire(a, usage);
    let make_job = job_factory(job);
    let mut log = logger("buyer");
    let r = super::run_buyer(super::BuyerRun {
        state_dir: a.path("state"),
        wire,
        rail: rail.as_mut(),
        make_job: &make_job,
        make_backend,
        policy,
        input,
        max_price_msat: a.num("max-price-msat", 2_000_000),
        poll: std::time::Duration::from_millis(a.num("poll-ms", 200)),
        resend: std::time::Duration::from_secs(a.num("resend-secs", 5)),
        offer_wait_secs: a.num("offer-wait-secs", 120),
        deadline: std::time::Duration::from_secs(a.num("deadline-secs", 600)),
        tamper_accept: a.flag("tamper-accept"),
        log: &mut log,
    });
    match r {
        Ok(s) => {
            println!(
                "buyer summary: {} {} spent_msat {}",
                s.state,
                s.reason.clone().unwrap_or_default(),
                s.spent_msat
            );
            if let Some(hex_r) = &s.result_hex {
                if let Ok(grid) = hex::decode(hex_r) {
                    println!("{}", job.render(&grid));
                }
            }
            std::process::exit(match s.state.as_str() {
                "Delivered" => 0,
                "Refunded" => 10,
                _ => 11,
            })
        }
        Err(e) => {
            eprintln!("buyer stopped: {e}");
            std::process::exit(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const U: &str = "x --state DIR [--image-id HEX] [--allow-sim]";

    fn parse(a: &[&str]) -> Result<Args, String> {
        Args::parse_from(U, FLAGS, a.iter().map(|s| s.to_string()))
    }

    #[test]
    fn options_the_usage_does_not_name_are_refused() {
        let a = parse(&["--state", "d", "--image-id", "ab", "--allow-sim"]).unwrap();
        assert_eq!(a.get("image-id"), Some("ab"));
        assert!(a.flag("allow-sim"));
        // A typo must not fall back to the pinned default.
        assert_eq!(
            parse(&["--image_id", "ab"]).err().unwrap(),
            "unknown option --image_id"
        );
        assert!(parse(&["--tamper-accept"]).is_err());
        assert!(parse(&["--state"]).is_err());
        assert!(parse(&["state"]).is_err());
    }
}
