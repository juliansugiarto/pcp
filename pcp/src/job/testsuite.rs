//! `pcp/testsuite-toyexpr/v0`: a deterministic stand-in for "a patch that
//! passes a hermetic test suite".
//!
//! The buyer publishes a test suite (the *input*): a list of `(x, expected)`
//! pairs of signed 64-bit integers. The seller delivers a function body (the
//! *result*) in a toy expression language over one variable `x`. `check`
//! parses the body and evaluates it on every test vector; it passes iff every
//! output equals the expected value.
//!
//! The real job class this stands in for runs a prebuilt WASM or RISC-V
//! module against the tests inside a zkVM guest. The toy language keeps the
//! same shape (source in, pass/fail out, no I/O) with none of the toolchain.
//!
//! # Input encoding
//! `u32_be(count) || count * (i64_be(x) || i64_be(expected))`, count in
//! `1..=MAX_VECTORS`.
//!
//! # Result: the toy expression language (UTF-8 source)
//! ```text
//! expr  := cmp
//! cmp   := sum (("<" | "<=" | "==" | "!=" | ">" | ">=") sum)?
//! sum   := prod (("+" | "-") prod)*
//! prod  := unary (("*" | "/" | "%") unary)*
//! unary := "-" unary | atom
//! atom  := INT | "x" | "(" expr ")" | "if" "(" expr "," expr "," expr ")"
//! ```
//! Semantics: i64 with wrapping `+ - *` and negation; `/` and `%` truncate
//! toward zero (wrapping on `i64::MIN / -1`); division or remainder by zero is
//! an evaluation error (the test fails); comparisons yield 1 or 0;
//! `if(c, a, b)` is `a` when `c != 0`, else `b`, and evaluates only the taken
//! branch. Source is limited to `MAX_SOURCE` bytes and `MAX_DEPTH` nesting.
//! Whitespace is insignificant. There is no I/O, no loop and no recursion, so
//! evaluation is linear in the source size.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::JobClass;

/// Maximum number of test vectors in a suite.
pub const MAX_VECTORS: usize = 4096;
/// Maximum source length of a candidate, in bytes.
pub const MAX_SOURCE: usize = 4096;
/// Maximum expression nesting depth.
pub const MAX_DEPTH: usize = 64;

/// The "patch passes the test suite" job class.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TestSuiteJob;

/// Outcome of running a candidate against a suite (for the seller's own
/// iteration loop and for demo output).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunReport {
    /// The suite could not be decoded.
    BadSuite,
    /// The candidate did not parse.
    ParseError(String),
    /// Every vector passed.
    Pass { vectors: usize },
    /// The first failing vector.
    Fail {
        index: usize,
        x: i64,
        expected: i64,
        got: Option<i64>,
    },
}

impl TestSuiteJob {
    /// Canonical encoding of a test suite.
    pub fn encode_suite(vectors: &[(i64, i64)]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 16 * vectors.len());
        out.extend_from_slice(&(vectors.len() as u32).to_be_bytes());
        for (x, y) in vectors {
            out.extend_from_slice(&x.to_be_bytes());
            out.extend_from_slice(&y.to_be_bytes());
        }
        out
    }

    /// Decode a test suite; `None` if malformed or out of bounds.
    pub fn decode_suite(bytes: &[u8]) -> Option<Vec<(i64, i64)>> {
        let count = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
        if count == 0 || count > MAX_VECTORS || bytes.len() != 4 + 16 * count {
            return None;
        }
        Some(
            bytes[4..]
                .chunks_exact(16)
                .map(|c| {
                    (
                        i64::from_be_bytes(c[..8].try_into().unwrap()),
                        i64::from_be_bytes(c[8..].try_into().unwrap()),
                    )
                })
                .collect(),
        )
    }

    /// Run a candidate against an encoded suite and report the first failure.
    pub fn run(&self, input: &[u8], source: &[u8]) -> RunReport {
        let Some(suite) = Self::decode_suite(input) else {
            return RunReport::BadSuite;
        };
        let program = match parse(source) {
            Ok(p) => p,
            Err(e) => return RunReport::ParseError(e),
        };
        for (index, &(x, expected)) in suite.iter().enumerate() {
            let got = eval(&program, x);
            if got != Some(expected) {
                return RunReport::Fail {
                    index,
                    x,
                    expected,
                    got,
                };
            }
        }
        RunReport::Pass {
            vectors: suite.len(),
        }
    }
}

impl JobClass for TestSuiteJob {
    fn job_id(&self) -> &'static str {
        "pcp/testsuite-toyexpr/v0"
    }

    fn params(&self) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&(MAX_VECTORS as u32).to_be_bytes());
        p.extend_from_slice(&(MAX_SOURCE as u32).to_be_bytes());
        p.extend_from_slice(&(MAX_DEPTH as u32).to_be_bytes());
        p
    }

    fn check(&self, input: &[u8], result: &[u8]) -> bool {
        matches!(self.run(input, result), RunReport::Pass { .. })
    }
}

// ---------------------------------------------------------------------------
// Toy expression language

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expr {
    Int(i64),
    X,
    Neg(Box<Expr>),
    Bin(Op, Box<Expr>, Box<Expr>),
    If(Box<Expr>, Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Lt,
    Le,
    Eq,
    Ne,
    Gt,
    Ge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Int(i64),
    X,
    If,
    LParen,
    RParen,
    Comma,
    Op(&'static str),
}

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let b = src.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i];
        match c {
            b' ' | b'\t' | b'\n' | b'\r' => i += 1,
            b'0'..=b'9' => {
                let start = i;
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                let v: i64 = src[start..i]
                    .parse()
                    .map_err(|_| format!("integer out of range at byte {start}"))?;
                out.push(Tok::Int(v));
            }
            b'x' => {
                out.push(Tok::X);
                i += 1;
            }
            b'i' if b.get(i + 1) == Some(&b'f') => {
                out.push(Tok::If);
                i += 2;
            }
            b'(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            b')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            b',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            _ => {
                let two = src.get(i..i + 2).unwrap_or("");
                let op: &'static str = match two {
                    "<=" => "<=",
                    ">=" => ">=",
                    "==" => "==",
                    "!=" => "!=",
                    _ => match c {
                        b'+' => "+",
                        b'-' => "-",
                        b'*' => "*",
                        b'/' => "/",
                        b'%' => "%",
                        b'<' => "<",
                        b'>' => ">",
                        _ => return Err(format!("unexpected character at byte {i}")),
                    },
                };
                i += op.len();
                out.push(Tok::Op(op));
            }
        }
    }
    Ok(out)
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
    depth: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn expect(&mut self, t: Tok) -> Result<(), String> {
        match self.next() {
            Some(ref got) if *got == t => Ok(()),
            other => Err(format!("expected {t:?}, found {other:?}")),
        }
    }

    fn enter(&mut self) -> Result<(), String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            Err("expression nested too deeply".into())
        } else {
            Ok(())
        }
    }

    fn expr(&mut self) -> Result<Expr, String> {
        self.enter()?;
        let lhs = self.sum()?;
        let op = match self.peek() {
            Some(Tok::Op("<")) => Some(Op::Lt),
            Some(Tok::Op("<=")) => Some(Op::Le),
            Some(Tok::Op("==")) => Some(Op::Eq),
            Some(Tok::Op("!=")) => Some(Op::Ne),
            Some(Tok::Op(">")) => Some(Op::Gt),
            Some(Tok::Op(">=")) => Some(Op::Ge),
            _ => None,
        };
        let e = match op {
            Some(op) => {
                self.pos += 1;
                let rhs = self.sum()?;
                Expr::Bin(op, Box::new(lhs), Box::new(rhs))
            }
            None => lhs,
        };
        self.depth -= 1;
        Ok(e)
    }

    fn sum(&mut self) -> Result<Expr, String> {
        let mut lhs = self.prod()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Op("+")) => Op::Add,
                Some(Tok::Op("-")) => Op::Sub,
                _ => return Ok(lhs),
            };
            self.pos += 1;
            let rhs = self.prod()?;
            lhs = Expr::Bin(op, Box::new(lhs), Box::new(rhs));
        }
    }

    fn prod(&mut self) -> Result<Expr, String> {
        let mut lhs = self.unary()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Op("*")) => Op::Mul,
                Some(Tok::Op("/")) => Op::Div,
                Some(Tok::Op("%")) => Op::Rem,
                _ => return Ok(lhs),
            };
            self.pos += 1;
            let rhs = self.unary()?;
            lhs = Expr::Bin(op, Box::new(lhs), Box::new(rhs));
        }
    }

    fn unary(&mut self) -> Result<Expr, String> {
        if self.peek() == Some(&Tok::Op("-")) {
            self.pos += 1;
            self.enter()?;
            let e = Expr::Neg(Box::new(self.unary()?));
            self.depth -= 1;
            return Ok(e);
        }
        self.atom()
    }

    fn atom(&mut self) -> Result<Expr, String> {
        match self.next() {
            Some(Tok::Int(v)) => Ok(Expr::Int(v)),
            Some(Tok::X) => Ok(Expr::X),
            Some(Tok::LParen) => {
                let e = self.expr()?;
                self.expect(Tok::RParen)?;
                Ok(e)
            }
            Some(Tok::If) => {
                self.expect(Tok::LParen)?;
                let c = self.expr()?;
                self.expect(Tok::Comma)?;
                let a = self.expr()?;
                self.expect(Tok::Comma)?;
                let b = self.expr()?;
                self.expect(Tok::RParen)?;
                Ok(Expr::If(Box::new(c), Box::new(a), Box::new(b)))
            }
            other => Err(format!("unexpected token {other:?}")),
        }
    }
}

fn parse(source: &[u8]) -> Result<Expr, String> {
    if source.len() > MAX_SOURCE {
        return Err("source too long".into());
    }
    let src = core::str::from_utf8(source).map_err(|_| "source is not UTF-8".to_string())?;
    let mut p = Parser {
        toks: lex(src)?,
        pos: 0,
        depth: 0,
    };
    let e = p.expr()?;
    if p.pos != p.toks.len() {
        return Err(format!("trailing input at token {}", p.pos));
    }
    Ok(e)
}

fn eval(e: &Expr, x: i64) -> Option<i64> {
    Some(match e {
        Expr::Int(v) => *v,
        Expr::X => x,
        Expr::Neg(a) => eval(a, x)?.wrapping_neg(),
        Expr::If(c, a, b) => {
            if eval(c, x)? != 0 {
                eval(a, x)?
            } else {
                eval(b, x)?
            }
        }
        Expr::Bin(op, a, b) => {
            let (a, b) = (eval(a, x)?, eval(b, x)?);
            match op {
                Op::Add => a.wrapping_add(b),
                Op::Sub => a.wrapping_sub(b),
                Op::Mul => a.wrapping_mul(b),
                Op::Div => {
                    if b == 0 {
                        return None;
                    }
                    a.wrapping_div(b)
                }
                Op::Rem => {
                    if b == 0 {
                        return None;
                    }
                    a.wrapping_rem(b)
                }
                Op::Lt => (a < b) as i64,
                Op::Le => (a <= b) as i64,
                Op::Eq => (a == b) as i64,
                Op::Ne => (a != b) as i64,
                Op::Gt => (a > b) as i64,
                Op::Ge => (a >= b) as i64,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clamp_suite() -> Vec<u8> {
        TestSuiteJob::encode_suite(&[(-5, 0), (0, 0), (42, 42), (100, 100), (101, 100)])
    }

    #[test]
    fn language_basics() {
        let ev = |s: &str, x| eval(&parse(s.as_bytes()).unwrap(), x);
        assert_eq!(ev("1 + 2 * 3", 0), Some(7));
        assert_eq!(ev("(1 + 2) * 3", 0), Some(9));
        assert_eq!(ev("-x - -3", 4), Some(-1));
        assert_eq!(ev("7 / -2", 0), Some(-3));
        assert_eq!(ev("7 % -2", 0), Some(1));
        assert_eq!(ev("x / 0", 1), None);
        assert_eq!(ev("if(x < 0, 0 - x, x)", -9), Some(9));
        assert_eq!(ev("if(1, 5, 1 / 0)", 0), Some(5), "lazy branches");
        assert_eq!(ev("x * x", i64::MAX), Some(1), "wrapping");
        assert_eq!(ev("x / -1", i64::MIN), Some(i64::MIN));
        assert!(parse(b"1 +").is_err());
        assert!(parse(b"y").is_err());
        assert!(parse(b"1 2").is_err());
        assert!(parse("(".repeat(100).as_bytes()).is_err());
        assert!(parse(&vec![b'1'; MAX_SOURCE + 1]).is_err());
    }

    #[test]
    fn suite_checks() {
        let job = TestSuiteJob;
        let suite = clamp_suite();
        assert!(!job.check(&suite, b"if(x < 0, 0, x)"));
        assert!(job.check(&suite, b"if(x < 0, 0, if(x > 100, 100, x))"));
        assert!(matches!(
            job.run(&suite, b"if(x < 0, 0, x)"),
            RunReport::Fail { index: 4, .. }
        ));
        assert!(!job.check(&suite[..10], b"x"), "truncated suite rejected");
        assert!(
            !job.check(&TestSuiteJob::encode_suite(&[]), b"x"),
            "empty suite"
        );
    }
}
