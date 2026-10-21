//! `pcp/sudoku/v0`: the 2016 ZKCP demo job.
//!
//! Encoding (both input and result): `n*n` bytes in row-major order, where
//! `n` is 4 or 9. In the input, `0` is a blank and `1..=n` is a given. In the
//! result every cell is `1..=n`.
//!
//! `check(input, result)` is true iff the result has the right length, every
//! cell is in range, every given in the input is preserved, and every row,
//! column and box is a permutation of `1..=n`.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::JobClass;

/// Sudoku solution checker for 4x4 (2x2 boxes) or 9x9 (3x3 boxes) grids.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SudokuJob {
    n: usize,
    b: usize,
}

impl SudokuJob {
    /// A 4x4 sudoku.
    pub const fn four() -> Self {
        SudokuJob { n: 4, b: 2 }
    }

    /// A 9x9 sudoku.
    pub const fn nine() -> Self {
        SudokuJob { n: 9, b: 3 }
    }

    /// Grid side length.
    pub fn n(&self) -> usize {
        self.n
    }

    /// Parse a grid from text: digits, with `0` or `.` as blanks; whitespace
    /// and `|`, `-`, `+` are ignored.
    pub fn parse_grid(&self, text: &str) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(self.n * self.n);
        for c in text.chars() {
            match c {
                '.' | '0' => out.push(0),
                '1'..='9' => out.push(c as u8 - b'0'),
                c if c.is_whitespace() || c == '|' || c == '-' || c == '+' => {}
                _ => return None,
            }
        }
        (out.len() == self.n * self.n && out.iter().all(|&v| (v as usize) <= self.n)).then_some(out)
    }

    /// Render a grid as text, one row per line.
    pub fn render(&self, grid: &[u8]) -> String {
        grid.chunks(self.n)
            .map(|row| {
                row.iter()
                    .map(|&v| {
                        if v == 0 {
                            ".".to_string()
                        } else {
                            v.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn group_ok(&self, cells: impl Iterator<Item = u8>) -> bool {
        let mut seen = 0u32;
        for v in cells {
            if v == 0 || v as usize > self.n {
                return false;
            }
            let bit = 1u32 << v;
            if seen & bit != 0 {
                return false;
            }
            seen |= bit;
        }
        true
    }

    /// Solve by backtracking (the seller's "work"). Returns `None` if the
    /// puzzle is malformed or has no solution.
    pub fn solve(&self, input: &[u8]) -> Option<Vec<u8>> {
        if input.len() != self.n * self.n || input.iter().any(|&v| v as usize > self.n) {
            return None;
        }
        let mut g = input.to_vec();
        if self.backtrack(&mut g, 0) {
            Some(g)
        } else {
            None
        }
    }

    fn allowed(&self, g: &[u8], idx: usize, v: u8) -> bool {
        let (r, c) = (idx / self.n, idx % self.n);
        for i in 0..self.n {
            if g[r * self.n + i] == v || g[i * self.n + c] == v {
                return false;
            }
        }
        let (br, bc) = (r / self.b * self.b, c / self.b * self.b);
        for dr in 0..self.b {
            for dc in 0..self.b {
                if g[(br + dr) * self.n + bc + dc] == v {
                    return false;
                }
            }
        }
        true
    }

    fn backtrack(&self, g: &mut [u8], from: usize) -> bool {
        let Some(idx) = (from..g.len()).find(|&i| g[i] == 0) else {
            return true;
        };
        for v in 1..=self.n as u8 {
            if self.allowed(g, idx, v) {
                g[idx] = v;
                if self.backtrack(g, idx + 1) {
                    return true;
                }
                g[idx] = 0;
            }
        }
        false
    }
}

impl JobClass for SudokuJob {
    fn job_id(&self) -> &'static str {
        "pcp/sudoku/v0"
    }

    fn params(&self) -> Vec<u8> {
        vec![self.n as u8]
    }

    fn check(&self, input: &[u8], result: &[u8]) -> bool {
        let n = self.n;
        if input.len() != n * n || result.len() != n * n {
            return false;
        }
        if input.iter().any(|&v| v as usize > n) {
            return false;
        }
        // Givens preserved.
        if input
            .iter()
            .zip(result)
            .any(|(&given, &got)| given != 0 && given != got)
        {
            return false;
        }
        for i in 0..n {
            let row = (0..n).map(|j| result[i * n + j]);
            let col = (0..n).map(|j| result[j * n + i]);
            let (br, bc) = (i / self.b * self.b, i % self.b * self.b);
            let bx = (0..n).map(|j| result[(br + j / self.b) * n + bc + j % self.b]);
            if !self.group_ok(row) || !self.group_ok(col) || !self.group_ok(bx) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_by_four() {
        let job = SudokuJob::four();
        let input = job
            .parse_grid("1 . . 4 | . . 1 . | . 1 . . | 4 . . 1")
            .unwrap();
        let sol = job.solve(&input).unwrap();
        assert!(job.check(&input, &sol));
        let mut bad = sol.clone();
        bad.swap(1, 2);
        assert!(!job.check(&input, &bad));
        assert!(!job.check(&input, &sol[..15]));
    }

    #[test]
    fn givens_must_be_preserved() {
        let job = SudokuJob::four();
        let sol = job.parse_grid("1234 3412 2143 4321").unwrap();
        assert!(job.check(&[0; 16], &sol));
        let mut input = vec![0u8; 16];
        input[0] = 2; // a given the "solution" ignores
        assert!(!job.check(&input, &sol));
    }

    #[test]
    fn nine_by_nine() {
        let job = SudokuJob::nine();
        let input = job
            .parse_grid(
                "53..7.... 6..195... .98....6. 8...6...3 4..8.3..1 7...2...6 .6....28. ...419..5 ....8..79",
            )
            .unwrap();
        let sol = job.solve(&input).unwrap();
        assert!(job.check(&input, &sol));
        assert_ne!(SudokuJob::four().spec_hash(), job.spec_hash());
    }
}
