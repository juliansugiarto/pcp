//! The seller's work on a stranger's input, bounded.
//!
//! `SudokuJob::solve` (in the guest-compiled `job/` module, which cannot
//! change without a new image id) backtracks without a limit: a crafted
//! puzzle with no solution keeps it busy for hours, and the seller loop
//! with it. This solver picks the most constrained cell first and gives up
//! after a fixed number of search nodes, so one message costs the seller a
//! bounded amount of time. Its answer is checked with the job's own check
//! before it is returned.

use crate::job::{JobClass, SudokuJob};

/// Search nodes before giving up. Hard 9x9 puzzles need fewer than 10,000
/// with this cell order; one node costs about 0.55 microseconds in a release
/// build (Fable, review of 80cfc98), so the bound is about 0.1 s.
pub const MAX_NODES: u64 = 200_000;

/// Solve `input` for `job`, or `None` if it has no solution, is malformed,
/// or needs more than `max_nodes` search nodes.
pub fn solve_sudoku(job: &SudokuJob, input: &[u8], max_nodes: u64) -> Option<Vec<u8>> {
    let n = job.n();
    let b = (1..=n).find(|b| b * b == n)?;
    if input.len() != n * n || input.iter().any(|&v| v as usize > n) {
        return None;
    }
    let mut g = input.to_vec();
    // Givens must not clash with each other.
    for i in 0..n * n {
        if g[i] != 0 {
            let v = g[i];
            g[i] = 0;
            let ok = candidates(&g, n, b, i) & (1 << v) != 0;
            g[i] = v;
            if !ok {
                return None;
            }
        }
    }
    let mut nodes = 0u64;
    if search(&mut g, n, b, &mut nodes, max_nodes) && job.check(input, &g) {
        Some(g)
    } else {
        None
    }
}

/// Bit v set when value v (1..=n) can go in cell i.
fn candidates(g: &[u8], n: usize, b: usize, i: usize) -> u32 {
    let (r, c) = (i / n, i % n);
    let mut used = 0u32;
    for k in 0..n {
        used |= 1 << g[r * n + k];
        used |= 1 << g[k * n + c];
    }
    let (br, bc) = (r / b * b, c / b * b);
    for dr in 0..b {
        for dc in 0..b {
            used |= 1 << g[(br + dr) * n + bc + dc];
        }
    }
    let all = ((1u32 << (n + 1)) - 1) & !1;
    all & !used
}

fn search(g: &mut [u8], n: usize, b: usize, nodes: &mut u64, max: u64) -> bool {
    *nodes += 1;
    if *nodes > max {
        return false;
    }
    // The empty cell with the fewest candidates.
    let mut best: Option<(usize, u32)> = None;
    for i in 0..g.len() {
        if g[i] == 0 {
            let c = candidates(g, n, b, i);
            if c == 0 {
                return false;
            }
            if best.is_none_or(|(_, bc)| c.count_ones() < bc.count_ones()) {
                best = Some((i, c));
            }
        }
    }
    let Some((i, cands)) = best else {
        return true;
    };
    for v in 1..=n as u8 {
        if cands & (1 << v) != 0 {
            g[i] = v;
            if search(g, n, b, nodes, max) {
                return true;
            }
            if *nodes > max {
                g[i] = 0;
                return false;
            }
        }
    }
    g[i] = 0;
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn solves_what_the_unbounded_solver_solves() {
        let j = SudokuJob::nine();
        let p = j.parse_grid(crate::node::cli::DEFAULT_PUZZLE9).unwrap();
        assert_eq!(solve_sudoku(&j, &p, MAX_NODES), j.solve(&p));
        let j4 = SudokuJob::four();
        let p4 = j4.parse_grid("1..4 ..1. .1.. 4..1").unwrap();
        assert_eq!(solve_sudoku(&j4, &p4, MAX_NODES), j4.solve(&p4));
        // An empty grid has many solutions; any one that checks will do.
        let empty = vec![0u8; 81];
        let s = solve_sudoku(&j, &empty, MAX_NODES).unwrap();
        assert!(j.check(&empty, &s));
    }

    #[test]
    fn a_crafted_puzzle_cannot_park_the_seller() {
        // Fable's puzzle (review 18): row 8 holds 1..8 in cells 72-79 and
        // cell 8 holds 9, so cell 80 has no candidate. SudokuJob::solve
        // fills rows 0-7 first and does not return; this one refuses at
        // once.
        let j = SudokuJob::nine();
        let mut p = vec![0u8; 81];
        for (k, cell) in (72..80).enumerate() {
            p[cell] = k as u8 + 1;
        }
        p[8] = 9;
        let t = Instant::now();
        assert_eq!(solve_sudoku(&j, &p, MAX_NODES), None);
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn the_node_limit_holds() {
        // A puzzle with clashing givens is refused before any search; a
        // hard search stops at the limit.
        let j = SudokuJob::nine();
        let mut p = vec![0u8; 81];
        p[0] = 5;
        p[1] = 5;
        assert_eq!(solve_sudoku(&j, &p, MAX_NODES), None);
        let empty = vec![0u8; 81];
        assert_eq!(solve_sudoku(&j, &empty, 10), None);
        assert!(solve_sudoku(&j, &[0u8; 80], MAX_NODES).is_none());
        assert!(solve_sudoku(&j, &[10u8; 81], MAX_NODES).is_none());
    }
}
