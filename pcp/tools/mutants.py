#!/usr/bin/env python3
"""Disable each protocol check, one at a time, and require a test to fail.

    python3 pcp/tools/mutants.py OUT_DIR [FILE ...]

A "check" is a line that refuses with an error (`Some(XError::...)` or
`Err(XError::...)`, for PcpError, MandateError, VerifyError, RelationError
and the like) right after a one-line condition
`if COND {` / `} else if COND {`. The mutant replaces COND by
`false && (COND)`, so the check never fires. The whole library test suite
(features lnd, http) then runs in a scratch copy; the mutant must make at
least one test fail ("killed"). A surviving mutant is either a missing
test or an equivalent mutant (an earlier check already refuses the same
inputs); each survivor is listed for triage.

The working tree is never touched: everything happens in OUT_DIR/pcp.
Guest-compiled files may be mutated there too (the image id belongs to the
real tree only). Writes OUT_DIR/mutants.txt and exits 1 if any mutant
survived. Needs cargo and python3; about 30 s per mutant after the first
build.
"""

import os
import re
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_FILES = [
    "src/protocol.rs",
    "src/mandate.rs",
    "src/proof.rs",
    "src/statement.rs",
    "src/job/sudoku.rs",
    "src/job/testsuite.rs",
    "src/node/mod.rs",
    "src/node/http.rs",
]
EQUIVALENT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants-equivalent.txt")
REFUSE = re.compile(r"(Some|Err)\((\w+Error)::(\w+)")
COND = re.compile(r"^(\s*(?:\}\s*else\s+)?if\s+)(.*\S)(\s*\{\s*)$")


def checks(path):
    lines = open(path).read().split("\n")
    out = []
    for i, line in enumerate(lines):
        m = REFUSE.search(line)
        if not m or i == 0:
            continue
        c = COND.match(lines[i - 1])
        if not c or c.group(2).startswith("let "):
            continue
        out.append((i - 1, m.group(2) + "::" + m.group(3), c))
    return lines, out


TIMEOUT = 600


def run(cmd, cwd, env):
    """Run cmd; a run that hangs (a mutant that loops) counts as a failure."""
    p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        out, err = p.communicate(timeout=TIMEOUT)
        return subprocess.CompletedProcess(cmd, p.returncode, out, err)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, 9)
        p.communicate()
        return subprocess.CompletedProcess(cmd, -9, "", "timed out")


def main():
    out = os.path.abspath(sys.argv[1])
    files = sys.argv[2:] or DEFAULT_FILES
    work = os.path.join(out, "pcp")
    if os.path.exists(work):
        shutil.rmtree(work)
    shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns("target", "fuzz"))
    env = dict(os.environ, CARGO_TARGET_DIR=os.path.join(out, "target"))
    test = ["cargo", "test", "-q", "--lib", "--features", "lnd,http"]
    base = run(test, work, env)
    if base.returncode != 0:
        print("the unmutated tree fails its tests:\n" + base.stdout[-2000:] + base.stderr[-2000:])
        return 2
    equivalent = {}
    for line in open(EQUIVALENT):
        if line.strip() and not line.startswith("#"):
            f, cond, why = line.rstrip("\n").split("\t")
            equivalent[(f, cond)] = why
    rows, survived = [], 0
    for rel in files:
        path = os.path.join(work, rel)
        orig = open(path).read()
        lines, found = checks(path)
        for idx, err, c in found:
            mutated = list(lines)
            mutated[idx] = c.group(1) + "false && (" + c.group(2) + ")" + c.group(3)
            open(path, "w").write("\n".join(mutated))
            t = time.time()
            r = run(test, work, env)
            open(path, "w").write(orig)
            if "error[" in r.stderr and "could not compile" in r.stderr:
                verdict = "no-compile"
            elif r.returncode == -9:
                verdict = "killed (hang)"
            elif r.returncode != 0:
                verdict = "killed"
            elif (rel, c.group(2)) in equivalent:
                verdict = "equivalent"
            else:
                verdict = "SURVIVED"
                survived += 1
            row = f"{rel}:{idx + 1}\t{err}\t{verdict}\t{time.time() - t:.0f}s\t{c.group(2)[:90]}"
            print(row, flush=True)
            rows.append(row)
    with open(os.path.join(out, "mutants.txt"), "w") as f:
        f.write("location\tcheck\tverdict\tsecs\tcondition\n" + "\n".join(rows) + "\n")
        f.write(f"total {len(rows)} survived {survived}\n")
    print(f"total {len(rows)} survived {survived}")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
