#!/usr/bin/env python3
"""
generate_results.py - one command from source to verdict and graphs.

    python3 generate_results.py                 # build, run, grade, plot
    python3 generate_results.py --skip-build    # reuse the current kernel and fs.img
    python3 generate_results.py --only 5        # one scenario group, for a quick look
    python3 generate_results.py --log results/scenarios.log --out results

Four stages, and each one's output is kept so a failure can be re-graded
without booting anything again:

  build   make kernel/kernel fs.img
  run     /scenarios under QEMU, serial log streamed to a file
  grade   budget_oracle.py re-derives every expectation and diffs the kernel
  plot    analyze_results.py draws the graphs from the same trace

The guest asserts nothing; the host decides. That ordering is the whole design -
see budget_oracle.py for why expectations cannot live next to the code they
test.

QEMU has to be at least 7.2; anything older cannot boot this kernel. It is
searched for in this order: --qemu, $QEMU, then PATH. The streaming harness is
run_xv6_test.py in this directory; set XV6_HARNESS to use another one.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.environ.get("XV6_HARNESS") or os.path.join(REPO, "run_xv6_test.py")
MIN_QEMU = (7, 2)


def stage(n, title):
    print("\n" + "=" * 72)
    print("  %s  (%d of 4)" % (title, n))
    print("=" * 72, flush=True)


def sh(cmd, **kw):
    print("$ " + " ".join(cmd))
    return subprocess.run(cmd, cwd=REPO, **kw)


def qemu_version(binary):
    out = subprocess.run([binary, "--version"], capture_output=True, text=True).stdout
    match = re.search(r"QEMU emulator version (\d+)\.(\d+)", out)
    return tuple(int(x) for x in match.groups()) if match else (0, 0)


def find_qemu(wanted):
    candidates = []
    if wanted:
        candidates.append(wanted)
    if os.environ.get("QEMU"):
        candidates.append(os.environ["QEMU"])
    found = shutil.which("qemu-system-riscv64")
    if found:
        candidates.append(found)

    for binary in candidates:
        if not os.path.exists(binary):
            continue
        version = qemu_version(binary)
        if version < MIN_QEMU:
            print("skipping %s: version %s is below %s and cannot boot this kernel" % (
                binary, ".".join(map(str, version)), ".".join(map(str, MIN_QEMU))))
            continue
        print("using %s (version %s)" % (binary, ".".join(map(str, version))))
        return binary
    print("no usable qemu-system-riscv64 (need >= %s). Pass --qemu PATH." %
          ".".join(map(str, MIN_QEMU)))
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--qemu", help="path to qemu-system-riscv64")
    ap.add_argument("--harness", default=HARNESS, help="streaming QEMU harness script")
    ap.add_argument("--log", default=None, help="where to write the serial log")
    ap.add_argument("--out", default="results", help="where to write the graphs")
    ap.add_argument("--only", default="all", help="run one scenario group by number")
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--timeout", type=float, default=1200, help="hard limit for the QEMU run")
    ap.add_argument("--idle", type=float, default=240, help="stop after this long with no output")
    args = ap.parse_args()

    os.makedirs(os.path.join(REPO, args.out), exist_ok=True)
    log = args.log or os.path.join(REPO, args.out, "scenarios.log")

    qemu = find_qemu(args.qemu)
    if qemu is None:
        return 2

    if not args.skip_build:
        stage(1, "build kernel and disk image")
        if sh(["make", "kernel/kernel", "fs.img"]).returncode != 0:
            print("build failed; nothing to run")
            return 1
    else:
        stage(1, "build skipped (--skip-build)")
        for artifact in ("kernel/kernel", "fs.img"):
            if not os.path.exists(os.path.join(REPO, artifact)):
                print("%s is missing and the build was skipped" % artifact)
                return 1

    stage(2, "run /scenarios under QEMU and capture the trace")
    if not os.path.exists(args.harness):
        print("harness %s not found; pass --harness" % args.harness)
        return 2
    started = time.time()
    program = "scenarios" if args.only == "all" else "scenarios %s" % args.only
    rc = sh([sys.executable, args.harness, qemu, "1", program, log,
             str(args.timeout), str(args.idle), REPO])
    print("trace written to %s (%d bytes, %.0f s)" % (
        log, os.path.getsize(log), time.time() - started))
    if rc.returncode != 0 or not os.path.exists(log):
        print("the run did not produce a log; the stages below need one")
        return 1

    stage(3, "grade the trace against an independent model of the lab rules")
    oracle = sh([sys.executable, os.path.join(REPO, "budget_oracle.py"), log,
                 "--json", os.path.join(REPO, args.out, "oracle.json")])
    # Grading is only meaningful if the grader can fail, so inject known-bad
    # traces and require each one to be caught.
    teeth = sh([sys.executable, os.path.join(REPO, "check_oracle_teeth.py"), log])

    stage(4, "draw the graphs from the same trace")
    plots = sh([sys.executable, os.path.join(REPO, "analyze_results.py"), log,
                "--out", os.path.join(REPO, args.out)])

    print("\n" + "=" * 72)
    print("  artifacts")
    print("=" * 72)
    print("  trace       %s" % log)
    print("  model dump  %s" % os.path.join(args.out, "oracle.json"))
    for name in sorted(os.listdir(os.path.join(REPO, args.out))):
        if name.endswith(".png"):
            print("  graph       %s" % os.path.join(args.out, name))
    verdict = 0 if oracle.returncode == 0 and plots.returncode == 0 and teeth.returncode == 0 \
        else 1
    print("\nverdict: %s" % ("the engine matched every derived expectation, and the"
                             " oracle proved it can say no" if verdict == 0 else
                             "MISMATCH - read the [FAIL] lines above"))
    return verdict


if __name__ == "__main__":
    sys.exit(main())
