#!/usr/bin/env python3
"""
check_oracle_teeth.py - prove that budget_oracle.py is capable of saying no.

An oracle that always answers "agreed" is worth nothing, and the only way to
tell that apart from a correct one is to feed it a kernel that lied. Each mutant
below is a single-field edit to a real trace - the kind of thing a real bug in
charge(), refill() or sys_setbudget() would put on the serial line - and each one
has to be caught by a named check.

    python3 check_oracle_teeth.py [trace-log]

Exits 0 only if the untouched trace passes and every mutant fails.
"""

import contextlib
import io
import os
import re
import sys
import tempfile

from budget_oracle import Oracle, Trace

# (name, what a bug would look like, regex, replacement, which check should fire)
MUTANTS = [
    ("undercharge",
     "a granted unlink deducts 9 instead of its published 10",
     r"(\[OP\],B_unlink,0,unlink,bb=30,exp=10,res=0,da=1,db=0,dr=0,)du=10", r"\g<1>du=9",
     "counters"),
    ("wrong_price",
     "the kernel charges console writes 3 tokens instead of 1",
     r"(\[OP\],B_console,\d+,console,[^\n]*?)exp=1", r"\g<1>exp=3",
     "priced at"),
    ("phantom_grant",
     "an operation the bucket could not pay for is reported as having run",
     r"(\[OP\],B_unlink,3,unlink,bb=0,)exp=10,res=1,da=0,db=0,dr=1", r"\g<1>exp=10,res=0,da=1,db=0,dr=0",
     "must be denied"),
    ("bucket_never_drains",
     "spend is not deducted: the bucket stays full after a grant",
     r"(\[OP\],B_unlink,1,unlink,)bb=20", r"\g<1>bb=30",
     "bucket at"),
    ("free_class_charged",
     "a class that is not on the cost table starts paying for it",
     r"(\[OP\],B_own,\d+,ownwrite,[^\n]*?)du=0", r"\g<1>du=1",
     "moved no counter"),
    ("totals_lie",
     "the scenario summary reports a different spend than the operations did",
     r"(\[RES\],B_unlink,allowed=3,blocked=0,refused=2,used=)30", r"\g<1>40",
     "used ="),
    ("lost_operation",
     "a traced operation never reaches the serial line",
     r"\[OP\],B_console,7,console[^\n]*\n\[DATA\],B_console,[^\n]*\n", "",
     "operations traced"),
    ("truncated_run",
     "the program dies part-way through and nobody notices",
     r"\[DONE\][^\n]*\n", "",
     "[DONE]"),
    ("stolen_accrual",
     "a BLOCK wait grants the operation but the bucket never refilled",
     r"(\[OP\],D_unlink,3,unlink,)bb=0,exp=10,res=0,da=1,db=1", r"\g<1>bb=0,exp=10,res=0,da=1,db=0",
     "counters"),
    ("fanout_over_admits",
     "one child too many is admitted through the same shared bucket",
     r"(\[FAN\],X_fanout,)11,rc=1,bb=0", r"\g<1>11,rc=0,bb=10",
     "grants = floor"),
    ("no_authority_gate",
     "a confined process raises its own ceiling and the kernel lets it",
     r"(\[EDGE\],confine_raise_own_ceiling,rc=)-43", r"\g<1>0",
     "refused for lack of authority"),
    ("gate_lies_but_writes",
     "the refusal is returned but the policy is rewritten anyway",
     r"(\[EDGE\],confine_after_escape,moved=)0,max=20", r"\g<1>1,max=10000",
     "moved no policy at all"),
]


def grade(text):
    handle = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
    handle.write(text)
    handle.close()
    try:
        oracle = Oracle(Trace(handle.name), muted=True)
        # The per-check [FAIL] lines are the oracle's own terminal report; this
        # script wants the tally, so the noise is captured rather than printed.
        with contextlib.redirect_stdout(io.StringIO()):
            oracle.run()
        return oracle
    finally:
        os.unlink(handle.name)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "results/scenarios.log"
    if not os.path.exists(path):
        print("no trace at %s; run generate_results.py first" % path)
        return 2
    with open(path) as handle:
        text = handle.read()

    clean = grade(text)
    print("unmutated trace: %d checks, %d failures" % (clean.checks, clean.fails))
    if clean.fails:
        print("the trace you are grading already fails, so mutant results mean nothing")
        return 1

    missed = 0
    injected = 0
    for name, story, pattern, repl, expect in MUTANTS:
        mutated, count = re.subn(pattern, repl, text, count=1)
        if count == 0:
            # A partial trace (--only 5) legitimately lacks the scenarios some
            # mutants edit; that is not a gap in the oracle.
            print("  %-24s %-22s not exercised by this trace: %s" % (
                "N/A", name, story))
            continue
        injected += 1
        oracle = grade(mutated)
        caught = oracle.fails > 0
        right_check = any(expect in failure for failure in oracle.failures)
        if not caught or not right_check:
            missed += 1
        print("  %-24s %-22s %d failure(s), %s: %s" % (
            "CAUGHT" if caught and right_check else "ESCAPED", name, oracle.fails,
            "by the check meant to catch it" if right_check else "not by '%s'" % expect,
            story))
        if caught and not right_check:
            for failure in oracle.failures[:3]:
                print("      fired instead: %s" % failure)

    print("\n%d mutants injected, %d escaped the oracle" % (injected, missed))
    if injected == 0:
        print("nothing was injected - this trace cannot prove anything about the oracle")
        return 1
    if missed:
        print("AN ORACLE THAT CANNOT FAIL IS NOT EVIDENCE - fix the checks above")
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
