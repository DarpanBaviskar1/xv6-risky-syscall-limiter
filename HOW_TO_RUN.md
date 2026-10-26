# How to run this project

A hands-on guide to building the modified xv6-riscv kernel, running it, and
getting both the terminal output and the graded graphs. The design rationale is
in `README`; this file is only about doing things.

All commands below run from the repository root - the directory containing this
file.


## 0. Prerequisites

QEMU must be at least 7.2 (older builds cannot boot this kernel's M-mode entry).

```
qemu-system-riscv64 --version     # must print 7.2.0 or newer
```

No path is baked into any script here: the QEMU binary is taken from `--qemu`,
else `$QEMU`, else looked up on `PATH`. So a newer build only has to be
reachable, not hard-coded:

```
# put the directory holding a >= 7.2 qemu-system-riscv64 first on PATH
export PATH="<that-directory>:$PATH"
```

`make` is the one exception - it assigns `QEMU` itself, so an exported value is
ignored and only a command-line assignment overrides it:

```
make qemu QEMU="$(command -v qemu-system-riscv64)"
```

The host-side analysis needs two Python packages, and only for the plotting
stage:

```
pip install -r requirements.txt
```

The Makefile's own version check is dead code (a known bug, README section 10
item 6), so a too-old QEMU fails as a boot hang rather than a clear message.
Check the version by hand if the kernel does not boot.


## 1. Build

```
make kernel/kernel fs.img
```

`make` alone does **not** build `fs.img`, and the disk image is required to boot.
The build is clean under `-Wall -Werror`. Rebuild after any source change; the
image embeds `README` (not this file) plus every user program.


## 2. Run it interactively (the xv6 console)

```
make qemu CPUS=1
```

You get the xv6 shell in this terminal. Type commands at the `$ ` prompt.
Leave QEMU with **Ctrl-A X** (Ctrl-A then C enters the QEMU monitor instead).

Note: this runs on the live `fs.img` (no snapshot), so files you create persist.

### Programs available inside the guest

| Command | What it does | Time (CPUS=1) |
|---|---|---|
| `budgetstat` | Prints the published cost table and all 20 group records. Free, instant. | < 1 s |
| `test_budget_suite` | The project's own 7 tests, 110 computed assertions | ~158 s |
| `test_budget_suite 4` | One test, by number | ~10 s |
| `scenarios` | 28 workload scenarios, 147 traced operations. Records only, asserts nothing. | ~173 s |
| `scenarios 5` | One scenario group, by number | varies |
| `usertests` | Upstream xv6 test suite, under a non-binding budget | ~152 s |
| `usertests fourteen` | One upstream test, by name | ~12 s |

Do not interrupt the long runs. `test_budget_suite` looks idle for over 100 s in
Test 3 while it waits for a bucket to refill, and the staircase scenario pauses
about 10 s between grants. That is the limiter working, not a hang.

### What success looks like

`budgetstat` — check the prices, `group table=20 entries`, both refusal codes
(`-42` = cannot afford, `-43` = not allowed to change policy), and the last line:
`this process: holds policy authority (...)`.

`test_budget_suite` ends with:

```
========================================================
  All Tests Completed
========================================================
[SUMMARY] checks=110 failed=0
```

`scenarios` ends with `[DONE]` and prints no `[ABORT]`. It deliberately contains
no verdict — the grade is produced on the host (section 4), because a test that
judges itself with the code under test proves nothing.

`usertests` ends with:

```
[budget] group 18 after usertests: allowed=55012 blocked=0 refused=0 used=287117 budget=3995767/4000000
[budget] the limiter accounted for every call and throttled none
ALL TESTS PASSED
```

While it runs you will see `usertrap(): unexpected scause 0xf` lines and
`balloc: out of blocks` / `ialloc: no inodes`. Stock xv6 prints the same; each is
followed by `OK`. Only `FAILED` or a panic counts as failure.

### Two things that surprise people

**`ls` is slow.** Console output costs 1 token per write under the lab's cost
table, group 0 (the shell) holds 100 tokens refilling 10 per 10 seconds in BLOCK
mode, and a directory listing is dozens of writes. So the first ~100 writes are
instant and the rest trickle at roughly one per second. This is the limiter
working on the shell's own group, not a file-system bug. Use `budgetstat` (free,
instant) to inspect state, and leave group 0 alone — starving it throttles the
console itself.

Only one QEMU may hold `fs.img` at a time. Exit the interactive session before
starting any scripted run.


## 3. One command: build, run, grade, plot

```
python3 generate_results.py
```

Builds, runs `/scenarios` under QEMU on a throwaway disk, grades the trace
against an independent model of the lab rules, proves the grader can fail by
injecting 12 corrupted traces, then draws the figures. About 3 minutes.

```
python3 generate_results.py --skip-build     # reuse kernel and image
python3 generate_results.py --only 5         # one scenario group
python3 generate_results.py --out results    # where artifacts go (default)
```

If several QEMUs are installed, `--qemu` (or `$QEMU`) picks one; otherwise the
first `qemu-system-riscv64` on `PATH` is used and its version is printed.

Exit status is the verdict: `0` green, `1` mismatch. Usable as a check in a
script or CI.

### Artifacts

| Path | What it is |
|---|---|
| `results/scenarios.log` | The raw trace the guest printed (`[PARAMS]`, `[SCN]`, `[OP]`, `[RES]`, `[EDGE]`, `[DONE]`) |
| `results/oracle.json` | The parsed trace plus every row the model derived |
| `results/staircase_block_vs_fail.png` | BLOCK staircase against its FAIL twin |
| `results/bucket_accounting.png` | Bucket level and counters per operation |
| `results/cost_matrix.png` | Every row of the cost table as measured |
| `results/fanout_shared_bucket.png` | 12 children spending one bucket |
| `results/confinement_boundary.png` | The seven escapes a policy-less process attempts, and the charged workload after them |
| `results/predicted_vs_measured.png` | Model prediction against the kernel's own counters |

Expected green line in the output:

```
[ORACLE] scenarios=28 operations=147 checks=959 pass=959 fail=0
12 mutants injected, 0 escaped the oracle
```


## 4. One run, logged — for anything else

Runs a single command headlessly, with a snapshot disk, and writes the serial
output to a file:

```
python3 run_xv6_test.py \
    qemu-system-riscv64 1 "scenarios 5" results/s5.log 600 240
```

Arguments: QEMU, CPU count, command (quote it if it takes an argument), log file,
hard timeout (s), idle timeout (s), and optionally a directory to run QEMU in -
it defaults to the current directory, which is why the example ends at the idle
timeout.

Grade that log yourself:

```
python3 budget_oracle.py results/s5.log                 # verdict, in the terminal
python3 budget_oracle.py results/s5.log --verbose       # per-operation detail
python3 budget_oracle.py results/s5.log --json results/s5.json

python3 analyze_results.py results/s5.log --out results/figs   # graphs only
python3 check_oracle_teeth.py results/s5.log                   # prove the grader can fail
```

`budget_oracle.py` and `analyze_results.py` exit non-zero when the trace
disagrees with the model or has no `[PARAMS]` record.

Polling the guest does not disturb it: `getbudgetstat` and `report` are on the
free path, so a watcher spends no tokens. That is why `budgetstat` can be read at
any moment without changing what it measures.


## 5. Am I running it correctly? A checklist

| Claim | Where to check |
|---|---|
| Prices match the lab sheet | `budgetstat`, then `[SUMMARY] failed=0` |
| A dry group is refused | `scenarios 1` → `res=-42`, `refused>0` |
| BLOCK waits instead of refusing | `scenarios 5` → grant timestamps ~100 ticks apart |
| A dry bucket does not block free work | `scenarios 3` → 28 operations, all `res=0`, `used=0` |
| A denial charges nothing | suite Test 7 `[PASS]` lines |
| No process can raise its own budget | `scenarios 9` → seven `[EDGE] ... rc=-43`, then `moved=0` |
| The limiter does not break xv6 | `usertests` → ALL TESTS PASSED |
| The grader can say no | `check_oracle_teeth.py` → `12 mutants injected, 0 escaped` |

The full green run is: `generate_results.py` exits 0, `[SUMMARY] checks=110
failed=0` from the suite, `ALL TESTS PASSED` from usertests. Those three are
independent of each other and all three must hold.


## 6. Troubleshooting

**QEMU exits instantly and `results/scenarios.log` is ~158 bytes**, containing
`Failed to get shared "write" lock`. Another QEMU (usually your interactive
`make qemu`) holds `fs.img`. Exit it with Ctrl-A X, confirm with
`pgrep -af '[q]emu-system-riscv'` (prints nothing when clean), and re-run.

**The kernel does not boot / hangs at "xv6 kernel is booting".** Check
`qemu-system-riscv64 --version` is >= 7.2, and that `-bios none` is in the QEMU
command line (the Makefile supplies it; a hand-written `qemu` invocation may not).

**A long run is killed part-way.** The idle timeout must exceed 240 s:
`test_budget_suite` idles 110 s inside Test 3, and every BLOCK wait costs about
10 s of wall clock. `generate_results.py --idle 400` raises it.

**`ls` crawls.** Expected; see section 2. Group 0's policy is intentionally the
default 100 tokens / 10 refill. Nothing in the tree can change it from the shell
yet.

**Never run `pkill -f qemu-system-riscv64`.** It also matches the shell that
invokes it. Use `pgrep -af '[q]emu-system-riscv'` and kill by PID.

**Disk space.** The host disk is nearly full; do not delete project artifacts to
make room without checking with the owner first.


## 7. Where the rest is written down

- `README` — the full briefing: design, cost table, syscalls, counter semantics,
  verification results, open items, roadmap, environment notes.
- `README` section 6 — the same run/capture instructions in prose, plus timing
  details.
- `README` section 9 — what each green run actually proves.
- `README` section 11 — what is not built yet (a `budgetctl` to set policy from
  the console, a plan-file interpreter for user-authored suites, a separate QEMU
  window).
