# xv6-risky-syscall-limiter

**Irreversibility Budget for Process Groups** — CSL3030 Operating Systems Lab (IIT Jodhpur), Question 1.

A modified [xv6-riscv](https://pdos.csail.mit.edu/6.1810/) kernel in which a class of
destructive system calls has to pay for itself out of a per-process-group token budget.

This file is the whole briefing: design, build, run, verification, known limits, and roadmap.
There is no other design document.

---

## Table of contents

1. [At a glance](#1-at-a-glance)
2. [The idea](#2-the-idea)
3. [The cost table](#3-the-cost-table)
4. [Design](#4-design)
5. [New system calls](#5-new-system-calls)
6. [Guest programs](#6-guest-programs)
7. [Quick start](#7-quick-start)
8. [Running and capturing](#8-running-and-capturing)
9. [Host-side tooling](#9-host-side-tooling)
10. [Verification results](#10-verification-results)
11. [Interpreting what you see](#11-interpreting-what-you-see)
12. [Build and filesystem constraints](#12-build-and-filesystem-constraints)
13. [Troubleshooting](#13-troubleshooting)
14. [Known problems and open decisions](#14-known-problems-and-open-decisions)
15. [Roadmap](#15-roadmap)
16. [Repository layout](#16-repository-layout)
17. [Environment notes](#17-environment-notes)
18. [Upstream xv6 and license](#18-upstream-xv6-and-license)

---

## 1. At a glance

**What exists.** A working, booting xv6-riscv kernel in which `unlink()`, `write()` and `exec()`
are charged against a per-group token bucket, plus six new system calls (`setgroup`, `setbudget`,
`getbudgetstat`, `report`, `budgetinfo`, `dropbudgetauth`) and three new user programs
(`budgetstat`, `test_budget_suite`, `scenarios`) to configure, observe and exercise it. Writing
policy is gated on an inherited capability that only the boot process starts with and that any
process can give up forever. On the host side, `budget_oracle.py` re-derives what the engine
should have done, `analyze_results.py` draws it, and `generate_results.py` runs all of it with one
command.

**What is proven.** The bucket, the charging path, every row of the cost table (console write 1,
own-group write 0, other-group write 3, pipe write 0, `unlink` 10, foreign exec 5, own-group exec
0), BLOCK vs FAIL, lazy refill, per-group isolation, a denial that costs nothing and is
distinguishable from a real error, and a reporting path that costs nothing — all measured on real
QEMU: **110 assertions, 110 pass, 0 fail**. Beyond that, **28 workload scenarios and 147 traced
operations** graded against an independent model of the lab rules: **959 derived checks, 959
agree**, and the model is known to be capable of disagreeing because **twelve injected lies are
each caught by the check meant to catch them**. The authority rule is measured, not asserted: a
confined child refuses all seven ways out of its group, its policy never moves, the rich decoy
group it cannot reach stays untouched, and it is still charged for the work it is allowed to do.
The lab's "all existing usertests still pass" line is true on this kernel — **65 tests, ALL TESTS
PASSED**, with the limiter accounting for 55,012 risky calls in group 18 and throttling none.

**What is not done**, in order of how much it matters: *Step 5, the showcase* — a real QEMU
console window you drive xv6 from, the way the x86 build used to give you, and a way for a user to
write their own budget test suite and run it from that CLI (§15). Nothing claimed in this file
depends on it.

**Where this stands.** The engine, its authority rule, its instrumentation, its oracle and the
upstream test suite are all verified. What remains is presentation.

---

## 2. The idea

Destructive operations are irreversible. `unlink()` cannot be undone by the process that called
it. A normal sandbox asks *"is this allowed?"* once and then permits or denies. This kernel asks a
different question: **how much irreversibility has this group consumed, and is this call worth a
token?**

Each process group holds a token budget. Risky syscalls cost tokens. Tokens trickle back over
time (refill). When a group is out of tokens the kernel either makes it wait (`BLOCK`) or refuses
the call (`FAIL`). Nothing else about xv6 changes: files are still readable, fork is still free,
kill is still free. The budget is only about irreversibility.

So this is **not a permission system**. A group with budget can do anything a stock xv6 group can
do; it just pays. That distinction matters for the first open item in §14.

---

## 3. The cost table

Defined by the `COST_*` constants in `kernel/budget.h` and applied by `syscall_cost()` in
`kernel/syscall.c`.

| syscall | cost | why |
|---|---|---|
| `unlink(path)` | **10** | the reference destructive operation |
| `write(fd, …)` with `fd = 1` or `2` | **1** | console output is irreversible — it is already on screen / in the log |
| `write` to a file owned by our group | **0** | the group already owns the damage |
| `write` to a file owned by another group | **3** | cross-group side effect |
| `exec(path)` whose creating group is not ours | **5** | running another group's binary hands control to code you did not write |
| `exec` of a binary our own group wrote | **0** | same reason as the own-group write |
| `write` to a pipe | **0** | destroys nothing on disk. Charging it made every shell pipeline pay for the kernel's own buffering |
| everything else | **0** | free |

"Owned by our group" means `ip->gid == p->gid`: the file's *creating* group, read from the on-disk
inode, compared against the calling process's group.

**Cost is per SYSCALL, not per byte and not per printf.** This is the single most surprising thing
about the design: xv6's user-level `printf()` issues one `write()` per character (`user/printf.c`
calls `write(fd, &c, 1)` once per character), so a 60-character line is 60 console writes and 60
tokens. Even after batching `printf` into one write per call, note that this tree's
`user/echo.c` calls `write()` twice per argument (the text, then the newline), so `echo one word`
is 2 tokens, not 1. Any expectation you compute must be in `write()` calls.

The charged output path is a choice, not an accident. `user/printf.c` now has one formatter and
two sinks: `printf`/`ffprintf` keep the historical one-character-one-write behaviour, which the
budget charges for, and `rprintf()` formats into a buffer and emits it through the free `report()`
syscall. Nothing was exempted behind the lab's back — the free path is a separate, explicitly
named, separately counted syscall.

**This table is DATA, not prose.** `budgetinfo()` (syscall 27, free) copies the kernel's own
constants out to user space, so a test, a plotting script or the oracle can price an operation
from the table that is actually being charged rather than from a transcription of it. `budgetstat`
prints it above the group rows. §10 shows the run in which an independent copy of that table was
checked against it.

---

## 4. Design

### 4.1 Group identity and policy authority

`struct proc` (`kernel/proc.h`) carries two inherited facts:

```c
int gid;          // which budget this process spends from
int budget_auth;  // 1 = may write group policy (setgroup/setbudget)
```

Both follow the same inheritance path:

| place | effect |
|---|---|
| `userinit()` | `p->gid = 0`, `p->budget_auth = 1` |
| `kfork` / `fork` | copies both from the parent |
| `exec` | neither touched, so both are inherited |
| `freeproc()` | `p->budget_auth = 0` — a recycled slot starts clean |
| `setgroup(g)` | `p->gid = g` (requires authority) |
| `dropbudgetauth()` | `p->budget_auth = 0` — one-way, forever |

`gid` is therefore inherited down the whole process tree and survives `exec`, which is what the
lab asks for: a child cannot shed its group by exec'ing, and cannot escape by re-exec'ing itself.
Authority works the same way and is the subject of §4.7.

A file's group is a separate, on-disk fact: `short gid` in `struct dinode` (`kernel/fs.h`) and in
`struct inode` (`kernel/file.h`). It is stamped at creation (`kernel/fs.c`, `dip->gid =
myproc()->gid`), copied on `link()`, and loaded into the in-memory inode in `ilock()`. `mkfs`
initialises it to 0 (`mkfs/mkfs.c`), so every shipped binary belongs to group 0.

### 4.2 The group table

`kernel/budget.c` owns 20 groups, declared in `kernel/budget.h`:

```c
struct group {
  struct spinlock lock;
  int used;          // tokens spent since the last setbudget()
  int budget;        // tokens currently available
  int max;           // ceiling
  int refill;        // tokens added per 100 ticks
  int mode;          // BUDGET_BLOCK or BUDGET_FAIL
  uint last_refill;  // tick the accrual is caught up to
  int n_allowed;     // charged syscalls that were granted
  int n_blocked;     // syscalls that had to wait (episodes, not wakeups)
  int n_refused;     // syscalls denied: FAIL mode, or unaffordable in BLOCK
  int n_reported;    // report() calls served, counted but never charged
  int report_bytes;  // bytes emitted through the free reporting path
} groups[NGROUP];    // NGROUP = 20
```

One spinlock per group, not one global lock, so two groups genuinely run in parallel. That is
what Test 5 exercises on 3 CPUs.

Defaults, from `budgetinit()` (called in `kernel/main.c` after `fileinit()` and before
`virtio_disk_init()`): `budget=100`, `max=100`, `refill=10` per 100 ticks, `mode=BLOCK`, all
counters zero.

This struct used to be duplicated in `budget.c` and `sysproc.c`. Two definitions of the same
layout in two translation units is a silent-corruption bug waiting for someone to edit one of
them; it now lives in one header.

### 4.3 Where the charge happens

In the dispatcher (`kernel/syscall.c`), *before* the syscall body runs:

```c
if (num > 0 && num < NELEM(syscalls) && syscalls[num]) {
  int cost = syscall_cost(num, p);
  int denial = charge(p->gid, cost);
  if (denial < 0) {
    p->trapframe->a0 = denial;   // BUDGET_DENIED: the syscall never ran
    return;
  }
  p->trapframe->a0 = syscalls[num]();
}
```

Three properties worth preserving:

* **Pay before you break.** The token is taken first. If the call is denied it never executed, so
  there is nothing to roll back. Charging after the call would mean a denial that already deleted
  the file.
* **Unknown syscall numbers are not charged.** The validity check gates the charge, so garbage in
  `a7` costs nothing and cannot be used to drain a budget.
* **A denial is not `-1`.** It is `BUDGET_DENIED` (`-42`). Still negative, so every existing
  `if (x < 0)` error path keeps firing, but a program can now tell "the limiter stopped me" from
  "my own arguments were wrong" — which is what makes a test able to assert on a denial at all.
  The pair is verified in Test 2 (denial → `-42`) and Test 7 (unlink of a missing file → `-1`).

The consequence of "pay before you break" that surprises people: **an `unlink` of a file that does
not exist still costs 10 tokens.** The token buys the *attempt*, and the kernel cannot know the
attempt is harmless until it has run it. Test 7 asserts this explicitly rather than hiding it.

`charge()` returns early on `cost <= 0`, before taking the lock, so the free majority of syscalls
pay no spinlock and pollute no counters.

### 4.4 BLOCK vs FAIL

```
charge(gid, cost):
  if cost <= 0: return 0
  lock; catch refill up to now
  if BLOCK and budget < cost and (max < cost or refill <= 0):
    n_refused++; unlock; return BUDGET_DENIED    // would never be affordable
  while budget < cost:
    FAIL mode  -> n_refused++, unlock, return BUDGET_DENIED
    BLOCK mode -> n_blocked++ (once per episode), sleep on &ticks,
                  relock, refill
  budget -= cost; used += cost; n_allowed++; return 0
```

The **unaffordable guard** is a Step 2 addition and it matters: without it, a BLOCK group whose
ceiling sits below the price of the call (max 9 vs an `unlink` at 10), or whose refill is 0 with a
short bucket, does not wait — it sleeps forever. Waiting for a token that can never arrive is a
*hang*, not a delay, so the kernel denies it the way FAIL would. Test 3 covers both shapes.

BLOCK sleeps on `&ticks`, which the timer interrupt wakes every tick (`kernel/trap.c` does
`ticks++; wakeup(&ticks)`). A blocked process therefore rechecks once per tick and proceeds on the
first tick whose refill covers the cost. That is what produces the staircase in the graph.

`n_blocked` counts **episodes**, not wakeups: one `unlink` that sleeps through 100 ticks is one
blocked event, not 100. Test 6's BLOCK phase reads exactly 2 for 5 unlinks against a 30-token
bucket, i.e. one per throttled call.

### 4.5 Refill

Lazy — there is no background thread:

```
periods      = (ticks - last_refill) / 100
budget      += periods * refill          // clamped to max
last_refill += periods * 100
```

`group_snapshot()`, which backs `getbudgetstat`, runs the same catch-up before copying, so an idle
group reports its true accrued budget instead of a stale one. Without that, a report taken between
syscalls looks like refill is broken.

One tick is about 100 ms in this tree (`kernel/trap.c` arms the next timer 1,000,000 timebase
cycles out at 10 MHz), so the default 10 tokens per 100 ticks (`BUDGET_PERIOD`) is roughly **10
tokens per 10 seconds** — about one `unlink` per 10 seconds.

### 4.6 Observability has to be free

While reporting is charged, an instrumented process cannot report. That is not a theoretical
wrinkle: in the Step 1 logs, Test 4 printed no verdict at all, because the ten children spent the
group's tokens on `printf` characters before they got to the assertion, and the parent's own output
was blocked behind them.

So the reporting path is free and separately counted (`report()`, §5; `rprintf()`,
`user/printf.c`). The accounting rule:

```
charged path  : destroys something  -> spends budget
free path     : observes            -> spends nothing, but is counted
```

A free channel nobody measures is a free channel nobody can explain, so every `report()` bumps
`n_reported` and `report_bytes`. `budgetstat`'s own table now costs nothing, which is the
difference between a limiter you can *demonstrate* and a limiter that silences its own
demonstration.

### 4.7 Who may set policy

The question a grader asks first: if any process can call `setbudget()`, then any confined process
can raise its own ceiling, and the limiter is decoration.

The rule this kernel implements:

> **authority is inherited from the boot process, can be given up, and can never be acquired.**

* `userinit()` is the only process born with `p->budget_auth = 1`. `init`, the shell, and every
  program you run from the shell descend from it, so a person at the console has it.
* `fork` copies it and `exec` preserves it, exactly like `gid`.
* `freeproc()` clears it, so a recycled process slot cannot inherit a capability from whoever
  occupied it last.
* `dropbudgetauth()` clears it for the caller and returns 1 if this call took something away
  (0 if there was nothing to take). It cannot fail and cannot be undone; there is no syscall that
  grants authority to anyone.
* `setgroup()` and `setbudget()` check it *first thing* — before validating their arguments — and
  answer `BUDGET_NOAUTH` (`-43`) if the caller lacks it. Ordered that way deliberately: a confined
  process must not be able to use a policy call as an oracle for what the argument checks would
  have said.
* **Reads are never gated.** `getbudgetstat()`, `report()` and `budgetinfo()` stay open to
  everybody, because a confined workload that cannot see its own budget cannot demonstrate the
  confinement.

`-43` is a different value from `-42` on purpose. "You are not allowed to ask" and "you cannot
afford it" are different facts, and a test that conflates them is not testing the gate. Both
sentinels, like the whole cost table, are published by `budgetinfo()` rather than duplicated in
headers, so userland can assert on them without re-guessing them.

The observable consequence is a two-tier system, and §10.4 measures it: a child that drops
authority keeps its group, keeps being charged for its work, and fails every one of the seven ways
out it can try.

### 4.8 Group id reservations

`NGROUP` is 20 — a project choice, not a lab requirement, pinned in `budget_oracle.py` so a
shrinking table cannot silently hide a group. The ids are allocated, not incidental:

| id | purpose |
|---|---|
| 0 | root and shell; never reconfigured by a scenario |
| 1 | invalid-input edges (nothing is expected to run there) |
| 2–12 | one per workload scenario group |
| 13, 14 | owners of the staged foreign binaries |
| 15 | the mode × fill × cost grid |
| 16 | `BUDGET_GID_CONFINE` — the group a confined workload is locked into |
| 17 | `BUDGET_GID_DECOY` — a deliberately rich group, to migrate into |
| 18 | `BUDGET_GID_TESTS` — upstream usertests: a policy too big to bind |
| 19 | spare |

The sentinel names live in `kernel/budget.h`, so `user/usertests.c`, `user/scenarios.c` and
`budget_oracle.py` all read the same reservation instead of agreeing on a magic number three times.

---

## 5. New system calls

| # | call | returns | charged? |
|---|---|---|---|
| 23 | `setgroup(gid)` | `0`, `-1` or `BUDGET_NOAUTH` | policy call (gated) |
| 24 | `setbudget(gid, max, refill, mode)` | `0`, `-1` or `BUDGET_NOAUTH` | policy call (gated) |
| 25 | `getbudgetstat(struct group_stat *out)` | `0` or `-1` | **free** |
| 26 | `report(buf, len)` | `len` or `-1` | **free** (counted) |
| 27 | `budgetinfo(struct budget_params *out)` | `0` or `-1` | **free** |
| 28 | `dropbudgetauth()` | `1` or `0` | **free** |

`getbudgetstat` copies all 20 records into the user buffer; `budgetstat` is the human-readable dump
of that. Numbers live in `kernel/syscall.h` and the user stubs are **generated**: `user/usys.pl` is
the source of truth, `user/usys.S` is built from it by make (add a line to `usys.pl`, never to
`usys.S` — `make clean` deletes the `.S` and a hand edit loses its stub).

**`report()` is the free path.** It copies in at most `REPORT_MAX` (128) bytes, `printk`s them
verbatim, counts the call against the group and returns the length. It costs no budget and is not
on the lab's cost table, so it does not distort any of the measured charges. A rejected `report()`
(over-long, bad pointer) is still free. `rprintf()` in `user/printf.c` is the user-visible wrapper:
it formats, then splits the text into report-sized chunks, so an arbitrarily long line still never
spends a token.

**`budgetinfo()` is the cost table itself, published.** It copies `struct budget_params`
(`kernel/budget.h`) — the period, `NGROUP`, both denial sentinels (`denied` = could not pay,
`noauth` = not allowed to ask), every price, and the defaults `budgetinit()` installs — into the
caller's buffer, for free, for the same reason `report()` is free: a limiter that charges to be
inspected cannot be inspected. It exists so that nothing downstream has to keep a private copy of
the numbers. `user/scenarios.c` prices every operation from this struct, `budgetstat` prints it
above the table, and `budget_oracle.py` grades the run against the table the kernel actually
charged in that same run. A price changed in the kernel is now visible to everything that depends
on it, instead of silently disagreeing with a copy in a test program or a plotting script.

**`setbudget` semantics that are deliberate:**

* `max`, `refill` and `mode` are validated; negative `max`/`refill` are rejected, and so is a mode
  that is neither `BUDGET_BLOCK` nor `BUDGET_FAIL` (Test 3).
* Changing `max` **clamps** held budget down to the new ceiling. It does **not** top the bucket up
  to `max`. A policy change must not hand out free tokens (Test 2 reads `budget=0` after raising
  `max` to 50).
* Before it rewrites anything, it **banks** what the old policy already earned (`budget_bank()`,
  `kernel/budget.c`). This was a real bug found in Step 3: `setbudget` reset `last_refill` to
  *now*, so tokens accrued by the outgoing refill rate but not yet spent were thrown away, and a
  group that behaved itself and was then reconfigured silently lost budget it had been granted.
  The scenario that proves it is the *fill=wait* family: every one of them reconfigures a group
  that has been accruing, and every one of them now starts at exactly its ceiling.
* There is therefore **no way to buy tokens except by waiting.** Tests that need a full bucket
  refill it by waiting (Test 7) rather than by reconfiguring, and say so.
* `used` is reset, because it means "spend within the new policy window". The event counters are
  lifetime totals and are **not** reset, so a fresh group still starts at 0 and history is never
  silently erased. Every test either uses its own group or asserts on deltas.

`setgroup` and `setbudget` are the two policy calls, and both are gated on `budget_auth` (§4.7):
without it they return `BUDGET_NOAUTH` before looking at their arguments, and they do not touch any
group's state. `dropbudgetauth()` is the only other call that changes authority and it can only
take it away. Nothing else in the kernel grants it — there is no code path that sets
`budget_auth = 1` except `userinit()`. Scenario 9 and §10.4 are the measurement.

---

## 6. Guest programs

Three programs are built into `fs.img` alongside stock xv6 (`make fs.img` embeds `README.md` plus
every user program).

| Command | What it does | Time (CPUS=1) |
|---|---|---|
| `budgetstat` | Prints the published cost table and all 20 group records. Free, instant. | < 1 s |
| `test_budget_suite` | The project's own 7 tests, 110 computed assertions | ~158 s |
| `test_budget_suite 4` | One test, by number | ~10 s |
| `scenarios` | 28 workload scenarios, 147 traced operations. Records only, asserts nothing. | ~173 s |
| `scenarios 5` | One scenario group, by number | varies |
| `usertests` | Upstream xv6 test suite, under a non-binding budget | ~152 s |
| `usertests fourteen` | One upstream test, by name | ~12 s |

### 6.1 `test_budget_suite` — seven tests, 110 assertions

`user/test_budget_suite.c`. It is REAL: it drives the kernel through actual syscalls and reads
actual state back through `getbudgetstat`. It is not a simulation and no expectation is hardcoded —
every assertion is computed from a snapshot taken around the operation it judges.

| Test | What it establishes |
|---|---|
| 1 — Cost matrix | Every row of §3, each asserted as a delta: console write 1, own-group file write 0, other-group file write 3, `unlink` 10, exec of another group's binary 5, exec of a binary this group wrote 0. The exec rows run in a child, because a successful exec replaces the process that would have reported it. |
| 2 — Reconfiguration and modes | Clamping (budget 100 → 20), two unlinks to empty the bucket, a third that BLOCKs for about a refill period and is counted as ONE episode, then FAIL: raising `max` to 50 grants nothing, and the denial returns `BUDGET_DENIED` immediately. |
| 3 — Boundaries | `setgroup(-1)` and `setgroup(NGROUP)` rejected, `setgroup(NGROUP-1)` accepted, `setbudget` with a bad gid, negative max, negative refill and an unknown mode all rejected; an exactly affordable `unlink` (max 10, cost 10) runs and drains; an over-budget `unlink` is denied and spends nothing; a price ABOVE the ceiling, and a bucket with no accrual, are both denied in BLOCK mode instead of hanging; refill after 1100 idle ticks caps at `max`. |
| 4 — Fork-bomb resistance | Group 5, 30 tokens, refill 0, FAIL, then 10 children each trying one `unlink`. Kernel grants 3 / refuses 7, and the children's own exit statuses are cross-checked against the kernel's counters — two independent measurements of the same fact. |
| 5 — Isolation under concurrency | Group 6 loose (100 tokens, BLOCK) and group 7 tight (30 tokens, FAIL) hammer at the same time without either being waited on. Each group's counters, spend and remaining budget are asserted separately, and each process's own count is compared against what the kernel recorded. |
| 6 — Lazy refill, staircase vs flat | Emits `[DATA]` rows for BLOCK then FAIL, and asserts the shape: BLOCK completes all 5 at 100-tick intervals with 2 blocked episodes and 0 refusals; FAIL completes 3 instantly with 2 refusals and 0 blocked. |
| 7 — What a denial costs | An exec denied by the budget runs nothing and spends nothing; an `unlink` of a missing file returns `-1` (not the sentinel) and IS still charged; `uptime`/`getbudgetstat`/`report` all work while the bucket is closed. |

`user/budgetstat.c` dumps the same table for ad-hoc inspection, and the suite dumps it itself at
the end, so one log is self-explaining.

**Five traps surfaced while making the suite honest.** All five are now covered by assertions
rather than by prose:

* The old suite used `open(..., 0x100)` at 11 sites. `O_CREATE` here is `0x200` (`kernel/fcntl.h`),
  so nothing was ever created, and Test 4's unlinks returned `ENOENT` rather than a budget
  decision. Fixed, and the victims are now created for free before the bucket closes.
* It also used `printf(fname, "victim%d.txt", i)` as if `printf` were `sprintf`. xv6 had no
  format-into-buffer form at all; `user/printf.c` now has `snprintf()` and the suite uses it.
* Reusing one victim file across Test 6's two modes cost 3 tokens: the recreate was a write into
  the *other* group's inode, so the FAIL phase read 2 grants instead of 3. Each mode now owns its
  own file. This is the cost table biting the harness that measures it.
* A BLOCK wait measured 99 ticks, not 100, because `refill()` advances `last_refill` by whole
  periods and banks the remainder. Expectations on elapsed ticks therefore need slop
  (`TICK_SLOP`); the structural claim is the episode count, not the tick count.
* The exec rows first pointed at `/_sync`, because that is the source file's name in `user/`. mkfs
  installs it as `/sync`, so `exec()` failed for a reason unrelated to the budget and the charge
  read 0 — which a delta assertion accepts as a pass. A zero delta is only evidence if the
  operation happened, so the exec assertions now check the child's exit status as well as the token
  arithmetic.

### 6.2 `scenarios` — a workload tracer, not a test

`user/scenarios.c`. The suite asks seven questions with fixed numbers in them; scenarios runs 28
shaped workloads and reports everything the kernel did around every one of its 147 operations, and
asserts nothing at all.

| Group | Workload |
|---|---|
| 1 | An `rm -rf`-shaped group draining to empty, in FAIL, in BLOCK with no accrual, and in BLOCK with accrual |
| 2 | A chatty logger: 20 console writes against a 12-token ceiling, then a BLOCK logger that has to wait for a 1-token refill |
| 3 | A build that only touches its own files: own writes, own exec, pipe writes and free reporting — 28 operations against a bucket of 0 in FAIL mode; all 28 must run, because none of them is on the cost table |
| 4 | Cross-group damage: writes into another group's file (3) and exec of another group's binary (5), including a ceiling priced BELOW the cost |
| 5 | Timing: the staircase, the flat line, and a drain-wait-grant timeline that makes the accrual arithmetic observable one operation at a time |
| 6 | Fan-out: 12 children, one bucket sized for 5 of them |
| 7 | An affordability grid: 7 classes × BLOCK/FAIL, each cell given a bucket of exactly two operations' worth |
| 8 | Inputs the engine must reject, each reported as an `[EDGE]` record |
| 9 | Confinement: a controller puts a child in a poor group (2 operations' worth, FAIL) beside a rich decoy; the child drops its policy authority and then tries seven ways out — raise its own ceiling, move itself to the decoy, re-point the decoy's policy, and so on — after which it runs a normal scenario and a grandchild repeats the attempts |

Scenario 9 is measured twice over: the attempts are `[EDGE]` records (property: none of them may
move any policy), and the workload that follows is a full `[SCN]`/`[OP]` trace installed with
`install=0`, so the same oracle model that grades a controller's group grades a confined one. It
has to come out *charged*: confinement is a limit, not an exemption.

Its output is a trace with one grammar, documented at the top of the file (`[PARAMS]`, `[SCN]`,
`[OP]`, `[DATA]`, `[RES]`, `[FAN]`, `[EDGE]`, `[DONE]`), and every number in it comes from the
kernel: the `[OP]` lines carry the bucket the operation saw and all four counter deltas across it.
That is what `budget_oracle.py` consumes.

---

## 7. Quick start

All commands run from the repository root.

### 7.1 Prerequisites

**QEMU must be at least 7.2** — older builds cannot boot this kernel's M-mode entry.

```sh
qemu-system-riscv64 --version     # must print 7.2.0 or newer
```

No path is baked into any script here: the QEMU binary is taken from `--qemu`, else `$QEMU`, else
looked up on `PATH`. So a newer build only has to be reachable, not hard-coded:

```sh
export PATH="<directory holding a >= 7.2 qemu-system-riscv64>:$PATH"
```

`make` is the one exception — it assigns `QEMU` itself, so an exported value is ignored and only a
command-line assignment overrides it:

```sh
make qemu QEMU="$(command -v qemu-system-riscv64)"
```

The Makefile's own version check is dead code (a known bug, §14 item 6), so a too-old QEMU fails as
a boot hang rather than a clear message. Check the version by hand if the kernel does not boot.

**RISC-V toolchain:** `riscv64-linux-gnu-gcc` (the Makefile's `TOOLPREFIX` probe finds it
automatically).

**Python (host-side analysis only, and only for the plotting stage):**

```sh
pip install -r requirements.txt      # matplotlib, numpy
```

`budget_oracle.py`, `check_oracle_teeth.py` and the runners are standard library only. Tested with
Python 3.10, matplotlib 3.10.3, numpy 2.1.3.

### 7.2 Build

```sh
make kernel/kernel fs.img
```

`make` alone does **not** build `fs.img`, and the disk image is required to boot. The build is
clean under `-Wall -Werror`. Rebuild after any source change; the image embeds `README.md` (this
file) plus every user program.

### 7.3 Run it interactively

```sh
make qemu CPUS=1
```

You get the xv6 shell in this terminal. Type commands at the `$ ` prompt. Leave QEMU with **Ctrl-A
X** (Ctrl-A then C enters the QEMU monitor instead).

> Note: this runs on the live `fs.img` (no snapshot), so files you create persist. Only one QEMU may
> hold `fs.img` at a time — exit the interactive session before starting any scripted run.

```sh
$ budgetstat               # the cost table + all 20 group records, instant
$ test_budget_suite 4      # one test, ~10 s
$ scenarios 3              # one scenario group
$ usertests copyout        # one upstream test, by name
```

### 7.4 One command: build, run, grade, plot

```sh
python3 generate_results.py
```

Builds, runs `/scenarios` under QEMU on a throwaway disk, grades the trace against an independent
model of the lab rules, proves the grader can fail by injecting 12 corrupted traces, then draws the
figures. About 3 minutes.

```sh
python3 generate_results.py --skip-build     # reuse kernel and image
python3 generate_results.py --only 5         # one scenario group
python3 generate_results.py --out results    # where artifacts go (default)
```

If several QEMUs are installed, `--qemu` (or `$QEMU`) picks one; otherwise the first
`qemu-system-riscv64` on `PATH` is used and its version is printed.

**Exit status is the verdict: `0` green, `1` mismatch.** Usable as a check in a script or CI.

The expected green lines:

```
[ORACLE] scenarios=28 operations=147 checks=959 pass=959 fail=0
12 mutants injected, 0 escaped the oracle
```

### 7.5 What success looks like

`budgetstat` — check the prices, `group table=20 entries`, both refusal codes (`-42` = cannot
afford, `-43` = not allowed to change policy), and the last line: `this process: holds policy
authority (…)`.

`test_budget_suite` ends with:

```
========================================================
  All Tests Completed
========================================================
[SUMMARY] checks=110 failed=0
```

`scenarios` ends with `[DONE]` and prints no `[ABORT]`. It deliberately contains no verdict — the
grade is produced on the host (§8), because a test that judges itself with the code under test
proves nothing.

`usertests` ends with:

```
[budget] group 18 after usertests: allowed=55012 blocked=0 refused=0 used=287117 budget=3995767/4000000
[budget] the limiter accounted for every call and throttled none
ALL TESTS PASSED
```

While it runs you will see `usertrap(): unexpected scause 0xf` lines and `balloc: out of blocks` /
`ialloc: no inodes`. Stock xv6 prints the same; each is followed by `OK`. Only `FAILED` or a panic
counts as failure.

**Do not interrupt the long runs.** `test_budget_suite` looks idle for over 100 s in Test 3 while it
waits for a bucket to refill, and the staircase scenario pauses about 10 s between grants. That is
the limiter working, not a hang.

---

## 8. Running and capturing

§7 is the step-by-step; this is the reasoning behind it.

**Interactive.** The Makefile already passes `-bios none` (`Makefile:183`), which is required:
`kernel/entry.S` reads `mhartid` and `start()` uses `mret` and PMP, so the kernel must enter in
M-mode at `0x80000000`; `kernel.ld` and `KERNBASE` are set to match.

**Scripted — use the streaming harness, not the expect ones in this repo:**

```sh
python3 run_xv6_test.py \
    qemu-system-riscv64 1 "scenarios 5" results/s5.log 600 240
```

Positional arguments: QEMU, CPUS, command to run (quote it if it takes an argument), log file, hard
timeout (s), idle timeout (s), and optionally a directory to run QEMU in (defaults to the current
one). It runs QEMU with `-snapshot`, so a test can neither mutate `fs.img` nor leave files behind;
waits for the `$ ` prompt, types the command, streams the log through `select()`, and exits with
Ctrl-A x.

Grade that log yourself:

```sh
python3 budget_oracle.py results/s5.log                 # verdict, in the terminal
python3 budget_oracle.py results/s5.log --verbose       # per-operation detail
python3 budget_oracle.py results/s5.log --json results/s5.json

python3 analyze_results.py results/s5.log --out results/figs   # graphs only
python3 check_oracle_teeth.py results/s5.log                   # prove the grader can fail
```

`budget_oracle.py` and `analyze_results.py` exit non-zero when the trace disagrees with the model or
has no `[PARAMS]` record.

**Three timings that are easy to get wrong.**

* The whole suite is ~158 s wall at CPUS=1. The long pole is Test 3, which deliberately idles for
  1100 ticks (~110 s) to watch accrual cap at `max`; that sleep is the largest silent gap in the
  run, so an idle window under ~150 s will stop a healthy run and look like a hang. 240 s is the
  safe default. Before Step 2 the same suite took ~300 s, because per-character `printf` was
  throttling the test's own output.
* The run is not silent at the end: the suite prints `[SUMMARY]` and then the `budgetstat` table
  *after* the "All Tests Completed" marker the harness watches for. It therefore drains for
  `XV6_DONE_GRACE` seconds (default 3.0), ending early once `XV6_DONE_QUIET` (0.5 s) passes with no
  new bytes. Without that, the most important lines in the log — the verdict counts and the final
  table — get cut off.
* `/scenarios` is ~173 s, and the reason is arithmetic worth knowing before you set a timeout: a
  tick is a tenth of a second, so `BUDGET_PERIOD`'s 100 ticks are 10 seconds of guest time and,
  because QEMU keeps the timebase near real time, about 10 seconds of wall clock. Every BLOCK wait
  and every deliberate top-up pays that, and the trace has about a dozen of them. `scenarios 5` is
  the slow one per operation; a group with no waits, like `scenarios 3`, finishes in seconds.

**Polling the guest does not disturb it:** `getbudgetstat` and `report` are on the free path, so a
watcher spends no tokens. That is why `budgetstat` can be read at any moment without changing what
it measures.

**There is deliberately no assertion inside the guest.** A test that derives its expectations from
the code under test cannot find a bug in that code, and a program running inside the kernel's reach
is the least independent place to put the oracle. `/scenarios` reports; the host decides.

---

## 9. Host-side tooling

| Tool | Role |
|---|---|
| `generate_results.py` | One command: discover QEMU ≥ 7.2, build, run `/scenarios` on a snapshot disk, grade, inject mutants, plot. Exit status is the verdict. |
| `run_xv6_test.py` | The streaming harness that actually works (see §8, and §14 item 5 for the ones that do not). |
| `budget_oracle.py` | A second implementation of the lab's rules, written from the spec and not from `kernel/budget.c`. Reads the trace, works out what every operation *should* have done, diffs it against the kernel's counters. No hardcoded verdict. |
| `analyze_results.py` | Draws figures from the same trace — only what the trace reported, with every threshold derived from the published table. |
| `check_oracle_teeth.py` | Injects single-field lies into a real trace and requires each to be caught by the specific check meant to catch it. |

### 9.1 Artifacts in `results/`

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

---

## 10. Verification results

Environment: CPUS=1, `-snapshot`, kernel and userland clean under `-Wall -Werror`. Early runs were
captured with QEMU 9.2.4, later ones with 7.2. Run logs are archived outside the repo (§17).

### 10.1 The measured suite run

The whole suite is **110 checks, 0 failures, 157.9 s wall** (`step2_suite_green_c1.log`). Every one
of the 110 verdicts is in the log, printed by the group whose budget the test had just drained —
which is the thing Step 2 was for.

**Reproducible:** re-run from a rebuilt `fs.img` (`step2_suite_recheck_c1.log`), the new log is
byte-identical to the archived one — same 110 verdicts, same `[SUMMARY]` line, same uptime in every
`[DATA]` staircase row. At CPUS=1 with `-snapshot` nothing races, so the whole suite is
deterministic and diffing two logs is a valid regression test.

Before / after, same kernel, same QEMU:

| | Step 1 baseline | Step 2 green run |
|---|---|---|
| wall time | 302 s | 158 s |
| verdicts | 4 coarse `[PASS]` lines, no per-assertion accounting | 110 `[PASS]` lines plus `[SUMMARY] checks=110 failed=0` |
| Test 4 | printed its children's output and no verdict of its own | prints 10 assertions, all pass, including "exit statuses match the denials = 7" |
| Test 3 | "Unlink with exact budget result: -1 (expect 0)" printed as INFO, and the test still said PASS — its own `printf` had eaten 1 token first | passes for the right reason: the group really holds exactly 10 when the `unlink` runs, because the print before it is free |
| `budgetstat` | literal `%3d` plus mojibake, every character a charged write; ~110 s for a dozen lines | the table appears at once, with padded numbers and a REPORTED column |
| a budget denial | `-1`, indistinguishable from `ENOENT` | `BUDGET_DENIED` (`-42`), which the tests assert on |

The Step 1 log is the old suite, whose expectations were prose ("expect 0") rather than computed.
That is the point: a suite that reports in sentences can print "expect 0", get `-1`, and still say
PASS — and it cannot report anything at all once its own printing is charged.

### 10.2 Selected assertions

**Exec cost.** First measured by hand (`step1_exec_cost.log`: group 9 exec'ing a group-0 `/echo`
used 7 = 5 exec + 2 writes; group 0 exec'ing its own used 2 = 0 + the child's two writes; group 10
with budget 4 refused and used 0), now asserted as deltas inside Test 1 against a silent binary
(`/sync`):

```
T1 foreign exec charge = 5           T1 own-group exec charge = 0
T1 foreign exec counted = 1          T1 own-group exec skipped the bucket = 0
T1 foreign exec ran = 0 (exit)       T1 own-group exec ran = 0 (exit)
```

and in Test 7 against a closed bucket:

```
T7 denied exec returns the sentinel = 10 (the child's exit code for -42)
T7 denied exec did not run the binary
T7 denied exec spent nothing / granted nothing / refused = 1
```

`ran = 0` is the assertion that makes the charge assertion worth reading: a zero delta is only
evidence if the operation actually happened. The property that matters most here is the last block —
**a denial cannot be used to burn budget**, because the charge is refused before anything is
deducted.

**Test 2, the two semantics that are easiest to get wrong:**

```
a lower ceiling clamps the held budget          100 -> 20, not 20 -> 50
T2 BLOCK ticks waited                           100
T2 BLOCK waited unlink counted as ONE episode   blocked delta = 1
T2 FAIL denial returns the sentinel             -42
T2 FAIL denial spent nothing / did not block    used delta 0, blocked delta 0
T2 FAIL denial ticks waited                     0
```

**Test 3, boundaries.** `setgroup(-1)`, `setgroup(NGROUP)`, a bad gid, a negative max, a negative
refill and an unknown mode each return `-1`; `setgroup(NGROUP-1)` returns `0`. Two of the four cases
that used to be a hang or a false negative are the interesting ones:

```
exactly affordable (max 10, cost 10)   ran, drained to 0, spent exactly 10
price above the ceiling, BLOCK mode    denied (-42), blocked delta 0
no accrual and an empty bucket, BLOCK  denied (-42), blocked delta 0
refill after 1100 idle ticks           caps at exactly max = 100
a line printed with a closed bucket    spent 0, granted 0, reported 1
```

The middle two are the Step 2 fix to `charge()`: BLOCK is only a wait if the bucket can eventually
reach the price. Sleeping forever on a price that can never be afforded is a hang, not a throttle.

> **Honest caveat:** "T3 a rejected `setgroup` left the group alone" checks only that
> `setgroup(-5)` returns `-1`. It never reads the process's group back, so it would pass even if a
> rejected call had moved the process. What actually proves the property is the source:
> `sys_setgroup()` returns `-1` before the `p->gid = gid` assignment. To make the test prove it
> too, a readback of the calling process's group is needed, and there is no `getgroup()` syscall
> yet.

**Test 4, fork bomb — now two measurements.** Group 5, 30 tokens, refill 0, FAIL, 10 children each
attempting one `unlink`:

```
kernel granted 3 / refused 7        (from getbudgetstat)
children that deleted 3 / denied 7  (from the exit statuses)
total spend equals the ceiling      used delta = 30, budget = 0
```

The kernel's counters and the children's own exit codes are independent readings of the same fact;
before Step 2 the second one could not be printed at all.

**Test 5, isolation under concurrency.** Group 6 (100, BLOCK) and group 7 (30, FAIL) hammer
simultaneously, neither waited on: 5 granted / 0 waited / 50 spent versus 3 granted / 2 refused /
30 spent, plus "the throttled group did not tax the other" and each process's own count agreeing
with the kernel's.

**Test 6, the staircase and the flat line — the lab's headline graph, from `[DATA]` rows the kernel
produced, not from an `axhline`:**

```
[DATA],BLOCK,1204,0   [DATA],FAIL,1404,0
[DATA],BLOCK,1204,1   [DATA],FAIL,1404,1
[DATA],BLOCK,1204,2   [DATA],FAIL,1404,2
[DATA],BLOCK,1204,3   [DATA],FAIL,1404,3   <- 3 done, then denial is instant
[DATA],BLOCK,1304,4   [DATA],FAIL,1404,3   <- refused, file still there
[DATA],BLOCK,1404,5   [DATA],FAIL,1424,3   <- the test's own pause(20)

BLOCK: 5 deletions, 5 granted, 0 refused, 2 blocked episodes, 200 ticks
FAIL : 3 deletions, 3 granted, 2 refused, 0 blocked, 40 ticks (< 1 period)
```

Same price, same bucket, opposite shape: BLOCK steps one `unlink` per refill period, FAIL flatlines
at the ceiling. The 4th and 5th BLOCK rows are the two unlinks that had to wait for accrual, and
`n_blocked = 2` says the kernel knows it waited exactly twice.

**Test 7, denials vs real errors, and the free path.** A denied exec returns the sentinel and spends
nothing; an `unlink` of a missing file returns `-1` — not the sentinel — and IS charged 10, because
the kernel cannot know an attempt is harmless until it has run it; and `uptime`, `getbudgetstat`
and `report` with a closed bucket move no grant counters while `n_reported` advances ("one line is
one report = 1", "bytes reported with a closed bucket = 46").

**Self-reported table at the end of the green run** (the REPORTED column is what Step 2 added;
group 6's 0 is its child, which never printed):

```
    GID BUDGET/MAX REFILL  MODE  ALLOWED BLOCKED REFUSED REPORTED
      0    100/  100     10 BLOCK       19        0        0         4
      1    100/  100   1000 BLOCK        4        0        0        18
      3      0/    0      0 FAIL         1        0        3        22
      4      0/   50      0 FAIL         3        1        1        25
      5      0/   30      0 FAIL         3        0        7        13
      6    100/  100   1000 BLOCK        5        0        0         0
      7      0/   30      0 FAIL         3        0        2        12
      8     10/   30     10 BLOCK        5        2        0        12
      9     10/   30     10 FAIL         3        0        2        13
     10      0/    0      0 FAIL         1        0        1        22
     15    100/  100     10 BLOCK        0        0        0         6
```

### 10.3 The workloads and the oracle

Measured in `results/scenarios.log`: **28 scenarios, 147 traced operations, 959 derived checks, 0
failures, 173 s wall at CPUS=1.** Regenerate with `python3 generate_results.py`.

What the oracle checks, in six layers:

1. **The published table.** Every price `budgetinfo()` reports is compared against the lab sheet
   (`unlink` 10, console write 1, own-group write 0, other-group write 3, foreign exec 5, own exec
   0), plus `NGROUP` 20, the `-42` and `-43` sentinels — distinct, both negative, and not the same
   value — and the mode constants. A cost-table change now fails a test instead of quietly becoming
   the new truth.
2. **Every operation, one at a time.** The decision (grant / wait / refuse), the price charged, all
   four counter deltas across it, and the bucket itself — predicted exactly where nothing accrues,
   and bounded by the refill the kernel could have earned where something does.
3. **The fan-out aggregate**, which is closed-form however the children interleave:
   `grants = floor(bucket / price)`.
4. **The inputs the engine must reject.**
5. **Confinement.** Every escape a policy-less process attempts must be refused with the
   no-authority sentinel, must move no policy in its own group or in the decoy's, must leave the
   child's exit status clean, and must not exempt the confined workload from being charged for the
   work it is allowed to do.
6. **Properties across the whole run.** Free classes never move a counter at any budget, a denial
   charges nothing, every charged operation is accounted exactly once, and every bucket that was
   told to fill reached its ceiling.

Predicted and measured from the green run (the columns are the model's; a measured line appears
underneath only when the two disagree, and none did):

```
scenario                   class          max refill   mode ops  gr refused  used  wait
---------------------------------------------------------------------------------------
B_unlink                   unlink          30     0   FAIL   5   3      2    30     0
C_unlink                   unlink          31     0  BLOCK   5   3      2    30     0
D_unlink                   unlink          20    10  BLOCK   5   5      0    50     3
B_console                  console         12     0   FAIL  20  12      8    12     0
C_console                  console          6     1  BLOCK   8   8      0     8     2
B_own                      ownwrite         0     0   FAIL  28   0      0     0     0
B_fwrite                   foreignwrite     9     0   FAIL   4   3      1     9     0
B_fexec                    foreignexec     10     0   FAIL   4   2      2    10     0
C_fexec                    foreignexec      4     0  BLOCK   3   0      3     0     0
K_stair                    unlink          30    10  BLOCK   5   5      0    50     2
K_flat                     unlink          30     0   FAIL   5   3      2    30     0
K_accrue                   unlink          20    10   FAIL   8   4      2    40     0
X_fanout                   unlink          50     0   FAIL  12   5      7    50     0
G_unlink_BLOCK             unlink          20     0  BLOCK   3   2      1    20     0
G_console_FAIL             console          2     0   FAIL   3   2      1     2     0
G_foreignwrite_BLOCK       foreignwrite     6     0  BLOCK   3   2      1     6     0
G_foreignexec_FAIL         foreignexec     10     0   FAIL   3   2      1    10     0
G_ownwrite_BLOCK           ownwrite         0     0  BLOCK   3   0      0     0     0
G_pipe_FAIL                pipe             0     0   FAIL   3   0      0     0     0
C_confine                  unlink          20     0   FAIL   5   2      3    20     0
```

(The grid is 7 classes × 2 modes = 14 cells; four of its six uncharged rows are left out above, and
"gr" counts only operations that reached the bucket, which is why a free class shows 0 — its three
operations are separately asserted as having run with every counter unmoved.)

Five rows are worth reading individually:

* **`B_own`** — 28 operations against a bucket of 0 in FAIL mode, all of them free classes, all of
  them ran. This is the row that would catch a limiter that charges for looking at itself.
* **`C_fexec`** — the price of a foreign exec is 5 and the ceiling is 4, in BLOCK mode. Every
  attempt is refused with `wait=0`: the engine will not sleep on a price it can never afford.
  Waiting here would be a hang, not a throttle.
* **`K_stair` / `K_flat`** — the lab's headline pair, same workload, opposite shape. BLOCK finished
  all 5 unlinks and spent 200 ticks doing it (two waits of one period each); FAIL finished 3 in 0
  ticks and refused the rest.
* **`X_fanout`** — 12 children, one bucket of 50, price 10. Five could pay and five did; the seven
  that refused each found the bucket already empty. The order their lines reached the console is
  not the order they were forked — the last seven printed before the first five — which is exactly
  why this scenario is graded on its aggregate and not per child: `grants = floor(50 / 10)` is
  determined, who got there first is not.
* **`C_confine`** — the only scenario in the trace whose policy nobody in the run was allowed to
  write at the time it executed. The controller installed it (group 16: ceiling 20, refill 0,
  FAIL), its child dropped its authority, failed all seven escapes with `-43`, and then ran five
  unlinks: 2 granted, 3 refused, 20 tokens spent. **Confinement changed the right to reconfigure,
  not the obligation to pay.**

**The bug Step 3 found, and the only reason it was findable.** `sys_setbudget()` reset `last_refill`
to "now" without first banking what the outgoing policy had already earned. A group that had spent
its tokens politely and was then reconfigured lost the elapsed part of the current period — tokens
it had been granted, thrown away by a bookkeeping write. Nothing in the seven-test suite could see
it, because no test reconfigured a group that was mid-period and then needed the accrual. The
scenario runner does: filling a bucket for the grid means setting a generous refill, waiting a
period, and reading the ceiling back, and it warned 8 times before the fix and 0 times after. The
fix is `budget_bank()` (`kernel/budget.c`), which `refill()`, `sys_setbudget()` and the snapshot
path all call, so the accrual clock can only be moved by someone who has already been paid for the
period they are closing.

**Reproducible, with one honest exception.** Three captures of `/scenarios`, taken before and after
a userland rebuild and hours apart, produce traces that are byte-identical after removing the
absolute tick stamps — every decision, every counter delta, every aggregate, and the fan-out
children's report order too. The stamps themselves drift by up to one tick between boots (`t=2`
becomes `t=3`), which is boot timing, not policy. Step 2's suite was byte-identical *including*
uptime; this trace is not, because it runs 142 operations across 8 groups and one tick of scheduler
luck is now visible. The oracle therefore **bounds** time-dependent predictions rather than diffing
them — the same conclusion §6.1's `TICK_SLOP` note reached from the other direction.

**The oracle was checked against lies, not just against the truth.**
`python3 check_oracle_teeth.py` injects twelve single-field corruptions into a real trace — an
undercharge, a wrong price, a phantom grant, a bucket that never drains, a free class that starts
paying, a summary that disagrees with its operations, a lost line, a truncated run, a wait that was
not counted, one child admitted too many through the shared bucket, a confined process that raises
its own ceiling and is allowed to, and a gate that refuses with `-43` while still rewriting the
policy behind the refusal — and requires each to be caught by the specific check meant to catch it.
All twelve are, each by its own named check, and the script exits non-zero if any escapes. **An
oracle that cannot fail is not evidence**, and before Step 3 that is exactly what
`analyze_results.py` was.

**Step 2's suite, re-measured after every kernel change.** Because `budget_bank()` and the authority
gate both moved real code, the old seven-test suite is the regression: 110 checks, 0 failures,
157.9 s — unchanged counts, unchanged wall time — on the Step 4 kernel.

### 10.4 The authority rule, measured

Scenario 9's `[EDGE]` records are the whole verdict, straight from `results/scenarios.log`:

```
confine_drop_first                  had=1     (this call took something away)
confine_raise_own_ceiling           rc=-43
confine_rewrite_decoy               rc=-43
confine_migrate_to_rich_group       rc=-43    (the decoy holds 10000 tokens)
confine_bad_gid_still_noauth        rc=-43    (gate fires before argument checks)
confine_drop_second                 rc=0      (nothing left to give up)
confine_policy_after_second_drop    rc=-43
confine_can_read_table              rc=0, ngroup=20   (reads stay open)
confine_bucket_visible              rc=0, max=20, budget=20
confine_grandchild_policy/_migrate  rc=-43    (exec does not reacquire it)
confine_after_escape                moved=0, max=20, refill=0, mode=1
confine_decoy_untouched             moved=0, max=10000
```

and the workload that follows those attempts is charged, not exempt: `C_confine` ran 5 unlinks
against the inherited 20-token ceiling, 2 granted, 3 refused, 20 spent, with `fill=inherited` — the
scenario never called `setbudget()` itself. `check_confinement()` in the oracle turns all of that
into ~17 named checks, and `results/confinement_boundary.png` draws the attempts on the left and the
charged bucket on the right.

### 10.5 The lab's "all existing usertests still pass"

True, and measured. `usertests` on this kernel prints **ALL TESTS PASSED** — 65 `test …: OK` lines
across the fast and slow groups, 0 FAILED, 0 panics, 152 s at CPUS=1 — with the limiter running the
whole time:

```
[budget] group 18 after usertests: allowed=55012 blocked=0 refused=0
         used=287117 budget=3995767/4000000
[budget] the limiter accounted for every call and throttled none
```

The shape of that run is a design statement, not a workaround. `user/usertests.c` now puts itself in
`BUDGET_GID_TESTS` (18) and installs a policy too big to bind — 4,000,000 tokens, 400,000 refill,
BLOCK — so the limiter observes every risky call the upstream suite makes and never once stops it.
It cannot simply ask for a full bucket, because `setbudget()` clamps down and never tops up (§5):
the setup installs the ceiling at the ceiling rate, waits one `BUDGET_PERIOD` to earn it, then
re-installs the real refill. That is the same "no way to buy tokens except by waiting" rule Test 7
asserts, used here to boot the whole upstream suite. Refill is chosen so a period's accrual outruns
the suite's demand; at the default 10 tokens per 10 s, `manywrites`' ~2000 unlinks would take hours.

**One genuine bug surfaced, and it was not the limiter's.** `fourteen` failed with
"create 123456789012345/123456789012345/123456789012345 failed". Three measurements pinned it: a
pristine upstream xv6, built and run separately in a scratch tree, prints `test fourteen: OK` and
ALL TESTS PASSED, so the base tree does not fail on its own; an isolated `usertests fourteen` here
reports `used=131, blocked=0, refused=0`, so the budget never interfered; and the cause is §12's
`DIRSIZ=30` — `fourteen()` carries the comment `// DIRSIZ is 14.` and hard-codes 14- and 15-character
literals, which collide only while `DIRSIZ` is 14. The test now builds both names from the macro, so
the truncation collision it exists to check is checked at whatever `DIRSIZ` is, and it cannot go
stale a second time.

---

## 11. Interpreting what you see

**`ls` is slow — and that is the limiter, not a filesystem bug.** Console output costs 1 token per
write under the lab's cost table, group 0 (the shell) holds 100 tokens refilling 10 per 10 seconds
in BLOCK mode, and a directory listing is dozens of writes — one per character, because xv6's
`printf` writes one character per syscall. So the first ~100 writes are instant and the rest
trickle at roughly one per second. Use `budgetstat` (free, instant) to inspect state, and leave
group 0 alone: starving it throttles the console itself. Group 0's policy is intentionally the
default 100 / 10 / BLOCK.

**Expected console noise.** `usertrap(): unexpected scause 0xf`, `balloc: out of blocks`,
`ialloc: no inodes` all appear in stock xv6 runs too. Only `FAILED` or a panic counts as failure.

**Counter semantics — this table is the API.** These definitions are enforced by the code.

| field | meaning |
|---|---|
| `used` | Tokens spent since the last `setbudget()` for that group. Accumulated by `charge()`, reset by `setbudget()`. |
| `budget` | Tokens currently held, never above `max`. |
| `n_allowed` | Charged syscalls that were granted. Free syscalls (cost 0) are **not** counted. Before Step 1 every syscall counted, which made the number meaningless (96 "allowed" for ~16 real operations). |
| `n_blocked` | Charged syscalls that had to wait for a refill, counted once per blocked **episode**, not once per tick wakeup. Before Step 1 it counted wakeups, so it could far exceed `n_allowed`. |
| `n_refused` | Charged syscalls denied: FAIL mode, or BLOCK mode where the price can never be reached. The caller receives `BUDGET_DENIED` and the syscall body never ran. |
| `n_reported` | `report()` calls served. Counted, never charged. |
| `report_bytes` | Bytes emitted through `report()`. Counted, never charged. |

A policy call refused for lack of authority appears in **none** of these counters. `setgroup()` and
`setbudget()` are not charged operations and the gate returns `BUDGET_NOAUTH` before `charge()` is
reached, so a confined process that hammers the policy calls changes no number the oracle reads.
That is the property scenario 9 and the `gate_lies_but_writes` mutant both test.

Two rules make the numbers readable:

* The charged path spends budget; the free path spends nothing. The three-way split is granted /
  denied / reported, and no syscall appears in more than one of the accounting columns.
* The REPORTED column lags by the reports being printed. The snapshot is taken before the text that
  describes it — in `budgetstat` and in the suite's final dump, the current table's own lines are
  not in its own numbers.

**Invariant a reviewer can check:** `used` equals the sum of the costs of the `n_allowed` calls that
happened after the group's most recent `setbudget()`.

### Am I running it correctly? A checklist

| Claim | Where to check |
|---|---|
| Prices match the lab sheet | `budgetstat`, then `[SUMMARY] failed=0` |
| A dry group is refused | `scenarios 1` → `res=-42`, `refused>0` |
| BLOCK waits instead of refusing | `scenarios 5` → grant timestamps ~100 ticks apart |
| A dry bucket does not block free work | `scenarios 3` → 28 operations, all `res=0`, `used=0` |
| A denial charges nothing | suite Test 7 `[PASS]` lines |
| No process can raise its own budget | `scenarios 9` → seven `[EDGE] … rc=-43`, then `moved=0` |
| The limiter does not break xv6 | `usertests` → ALL TESTS PASSED |
| The grader can say no | `check_oracle_teeth.py` → `12 mutants injected, 0 escaped` |

The full green run is: `generate_results.py` exits 0, `[SUMMARY] checks=110 failed=0` from the
suite, `ALL TESTS PASSED` from usertests. Those three are independent of each other and all three
must hold.

---

## 12. Build and filesystem constraints

The host-side scripts need only the standard library, except the plotting stage
(`pip install -r requirements.txt` for matplotlib and numpy).

These layout constraints this tree satisfies and must keep satisfying. They were broken, cost hours
to diagnose, and are not obvious from the code:

* **`struct dinode` must remain exactly 64 bytes.** `NDIRECT` is 11 (not upstream's 12) so the
  layout is 5 shorts + `short gid` + `ushort pad1` + `uint size` + `uint addrs[NDIRECT + 1]`
  = 12 + 4 + 48 = 64.
* **The indirect pointer is `addrs[NDIRECT]`, i.e. `addrs[11]`, and the array is `NDIRECT + 1`
  long.** Direct blocks are `addrs[0..10]`. When `NDIRECT` was cut to 11 the old
  `addrs[NDIRECT-1]` indexing aliased direct block 10 as the indirect block, and mkfs died with
  `mkfs: read: Success`.
* **`DIRSIZ` is 30, not upstream's 14**, because the user program `test_budget_suite` is 17
  characters and mkfs asserts `strlen(shortname) <= DIRSIZ`. `sizeof(struct dirent)` becomes 32,
  which still divides `BSIZE` evenly. Consequences: `IPB=16`, `MAXFILE=267` blocks (~267 KB).
* **mkfs strips the leading underscore from every `UPROGS` name:** `user/_echo.c` is installed as
  `/echo`, `user/_sync.c` as `/sync`. A test that execs `/_sync` gets `ENOENT`, and if it is
  asserting on an exec charge it silently reads 0 tokens and calls that a pass. Exec the installed
  name.
* **`README.md` is baked into `fs.img`** (`Makefile:160-161`) and is readable inside the guest.
  `make fs.img` is how the in-guest copy is updated; the default goal builds only the kernel, so
  editing this file and running `make qemu` shows the OLD copy inside the guest.
* Do not reformat `kernel/fs.h`, `kernel/file.h` or the `addrs[]` indexing — this section explains
  why, and `make fs.img` will tell you the same thing less politely.

---

## 13. Troubleshooting

**QEMU exits instantly and `results/scenarios.log` is ~158 bytes**, containing
`Failed to get shared "write" lock`. Another QEMU (usually your interactive `make qemu`) holds
`fs.img`. Exit it with Ctrl-A X, confirm with `pgrep -af '[q]emu-system-riscv'` (prints nothing when
clean), and re-run. A stale lock right after a killed run is worth one retry before any diagnosis —
it looks exactly like a kernel that will not boot, and the log is two lines long.

**The kernel does not boot / hangs at "xv6 kernel is booting".** Check
`qemu-system-riscv64 --version` is ≥ 7.2, and that `-bios none` is in the QEMU command line (the
Makefile supplies it; a hand-written `qemu` invocation may not).

**A long run is killed part-way.** The idle timeout must exceed 240 s: `test_budget_suite` idles
110 s inside Test 3, and every BLOCK wait costs about 10 s of wall clock.
`generate_results.py --idle 400` raises it.

**`ls` crawls.** Expected; see §11. Nothing in the tree can change group 0's policy from the shell
yet.

**Never run `pkill -f qemu-system-riscv64`.** It also matches the shell that invokes it. Use
`pgrep -af '[q]emu-system-riscv'` and kill by PID.

**Disk space.** The host disk is nearly full; do not delete project artifacts to make room without
checking with the owner first.

---

## 14. Known problems and open decisions

Ordered by how much they matter.

### Solved in Step 2, listed so nobody re-litigates them

* Reporting is no longer charged (was the blocker on the suite's own verdicts) — §4.6, §5.
  `budgetstat` now prints its table instantly instead of taking 110 s to throttle through a dozen
  lines.
* A denial returns `BUDGET_DENIED` rather than an ambiguous `-1` — §4.3.
* `budgetstat`'s format strings: `%3d`/`%7d` are gone, the formatter has no field widths, so columns
  are padded by hand (`padnum` in `user/budgetstat.c` and in the suite). The old `(null)`-producing
  table is gone.
* The suite's `0x100`-for-`O_CREATE` and `printf`-as-`sprintf` bugs — §6.1.
* BLOCK mode on an unaffordable price used to sleep forever. Now denied — §4.4, Test 3.
* Pipe writes are free — §3.
* `syscall_cost()` read `ip->gid` from an inode that `namei()` returns **unlocked** and possibly
  never loaded, so the exec charge was decided from a stale icache slot. It happened to look right
  while everything was tested from group 0. `kernel/syscall.c` now `ilock()`s before reading the
  owner and `iunlockput()`s after. **Anyone extending the cost table should copy that pattern: an
  unlocked inode's fields are not a fact yet.**
* `user/usys.S` is generated. The budget stubs had been hand-written into it, which `make clean`
  silently deletes; they now come from `user/usys.pl`.

### Solved in Step 4

1. **THE LIMITER WAS NOT A SECURITY BOUNDARY.** Any process could call `setgroup(<new>)` or
   `setbudget(<own gid>, huge, huge, BLOCK)` and walk out of its own limits. The answer chosen is an
   inherited per-process capability, granted only by `userinit()`, passed by fork, preserved by
   exec, cleared by `freeproc()`, and surrenderable once via `dropbudgetauth()`. Reads stay open.
   §4.7, §5, §10.4, scenario 9, and two of the twelve negative-control mutants. Cooperative
   accounting for anybody the boot process chose not to trust is now enforcement, and the
   demonstration is in the trace rather than in the write-up.

2. **THE DEFAULTS WERE TOO TIGHT FOR UPSTREAM usertests.** Group 0 is still 100/10/BLOCK and that is
   still what a demo should use. What changed is that usertests no longer runs there: it installs
   itself in `BUDGET_GID_TESTS` (18) with 4,000,000 tokens and 400,000 refill, which the suite's own
   ~287,000 charged tokens never approach, and it prints what the limiter saw when it finishes. The
   lab's cost model and the upstream suite were never in principle in conflict — only in the choice
   of which group the regression tests spend. §10.5 has the run and the one real bug it found.

### Remaining

3. **A DENIED OPERATION IS NOT REFUNDED, but a CHARGED OPERATION THAT THEN FAILS IS SPENT.** `unlink`
   of a missing file costs 10 tokens and returns `-1` (Test 7 asserts this rather than hiding it).
   That follows from pay-before-you-break, and refunding would require the kernel to know in advance
   that an attempt is harmless. It is defensible and it is the first thing a reviewer will ask
   about, so state the reasoning in the write-up.

4. **`getbudgetstat` stages `struct group_stat stat[NGROUP]` — 880 bytes — on the kernel stack**
   (`kernel/sysproc.c`; 44 bytes per record × 20 groups). Fine in practice, but close to xv6's
   kernel stack budget; field-by-field `copyout` would remove the buffer entirely. (The figure was
   576 bytes before `NGROUP` went 16 → 20 and the two report columns were added.)

5. **The shipped xv6 harnesses do not work, and this is how someone concludes the kernel is broken
   when it is not.**
   * `run_tests.py`: `QEMU_BIN = "qemu-system-riscv64"` takes whatever `PATH` yields. The OpenSBI
     variants and the `pkill -f qemu-system-riscv64` cleanup are gone (the firmware was an absolute
     path outside the repo, an M-mode kernel cannot run behind a firmware, and the `pkill` also
     killed any tool invocation that merely mentioned that string). What still does not work:
     `proc.stdout.readline()` blocks forever because xv6's `$ ` prompt is not newline-terminated, so
     the `"$ "` in-line test never fires, the command is never typed, and the `TIMEOUT` loop
     condition is never re-evaluated. `TIMEOUT = 180` is shorter than the suite's own ~155 s plus
     boot. No `-snapshot`, so every config mutates the live `fs.img`. **Use `run_xv6_test.py`.**
   * `analyze_results.py`, until Step 3: parsed real `[DATA]` lines but hardcoded its conclusions —
     a fixed `test_order` list that includes a verdict Test 4 can never emit, and
     `axhline(y=2)`/`axhline(y=3)` labelled "Budget exhausted (2 unlinks = 20 tokens)" drawn
     unconditionally even when the data disagreed. A plotter with a scripted narrative, not an
     oracle. It now draws only what the trace reported and derives every threshold from the
     published table, and exits non-zero when the oracle disagrees.
   * `run_xv6_test.py` is the harness that actually works, and it now lives in this repo.
     `generate_results.py` wraps it with QEMU discovery, so the version-selection mistake above
     cannot be made by hand.

6. **Makefile has a dead version gate.** The `check-qemu-version` target name was deleted (the rule
   body at `Makefile:202-206` now hangs off a bare `:` rule), and the `qemu` target does not depend on it
   either. So the `MIN_QEMU_VERSION=7.2` check never runs, and `make qemu` with QEMU 6.2 fails in a
   way that looks like a kernel panic.

7. **The interrupt/entry changes in this tree are the project's, not ours,** and are worth
   understanding before touching boot: `kernel/start.c` does `w_sie(0)` where upstream enables
   `SEIE|STIE`, and `trapinithart()` in `kernel/trap.c` sets `SIE_STIE | SIE_SEIE | SIE_SSIE`, with
   `SIE_SSIE` added to `kernel/riscv.h`. Tested and cleared: these are **not** the cause of the slow
   console (that was the charged-output problem, now solved). An A/B run with `charge()` stubbed to
   return 0 made `ls` complete instantly.

### Also still open

* **The model reads the kernel's published table,** so a price that is wrong in the same way on both
  sides — a misreading of the lab sheet, say — is caught only by oracle layer 1, which compares that
  table against the numbers typed into `budget_oracle.py` from the spec. Those are the one place in
  the whole harness where an expected value is still written by hand, and deliberately so: somebody
  has to transcribe the assignment.
* **Authority proves a confined process cannot widen its own cage.** It does not claim a confined
  process cannot exhaust it: children in a group still share one bucket and can starve each other,
  which is the intended semantics of a per-group budget, as scenario 6 measures.

---

## 15. Roadmap

**Step 1 — honest accounting. DONE, and measured (§10).** `n_allowed` only for charged calls;
`n_blocked` once per block episode; `used` accumulated; `setbudget` clamps instead of topping up;
`SYS_exec` cost 5 implemented and verified including the denied-exec case; charge moved behind
syscall-number validation; `struct group` deduplicated into `kernel/budget.h` (which required adding
an include guard to `kernel/spinlock.h` — without it the second inclusion was a redefinition
error); the stat snapshot catches refill up so reports are not stale.

**Step 2 — free observability, honest errors. DONE, and measured (§10).** A reporting path that
consumes no budget (`SYS_report` 26, `report()`, `rprintf()`), so a test can always print its verdict
and `budgetstat` can always dump the table; `BUDGET_DENIED` (`-42`) instead of an ambiguous `-1`;
the per-character-`printf` cost sidestepped rather than removed (`user/printf.c` refactored onto one
formatter with two sinks, `snprintf()` added, `printf`/`fprintf` still charged); `budgetstat`'s field
widths replaced by hand padding against a struct shared through `kernel/budget.h`; the suite
rewritten as 110 computed deltas, green in 158 s where the old one took 302 s and reported nothing;
`charge()` no longer sleeps forever on a price BLOCK can never afford; pipe writes made free; and
the unlocked-inode `gid` read in the exec charge fixed. The whole list, with reasons, is §14.

**Step 3 — scenarios and an oracle. DONE, and measured (§10.3).** `user/scenarios.c` runs shaped
workloads — an `rm -rf`-shaped group, a chatty logger, a build that only touches its own files,
cross-group writes and execs, the staircase and its flat twin, a drain-wait-grant timeline, 12
children through one bucket, a 7-class × 2-mode affordability grid, and the invalid-input edges — and
asserts nothing. `budget_oracle.py` re-implements the lab's rules from the spec and diffs them
against that trace. `analyze_results.py` no longer contains a hardcoded verdict; it draws figures
from the same trace, and `check_oracle_teeth.py` proves the oracle notices ten kinds of lie. The cost
table became data (`SYS_budgetinfo` 27), which is what lets the test, the plots and the oracle price
an operation from the table the kernel actually charged. It found one real bug: a policy rewrite
threw away the accrual the old policy had already earned (`budget_bank()`, §5). Step 4 grew the same
harness from 27 / 142 / 908 / ten-liars to **28 / 147 / 959 / twelve**.

**Step 4 — authority and usertests. DONE, and measured (§10.4, §10.5).**

* *(a) Authority.* A confined process used to be able to widen its own cage, and the sharpest
  question a grader can ask went unanswered. Now `budget_auth` lives in `struct proc`, is granted
  only by `userinit()`, is inherited by fork and preserved by exec, is cleared when a process slot
  is recycled, and is given up forever through `SYS_dropbudgetauth` 28. `setgroup()` and
  `setbudget()` answer `BUDGET_NOAUTH` (`-43`) before they even read their arguments; every read
  path stays open. `NGROUP` went 16 → 20 to make room for the confinement cell, a rich decoy and a
  home for the upstream suite, all named in `kernel/budget.h`. Scenario 9 measures it and the oracle
  grades it as ~17 checks; two new negative controls prove that a gate which returns `-43` while
  still writing the policy, and a confined child which is allowed to raise its own ceiling, are both
  caught. Free reads are what make confinement demonstrable at all: a confined workload that cannot
  see its own bucket cannot prove it is confined.
* *(b) usertests.* The lab's "all existing usertests still pass" is now true and measured: the suite
  installs itself in group 18 under a policy too big to bind, runs 65 tests green behind a live
  limiter that logged every one of its 55,012 risky calls, and prints what the limiter saw on both
  the success and the failure path. It also found — and fixed — a stale upstream test: `fourteen()`
  hard-coded the 14-character names that only collide while `DIRSIZ` is 14, in a tree whose `DIRSIZ`
  had to grow to 30 (§12). Both names now come from the macro. Totals for this step: 28 scenarios /
  147 operations / 959 checks green, 12 mutants caught, Step 2's suite still 110/110, six figures in
  `results/`.

**Step 5 — the console window, and user-authored workloads. NOT STARTED.**

The x86 build of xv6 opened a QEMU window because it drove a VGA; this Makefile (`Makefile:183`)
passes `-nographic` instead, which folds the guest serial console *and* the QEMU monitor into the
terminal `make qemu` ran from — hence Ctrl-A X to leave and Ctrl-A C for the monitor. That terminal
is already interactive — `budgetstat`, `scenarios 5`, `usertests` all run there today — but it is
not a separate window, and it is not what a demo audience expects.

Two facts already checked, because they decide the design: the prebuilt xpack QEMU 9.2.4 was
compiled with display backends (`-display sdl`, `vnc`, `curses`) and with `-chardev vc`, so a real
serial window is available on a machine with a display. xv6-riscv still has no framebuffer driver,
so the window shows the serial text console, not a guest GUI — which is exactly what the x86 window
was.

What to build, in order:

1. A `make qemu-window` target that boots with `-serial vc` so a QEMU window appears, leaving
   `-nographic` untouched for every graded run. Verify the window really appears on the host, with a
   screenshot as evidence.
2. The same session tee'd into the project directory — QEMU's `chardev logfile=`, or
   `-serial tcp::PORT,server,nowait` plus a host bridge — so typing into the window still produces
   the trace the oracle reads. A window that cannot be captured is a window that cannot be graded.
3. Every existing runner reachable from that CLI: `budgetstat`, `test_budget_suite [N]`,
   `scenarios [N]`, `usertests [name]`, and the graphs redrawing on the host as the run proceeds
   (`analyze_results.py` and `budget_oracle.py` are idempotent, so a watcher can refresh `results/`
   live).
4. User-authored suites. The cheapest honest version is a plan-file interpreter in the guest: read a
   file of directives (which group, what policy, which operations, how many of them) and emit the
   existing `[SCN]`/`[OP]`/`[DATA]`/`[RES]` grammar. Then a workload someone writes at the console is
   graded by the same oracle with no new plumbing, and cannot fix its own expectations from inside
   the kernel's reach. xv6's `sh` already runs a script file, so command-level suites work today;
   the plan file is what a budget-engine suite needs.
5. A small `user/budgetctl.c` to set a group's policy from the CLI (the shell has authority), so a
   demo can throttle a workload by hand and watch it in `budgetstat`'s table.

---

## 16. Repository layout

```
kernel/          xv6 kernel + budget.c / budget.h (engine), syscall.c (charge path), proc.c, sysproc.c
user/            xv6 userland + budgetstat.c, test_budget_suite.c, scenarios.c, usys.pl (stub source)
mkfs/            filesystem image builder (stamps gid 0 on every inode)
results/         the graded run: scenarios.log, oracle.json, six PNG figures
.github/workflows/  CI: build + fmt check + usertests + crash test on Linux, build on macOS
budget_oracle.py        host model of the lab rules; grades a trace
analyze_results.py      host plotter, driven by the same oracle
check_oracle_teeth.py   mutant injection — proves the oracle can fail
generate_results.py     build → run → grade → mutate → plot, in one command
run_xv6_test.py         the streaming QEMU harness that works
run_tests.py, *.exp     legacy harnesses — see §14 item 5 before using them
test-xv6.py             upstream xv6 boot/CI driver
Makefile                 build, fs.img (embeds README.md), qemu target
requirements.txt         host plotting deps only
LICENSE                  upstream xv6 (MIT)
```

---

## 17. Environment notes

Development-host specifics, kept here because they have each cost real time:

* The host disk is very full. Do not delete anything to free space without asking; report candidates
  instead.
* Scratch space lives outside this repo: run logs in an external run-output directory, experimental
  trees in a tmpfs directory that is wiped on reboot. Nothing essential is kept there — this repo
  plus the `.diff` files are the durable copies.
* QEMU 7.2 is on `PATH`, which is what the scripts default to. The system package on that machine is
  6.2 and cannot boot this kernel, and it cannot be upgraded because `sudo` needs a password and is
  not usable non-interactively.
* Only one QEMU may hold `fs.img` at a time; two graded runs must therefore be serialised (§13).
* Run logs are archived **outside** this repo, in an external run-output directory: the Step 1
  baselines (`step1_final_suite_c1.log`, `step1_exec_cost.log`, `step1_accounting_fixes.diff`), the
  Step 2 green and recheck logs (`step2_suite_green_c1.log`, `step2_suite_recheck_c1.log`,
  `step2_budgetstat_free_c1.log`, `step2_budgetstat_rebuilt_image.log`,
  `step2_free_reporting.diff`), Step 3's (`step3_scenarios_c1.log`, `step3_suite_recheck_c1.log`)
  and Step 4's (`step4_usertests_all_green_c1.log`, `step4_fourteen_fixed_c1.log`,
  `step4_suite_recheck_c1.log`, `step4_scenarios_c1.log`). Nothing in that directory is under
  version control — if the repo is cloned elsewhere, the logs do not come with it; `results/` in the
  repo does.
* `kernel_budget_verification.png`, if still present in the repo root, is a dead artefact of the old
  plotter and can no longer even be regenerated: it depicts tests 1–6 of the pre-Step-2 suite, whose
  log has no `[PARAMS]` record, which is what `analyze_results.py` requires. Do not show it; the live
  equivalents are the six figures in `results/`.
* Scratch trees used for experiments (all tmpfs, gone after a reboot): `xv6up` (pristine upstream
  xv6, the diff reference for the line numbers above), `fixed` (printf batching + `O_CREATE` patch),
  `fast` (batched printf only), `ab` (interrupt A/B tests) and `verify` (Step 1 + harness patch —
  what `step2_free_reporting.diff` is diffed against). The green Step 2 run was measured in this
  repo, not in a scratch tree.
* Budget ~158 s for the full suite at CPUS=1 now that reporting is free (~300 s with the old
  per-character-`printf` suite); ~173 s for `/scenarios` and ~152 s for `usertests`. A 180 s timeout
  truncates the run before it reaches its summary, and a short idle window looks like a hang for the
  reason in §8.

---

## 18. Upstream xv6 and license

This tree is a fork of MIT xv6-riscv (2024+ layout, sources under `kernel/` and `user/`). Everything
not named in §4–§6 and §12 is stock xv6, including the FS log, the buffer cache, and this tree's
sleeplock-split sleep API (`sleep_prepare(chan)`, then `release(lk)`, then `sleep()`) and its
`printk()` rather than `cprintf()`.

Contributors to upstream xv6: Russ Cox (context switching, locking), Cliff Frey (MP), Xiao Yu (MP),
Nickolai Zeldovich, Austin Clements, and many bug reporters; errors in stock xv6 go to Frans
Kaashoek and Robert Morris (kaashoek, rtm@mit.edu).

See <https://pdos.csail.mit.edu/6.1810/> and the upstream `LICENSE` in this directory.
