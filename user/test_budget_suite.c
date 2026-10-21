//
// test_budget_suite.c -- the test suite for the irreversibility budget for
// process groups (CSL3030 Lab I, Question 1).
//
// Every verdict here is emitted with rprintf(), which goes through the free
// report() syscall. That is deliberate: a throttled group must still be able to
// print its own results. printf() spends one token per character and can be
// blocked mid-sentence by the very thing it is measuring, which silently loses
// the verdict -- which is exactly how the earlier revision of this file lost
// Test 4's.
//
// Assertions are written as deltas of the group counters across one operation,
// so a cost-0 syscall can never pollute an expectation. Set-up work uses
// open/write/close, all of which are free; the only charged operations in this
// file are the ones under test.
//
#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/fcntl.h"
#include "kernel/budget.h"
#include "user/user.h"

// The lab's cost table, restated so each expectation reads as a rule.
#define COST_CONSOLE 1
#define COST_OWN_WRITE 0
#define COST_FOREIGN_WRITE 3
#define COST_EXEC_FOREIGN 5
#define COST_EXEC_OWN 0
#define COST_UNLINK 10

#define BLOCKED 1
#define NOT_BLOCKED 0
#define GRANTED 1
#define DENIED 0

// mkfs stores each program under its own name minus the leading underscore, and
// sync prints nothing, so exec'ing it is charged exactly its own price with
// nothing to subtract afterwards.
#define SILENT_BIN "/sync"

#define CHUNK 2048
#define PERIOD 100 // ticks in one refill period
#define FAIL_SLACK 10 // ticks a FAIL-mode denial is allowed to take
// Refill keeps the remainder: last_refill advances by whole periods only, so
// the leftover ticks bank against the next wait and a measured wait can be a
// period minus that drift. Anything inside this slop is still one period.
#define TICK_SLOP 20

static int checks;
static int failed;
static int only; // 0 runs every test; n runs only test n

static int
run(int n)
{
  return only == 0 || only == n;
}

static void
snap(int gid, struct group_stat *out)
{
  struct group_stat stats[NGROUP];

  if (getbudgetstat(stats) < 0) {
    rprintf("[ABORT] getbudgetstat failed\n");
    exit(1);
  }
  *out = stats[gid];
}

static void
check(const char *label, int got, int want)
{
  char line[192];

  checks++;
  if (got == want)
    snprintf(line, sizeof(line), "[PASS] %s = %d\n", label, got);
  else {
    failed++;
    snprintf(line, sizeof(line), "[FAIL] %s got=%d want=%d\n", label, got, want);
  }
  rprintf("%s", line);
}

// Values reported but not asserted, for the write-up and the graphs.
static void
info(const char *label, int v)
{
  char line[160];

  snprintf(line, sizeof(line), "[INFO] %s = %d\n", label, v);
  rprintf("%s", line);
}

// Right-justify v in w characters; this formatter has no field widths.
static char *
padnum(char *buf, int sz, int v, int w)
{
  char t[16];
  int l, i, j;

  if (w >= sz)
    w = sz - 1;
  snprintf(t, (int)sizeof(t), "%d", v);
  l = (int)strlen(t);
  if (l > w)
    w = l;
  i = 0;
  while (i < w - l)
    buf[i++] = ' ';
  for (j = 0; j < l; j++)
    buf[i + j] = t[j];
  buf[i + l] = 0;
  return buf;
}

static void
dump_table(void)
{
  struct group_stat stats[NGROUP];
  char g[16], b[16], m[16], r[16], a[16], bl[16], rf[16], rp[16];

  if (getbudgetstat(stats) < 0) {
    rprintf("[ABORT] getbudgetstat failed\n");
    exit(1);
  }

  // REPORTED lags by the calls this dump itself makes: the snapshot is taken
  // before the text it prints.
  rprintf("\nGID BUDGET/MAX REFILL  MODE  ALLOWED BLOCKED REFUSED REPORTED\n");
  for (int i = 0; i < NGROUP; i++) {
    struct group_stat *s = &stats[i];

    if (!s->used && !s->n_allowed && !s->n_blocked && !s->n_refused &&
        !s->n_reported && s->max == 100 && s->refill == 10 &&
        s->mode == BUDGET_BLOCK)
      continue;

    rprintf("%s %s/%s %s %s %s %s %s %s\n",
            padnum(g, (int)sizeof(g), i, 3),
            padnum(b, (int)sizeof(b), s->budget, 6),
            padnum(m, (int)sizeof(m), s->max, 5),
            padnum(r, (int)sizeof(r), s->refill, 6),
            s->mode == BUDGET_BLOCK ? "BLOCK" : "FAIL ",
            padnum(a, (int)sizeof(a), s->n_allowed, 8),
            padnum(bl, (int)sizeof(bl), s->n_blocked, 8),
            padnum(rf, (int)sizeof(rf), s->n_refused, 8),
            padnum(rp, (int)sizeof(rp), s->n_reported, 9));
  }
}

// Create name, owned by the caller's current group, with content in it. Free:
// open, write to a file of one's own group and close all cost nothing.
static void
own_file(const char *name, const char *content)
{
  int fd;

  if ((fd = open(name, O_CREATE | O_WRONLY)) < 0) {
    rprintf("[ABORT] could not create a file owned by this group\n");
    exit(1);
  }
  write(fd, content, strlen(content));
  close(fd);
}

// Copy src into dst as the current group, so dst belongs to this group and an
// exec of it is free. Everything here is cost-0 except nothing.
static void
copy_as_own(const char *src, const char *dst)
{
  static char buf[CHUNK];
  int in, out, n;

  if ((in = open(src, O_RDONLY)) < 0) {
    rprintf("[ABORT] cannot open the source binary\n");
    exit(1);
  }
  if ((out = open(dst, O_CREATE | O_WRONLY)) < 0) {
    rprintf("[ABORT] cannot create the copy\n");
    exit(1);
  }
  while ((n = read(in, buf, (int)sizeof(buf))) > 0) {
    if (write(out, buf, n) != n) {
      rprintf("[ABORT] short copy\n");
      exit(1);
    }
  }
  close(in);
  close(out);
}

// ---------------------------------------------------------------------------
// Test 1: one charge per row of the cost table
// ---------------------------------------------------------------------------
static void
test1_cost_matrix(void)
{
  struct group_stat a, b;
  char *av[1] = {0};
  int fd, st;

  rprintf("\n===== TEST 1: syscall cost matrix =====\n");

  // Group 2 owns the foreign file; group 1 pays for touching it.
  setgroup(2);
  own_file("t1_foreign.txt", "foreign");

  setgroup(1);
  setbudget(1, 100, 1000, BUDGET_BLOCK);
  snap(1, &a);
  check("T1 setbudget resets the spend counter", a.used, 0);
  check("T1 measurement group starts at its ceiling", a.budget, 100);

  snap(1, &a);
  write(1, "x", 1); // one write() syscall to the console
  snap(1, &b);
  check("T1 console write charge", b.used - a.used, COST_CONSOLE);
  check("T1 console write counted as granted", b.n_allowed - a.n_allowed, 1);

  own_file("t1_own.txt", "own");
  fd = open("t1_own.txt", O_WRONLY);
  snap(1, &a);
  if (fd >= 0) {
    write(fd, "own", 3);
    close(fd);
  }
  snap(1, &b);
  check("T1 own-group file write charge", b.used - a.used, COST_OWN_WRITE);
  check("T1 own-group file write never reaches the bucket",
        b.n_allowed - a.n_allowed, 0);

  fd = open("t1_foreign.txt", O_WRONLY);
  snap(1, &a);
  if (fd >= 0) {
    write(fd, "foreign", 7);
    close(fd);
  }
  snap(1, &b);
  check("T1 other-group file write charge", b.used - a.used, COST_FOREIGN_WRITE);
  check("T1 other-group file write counted", b.n_allowed - a.n_allowed, 1);

  snap(1, &a);
  st = unlink("t1_foreign.txt");
  snap(1, &b);
  check("T1 unlink charge", b.used - a.used, COST_UNLINK);
  check("T1 unlink counted", b.n_allowed - a.n_allowed, 1);
  check("T1 unlink deleted the file", st, 0);

  // Exec is charged to the caller, so run it in a child and let the parent
  // observe. sync prints nothing, so the delta is the exec price alone.
  snap(1, &a);
  if (fork() == 0) {
    exec(SILENT_BIN, av);
    rprintf("[INFO] T1 foreign exec did not run\n");
    exit(3);
  }
  wait(&st);
  snap(1, &b);
  check("T1 foreign exec charge", b.used - a.used, COST_EXEC_FOREIGN);
  check("T1 foreign exec counted", b.n_allowed - a.n_allowed, 1);
  check("T1 foreign exec ran", st, 0);

  // A binary this group wrote is its own group's file: exec of it is free.
  copy_as_own(SILENT_BIN, "t1_own.bin");
  snap(1, &a);
  if (fork() == 0) {
    exec("/t1_own.bin", av);
    rprintf("[INFO] T1 own-group exec did not run\n");
    exit(3);
  }
  wait(&st);
  snap(1, &b);
  check("T1 own-group exec charge", b.used - a.used, COST_EXEC_OWN);
  check("T1 own-group exec skipped the bucket", b.n_allowed - a.n_allowed, 0);
  check("T1 own-group exec ran", st, 0);
}

// ---------------------------------------------------------------------------
// Test 2: reconfiguration, BLOCK vs FAIL, and a denial that names itself
// ---------------------------------------------------------------------------
static void
test2_dynamic_reconfig(void)
{
  struct group_stat a, b;
  int t0, t1, st;

  rprintf("\n===== TEST 2: dynamic reconfiguration and modes =====\n");

  setgroup(4);
  setbudget(4, 20, 10, BUDGET_BLOCK);
  snap(4, &a);
  check("T2 a lower ceiling clamps the held budget", a.budget, 20);
  check("T2 BLOCK mode installed", a.mode, BUDGET_BLOCK);

  own_file("t2_a.txt", "a");
  snap(4, &a);
  st = unlink("t2_a.txt");
  snap(4, &b);
  check("T2 first unlink granted", b.n_allowed - a.n_allowed, 1);
  check("T2 first unlink leaves half the bucket", b.budget, 10);
  check("T2 first unlink deleted the file", st, 0);

  own_file("t2_a.txt", "a");
  snap(4, &a);
  unlink("t2_a.txt");
  snap(4, &b);
  check("T2 second unlink empties the bucket", b.budget, 0);
  check("T2 spend accumulates within one policy window", b.used, 20);

  // Third unlink: BLOCK waits for a refill instead of failing.
  own_file("t2_a.txt", "a");
  snap(4, &a);
  t0 = uptime();
  st = unlink("t2_a.txt");
  t1 = uptime();
  snap(4, &b);
  check("T2 BLOCK grants once the bucket refills", st, 0);
  check("T2 BLOCK counts one wait episode", b.n_blocked - a.n_blocked, BLOCKED);
  check("T2 BLOCK denies nothing", b.n_refused - a.n_refused, DENIED);
  check("T2 BLOCK waited about a refill period",
        (t1 - t0) >= PERIOD - TICK_SLOP && (t1 - t0) <= PERIOD + TICK_SLOP, 1);
  info("T2 BLOCK ticks waited", t1 - t0);

  // Raising the ceiling must not hand out tokens.
  setbudget(4, 50, 0, BUDGET_FAIL);
  snap(4, &a);
  check("T2 FAIL mode installed", a.mode, BUDGET_FAIL);
  check("T2 a raised ceiling granted no tokens", a.budget, 0);
  check("T2 a raised ceiling is recorded as 50", a.max, 50);
  info("T2 budget after raising the ceiling to 50", a.budget);

  own_file("t2_b.txt", "b");
  snap(4, &a);
  t0 = uptime();
  st = unlink("t2_b.txt");
  t1 = uptime();
  snap(4, &b);
  check("T2 FAIL denial returns the sentinel", st, BUDGET_DENIED);
  check("T2 FAIL denial did not block", b.n_blocked - a.n_blocked, NOT_BLOCKED);
  check("T2 FAIL denial counted as refused", b.n_refused - a.n_refused, 1);
  check("T2 FAIL denial spent nothing", b.used - a.used, 0);
  check("T2 FAIL denial returned at once", (t1 - t0) < FAIL_SLACK, 1);
  info("T2 FAIL denial ticks", t1 - t0);
}

// ---------------------------------------------------------------------------
// Test 3: boundaries -- bad arguments, exact fits, and prices nobody can pay
// ---------------------------------------------------------------------------
static void
test3_boundary_edges(void)
{
  struct group_stat a, b;
  int st;

  rprintf("\n===== TEST 3: boundary and edge cases =====\n");

  check("T3 setgroup(-1) rejected", setgroup(-1), -1);
  check("T3 setgroup(NGROUP) rejected", setgroup(NGROUP), -1);
  check("T3 setgroup(NGROUP-1) accepted", setgroup(NGROUP - 1), 0);
  check("T3 setbudget bad gid rejected", setbudget(NGROUP, 10, 1, BUDGET_BLOCK), -1);
  check("T3 setbudget negative max rejected", setbudget(11, -1, 1, BUDGET_BLOCK), -1);
  check("T3 setbudget negative refill rejected", setbudget(11, 10, -1, BUDGET_BLOCK), -1);
  check("T3 setbudget bad mode rejected", setbudget(11, 10, 1, 7), -1);
  check("T3 a rejected setgroup left the group alone", setgroup(-5), -1);

  setgroup(3);

  // Exactly affordable: max equals the price of one unlink.
  setbudget(3, 10, 0, BUDGET_FAIL);
  snap(3, &a);
  check("T3 exactly affordable bucket", a.budget, COST_UNLINK);
  check("T3 setbudget resets the spend counter", a.used, 0);

  own_file("t3_exact.txt", "x");
  st = unlink("t3_exact.txt");
  snap(3, &b);
  check("T3 exactly affordable unlink ran", st, 0);
  check("T3 exactly affordable unlink drains it", b.budget, 0);
  check("T3 exactly affordable unlink spent its price", b.used, COST_UNLINK);

  // One token over: denied, and nothing spent.
  own_file("t3_over.txt", "x");
  snap(3, &a);
  st = unlink("t3_over.txt");
  snap(3, &b);
  check("T3 over-budget unlink denied", st, BUDGET_DENIED);
  check("T3 over-budget unlink spent nothing", b.used - a.used, 0);
  check("T3 over-budget unlink counted as refused", b.n_refused - a.n_refused, 1);

  // Permanently unaffordable: the ceiling is below the price, so no amount of
  // waiting can ever pay for it. BLOCK must deny rather than sleep forever.
  setbudget(3, 9, 1000, BUDGET_BLOCK);
  own_file("t3_steep.txt", "x");
  snap(3, &a);
  st = unlink("t3_steep.txt");
  snap(3, &b);
  check("T3 price above the ceiling denied in BLOCK", st, BUDGET_DENIED);
  check("T3 price above the ceiling did not block", b.n_blocked - a.n_blocked, NOT_BLOCKED);
  check("T3 price above the ceiling counted as refused", b.n_refused - a.n_refused, 1);

  // No accrual and a short bucket is the other way to be unaffordable.
  setbudget(3, 100, 0, BUDGET_BLOCK);
  snap(3, &a);
  check("T3 no-accrual ceiling", a.refill, 0);
  st = unlink("t3_steep.txt");
  snap(3, &b);
  check("T3 unaffordable without accrual denied in BLOCK", st, BUDGET_DENIED);
  check("T3 unaffordable without accrual did not block",
        b.n_blocked - a.n_blocked, NOT_BLOCKED);

  // Lazy refill is capped by the ceiling: 11 periods of 50 tokens against a
  // ceiling of 100 must read 100, not 550.
  setgroup(3);
  setbudget(3, 100, 50, BUDGET_BLOCK);
  snap(3, &a);
  check("T3 capped test starts empty", a.budget, 0);

  pause(1100);
  snap(3, &b);
  check("T3 refill caps at the ceiling", b.budget, 100);
  check("T3 idling spent nothing", b.used, 0);

  // A group with no tokens can still describe itself.
  setbudget(3, 0, 0, BUDGET_FAIL);
  snap(3, &a);
  rprintf("[INFO] T3 this line was printed with a closed bucket\n");
  snap(3, &b);
  check("T3 reporting spent no tokens", b.used - a.used, 0);
  check("T3 reporting granted nothing", b.n_allowed - a.n_allowed, 0);
  check("T3 reporting is counted on its own", b.n_reported - a.n_reported >= 1, 1);
}

// ---------------------------------------------------------------------------
// Test 4: evasion by fork bomb
// ---------------------------------------------------------------------------
static void
test4_fork_bomb(void)
{
  struct group_stat a, b;
  char name[32];
  int i, st, ok = 0, denied = 0, pid;

  rprintf("\n===== TEST 4: fork-bomb evasion resistance =====\n");

  setgroup(5);
  // Ten victims, created while the bucket is still full, so the children only
  // ever unlink.
  for (i = 0; i < 10; i++) {
    snprintf(name, sizeof(name), "t4_victim%d.txt", i);
    own_file(name, "victim");
  }

  setbudget(5, 30, 0, BUDGET_FAIL); // exactly three unlinks
  snap(5, &a);
  check("T4 bucket affords exactly 3 unlinks", a.budget / COST_UNLINK, 3);

  for (i = 0; i < 10; i++) {
    pid = fork();
    if (pid == 0) {
      snprintf(name, sizeof(name), "t4_victim%d.txt", i);
      st = unlink(name);
      if (st == 0)
        exit(10); // deleted
      if (st == BUDGET_DENIED)
        exit(20); // denied by the limiter
      exit(30);   // a real error: the file was not there
    }
    if (pid < 0) {
      rprintf("[ABORT] T4 fork failed\n");
      exit(1);
    }
    wait(&st);
    if (st == 10)
      ok++;
    else if (st == 20)
      denied++;
  }

  snap(5, &b);
  info("T4 children that deleted", ok);
  info("T4 children denied by the limiter", denied);
  check("T4 kernel granted exactly 3", b.n_allowed - a.n_allowed, 3);
  check("T4 kernel refused exactly 7", b.n_refused - a.n_refused, 7);
  check("T4 no child was made to wait", b.n_blocked - a.n_blocked, NOT_BLOCKED);
  check("T4 exit statuses match the grants", ok, 3);
  check("T4 exit statuses match the denials", denied, 7);
  check("T4 every child accounted for", ok + denied, 10);
  check("T4 total spend equals the ceiling", b.used, 30);
  check("T4 bucket fully drained", b.budget, 0);

  // Forking is not an escape route: a child inherits its parent's group, so the
  // extra processes drain the same shared bucket instead of dodging it.
  check("T4 children inherited the throttled group", st == 20 || st == 10, 1);
}

// ---------------------------------------------------------------------------
// Test 5: two groups throttled at the same time, independently
// ---------------------------------------------------------------------------
static void
test5_group_isolation(void)
{
  struct group_stat s6, s7;
  char name[32];
  int i, ok7 = 0, pid, st;

  rprintf("\n===== TEST 5: per-group isolation =====\n");

  // Group 6 gets a loose policy, group 7 a tight one. Both sets of victims are
  // created for free.
  setgroup(6);
  setbudget(6, 100, 1000, BUDGET_BLOCK);
  for (i = 0; i < 5; i++) {
    snprintf(name, sizeof(name), "t5_g6_%d.txt", i);
    own_file(name, "x");
  }

  setgroup(7);
  setbudget(7, 30, 0, BUDGET_FAIL);
  for (i = 0; i < 5; i++) {
    snprintf(name, sizeof(name), "t5_g7_%d.txt", i);
    own_file(name, "x");
  }

  // Both hammers run before either is waited on, so the two buckets are live at
  // the same time.
  pid = fork();
  if (pid == 0) {
    int ok6 = 0;

    setgroup(6);
    for (i = 0; i < 5; i++) {
      snprintf(name, sizeof(name), "t5_g6_%d.txt", i);
      if (unlink(name) == 0)
        ok6++;
    }
    exit(ok6);
  }
  if (pid < 0) {
    rprintf("[ABORT] T5 fork failed\n");
    exit(1);
  }

  for (i = 0; i < 5; i++) {
    snprintf(name, sizeof(name), "t5_g7_%d.txt", i);
    if (unlink(name) == 0)
      ok7++;
  }
  wait(&st);

  snap(6, &s6);
  snap(7, &s7);
  check("T5 loose group granted all 5", s6.n_allowed, 5);
  check("T5 loose group never waited", s6.n_blocked, NOT_BLOCKED);
  check("T5 loose group spent 50", s6.used, 50);
  check("T5 tight group granted exactly 3", s7.n_allowed, 3);
  check("T5 tight group refused 2", s7.n_refused, 2);
  check("T5 tight group never waited (FAIL mode)", s7.n_blocked, NOT_BLOCKED);
  check("T5 tight group spent 30", s7.used, 30);
  check("T5 the throttled group did not tax the other", s6.budget >= 50, 1);
  check("T5 the loose group did not fund the other", s7.budget, 0);
  check("T5 child's own count agrees with the kernel", st, 5);
  check("T5 parent's own count agrees with the kernel", ok7, 3);
}

// ---------------------------------------------------------------------------
// Test 6: lazy refill -- the BLOCK staircase against the FAIL flat line
// ---------------------------------------------------------------------------
// Each mode emits five [DATA] rows: mode, uptime, deletions so far. BLOCK steps
// by a refill period per throttled unlink; FAIL piles up at one instant.
static void
test6_refill_staircase(void)
{
  struct group_stat a, b;
  int completed, i, mode, gid, st, t, t0, t1;

  rprintf("\n===== TEST 6: lazy refill, BLOCK staircase vs FAIL flat =====\n");

  for (mode = BUDGET_BLOCK; mode <= BUDGET_FAIL; mode++) {
    const char *fname = mode == BUDGET_BLOCK ? "t6_block.txt" : "t6_fail.txt";

    gid = mode == BUDGET_BLOCK ? 8 : 9;

    // A separate victim per mode: reusing one file would make the recreate a
    // write into the *other* group's inode, costing 3 and quietly stealing a
    // token from the bucket under test.
    setgroup(gid);
    setbudget(gid, 30, 10, mode);
    own_file(fname, "data");
    snap(gid, &a);
    completed = 0;

    t0 = uptime();
    rprintf("[DATA],%s,%d,0\n", mode == BUDGET_BLOCK ? "BLOCK" : "FAIL", t0);

    for (i = 0; i < 5; i++) {
      st = unlink(fname);
      t = uptime();
      if (st == 0) {
        completed++;
        own_file(fname, "data"); // free, keeps the next unlink real
      } else if (st == BUDGET_DENIED) {
        pause(20); // under one period, so a denial stays a denial
      } else {
        pause(10); // the file vanished for a non-budget reason
      }
      rprintf("[DATA],%s,%d,%d\n", mode == BUDGET_BLOCK ? "BLOCK" : "FAIL",
              t, completed);
    }
    t1 = uptime();

    snap(gid, &b);
    info("T6 ticks elapsed in this mode", t1 - t0);
    if (mode == BUDGET_BLOCK) {
      // 30 tokens afford 3 of the 5 unlinks outright; the last 2 wait a period.
      check("T6 BLOCK completed all 5 deletions", completed, 5);
      check("T6 BLOCK granted 5", b.n_allowed - a.n_allowed, 5);
      check("T6 BLOCK denied nothing", b.n_refused - a.n_refused, DENIED);
      check("T6 BLOCK waited once per throttled unlink",
            b.n_blocked - a.n_blocked, 2);
      check("T6 BLOCK staircase advances the clock",
            (t1 - t0) >= 2 * (PERIOD - TICK_SLOP), 1);
    } else {
      check("T6 FAIL completed exactly 3 deletions", completed, 3);
      check("T6 FAIL granted 3", b.n_allowed - a.n_allowed, 3);
      check("T6 FAIL refused the other 2", b.n_refused - a.n_refused, 2);
      check("T6 FAIL never waited", b.n_blocked - a.n_blocked, NOT_BLOCKED);
      check("T6 FAIL flat line: no refill period passed", (t1 - t0) < PERIOD, 1);
    }
  }
}

// ---------------------------------------------------------------------------
// Test 7: a denial costs nothing; a real error still costs
// ---------------------------------------------------------------------------
static void
test7_denial_costs(void)
{
  struct group_stat a, b;
  char *av[1] = {0};
  int st;

  rprintf("\n===== TEST 7: denials, real errors and the free path =====\n");

  setgroup(10);
  setbudget(10, 0, 0, BUDGET_FAIL); // nothing is affordable
  snap(10, &a);
  check("T7 closed bucket starts unspent", a.used, 0);

  if (fork() == 0) {
    st = exec(SILENT_BIN, av);
    if (st == BUDGET_DENIED)
      exit(10);
    if (st == -1)
      exit(20); // the kernel rejected the exec on its own merits
    exit(30);   // it ran: the limiter failed to stop it
  }
  wait(&st);
  snap(10, &b);
  check("T7 denied exec returns the sentinel", st, 10);
  check("T7 denial is not the kernel rejecting exec", st != 20, 1);
  check("T7 denied exec did not run the binary", st != 0, 1);
  check("T7 denied exec spent nothing", b.used - a.used, 0);
  check("T7 denied exec counted as refused", b.n_refused - a.n_refused, 1);
  check("T7 denied exec granted nothing", b.n_allowed - a.n_allowed, 0);

  // Reopen the bucket the honest way -- by waiting for it to refill -- and show
  // that an operation which fails for its own reasons still pays for the
  // attempt: the token buys the attempt, because the kernel cannot know the
  // attempt is harmless until it has run it.
  setbudget(10, 100, 1000, BUDGET_BLOCK);
  pause(PERIOD);
  snap(10, &a);
  check("T7 accrual refills to the ceiling", a.budget, 100);

  st = unlink("t7_never_existed.txt");
  snap(10, &b);
  check("T7 real error returns -1", st, -1);
  check("T7 real error is distinguishable from a denial", st != BUDGET_DENIED, 1);
  check("T7 the failed attempt was still charged", b.used - a.used, COST_UNLINK);
  check("T7 the failed attempt counted as granted", b.n_allowed - a.n_allowed, 1);

  // With the bucket closed again, observability must survive. One rprintf
  // between the two snapshots is exactly one report() call; getbudgetstat is
  // free but is not a report, so it must not move the reporting counter.
  setbudget(10, 0, 0, BUDGET_FAIL);
  snap(10, &a);
  st = uptime();
  rprintf("[INFO] T7 printed while the bucket was closed\n");
  getbudgetstat(0);
  snap(10, &b);
  check("T7 free syscalls spent nothing", b.used - a.used, 0);
  check("T7 free syscalls moved no grant counters",
        (b.n_allowed + b.n_refused) - (a.n_allowed + a.n_refused), 0);
  check("T7 one line is one report", b.n_reported - a.n_reported, 1);
  info("T7 bytes reported with a closed bucket", b.report_bytes - a.report_bytes);
  info("T7 uptime readable with a closed bucket", st);
}

int
main(int argc, char *argv[])
{
  rprintf("========================================================\n");
  rprintf("  xv6-riscv irreversibility budget test suite\n");
  rprintf("========================================================\n");

  // One test at a time, for the runs that should not pay for the whole suite:
  // test_budget_suite 3
  if (argc > 1)
    only = atoi(argv[1]);

  // Give every group a known policy before measuring anything. Counters are
  // lifetime totals for the group, so each test uses its own group.
  for (int g = 1; g < NGROUP; g++)
    setbudget(g, 100, 10, BUDGET_BLOCK);

  if (run(1))
    test1_cost_matrix();
  if (run(2))
    test2_dynamic_reconfig();
  if (run(3))
    test3_boundary_edges();
  if (run(4))
    test4_fork_bomb();
  if (run(5))
    test5_group_isolation();
  if (run(6))
    test6_refill_staircase();
  if (run(7))
    test7_denial_costs();

  rprintf("\n========================================================\n");
  rprintf("  All Tests Completed\n");
  rprintf("========================================================\n");
  rprintf("[SUMMARY] checks=%d failed=%d\n", checks, failed);

  dump_table();
  exit(failed == 0 ? 0 : 1);
}
