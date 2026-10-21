//
// scenarios.c - shaped workloads for the irreversibility budget.
//
// This program asserts nothing. It runs workloads - an rm -rf that drains its
// group, a chatty logger, a build that execs another group's compiler, a
// fan-out of children racing for one bucket, an accrual timeline, a boundary
// grid over every cost class, and a set of invalid inputs - and emits a
// machine-readable trace of each operation together with the kernel's policy
// and the counter deltas across it.
//
// The expectations live OUTSIDE this program, in budget_oracle.py, which
// re-implements the token-bucket rules independently and diffs its predictions
// against what the kernel reports. A test that derives its own expectations
// from the code under test proves nothing: here the guest produces data, the
// host produces expectations, and agreement is the result.
//
// Prices come from budgetinfo(), the kernel's own published table, so a
// scenario never hardcodes a number it is meant to be testing. Trace lines go
// out through rprintf(), which is counted but never charged; the exception is
// the console-write operations, which pay because they ARE the thing under
// test. Charged output can land in the middle of the trace, so a parser must
// ignore leading noise before a record's opening bracket.
//
// Trace grammar:
//
//   [PARAMS],<kernel constants>       the cost table as the kernel sees it
//   [SCN],id,name,gid=,max=,refill=,  one scenario begins; budget= is the
//        mode=,budget=,ops=,atomic=   tokens available before its first op
//   [OP],id,i,kind,bb=,exp=,res=,     one operation, with the bucket state
//        da=,db=,dr=,du=,t=           before it and every delta across it
//   [DATA],id,t,granted               cumulative grants, for the staircase
//   [RES],id,allowed=,blocked=,       scenario totals, as deltas from its
//        refused=,used=,budget=,      own starting snapshot
//        granted=
//   [FAN],id,kid,rc=,bb=              one fan-out child's own result
//   [EDGE],name,<fields>              an input the engine must reject
//   [DONE]                            the trace is complete
//
// res codes: 0 = the syscall ran, 1 = refused by the budget (it returned the
// BUDGET_DENIED sentinel), 2 = it failed on its own merits, 3 = free syscall
// that never reaches the bucket.
//
#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/fcntl.h"
#include "kernel/budget.h"
#include "user/user.h"

#define COPY_CHUNK 2048
#define SILENT_BIN "/sync" // mkfs strips the leading underscore
#define NKIDS 12

// Groups that own staged artefacts, so "own" and "foreign" mean the same thing
// in every scenario: an exec class always runs in the group that owns (or does
// not own) the staged binary, and cross-group victims belong to FOREIGN_GID.
#define FOREIGN_GID 14
#define OWNEXEC_GID 13
#define OWN_BIN  "/sobin"   // owned by OWNEXEC_GID: exec of it is free
#define FOREIGN_BIN "/sfbin" // owned by FOREIGN_GID: exec of it is priced

// Operation classes. The name written into the trace is what the oracle prices,
// through the kernel's published table - never through a literal here.
enum {
  K_UNLINK,        // unlink a file this group owns
  K_CONSOLE,       // write(1, ".", 1): charged, and visible on the console
  K_OWNWRITE,      // write to a file this group owns
  K_FOREIGNWRITE,  // write to a file another group owns
  K_FOREIGNEXEC,   // exec a binary another group wrote
  K_OWNEXEC,       // exec a binary this group wrote
  K_PIPE,          // write to a pipe
  K_REPORT,        // the free reporting path
  K_IDLE           // pause(): free, and lets refill periods elapse
};

// One class repeated n times inside a scenario.
struct step {
  int kind;
  int n;
};

#define NSTEP(a) ((int)(sizeof(a) / sizeof((a)[0])))

static struct budget_params P;
static struct group_stat gstart; // fan-out: snapshot before the children ran
static int vseq;                 // unique victim names
static int fanchild;             // nonzero inside a fan-out child: no [OP] lines

static int
cost_of(int kind)
{
  switch (kind) {
    case K_UNLINK:        return P.cost_unlink;
    case K_CONSOLE:       return P.cost_console_write;
    case K_OWNWRITE:      return P.cost_own_write;
    case K_FOREIGNWRITE:  return P.cost_foreign_write;
    case K_FOREIGNEXEC:   return P.cost_foreign_exec;
    case K_OWNEXEC:       return P.cost_own_exec;
    case K_PIPE:          return P.cost_pipe_write;
    default:              return 0;
  }
}

static const char *
kind_name(int kind)
{
  switch (kind) {
    case K_UNLINK:        return "unlink";
    case K_CONSOLE:       return "console";
    case K_OWNWRITE:      return "ownwrite";
    case K_FOREIGNWRITE:  return "foreignwrite";
    case K_FOREIGNEXEC:   return "foreignexec";
    case K_OWNEXEC:       return "ownexec";
    case K_PIPE:          return "pipe";
    case K_REPORT:        return "report";
    default:              return "idle";
  }
}

// Which class the process running this scenario must belong to. The exec
// classes are pinned to the groups that own the staged binaries, because the
// price of an exec is decided by who wrote the image.
static int
gid_for(int kind, int gid)
{
  return kind == K_OWNEXEC ? OWNEXEC_GID : gid;
}

static void
stats_of(int gid, struct group_stat *out)
{
  struct group_stat all[NGROUP];

  if (getbudgetstat(all) < 0) {
    rprintf("[ABORT] getbudgetstat failed\n");
    exit(1);
  }
  *out = all[gid];
}

static void
own_file(const char *name, const char *content)
{
  int fd = open(name, O_CREATE | O_WRONLY);

  if (fd < 0) {
    rprintf("[ABORT] cannot create %s\n", name);
    exit(1);
  }
  write(fd, content, strlen(content));
  close(fd);
}

// Copy src to dst as the calling group. read() is free and writing to a file
// this group owns costs 0, so staging work never touches the bucket under test.
static void
copy_as_own(const char *src, const char *dst)
{
  char buf[COPY_CHUNK];
  int in = open(src, O_RDONLY);
  int out = open(dst, O_CREATE | O_WRONLY);
  int n;

  if (in < 0 || out < 0) {
    rprintf("[ABORT] cannot copy %s\n", src);
    exit(1);
  }
  while ((n = read(in, buf, sizeof(buf))) > 0)
    write(out, buf, n);
  close(in);
  close(out);
}

// Create name, owned by fgid. Group identity is per process, so this runs in a
// child; everything the child does is either free or an own-group write, so it
// never spends the budget of the group under test.
static void
make_foreign(const char *name, const char *src, int fgid)
{
  int pid = fork();

  if (pid == 0) {
    setgroup(fgid);
    if (src)
      copy_as_own(src, name);
    else
      own_file(name, "x");
    exit(0);
  }
  if (pid < 0) {
    rprintf("[ABORT] fork failed\n");
    exit(1);
  }
  wait(0);
}

// The two executables the exec scenarios run. Both are copies of /sync, which
// prints nothing, so a granted exec costs exactly its own price and leaves no
// output behind. Staged once each, by the group that is meant to own it.
static void
stage_bins(void)
{
  make_foreign(OWN_BIN, SILENT_BIN, OWNEXEC_GID);
  make_foreign(FOREIGN_BIN, SILENT_BIN, FOREIGN_GID);
}

// The path this class executes, if it executes anything.
static const char *
bin_of(int kind)
{
  if (kind == K_FOREIGNEXEC)
    return FOREIGN_BIN;
  if (kind == K_OWNEXEC)
    return OWN_BIN;
  return 0;
}

// Does this class need a file staged before the bucket can decide anything?
// The exec classes are staged once for the whole run, so they answer no.
static int
needs_victim(int kind)
{
  return kind == K_UNLINK || kind == K_OWNWRITE || kind == K_FOREIGNWRITE;
}

// ---------------------------------------------------------------------------
// one operation of one class
// ---------------------------------------------------------------------------
static int
do_op(int kind, const char *fname)
{
  int st, fd, pfd[2];
  char one = '.';

  switch (kind) {
    case K_UNLINK:
      st = unlink(fname);
      if (st == 0) {
        // Put the victim back, free, so the next attempt is a real unlink and
        // not an ENOENT dressed up as a decision.
        own_file(fname, "x");
        return 0;
      }
      return st == BUDGET_DENIED ? 1 : 2;
    case K_CONSOLE:
      st = (int)write(1, &one, 1);
      return st > 0 ? 0 : (st == BUDGET_DENIED ? 1 : 2);
    case K_OWNWRITE:
    case K_FOREIGNWRITE:
      fd = open(fname, O_WRONLY);
      if (fd < 0)
        return 2;
      st = (int)write(fd, &one, 1);
      close(fd);
      return st > 0 ? 0 : (st == BUDGET_DENIED ? 1 : 2);
    case K_FOREIGNEXEC:
    case K_OWNEXEC: {
      // exec replaces the process, so the attempt happens in a child and its
      // outcome comes back as that child's exit status.
      int pid = fork();
      int status;
      const char *bin = bin_of(kind);

      if (pid == 0) {
        char *av[1] = { 0 };

        st = exec(bin, av);
        if (st == BUDGET_DENIED)
          exit(11);
        if (st < 0)
          exit(12);
        exit(0); // the silent binary ran and finished
      }
      if (pid < 0)
        return 2;
      wait(&status);
      if (status == 11)
        return 1;
      return status == 0 ? 0 : 2;
    }
    case K_PIPE:
      if (pipe(pfd) < 0)
        return 2;
      st = (int)write(pfd[1], &one, 1);
      read(pfd[0], &one, 1);
      close(pfd[0]);
      close(pfd[1]);
      return st > 0 ? 0 : (st == BUDGET_DENIED ? 1 : 2);
    case K_REPORT:
      report("x", 1); // one report(): counted, never charged
      return 3;
    default:
      pause(P.period);
      return 3;
  }
}

// Stage the victim one step needs. Cross-group victims are made by a child in
// FOREIGN_GID; own victims are created by this process, which is already in the
// scenario's group.
static void
prepare(int kind, const char *fname)
{
  if (!needs_victim(kind))
    return;
  if (kind == K_FOREIGNWRITE)
    make_foreign(fname, 0, FOREIGN_GID);
  else
    own_file(fname, "x");
}

// Fill a group's bucket to its ceiling before measuring it. setbudget()
// deliberately never tops up - raising a ceiling must not hand out free tokens
// - so a scenario that wants a known full bucket has to wait for one period of
// the accrual it is allowed. That is about ten seconds of wall clock here, so
// it is only done when the bucket is not already known: a group that has never
// spent starts at the default budget, and clamping that down to a ceiling at
// or below the default lands exactly on the ceiling. fill= in the trace says
// which of the two routes a scenario took, so the oracle can check both.
static int spent[NGROUP]; // groups that have already paid, so their bucket is stale

static void
top_up(int gid, int max)
{
  struct group_stat s;

  setgroup(gid);
  setbudget(gid, max, max > 0 ? max : 1, BUDGET_BLOCK);
  pause(P.period + 2);
  setbudget(gid, max, 0, BUDGET_BLOCK); // real ceiling already reached
  stats_of(gid, &s);
  if (s.budget != s.max)
    rprintf("[WARN],top_up,gid=%d,budget=%d,max=%d\n", gid, s.budget, s.max);
}

// ---------------------------------------------------------------------------
// one scenario: a policy plus a sequence of steps, traced operation by
// operation.
//
// atomic=1 means this process is the only one spending, so the oracle can
// compare the kernel's decision for EVERY op against its own model. atomic=0
// marks concurrent workloads, where only the aggregate is meaningful.
//
// install=1 writes the policy before measuring it, which needs policy
// authority. install=0 is the confinement path: the policy is already in force,
// this process may not touch it, and max/refill/mode/budget are read back from
// the kernel instead of asked for. Tracing the same loop both ways is the point
// - the oracle gets to grade a confined group's charges with exactly the same
// model it uses for a controller's.
// ---------------------------------------------------------------------------
static void
scenario_run(const char *id, const char *name, int gid, int max, int refill,
             int mode, const struct step *steps, int nsteps, int atomic, int fill,
             int install)
{
  struct group_stat a, b, pre, start;
  char fname[32];
  const char *how = "inherited";
  int s, i, k, res, granted = 0, total = 0;

  for (s = 0; s < nsteps; s++)
    total += steps[s].n;

  if (install) {
    setgroup(gid);
    if (!fill)
      how = "as-is";
    else if (max == 0 || (!spent[gid] && max <= P.default_max))
      how = "clamp"; // the ceiling clamps a full - or empty - bucket onto itself
    else {
      top_up(gid, max);
      how = "wait";
    }
    if (setbudget(gid, max, refill, mode) < 0) {
      rprintf("[ABORT] setbudget(%d,%d,%d,%d) failed\n", gid, max, refill, mode);
      exit(1);
    }
  }
  stats_of(gid, &start);
  a = start;

  if (!fanchild)
    rprintf("[SCN],%s,%s,gid=%d,max=%d,refill=%d,mode=%d,budget=%d,ops=%d,"
            "atomic=%d,fill=%s\n", id, name, gid, start.max, start.refill,
            start.mode, start.budget, total, atomic, how);

  k = 0;
  for (s = 0; s < nsteps; s++) {
    if (gid_for(steps[s].kind, gid) != gid) {
      rprintf("[ABORT],%s,kind=%s needs gid=%d\n", id,
              kind_name(steps[s].kind), gid_for(steps[s].kind, gid));
      exit(1);
    }
    snprintf(fname, sizeof(fname), "sv%d", vseq++);
    prepare(steps[s].kind, fname);

    for (i = 0; i < steps[s].n; i++) {
      stats_of(gid, &pre);
      res = do_op(steps[s].kind, fname);
      stats_of(gid, &b);
      if (res == 0 || res == 3)
        granted++;
      if (!fanchild) {
        rprintf("[OP],%s,%d,%s,bb=%d,exp=%d,res=%d,da=%d,db=%d,dr=%d,du=%d,t=%d\n",
                id, k, kind_name(steps[s].kind), pre.budget,
                cost_of(steps[s].kind), res, b.n_allowed - a.n_allowed,
                b.n_blocked - a.n_blocked, b.n_refused - a.n_refused,
                b.used - a.used, uptime());
        rprintf("[DATA],%s,%d,%d\n", id, uptime(), granted);
        k++;
      }
      a = b;
    }
  }

  stats_of(gid, &b);
  if (!fanchild)
    rprintf("[RES],%s,allowed=%d,blocked=%d,refused=%d,used=%d,budget=%d,"
            "granted=%d\n", id, b.n_allowed - start.n_allowed,
            b.n_blocked - start.n_blocked, b.n_refused - start.n_refused,
            b.used - start.used, b.budget, granted);
  spent[gid] = 1;
  if (install)
    setgroup(0);
}

static void
scenario(const char *id, const char *name, int gid, int max, int refill,
         int mode, const struct step *steps, int nsteps, int atomic, int fill)
{
  scenario_run(id, name, gid, max, refill, mode, steps, nsteps, atomic, fill, 1);
}

// A child of the fan-out: one unlink, reported by the child itself so a denied
// sibling cannot hide it.
static void
fan_kid(const char *id, int gid, int kid, const char *fname)
{
  struct group_stat pre;
  int st;

  setgroup(gid);
  stats_of(gid, &pre);
  st = unlink(fname);
  rprintf("[FAN],%s,%d,rc=%d,bb=%d\n", id, kid,
          st == 0 ? 0 : (st == BUDGET_DENIED ? 1 : 2), pre.budget);
  exit(st == 0 ? 0 : (st == BUDGET_DENIED ? 1 : 2));
}

// N children, one bucket, one unlink each. With refill 0 the aggregate is
// closed-form however the children interleave: a granted unlink always takes
// exactly cost_unlink out of the bucket, so grants cannot exceed
// floor(max / cost) and the bucket can never go below zero.
static void
fan_out(const char *id, int gid, int max, int nkids)
{
  struct group_stat b;
  char fname[32];
  char nm[40];
  const char *how;
  int i, pid, status, denied = 0, ran = 0, err = 0, alive = nkids;

  snprintf(fname, sizeof(fname), "sv%d", vseq++);
  setgroup(gid);
  if (!spent[gid] && max <= P.default_max)
    how = "clamp";
  else {
    top_up(gid, max);
    how = "wait";
  }
  if (setbudget(gid, max, 0, BUDGET_FAIL) < 0) {
    rprintf("[ABORT] fan setbudget failed\n");
    exit(1);
  }
  // One victim per child, created here while the bucket is full and creating is
  // free. The children must not create their own victims: that would let the
  // ordering of setup decide how many unlinks succeed.
  for (i = 0; i < nkids; i++) {
    snprintf(nm, sizeof(nm), "%s%d", fname, i);
    own_file(nm, "x");
  }
  stats_of(gid, &gstart);
  setgroup(0);

  rprintf("[SCN],%s,fan-out,gid=%d,max=%d,refill=%d,mode=%d,budget=%d,ops=%d,"
          "atomic=0,fill=%s\n", id, gid, gstart.max, gstart.refill, gstart.mode,
          gstart.budget, nkids, how);

  for (i = 0; i < nkids; i++) {
    snprintf(nm, sizeof(nm), "%s%d", fname, i);
    pid = fork();
    if (pid == 0) {
      fanchild = 1;
      fan_kid(id, gid, i, nm);
    }
    if (pid < 0) {
      rprintf("[ABORT] fan fork failed\n");
      exit(1);
    }
  }
  while (alive > 0) {
    status = -1;
    pid = wait(&status);
    if (pid <= 0)
      break;
    alive--;
    if (status == 0)
      ran++;
    else if (status == 1)
      denied++;
    else
      err++;
  }

  stats_of(gid, &b);
  rprintf("[RES],%s,allowed=%d,blocked=%d,refused=%d,used=%d,budget=%d,"
          "granted=%d,rc_deny=%d,rc_err=%d\n",
          id, b.n_allowed - gstart.n_allowed, b.n_blocked - gstart.n_blocked,
          b.n_refused - gstart.n_refused, b.used - gstart.used, b.budget, ran,
          denied, err);
  spent[gid] = 1;
  setgroup(0);
}

// ---------------------------------------------------------------------------
// scenario groups
//
// Groups 2..12 and 15 host scenarios; 13 and 14 own the staged binaries, and
// gid 1 is reserved for the invalid-input checks. 16 and 17 are reserved by
// kernel/budget.h for the confinement group and its rich decoy, and 18 belongs
// to upstream usertests - they are not free for a new scenario to grab, because
// a confinement test that shares a group with the thing it is confining proves
// nothing. gid 0 is the shell's own group and is never reconfigured: throttling
// it would throttle the console that reports the results.
// ---------------------------------------------------------------------------
static void
scn_1_drain(void)
{
  static const struct step five[] = { { K_UNLINK, 5 } };

  // An rm -rf that drains its group. The ceiling is a whole number of prices,
  // or a whole number plus a remainder, so the trace crosses the affordability
  // boundary exactly once and the oracle sees every grant and every refusal
  // after it.
  scenario("B_unlink", "rmrf-FAIL", 2, 3 * P.cost_unlink, 0, BUDGET_FAIL,
           five, NSTEP(five), 1, 1);
  // BLOCK with no accrual: the engine must deny rather than sleep forever.
  scenario("C_unlink", "rmrf-BLOCK-no-refill", 3, 3 * P.cost_unlink + 1, 0,
           BUDGET_BLOCK, five, NSTEP(five), 1, 1);
  // BLOCK where tokens do come back: it waits, then grants.
  scenario("D_unlink", "rmrf-BLOCK-refill", 4, 2 * P.cost_unlink,
           P.cost_unlink, BUDGET_BLOCK, five, NSTEP(five), 1, 1);
}

static void
scn_2_logger(void)
{
  static const struct step many[] = { { K_CONSOLE, 20 } };
  static const struct step eight[] = { { K_CONSOLE, 8 } };

  // A chatty logger: every character is a charged console write, so it pays for
  // its own output and runs out mid-conversation.
  scenario("B_console", "logger-FAIL", 5, 12, 0, BUDGET_FAIL, many, NSTEP(many), 1, 1);
  // Two ops more than the bucket holds: each of the last two waits a period for
  // its single token, which is what makes the staircase step.
  scenario("C_console", "logger-BLOCK", 6, 6, P.cost_console_write,
           BUDGET_BLOCK, eight, NSTEP(eight), 1, 1);
}

static void
scn_3_own_work_is_free(void)
{
  static const struct step s[] = { { K_OWNWRITE, 8 }, { K_PIPE, 8 },
                                   { K_REPORT, 8 }, { K_OWNEXEC, 4 } };

  // Own-group work must never reach the bucket, even with the budget shut.
  scenario("B_own", "own-work", OWNEXEC_GID, 0, 0, BUDGET_FAIL, s, NSTEP(s), 1, 0);
}

static void
scn_4_cross_group(void)
{
  static const struct step four[] = { { K_FOREIGNWRITE, 4 } };
  static const struct step xfour[] = { { K_FOREIGNEXEC, 4 } };
  static const struct step xthree[] = { { K_FOREIGNEXEC, 3 } };

  // The build that writes into a tree another group owns and execs another
  // group's compiler.
  scenario("B_fwrite", "foreign-write", 8, 3 * P.cost_foreign_write, 0,
           BUDGET_FAIL, four, NSTEP(four), 1, 1);
  scenario("B_fexec", "foreign-exec", 9, 2 * P.cost_foreign_exec, 0,
           BUDGET_FAIL, xfour, NSTEP(xfour), 1, 1);
  // A ceiling below the price: BLOCK has nothing to wait for, so the engine
  // must refuse instead of hanging.
  scenario("C_fexec", "foreign-exec-ceiling-below-price", 9,
           P.cost_foreign_exec - 1, 0, BUDGET_BLOCK, xthree, NSTEP(xthree), 1, 0);
}

static void
scn_5_timing(void)
{
  static const struct step five[] = { { K_UNLINK, 5 } };
  static const struct step timeline[] = { { K_UNLINK, 2 }, { K_IDLE, 1 },
                                          { K_UNLINK, 1 }, { K_IDLE, 1 },
                                          { K_UNLINK, 3 } };

  // The staircase the lab asks for, the same workload held flat by FAIL, and a
  // drain-wait-grant timeline that shows where the tokens come back.
  //
  // K_flat keeps refill 0 on purpose: a denial in FAIL mode returns instantly,
  // so with no accrual the flat line is the shape of the policy rather than an
  // accident of scheduling. K_stair is the same ceiling with accrual turned on
  // and BLOCK waits, which is what makes it step.
  scenario("K_stair", "staircase", 10, 30, P.cost_unlink, BUDGET_BLOCK,
           five, NSTEP(five), 1, 1);
  scenario("K_flat", "flat", 11, 30, 0, BUDGET_FAIL, five, NSTEP(five), 1, 1);
  // One unlink per period: after a full drain the idle steps decide whether the
  // next op is affordable, so the accrual arithmetic becomes observable.
  scenario("K_accrue", "drain-wait-grant", 11, 2 * P.cost_unlink,
           P.cost_unlink, BUDGET_FAIL, timeline, NSTEP(timeline), 1, 1);
}

static void
scn_6_fanout(void)
{
  // Twelve children, one bucket sized for five of them.
  fan_out("X_fanout", 12, 5 * P.cost_unlink, NKIDS);
}

// Every cost class against a ceiling that straddles its own price, in both
// modes. Three operations from a full bucket cover the interesting cases:
// clearly affordable, affordable with the bucket landing exactly on zero, and
// the refusal after that.
static void
scn_7_grid(void)
{
  static const int kinds[] = { K_UNLINK, K_CONSOLE, K_FOREIGNWRITE,
                               K_FOREIGNEXEC, K_OWNWRITE, K_OWNEXEC, K_PIPE };
  struct step st;
  char id[40];
  int c, m, cost;

  st.n = 3;
  for (c = 0; c < (int)(sizeof(kinds) / sizeof(kinds[0])); c++) {
    st.kind = kinds[c];
    cost = cost_of(st.kind);
    for (m = 0; m < 2; m++) {
      snprintf(id, sizeof(id), "G_%s_%s", kind_name(st.kind),
               m == BUDGET_BLOCK ? "BLOCK" : "FAIL");
      scenario(id, "grid", gid_for(st.kind, 15), cost > 0 ? 2 * cost : 0, 0, m,
               &st, 1, 1, 1);
    }
  }
}

// Inputs the engine must reject, and the check that a rejection really left the
// group alone. A limiter that mis-parses its own settings is worse than one
// with no settings at all.
static void
scn_8_inputs(void)
{
  struct group_stat a, b;
  int rc;

  stats_of(1, &a);
  rc = setbudget(-1, 10, 0, BUDGET_FAIL);
  rprintf("[EDGE],setbudget_gid_negative,rc=%d\n", rc);
  rc = setbudget(NGROUP, 10, 0, BUDGET_FAIL);
  rprintf("[EDGE],setbudget_gid_out_of_range,rc=%d\n", rc);
  rc = setbudget(1, -1, 0, BUDGET_FAIL);
  rprintf("[EDGE],setbudget_max_negative,rc=%d\n", rc);
  rc = setbudget(1, 10, -1, BUDGET_FAIL);
  rprintf("[EDGE],setbudget_refill_negative,rc=%d\n", rc);
  rc = setbudget(1, 10, 0, 7);
  rprintf("[EDGE],setbudget_mode_unknown,rc=%d\n", rc);
  stats_of(1, &b);
  rprintf("[EDGE],after_rejects,max=%d,refill=%d,mode=%d,budget=%d,used=%d,"
          "moved=%d\n", b.max, b.refill, b.mode, b.budget, b.used,
          b.max != a.max || b.refill != a.refill || b.mode != a.mode ||
          b.budget != a.budget);

  // The validator is not simply refusing everything: one good call lands.
  rc = setbudget(1, 11, 2, BUDGET_FAIL);
  stats_of(1, &b);
  rprintf("[EDGE],accept_good,rc=%d,max=%d,refill=%d,mode=%d,used=%d\n", rc,
          b.max, b.refill, b.mode, b.used);

  rc = setgroup(-1);
  rprintf("[EDGE],setgroup_negative,rc=%d\n", rc);
  rc = setgroup(NGROUP);
  rprintf("[EDGE],setgroup_out_of_range,rc=%d\n", rc);
  stats_of(0, &b);
  rprintf("[EDGE],shell_group_untouched,max=%d,refill=%d,mode=%d\n", b.max,
          b.refill, b.mode);

  rc = budgetinfo(0);
  rprintf("[EDGE],budgetinfo_bad_address,rc=%d\n", rc);
  rc = getbudgetstat(0);
  rprintf("[EDGE],getbudgetstat_bad_address,rc=%d\n", rc);
  setgroup(0);
}

// Confinement: the authority rule, and what a process that tries to escape its
// own limits actually gets back.
//
// A controller - this process, which descends from init and has dropped nothing
// - installs a tight policy on the confinement group and a deliberately
// affordable one on the decoy next to it, then forks a child that gives its
// authority up and works through every way out it could think of: raise its own
// ceiling, rewrite the decoy so it could walk in, migrate into the decoy as it
// stands, and drop a second time in case dropping turned out to be a toggle.
// Each attempt is traced and graded against the no-authority sentinel the kernel
// publishes, not against a literal typed here.
//
// The refusals are not the interesting half. After them the child runs an
// ordinary five-unlink workload through the same tracing machinery as every
// other scenario, so the oracle checks with the same model that a confined group
// is still charged normally: a limiter that cannot be legislated but has also
// stopped accounting is a switch, not a budget. And the child's own bucket stays
// readable, because observability is never gated - a group that cannot see the
// limits it is under cannot argue with them.
static void
scn_9_confine(void)
{
  static const struct step five[] = { { K_UNLINK, 5 } };
  struct budget_params q;
  struct group_stat a, b, d;
  int conf = BUDGET_GID_CONFINE, decoy = BUDGET_GID_DECOY;
  int rich = 1000 * P.cost_unlink;
  int pid, status, rc, had;

  // One full bucket - setbudget clamps a never-spent group down onto its new
  // ceiling, so no accrual wait is needed - no refill, FAIL, ceiling of exactly
  // two unlinks.
  setgroup(conf);
  setbudget(conf, 2 * P.cost_unlink, 2 * P.cost_unlink, BUDGET_BLOCK);
  setbudget(conf, 2 * P.cost_unlink, 0, BUDGET_FAIL);
  setgroup(decoy);
  setbudget(decoy, rich, rich, BUDGET_BLOCK);
  setgroup(conf);
  spent[conf] = 1;

  stats_of(conf, &a);
  stats_of(decoy, &d);
  rprintf("[EDGE],confinement_setup,gid=%d,max=%d,refill=%d,mode=%d,budget=%d,"
          "decoy=%d,decoy_max=%d\n", conf, a.max, a.refill, a.mode, a.budget,
          decoy, d.max);

  pid = fork();
  if (pid == 0) {
    had = dropbudgetauth();
    rprintf("[EDGE],confine_drop_first,had=%d\n", had);

    rc = setbudget(conf, rich, rich, BUDGET_BLOCK);
    rprintf("[EDGE],confine_raise_own_ceiling,rc=%d\n", rc);
    rc = setbudget(decoy, 1, 0, BUDGET_FAIL);
    rprintf("[EDGE],confine_rewrite_decoy,rc=%d\n", rc);
    rc = setgroup(decoy);
    rprintf("[EDGE],confine_migrate_to_rich_group,rc=%d\n", rc);
    // An out-of-range gid used to return -1 for anyone who asked. Now the
    // authority gate answers first, because a caller who may not be asking gains
    // nothing from learning which part of its request was malformed.
    rc = setgroup(-1);
    rprintf("[EDGE],confine_bad_gid_still_noauth,rc=%d\n", rc);
    rc = dropbudgetauth();
    rprintf("[EDGE],confine_drop_second,had=1,rc=%d\n", rc);
    rc = setbudget(conf, rich, rich, BUDGET_BLOCK);
    rprintf("[EDGE],confine_policy_after_second_drop,rc=%d\n", rc);

    rc = budgetinfo(&q);
    rprintf("[EDGE],confine_can_read_table,rc=%d,ngroup=%d\n", rc, q.ngroup);
    stats_of(conf, &b);
    rprintf("[EDGE],confine_bucket_visible,rc=0,max=%d,budget=%d\n", b.max,
            b.budget);

    // Confined, but still accounted for: the same five unlinks the controller
    // would have run, traced op by op against the inherited policy.
    scenario_run("C_confine", "confined-work", conf, 0, 0, 0, five, NSTEP(five),
                 1, 0, 0);

    // Authority does not reappear further down the tree.
    int gr;
    int gpid = fork();
    if (gpid == 0) {
      rc = setbudget(conf, rich, 0, BUDGET_FAIL);
      rprintf("[EDGE],confine_grandchild_policy,rc=%d\n", rc);
      gr = setgroup(decoy);
      rprintf("[EDGE],confine_grandchild_migrate,rc=%d\n", gr);
      exit(rc == P.noauth && gr == P.noauth ? 0 : 1);
    }
    wait(&status);
    exit(status == 0 ? 0 : 1);
  }
  wait(&status);
  rprintf("[EDGE],confine_child_status,status=%d\n", status);

  // Nothing the child tried moved a policy. Its WORK moved the bucket and the
  // counters, which is the point - so `moved` compares only the three policy
  // fields, and the decoy is checked separately because rewriting it was one of
  // the attempts.
  stats_of(conf, &b);
  rprintf("[EDGE],confine_after_escape,moved=%d,max=%d,refill=%d,mode=%d,"
          "budget=%d,used=%d\n", b.max != a.max || b.refill != a.refill ||
          b.mode != a.mode, b.max, b.refill, b.mode, b.budget, b.used);
  stats_of(decoy, &b);
  rprintf("[EDGE],confine_decoy_untouched,moved=%d,max=%d\n", b.max != d.max,
          b.max);
  setgroup(0);
}

int
main(int argc, char *argv[])
{
  const char *filter = argc > 1 ? argv[1] : "all";
  int all = filter[0] == 'a';
  int which = all ? 0 : atoi(filter);

  rprintf("=========================================================\n");
  rprintf("  budget workload scenarios: trace only, no assertions\n");
  rprintf("=========================================================\n");
  if (budgetinfo(&P) < 0) {
    rprintf("[ABORT] budgetinfo failed: no published cost table\n");
    exit(1);
  }
  rprintf("[PARAMS],period=%d,ngroup=%d,denied=%d,noauth=%d,block=%d,fail=%d,"
          "unlink=%d,console=%d,ownwrite=%d,foreignwrite=%d,foreignexec=%d,"
          "ownexec=%d,pipe=%d,closedwrite=%d,dmax=%d,drefill=%d,dmode=%d\n",
          P.period, P.ngroup, P.denied, P.noauth, P.mode_block, P.mode_fail,
          P.cost_unlink, P.cost_console_write, P.cost_own_write,
          P.cost_foreign_write, P.cost_foreign_exec, P.cost_own_exec,
          P.cost_pipe_write, P.cost_closed_write, P.default_max,
          P.default_refill, P.default_mode);

  stage_bins();

  if (all || which == 1) scn_1_drain();
  if (all || which == 2) scn_2_logger();
  if (all || which == 3) scn_3_own_work_is_free();
  if (all || which == 4) scn_4_cross_group();
  if (all || which == 5) scn_5_timing();
  if (all || which == 6) scn_6_fanout();
  if (all || which == 7) scn_7_grid();
  if (all || which == 8) scn_8_inputs();
  if (all || which == 9) scn_9_confine();

  rprintf("[DONE]\n");
  exit(0);
}
