#ifndef _BUDGET_H
#define _BUDGET_H

#include "types.h"
#include "spinlock.h"

#define NGROUP 20

#define BUDGET_BLOCK 0
#define BUDGET_FAIL 1

// A charged syscall refused for lack of budget returns this instead of -1, so a
// program can tell "denied by the limiter" from "failed on its own merits".
// Negative, so every existing `< 0` error check still fires.
#define BUDGET_DENIED (-42)

// A POLICY call refused for lack of authority. Deliberately not the same value:
// "your group cannot afford this" and "you are not allowed to ask" are different
// diagnoses, and a confined process needs to be able to tell an escape that was
// blocked from an argument it mistyped. Also negative.
#define BUDGET_NOAUTH (-43)

// Reserved group ids. Written down in one place because the confinement test
// depends on the decoy being a different group from the one it confines, and a
// test that renumbers its groups silently changes what its own assertions mean.
// 0 is every process's starting group and the shell's own; it is never
// reconfigured, because throttling it throttles the console that reports.
#define BUDGET_GID_ROOT   0
#define BUDGET_GID_EDGES  1   // invalid-input checks
#define BUDGET_GID_CONFINE 16 // the group a confined workload is locked into
#define BUDGET_GID_DECOY   17 // a rich group, to try (and fail) to migrate into
#define BUDGET_GID_TESTS   18 // upstream usertests: a policy too big to bind

// Tokens accrue in whole periods of this many ticks; 1 tick is 100 ms.
#define BUDGET_PERIOD 100

// THE COST TABLE - the only place these numbers are written down. syscall_cost()
// charges from these, sys_budgetinfo() hands them to user space, and the test
// oracle reads them from the kernel rather than from a copy that could drift.
#define COST_UNLINK 10         // the reference destructive operation
#define COST_CONSOLE_WRITE 1   // console output is already on screen
#define COST_OWN_WRITE 0       // the group owns the damage it does
#define COST_FOREIGN_WRITE 3   // cross-group side effect
#define COST_FOREIGN_EXEC 5    // running code another group wrote
#define COST_OWN_EXEC 0
#define COST_PIPE_WRITE 0      // destroys nothing on disk
#define COST_CLOSED_WRITE 1    // write to a bad fd: charged like console

// Largest single report() payload. Longer text must be split by the caller.
#define REPORT_MAX 128

struct group {
  struct spinlock lock;
  int used;          // tokens spent since the last setbudget()
  int budget;        // tokens currently available
  int max;           // budget ceiling
  int refill;        // tokens added per 100 ticks
  int mode;          // BUDGET_BLOCK or BUDGET_FAIL
  uint last_refill;  // tick value the accrual is caught up to
  int n_allowed;     // charged syscalls that were granted
  int n_blocked;     // syscalls that had to wait for a refill (episodes, not wakeups)
  int n_refused;     // syscalls denied outright in FAIL mode
  int n_reported;    // report() calls served, counted but never charged
  int report_bytes;  // bytes emitted through the free reporting path
};

extern struct group groups[NGROUP];

// What sys_getbudgetstat() copies to user space. Include this header from
// user space rather than restating the layout.
struct group_stat {
  int used;
  int budget;
  int max;
  int refill;
  int mode;
  uint last_refill;
  int n_allowed;
  int n_blocked;
  int n_refused;
  int n_reported;
  int report_bytes;
};

// Copy the accounting fields of a locked group into a user-visible record.
void group_snapshot(struct group_stat *dst, struct group *g);

// Add the tokens a group has earned since its last banked refill, capped at
// its ceiling. Called with g->lock held. Anything that rewrites a group's
// policy must call this first: resetting the accrual clock without banking it
// throws away the part of the period already earned.
void budget_bank(struct group *g);

// What sys_budgetinfo() copies to user space: the kernel's own constants, so an
// oracle can derive expectations from the table the kernel actually charges
// instead of from a copy in a test program or a script.
struct budget_params {
  int period;         // ticks per refill period
  int ngroup;         // size of the group table
  int denied;         // BUDGET_DENIED, the sentinel a refusal returns
  int noauth;         // BUDGET_NOAUTH, the sentinel an unauthorized policy call returns
  int mode_block;     // BUDGET_BLOCK
  int mode_fail;      // BUDGET_FAIL
  int cost_unlink;
  int cost_console_write;
  int cost_own_write;
  int cost_foreign_write;
  int cost_foreign_exec;
  int cost_own_exec;
  int cost_pipe_write;
  int cost_closed_write;
  int default_max;    // what budgetinit() installs
  int default_refill;
  int default_mode;
};

// Fill in the table. Kept next to the constants so the two cannot drift.
void budget_params_fill(struct budget_params *out);

// Account for one free report() without spending any budget. Called with no
// lock held.
void budget_note_report(int gid, int n);

#endif
