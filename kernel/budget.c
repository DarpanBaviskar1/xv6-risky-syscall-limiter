#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "spinlock.h"
#include "proc.h"
#include "budget.h"

struct group groups[NGROUP];

// The policy a group starts with before anyone calls setbudget(). Named here so
// budgetstat() and the oracle can report it rather than guess it.
#define DEFAULT_BUDGET 100
#define DEFAULT_REFILL 10

void
budgetinit(void)
{
  for (int i = 0; i < NGROUP; i++) {
    initlock(&groups[i].lock, "group");
    groups[i].used = 0;
    groups[i].budget = DEFAULT_BUDGET;
    groups[i].max = DEFAULT_BUDGET;
    groups[i].refill = DEFAULT_REFILL;
    groups[i].mode = BUDGET_BLOCK;
    groups[i].last_refill = ticks;
    groups[i].n_allowed = 0;
    groups[i].n_blocked = 0;
    groups[i].n_refused = 0;
    groups[i].n_reported = 0;
    groups[i].report_bytes = 0;
  }
}

void
budget_params_fill(struct budget_params *out)
{
  out->period = BUDGET_PERIOD;
  out->ngroup = NGROUP;
  out->denied = BUDGET_DENIED;
  out->noauth = BUDGET_NOAUTH;
  out->mode_block = BUDGET_BLOCK;
  out->mode_fail = BUDGET_FAIL;
  out->cost_unlink = COST_UNLINK;
  out->cost_console_write = COST_CONSOLE_WRITE;
  out->cost_own_write = COST_OWN_WRITE;
  out->cost_foreign_write = COST_FOREIGN_WRITE;
  out->cost_foreign_exec = COST_FOREIGN_EXEC;
  out->cost_own_exec = COST_OWN_EXEC;
  out->cost_pipe_write = COST_PIPE_WRITE;
  out->cost_closed_write = COST_CLOSED_WRITE;
  out->default_max = DEFAULT_BUDGET;
  out->default_refill = DEFAULT_REFILL;
  out->default_mode = BUDGET_BLOCK;
}

// Bring the bucket up to date with the clock. Called with g->lock held.
//
// This is deliberately a separate entry point rather than a private helper:
// anything that rewrites a group's parameters has to bank what the old policy
// already earned first, or the elapsed-but-unspent part of the last period is
// quietly thrown away.
void
budget_bank(struct group *g)
{
  uint elapsed = ticks - g->last_refill;
  int periods = elapsed / BUDGET_PERIOD;

  if (periods > 0) {
    g->budget += periods * g->refill;
    if (g->budget > g->max)
      g->budget = g->max;
    g->last_refill += periods * BUDGET_PERIOD;
  }
}

int
charge(int gid, int cost)
{
  if (gid < 0 || gid >= NGROUP)
    return 0;

  // A free syscall must not be counted, and must not pay for the spinlock.
  if (cost <= 0)
    return 0;

  struct group *g = &groups[gid];
  acquire(&g->lock);
  budget_bank(g);

  // BLOCK is only a wait if the bucket can eventually reach the price. With a
  // ceiling below the cost, or no accrual and a short bucket, sleeping forever
  // is a hang rather than a delay, so deny the same way FAIL would.
  if (g->mode == BUDGET_BLOCK && g->budget < cost &&
      (g->max < cost || g->refill <= 0)) {
    g->n_refused++;
    release(&g->lock);
    return BUDGET_DENIED;
  }

  // One block episode may span many tick wakeups; count it once.
  int blocked = 0;
  while (g->budget < cost) {
    if (g->mode == BUDGET_FAIL) {
      g->n_refused++;
      release(&g->lock);
      return BUDGET_DENIED;
    } else {
      if (!blocked) {
        g->n_blocked++;
        blocked = 1;
      }
      sleep_prepare(&ticks);
      release(&g->lock);
      sleep();
      acquire(&g->lock);
      budget_bank(g);
    }
  }

  g->budget -= cost;
  g->used += cost;
  g->n_allowed++;
  release(&g->lock);
  return 0;
}

// Called with g->lock held.
void
group_snapshot(struct group_stat *dst, struct group *g)
{
  // Catch the accrual up first, otherwise an idle group reports a stale
  // budget and the refill behaviour looks wrong in the output.
  budget_bank(g);

  dst->used = g->used;
  dst->budget = g->budget;
  dst->max = g->max;
  dst->refill = g->refill;
  dst->mode = g->mode;
  dst->last_refill = g->last_refill;
  dst->n_allowed = g->n_allowed;
  dst->n_blocked = g->n_blocked;
  dst->n_refused = g->n_refused;
  dst->n_reported = g->n_reported;
  dst->report_bytes = g->report_bytes;
}

// The reporting path spends no budget, but it is still counted: a free
// channel nobody measures is a free channel nobody can explain.
void
budget_note_report(int gid, int n)
{
  if (gid < 0 || gid >= NGROUP)
    return;
  struct group *g = &groups[gid];
  acquire(&g->lock);
  g->n_reported++;
  g->report_bytes += n;
  release(&g->lock);
}
