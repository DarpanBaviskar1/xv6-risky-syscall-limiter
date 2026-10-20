#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"
#include "vm.h"
#include "budget.h"

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  kexit(n);
  return 0; // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return kfork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return kwait(p);
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int t;
  int n;

  argint(0, &n);
  argint(1, &t);
  addr = myproc()->sz;

  if (t == SBRK_EAGER || n < 0) {
    if (growproc(n) < 0) {
      return -1;
    }
  } else {
    // Lazily allocate memory for this process: increase its memory
    // size but don't allocate memory. If the processes uses the
    // memory, vmfault() will allocate it.
    if (addr + n < addr)
      return -1;
    if (addr + n > TRAPFRAME)
      return -1;
    myproc()->sz += n;
  }
  return addr;
}

uint64
sys_pause(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  if (n < 0)
    n = 0;
  acquire(&tickslock);
  ticks0 = ticks;
  while (ticks - ticks0 < n) {
    if (killed(myproc())) {
      release(&tickslock);
      return -1;
    }
    sleep_prepare(&ticks);
    release(&tickslock);
    sleep();
    acquire(&tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kkill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

// Budget policy authority, decided here rather than in the dispatcher: these
// two syscalls WRITE policy, so they are the escape routes a confined process
// would use. Reading is never gated - getbudgetstat() and budgetinfo() stay
// open to any process, because a limiter a confined group cannot inspect is not
// an auditable limiter.
//
// The check comes before argument validation on purpose. Telling an
// unauthorised caller that its gid was out of range hands it information about
// the validator that it cannot act on anyway; the only fact worth returning is
// that it may not be asking.
uint64
sys_setgroup(void)
{
  int gid;
  struct proc *p = myproc();

  if (!p->budget_auth)
    return BUDGET_NOAUTH;

  argint(0, &gid);
  if (gid < 0 || gid >= NGROUP)
    return -1;
  p->gid = gid;
  return 0;
}

uint64
sys_setbudget(void)
{
  int gid, max, refill, mode;
  struct proc *p = myproc();

  if (!p->budget_auth)
    return BUDGET_NOAUTH;

  argint(0, &gid);
  argint(1, &max);
  argint(2, &refill);
  argint(3, &mode);
  if (gid < 0 || gid >= NGROUP)
    return -1;
  if (mode != BUDGET_BLOCK && mode != BUDGET_FAIL)
    return -1;
  if (max < 0 || refill < 0)
    return -1;
  struct group *g = &groups[gid];
  acquire(&g->lock);
  // Bank the accrual the OLD policy earned before its rate is replaced, and
  // before last_refill is reset below. Without this the part of a period that
  // had already elapsed is thrown away, so a group that behaved itself and was
  // then reconfigured would silently lose tokens it had been granted.
  budget_bank(g);
  g->max = max;
  g->refill = refill;
  g->mode = mode;
  // Changing the ceiling must not grant free tokens: keep what the group has
  // already earned, but never let the held budget exceed the new ceiling.
  if (g->budget > g->max)
    g->budget = g->max;
  g->last_refill = ticks;
  // used and the event counters measure separate things: spend within this
  // policy window, versus lifetime activity for the group.
  g->used = 0;
  release(&g->lock);
  return 0;
}

// Give up budget policy authority, forever.
//
// This is the other half of the authority rule, and the only half a confined
// workload can reach: without a way to drop, "only the controller writes
// policy" would mean "everything descends from init, so everything writes
// policy". A runner installs the policy, moves itself into the group, drops, and
// then execs the workload - exec does not reset process flags, so the image
// that starts running is already unauthorised, and so is everything it forks.
//
// Returns 1 if this call took authority away, 0 if the caller had none to take.
// Idempotent, and there is no matching grant: the kernel has no syscall that
// gives authority back, to this process or to any of its descendants.
uint64
sys_dropbudgetauth(void)
{
  struct proc *p = myproc();
  int had = p->budget_auth;

  p->budget_auth = 0;
  return had;
}

// Hand the kernel's own constants to user space. Free, for the same reason
// report() is free: a limiter that charges to be inspected cannot be inspected
// while it is throttling. The oracle needs the table the kernel actually
// charges, not the table a test program assumes.
uint64
sys_budgetinfo(void)
{
  uint64 addr;
  argaddr(0, &addr);
  struct proc *p = myproc();
  struct budget_params out;

  budget_params_fill(&out);
  if (copyout(p->pagetable, p->sz, addr, (char *)&out, sizeof(out)) < 0)
    return -1;
  return 0;
}

uint64
sys_getbudgetstat(void)
{
  uint64 addr;
  argaddr(0, &addr);
  struct proc *p = myproc();

  // Staged without the spinlock so user space sees only the accounting fields.
  struct group_stat stat[NGROUP];

  for (int i = 0; i < NGROUP; i++) {
    acquire(&groups[i].lock);
    group_snapshot(&stat[i], &groups[i]);
    release(&groups[i].lock);
  }

  if (copyout(p->pagetable, p->sz, addr, (char *)stat, sizeof(stat)) < 0)
    return -1;
  return 0;
}

// Emit text through the free reporting path.
//
// Observability must not cost budget. A group that is throttled still has to
// be able to say that it is throttled; otherwise the limiter cannot be
// measured, and the test suite silently loses its own verdicts. This is
// deliberately a separate syscall rather than an exemption on write(), so the
// lab's "console write costs 1 token" rule keeps its meaning for ordinary
// output and the free path stays explicitly chosen and counted.
uint64
sys_report(void)
{
  uint64 addr;
  int n;
  char buf[REPORT_MAX + 1];
  struct proc *p = myproc();

  argaddr(0, &addr);
  argint(1, &n);
  if (n < 0 || n > REPORT_MAX)
    return -1;
  if (copyin(p->pagetable, p->sz, buf, addr, n) < 0)
    return -1;
  buf[n] = 0;
  printk("%s", buf);
  budget_note_report(p->gid, n);
  return n;
}
