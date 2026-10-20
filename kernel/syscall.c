#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "syscall.h"
#include "defs.h"
#include "file.h"
#include "fs.h"
#include "budget.h"  // COST_*: the cost table is data, not literals

// Fetch the uint64 at addr from the current process.
int
fetchaddr(uint64 addr, uint64 *ip)
{
  struct proc *p = myproc();
  if (addr >= p->sz ||
      addr + sizeof(uint64) > p->sz) // both tests needed, in case of overflow
    return -1;
  if (copyin(p->pagetable, p->sz, (char *)ip, addr, sizeof(*ip)) != 0)
    return -1;
  return 0;
}

// Fetch the nul-terminated string at addr from the current process.
// Returns length of string, not including nul, or -1 for error.
int
fetchstr(uint64 addr, char *buf, int max)
{
  struct proc *p = myproc();
  if (copyinstr(p->pagetable, p->sz, buf, addr, max) < 0)
    return -1;
  return strlen(buf);
}

static uint64
argraw(int n)
{
  struct proc *p = myproc();
  switch (n) {
  case 0:
    return p->trapframe->a0;
  case 1:
    return p->trapframe->a1;
  case 2:
    return p->trapframe->a2;
  case 3:
    return p->trapframe->a3;
  case 4:
    return p->trapframe->a4;
  case 5:
    return p->trapframe->a5;
  }
  panic("argraw");
  return -1;
}

// Fetch the nth 32-bit system call argument.
void
argint(int n, int *ip)
{
  *ip = argraw(n);
}

// Retrieve an argument as a pointer.
// Doesn't check for legality, since
// copyin/copyout will do that.
void
argaddr(int n, uint64 *ip)
{
  *ip = argraw(n);
}

// Fetch the nth word-sized system call argument as a null-terminated string.
// Copies into buf, at most max.
// Returns string length if OK (not including nul), -1 if error.
int
argstr(int n, char *buf, int max)
{
  uint64 addr;
  argaddr(n, &addr);
  return fetchstr(addr, buf, max);
}

// Prototypes for the functions that handle system calls.
extern uint64 sys_fork(void);
extern uint64 sys_exit(void);
extern uint64 sys_wait(void);
extern uint64 sys_pipe(void);
extern uint64 sys_read(void);
extern uint64 sys_kill(void);
extern uint64 sys_exec(void);
extern uint64 sys_fstat(void);
extern uint64 sys_chdir(void);
extern uint64 sys_dup(void);
extern uint64 sys_getpid(void);
extern uint64 sys_sbrk(void);
extern uint64 sys_pause(void);
extern uint64 sys_uptime(void);
extern uint64 sys_open(void);
extern uint64 sys_write(void);
extern uint64 sys_mknod(void);
extern uint64 sys_unlink(void);
extern uint64 sys_link(void);
extern uint64 sys_mkdir(void);
extern uint64 sys_close(void);
extern uint64 sys_sync(void);
extern uint64 sys_setgroup(void);
extern uint64 sys_setbudget(void);
extern uint64 sys_getbudgetstat(void);
extern uint64 sys_report(void);
extern uint64 sys_budgetinfo(void);
extern uint64 sys_dropbudgetauth(void);

// An array mapping syscall numbers from syscall.h
// to the function that handles the system call.
static uint64 (*syscalls[])(void) = {
  // clang-format off
  [SYS_fork]    = sys_fork,
  [SYS_exit]    = sys_exit,
  [SYS_wait]    = sys_wait,
  [SYS_pipe]    = sys_pipe,
  [SYS_read]    = sys_read,
  [SYS_kill]    = sys_kill,
  [SYS_exec]    = sys_exec,
  [SYS_fstat]   = sys_fstat,
  [SYS_chdir]   = sys_chdir,
  [SYS_dup]     = sys_dup,
  [SYS_getpid]  = sys_getpid,
  [SYS_sbrk]    = sys_sbrk,
  [SYS_pause]   = sys_pause,
  [SYS_uptime]  = sys_uptime,
  [SYS_open]    = sys_open,
  [SYS_write]   = sys_write,
  [SYS_mknod]   = sys_mknod,
  [SYS_unlink]  = sys_unlink,
  [SYS_link]    = sys_link,
  [SYS_mkdir]   = sys_mkdir,
  [SYS_close]   = sys_close,
  [SYS_sync]    = sys_sync,
  [SYS_setgroup]     = sys_setgroup,
  [SYS_setbudget]    = sys_setbudget,
  [SYS_getbudgetstat] = sys_getbudgetstat,
  [SYS_report]       = sys_report,
  [SYS_budgetinfo]   = sys_budgetinfo,
  [SYS_dropbudgetauth] = sys_dropbudgetauth,
  // clang-format on
};

// Return the budget cost for a system call.
// Only irreversible operations are charged; the dispatcher skips the
// accounting path entirely for a cost of zero.
int
syscall_cost(int num, struct proc *p)
{
  switch (num) {
    case SYS_unlink:
      return COST_UNLINK;
    case SYS_exec: {
      // Running a binary another group wrote is irreversible-ish: the image
      // replaces this process, so the cost cannot be refunded.
      char path[MAXPATH];
      if (argstr(0, path, sizeof(path)) < 0)
        return 0;
      struct inode *ip = namei(path);
      if (ip == 0)
        return 0; // sys_exec will fail on its own; nothing to charge
      // namei() hands back an unlocked inode, which may be an icache slot that
      // has never been read from disk, so its gid field is whatever the slot
      // held before. Lock it before believing the owner.
      ilock(ip);
      int owner = ip->gid;
      iunlockput(ip);
      return owner == p->gid ? COST_OWN_EXEC : COST_FOREIGN_EXEC;
    }
    case SYS_write: {
      int fd = p->trapframe->a0;
      if (fd == 1 || fd == 2) {
        return COST_CONSOLE_WRITE;
      }
      if (fd >= 0 && fd < NOFILE && p->ofile[fd]) {
        struct file *f = p->ofile[fd];
        if (f->type == FD_INODE && f->ip)
          return f->ip->gid == p->gid ? COST_OWN_WRITE : COST_FOREIGN_WRITE;
        // A pipe write destroys nothing on disk and is not the console, so it
        // is not the kind of operation the budget exists for. Charging it made
        // every shell pipeline pay for the kernel's own buffering.
        return COST_PIPE_WRITE;
      }
      return COST_CLOSED_WRITE; // closed descriptor: charged like console
    }
    default:
      return 0;
  }
}

void
syscall(void)
{
  int num;
  struct proc *p = myproc();

  num = p->trapframe->a7;

  if (num > 0 && num < NELEM(syscalls) && syscalls[num]) {
    // Charge before dispatching: the operation must be paid for up front,
    // since it may not be reversible once it has run.
    int cost = syscall_cost(num, p);
    int denial = charge(p->gid, cost);
    if (denial < 0) {
      // Pass the sentinel through so the caller can tell a budget denial from
      // the syscall failing on its own merits. Still negative, so existing
      // error checks keep working.
      p->trapframe->a0 = denial;
      return;
    }

    // Use num to lookup the system call function for num, call it,
    // and store its return value in p->trapframe->a0
    p->trapframe->a0 = syscalls[num]();
  } else {
    printk("%d %s: unknown sys call %d\n", p->pid, p->name, num);
    p->trapframe->a0 = -1;
  }
}
