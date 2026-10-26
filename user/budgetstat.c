#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/budget.h"
#include "user/user.h"

// Right-justify v in w characters. This tree's formatter has no field widths,
// so the columns are built by hand. sz is the size of buf; w must be < sz.
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

int
main(int argc, char *argv[])
{
    struct group_stat stats[NGROUP];
    struct budget_params P;
    int shown = 0;

    if (budgetinfo(&P) < 0) {
        fprintf(2, "budgetstat: budgetinfo failed\n");
        exit(1);
    }
    if (getbudgetstat(stats) < 0) {
        fprintf(2, "budgetstat: getbudgetstat failed\n");
        exit(1);
    }

    // The prices, straight out of the kernel that is charging them. Printed
    // first because a count is only interpretable against the table that
    // produced it, and because the alternative - a copy of the table in this
    // file - is how a test starts agreeing with itself.
    rprintf("kernel policy table (published by budgetinfo, free to read)\n");
    rprintf("  unlink=%d  console write=%d  own-group write=%d\n",
            P.cost_unlink, P.cost_console_write, P.cost_own_write);
    rprintf("  other-group write=%d  exec of other group's file=%d  own exec=%d\n",
            P.cost_foreign_write, P.cost_foreign_exec, P.cost_own_exec);
    rprintf("  pipe write=%d  write to closed fd=%d\n",
            P.cost_pipe_write, P.cost_closed_write);
    rprintf("  refill period=%d ticks   group table=%d entries\n", P.period, P.ngroup);
    rprintf("  a refusal returns %d   a policy call without authority returns %d\n",
            P.denied, P.noauth);
    rprintf("  defaults: max=%d refill=%d mode=%s\n\n", P.default_max, P.default_refill,
            P.default_mode == BUDGET_BLOCK ? "BLOCK" : "FAIL");

    // Whether THIS process may write policy. There is no getter, and adding one
    // would be a syscall that answers a question any process can already ask
    // better: setbudget(-1, ...) cannot succeed under either answer, so the
    // return code is pure diagnosis and the call changes nothing.
    rprintf("this process: %s\n\n",
            setbudget(-1, 1, 1, BUDGET_BLOCK) == P.noauth
                ? "confined - it cannot change any group's policy"
                : "holds policy authority (descended from init without dropping)");

    rprintf("GID BUDGET/MAX REFILL  MODE  ALLOWED BLOCKED REFUSED REPORTED\n");
    rprintf("                                        (all free, never charged)\n");

    for (int i = 0; i < NGROUP; i++) {
        struct group_stat *s = &stats[i];

        // A group nobody has touched and nobody has reconfigured is noise.
        // used resets on setbudget, so also key off a non-default policy - and
        // the defaults come from the kernel rather than from a number typed in
        // here, so this stays true after a reconfiguration of group 0.
        int active = s->n_allowed || s->n_blocked || s->n_refused ||
                     s->n_reported || s->used;
        int configured = !(s->max == P.default_max && s->refill == P.default_refill &&
                           s->mode == P.default_mode);
        if (!active && !configured)
            continue;

        // Each padnum() target needs width+1 bytes for the digits plus the
        // nul, so they are all sized generously.
        char g[16], b[16], m[16], r[16], a[16], bl[16], rf[16], rp[16];
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
        shown++;
    }

    if (shown == 0)
        rprintf("  (no group has activity or a non-default policy)\n");

    exit(0);
}
