#include "kernel/types.h"
#include "kernel/budget.h"
#include "user/user.h"

// xv6's atoi doesn't handle negative numbers. Parse signed int manually.
static int
parse_int(const char *s)
{
  int neg = 0;
  int n = 0;

  if (*s == '-') {
    neg = 1;
    s++;
  }
  while (*s >= '0' && *s <= '9') {
    n = n * 10 + (*s - '0');
    s++;
  }
  return neg ? -n : n;
}

static void
usage(void)
{
  fprintf(2, "usage: budgetctl set <gid> <max> <refill> <BLOCK|FAIL>\n");
  fprintf(2, "       budgetctl drop\n");
  exit(1);
}

static int
parse_mode(const char *s)
{
  if (strcmp(s, "BLOCK") == 0)
    return BUDGET_BLOCK;
  if (strcmp(s, "FAIL") == 0)
    return BUDGET_FAIL;
  return -1;
}

int
main(int argc, char *argv[])
{
  if (argc < 2)
    usage();

  if (strcmp(argv[1], "set") == 0) {
    if (argc != 6)
      usage();

    int gid = parse_int(argv[2]);
    int max = parse_int(argv[3]);
    int refill = parse_int(argv[4]);
    int mode = parse_mode(argv[5]);

    if (gid < 0 || gid >= NGROUP) {
      fprintf(2, "budgetctl: gid %d out of range [0, %d]\n", gid, NGROUP - 1);
      exit(1);
    }
    if (max < 0) {
      fprintf(2, "budgetctl: max must be >= 0\n");
      exit(1);
    }
    if (refill < 0) {
      fprintf(2, "budgetctl: refill must be >= 0\n");
      exit(1);
    }
    if (mode < 0) {
      fprintf(2, "budgetctl: mode must be BLOCK or FAIL\n");
      exit(1);
    }

    int rc = setbudget(gid, max, refill, mode);
    if (rc == 0) {
      printf("budgetctl: group %d configured: max=%d refill=%d mode=%s\n",
             gid, max, refill, mode == BUDGET_BLOCK ? "BLOCK" : "FAIL");
    } else if (rc == BUDGET_NOAUTH) {
      fprintf(2, "budgetctl: permission denied: no policy authority\n");
      exit(1);
    } else {
      fprintf(2, "budgetctl: setbudget failed (rc=%d)\n", rc);
      exit(1);
    }
  } else if (strcmp(argv[1], "drop") == 0) {
    if (argc != 2)
      usage();

    int rc = dropbudgetauth();
    printf("%d\n", rc);  // 1 if authority was dropped, 0 if already absent
  } else {
    usage();
  }

  exit(0);
}