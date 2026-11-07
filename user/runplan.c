#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/fcntl.h"
#include "kernel/budget.h"
#include "user/user.h"

#define MAX_LINE 256
#define MAX_ARGS 16
#define MAX_LINES 200

static struct budget_params P;
static int scn_id = 0;
static int op_index = 0;
static int current_gid = 0;
static int scenario_started = 0;
static int ops_in_scenario = 0;
static int grants_in_scenario = 0;

// Store lines for two-pass execution
static char stored_lines[MAX_LINES][MAX_LINE];
static int stored_line_count = 0;

// xv6's atoi doesn't handle negatives. Parse signed int manually.
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

// Get current ticks from uptime syscall
static uint
get_ticks(void)
{
  return uptime();
}

// Emit [PARAMS] line with kernel's published cost table (key=value format for oracle)
static void
emit_params(void)
{
  rprintf("[PARAMS],period=%d,ngroup=%d,denied=%d,noauth=%d,block=%d,fail=%d,"
          "unlink=%d,console=%d,ownwrite=%d,foreignwrite=%d,foreignexec=%d,ownexec=%d,"
          "pipe=%d,closedwrite=%d,dmax=%d,drefill=%d,dmode=%d\n",
          P.period, P.ngroup, P.denied, P.noauth,
          P.mode_block, P.mode_fail,
          P.cost_unlink, P.cost_console_write, P.cost_own_write,
          P.cost_foreign_write, P.cost_foreign_exec, P.cost_own_exec,
          P.cost_pipe_write, P.cost_closed_write,
          P.default_max, P.default_refill, P.default_mode);
}

// Get group stats snapshot
static void
get_group_stat(int gid, struct group_stat *out)
{
  struct group_stat all[NGROUP];
  if (getbudgetstat(all) < 0) {
    rprintf("[ABORT] getbudgetstat failed\n");
    exit(1);
  }
  *out = all[gid];
}

// Emit [SCN] line
static void
emit_scn(const char *name, int gid, int max, int refill, int mode, int budget, int ops)
{
  rprintf("[SCN],%d,%s,gid=%d,max=%d,refill=%d,mode=%d,budget=%d,ops=%d,atomic=1,fill=clamp\n",
          scn_id, name, gid, max, refill, mode, budget, ops);
}

// Emit [OP] line
static void
emit_op(const char *kind, int budget_before, int expected_cost, int res,
        int da, int db, int dr, int du, uint ticks)
{
  rprintf("[OP],%d,%d,%s,bb=%d,exp=%d,res=%d,da=%d,db=%d,dr=%d,du=%d,t=%d\n",
          scn_id, op_index, kind, budget_before, expected_cost, res,
          da, db, dr, du, ticks);
}

// Emit [DATA] line for staircase
static void
emit_data(uint ticks, int granted_so_far)
{
  rprintf("[DATA],%d,%d,%d\n", scn_id, ticks, granted_so_far);
}

// Emit [RES] line
static void
emit_res(int allowed, int blocked, int refused, int used, int budget, int granted)
{
  rprintf("[RES],%d,allowed=%d,blocked=%d,refused=%d,used=%d,budget=%d,granted=%d\n",
          scn_id, allowed, blocked, refused, used, budget, granted);
}

// Emit [EDGE] line for rejected operations
static void
emit_edge(const char *name, int rc)
{
  rprintf("[EDGE],%s,rc=%d\n", name, rc);
}

// Emit [DONE] line
static void
emit_done(void)
{
  rprintf("[DONE]\n");
}

// Create a file owned by current group
static void
create_file(const char *path, const char *content)
{
  int fd = open(path, O_CREATE | O_WRONLY);
  if (fd < 0) {
    rprintf("[ABORT] create_file: cannot create %s\n", path);
    exit(1);
  }
  if (content && content[0]) {
    write(fd, content, strlen(content));
  }
  close(fd);
}

// Unlink a file and recreate it (like scenarios.c)
static int
do_unlink(const char *path)
{
  int rc = unlink(path);
  if (rc == 0) {
    // Recreate the file for free so next unlink is a real test
    create_file(path, "x");
  }
  if (rc == BUDGET_DENIED) return 1;
  if (rc < 0) return 2;
  return 0;
}

// Write to console (fd 1)
static int
do_write_console(const char *str)
{
  int rc = write(1, str, strlen(str));
  if (rc == BUDGET_DENIED) return 1;
  if (rc < 0) return 2;
  return 0;
}

// Write to a file
static int
do_write_file(const char *path, const char *str)
{
  int fd = open(path, O_WRONLY);
  if (fd < 0) return 2;
  int rc = write(fd, str, strlen(str));
  close(fd);
  if (rc == BUDGET_DENIED) return 1;
  if (rc < 0) return 2;
  return 0;
}

// Exec a binary
static int
do_exec(const char *path)
{
  int pid = fork();
  if (pid == 0) {
    char *av[1] = { 0 };
    int rc = exec(path, av);
    if (rc == BUDGET_DENIED) exit(11);
    if (rc < 0) exit(12);
    exit(0);
  }
  if (pid < 0) return 2;
  int status;
  wait(&status);
  if (status == 11) return 1;
  return status == 0 ? 0 : 2;
}

// Write to pipe
static int
do_pipe_write(const char *str)
{
  int pfd[2];
  if (pipe(pfd) < 0) return 2;
  int rc = write(pfd[1], str, strlen(str));
  char buf[1];
  read(pfd[0], buf, 1);
  close(pfd[0]);
  close(pfd[1]);
  if (rc == BUDGET_DENIED) return 1;
  if (rc < 0) return 2;
  return 0;
}

// Report (free syscall)
static void
do_report(const char *str)
{
  report(str, strlen(str));
}

// Sleep for ticks
static void
do_sleep(int ticks)
{
  pause(ticks);
}

// Parse a line into argc/argv, supporting quoted strings
static int
parse_line(char *line, char **argv)
{
  int argc = 0;
  char *p = line;

  while (*p && argc < MAX_ARGS) {
    while (*p == ' ' || *p == '\t') p++;
    if (!*p) break;

    char quote = 0;
    if (*p == '"' || *p == '\'') {
      quote = *p;
      p++;
    }

    argv[argc++] = p;

    if (quote) {
      while (*p && *p != quote) p++;
      if (*p) *p++ = '\0';
    } else {
      while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
      if (*p) *p++ = '\0';
    }
  }
  return argc;
}

// Check if a directive produces an OP trace record
static int
is_traced_op(const char *directive)
{
  return (strcmp(directive, "UNLINK") == 0 ||
          strcmp(directive, "WRITE_CONSOLE") == 0 ||
          strcmp(directive, "WRITE_FOREIGN") == 0 ||
          strcmp(directive, "WRITE_OWN") == 0 ||
          strcmp(directive, "EXEC_FOREIGN") == 0 ||
          strcmp(directive, "EXEC_OWN") == 0 ||
          strcmp(directive, "PIPE_WRITE") == 0 ||
          strcmp(directive, "REPORT") == 0 ||
          strcmp(directive, "SLEEP") == 0);
}

// Execute a single directive
static void
execute_directive(int argc, char **argv)
{
  if (argc == 0) return;

  struct group_stat before, after;
  int rc, cost, da, db, dr, du;
  uint ticks;

  // Directives that don't need a scenario
  if (strcmp(argv[0], "SETBUDGET") == 0) {
    if (argc != 5) {
      rprintf("[ABORT] SETBUDGET needs 4 args: gid max refill mode\n");
      exit(1);
    }
    int gid = parse_int(argv[1]);
    int max = parse_int(argv[2]);
    int refill = parse_int(argv[3]);
    int mode = (strcmp(argv[4], "BLOCK") == 0) ? BUDGET_BLOCK : BUDGET_FAIL;

    if (gid < 0 || gid >= NGROUP) {
      rprintf("[ABORT] SETBUDGET: gid %d out of range\n", gid);
      exit(1);
    }
    if (max < 0 || refill < 0 || mode < 0) {
      rprintf("[ABORT] SETBUDGET: invalid args\n");
      exit(1);
    }

    rc = setbudget(gid, max, refill, mode);
    if (rc == 0) {
      rprintf("# SETBUDGET: group %d configured max=%d refill=%d mode=%s\n",
              gid, max, refill, mode == BUDGET_BLOCK ? "BLOCK" : "FAIL");
    } else if (rc == BUDGET_NOAUTH) {
      emit_edge("setbudget_noauth", rc);
    } else {
      emit_edge("setbudget_invalid", rc);
    }
    return;
  }

  if (strcmp(argv[0], "SETGROUP") == 0) {
    if (argc != 2) {
      rprintf("[ABORT] SETGROUP needs 1 arg: gid\n");
      exit(1);
    }
    int gid = parse_int(argv[1]);
    if (gid < 0 || gid >= NGROUP) {
      rprintf("[ABORT] SETGROUP: gid %d out of range\n", gid);
      exit(1);
    }
    rc = setgroup(gid);
    if (rc == 0) {
      current_gid = gid;
      rprintf("# SETGROUP: now in group %d\n", gid);
    } else if (rc == BUDGET_NOAUTH) {
      emit_edge("setgroup_noauth", rc);
    } else {
      emit_edge("setgroup_invalid", rc);
    }
    return;
  }

  if (strcmp(argv[0], "DROP_AUTH") == 0) {
    rc = dropbudgetauth();
    rprintf("# DROP_AUTH: authority dropped=%d\n", rc);
    return;
  }

  // Directives that need a scenario to be active
  if (!scenario_started) {
    rprintf("[ABORT] No active scenario. Use SETBUDGET first to start one.\n");
    exit(1);
  }

  if (strcmp(argv[0], "CREATE_FILE") == 0) {
    if (argc < 2 || argc > 3) {
      rprintf("[ABORT] CREATE_FILE needs path [content]\n");
      exit(1);
    }
    create_file(argv[1], argc == 3 ? argv[2] : "");
    rprintf("# CREATE_FILE: %s\n", argv[1]);
    return;
  }

  if (strcmp(argv[0], "UNLINK") == 0) {
    if (argc != 2) {
      rprintf("[ABORT] UNLINK needs path\n");
      exit(1);
    }
    get_group_stat(current_gid, &before);
    ticks = get_ticks();
    cost = P.cost_unlink;
    rc = do_unlink(argv[1]);
    get_group_stat(current_gid, &after);

    da = after.n_allowed - before.n_allowed;
    db = after.n_blocked - before.n_blocked;
    dr = after.n_refused - before.n_refused;
    du = after.used - before.used;

    emit_op("unlink", before.budget, cost, rc, da, db, dr, du, ticks);
    if (rc == 0) {
      emit_data(ticks, after.n_allowed);
      grants_in_scenario++;
    }
    ops_in_scenario++;
    return;
  }

  if (strcmp(argv[0], "WRITE_CONSOLE") == 0) {
    if (argc != 2) {
      rprintf("[ABORT] WRITE_CONSOLE needs string\n");
      exit(1);
    }
    get_group_stat(current_gid, &before);
    ticks = get_ticks();
    cost = P.cost_console_write;
    rc = do_write_console(argv[1]);
    get_group_stat(current_gid, &after);

    da = after.n_allowed - before.n_allowed;
    db = after.n_blocked - before.n_blocked;
    dr = after.n_refused - before.n_refused;
    du = after.used - before.used;

    emit_op("console", before.budget, cost, rc, da, db, dr, du, ticks);
    if (rc == 0) {
      grants_in_scenario++;
    }
    ops_in_scenario++;
    return;
  }

  if (strcmp(argv[0], "WRITE_FOREIGN") == 0) {
    if (argc != 3) {
      rprintf("[ABORT] WRITE_FOREIGN needs path string\n");
      exit(1);
    }
    get_group_stat(current_gid, &before);
    ticks = get_ticks();
    cost = P.cost_foreign_write;
    rc = do_write_file(argv[1], argv[2]);
    get_group_stat(current_gid, &after);

    da = after.n_allowed - before.n_allowed;
    db = after.n_blocked - before.n_blocked;
    dr = after.n_refused - before.n_refused;
    du = after.used - before.used;

    emit_op("foreignwrite", before.budget, cost, rc, da, db, dr, du, ticks);
    if (rc == 0) {
      grants_in_scenario++;
    }
    ops_in_scenario++;
    return;
  }

  if (strcmp(argv[0], "WRITE_OWN") == 0) {
    if (argc != 3) {
      rprintf("[ABORT] WRITE_OWN needs path string\n");
      exit(1);
    }
    get_group_stat(current_gid, &before);
    ticks = get_ticks();
    cost = P.cost_own_write;
    rc = do_write_file(argv[1], argv[2]);
    get_group_stat(current_gid, &after);

    da = after.n_allowed - before.n_allowed;
    db = after.n_blocked - before.n_blocked;
    dr = after.n_refused - before.n_refused;
    du = after.used - before.used;

    emit_op("ownwrite", before.budget, cost, rc, da, db, dr, du, ticks);
    if (rc == 0) {
      grants_in_scenario++;
    }
    ops_in_scenario++;
    return;
  }

  if (strcmp(argv[0], "EXEC_FOREIGN") == 0) {
    if (argc != 2) {
      rprintf("[ABORT] EXEC_FOREIGN needs path\n");
      exit(1);
    }
    get_group_stat(current_gid, &before);
    ticks = get_ticks();
    cost = P.cost_foreign_exec;
    rc = do_exec(argv[1]);
    get_group_stat(current_gid, &after);

    da = after.n_allowed - before.n_allowed;
    db = after.n_blocked - before.n_blocked;
    dr = after.n_refused - before.n_refused;
    du = after.used - before.used;

    emit_op("foreignexec", before.budget, cost, rc, da, db, dr, du, ticks);
    if (rc == 0) {
      grants_in_scenario++;
    }
    ops_in_scenario++;
    return;
  }

  if (strcmp(argv[0], "EXEC_OWN") == 0) {
    if (argc != 2) {
      rprintf("[ABORT] EXEC_OWN needs path\n");
      exit(1);
    }
    get_group_stat(current_gid, &before);
    ticks = get_ticks();
    cost = P.cost_own_exec;
    rc = do_exec(argv[1]);
    get_group_stat(current_gid, &after);

    da = after.n_allowed - before.n_allowed;
    db = after.n_blocked - before.n_blocked;
    dr = after.n_refused - before.n_refused;
    du = after.used - before.used;

    emit_op("ownexec", before.budget, cost, rc, da, db, dr, du, ticks);
    if (rc == 0) {
      grants_in_scenario++;
    }
    ops_in_scenario++;
    return;
  }

  if (strcmp(argv[0], "PIPE_WRITE") == 0) {
    if (argc != 2) {
      rprintf("[ABORT] PIPE_WRITE needs string\n");
      exit(1);
    }
    get_group_stat(current_gid, &before);
    ticks = get_ticks();
    cost = P.cost_pipe_write;
    rc = do_pipe_write(argv[1]);
    get_group_stat(current_gid, &after);

    da = after.n_allowed - before.n_allowed;
    db = after.n_blocked - before.n_blocked;
    dr = after.n_refused - before.n_refused;
    du = after.used - before.used;

    emit_op("pipe", before.budget, cost, rc, da, db, dr, du, ticks);
    if (rc == 0) {
      grants_in_scenario++;
    }
    ops_in_scenario++;
    return;
  }

  if (strcmp(argv[0], "REPORT") == 0) {
    if (argc != 2) {
      rprintf("[ABORT] REPORT needs string\n");
      exit(1);
    }
    get_group_stat(current_gid, &before);
    ticks = get_ticks();
    cost = 0;
    do_report(argv[1]);
    get_group_stat(current_gid, &after);

    da = after.n_allowed - before.n_allowed;
    db = after.n_blocked - before.n_blocked;
    dr = after.n_refused - before.n_refused;
    du = after.used - before.used;

    emit_op("report", before.budget, cost, 3, da, db, dr, du, ticks);
    grants_in_scenario++;  // free operation always succeeds
    ops_in_scenario++;
    return;
  }

  if (strcmp(argv[0], "SLEEP") == 0) {
    if (argc != 2) {
      rprintf("[ABORT] SLEEP needs ticks\n");
      exit(1);
    }
    int ticks_to_sleep = parse_int(argv[1]);
    get_group_stat(current_gid, &before);
    ticks = get_ticks();
    cost = 0;
    do_sleep(ticks_to_sleep);
    get_group_stat(current_gid, &after);

    da = after.n_allowed - before.n_allowed;
    db = after.n_blocked - before.n_blocked;
    dr = after.n_refused - before.n_refused;
    du = after.used - before.used;

    emit_op("idle", before.budget, cost, 3, da, db, dr, du, ticks);
    grants_in_scenario++;  // free operation always succeeds
    ops_in_scenario++;
    return;
  }

  rprintf("[ABORT] Unknown directive: %s\n", argv[0]);
  exit(1);
}

// First pass: count traced operations
static int
count_traced_ops(void)
{
  int count = 0;
  for (int i = 0; i < stored_line_count; i++) {
    char line[MAX_LINE];
    strcpy(line, stored_lines[i]);
    char *argv_parsed[MAX_ARGS];
    int argc_parsed = parse_line(line, argv_parsed);
    if (argc_parsed > 0 && is_traced_op(argv_parsed[0])) {
      count++;
    }
  }
  return count;
}

int
main(int argc, char *argv[])
{
  int fd = 0; // stdin by default
  char line[MAX_LINE];
  char *argv_parsed[MAX_ARGS];

  // If a file path is given, open it
  if (argc > 1) {
    fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
      fprintf(2, "runplan: cannot open %s\n", argv[1]);
      exit(1);
    }
  }

  // Get kernel's cost table
  if (budgetinfo(&P) < 0) {
    fprintf(2, "runplan: budgetinfo failed\n");
    exit(1);
  }

  // First pass: read all lines into memory
  while (stored_line_count < MAX_LINES) {
    int i = 0;
    char c;
    int n;

    // Read a line
    while (i < MAX_LINE - 1) {
      n = read(fd, &c, 1);
      if (n <= 0) break;
      if (c == '\n') break;
      line[i++] = c;
    }
    if (n <= 0 && i == 0) break; // EOF
    line[i] = '\0';

    // Skip comments and empty lines
    char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (!*p || *p == '#') continue;

    // Store line
    strcpy(stored_lines[stored_line_count], line);
    stored_line_count++;
  }

  if (fd != 0) close(fd);

  // Count traced operations for SCN
  int total_traced_ops = count_traced_ops();

  // Emit PARAMS first
  emit_params();

  // Second pass: execute stored lines
  for (int i = 0; i < stored_line_count; i++) {
    char *p = stored_lines[i];
    while (*p == ' ' || *p == '\t') p++;
    if (!*p || *p == '#') continue;

    int argc_parsed = parse_line(p, argv_parsed);

    // Handle SETBUDGET as scenario starter
    if (argc_parsed > 0 && strcmp(argv_parsed[0], "SETBUDGET") == 0) {
      // If there was a previous scenario, emit its RES
      if (scenario_started) {
        struct group_stat final_stat;
        get_group_stat(current_gid, &final_stat);
        emit_res(
          final_stat.n_allowed, final_stat.n_blocked, final_stat.n_refused,
          final_stat.used, final_stat.budget, grants_in_scenario
        );
      }

      // Parse SETBUDGET args to start new scenario
      if (argc_parsed != 5) {
        rprintf("[ABORT] SETBUDGET needs 4 args: gid max refill mode\n");
        exit(1);
      }
      int gid = parse_int(argv_parsed[1]);
      int max = parse_int(argv_parsed[2]);
      int refill = parse_int(argv_parsed[3]);
      int mode = (strcmp(argv_parsed[4], "BLOCK") == 0) ? BUDGET_BLOCK : BUDGET_FAIL;

      if (gid < 0 || gid >= NGROUP || max < 0 || refill < 0 || mode < 0) {
        rprintf("[ABORT] SETBUDGET: invalid args\n");
        exit(1);
      }

      // Apply the budget
      int rc = setbudget(gid, max, refill, mode);
      if (rc != 0) {
        rprintf("[ABORT] SETBUDGET failed: rc=%d\n", rc);
        exit(1);
      }

      // Set group
      rc = setgroup(gid);
      if (rc != 0) {
        rprintf("[ABORT] SETGROUP failed: rc=%d\n", rc);
        exit(1);
      }
      current_gid = gid;

      // Get initial budget
      struct group_stat initial;
      get_group_stat(gid, &initial);

      // Start new scenario
      scn_id++;
      op_index = 0;
      ops_in_scenario = 0;
      grants_in_scenario = 0;
      scenario_started = 1;

      emit_scn("plan", gid, max, refill, mode, initial.budget, total_traced_ops);
      continue;
    }

    // Execute directive
    execute_directive(argc_parsed, argv_parsed);
    op_index++;
  }

  // Emit final RES for last scenario
  if (scenario_started) {
    struct group_stat final_stat;
    get_group_stat(current_gid, &final_stat);
    emit_res(
      final_stat.n_allowed, final_stat.n_blocked, final_stat.n_refused,
      final_stat.used, final_stat.budget, grants_in_scenario
    );
  }

  emit_done();

  exit(0);
}