# xv6-risky-syscall-limiter
xv6-riscv Irreversibility Budget Engine is a kernel safety extension enforcing per-group cost limits on risky syscalls like unlinks. Featuring a pre-dispatch token bucket with lazy timer refills and disk inode creator tracking, it intercepts harmful actions before execution and blocks fork-bomb evasions using BLOCK and FAIL throttling modes.
