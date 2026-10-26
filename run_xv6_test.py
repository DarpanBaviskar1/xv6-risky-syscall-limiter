#!/usr/bin/env python3
"""Run one xv6 user program under QEMU, stream output, stop on completion/idle."""
import os, select, signal, subprocess, sys, time

QEMU, CPUS, CMD, LOG = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
TIMEOUT = float(sys.argv[5]) if len(sys.argv) > 5 else 1800.0
IDLE = float(sys.argv[6]) if len(sys.argv) > 6 else 90.0
ROOT = sys.argv[7] if len(sys.argv) > 7 else os.getcwd()
# Output seen after a completion marker is still part of the run: the suite
# prints its summary line and the budgetstat table after "All Tests Completed",
# and report() output lands in bursts. Drain instead of stopping dead.
DONE_GRACE = float(os.environ.get("XV6_DONE_GRACE", "3.0"))
DONE_QUIET = float(os.environ.get("XV6_DONE_QUIET", "0.5"))

args = [QEMU, "-machine", "virt", "-bios", "none", "-kernel", "kernel/kernel",
        "-m", "128M", "-smp", CPUS, "-nographic",
        "-global", "virtio-mmio.force-legacy=false",
        "-drive", f"file=fs.img,if=none,format=raw,id=x0",
        "-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0",
        "-snapshot"]

proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, bufsize=0,
                        preexec_fn=os.setsid, cwd=ROOT)

status = "NO_PROMPT"
sent = False
deadline = None
start = time.time()
last_byte = start
buf = b""
done_markers = ["All Tests Completed", "panic:", "segfault", "SEGFAULT"]
log = open(LOG, "wb")

try:
    while time.time() - start < TIMEOUT:
        pause = DONE_QUIET if deadline else 0.5
        r, _, _ = select.select([proc.stdout], [], [], pause)
        if not r:
            if proc.poll() is not None:
                status = "QEMU_EXITED"
                break
            if deadline and time.time() > deadline:
                break
            if sent and time.time() - last_byte > IDLE:
                status = f"IDLE_{status}"
                break
            continue
        chunk = os.read(proc.stdout.fileno(), 4096)
        if not chunk:
            status = "QEMU_EXITED"
            break
        last_byte = time.time()
        log.write(chunk)
        log.flush()
        buf = (buf + chunk)[-3000:]
        text = buf.decode("utf-8", "replace")

        if not sent and "$ " in text:
            sent = True
            status = "RUNNING"
            proc.stdin.write((CMD + "\n").encode())
            proc.stdin.flush()
            print(f"[{time.time()-start:7.1f}s] prompt; sent: {CMD}", flush=True)
            buf = b""
            continue

        if sent:
            for m in done_markers:
                if m in text:
                    status = "DONE:" + m if m == "All Tests Completed" else "PANIC"
                    if deadline is None:
                        deadline = time.time() + DONE_GRACE
                    break
            if deadline and time.time() > deadline:
                break
            if deadline is None and text.rstrip().endswith("$") and len(text) > 4:
                status = "PROMPT_RETURNED"
                break
    else:
        status = f"TIMEOUT_{status}"
finally:
    try:
        proc.stdin.write(b"\x01x")
        proc.stdin.flush()
    except Exception:
        pass
    try:
        proc.wait(timeout=8)
    except Exception:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        proc.wait()
    log.close()

print(f"[{time.time()-start:7.1f}s] STATUS={status} log={LOG} "
      f"bytes={os.path.getsize(LOG)}", flush=True)
