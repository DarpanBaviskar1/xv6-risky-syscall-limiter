#!/usr/bin/env python3
"""
Error-tolerant test runner for xv6-riscv Phase 1 Budget System.
Tries multiple QEMU configurations to handle version conflicts and boot issues.
"""

import subprocess
import sys
import os
import time
import signal
from pathlib import Path

# Configuration
KERNEL = "kernel/kernel"
FS_IMG = "fs.img"
TEST_CMD = "test_budget_suite"
TIMEOUT = 180  # seconds
QEMU_BIN = "qemu-system-riscv64"

# Multiple QEMU configurations to try (in order of preference). Every one is
# -bios none: kernel/entry.S expects to start in M-mode at 0x80000000, so an
# OpenSBI firmware in front of it cannot work, and naming one would also mean
# hard-coding a path outside this repo.
QEMU_CONFIGS = [
    {
        "name": "Standard (Makefile) -bios none",
        "args": [
            "-machine", "virt",
            "-bios", "none",
            "-kernel", KERNEL,
            "-m", "128M",
            "-smp", "3",
            "-nographic",
            "-global", "virtio-mmio.force-legacy=false",
            "-drive", f"file={FS_IMG},if=none,format=raw,id=x0",
            "-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0"
        ]
    },
    {
        "name": "Single CPU, -bios none",
        "args": [
            "-machine", "virt",
            "-bios", "none",
            "-kernel", KERNEL,
            "-m", "128M",
            "-smp", "1",
            "-nographic",
            "-global", "virtio-mmio.force-legacy=false",
            "-drive", f"file={FS_IMG},if=none,format=raw,id=x0",
            "-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0"
        ]
    },
    {
        "name": "With explicit serial stdio (no -nographic)",
        "args": [
            "-machine", "virt",
            "-bios", "none",
            "-kernel", KERNEL,
            "-m", "128M",
            "-smp", "3",
            "-display", "none",
            "-serial", "stdio",
            "-global", "virtio-mmio.force-legacy=false",
            "-drive", f"file={FS_IMG},if=none,format=raw,id=x0",
            "-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0"
        ]
    },
    {
        "name": "With QEMU monitor on stdio, serial on pty",
        "args": [
            "-machine", "virt",
            "-bios", "none",
            "-kernel", KERNEL,
            "-m", "128M",
            "-smp", "3",
            "-monitor", "stdio",
            "-serial", "pty",
            "-global", "virtio-mmio.force-legacy=false",
            "-drive", f"file={FS_IMG},if=none,format=raw,id=x0",
            "-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0"
        ]
    },
]

def check_qemu_version():
    """Check QEMU version and return version string."""
    try:
        result = subprocess.run([QEMU_BIN, "--version"], capture_output=True, text=True, timeout=5)
        version_line = result.stdout.split('\n')[0]
        return version_line
    except Exception as e:
        return f"Error: {e}"

def run_qemu_config(config, log_file):
    """Run a single QEMU configuration and return output."""
    print(f"\n{'='*60}")
    print(f"Trying: {config['name']}")
    print(f"{'='*60}")

    cmd = [QEMU_BIN] + config["args"]
    print(f"Command: {' '.join(cmd)}")

    # Start QEMU process
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE,
        text=True,
        bufsize=1,
        preexec_fn=os.setsid
    )

    output_lines = []
    test_started = False
    test_completed = False

    try:
        # Read output line by line with timeout
        start_time = time.time()
        while time.time() - start_time < TIMEOUT:
            # Check if process has exited
            if proc.poll() is not None:
                break

            # Read available output
            line = proc.stdout.readline()
            if line:
                output_lines.append(line)
                print(line.rstrip())

                # Write to log file
                with open(log_file, 'a') as f:
                    f.write(line)

                # Check for shell prompt to start test
                if "$ " in line and not test_started:
                    print(f"\n>>> Sending test command: {TEST_CMD}")
                    proc.stdin.write(f"{TEST_CMD}\n")
                    proc.stdin.flush()
                    test_started = True

                # Check for test completion
                if test_started and "All Tests Completed" in line:
                    test_completed = True
                    # Give some time for final output
                    time.sleep(2)
                    break

                # Also check for individual test completion patterns
                if test_started and "[PASS] Test 6 completed" in line:
                    test_completed = True
                    time.sleep(2)
                    break
            else:
                time.sleep(0.1)

        if not test_completed and test_started:
            # Try to get more output
            time.sleep(3)
            try:
                proc.stdin.write("\x01x")  # Ctrl-a x to exit QEMU
                proc.stdin.flush()
            except:
                pass
            time.sleep(1)

            # Read remaining output
            try:
                remaining = proc.stdout.read()
                if remaining:
                    output_lines.append(remaining)
                    print(remaining)
                    with open(log_file, 'a') as f:
                        f.write(remaining)
            except:
                pass

    except subprocess.TimeoutExpired:
        print(f"Timeout after {TIMEOUT} seconds")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Clean up
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except:
            try:
                proc.terminate()
            except:
                pass
        try:
            proc.wait(timeout=5)
        except:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except:
                pass

    return ''.join(output_lines), test_completed

def main():
    print("="*60)
    print("xv6-riscv Phase 1 Budget System - Test Runner")
    print("="*60)

    # Check files exist
    for f in [KERNEL, FS_IMG]:
        if not Path(f).exists():
            print(f"ERROR: {f} not found!")
            return 1

    # Check QEMU
    qemu_version = check_qemu_version()
    print(f"QEMU Version: {qemu_version}")

    # Prepare log file
    log_file = "qemu_output.log"
    if Path(log_file).exists():
        Path(log_file).unlink()

    # Try each configuration. Each attempt reaps its own process group in
    # run_qemu_config's finally block, which is the only safe way to clean up:
    # a "pkill -f qemu-system-riscv64" also matches the shell that invoked it.
    for i, config in enumerate(QEMU_CONFIGS):
        output, success = run_qemu_config(config, log_file)

        if success:
            print(f"\n✓ SUCCESS with configuration: {config['name']}")
            print(f"Output saved to: {log_file}")
            return 0
        else:
            print(f"\n✗ FAILED with configuration: {config['name']}")
            if i < len(QEMU_CONFIGS) - 1:
                print("Trying next configuration...")

    print("\n" + "="*60)
    print("ALL CONFIGURATIONS FAILED")
    print("="*60)
    print("Check qemu_output.log for details")
    return 1

if __name__ == "__main__":
    sys.exit(main())