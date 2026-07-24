"""Phase 0 verification: sandbox tool routing.

Usage:
    python scripts/verify_phase0.py

Prerequisites:
    docker compose up --build   # rebuild sandbox with ctags, start containers
"""

from __future__ import annotations

import subprocess
import sys

SANDBOX_CONTAINER = "agentic-code-audit-sandbox"

SANDBOX_TOOLS = [
    # C/C++ static analysis
    ("cppcheck", "static analysis"),
    ("clang-tidy", "deep C/C++ checks"),
    # Code navigation
    ("ctags", "function boundary extraction"),
    # Build chain
    ("cmake", "C/C++ build system"),
    ("gcc", "C compiler"),
    ("g++", "C++ compiler"),
    ("clang", "LLVM C compiler"),
    ("clang++", "LLVM C++ compiler"),
    ("make", "build"),
    ("ninja", "build"),
    # Debug / verification
    ("valgrind", "memory safety"),
    ("gdb", "debugger"),
    ("lldb", "LLVM debugger"),
    # Multi-language
    ("go", "Go runtime"),
    ("cargo", "Rust runtime"),
    ("java", "Java runtime"),
    ("php", "PHP runtime"),
]


def run(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=False)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, "", str(exc)


def check_sandbox_running() -> bool:
    code, out, _ = run(["docker", "inspect", "--format", "{{.State.Running}}", SANDBOX_CONTAINER])
    return code == 0 and out == "true"


def main() -> int:
    print("=" * 64)
    print("Phase 0 Verification: Sandbox Tool Routing")
    print("=" * 64)

    # 1. Sandbox container status
    print(f"\n[1] Checking sandbox container '{SANDBOX_CONTAINER}' ...")
    if not check_sandbox_running():
        print(f"    [FAIL]  Sandbox container '{SANDBOX_CONTAINER}' is NOT running.")
        print("    ->  Run: docker compose up --build")
        return 1
    print("    [OK]  Sandbox container is running.")

    # 2. Check each tool inside sandbox
    print("\n[2] Checking sandbox tool availability ...")
    ok_count = 0
    miss_count = 0
    for tool_name, purpose in SANDBOX_TOOLS:
        code, out, err = run(
            ["docker", "exec", SANDBOX_CONTAINER, "which", tool_name],
            timeout=5,
        )
        if code == 0 and out:
            vcode, vout, _ = run(
                ["docker", "exec", SANDBOX_CONTAINER, tool_name, "--version"],
                timeout=10,
            )
            version_line = (vout or err).splitlines()
            version = version_line[0][:80] if version_line else "(version check failed)"
            print(f"    [OK]   {tool_name:14s}  {purpose:30s}  {version}")
            ok_count += 1
        else:
            print(f"    [MISS] {tool_name:14s}  {purpose:30s}  NOT FOUND in sandbox")
            miss_count += 1

    # 3. Quick functional test: cppcheck on a test file
    print("\n[3] Functional test: cppcheck on a test snippet ...")
    test_code = r"""
#include <stdio.h>
#include <string.h>

void unsafe_copy(char *input) {
    char buf[10];
    strcpy(buf, input);  // should trigger cppcheck
}

int main(int argc, char **argv) {
    if (argc > 1) {
        unsafe_copy(argv[1]);
    }
    return 0;
}
"""
    write_cmd = [
        "docker", "exec", "-i", SANDBOX_CONTAINER,
        "bash", "-c", f"cat > /tmp/test_unsafe.c << 'CPPEOF'\n{test_code}\nCPPEOF"
    ]
    wcode, _, werr = run(write_cmd, timeout=5)
    if wcode != 0:
        print(f"    [FAIL]  Failed to write test file: {werr}")
    else:
        cppcheck_cmd = [
            "docker", "exec", SANDBOX_CONTAINER,
            "cppcheck", "--enable=all", "--xml", "--xml-version=2", "/tmp/test_unsafe.c"
        ]
        ccode, cout, cerr = run(cppcheck_cmd, timeout=30)
        if ccode == 0 and ("strcpy" in cout or "bufferAccess" in cout or "unsafe" in cout.lower()):
            print("    [OK]   cppcheck detected issues in test file -> sandbox routing works!")
        elif ccode == 0:
            print("    [WARN]  cppcheck ran but output doesn't mention expected patterns.")
            print(f"       stdout preview: {(cout or cerr)[:200]}")
        else:
            print(f"    [FAIL]  cppcheck failed (exit={ccode}): {(cout or cerr)[:300]}")

    # 4. Functional test: ctags
    print("\n[4] Functional test: ctags on test file ...")
    ctags_cmd = [
        "docker", "exec", SANDBOX_CONTAINER,
        "ctags", "--c-kinds=f", "-x", "/tmp/test_unsafe.c"
    ]
    tcode, tout, terr = run(ctags_cmd, timeout=10)
    if tcode == 0 and ("unsafe_copy" in tout or "main" in tout):
        print("    [OK]   ctags extracted function boundaries -> sandbox routing works!")
    elif tcode == 0:
        print(f"    [WARN]  ctags ran but output unexpected: {tout[:200]}")
    else:
        print(f"    [FAIL]  ctags failed (exit={tcode}): {(tout or terr)[:200]}")

    # Summary
    print(f"\n{'=' * 64}")
    print(f"Summary: {ok_count}/{len(SANDBOX_TOOLS)} tools available in sandbox, {miss_count} missing")
    if miss_count > 0:
        print("Missing tools are expected if not installed in sandbox Dockerfile.")
    print(f"{'=' * 64}")

    return 0 if miss_count <= 4 else 1


if __name__ == "__main__":
    sys.exit(main())
