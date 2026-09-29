#!/usr/bin/env bash
# Simulates privilege-escalation primitives.
# Expected detections: SENTINEL-020 (needs a target), SENTINEL-021, SENTINEL-022.
set -u
cd "$(dirname "$0")" || exit 1
# shellcheck source=lib.sh
source ./lib.sh

banner "scenario: privilege escalation primitives"

banner "unshare(CLONE_NEWUSER) — user namespace creation"
unshare --user --map-root-user true 2>/dev/null || true
pause 1

banner "unshare(CLONE_NEWUSER|CLONE_NEWNS)"
unshare --user --mount --map-root-user true 2>/dev/null || true
pause 1

banner "ptrace attach/detach against a child sleep (PTRACE_ATTACH = 16)"
sleep 3 &
TARGET=$!
python3 - "$TARGET" <<'EOF' 2>/dev/null || true
import ctypes, os, sys, time
pid = int(sys.argv[1])
libc = ctypes.CDLL("libc.so.6", use_errno=True)
PTRACE_ATTACH, PTRACE_DETACH = 16, 17
if libc.ptrace(PTRACE_ATTACH, pid, None, None) == 0:
    os.waitpid(pid, 0)
    libc.ptrace(PTRACE_DETACH, pid, None, None)
EOF
wait "$TARGET" 2>/dev/null || true
pause 1

banner "capset probe via python ctypes (raises EPERM as non-root — still traced)"
python3 - <<'EOF' 2>/dev/null || true
import ctypes
# __NR_capset = 126 on x86_64; passing NULL is invalid but the syscall is
# entered, which is all the tracepoint needs.
libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.syscall(126, None, None)
EOF

banner "privilege_escalation scenario done (expect SENTINEL-021/022 alerts)"
