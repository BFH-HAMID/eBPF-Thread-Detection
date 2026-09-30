#!/usr/bin/env bash
# Simulates container-escape steps (all harmless attempts: they fail without
# real privileges, but the syscalls are what the probes see).
# Expected detections: SENTINEL-030 – SENTINEL-035.
set -u
cd "$(dirname "$0")" || exit 1
# shellcheck source=lib.sh
source ./lib.sh

banner "scenario: container escape indicators"

banner "nsenter into the init namespace (fails unprivileged; still traced)"
nsenter -t 1 -m -u -i -n true 2>/dev/null || true
pause 1

banner "setns via /proc/1/ns/mnt"
python3 - <<'EOF' 2>/dev/null || true
import ctypes, os
libc = ctypes.CDLL("libc.so.6", use_errno=True)
try:
    fd = os.open("/proc/1/ns/mnt", os.O_RDONLY)
    libc.setns(fd, 0)          # __NR setns
    os.close(fd)
except OSError:
    pass
EOF
pause 1

banner "cgroup release_agent probe"
for p in /sys/fs/cgroup/release_agent /sys/fs/cgroup/notify_on_release \
         /tmp/cgroup/release_agent; do
    cat "$p" >/dev/null 2>&1 || true
done
# Classic escape setup: mount a cgroup and write release_agent (fails without
# CAP_SYS_ADMIN, but mount(2) is traced before it fails).
mkdir -p /tmp/sentinel-cgroup 2>/dev/null || true
mount -t cgroup -o rdma cgroup /tmp/sentinel-cgroup 2>/dev/null || true
umount /tmp/sentinel-cgroup 2>/dev/null || true
pause 1

banner "host path / docker.sock probes"
mkdir -p /tmp/sentinel-host 2>/dev/null || true
mount --bind /etc /tmp/sentinel-host 2>/dev/null || true
cat /var/run/docker.sock >/dev/null 2>&1 || true
cat /run/containerd/containerd.sock >/dev/null 2>&1 || true
pause 1

banner "pivot_root attempt (fails unprivileged; still traced)"
mkdir -p /tmp/sentinel-root/{old,new} 2>/dev/null || true
pivot_root /tmp/sentinel-root/new /tmp/sentinel-root/old 2>/dev/null || true
rm -rf /tmp/sentinel-root 2>/dev/null || true

banner "container_escape scenario done (expect SENTINEL-030–035 alerts)"
