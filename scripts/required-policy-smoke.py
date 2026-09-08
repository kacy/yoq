#!/usr/bin/env python3
"""Exercise standalone policy owners and required enforcement in private namespaces."""
import contextlib
import fcntl
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parent.parent
YOQ = REPO / "zig-out/bin/yoq"
SERVER = REPO / "zig-out/bin/yoq-test-http-server"
PROBE = REPO / "zig-out/bin/yoq-test-net-probe"


def inside(directory):
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["ip", "link", "add", "eth0", "type", "dummy"], check=True)
    root = Path(directory)
    (root / "home").mkdir()
    (root / "rootfs/bin").mkdir(parents=True)
    shutil.copy2(SERVER, root / "rootfs/bin/server")
    shutil.copy2(PROBE, root / "rootfs/bin/probe")
    env = dict(os.environ, HOME=str(root / "home"))
    database = root / "home/.local/share/yoq/yoq.db"
    running = set()

    def cli(*args, check=True):
        return subprocess.run([str(YOQ), *map(str, args)], env=env,
                              capture_output=True, timeout=40, check=check)

    def connection():
        return contextlib.closing(sqlite3.connect(database, timeout=5))

    def start(name, check=True):
        result = cli("run", "-d", "--name", name, root / "rootfs",
                     "/bin/server", "8080", "policy-ready", check=check)
        if result.returncode == 0:
            running.add(name)
        return result

    def stop_all():
        for name in list(running):
            cli("stop", name)
            running.remove(name)

    def probe(address):
        return cli("exec", "api", "/bin/probe", "http-get", address, "8080", "/", check=False)

    def wait_for(description, condition):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if condition():
                return
            time.sleep(.25)
        raise AssertionError(f"timed out waiting for {description}")

    def success(address):
        result = probe(address)
        return result.returncode == 0 and b"policy-ready" in result.stdout

    def denied(address):
        result = probe(address)
        return result.returncode == 1 and b"ConnectionPending" in result.stderr

    def rejected(name):
        result = start(name, check=False)
        assert result.returncode != 0, f"configured policy allowed {name} to start"
        with connection() as db:
            row = db.execute("SELECT startup_outcome,pid FROM containers WHERE name=?", (name,)).fetchone()
            assert row == ("failed", None), row
            assert db.execute("SELECT COUNT(*) FROM service_names WHERE name=?", (name,)).fetchone()[0] == 0
            assert db.execute("SELECT COUNT(*) FROM service_endpoints WHERE service_name=?", (name,)).fetchone()[0] == 0

    try:
        start("web")
        start("api")
        with connection() as db:
            target = db.execute("SELECT ip_address FROM containers WHERE name='web'").fetchone()[0]
        wait_for("standalone service traffic", lambda: success("web") and success(target))
        cli("policy", "deny", "api", "web")
        wait_for("standalone VIP deny", lambda: denied("web"))
        wait_for("standalone direct deny", lambda: denied(target))
        cli("policy", "rm", "api", "web")
        wait_for("standalone policy removal", lambda: success("web") and success(target))
        stop_all()

        # A held private namespace lock makes real BPF attachment fail. Optional
        # acceleration may fail for policy-free workloads; configured policy may not.
        with open("/proc/thread-self/ns/net", "rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            start("optional-bpf")
            with connection() as db:
                db.execute("INSERT INTO network_policies VALUES ('api','web','deny',1)")
                db.commit()
            rejected("required-bpf")
        stop_all()
        with connection() as db:
            db.execute("UPDATE network_policies SET action='invalid'")
            db.commit()
        rejected("invalid-policy")
        with connection() as db:
            db.execute("UPDATE network_policies SET action='deny'")
            db.executemany("INSERT INTO service_names VALUES (?,?,?,1)",
                           [("api", f"source-{i}", f"10.42.10.{i+1}") for i in range(65)] +
                           [("web", f"target-{i}", f"10.42.20.{i+1}") for i in range(64)])
            db.commit()
        rejected("oversized-policy")
        print("standalone owner deny/removal and required-policy startup rejection passed", flush=True)
    finally:
        for name in running:
            cli("stop", name, check=False)
        for log in (root / "home/.local/share/yoq/logs").glob("*.log"):
            if sys.exc_info()[0] is not None:
                print(f"--- {log.name} ---\n{log.read_text(errors='replace')[-8192:]}", file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--inside":
        inside(sys.argv[2])
    else:
        if not all(path.is_file() for path in (YOQ, SERVER, PROBE)):
            raise SystemExit("build yoq and runtime-network helpers before running this fixture")
        with tempfile.TemporaryDirectory(prefix="yoq-required-policy-", dir=os.environ.get("RUNNER_TEMP")) as directory:
            subprocess.run(["unshare", "--mount", "--net", "--pid", "--fork", "--mount-proc",
                            sys.executable, __file__, "--inside", directory], check=True, timeout=200)
