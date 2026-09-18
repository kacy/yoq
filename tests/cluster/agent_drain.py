#!/usr/bin/env python3
"""drain a real service between two workers while the leader restarts."""
import argparse
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time
import urllib.request

from agent_recovery import Rig, wait_for

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("runtime_fixture", REPO / "scripts/scheduled-runtime-smoke.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def exercise(rig):
    rig.prepare()
    rig.run("mount", "--make-rprivate", "/")
    hosts = rig.artifacts / "hosts"
    hosts.write_text(Path("/etc/hosts").read_text() + "\n10.233.0.254 registry.fixture\n")
    rig.run("mount", "--bind", str(hosts), "/etc/hosts")
    cert, key = rig.artifacts / "cert.pem", rig.artifacts / "key.pem"
    rig.run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-keyout", str(key), "-out", str(cert), "-subj", "/CN=registry.fixture",
            "-addext", "subjectAltName=DNS:registry.fixture")
    rig.run("mount", "--bind", str(cert), "/etc/ssl/certs/ca-certificates.crt")
    registry, image = fixture.start_registry(cert, key)
    try:
        for node in range(1, 4):
            rig.start_server(node)
        leader = wait_for("initial leader", rig.leader)
        rig.start(4, "join", f"10.233.0.{leader}", "--port", "7700", "--token", rig.token)
        source = wait_for("source worker", lambda: rig.registered_agents(leader))[0]["id"]
        body = {"app_name": "drain-fixture", "services": [{
            "name": "web", "image": image, "cpu_limit": 250, "memory_limit_mb": 64,
            "health_check": {"kind": "http", "path": "/", "port": 8080, "interval": 1, "timeout": 1, "retries": 20},
            "rollout": {"health_check_timeout": 40},
        }]}
        # apply waits for image preparation and actual container readiness.
        request = urllib.request.Request(f"http://10.233.0.{leader}:7700/apps/apply",
                                                data=fixture.encode(body), headers={"Authorization": "Bearer " + rig.api_token})
        with rig.http.open(request, timeout=60) as response:
            result = json.load(response)
        assert result.get("status") == "completed", result

        def assignments():
            with closing(sqlite3.connect(f"file:{rig.data(leader) / 'cluster/state.db'}?mode=ro", uri=True)) as db:
                db.row_factory = sqlite3.Row
                return [dict(row) for row in db.execute("SELECT id, agent_id, status FROM assignments WHERE app_name='drain-fixture' ORDER BY created_at, id")]

        def container(node):
            with closing(sqlite3.connect(f"file:{rig.data(node) / 'yoq.db'}?mode=ro", uri=True)) as db:
                return db.execute("SELECT ip_address FROM containers WHERE hostname='web' AND pid IS NOT NULL").fetchone()

        original = assignments()[0]["id"]
        old_ip = wait_for("source container address", lambda: container(4))[0]

        def serves(node, address):
            result = rig.run(*rig.inside(node, "curl", "--noproxy", "*", "--silent", "--max-time", "2", f"http://{address}:8080/"))
            assert result.stdout == "scheduled-ready", result.stdout

        result = rig.request(leader, f"/agents/{source}/drain", b"")
        assert result["status"] == "drain_blocked", result
        rig.require_running(4)
        assert assignments()[0]["status"] == "running"
        serves(4, old_ip)
        rig.start(5, "join", f"10.233.0.{leader}", "--port", "7700", "--token", rig.token)
        wait_for("replacement worker", lambda: len(rig.request(leader, "/agents")) == 2)
        pending = wait_for("persisted replacement assignment", lambda: [row for row in assignments() if row["id"] != original and row["status"] == "pending"])[0]
        assert next(row for row in assignments() if row["id"] == original)["status"] == "running"
        serves(4, old_ip)
        rig.stop(leader)
        leader = wait_for("new leader during drain", rig.leader)
        deadline = time.monotonic() + 75
        while time.monotonic() < deadline:
            rows = assignments()
            old = next(row for row in rows if row["id"] == original)
            replacement = next(row for row in rows if row["id"] == pending["id"])
            if replacement["status"] != "running":
                assert old["status"] == "running", rows
                serves(4, old_ip)
            elif old["status"] == "stopped":
                break
            time.sleep(0.2)
        else:
            raise AssertionError("drain did not finish after leader restart")
        new_ip = wait_for("replacement container address", lambda: container(5))[0]
        serves(5, new_ip)
        wait_for("committed drained state", lambda: any(row["id"] == source and row["status"] == "drained" for row in rig.request(leader, "/agents")))
        wait_for("source worker shutdown", lambda: rig.processes[4].poll() is not None)
        (rig.artifacts / "drain-result.json").write_text(json.dumps({"source": source, "original": original, "replacement": pending["id"], "leader": leader}, indent=2))
        print("blocked drain, live readiness handoff, leader restart, and drained shutdown passed")
    finally:
        registry.shutdown()
        registry.server_close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get("YOQ_RECOVERY_ISOLATED") != "1":
        raise SystemExit("run through scripts/agent-drain-smoke.sh in its private namespaces")
    rig = Rig(args.binary, args.artifacts, workers=2)
    try:
        exercise(rig)
    finally:
        rig.cleanup()


if __name__ == "__main__":
    main()
