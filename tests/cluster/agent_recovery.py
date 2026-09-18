#!/usr/bin/env python3
"""exercise leader loss and durable reports with real servers and an agent."""

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import threading
import time
import urllib.error
import urllib.request


def wait_for(description, check, seconds=60):
    deadline = time.monotonic() + seconds
    last_error = None
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except (OSError, ValueError, sqlite3.Error) as error:
            last_error = error
        time.sleep(0.2)
    raise RuntimeError(f"timed out waiting for {description}: {last_error}")


class Rig:
    def __init__(self, binary, artifacts):
        self.binary = str(binary.resolve())
        self.artifacts = artifacts.resolve()
        self.artifacts.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.token = secrets.token_hex(32)
        self.api_token = secrets.token_hex(32)
        self.namespaces = {}
        self.processes = {}
        self.logs = []
        self.restored_homes = {}
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    @staticmethod
    def run(*command):
        return subprocess.run(command, check=True, capture_output=True, text=True, timeout=15)

    def inside(self, node, *command):
        return ["nsenter", "--target", str(self.namespaces[node].pid), "--net", "--", *command]

    def home(self, node):
        return self.restored_homes.get(node, self.artifacts / f"node-{node}")

    def data(self, node):
        return self.home(node) / ".local/share/yoq"

    def prepare(self):
        self.run("ip", "link", "set", "lo", "up")
        self.run("ip", "link", "add", "recovery", "type", "bridge")
        self.run("ip", "address", "add", "10.233.0.254/24", "dev", "recovery")
        self.run("ip", "link", "set", "recovery", "up")
        parent_namespace = os.readlink("/proc/self/ns/net")
        for node in range(1, 5):
            namespace = subprocess.Popen(["unshare", "--net", "--", "sleep", "infinity"])
            self.namespaces[node] = namespace
            wait_for("network namespace", lambda: os.readlink(f"/proc/{namespace.pid}/ns/net") != parent_namespace)
            host_link, node_link = f"host-{node}", f"node-{node}"
            self.run("ip", "link", "add", host_link, "type", "veth", "peer", "name", node_link)
            self.run("ip", "link", "set", node_link, "netns", str(namespace.pid))
            self.run("ip", "link", "set", host_link, "master", "recovery")
            self.run("ip", "link", "set", host_link, "up")
            for args in [("link", "set", "lo", "up"), ("link", "set", node_link, "name", "eth0"),
                         ("address", "add", f"10.233.0.{node}/24", "dev", "eth0"), ("link", "set", "eth0", "up"),
                         ("route", "add", "default", "via", "10.233.0.254")]:
                self.run(*self.inside(node, "ip", *args))
            self.data(node).mkdir(parents=True, mode=0o700)
            token_file = self.data(node) / "api_token"
            token_file.write_text(self.api_token)
            token_file.chmod(0o600)

    def start(self, node, *arguments):
        if node in self.processes and self.processes[node].poll() is None:
            raise RuntimeError(f"node {node} already running")
        log = (self.artifacts / f"node-{node}-{time.monotonic_ns()}.log").open("ab")
        self.logs.append(log)
        environment = dict(os.environ, HOME=str(self.home(node)))
        self.processes[node] = subprocess.Popen(self.inside(node, self.binary, *arguments), env=environment, stdout=log, stderr=subprocess.STDOUT)

    def start_server(self, node):
        peers = ",".join(f"{other}@10.233.0.{other}:9700" for other in range(1, 4) if other != node)
        credential = ["--token-file", str(self.data(node) / "join_token")] if node in self.restored_homes else ["--token", self.token]
        self.start(node, "init-server", "--id", str(node), "--port", "9700", "--api-port", "7700", "--peers", peers, *credential)

    def stop(self, node):
        process = self.processes.get(node)
        if process and process.poll() is None:
            process.kill()
            process.wait(timeout=10)

    def require_running(self, node):
        status = self.processes[node].poll()
        if status is not None:
            raise RuntimeError(f"node {node} exited with status {status}")

    def registered_agents(self, server):
        self.require_running(4)
        return self.request(server, "/agents")

    def worker_credential(self):
        identities = [path for path in (self.data(4) / "enrollment").iterdir() if len(path.name) == 64]
        if len(identities) != 1:
            raise RuntimeError("expected one persisted enrollment identity")
        return identities[0].read_bytes()[:32].hex()

    def request(self, node, path, body=None, credential=None):
        request = urllib.request.Request(f"http://10.233.0.{node}:7700{path}", data=body,
                                         headers={"Authorization": f"Bearer {credential or self.api_token}"})
        with self.http.open(request, timeout=3) as response:
            return json.load(response)

    def leader(self):
        leaders = []
        for node in range(1, 4):
            if self.processes[node].poll() is not None:
                continue
            try:
                if self.request(node, "/cluster/status").get("role") == "leader":
                    leaders.append(node)
            except OSError:
                continue
        return leaders[0] if len(leaders) == 1 else None

    def reports(self):
        path = self.data(4) / "agent-cache.db"
        with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=1)) as database:
            return database.execute("SELECT assignment_id, status, delivered, generation, revision, reason FROM assignment_results").fetchall()

    def cleanup(self):
        for node in self.processes:
            self.stop(node)
        for namespace in self.namespaces.values():
            if namespace.poll() is None:
                namespace.kill()
            namespace.wait(timeout=10)
        for log in self.logs:
            log.close()


class HeldRegistry:
    """hold the image request until the agent's management api is isolated."""

    def __init__(self):
        self.socket = socket.create_server(("10.233.0.254", 5000))
        self.socket.settimeout(1)
        self.connected = threading.Event()
        self.release = threading.Event()
        self.stopped = threading.Event()
        self.connections = 0
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stopped.is_set():
            try:
                connection, _ = self.socket.accept()
            except TimeoutError:
                continue
            with connection:
                self.connections += 1
                self.connected.set()
                self.release.wait(45)
                # failing image preparation produces a real terminal report
                # without fetching an external image or launching a container.
                # keep accepting so a repeated image pull is observable.

    def close(self):
        self.stopped.set()
        self.release.set()
        self.thread.join(timeout=3)
        self.socket.close()


def exercise(rig):
    rig.prepare()
    for node in range(1, 4):
        rig.start_server(node)
    first = wait_for("initial leader", rig.leader)
    seed = f"10.233.0.{first}"
    rig.start(4, "join", seed, "--port", "7700", "--token", rig.token)
    agents = wait_for("joined agent", lambda: rig.registered_agents(first))
    if len(agents) != 1:
        raise RuntimeError(f"expected one joined agent, got {len(agents)}")
    agent_id = agents[0]["id"]
    wait_for("persisted server discovery", lambda: list((rig.data(4) / "enrollment").glob("*.api-servers")))

    killed_at = int(time.time())
    rig.stop(first)
    leader = wait_for("leader election after process death", rig.leader)
    if leader == first:
        raise RuntimeError("dead server remained leader")
    follower = next(node for node in range(1, 4) if node not in (first, leader))

    def follower_redirects():
        try:
            rig.request(follower, f"/agents/{agent_id}/heartbeat", b"{}", rig.worker_credential())
        except urllib.error.HTTPError as error:
            with error:
                return error.code == 503 and json.load(error).get("leader") == f"10.233.0.{leader}:7700"
        return False

    wait_for("surviving follower learns the elected leader", follower_redirects)
    wait_for("committed heartbeat after leader loss",
             lambda: any(item["id"] == agent_id and item["last_heartbeat"] > killed_at
                         for item in rig.request(leader, "/agents")))
    registry = HeldRegistry()
    try:
        sql = ("INSERT INTO assignments (id, agent_id, image, command, status, workload_kind, created_at) "
               f"VALUES ('a11ce0000001', '{agent_id}', '10.233.0.254:5000/missing:latest', '', 'pending', 'worker', {int(time.time())});")
        rig.request(leader, "/cluster/propose", sql.encode())
        wait_for("assignment received after leader loss", registry.connected.is_set)
        rig.run(*rig.inside(4, "iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "7700", "-j", "REJECT"))
        registry.release.set()
        pending = wait_for("durable undelivered terminal report",
                           lambda: [row for row in rig.reports() if row[:3] == ("a11ce0000001", "failed", 0)])[0]
        rig.stop(4)
        if pending not in rig.reports():
            raise RuntimeError("the terminal report did not survive agent process death")
        connections_before_restart = registry.connections
        # restart with the original, dead seed. both credentials and alternate
        # endpoints must come from the existing enrollment files.
        rig.start(4, "join", seed, "--port", "7700", "--token", rig.token)
        rig.run(*rig.inside(4, "iptables", "-D", "OUTPUT", "-p", "tcp", "--dport", "7700", "-j", "REJECT"))
        terminal = wait_for("committed result after agent restart", lambda: [item for item in rig.request(leader, f"/agents/{agent_id}/assignments", credential=rig.worker_credential()) if item["id"] == "a11ce0000001" and item["status"] == "failed"])
        if terminal[0]["generation"] != pending[3] or terminal[0]["status_reason"] != pending[5]:
            raise RuntimeError("the committed result differs from the persisted terminal report")

        def acknowledged_or_retired():
            rows = [row for row in rig.reports() if row[0] == pending[0]]
            return not rows or rows == [pending[:2] + (1,) + pending[3:]]

        wait_for("outbox acknowledgment or confirmed retirement", acknowledged_or_retired)
        if registry.connections != connections_before_restart:
            raise RuntimeError("agent restart repeated the completed image pull")
        current = rig.request(leader, "/agents")
        if [item["id"] for item in current] != [agent_id]:
            raise RuntimeError("agent restart changed the enrollment identity")
        rig.start_server(first)
        wait_for("restarted voter catches up", lambda: rig.request(first, "/cluster/status")["last_applied"] >= rig.request(leader, "/cluster/status")["commit_index"])
        (rig.artifacts / "result.json").write_text(json.dumps({"agent_id": agent_id, "killed_leader": first, "surviving_leader": leader, "terminal_assignment": terminal}, indent=2))
        print("leader loss, assignment delivery, agent restart, and durable result recovery passed")
    finally:
        registry.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get("YOQ_RECOVERY_ISOLATED") != "1":
        raise SystemExit("run through scripts/agent-recovery-smoke.sh in its private namespaces")
    rig = Rig(args.binary, args.artifacts)
    try:
        exercise(rig)
        if os.environ.get("YOQ_RECOVERY_BUNDLES") == "1":
            from bundle_recovery import exercise_bundles
            exercise_bundles(rig)
    except Exception:
        for path in sorted(rig.artifacts.glob("*.log")):
            print(f"--- {path.name} ---", flush=True)
            print(path.read_text(errors="replace")[-6000:], flush=True)
        raise
    finally:
        rig.cleanup()


if __name__ == "__main__":
    main()
