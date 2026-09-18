"""restore the stopped process fixture into fresh fixed-voter data roots."""

import json
import subprocess
from pathlib import Path

from agent_recovery import wait_for


def exercise_bundles(rig):
    token_file = rig.artifacts / "join-token"
    token_file.write_text(rig.token)
    token_file.chmod(0o600)
    set_id = "process-recovery"

    def command(*arguments, reject=False):
        result = subprocess.run([rig.binary, "cluster", *map(str, arguments)],
                                capture_output=True, text=True, timeout=30)
        if (result.returncode != 0) != reject:
            raise RuntimeError(f"unexpected cluster command result: {result.stdout}{result.stderr}")
        return result

    # a running voter must refuse capture, including when it has no writes in flight.
    active = rig.artifacts / "active-voter"
    command("backup", active, "--data-dir", rig.data(1), "--set", set_id,
            "--join-token-file", token_file, reject=True)
    if active.exists():
        raise RuntimeError("active-voter rejection published a bundle")

    rig.stop(4)
    leader = wait_for("leader before coordinated capture", rig.leader)
    target = rig.request(leader, "/cluster/status")["commit_index"]
    for node in range(1, 4):
        wait_for(f"voter {node} applied capture boundary",
                 lambda node=node: rig.request(node, "/cluster/status")["last_applied"] >= target)
    for node in range(1, 4):
        rig.stop(node)

    bundles = []
    for node in range(1, 4):
        bundle = rig.artifacts / f"bundle-{node}"
        command("backup", bundle, "--data-dir", rig.data(node), "--set", set_id,
                "--join-token-file", token_file)
        command("verify", bundle)
        bundles.append(bundle)
    command("verify-set", "--set", set_id, *bundles)
    fingerprint = json.loads((bundles[0] / "manifest.json").read_text())["cluster_fingerprint"]

    # changing an artifact must fail verification before any destination is opened.
    token_copy = bundles[0] / "api_token"
    original = token_copy.read_bytes()
    token_copy.write_bytes(b"x" + original[1:])
    command("verify", bundles[0], reject=True)
    token_copy.write_bytes(original)

    for node, bundle in enumerate(bundles, 1):
        home = rig.artifacts / f"restored-{node}"
        destination = home / ".local/share/yoq"
        destination.parent.mkdir(parents=True, mode=0o700)
        arguments = ("restore", bundle, "--data-dir", destination, "--node-id", node,
                     "--voters", "1,2,3", "--set", set_id, "--cluster", fingerprint)
        command(*arguments)
        command(*arguments, reject=True)
        rig.restored_homes[node] = home
    for node in range(1, 4):
        rig.start_server(node)
    restored_leader = wait_for("leader in restored fixed-voter cluster", rig.leader)
    expected = json.loads((rig.artifacts / "result.json").read_text())
    agent_id = expected["agent_id"]

    def restored_assignment():
        return [item for item in rig.request(restored_leader, f"/agents/{agent_id}/assignments", credential=rig.worker_credential())
                if item["id"] == "a11ce0000001" and item["status"] == "failed"]

    wait_for("terminal assignment after cluster restore", restored_assignment)
    # the original enrollment belongs to the same restored cluster and still works.
    seed = f"10.233.0.{expected['killed_leader']}"
    rig.start(4, "join", seed, "--port", "7700", "--token", rig.token)
    agent_log = Path(rig.logs[-1].name)
    wait_for("agent rejoins restored cluster",
             lambda: f"registered as agent {agent_id}" in agent_log.read_text())
    if [item["id"] for item in rig.request(restored_leader, "/agents")] != [agent_id]:
        raise RuntimeError("cluster restore changed the enrollment identity")
    expected["restored_leader"] = restored_leader
    expected["cluster_fingerprint"] = fingerprint
    (rig.artifacts / "result.json").write_text(json.dumps(expected, indent=2))
    print("coordinated capture, corrupt bundle rejection, fresh restore, election, and enrollment passed")
