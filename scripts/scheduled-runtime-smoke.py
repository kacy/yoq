#!/usr/bin/env python3
"""Exercise scheduled OCI execution and readiness in disposable Linux namespaces."""

import concurrent.futures
import gzip
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import secrets
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request

REPO = Path(__file__).resolve().parent.parent
YOQ = REPO / "zig-out/bin/yoq"
HELPER = REPO / "zig-out/bin/yoq-test-http-server"


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode()


def image_blobs():
    # A real, nonempty OCI layer containing only the static fixture server.
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in ("bin", "etc", "dev", "proc", "sys", "tmp", "run"):
            entry = tarfile.TarInfo(name)
            entry.type = tarfile.DIRTYPE
            entry.mode = 0o755
            archive.addfile(entry)
        archive.add(HELPER, arcname="bin/yoq-test-http-server", recursive=False)
    layer = gzip.compress(tar_bytes.getvalue(), mtime=0)
    config = encode({
        "architecture": "amd64", "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": [digest(tar_bytes.getvalue())]},
        "config": {
            "Entrypoint": ["/bin/yoq-test-http-server"],
            "Cmd": ["8080", "scheduled-ready", "5"],
            "User": "65534:65534", "WorkingDir": "/", "Env": ["PATH=/bin"],
        },
    })
    manifest = encode({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(config), "size": len(config)},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": digest(layer), "size": len(layer)}],
    })
    return manifest, {digest(config): config, digest(layer): layer}


def start_registry(cert, key):
    manifest, blobs = image_blobs()

    class Registry(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/v2/":
                data = b"{}"
            elif self.path == "/v2/fixture/manifests/" + digest(manifest):
                data = manifest
            elif self.path.startswith("/v2/fixture/blobs/"):
                data = blobs.get(self.path.rsplit("/", 1)[1])
            else:
                data = None
            if data is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Type", "application/vnd.oci.image.manifest.v1+json" if data is manifest else "application/octet-stream")
            self.send_header("Docker-Content-Digest", digest(data))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Registry)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"127.0.0.1:{server.server_port}/fixture@{digest(manifest)}"


def wait_for(description, operation, timeout=45):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            result = operation()
            if result:
                return result
        except (OSError, urllib.error.URLError, sqlite3.Error) as error:
            last_error = error
        time.sleep(0.1)
    raise AssertionError(f"timed out waiting for {description}: {last_error}")


def inside(root, outer_mount, outer_net):
    # Refuse private trust mounting unless the wrapper actually isolated us.
    assert os.readlink("/proc/self/ns/mnt") != outer_mount
    assert os.readlink("/proc/self/ns/net") != outer_net
    run("mount", "--make-rprivate", "/")
    run("ip", "link", "set", "lo", "up")
    cert, key = root / "cert.pem", root / "key.pem"
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-keyout", str(key), "-out", str(cert), "-subj", "/CN=127.0.0.1",
        "-addext", "subjectAltName=IP:127.0.0.1", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run("mount", "--bind", str(cert), "/etc/ssl/certs/ca-certificates.crt")
    registry, image = start_registry(cert, key)
    processes = []
    logs = []
    homes = {}
    token, enrollment = secrets.token_hex(32), secrets.token_hex(32)
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def api(path, body=None):
        request = urllib.request.Request("http://127.0.0.1:17700" + path,
                                         data=encode(body) if body is not None else None,
                                         headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        with client.open(request, timeout=40) as response:
            return json.load(response)

    def spawn(name, args):
        home = root / name
        home.mkdir()
        homes[name] = home
        output = open(root / (name + ".log"), "w")
        logs.append(output)
        env = dict(os.environ, HOME=str(home), XDG_DATA_HOME=str(home))
        processes.append(subprocess.Popen([str(YOQ), *args], env=env, stdout=output, stderr=output))

    def container_row():
        path = homes["agent"] / ".local/share/yoq/yoq.db"
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
            db.row_factory = sqlite3.Row
            return db.execute("SELECT id, pid, ip_address FROM containers WHERE hostname='web' AND pid IS NOT NULL").fetchone()

    try:
        spawn("server", ["init-server", "--id", "1", "--port", "19700", "--api-port", "17700",
                         "--peers", "", "--token", enrollment, "--api-token", token])
        wait_for("server API", lambda: api("/agents") == [])
        # Let the single voter elect itself before enrollment.
        time.sleep(2)
        spawn("agent", ["join", "127.0.0.1", "--port", "17700", "--agent-port", "17701",
                        "--token", enrollment, "--role", "agent"])
        agents = wait_for("registered agent", lambda: api("/agents"))
        agent_id = agents[0]["id"]
        body = {"app_name": "scheduled-fixture", "services": [{
            "name": "web", "image": image, "cpu_limit": 250, "memory_limit_mb": 64,
            "health_check": {"kind": "http", "path": "/", "port": 8080, "interval": 1, "timeout": 1, "retries": 20},
            "rollout": {"health_check_timeout": 30},
        }]}
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            apply = pool.submit(api, "/apps/apply", body)
            row = wait_for("scheduled container process", container_row)
            assert row["ip_address"], "scheduled container has no routed IP"
            assignments = api(f"/agents/{agent_id}/assignments")
            assert assignments[0]["status"] == "pending", assignments
            assert not apply.done(), "apply completed before the delayed service became ready"
            url = f"http://{row['ip_address']}:8080/"

            def reachable():
                with client.open(url, timeout=1) as response:
                    return response.read() == b"scheduled-ready"

            wait_for("HTTP across the container network", reachable)
            result = apply.result(timeout=35)
            assert result.get("status") == "completed", result
            assignments = api(f"/agents/{agent_id}/assignments")
            assert assignments[0]["status"] == "running", assignments
            status = Path(f"/proc/{row['pid']}/status").read_text()
            assert "Uid:\t65534\t65534\t65534\t65534" in status, status
            cgroup = Path("/sys/fs/cgroup/yoq") / row["id"]
            assert (cgroup / "cpu.max").read_text().strip() == "25000 100000"
            assert (cgroup / "memory.max").read_text().strip() == str(64 * 1024 * 1024)
            run(str(YOQ), "stop", "web", env=dict(os.environ, HOME=str(homes["agent"])), stdout=subprocess.DEVNULL)
            wait_for("assignment exit", lambda: api(f"/agents/{agent_id}/assignments")[0]["status"] == "stopped")
        print("scheduled runtime: OCI pull, readiness, routed HTTP, identity, limits, and exit passed", flush=True)
    finally:
        for process in reversed(processes):
            process.terminate()
        for process in reversed(processes):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        registry.shutdown()
        registry.server_close()
        for output in logs:
            output.close()
        for name in homes:
            print(f"--- {name} log ---\n{(root / (name + '.log')).read_text()}", flush=True)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--inside":
        inside(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
        return
    if os.geteuid() != 0:
        raise SystemExit("scheduled runtime fixture requires root")
    if not YOQ.is_file() or not HELPER.is_file():
        raise SystemExit("build yoq and the runtime-network helper before running this fixture")
    with tempfile.TemporaryDirectory(prefix="yoq-scheduled-", dir=os.environ.get("RUNNER_TEMP")) as directory:
        try:
            run("unshare", "--mount", "--net", "--pid", "--fork", "--mount-proc", sys.executable,
                str(Path(__file__).resolve()), "--inside", directory,
                os.readlink("/proc/self/ns/mnt"), os.readlink("/proc/self/ns/net"))
        finally:
            # The PID namespace has exited, so its tasks are already gone.
            # Remove only empty cgroups named by this fixture's private database.
            database = Path(directory) / "agent/.local/share/yoq/yoq.db"
            if database.exists():
                with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as db:
                    for (container_id,) in db.execute("SELECT id FROM containers"):
                        if len(container_id) == 12 and all(c in "0123456789abcdef" for c in container_id):
                            cgroup = Path("/sys/fs/cgroup/yoq") / container_id
                            if cgroup.exists():
                                cgroup.rmdir()


if __name__ == "__main__":
    main()
