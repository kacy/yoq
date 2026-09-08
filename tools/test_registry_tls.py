#!/usr/bin/env python3
"""Compare production registry pulls against a disposable TLS registry."""
import argparse
import gzip
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def blobs():
    layers, contents, diff_ids = [], {}, []
    for index in range(3):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as tar:
            data = f"layer {index}".encode()
            entry = tarfile.TarInfo(f"layer-{index}")
            entry.size = len(data)
            tar.addfile(entry, io.BytesIO(data))
        raw = archive.getvalue()
        data = gzip.compress(raw, mtime=0)
        contents[digest(data)] = data
        diff_ids.append(digest(raw))
        layers.append({"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": digest(data), "size": len(data)})
    config = encoded({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": diff_ids}, "config": {}})
    contents[digest(config)] = config
    manifest = encoded({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(config), "size": len(config)},
                        "layers": layers})
    return manifest, contents


def inside(binary, root, outer_namespace):
    assert os.readlink("/proc/self/ns/mnt") != outer_namespace
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    cert, key = root / "ca.pem", root / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost"], check=True, capture_output=True)
    manifest, contents = blobs()
    requests = []

    class Registry(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            if self.path == "/v2/":
                data = b"{}"
            elif self.path == "/v2/fixture/manifests/" + digest(manifest):
                data = manifest
            else:
                data = contents.get(self.path.removeprefix("/v2/fixture/blobs/"))
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

    def pull(host, home):
        home.mkdir()
        image = f"{host}:{server.server_port}/fixture@{digest(manifest)}"
        return subprocess.run([str(binary), image], env=dict(os.environ, HOME=str(home)), capture_output=True, timeout=30)

    try:
        rejected = pull("localhost", root / "untrusted")
        assert rejected.returncode == 2, rejected.stderr.decode()
        assert b"registry pull rejected: NetworkError" in rejected.stderr
        assert not requests, "untrusted TLS peer received an HTTP request"
        subprocess.run(["mount", "--bind", str(cert), "/etc/ssl/certs/ca-certificates.crt"], check=True)
        wrong_host = pull("127.0.0.1", root / "wrong-host")
        assert wrong_host.returncode == 2, wrong_host.stderr.decode()
        assert not requests, "certificate for another hostname was accepted"
        accepted = pull("localhost", root / "trusted")
        assert accepted.returncode == 0, accepted.stderr.decode()
        assert set(requests) == {"/v2/", "/v2/fixture/manifests/" + digest(manifest),
                                 *("/v2/fixture/blobs/" + key for key in contents)}, requests
        for key, data in contents.items():
            if key == json.loads(manifest)["config"]["digest"]:
                continue
            cached = root / "trusted/.local/share/yoq/blobs/sha256" / key.split(":")[1]
            assert cached.read_bytes() == data
        print("registry TLS: untrusted and wrong-host rejected; trusted manifest, config, and parallel layers verified", flush=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--inside", type=Path)
    parser.add_argument("--outer-namespace")
    args = parser.parse_args()
    if args.inside:
        inside(args.binary.resolve(), args.inside, args.outer_namespace)
        return
    if os.geteuid() != 0:
        raise SystemExit("registry TLS fixture requires a private mount namespace (run as root)")
    with tempfile.TemporaryDirectory(prefix="yoq-registry-tls-") as directory:
        subprocess.run(["unshare", "--mount", sys.executable, str(Path(__file__).resolve()),
                        "--binary", str(args.binary.resolve()), "--inside", directory,
                        "--outer-namespace", os.readlink("/proc/self/ns/mnt")], check=True)


if __name__ == "__main__":
    main()
