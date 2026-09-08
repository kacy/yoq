#!/usr/bin/env python3
"""Check production registry transfers against a disposable TLS registry."""
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
    parsed_manifest = json.loads(manifest)
    redirected_blobs = {"/redirected/config": parsed_manifest["config"]["digest"],
                        "/redirected/layer": parsed_manifest["layers"][0]["digest"]}
    redirects = {"/v2/fixture/blobs/" + key: path for path, key in redirected_blobs.items()}
    requests = []
    uploads = []
    short_upload_sizes = []
    short_upload_finished = threading.Event()
    upload_cases = ("relative", "absolute", "other-port", "bad-init", "bad-complete")

    class Registry(http.server.BaseHTTPRequestHandler):
        def empty_response(self, status, location=None):
            self.send_response(status)
            self.send_header("Content-Length", "0")
            if location is not None:
                self.send_header("Location", location)
            self.end_headers()

        def record_upload(self):
            data = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            uploads.append((self.command, self.server.server_port, self.path,
                            self.headers.get("Authorization"), data, self.headers.get("Content-Type")))

        def do_POST(self):
            self.record_upload()
            case = self.path.removeprefix("/v2/").removesuffix("/blobs/uploads/")
            if case not in upload_cases and case != "short-file":
                self.send_error(404)
                return
            location = f"/uploads/{case}?state=fixture%2Bstate&part=1"
            if case != "relative":
                port = other_server.server_port if case == "other-port" else server.server_port
                location = f"https://localhost:{port}{location}"
            self.empty_response(200 if case == "bad-init" else 202, location)

        def do_PUT(self):
            if self.path.startswith("/uploads/short-file?"):
                short_upload_sizes.append(int(self.headers["Content-Length"]))
                self.connection.settimeout(30)
                try:
                    # the client closes the connection when the file ends early.
                    while self.rfile.read1(8192):
                        pass
                except (ConnectionResetError, ssl.SSLEOFError):
                    pass
                short_upload_finished.set()
                return
            self.record_upload()
            self.empty_response(200 if self.path.startswith("/uploads/bad-complete?") else 201)

        def do_GET(self):
            requests.append(self.path)
            if self.path in redirects:
                location = redirects[self.path]
                if location == "/redirected/config":
                    location = f"https://localhost:{server.server_port}{location}"
                self.empty_response(307, location)
                return
            if self.path == "/v2/":
                data = b"{}"
            elif self.path == "/v2/fixture/manifests/" + digest(manifest):
                data = manifest
            elif self.path in redirected_blobs:
                data = contents[redirected_blobs[self.path]]
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

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    servers = []

    def start_server():
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Registry)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
        return server

    def pull(host, home):
        home.mkdir()
        image = f"{host}:{server.server_port}/fixture@{digest(manifest)}"
        return subprocess.run([str(binary), image], env=dict(os.environ, HOME=str(home)), capture_output=True, timeout=30)

    try:
        server = start_server()
        other_server = start_server()
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
                                 *("/v2/fixture/blobs/" + key for key in contents), *redirected_blobs}, requests
        for key, data in contents.items():
            if key == parsed_manifest["config"]["digest"]:
                continue
            cached = root / "trusted/.local/share/yoq/blobs/sha256" / key.split(":")[1]
            assert cached.read_bytes() == data

        # the file body crosses several streaming buffers and ends with a short chunk.
        for mode, data in (("upload-bytes", b"config upload\x00\xff"),
                           ("upload-file", bytes(range(256)) * 97 + b"tail"),
                           ("upload-bytes", b""), ("upload-file", b"")):
            source = root / mode
            source.write_bytes(data)
            for case in upload_cases:
                uploads.clear()
                result = subprocess.run([str(binary), mode, f"localhost:{server.server_port}", case,
                                         digest(data), str(source)], capture_output=True, timeout=30)
                failure = {"bad-init": b"UploadInitFailed", "bad-complete": b"UploadFailed"}.get(case)
                assert result.returncode == (2 if failure else 0), result.stderr.decode()
                if failure:
                    assert b"registry upload rejected: " + failure in result.stderr, result.stderr.decode()
                expected = [("POST", server.server_port, f"/v2/{case}/blobs/uploads/",
                             "Bearer fixture-token", b"", "application/octet-stream")]
                if case != "bad-init":
                    port = other_server.server_port if case == "other-port" else server.server_port
                    auth = None if case == "other-port" else "Bearer fixture-token"
                    expected.append(("PUT", port, f"/uploads/{case}?state=fixture%2Bstate&part=1&digest={digest(data)}",
                                     auth, data, "application/octet-stream"))
                assert uploads == expected, (mode, case, uploads)

        source = root / "short-file"
        data = bytes(range(256)) * 97
        source.write_bytes(data)
        result = subprocess.run([str(binary), "upload-file-short", f"localhost:{server.server_port}",
                                 "short-file", digest(data), str(source)], capture_output=True, timeout=30)
        assert result.returncode == 2, result.stderr.decode()
        assert b"registry upload rejected: UploadFailed" in result.stderr, result.stderr.decode()
        assert short_upload_finished.wait(30), "short upload connection did not close"
        assert short_upload_sizes == [len(data) + 1], short_upload_sizes
        print("registry TLS: certificate checks, parallel pulls, byte and file uploads, and upload auth verified", flush=True)
    finally:
        for server, thread in servers:
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
