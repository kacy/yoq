#!/usr/bin/env python3
"""Exercise production TLS client/server against the system OpenSSL library."""
import pathlib
import socket
import ssl
import subprocess
import tempfile
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run_case(binary, cert, key, mode, compatibility):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if mode == "client" else ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_ecdh_curve("X25519")
    if not compatibility:
        context.options &= ~ssl.OP_ENABLE_MIDDLEBOX_COMPAT
    if mode == "client":
        context.load_cert_chain(cert, key)
        context.num_tickets = 0
    else:
        context.check_hostname = False
        context.load_verify_locations(cert)
    local, peer = socket.socketpair()
    peer.settimeout(8)
    with local, peer, open(cert, "rb") as cert_file, open(key, "rb") as key_file:
        process = subprocess.Popen(
            [str(binary), mode, str(local.fileno()), str(cert_file.fileno()), str(key_file.fileno())],
            pass_fds=(local.fileno(), cert_file.fileno(), key_file.fileno()),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        local.close()
        try:
            with context.wrap_socket(peer, server_side=mode == "client") as tls:
                if mode == "client":
                    assert tls.recv(4) == b"ping"
                    tls.sendall(b"pong")
                else:
                    tls.sendall(b"ping")
                    assert tls.recv(4) == b"pong"
            _, stderr = process.communicate(timeout=8)
            assert process.returncode == 0, stderr.decode()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    print(f"passed: yoq {mode}, OpenSSL compatibility CCS {compatibility}")


def run_relay(binary, cert, key):
    """Large, coalesced application records traverse the actual relay intact."""
    payload = bytes(range(256)) * 512
    response = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(8)
    errors = []

    def backend():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(8)
                received = b""
                while b"\r\n\r\n" not in received:
                    received += connection.recv(16384)
                headers, body = received.split(b"\r\n\r\n", 1)
                assert b"X-Forwarded-Proto: https" in headers
                while len(body) < len(payload):
                    chunk = connection.recv(16384)
                    assert chunk, "relay truncated request"
                    body += chunk
                assert body == payload
                connection.sendall(response)
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=backend)
    worker.start()
    local, peer = socket.socketpair()
    peer.settimeout(8)
    with listener, local, peer, open(cert, "rb") as cert_file, open(key, "rb") as key_file:
        process = subprocess.Popen(
            [str(binary), "relay", str(local.fileno()), str(cert_file.fileno()), str(key_file.fileno()), str(listener.getsockname()[1])],
            pass_fds=(local.fileno(), cert_file.fileno(), key_file.fileno()),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        local.close()
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.set_ecdh_curve("X25519")
            context.load_verify_locations(cert)
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            tls = context.wrap_bio(incoming, outgoing)

            def flush():
                data = outgoing.read()
                # Split record headers as well as ciphertext; TCP does not
                # preserve the record boundaries supplied to sendall.
                for offset in range(0, len(data), 123):
                    peer.sendall(data[offset:offset + 123])

            while True:
                try:
                    tls.do_handshake()
                    flush()
                    break
                except ssl.SSLWantReadError:
                    flush()
                    incoming.write(peer.recv(65536))
            request = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload
            tls.write(request)
            flush()
            received = b""
            while len(received) < len(response):
                try:
                    received += tls.read(65536)
                except ssl.SSLWantReadError:
                    encrypted = peer.recv(65536)
                    assert encrypted, "relay truncated response"
                    incoming.write(encrypted)
            assert received == response
            _, stderr = process.communicate(timeout=8)
            assert process.returncode == 0, stderr.decode()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            worker.join(timeout=9)
    assert not worker.is_alive()
    assert not errors, errors
    print("passed: fragmented TLS relay, 128 KiB request and response")


def run_header_limit(binary, cert, key, protocol):
    """Incomplete HTTP/1 headers and HTTP/2 frames cannot retain over 64 KiB."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    local, peer = socket.socketpair()
    peer.settimeout(8)
    with listener, local, peer, open(cert, "rb") as cert_file, open(key, "rb") as key_file:
        process = subprocess.Popen(
            [str(binary), "relay", str(local.fileno()), str(cert_file.fileno()), str(key_file.fileno()), str(listener.getsockname()[1])],
            pass_fds=(local.fileno(), cert_file.fileno(), key_file.fileno()),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        local.close()
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.set_ecdh_curve("X25519")
            context.load_verify_locations(cert)
            context.set_alpn_protocols([protocol])
            with context.wrap_socket(peer) as tls:
                prefix = b"GET / HTTP/1.1\r\nX-Incomplete: "
                if protocol == "h2":
                    prefix = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + (100000).to_bytes(3, "big") + b"\x01\x04\x00\x00\x00\x01"
                try:
                    tls.sendall(prefix + b"x" * (70 * 1024))
                    assert tls.recv(1) == b""
                except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
                    pass
            _, stderr = process.communicate(timeout=8)
            assert process.returncode != 0 and b"RequestTooLarge" in stderr, stderr.decode()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    print(f"passed: bounded incomplete {protocol} request")


def main():
    with tempfile.TemporaryDirectory(prefix="yoq-tls-interop-") as directory:
        path = pathlib.Path(directory)
        cert, key, binary = path / "cert.pem", path / "key.pem", path / "interop"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost",
        ], check=True, capture_output=True)
        subprocess.run([
            "zig", "build-exe", "-lc", "--dep", "linux_platform", "-Mroot=src/test_tls_interop.zig",
            "-Mlinux_platform=src/lib/linux_platform.zig", f"-femit-bin={binary}",
        ], cwd=ROOT, check=True)
        for mode in ("client", "server"):
            for compatibility in (False, True):
                run_case(binary, cert, key, mode, compatibility)
        run_relay(binary, cert, key)
        for protocol in ("http/1.1", "h2"):
            run_header_limit(binary, cert, key, protocol)


if __name__ == "__main__":
    main()
