#!/usr/bin/env python3
"""Verify the native DNS listener accepts only container-bridge ingress."""
import argparse
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

QUERY = bytes.fromhex("123401000001000000000000") + b"\x07fixture\x00\x00\x01\x00\x01"


def query(address, expected):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.4)
        sock.sendto(QUERY, (address, 53))
        try:
            response, _ = sock.recvfrom(512)
        except TimeoutError:
            assert not expected, "bridge DNS did not answer"
            return
        assert expected, "DNS answered on an unrelated interface"
        assert response[:2] == QUERY[:2]
        assert struct.unpack("!H", response[6:8])[0] == 1
        assert response[-4:] == bytes((10, 42, 2, 9)), response


def run(*args):
    return subprocess.run(args, check=True, capture_output=True)


def inside(binary, outer):
    assert os.readlink("/proc/self/ns/net") != outer
    run("ip", "link", "set", "lo", "up")
    # Missing bridge must fail closed, before any wildcard listener exists.
    missing = subprocess.run([str(binary)], capture_output=True, timeout=3)
    assert missing.returncode != 0 and b"ResolverStartFailed" in missing.stderr, missing.stderr
    query("127.0.0.1", False)
    # Simulate the host stub resolver without touching any real host service.
    stub = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    stub.bind(("127.0.0.53", 53))
    stub.settimeout(1)
    run("ip", "link", "add", "yoq0", "type", "bridge")
    run("ip", "addr", "add", "10.42.2.1/24", "dev", "yoq0")
    run("ip", "addr", "add", "10.42.0.1/24", "dev", "yoq0")
    run("ip", "link", "set", "yoq0", "up")
    client = subprocess.Popen(["unshare", "--net", "sleep", "30"])
    server = None
    try:
        deadline = time.monotonic() + 2
        while os.readlink(f"/proc/{client.pid}/ns/net") == os.readlink("/proc/self/ns/net"):
            assert time.monotonic() < deadline
            time.sleep(0.01)
        prefix = ["nsenter", f"--net=/proc/{client.pid}/ns/net", "--"]
        run(*prefix, "ip", "link", "set", "lo", "up")
        for name, address, bridge in (("bridge", "10.42.2.2/24", True), ("outside", "192.0.2.2/24", False)):
            host, peer = name + "-host", name + "-peer"
            run("ip", "link", "add", host, "type", "veth", "peer", "name", peer)
            run("ip", "link", "set", peer, "netns", str(client.pid))
            if bridge:
                run("ip", "link", "set", host, "master", "yoq0")
            else:
                run("ip", "addr", "add", "192.0.2.1/24", "dev", host)
            run("ip", "link", "set", host, "up")
            run(*prefix, "ip", "addr", "add", address, "dev", peer)
            run(*prefix, "ip", "link", "set", peer, "up")
        run(*prefix, "ip", "addr", "add", "10.42.0.2/24", "dev", "bridge-peer")
        server = subprocess.Popen([str(binary)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 3
        while True:
            result = subprocess.run([*prefix, sys.executable, str(Path(__file__).resolve()), "--query", "10.42.2.1", "--expect"], capture_output=True)
            if result.returncode == 0:
                break
            if server.poll() is not None:
                raise AssertionError(server.stderr.read().decode())
            assert time.monotonic() < deadline, result.stderr
        run(*prefix, sys.executable, str(Path(__file__).resolve()), "--query", "10.42.0.1", "--expect")
        # Deliver a gateway-addressed packet through the unrelated interface:
        # explicit address binding alone would still accept this packet.
        run(*prefix, "ip", "route", "add", "10.42.2.1/32", "via", "192.0.2.1", "dev", "outside-peer")
        run(*prefix, sys.executable, str(Path(__file__).resolve()), "--query", "10.42.2.1")
        run(*prefix, "ip", "route", "del", "10.42.2.1/32")
        run(*prefix, sys.executable, str(Path(__file__).resolve()), "--query", "192.0.2.1")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.settimeout(1)
            probe.sendto(b"host-dns", ("127.0.0.53", 53))
            message, peer = stub.recvfrom(512)
            assert message == b"host-dns"
            stub.sendto(b"host-dns-ok", peer)
            assert probe.recv(512) == b"host-dns-ok"
        query("127.0.0.1", False)
        print("DNS kernel: local and node gateways coexist with host DNS; unrelated ingress and loopback rejected", flush=True)
    finally:
        stub.close()
        for process in (server, client):
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--inside")
    parser.add_argument("--query")
    parser.add_argument("--expect", action="store_true")
    args = parser.parse_args()
    if args.query:
        query(args.query, args.expect)
    elif args.inside:
        inside(args.binary.resolve(), args.inside)
    else:
        assert os.geteuid() == 0
        with tempfile.TemporaryDirectory(prefix="yoq-dns-bridge-") as home:
            subprocess.run(["unshare", "--net", sys.executable, str(Path(__file__).resolve()),
                            "--binary", str(args.binary.resolve()), "--inside", os.readlink("/proc/self/ns/net")],
                           env=dict(os.environ, HOME=home), check=True)


if __name__ == "__main__":
    main()
