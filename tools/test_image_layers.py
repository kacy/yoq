#!/usr/bin/env python3
"""Compare native yoq layer mounts with umoci's independent OCI unpacker.

Run the compiled src/test_image_layers.zig helper with root privileges. Every
archive, mountpoint and oracle image lives in a disposable temporary directory;
mounting occurs inside the helper's private mount namespace, without pivot_root.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import shutil
import tarfile
import tempfile


def run(*args, **options):
    result = subprocess.run(list(map(str, args)), capture_output=True, timeout=30, **options)
    if result.returncode != 0:
        raise RuntimeError(f"{args}: {result.stderr.decode()}")
    return result


def archive(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as stream:
        for name, content in entries:
            header = tarfile.TarInfo(name)
            header.size = len(content)
            header.mode = 0o755 if name.endswith("/") else 0o644
            if name.endswith("/"):
                header.type = tarfile.DIRTYPE
            stream.addfile(header, io.BytesIO(content.encode()))
    return output.getvalue()


def write_image(directory, layers):
    (directory / "blobs/sha256").mkdir(parents=True)

    def blob(data, media_type):
        digest = hashlib.sha256(data).hexdigest()
        (directory / "blobs/sha256" / digest).write_bytes(data)
        return {"mediaType": media_type, "digest": "sha256:" + digest, "size": len(data)}

    config = {"architecture": "amd64", "os": "linux", "config": {}, "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest() for layer in layers]}}
    config_descriptor = blob(json.dumps(config).encode(), "application/vnd.oci.image.config.v1+json")
    manifest = {"schemaVersion": 2, "config": config_descriptor, "layers": [blob(gzip.compress(layer), "application/vnd.oci.image.layer.v1.tar+gzip") for layer in layers]}
    reference = blob(json.dumps(manifest).encode(), "application/vnd.oci.image.manifest.v1+json")
    reference["annotations"] = {"org.opencontainers.image.ref.name": "fixture"}
    (directory / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [reference]}))
    (directory / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')


def contents(root):
    return {str(path.relative_to(root)): path.read_text() for path in root.rglob("*") if path.is_file()}


def view(binary, directory, base, top):
    for name in ("upper", "work", "merged"):
        (directory / name).mkdir()
    return json.loads(run(binary, "mount", base, top, directory / "upper", directory / "work", directory / "merged").stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--umoci", default="umoci")
    options = parser.parse_args()
    binary = options.binary.resolve()
    if os.geteuid() != 0:
        raise SystemExit("native OverlayFS fixture requires root")
    base_entries = [("patched", "old"), ("removed", "old"), ("opaque/old", "old"), ("merge/old", "old"), ("replace-dir/old", "old"), ("survivor", "base"), ("recreated-file", "old")]
    top_entries = [("patched", "new"), (".wh.removed", ""), ("opaque/new", "new"), ("opaque/.wh..wh..opq", ""), (".wh.replace-dir", ""), ("replace-dir/new", "new"), ("recreated-file", "new"), (".wh.recreated-file", ""), ("merge/new", "new")]
    cases = [top_entries, list(reversed(top_entries)), [("new", "new"), (".wh..wh..opq", "")]]
    with tempfile.TemporaryDirectory(prefix="yoq-layer-interop-") as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        shutil.copy2(binary, root / "fixture")
        binary = root / "fixture"
        binary.chmod(0o755)
        for index, top in enumerate(cases):
            case = root / str(index)
            case.mkdir()
            layers = [archive(base_entries), archive(top)]
            extracted = []
            for number, data in enumerate(layers):
                compressed = case / f"{number}.tar.gz"
                compressed.write_bytes(gzip.compress(data))
                destination = case / f"layer-{number}"
                destination.mkdir()
                run(binary, "extract", compressed, destination)
                extracted.append(destination)
            image = case / "image"
            write_image(image, layers)
            oracle = case / "oracle"
            run(options.umoci, "raw", "unpack", "--image", str(image) + ":fixture", oracle)
            actual = view(binary, case, *extracted)
            assert actual == contents(oracle), (actual, contents(oracle))
            assert all(not Path(path).name.startswith(".wh.") for path in actual)
            # Export native metadata and unpack it with an independent engine.
            exported = case / "exported.tar"
            run(binary, "export", extracted[1], exported)
            roundtrip_image = case / "roundtrip-image"
            write_image(roundtrip_image, [layers[0], exported.read_bytes()])
            roundtrip = case / "roundtrip"
            run(options.umoci, "raw", "unpack", "--image", str(roundtrip_image) + ":fixture", roundtrip)
            assert contents(roundtrip) == actual
            print(f"passed: OCI overlay and exported layer match umoci, case {index}")

        generic = root / "generic"
        generic.mkdir()
        marker_archive = root / "markers.tar.gz"
        marker_archive.write_bytes(gzip.compress(archive([(".wh.removed", ""), ("opaque/.wh..wh..opq", "")])))
        run(binary, "generic", marker_archive, generic)
        assert ".wh.removed" in contents(generic)
        print("passed: generic archives retain OCI-looking names")

        rootless = root / "rootless"
        rootless.mkdir()
        os.chown(rootless, 65534, 65534)
        rejected = subprocess.run([str(binary), "extract", str(marker_archive), str(rootless)], user=65534, group=65534, extra_groups=[], capture_output=True, timeout=15)
        assert rejected.returncode != 0 and b"WhiteoutRequiresPrivilege" in rejected.stderr, rejected.stderr.decode()
        assert not contents(rootless)
        print("passed: unprivileged image whiteouts fail explicitly")

        invalid = root / "invalid.tar.gz"
        invalid.write_bytes(gzip.compress(archive([(".wh.removed", "nonempty")])))
        rejected = subprocess.run([str(binary), "extract", str(invalid), str(rootless)], capture_output=True, timeout=15)
        assert rejected.returncode != 0 and b"InvalidWhiteout" in rejected.stderr
        print("passed: malformed whiteout is rejected")


if __name__ == "__main__":
    main()
