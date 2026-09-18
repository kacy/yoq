#!/usr/bin/env python3
"""exercise the documented backup commands against disposable local state."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    binary = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="yoq-recovery-") as directory:
        root = Path(directory)
        # only the child processes use this home; the caller's state is untouched.
        environment = os.environ | {"HOME": str(root)}

        def run(*arguments, input=None, succeeds=True):
            result = subprocess.run(
                [str(binary), *map(str, arguments)], cwd=root,
                env=environment, input=input, capture_output=True,
                text=True, timeout=30, check=False,
            )
            if (result.returncode == 0) != succeeds:
                raise RuntimeError(f"{arguments[0]} returned {result.returncode}: {result.stderr}")
            return result.stdout.strip()

        archive = root / "before-upgrade.yoqbackup"
        run("secret", "set", "recovery-fixture", input="before")
        run("backup", "--output", archive)
        if archive.stat().st_mode & 0o077:
            raise RuntimeError("backup grants access to other users")
        run("secret", "set", "recovery-fixture", input="after")
        run("restore", "--verify", archive)
        if run("secret", "get", "recovery-fixture") != "after":
            raise RuntimeError("verification changed the live database")

        damaged = root / "damaged.yoqbackup"
        contents = bytearray(archive.read_bytes())
        contents[-1] ^= 1
        damaged.write_bytes(contents)
        run("restore", damaged, succeeds=False)
        if run("secret", "get", "recovery-fixture") != "after":
            raise RuntimeError("rejected backup changed the live database")

        run("restore", archive)
        if run("secret", "get", "recovery-fixture") != "before":
            raise RuntimeError("restored state did not survive reopening")
        print("backup and restore commands preserved verified state and rejected corruption")


if __name__ == "__main__":
    main()
