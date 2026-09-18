#!/usr/bin/env python3
"""exercise credential forwarding and failure cleanup without touching a vm."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "infra/gcp/remote/install-yoq.sh"


class RemoteInstall(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="yoq-install-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.token = "test-only-credential"
        self.env = os.environ | {
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "TMPDIR": str(self.root),
            "FIXTURE_ROOT": str(self.root),
        }
        self.command("gh", """#!/usr/bin/env bash
set -eu
[[ "$*" == 'auth status --hostname github.com' ]]
[[ "$GH_TOKEN" == test-only-credential ]]
printf '%s\\n' "$*" >> "$FIXTURE_ROOT/arguments"
""")
        self.command("curl", """#!/usr/bin/env bash
set -eu
printf '%s\\n' "$*" >> "$FIXTURE_ROOT/arguments"
[[ "${FAIL_DOWNLOAD:-}" != yes ]] || exit 22
while [[ "$1" != -o ]]; do shift; done
printf '%s\\n' '#!/usr/bin/env bash' \\
  '[[ "$GH_TOKEN" == test-only-credential ]]' \\
  'touch "$FIXTURE_ROOT/installed"' > "$2"
""")

    def command(self, name, source):
        path = self.bin / name
        path.write_text(source)
        path.chmod(0o700)

    def install(self, token=None, url="https://example.invalid/install"):
        return subprocess.run(
            ["bash", "-x", str(INSTALLER), url],
            input=(self.token if token is None else token) + "\n",
            text=True, capture_output=True, env=self.env, check=False,
        )

    def assert_clean(self, result):
        self.assertNotIn(self.token, result.stdout + result.stderr)
        self.assertEqual([], list(self.root.glob("tmp.*")))
        args = self.root / "arguments"
        if args.exists():
            self.assertNotIn(self.token, args.read_text())

    def test_installer_inherits_token_without_putting_it_in_arguments(self):
        result = self.install()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue((self.root / "installed").exists())
        self.assert_clean(result)

    def test_download_failure_cleans_the_private_script(self):
        self.env["FAIL_DOWNLOAD"] = "yes"
        result = self.install()
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((self.root / "installed").exists())
        self.assert_clean(result)

    def test_missing_token_stops_before_downloading(self):
        result = self.install(token="")
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((self.root / "arguments").exists())
        self.assert_clean(result)

    def test_plain_http_installer_is_rejected(self):
        result = self.install(url="http://example.invalid/install")
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((self.root / "arguments").exists())
        self.assert_clean(result)


if __name__ == "__main__":
    unittest.main()
