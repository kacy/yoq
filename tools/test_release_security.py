import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

from release_metadata import documents, sqlite_dependency
from security_gate import action_commits

ROOT = Path(__file__).resolve().parents[1]


class ReleaseSecurityTests(unittest.TestCase):
    def test_inventory_includes_real_dependencies_and_archive_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            archive = output / 'yoq-linux-amd64-v1.2.3.tar.gz'
            archive.write_bytes(b'archive bytes')
            commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
            provenance, sbom = documents(ROOT, output, 'v1.2.3', commit, '42-2')
            self.assertEqual(provenance['invocation'], {'tag': 'v1.2.3', 'commit': commit})
            self.assertEqual(provenance['subject'][0]['sha256'], hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual({p['name'] for p in sbom['packages']}, {'yoq', 'sqlite', 'zig-sqlite'})
            self.assertTrue(sbom['documentNamespace'].endswith('/42-2'))
            self.assertEqual(sbom['files'][0]['checksums'][0]['checksumValue'], provenance['subject'][0]['sha256'])
            with self.assertRaises(ValueError):
                documents(ROOT, output, 'v9.9.9', commit, '43-1')

    def test_sqlite_manifests_must_agree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'vendor/zig-sqlite').mkdir(parents=True)
            (root / 'build.zig.zon').write_text('https://www.sqlite.org/2025/sqlite-amalgamation-3490200.zip')
            (root / 'vendor/zig-sqlite/build.zig.zon').write_text('different source')
            with self.assertRaises(ValueError):
                sqlite_dependency(root)

    def test_mutable_actions_fail_static_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.github').mkdir()
            workflow = root / '.github/workflow.yml'
            workflow.write_text('steps:\n  - uses: actions/checkout@v4\n')
            with self.assertRaises(ValueError):
                action_commits(root)
            workflow.write_text('steps:\n  - uses: actions/checkout@' + 'a' * 40 + '\n')
            self.assertEqual(action_commits(root), {'actions/checkout': 'a' * 40})

    def run_installer(self, failure):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'bin'
            binary.mkdir()
            log = root / 'calls'
            # All download, attestation, and install commands are local fakes.
            # The real checksum and metadata digest checks still execute.
            driver = '#!' + sys.executable + '\n' + textwrap.dedent('''\
                import hashlib, json, os, pathlib, sys
                tool = pathlib.Path(sys.argv[0]).name
                args = sys.argv[1:]
                with open(os.environ['RELEASE_TEST_LOG'], 'a') as log:
                    log.write(tool + ' ' + ' '.join(args) + '\\n')
                tag = 'v1.2.3'
                archive = 'yoq-linux-amd64-' + tag + '.tar.gz'
                payload = b'fake release archive'
                digest = hashlib.sha256(payload).hexdigest()
                failure = os.environ['RELEASE_TEST_FAILURE']
                if tool == 'uname':
                    print('x86_64' if '-m' in args else 'Linux')
                elif tool == 'id':
                    print('0')
                elif tool == 'curl':
                    if '-o' not in args:
                        print(json.dumps({'tag_name': tag}))
                    else:
                        target = pathlib.Path(args[args.index('-o') + 1])
                        if target.name.endswith('.sha256'):
                            target.write_text(digest + '  ' + archive + '\\n')
                        elif target.name == 'provenance.json':
                            target.write_text(json.dumps({'invocation': {'tag': 'v0.0.0' if failure == 'tag' else tag},
                                'subject': [{'name': archive, 'sha256': '0' * 64 if failure == 'digest' else digest}]}))
                        else:
                            target.write_bytes(payload)
                elif tool == 'gh':
                    artifact = args[2]
                    if failure == 'archive' and artifact.endswith('.tar.gz'):
                        sys.exit(1)
                    if failure == 'metadata' and artifact.endswith('provenance.json'):
                        sys.exit(1)
                ''')
            for tool in ['curl', 'gh', 'tar', 'mv', 'chmod', 'id', 'uname']:
                path = binary / tool
                path.write_text(driver)
                path.chmod(0o755)
            env = dict(os.environ, PATH=str(binary) + ':' + os.environ['PATH'],
                       RELEASE_TEST_LOG=str(log), RELEASE_TEST_FAILURE=failure)
            result = subprocess.run(['sh', str(ROOT / 'scripts/install.sh')], env=env, capture_output=True, text=True)
            return result.returncode, log.read_text()

    def test_installer_rejects_unsigned_or_mismatched_artifacts_before_extraction(self):
        for failure in ['archive', 'metadata', 'tag', 'digest']:
            with self.subTest(failure=failure):
                status, calls = self.run_installer(failure)
                self.assertNotEqual(status, 0)
                self.assertNotIn('\ntar ', calls)
                self.assertNotIn('\nmv ', calls)

    def test_installer_verifies_both_subjects_before_extraction(self):
        status, calls = self.run_installer('')
        self.assertEqual(status, 0)
        self.assertEqual(calls.count('gh attestation verify'), 2)
        self.assertIn('--signer-workflow kacy/yoq/.github/workflows/release.yml', calls)
        self.assertLess(calls.rindex('gh attestation verify'), calls.index('tar -xzf'))


if __name__ == '__main__':
    unittest.main()
