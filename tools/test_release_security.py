import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

from release_metadata import documents, sqlite_dependency
from security_gate import action_commits, lookup, sqlite_findings, sqlite_triage, SQLITE_REPOSITORY

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
            self.assertEqual(action_commits(root), {('actions/checkout', 'a' * 40)})
            (root / '.github/other.yaml').write_text('steps:\n  - uses: actions/checkout@' + 'b' * 40 + '\n')
            self.assertEqual(len(action_commits(root)), 2)
            (root / '.github/other.yaml').write_text('steps:\n  - uses: actions/checkout@v4\n')
            with self.assertRaises(ValueError):
                action_commits(root)

    @staticmethod
    def sqlite_advisory(identifier, events):
        return {'id': identifier, 'affected': [{'ranges': [{
            'type': 'GIT', 'repo': SQLITE_REPOSITORY,
            'database_specific': {'extracted_events': events},
        }], 'versions': ['version-3.49.0']}]}

    def test_sqlite_maintenance_release_is_checked_against_known_advisory_intervals(self):
        # These are the published OSV intervals. The incomplete Git version
        # list deliberately omits the affected maintenance release 3.49.2.
        advisories = [
            self.sqlite_advisory('CVE-2025-6965', [{'introduced': '0'}, {'fixed': '3.50.2'}]),
            self.sqlite_advisory('CVE-2026-11822', [{'introduced': '0'}, {'fixed': '3.53.2'}]),
        ]
        self.assertEqual([v['id'] for v in sqlite_findings('3.49.2', advisories)],
                         ['CVE-2025-6965', 'CVE-2026-11822'])
        self.assertEqual([v['id'] for v in sqlite_findings('3.50.2', advisories)],
                         ['CVE-2026-11822'])
        self.assertEqual(sqlite_findings('3.53.2', advisories), [])
        self.assertEqual(sqlite_findings('3.53.4', advisories), [])

    def test_sqlite_inclusive_intervals_and_unmapped_records(self):
        advisory = self.sqlite_advisory('CVE-2021-45346', [
            {'introduced': '3.35.1'}, {'last_affected': '3.35.1'},
            {'introduced': '3.37.0'}, {'last_affected': '3.37.0'},
        ])
        for version in ['3.35.1', '3.37.0']:
            self.assertEqual(sqlite_findings(version, [advisory]), [advisory])
        self.assertEqual(sqlite_findings('3.35.2', [advisory]), [])
        with self.assertRaises(ValueError):
            sqlite_findings('3.53.4', [])
        for events in [None, [{'introduced': 'unknown'}], [{'fixed': '3.50.2'}],
                       [{'introduced': '3.50.0'}, {'fixed': '3.49.0'}]]:
            with self.subTest(events=events), self.assertRaises(ValueError):
                sqlite_findings('3.53.4', [self.sqlite_advisory('unmapped', events)])

    def test_sqlite_source_review_is_bound_to_version_and_build_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tools').mkdir()
            build = root / 'build.zig'
            build.write_text('fixed build configuration')
            reasons = {'extension-only': 'the optional extension is not compiled'}
            triage = {'sqlite_version': '3.53.4',
                      'build_sha256': hashlib.sha256(build.read_bytes()).hexdigest(),
                      'not_affected': reasons}
            (root / 'tools/sqlite_advisory_triage.json').write_text(json.dumps(triage))
            self.assertEqual(sqlite_triage(root, '3.53.4'), reasons)
            unknown = self.sqlite_advisory('extension-only', None)
            self.assertEqual(sqlite_findings('3.53.4', [unknown], sqlite_triage(root, '3.53.4')), [])
            with self.assertRaises(ValueError):
                sqlite_triage(root, '3.49.2')
            build.write_text('now enable the optional extension')
            with self.assertRaises(ValueError):
                sqlite_triage(root, '3.53.4')

    def test_osv_lookup_follows_pagination_and_rejects_repeated_tokens(self):
        query = {'package': {'name': SQLITE_REPOSITORY, 'ecosystem': 'GIT'}}
        pages = [{'next_page_token': 'page-2'},
                 {'vulns': [{'id': 'CVE-test'}], 'next_page_token': 'page-3'},
                 {'vulns': [{'id': 'CVE-test'}, {'id': 'withdrawn', 'withdrawn': '2026-01-01'}]}]
        with patch('security_gate.urllib.request.urlopen',
                   side_effect=[io.BytesIO(json.dumps(page).encode()) for page in pages]) as request:
            self.assertEqual(lookup(query), [{'id': 'CVE-test'}])
            bodies = [json.loads(call.args[0].data) for call in request.call_args_list]
            self.assertEqual(bodies, [query, dict(query, page_token='page-2'), dict(query, page_token='page-3')])
            self.assertNotIn('page_token', query)
        repeated = {'next_page_token': 'same'}
        with patch('security_gate.urllib.request.urlopen',
                   side_effect=[io.BytesIO(json.dumps(repeated).encode()) for _ in range(2)]):
            with self.assertRaises(ValueError):
                lookup(query)

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
