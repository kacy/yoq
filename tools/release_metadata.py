#!/usr/bin/env python3
"""Describe the exact release inputs and archive bytes using SPDX 2.3."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from datetime import datetime, timezone


def sqlite_dependency(root):
    manifest = (root / 'build.zig.zon').read_text()
    match = re.search(r'https://www.sqlite.org/(\d+)/sqlite-amalgamation-(\d{7})\.zip', manifest)
    if match is None:
        raise ValueError('unrecognized SQLite dependency; update release inventory')
    encoded = match[2]
    version = '.'.join(str(int(part)) for part in (encoded[:1], encoded[1:3], encoded[3:5]))
    vendored = (root / 'vendor/zig-sqlite/build.zig.zon').read_text()
    if match[0] not in vendored:
        raise ValueError('root and vendored SQLite sources disagree')
    return version, match[0]


def package(identifier, name, version, location):
    return {'SPDXID': identifier, 'name': name, 'versionInfo': version,
            'downloadLocation': location, 'filesAnalyzed': False,
            'licenseConcluded': 'NOASSERTION', 'licenseDeclared': 'NOASSERTION',
            'copyrightText': 'NOASSERTION'}


def documents(root, output, tag, commit, run):
    if not re.fullmatch(r'v\d+\.\d+\.\d+', tag):
        raise ValueError('invalid release tag')
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('invalid source commit')
    version, url = sqlite_dependency(root)
    artifacts = [{'name': p.name, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                 for p in sorted(output.glob('*.tar.gz'))]
    if not artifacts:
        raise ValueError('no release archives')
    if any(not a['name'].endswith('-' + tag + '.tar.gz') for a in artifacts):
        raise ValueError('archive name does not match release tag')
    provenance = {'schema': 'https://github.com/kacy/yoq/release-provenance/v1',
                  'invocation': {'tag': tag, 'commit': commit}, 'subject': artifacts}
    wrapper_tree = subprocess.check_output(
        ['git', 'rev-parse', commit + ':vendor/zig-sqlite'], cwd=root, text=True).strip()
    sbom = {
        'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0', 'SPDXID': 'SPDXRef-DOCUMENT',
        'name': 'yoq-' + tag,
        'documentNamespace': 'https://github.com/kacy/yoq/releases/' + tag + '/' + run,
        'creationInfo': {'created': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                         'creators': ['Tool: yoq-release-metadata']},
        'packages': [package('SPDXRef-yoq', 'yoq', tag[1:], 'https://github.com/kacy/yoq'),
                     package('SPDXRef-sqlite', 'sqlite', version, url),
                     package('SPDXRef-wrapper', 'zig-sqlite', 'git-tree-' + wrapper_tree, 'NOASSERTION')],
        'relationships': [
            {'spdxElementId': 'SPDXRef-DOCUMENT', 'relationshipType': 'DESCRIBES', 'relatedSpdxElement': 'SPDXRef-yoq'},
            {'spdxElementId': 'SPDXRef-yoq', 'relationshipType': 'DEPENDS_ON', 'relatedSpdxElement': 'SPDXRef-sqlite'},
            {'spdxElementId': 'SPDXRef-yoq', 'relationshipType': 'DEPENDS_ON', 'relatedSpdxElement': 'SPDXRef-wrapper'}],
        'files': [{'SPDXID': 'SPDXRef-archive-' + str(i), 'fileName': './' + a['name'],
                   'checksums': [{'algorithm': 'SHA256', 'checksumValue': a['sha256']}],
                   'licenseConcluded': 'NOASSERTION', 'copyrightText': 'NOASSERTION'}
                  for i, a in enumerate(artifacts)],
    }
    return provenance, sbom


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--run', required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    provenance, sbom = documents(root, args.output, args.tag, args.commit, args.run)
    for name, data in [('provenance.json', provenance), ('sbom.spdx.json', sbom)]:
        (args.output / name).write_text(json.dumps(data, indent=2) + '\n')


if __name__ == '__main__':
    main()
