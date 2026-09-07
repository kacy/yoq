#!/usr/bin/env python3
"""Check action pins and query OSV for build dependencies; fail on lookup errors."""
import hashlib
import json
from pathlib import Path
import re
import urllib.request
from release_metadata import sqlite_dependency


def action_commits(root):
    commits = set()
    for path in (root / '.github').rglob('*'):
        if path.suffix not in ('.yml', '.yaml'):
            continue
        for action in re.findall(r'^\s*(?:- )?uses:\s*([^\s]+)', path.read_text(), re.M):
            if action.startswith('./'):
                continue
            repo, separator, commit = action.partition('@')
            if not separator or not re.fullmatch('[0-9a-f]{40}', commit):
                raise ValueError(f'{path.relative_to(root)}: action must be pinned: {action}')
            commits.add((repo, commit))
    if not commits:
        raise ValueError('no pinned actions found')
    return commits


def lookup(query):
    vulnerabilities = {}
    tokens = set()
    request_body = dict(query)
    while True:
        request = urllib.request.Request('https://api.osv.dev/v1/query',
                                        data=json.dumps(request_body).encode(),
                                        headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.load(response)
        if not isinstance(result, dict) or 'error' in result:
            raise ValueError(f'OSV lookup failed: {result}')
        for vulnerability in result.get('vulns', []):
            if not vulnerability.get('withdrawn'):
                vulnerabilities[vulnerability['id']] = vulnerability
        token = result.get('next_page_token')
        if not token:
            return list(vulnerabilities.values())
        if token in tokens:
            raise ValueError('OSV pagination repeated a page token')
        tokens.add(token)
        request_body['page_token'] = token


SQLITE_REPOSITORY = 'https://github.com/sqlite/sqlite'


def numeric_version(version):
    if version == '0':
        return (0, 0, 0, 0)
    if not re.fullmatch(r'\d+(?:\.\d+){1,3}', version):
        raise ValueError(f'unrecognized SQLite version: {version}')
    parts = tuple(int(part) for part in version.split('.'))
    return parts + (0,) * (4 - len(parts))


def interval_contains(version, events):
    """Evaluate OSV's original version intervals, including maintenance releases."""
    if not isinstance(events, list) or not events:
        raise ValueError('missing extracted SQLite version intervals')
    affected = False
    introduced = None
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            raise ValueError('invalid SQLite version event')
        kind, value = next(iter(event.items()))
        boundary = numeric_version(value)
        if kind == 'introduced' and introduced is None:
            introduced = boundary
        elif kind in ('fixed', 'limit', 'last_affected') and introduced is not None:
            if boundary < introduced:
                raise ValueError('reversed SQLite version interval')
            before_end = version <= boundary if kind == 'last_affected' else version < boundary
            affected |= introduced <= version and before_end
            introduced = None
        else:
            raise ValueError('unrecognized SQLite version interval')
    return affected or (introduced is not None and introduced <= version)


def sqlite_findings(version, advisories, not_affected=None):
    if not advisories:
        raise ValueError('SQLite repository advisory inventory is empty; mapping requires review')
    current = numeric_version(version)
    findings = []
    unclassified = []
    for advisory in advisories:
        if advisory.get('withdrawn') or advisory['id'] in (not_affected or {}):
            continue
        ranges = [interval for affected in advisory.get('affected', [])
                  for interval in affected.get('ranges', [])
                  if interval.get('type') == 'GIT' and
                  interval.get('repo', '').removesuffix('.git') == SQLITE_REPOSITORY]
        if not ranges:
            unclassified.append(advisory['id'])
            continue
        affected = False
        for interval in ranges:
            source = interval.get('database_specific', {})
            if not source.get('extracted_events'):
                unclassified.append(advisory['id'])
                continue
            affected |= interval_contains(current, source['extracted_events'])
        if affected:
            findings.append(advisory)
    if unclassified:
        matching = ', '.join(advisory['id'] for advisory in findings) or 'none'
        raise ValueError(f"SQLite triage required for {', '.join(sorted(set(unclassified)))}; "
                         f"known affected advisories for {version}: {matching}")
    return findings


def sqlite_triage(root, version):
    """A dependency or build configuration change requires renewed source review."""
    triage = json.loads((root / 'tools/sqlite_advisory_triage.json').read_text())
    build_digest = hashlib.sha256((root / 'build.zig').read_bytes()).hexdigest()
    if triage['sqlite_version'] != version or triage['build_sha256'] != build_digest:
        raise ValueError('SQLite advisory triage must be refreshed for this version/build configuration')
    reasons = triage['not_affected']
    if not isinstance(reasons, dict) or any(not isinstance(reason, str) or not reason.strip()
                                            for reason in reasons.values()):
        raise ValueError('SQLite advisory triage needs a source-review reason for each record')
    return reasons


def main():
    root = Path(__file__).resolve().parents[1]
    commits = action_commits(root)
    version, _ = sqlite_dependency(root)
    # Exact Git tags/commits miss maintenance-branch versions in OSV's
    # generated Git ranges. Query the repository inventory and compare the
    # original numeric version intervals instead of treating absence as safe.
    inventory = lookup({'package': {'name': SQLITE_REPOSITORY, 'ecosystem': 'GIT'}})
    triage = sqlite_triage(root, version)
    sqlite_vulnerabilities = sqlite_findings(version, inventory, triage)
    for advisory in inventory:
        if advisory['id'] in triage:
            print(f"{advisory['id']}: reviewed not affected: {triage[advisory['id']]}", flush=True)
    results = [(f'sqlite {version} (OSV repository intervals)', sqlite_vulnerabilities)]
    results.extend((name + '@' + commit, lookup({'commit': commit}))
                   for name, commit in sorted(commits))
    findings = []
    for name, vulnerabilities in results:
        print(f'{name}: {len(vulnerabilities)} active OSV findings', flush=True)
        for vulnerability in vulnerabilities:
            findings.append(vulnerability['id'])
            print(f"  https://osv.dev/vulnerability/{vulnerability['id']}", flush=True)
    if findings:
        raise SystemExit('dependency advisories require maintainer triage; release blocked')
    print('OSV coverage is limited to indexed projects; see docs/security-checks.md')


if __name__ == '__main__':
    main()
