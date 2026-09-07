#!/usr/bin/env python3
"""Check action pins and query OSV for build dependencies; fail on lookup errors."""
import json
from pathlib import Path
import re
import urllib.request
from release_metadata import sqlite_dependency


def action_commits(root):
    commits = {}
    for path in (root / '.github').rglob('*.yml'):
        for action in re.findall(r'^\s*(?:- )?uses:\s*([^\s]+)', path.read_text(), re.M):
            if action.startswith('./'):
                continue
            repo, separator, commit = action.partition('@')
            if not separator or not re.fullmatch('[0-9a-f]{40}', commit):
                raise ValueError(f'{path.relative_to(root)}: action must be pinned: {action}')
            commits[repo] = commit
    if not commits:
        raise ValueError('no pinned actions found')
    return commits


def lookup(query):
    request = urllib.request.Request('https://api.osv.dev/v1/query',
                                    data=json.dumps(query).encode(),
                                    headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        result = json.load(response)
    if not isinstance(result, dict) or 'error' in result:
        raise ValueError(f'OSV lookup failed: {result}')
    return [v for v in result.get('vulns', []) if not v.get('withdrawn')]


def main():
    root = Path(__file__).resolve().parents[1]
    commits = action_commits(root)
    version, _ = sqlite_dependency(root)
    queries = [(f'sqlite3 {version} (OSS-Fuzz)',
                {'package': {'name': 'sqlite3', 'ecosystem': 'OSS-Fuzz'}, 'version': version})]
    queries.extend((name + '@' + commit, {'commit': commit}) for name, commit in sorted(commits.items()))
    findings = []
    for name, query in queries:
        vulnerabilities = lookup(query)
        print(f'{name}: {len(vulnerabilities)} active OSV findings', flush=True)
        for vulnerability in vulnerabilities:
            findings.append(vulnerability['id'])
            print(f"  https://osv.dev/vulnerability/{vulnerability['id']}", flush=True)
    if findings:
        raise SystemExit('dependency advisories require maintainer triage; release blocked')
    print('OSV coverage is limited to indexed projects; see docs/security-checks.md')


if __name__ == '__main__':
    main()
