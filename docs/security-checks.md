# release security checks

Repository maintainers own dependency updates and failing security checks. The
security workflow runs on pull requests and daily. It rejects mutable action
references, queries OSV for exact action commits and the complete SQLite Git
repository advisory inventory, and runs the existing panic-path audit. Lookup failures fail the job; advisory
results link directly to the records that need triage. Dependabot proposes action
pin updates weekly. Review the action source at its proposed commit before merging.

OSV coverage is limited to indexed projects and reported vulnerabilities. It is
not a complete CVE inventory. The locally modified zig-sqlite wrapper has no
independent advisory mapping and requires source review when changed. Its exact
Git tree is included in the release inventory. SQLite is identified by the source
URL and version in both dependency manifests; mismatched manifests fail inventory
creation.

SQLite maintenance tags are missing from some OSV Git affected-version lists;
the former OSS-Fuzz package lookup also returned an empty inventory. The gate
therefore evaluates the converter's explicit numeric version intervals from the
whole repository inventory. An empty inventory, unmapped advisory, malformed
interval, or failed paginated lookup blocks release rather than reporting a
clean dependency.

Three records without version intervals have source-reviewed exclusions in
`tools/sqlite_advisory_triage.json`: CVE-2026-39113 concerns the absent sqlar
extension; CVE-2026-50812 and CVE-2026-50813 concern the disabled Session extension.
The review applies only to SQLite 3.53.4 and the recorded SHA-256 of `build.zig`.
Changing the dependency version or build configuration invalidates this review.
The reasons are printed by the gate; new unmapped records still block release.

Release builds depend on unit tests and security checks for the resolved tag
commit. The bundle includes an SPDX 2.3 inventory of yoq, SQLite, the vendored
wrapper, and archive hashes. It describes bundled source dependencies, not the
host's dynamically linked libraries. Each archive and both metadata documents
receive GitHub provenance attestations.

The installer requires Python 3 and GitHub CLI with `gh attestation verify`.
It checks the repository, release workflow identity, and hosted runner policy
before extraction. Signed metadata must also bind the requested tag to the
archive digest. Missing or invalid attestations stop installation, including
older releases without attestations. GitHub API access must be available; run
`gh auth login` if the CLI requests authentication. Checksums alone are not a
publisher identity check.

A manual release's attestation describes the workflow invocation; the signed
metadata separately records the immutable tag commit actually checked out.
The workflow does not claim that a dispatch branch and release tag are identical.
