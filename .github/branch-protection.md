# branch protection rollout

protect `main` with pull requests before merge and start with only the phase-1 checks required.

initial required checks:

- `ci / fmt-check`
- `ci / build-debug`
- `ci / docker-build`
- `ci / examples-validate`

phase-2 required checks after the current `zig build test` failure is fixed:

- `ci / unit-tests`
- `ci / bpf-consistency`

recommended settings:

- require branches to be up to date before merging if ci duration stays acceptable
- do not require `quality`, `runtime-validation`, or `release`
- no repository secrets are required for the base workflow set
- if ghcr publishing is added later, `GITHUB_TOKEN` is sufficient for the first pass
