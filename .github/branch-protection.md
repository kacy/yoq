# branch protection rollout

protect `main` with pull requests before merge.

recommended required checks, using the check names reported by github:

- `fmt-check`
- `build-debug / build-debug`
- `docker-build`
- `examples-validate`
- `unit-tests / unit-tests`
- `hardening-smoke / hardening-smoke`
- `agent-recovery`
- `dependency-security`
- `bpf-consistency`

recommended settings:

- allow squash merges only
- require branches to be up to date before merging if ci duration stays acceptable
- do not require `quality`, `runtime-validation`, or `release`
- no repository secrets are required for the base workflow set
- if ghcr publishing is added later, `GITHUB_TOKEN` is sufficient for the first pass

this file describes the intended policy; it does not enable repository rules. confirm the selected names against a completed pull request run when configuring protection.
