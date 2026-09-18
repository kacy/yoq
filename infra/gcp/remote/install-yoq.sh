#!/usr/bin/env bash
set -euo pipefail
set +x

INSTALL_URL="${1:?usage: install-yoq.sh <https installer url>}"
case "$INSTALL_URL" in
  https://*) ;;
  *) echo 'the installer url must use https' >&2; exit 1 ;;
esac

# credentials arrive on the encrypted ssh stdin, never in command arguments.
IFS= read -r GH_TOKEN
[ -n "$GH_TOKEN" ] || { echo 'missing github token for release verification' >&2; exit 1; }
export GH_TOKEN
gh auth status --hostname github.com >/dev/null 2>&1
INSTALL_SCRIPT=$(mktemp)
trap 'rm -f "$INSTALL_SCRIPT"; unset GH_TOKEN' EXIT
curl --proto '=https' --proto-redir '=https' -fsSL "$INSTALL_URL" -o "$INSTALL_SCRIPT"
bash "$INSTALL_SCRIPT"
