#!/usr/bin/env bash
# Runs as root via the sudoers rule install.sh sets up — invoked by the
# panel itself (see xray_manager.check_for_update/apply_update) so the
# unprivileged blinkray user can update without needing its own GitHub
# credentials. sudoers matches this exact path + argument, so keep the
# two subcommands ("check"/"apply") as the only entry points; renaming or
# adding new ones needs a matching sudoers change in install.sh too.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

case "${1:-}" in
  check)
    git fetch --quiet origin main
    LOCAL="$(git rev-parse HEAD)"
    REMOTE="$(git rev-parse origin/main)"
    if [ "$LOCAL" = "$REMOTE" ]; then
      echo "UP_TO_DATE $(git rev-parse --short HEAD)"
    else
      COUNT="$(git rev-list --count HEAD..origin/main)"
      MSG="$(git log -1 --format=%s origin/main)"
      echo "BEHIND ${COUNT} ${MSG}"
    fi
    ;;
  apply)
    git fetch --quiet origin main
    LOCAL="$(git rev-parse HEAD)"
    REMOTE="$(git rev-parse origin/main)"
    if [ "$LOCAL" = "$REMOTE" ]; then
      echo "ALREADY_UP_TO_DATE"
      exit 0
    fi
    git reset --hard origin/main
    chown -R blinkray:blinkray "$SCRIPT_DIR"
    sudo -u blinkray "${SCRIPT_DIR}/venv/bin/pip" install -q -r "${SCRIPT_DIR}/requirements.txt"
    echo "UPDATED $(git rev-parse --short HEAD)"
    # The panel process that invoked this script (via sudo) is about to
    # restart itself — do it in the background with a short delay so this
    # script can return its output first and the panel gets a chance to
    # send the HTTP response before systemd kills it.
    (sleep 1 && systemctl restart blinkray.service) &
    disown
    ;;
  *)
    echo "usage: $0 check|apply" >&2
    exit 1
    ;;
esac
