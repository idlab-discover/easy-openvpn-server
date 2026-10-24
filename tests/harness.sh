#!/bin/bash
# End-to-end tests for easy-openvpn-server, using LXD.
#
# Installs the current stable snap in a VM, creates clients, then upgrades to
# the snap under test and checks that old and new client configs still work.
#
# Usage:
#   tests/harness.sh [--snap FILE | --channel CHANNEL | --candidate] [--keep]
#
#   --snap FILE        upgrade to this local .snap file
#   --channel CHANNEL  upgrade to this store channel
#   --candidate        same as --channel latest/candidate
#   --keep             don't delete the LXD instances and networks afterwards
#
# Without --snap or --channel, only the stable snap is tested (baseline).
#
# Needs LXD with VM support. Client containers are reused between runs when
# --keep was used; the server VM is always recreated.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=tests/lib.sh
source "$HERE/lib.sh"

UPGRADE_TO=""
KEEP=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --snap)
            UPGRADE_TO="$(realpath "$2")"
            shift 2
            ;;
        --channel)
            UPGRADE_TO="$2"
            shift 2
            ;;
        --candidate)
            UPGRADE_TO=latest/candidate
            shift
            ;;
        --keep)
            KEEP=true
            shift
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

WORK="$(mktemp -d -t eovpn-harness.XXXXXX)"

finish() {
    local rc=$?
    if [[ $FAILED -gt 0 || $rc -ne 0 ]] && instance_exists "$SERVER"; then
        lxc exec "$SERVER" -- journalctl -u "snap.$SNAP_NAME.*" --no-pager 2>/dev/null |
            cat >"$WORK/server-journal.log" || true
        echo "Server journal saved to $WORK/server-journal.log" >&2
    fi
    if [[ "$KEEP" == false ]]; then teardown; fi
    echo >&2
    echo "Passed: $PASSED  Failed: $FAILED" >&2
    local f
    for f in "${FAILURES[@]}"; do echo "  - $f" >&2; done
    if [[ $rc -ne 0 ]]; then
        echo "Harness aborted (exit $rc)" >&2
        exit "$rc"
    fi
    [[ $FAILED -eq 0 ]]
}
trap finish EXIT

#
# Scenarios
#

# 1. Old client configs keep working after an upgrade.
scenario_upgrade() {
    log "Scenario 1: upgrade"
    install_snap_from_store latest/stable
    srv "$SNAP_NAME" add-client Alice >/dev/null 2>&1
    srv "$SNAP_NAME" add-client bob >/dev/null 2>&1
    local name
    for name in default Alice bob; do
        check "export $name.ovpn from stable" export_client "$name" "$WORK/old-$name.ovpn"
    done

    if [[ -n "$UPGRADE_TO" ]]; then
        upgrade_snap "$UPGRADE_TO"
    fi

    only_proto udp "$WORK/old-default.ovpn" "$WORK/old-default-udp.ovpn"
    only_proto tcp "$WORK/old-default.ovpn" "$WORK/old-default-tcp.ovpn"
    local c
    for c in "${CLIENTS[@]}"; do
        if check "$c: old default.ovpn connects over udp" client_connect "$c" "$WORK/old-default-udp.ovpn"; then
            check "$c: reaches lan host through the VPN (udp)" reaches_via_vpn "$c" "$LANHOST_IP"
        else
            client_log "$c" >"$WORK/$c-udp.log"
        fi
        client_disconnect "$c"
    done
    if check "eovpn-c24: old default.ovpn connects over tcp" client_connect eovpn-c24 "$WORK/old-default-tcp.ovpn"; then
        check "eovpn-c24: reaches lan host through the VPN (tcp)" reaches_via_vpn eovpn-c24 "$LANHOST_IP"
    else
        client_log eovpn-c24 >"$WORK/eovpn-c24-tcp.log"
    fi
    client_disconnect eovpn-c24
}

log "Work directory: $WORK"
setup_topology
scenario_upgrade
