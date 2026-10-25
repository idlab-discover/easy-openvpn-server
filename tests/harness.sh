#!/bin/bash
# End-to-end tests for easy-openvpn-server, using LXD.
#
# Installs the current stable snap in a VM, creates clients, then upgrades to
# the snap under test and checks that old and new client configs still work.
#
# Usage:
#   tests/harness.sh [--snap FILE | --channel CHANNEL | --candidate] [--server-release R] [--keep]
#
#   --snap FILE        upgrade to this local .snap file
#   --channel CHANNEL  upgrade to this store channel
#   --candidate        same as --channel latest/candidate
#   --keep             don't delete the LXD instances and networks afterwards
#
# The whole run stops after HARNESS_TIMEOUT (default 45m).
#   --server-release R Ubuntu release of the server VM (default 24.04). Use
#                      26.04 to test with the in-kernel OpenVPN data channel (DCO).
#
# Without --snap or --channel, only the stable snap is tested (baseline).
#
# Needs LXD with VM support. Client containers are reused between runs when
# --keep was used; the server VM is always recreated.
set -euo pipefail

# If stdin is a terminal, `lxc` goes interactive. When the harness runs in the
# background, that stops it (SIGTTIN/SIGTTOU) and it hangs forever.
exec </dev/null

# A full run takes about 10-15 minutes. If anything hangs, stop after
# HARNESS_TIMEOUT. `timeout` signals the whole process group, so a stuck
# `lxc` call stops too, and the TERM trap below still cleans up.
if [[ -z "${HARNESS_UNDER_TIMEOUT:-}" ]]; then
    export HARNESS_UNDER_TIMEOUT=1
    exec timeout --kill-after=5m "${HARNESS_TIMEOUT:-45m}" "$0" "$@"
fi
trap 'echo "Harness timed out after ${HARNESS_TIMEOUT:-45m}" >&2; exit 124' TERM

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
        --server-release)
            SERVER_RELEASE="$2"
            shift 2
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
    if [[ $FAILED -gt 0 || $rc -ne 0 ]] && vm_exists "$SERVER_VM"; then
        lxc exec "$SERVER_VM" -- journalctl -u "snap.easy-openvpn-server.*" --no-pager 2>/dev/null |
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
    # The snap creates `default` itself.
    local name
    for name in default Alice bob; do
        if [[ "$name" != default ]]; then
            server_vm_exec easy-openvpn-server add-client "$name" >/dev/null 2>&1
        fi
        check "export $name.ovpn from stable" export_client_config "$name" "$WORK/old-$name.ovpn"
    done

    if [[ -n "$UPGRADE_TO" ]]; then
        upgrade_snap "$UPGRADE_TO"
    fi

    only_proto udp "$WORK/old-default.ovpn" "$WORK/old-default-udp.ovpn"
    only_proto tcp "$WORK/old-default.ovpn" "$WORK/old-default-tcp.ovpn"
    local c
    for c in "${CLIENT_VMS[@]}"; do
        if require "$c: old default.ovpn connects over udp" client_vpn_connect "$c" "$WORK/old-default-udp.ovpn"; then
            check "$c: reaches lan VM through the VPN (udp)" client_reaches_lan_vm_via_vpn "$c" "$LAN_VM_IP"
        else
            client_vpn_log "$c" >"$WORK/$c-udp.log"
        fi
        client_vpn_disconnect "$c"
    done
    if require "eovpn-client-2404-vm: old default.ovpn connects over tcp" client_vpn_connect eovpn-client-2404-vm "$WORK/old-default-tcp.ovpn"; then
        check "eovpn-client-2404-vm: reaches lan VM through the VPN (tcp)" client_reaches_lan_vm_via_vpn eovpn-client-2404-vm "$LAN_VM_IP"
    else
        client_vpn_log eovpn-client-2404-vm >"$WORK/eovpn-client-2404-vm-tcp.log"
    fi
    client_vpn_disconnect eovpn-client-2404-vm
}

# 3. Removing a client revokes its certificate, also when its name has capitals.
scenario_revocation() {
    log "Scenario 3: revocation"
    check "remove-client Alice succeeds" snapcmd remove-client Alice
    wait_for_daemons
    only_proto udp "$WORK/old-Alice.ovpn" "$WORK/old-Alice-udp.ovpn"
    only_proto udp "$WORK/old-bob.ovpn" "$WORK/old-bob-udp.ovpn"
    check_not "eovpn-client-2404-vm: removed client Alice can't connect" client_vpn_connect eovpn-client-2404-vm "$WORK/old-Alice-udp.ovpn"
    client_vpn_disconnect eovpn-client-2404-vm
    check "eovpn-client-2404-vm: other client bob still connects" client_vpn_connect eovpn-client-2404-vm "$WORK/old-bob-udp.ovpn"
    client_vpn_disconnect eovpn-client-2404-vm
    check_not "remove-client of an unknown client fails" snapcmd remove-client nobody
}

# 2. A fresh install of the snap under test works, and new configs connect.
scenario_fresh_install() {
    log "Scenario 2: fresh install"
    server_vm_exec snap remove --purge easy-openvpn-server >/dev/null
    if [[ -f "$UPGRADE_TO" ]]; then
        lx file push "$UPGRADE_TO" "$SERVER_VM/root/under-test.snap"
        server_vm_exec snap install --dangerous /root/under-test.snap >/dev/null
        # Auto-connect doesn't apply to local snaps.
        connect_interfaces
        wait_for_daemons
    else
        install_snap_from_store "$UPGRADE_TO"
    fi
    if ! require "export default.ovpn from fresh install" export_client_config default "$WORK/new-default.ovpn"; then return 0; fi
    only_proto udp "$WORK/new-default.ovpn" "$WORK/new-default-udp.ovpn"
    only_proto tcp "$WORK/new-default.ovpn" "$WORK/new-default-tcp.ovpn"
    local c
    for c in "${CLIENT_VMS[@]}"; do
        if require "$c: new default.ovpn connects over udp" client_vpn_connect "$c" "$WORK/new-default-udp.ovpn"; then
            check "$c: reaches lan VM through the VPN (udp, new config)" client_reaches_lan_vm_via_vpn "$c" "$LAN_VM_IP"
        else
            client_vpn_log "$c" >"$WORK/$c-new-udp.log"
        fi
        client_vpn_disconnect "$c"
    done
    if require "eovpn-client-2604-vm: new default.ovpn connects over tcp" client_vpn_connect eovpn-client-2604-vm "$WORK/new-default-tcp.ovpn"; then
        check "eovpn-client-2604-vm: reaches lan VM through the VPN (tcp, new config)" client_reaches_lan_vm_via_vpn eovpn-client-2604-vm "$LAN_VM_IP"
    else
        client_vpn_log eovpn-client-2604-vm >"$WORK/eovpn-client-2604-vm-new-tcp.log"
    fi
    client_vpn_disconnect eovpn-client-2604-vm
}

log "Work directory: $WORK"
setup_topology
scenario_upgrade
scenario_revocation
if [[ -n "$UPGRADE_TO" ]]; then
    scenario_fresh_install
fi
