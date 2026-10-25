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
    only_proto udp "$WORK/old-bob.ovpn" "$WORK/old-bob-udp.ovpn"

    # Older versions also used `client-configs/` as client-config-dir. Check
    # that files there never had any effect, as the CLI's warning claims.
    local bob_ip
    bob_ip="$(udp_tun_prefix).101"
    server_vm_exec sh -c "echo 'ifconfig-push $bob_ip $(udp_tun_prefix).102' > /root/snap/easy-openvpn-server/current/client-configs/bob"
    if require "eovpn-client-2404-vm: bob connects to stable" client_vpn_connect eovpn-client-2404-vm "$WORK/old-bob-udp.ovpn"; then
        check_not "stable ignores client-configs/bob" client_vpn_has_ip eovpn-client-2404-vm "$bob_ip"
    fi
    client_vpn_disconnect eovpn-client-2404-vm

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

# 4. Client-specific config in $SNAP_COMMON/ccd is applied.
scenario_ccd() {
    log "Scenario 4: client-specific config"
    local ccd="/var/snap/easy-openvpn-server/common/ccd" bob_ip
    bob_ip="$(udp_tun_prefix).101"
    server_vm_exec sh -c "echo 'ifconfig-push $bob_ip $(udp_tun_prefix).102' > $ccd/bob"
    server_vm_exec sh -c "echo 'push \"route 192.0.2.0 255.255.255.0\"' > $ccd/DEFAULT"
    if require "eovpn-client-2404-vm: bob connects" client_vpn_connect eovpn-client-2404-vm "$WORK/old-bob-udp.ovpn"; then
        check "ccd/bob gives bob its fixed address" client_vpn_has_ip eovpn-client-2404-vm "$bob_ip"
        check_not "ccd/DEFAULT doesn't apply to bob, who has his own file" client_vpn_has_route eovpn-client-2404-vm 192.0.2.0/24
    fi
    client_vpn_disconnect eovpn-client-2404-vm
    if require "eovpn-client-2404-vm: default connects" client_vpn_connect eovpn-client-2404-vm "$WORK/old-default-udp.ovpn"; then
        check "ccd/DEFAULT applies to clients without their own file" client_vpn_has_route eovpn-client-2404-vm 192.0.2.0/24
    fi
    client_vpn_disconnect eovpn-client-2404-vm
    server_vm_exec rm -f "$ccd/bob" "$ccd/DEFAULT"
    check "setup warns about files in the old client-configs folder" \
        sh -c "lxc exec $SERVER_VM -- easy-openvpn-server setup 2>&1 | grep -q 'client-specific config'"
    wait_for_daemons
}

# 5. Firewall rules for traffic from VPN clients.
scenario_firewall() {
    log "Scenario 5: firewall"
    if require "eovpn-client-2404-vm: default connects" client_vpn_connect eovpn-client-2404-vm "$WORK/old-default-udp.ovpn"; then
        check "eovpn-client-2404-vm: lan VM is reachable through the VPN" client_reaches_lan_vm_via_vpn eovpn-client-2404-vm "$LAN_VM_IP"
        check_not "eovpn-client-2404-vm: cloud metadata ($METADATA_IP) is blocked" client_reaches_lan_vm_via_vpn eovpn-client-2404-vm "$METADATA_IP"
    fi
    client_vpn_disconnect eovpn-client-2404-vm
    check "DNS servers pushed to clients are exempt from the blocks" \
        sh -c "lxc exec $SERVER_VM -- iptables -S eovpn-udp-server | grep -q -- '--dport 53 -j RETURN'"

    server_vm_exec snap restart easy-openvpn-server >/dev/null
    wait_for_daemons
    check "no duplicate rules after a restart (iptables)" fw_rule_count iptables 2
    check "no duplicate rules after a restart (ip6tables)" fw_rule_count ip6tables 2
    server_vm_exec snap stop easy-openvpn-server >/dev/null
    check "no rules left after stopping (iptables)" fw_rule_count iptables 0
    check "no rules left after stopping (ip6tables)" fw_rule_count ip6tables 0
    server_vm_exec snap start easy-openvpn-server >/dev/null
    wait_for_daemons
}

# 6. Clients reaching each other: kept on upgrades (with a warning), and
# controlled by the firewall.client-to-client setting.
scenario_client_to_client() {
    log "Scenario 6: client-to-client"
    local cfg="$WORK/old-default-udp.ovpn"
    check_client_to_client allowed "upgraded install: clients can still reach each other" "$cfg"
    check "upgraded install: warning in CLI output" warning_in_cli

    server_vm_exec snap set easy-openvpn-server firewall.client-to-client=false
    wait_for_daemons
    check_client_to_client blocked "client-to-client=false: clients can't reach each other" "$cfg"
    check_not "client-to-client=false: other tunnels on the server aren't blocked (no -o tun+)" \
        sh -c "lxc exec $SERVER_VM -- iptables -S eovpn-udp-server | grep -q -- '-o tun'"
    check_not "client-to-client=false: no warning in CLI output" warning_in_cli

    # Without the default gateway, clients need the pushed routes to the tunnel networks (#23).
    server_vm_exec snap set easy-openvpn-server firewall.client-to-client=true push-default-gateway=False
    wait_for_daemons
    check_client_to_client allowed "client-to-client=true: clients reach each other without the default gateway" "$cfg"
    check_not "client-to-client=true: no warning in CLI output" warning_in_cli
    server_vm_exec snap set easy-openvpn-server push-default-gateway=True
    wait_for_daemons
}

# 7. Client config files and input validation.
scenario_hygiene() {
    log "Scenario 7: file permissions and input validation"
    check "the values run.sh sources are only writable by root" daemon_env_files_are_private

    check_not "firewall.client-to-client that isn't true or false is rejected" \
        lxc exec "$SERVER_VM" -- snap set easy-openvpn-server firewall.client-to-client=maybe
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
    check_client_to_client blocked "fresh install: clients can't reach each other" "$WORK/new-default-udp.ovpn"
    check_not "fresh install: no client-to-client warning" warning_in_cli
}

log "Work directory: $WORK"
setup_topology
scenario_upgrade
scenario_revocation
if [[ -n "$UPGRADE_TO" ]]; then
    scenario_ccd
    scenario_firewall
    scenario_client_to_client
    scenario_hygiene
    scenario_fresh_install
fi
