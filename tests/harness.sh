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
    only_proto udp "$WORK/old-bob.ovpn" "$WORK/old-bob-udp.ovpn"

    # Older versions also used `client-configs/` as client-config-dir. Check
    # that files there never had any effect, as setup.py's warning claims.
    local bob_ip
    bob_ip="$(udp_tun_prefix).101"
    srv sh -c "echo 'ifconfig-push $bob_ip $(udp_tun_prefix).102' > /root/snap/$SNAP_NAME/current/client-configs/bob"
    if require "eovpn-c24: bob connects to stable" client_connect eovpn-c24 "$WORK/old-bob-udp.ovpn"; then
        check_not "stable ignores client-configs/bob" client_has_ip eovpn-c24 "$bob_ip"
    fi
    client_disconnect eovpn-c24

    if [[ -n "$UPGRADE_TO" ]]; then
        upgrade_snap "$UPGRADE_TO"
    fi

    only_proto udp "$WORK/old-default.ovpn" "$WORK/old-default-udp.ovpn"
    only_proto tcp "$WORK/old-default.ovpn" "$WORK/old-default-tcp.ovpn"
    local c
    for c in "${CLIENTS[@]}"; do
        if require "$c: old default.ovpn connects over udp" client_connect "$c" "$WORK/old-default-udp.ovpn"; then
            check "$c: reaches lan host through the VPN (udp)" reaches_via_vpn "$c" "$LANHOST_IP"
            if [[ -n "$UPGRADE_TO" ]]; then
                check "$c: old config with comp-lzo is told to stop compressing" client_told_to_stop_compressing "$c"
                check_not "$c: old config doesn't compress" client_compresses "$c"
            fi
        else
            client_log "$c" >"$WORK/$c-udp.log"
        fi
        client_disconnect "$c"
    done
    if require "eovpn-c24: old default.ovpn connects over tcp" client_connect eovpn-c24 "$WORK/old-default-tcp.ovpn"; then
        check "eovpn-c24: reaches lan host through the VPN (tcp)" reaches_via_vpn eovpn-c24 "$LANHOST_IP"
    else
        client_log eovpn-c24 >"$WORK/eovpn-c24-tcp.log"
    fi
    client_disconnect eovpn-c24
}

# 3. Removing a client revokes its certificate, also when its name has capitals.
scenario_revocation() {
    log "Scenario 3: revocation"
    check "remove-client Alice succeeds" snapcmd remove-client Alice
    wait_for_daemons
    only_proto udp "$WORK/old-Alice.ovpn" "$WORK/old-Alice-udp.ovpn"
    only_proto udp "$WORK/old-bob.ovpn" "$WORK/old-bob-udp.ovpn"
    check_not "eovpn-c24: removed client Alice can't connect" client_connect eovpn-c24 "$WORK/old-Alice-udp.ovpn"
    client_disconnect eovpn-c24
    check "eovpn-c24: other client bob still connects" client_connect eovpn-c24 "$WORK/old-bob-udp.ovpn"
    client_disconnect eovpn-c24
    check_not "remove-client of an unknown client fails" snapcmd remove-client nobody
}

# 4. Client-specific config in $SNAP_COMMON/ccd is applied.
scenario_ccd() {
    log "Scenario 4: client-specific config"
    local ccd="/var/snap/$SNAP_NAME/common/ccd" bob_ip
    bob_ip="$(udp_tun_prefix).101"
    srv sh -c "echo 'ifconfig-push $bob_ip $(udp_tun_prefix).102' > $ccd/bob"
    srv sh -c "echo 'push \"route 192.0.2.0 255.255.255.0\"' > $ccd/DEFAULT"
    if require "eovpn-c24: bob connects" client_connect eovpn-c24 "$WORK/old-bob-udp.ovpn"; then
        check "ccd/bob gives bob its fixed address" client_has_ip eovpn-c24 "$bob_ip"
        check_not "ccd/DEFAULT doesn't apply to bob, who has his own file" client_has_route eovpn-c24 192.0.2.0/24
    fi
    client_disconnect eovpn-c24
    if require "eovpn-c24: default connects" client_connect eovpn-c24 "$WORK/old-default-udp.ovpn"; then
        check "ccd/DEFAULT applies to clients without their own file" client_has_route eovpn-c24 192.0.2.0/24
    fi
    client_disconnect eovpn-c24
    srv rm -f "$ccd/bob" "$ccd/DEFAULT"
    check "setup warns about files in the old client-configs folder" \
        sh -c "lxc exec $SERVER -- $SNAP_NAME setup 2>&1 | grep -q 'client-specific config'"
    wait_for_daemons
}

# 5. Firewall rules for traffic from VPN clients.
scenario_firewall() {
    log "Scenario 5: firewall"
    if require "eovpn-c24: default connects" client_connect eovpn-c24 "$WORK/old-default-udp.ovpn"; then
        check "eovpn-c24: lan host is reachable through the VPN" reaches_via_vpn eovpn-c24 "$LANHOST_IP"
        check_not "eovpn-c24: cloud metadata ($METADATA_IP) is blocked" reaches_via_vpn eovpn-c24 "$METADATA_IP"
    fi
    client_disconnect eovpn-c24
    check "DNS servers pushed to clients are exempt from the blocks" \
        sh -c "lxc exec $SERVER -- iptables -S eovpn-udp-server | grep -q -- '--dport 53 -j RETURN'"

    srv snap restart "$SNAP_NAME" >/dev/null
    wait_for_daemons
    check "no duplicate rules after a restart (iptables)" fw_rule_count iptables 2
    check "no duplicate rules after a restart (ip6tables)" fw_rule_count ip6tables 2
    srv snap stop "$SNAP_NAME" >/dev/null
    check "no rules left after stopping (iptables)" fw_rule_count iptables 0
    check "no rules left after stopping (ip6tables)" fw_rule_count ip6tables 0
    srv snap start "$SNAP_NAME" >/dev/null
    wait_for_daemons
}

# 6. Clients reaching each other: kept on upgrades (with a warning), and
# controlled by the firewall.client-to-client setting.
scenario_client_to_client() {
    log "Scenario 6: client-to-client"
    local cfg="$WORK/old-default-udp.ovpn"
    check_client_to_client allowed "upgraded install: clients can still reach each other" "$cfg"
    check "upgraded install: warning in status" warning_in_status
    check "upgraded install: warning in CLI output" warning_in_cli
    check "upgraded install: warning in the daemon log" warning_in_journal

    srv snap set "$SNAP_NAME" firewall.client-to-client=false
    wait_for_daemons
    check_client_to_client blocked "client-to-client=false: clients can't reach each other" "$cfg"
    check_not "client-to-client=false: no warning in status" warning_in_status
    check_not "client-to-client=false: no warning in CLI output" warning_in_cli

    # Without the default gateway, clients need the pushed routes to the tunnel networks (#23).
    srv snap set "$SNAP_NAME" firewall.client-to-client=true push-default-gateway=False
    wait_for_daemons
    check_client_to_client allowed "client-to-client=true: clients reach each other without the default gateway" "$cfg"
    check_not "client-to-client=true: no warning in status" warning_in_status
    srv snap set "$SNAP_NAME" push-default-gateway=True
    wait_for_daemons
}

# 7. Client config files and input validation.
scenario_hygiene() {
    log "Scenario 7: file permissions and input validation"
    check "client configs (with private keys) are only readable by root" ovpn_files_are_private
}

# 2. A fresh install of the snap under test works, and new configs connect.
scenario_fresh_install() {
    log "Scenario 2: fresh install"
    srv snap remove --purge "$SNAP_NAME" >/dev/null
    if [[ -f "$UPGRADE_TO" ]]; then
        lx file push "$UPGRADE_TO" "$SERVER/root/under-test.snap"
        srv snap install --dangerous /root/under-test.snap >/dev/null
        srv snap connect "$SNAP_NAME:network-control"
        srv snap connect "$SNAP_NAME:firewall-control"
        wait_for_daemons
    else
        install_snap_from_store "$UPGRADE_TO"
    fi
    if ! require "export default.ovpn from fresh install" export_client default "$WORK/new-default.ovpn"; then return 0; fi
    only_proto udp "$WORK/new-default.ovpn" "$WORK/new-default-udp.ovpn"
    only_proto tcp "$WORK/new-default.ovpn" "$WORK/new-default-tcp.ovpn"
    local c
    for c in "${CLIENTS[@]}"; do
        if require "$c: new default.ovpn connects over udp" client_connect "$c" "$WORK/new-default-udp.ovpn"; then
            check "$c: reaches lan host through the VPN (udp, new config)" reaches_via_vpn "$c" "$LANHOST_IP"
            check_not "$c: new config doesn't compress" client_compresses "$c"
            check "$c: uses an AEAD data cipher" client_uses_aead_cipher "$c"
            check "$c: block-outside-dns is pushed" client_got_pushed "$c" block-outside-dns
        else
            client_log "$c" >"$WORK/$c-new-udp.log"
        fi
        client_disconnect "$c"
    done
    if require "eovpn-c26: new default.ovpn connects over tcp" client_connect eovpn-c26 "$WORK/new-default-tcp.ovpn"; then
        check "eovpn-c26: reaches lan host through the VPN (tcp, new config)" reaches_via_vpn eovpn-c26 "$LANHOST_IP"
    else
        client_log eovpn-c26 >"$WORK/eovpn-c26-new-tcp.log"
    fi
    client_disconnect eovpn-c26
    check_client_to_client blocked "fresh install: clients can't reach each other" "$WORK/new-default-udp.ovpn"
    if require "build a config that uses the server's certificate" \
        with_server_cert "$WORK/new-default-udp.ovpn" "$WORK/server-cert-udp.ovpn"; then
        check_not "the server's certificate can't be used to connect as a client" \
            client_connect eovpn-c24 "$WORK/server-cert-udp.ovpn"
        client_disconnect eovpn-c24
    fi
    check_not "fresh install: no client-to-client warning" warning_in_status
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
