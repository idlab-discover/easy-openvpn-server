# shellcheck shell=bash
# Helpers for tests/harness.sh. Sourced, not executed.
#
# Topology:
#
#   eovpn-c22/c24/c26 (OpenVPN 2.5/2.6/2.7 clients)
#          |
#     eovpn-wan  10.250.0.0/24
#          |
#   eovpn-server (VM, runs the snap)  wan=10.250.0.10  lan=10.251.0.10
#          |
#     eovpn-lan  10.251.0.0/24
#          |
#   eovpn-lanhost  10.251.0.20, also answers on 169.254.169.254 (fake cloud metadata)
#
# The lanhost runs a tiny HTTP server that answers with the source address of
# the request, so tests can tell whether traffic went through the VPN (source is
# the server's lan address because of NAT) or not.

SERVER=eovpn-server
LANHOST=eovpn-lanhost
CLIENTS=(eovpn-c22 eovpn-c24 eovpn-c26)
WAN_NET=eovpn-wan
LAN_NET=eovpn-lan
SERVER_WAN_IP=10.250.0.10
SERVER_LAN_IP=10.251.0.10
LANHOST_IP=10.251.0.20
METADATA_IP=169.254.169.254
SNAP_NAME=easy-openvpn-server
SERVER_RELEASE="${SERVER_RELEASE:-24.04}"

PASSED=0
FAILED=0
FAILURES=()

# `lxc` doesn't print anything when its stdout isn't a pipe or a terminal in
# some environments, so always pipe it. Callers need `set -o pipefail`.
# The timeout makes sure a stuck LXD call fails the run instead of hanging it.
lx() {
    timeout "${LX_TIMEOUT:-900}" lxc "$@" | cat
}

log() {
    printf '\033[1m==> %s\033[0m\n' "$*" >&2
}

pass() {
    PASSED=$((PASSED + 1))
    printf '\033[32mPASS\033[0m %s\n' "$*" >&2
}

fail() {
    FAILED=$((FAILED + 1))
    FAILURES+=("$*")
    printf '\033[31mFAIL\033[0m %s\n' "$*" >&2
}

# check "description" command...: PASS if the command succeeds. Always
# returns 0, so a failure doesn't abort the harness (`set -e`).
check() {
    require "$@" || true
}

# check_not "description" command...: PASS if the command fails.
check_not() {
    local desc="$1"
    shift
    if "$@"; then fail "$desc"; else pass "$desc"; fi
}

# require "description" command...: like check, but returns whether it
# passed. Only use it as a condition (`if require ...`), to skip checks that
# depend on it.
require() {
    local desc="$1"
    shift
    if "$@"; then
        pass "$desc"
    else
        fail "$desc"
        return 1
    fi
}

# retry <seconds> command...: retry once per second until it succeeds.
retry() {
    local timeout="$1"
    shift
    local i
    for ((i = 0; i < timeout; i++)); do
        if "$@" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    return 1
}

srv() {
    lx exec "$SERVER" -- "$@"
}

instance_exists() {
    lxc info "$1" >/dev/null 2>&1
}

#
# Topology
#

create_networks() {
    if ! lxc network show "$WAN_NET" >/dev/null 2>&1; then
        log "Creating network $WAN_NET"
        lx network create "$WAN_NET" ipv4.address=10.250.0.1/24 ipv4.nat=true ipv6.address=none
    fi
    if ! lxc network show "$LAN_NET" >/dev/null 2>&1; then
        log "Creating network $LAN_NET"
        lx network create "$LAN_NET" ipv4.address=10.251.0.1/24 ipv4.nat=false ipv6.address=none
    fi
}

create_lanhost() {
    if instance_exists "$LANHOST"; then return; fi
    log "Creating $LANHOST"
    lx init ubuntu:24.04 "$LANHOST" -n "$LAN_NET" -q
    lx config device set "$LANHOST" eth0 ipv4.address="$LANHOST_IP"
    lx start "$LANHOST"
    retry 60 lxc exec "$LANHOST" -- true
    lx exec "$LANHOST" -- cloud-init status --wait >/dev/null || true
    lx exec "$LANHOST" -- ip addr add "$METADATA_IP/32" dev lo
    lx exec "$LANHOST" -- sh -c 'cat > /root/whoami.py' <<'EOF'
import http.server

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.client_address[0].encode() + b"\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

http.server.ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever()
EOF
    lx exec "$LANHOST" -- systemd-run --quiet --unit whoami python3 /root/whoami.py
}

create_client() {
    local name="$1" release
    if instance_exists "$name"; then return; fi
    case "$name" in
        *c22) release=22.04 ;;
        *c24) release=24.04 ;;
        *c26) release=26.04 ;;
    esac
    log "Creating $name (Ubuntu $release)"
    lx launch "ubuntu:$release" "$name" -n "$WAN_NET" -q
    lx config device add "$name" tun unix-char path=/dev/net/tun >/dev/null
    retry 60 lxc exec "$name" -- true
    lx exec "$name" -- cloud-init status --wait >/dev/null || true
    lx exec "$name" -- sh -c 'apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -yq openvpn curl' >/dev/null
    log "$name: $(lx exec "$name" -- openvpn --version | head -1)"
}

create_server() {
    if instance_exists "$SERVER"; then
        log "Deleting old $SERVER"
        lx delete -f "$SERVER"
    fi
    log "Creating $SERVER (VM, Ubuntu $SERVER_RELEASE)"
    lx init "ubuntu:$SERVER_RELEASE" "$SERVER" --vm -n "$WAN_NET" -q -c limits.cpu=2 -c limits.memory=2GiB
    lx config device set "$SERVER" eth0 ipv4.address="$SERVER_WAN_IP" hwaddr=00:16:3e:e0:00:10
    lx config device add "$SERVER" eth1 nic network="$LAN_NET" ipv4.address="$SERVER_LAN_IP" \
        hwaddr=00:16:3e:e0:01:10 >/dev/null
    lxc config set "$SERVER" cloud-init.network-config - <<'EOF'
version: 2
ethernets:
  wan:
    match: {macaddress: "00:16:3e:e0:00:10"}
    dhcp4: true
  lan:
    match: {macaddress: "00:16:3e:e0:01:10"}
    dhcp4: true
    dhcp4-overrides: {use-routes: false, use-dns: false}
EOF
    lx start "$SERVER"
    if ! retry 180 lxc exec "$SERVER" -- true; then
        echo "Server VM agent didn't come up" >&2
        return 1
    fi
    srv cloud-init status --wait >/dev/null || true
    # Pretend the lanhost is the cloud metadata service.
    srv ip route add "$METADATA_IP/32" via "$LANHOST_IP"
    retry 120 lxc exec "$SERVER" -- snap wait system seed.loaded
}

setup_topology() {
    create_networks
    create_lanhost
    local c
    for c in "${CLIENTS[@]}"; do create_client "$c"; done
    create_server
}

teardown() {
    log "Cleaning up"
    local i
    for i in "$SERVER" "$LANHOST" "${CLIENTS[@]}"; do
        if instance_exists "$i"; then lx delete -f "$i"; fi
    done
    lxc network delete "$WAN_NET" >/dev/null 2>&1 || true
    lxc network delete "$LAN_NET" >/dev/null 2>&1 || true
}

#
# Snap on the server
#

# Wait until both OpenVPN daemons listen on their ports.
wait_for_daemons() {
    retry 120 sh -c "lxc exec $SERVER -- ss -Hlun 'sport = :1194' | grep -q ." &&
        retry 60 sh -c "lxc exec $SERVER -- ss -Hltn 'sport = :443' | grep -q ."
}

install_snap_from_store() {
    local channel="$1"
    log "Installing $SNAP_NAME from $channel"
    srv snap install "$SNAP_NAME" --channel="$channel" >/dev/null
    srv snap connect "$SNAP_NAME:network-control"
    srv snap connect "$SNAP_NAME:firewall-control"
    wait_for_daemons
}

# Upgrade to either a local .snap file or a store channel.
upgrade_snap() {
    local target="$1"
    if [[ -f "$target" ]]; then
        log "Upgrading to $target"
        lx file push "$target" "$SERVER/root/under-test.snap"
        srv snap install --dangerous /root/under-test.snap >/dev/null
    else
        log "Upgrading to channel $target"
        srv snap refresh "$SNAP_NAME" --channel="$target" >/dev/null
    fi
    # Interfaces stay connected on upgrade, but be explicit.
    srv snap connect "$SNAP_NAME:network-control"
    srv snap connect "$SNAP_NAME:firewall-control"
    srv snap restart "$SNAP_NAME" >/dev/null
    wait_for_daemons
}

# export_client <name> <file>: write the client's .ovpn to a local file.
export_client() {
    lxc exec "$SERVER" -- "$SNAP_NAME" show-client "$1" 2>/dev/null | cat >"$2"
    grep -q '^client' "$2"
}

# Keep only the remote lines for one protocol, so we can test udp and tcp separately.
only_proto() {
    local proto="$1" in="$2" out="$3"
    if [[ "$proto" == udp ]]; then
        grep -v '^\s*remote .* tcp$' "$in" >"$out"
    else
        grep -v '^\s*remote .* udp$' "$in" >"$out"
    fi
}

#
# OpenVPN clients
#

# client_connect <container> <ovpn file>: start OpenVPN and wait until the
# tunnel is up. Returns non-zero if it doesn't come up within 30 seconds.
client_connect() {
    local c="$1" cfg="$2"
    client_disconnect "$c"
    lx file push "$cfg" "$c/root/test.ovpn"
    lx exec "$c" -- rm -f /root/test.log
    # `--mute 0` overrides `mute 20` in the config, which otherwise can hide
    # the "Initialization Sequence Completed" line we wait for.
    # `--disable-dco`: unprivileged containers can't use the kernel data
    # channel (DCO). Without compression, 2.6+ clients would try to. 2.5
    # doesn't have DCO, or the option.
    local extra=() help
    # `openvpn --help` exits non-zero, so don't use it in a pipeline condition.
    help="$(lxc exec "$c" -- openvpn --help 2>&1 | cat || true)"
    if [[ "$help" == *--disable-dco* ]]; then
        extra=(--disable-dco)
    fi
    lx exec "$c" -- openvpn --config /root/test.ovpn --mute 0 "${extra[@]}" --daemon --log /root/test.log \
        --writepid /root/test.pid >/dev/null 2>&1
    retry 30 lxc exec "$c" -- grep -q "Initialization Sequence Completed" /root/test.log
}

client_disconnect() {
    local c="$1"
    lxc exec "$c" -- sh -c 'pkill -x openvpn; while pgrep -x openvpn >/dev/null; do sleep 0.2; done' \
        >/dev/null 2>&1 || true
}

client_log() {
    lxc exec "$1" -- cat /root/test.log 2>/dev/null | cat || true
}

# client_fetch <container> <ip>: HTTP GET to the lanhost; prints the source
# address the lanhost saw.
client_fetch() {
    lxc exec "$1" -- curl -sS -m 5 "http://$2/" 2>/dev/null | cat
}

# True when the request reached the lanhost through the VPN (NATed behind the server).
reaches_via_vpn() {
    [[ "$(client_fetch "$1" "$2")" == "$SERVER_LAN_IP" ]]
}

# snapcmd <args>: run `easy-openvpn-server <args>` on the server, quietly.
snapcmd() {
    lxc exec "$SERVER" -- "$SNAP_NAME" "$@" >/dev/null 2>&1
}

# The first three octets of the udp server's tunnel network, e.g. "10.12.34".
udp_tun_prefix() {
    lxc exec "$SERVER" -- snap get "$SNAP_NAME" internal.udp.tun-network | cat | sed 's/\.0\/24$//'
}

client_has_ip() {
    lxc exec "$1" -- ip -4 -br addr show tun0 | cat | grep -w "$2" >/dev/null
}

client_has_route() {
    lxc exec "$1" -- ip -4 route show "$2" | cat | grep tun0 >/dev/null
}

# fw_rule_count <iptables|ip6tables> <n>: true when there are exactly n of our
# rules in FORWARD and n in nat POSTROUTING (one per daemon), and when there
# are none, also no leftover chains.
fw_rule_count() {
    local cmd="$1" n="$2" forward nat chains
    forward="$(lxc exec "$SERVER" -- "$cmd" -S FORWARD | cat | grep -c 'easy-openvpn-server' || true)"
    nat="$(lxc exec "$SERVER" -- "$cmd" -t nat -S POSTROUTING | cat | grep -c 'easy-openvpn-server' || true)"
    chains="$(lxc exec "$SERVER" -- "$cmd" -S | cat | grep -c '^-N eovpn-' || true)"
    [[ "$forward" == "$n" && "$nat" == "$n" && "$chains" == "$n" ]]
}

client_tun_ip() {
    lxc exec "$1" -- ip -4 -br addr show tun0 | cat | awk '{print $3}'
}

# Connect eovpn-c24 and eovpn-c26 with the same config.
connect_pair() {
    client_connect eovpn-c24 "$1" && client_connect eovpn-c26 "$1"
}

disconnect_pair() {
    client_disconnect eovpn-c24
    client_disconnect eovpn-c26
}

# True when eovpn-c24 can ping eovpn-c26 over the VPN.
pair_can_reach_each_other() {
    local ip
    ip="$(client_tun_ip eovpn-c26)"
    [[ -n "$ip" ]] && lxc exec eovpn-c24 -- ping -c1 -W2 "$ip" >/dev/null 2>&1
}

# check_client_to_client <allowed|blocked> <description> <ovpn file>
check_client_to_client() {
    if require "eovpn-c24 and eovpn-c26 connect" connect_pair "$3"; then
        if [[ "$1" == allowed ]]; then
            check "$2" pair_can_reach_each_other
        else
            check_not "$2" pair_can_reach_each_other
        fi
    fi
    disconnect_pair
}

C2C_WARNING="Clients can reach each other over the VPN"

warning_in_status() {
    lxc exec "$SERVER" -- "$SNAP_NAME.status" 2>&1 | cat | grep "$C2C_WARNING" >/dev/null
}

warning_in_cli() {
    lxc exec "$SERVER" -- "$SNAP_NAME" list-clients 2>&1 | cat | grep "$C2C_WARNING" >/dev/null
}

warning_in_journal() {
    lxc exec "$SERVER" -- journalctl -u "snap.$SNAP_NAME.udp-server" --no-pager 2>&1 | cat | grep "$C2C_WARNING" >/dev/null
}

# True when the client's data channel compresses: it says so (2.6+), or the
# server pushed it compression options.
client_compresses() {
    local log
    log="$(client_log "$1")"
    grep -E "compression: '(lzo|lz4)" <<<"$log" >/dev/null ||
        grep 'PUSH_REPLY' <<<"$log" | grep -E 'comp-lzo( yes|,)|compress (lzo|lz4)' >/dev/null
}

# True when the server told the client to stop compressing (`compress migrate`).
client_told_to_stop_compressing() {
    client_log "$1" | grep 'PUSH_REPLY' | grep 'compress stub-v2' >/dev/null
}

# True when the client's data channel uses one of the AEAD ciphers we allow.
client_uses_aead_cipher() {
    client_log "$1" | grep -iE "data channel.*'(AES-256-GCM|CHACHA20-POLY1305|AES-128-GCM)'" >/dev/null
}

client_got_pushed() {
    client_log "$1" | grep 'PUSH_REPLY' | grep -- "$2" >/dev/null
}

# with_server_cert <in.ovpn> <out.ovpn>: replace the client's cert and key
# with the server's, to check the server rejects non-client certificates.
with_server_cert() {
    local dir="/root/snap/$SNAP_NAME/current"
    python3 -I - "$1" "$2" \
        "$(lxc exec "$SERVER" -- cat "$dir/server.crt" | cat)" \
        "$(lxc exec "$SERVER" -- cat "$dir/server.key" | cat)" <<'PY'
import re, sys
src, dst, cert, key = sys.argv[1:]
config = open(src).read()
config = re.sub(r"<cert>.*?</cert>", lambda m: "<cert>\n" + cert.strip() + "\n</cert>", config, flags=re.S)
config = re.sub(r"<key>.*?</key>", lambda m: "<key>\n" + key.strip() + "\n</key>", config, flags=re.S)
open(dst, "w").write(config)
PY
}

ovpn_files_are_private() {
    local modes
    modes="$(lxc exec "$SERVER" -- sh -c "stat -c %a /root/snap/$SNAP_NAME/current/client-configs/*.ovpn" | cat)"
    [[ -n "$modes" ]] && ! grep -v '^600$' <<<"$modes" >/dev/null
}
