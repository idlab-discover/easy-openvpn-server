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

PASSED=0
FAILED=0
FAILURES=()

# `lxc` doesn't print anything when its stdout isn't a pipe or a terminal in
# some environments, so always pipe it. Callers need `set -o pipefail`.
lx() {
    lxc "$@" | cat
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

# check "description" command...: PASS if the command succeeds.
# Returns whether it passed, so callers can skip dependent checks.
check() {
    local desc="$1"
    shift
    if "$@"; then
        pass "$desc"
    else
        fail "$desc"
        return 1
    fi
}

# check_not "description" command...: PASS if the command fails.
check_not() {
    local desc="$1"
    shift
    if "$@"; then
        fail "$desc"
        return 1
    else
        pass "$desc"
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
    log "Creating $SERVER (VM)"
    lx init ubuntu:24.04 "$SERVER" --vm -n "$WAN_NET" -q -c limits.cpu=2 -c limits.memory=2GiB
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
    lx exec "$c" -- openvpn --config /root/test.ovpn --mute 0 --daemon --log /root/test.log \
        --writepid /root/test.pid >/dev/null 2>&1
    retry 30 lxc exec "$c" -- grep -q "Initialization Sequence Completed" /root/test.log
}

client_disconnect() {
    local c="$1"
    lxc exec "$c" -- sh -c 'pkill -x openvpn; while pgrep -x openvpn >/dev/null; do sleep 0.2; done' \
        >/dev/null 2>&1 || true
}

client_log() {
    lxc exec "$1" -- cat /root/test.log 2>/dev/null | cat
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
