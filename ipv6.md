# How ipv6 support is implemented.

IPv6 support is currently implemented using `MASQUERADE`, basically the same as in IPv4. This is sub-optimal, however I think all the other options are even worse.

## Option 1: Use a dedicated routed IPv6 block for the tunnel network

This way, the tunnel IP will be the global IP of the clients. Issues:

* We can't assume we have such a block available. We might be able to request such a block using dhcpv6, but that won't be available in most places this snap should work.
* That has privacy issues because your global IP would show whether you're using a VPN or not.
* More privacy issues because OpenVPN assigns IPv4 addresses sequentially. When you're the `n`th client, your IP will be `PREFIX::n`.

[how to implement](https://community.openvpn.net/openvpn/wiki/IPv6)

## Option 2: Splitting a single routable IPv6 netblock

Issues:

* This requires changing the network configuration of the host system. This is already a deal-breaker because, since we have no idea how the network is managed (interfaces/networkd/networkmanager/custom script), we can't do this reliably and safely.
* Much stuff won't work because the netblock will be smaller than `/64`
* Since we're splitting the netblock in half, it might be possible that other hosts on the existing network fall into the tunnel part, so they won't be reachable anymore.

[how to implement](https://community.openvpn.net/openvpn/wiki/IPv6)

## Option 3: NAT66 or SNPT+DNTP

Stateless source IPv6-to-IPv6 Network Prefix Translation (as described by RFC 6296). Use ULA block for tunnel network and translate ULA address 1-to-1 to global address in server range.

Issues:

* We would need [a custom client-connect script](https://superuser.com/questions/1151539/routing-problems-with-ipv6-over-openvpn/1161720#1161720) to respond to neighbor solicitations for every connected client.
* We would need [another custom client-connect script](https://forums.openvpn.net/viewtopic.php?t=12678) to randomize tunnel IPs so they don't collide with other OpenVPN servers on the same subnet as the server host.
* Those scripts would need to figure out what the resulting IPv6 address will be after NAT66 translation.
* Some applications will still fail because it's NAT.

[More info about SNTP](https://manpages.ubuntu.com/manpages/bionic/man8/iptables-extensions.8.html)

This is how I got it working manually:

```bash
PUBLIC_IP=..       # Public ipv6 ADDRESS of the OpenVPN server
PUBLIC_NETWORK=..  # Public ipv6 network the OpenVPN server is connected to
PUBLIC_IFACE=..    # Interface of the OpenVPN server to the internet
TUNNEL_NETWORK=..  # ULA network assigned to the tunnel
TUNNEL_IFACE=..    # Interface used by the tunnel

# Rewrite packets coming from tunnel going to the internet.
sudo ip6tables -t mangle -I POSTROUTING -s $TUNNEL_NETWORK -o $PUBLIC_IFACE -j SNPT --src-pfx $TUNNEL_NETWORK --dst-pfx $PUBLIC_NETWORK
# Rewrite packets coming from the internet going to the tunnel
sudo ip6tables -t mangle -A PREROUTING -d $PUBLIC_NETWORK -i $PUBLIC_IFACE -j DNPT --src-pfx $PUBLIC_NETWORK --dst-pfx $TUNNEL_NETWORK
# Don't rewrite packets destined to OpenVPN server.
sudo ip6tables -t mangle -I PREROUTING -d $PUBLIC_IP -j ACCEPT
# Turn off tracking
sudo ip6tables -t raw -A PREROUTING -i $TUNNEL_IFACE -d 2000::/3 -j NOTRACK
sudo ip6tables -t raw -A PREROUTING -i $PUBLIC_IFACE -s $PUBLIC_NETWORK -j NOTRACK

# For each client, advertise its public address
PUBLIC_CLIENT_IP=..    # Public IPv6 that the client gets after SNPT rewriting
sudo ip -6 neigh add proxy $PUBLIC_CLIENT_IP dev $PUBLIC_IFACE


# Note: use tcpdump for debugging:
sudo tcpdump -n -i $PUBLIC_IFACE icmp6
```

## Option 4: MASQUERADE

Issues:

* It's port-based nat (yuck..)
* Bad performance when LOTS of clients are connected.
* Some applications will fail because it's NAT (probably even more failures than option 3)

## Conclusion

* Option 4 is the easiest to implement and is probably the most stable option because we're not messing with `client-connect` scripts.
* Option 3 is also a possibility, however it would take a lot of time to implement correctly.
* Option 2 is a no-go.
* Option 1 would be nice to implement as an option.

We'll initially implement option 4. If too much applications fail, we'll look at implementing Option 3.
