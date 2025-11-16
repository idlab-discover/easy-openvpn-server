# Easy OpenVPN Server

[![Snap Status](https://build.snapcraft.io/badge/idlab-discover/easy-openvpn-server.svg)](https://build.snapcraft.io/user/idlab-discover/easy-openvpn-server) [![Easy Openvpn Server](https://snapcraft.io/easy-openvpn-server/badge.svg)](https://snapcraft.io/easy-openvpn-server)

A plug-and-play OpenVPN server that "Just Works" and has secure defaults.

* By default, all the traffic of clients is sent over the VPN. Use this to securely connect to the internet, bust through firewalls and change your country.
* You can also use it to connect clients securely to a remote network and configure it so that only the traffic to the remote network will go over the VPN.

It supports both udp and tcp connections over IPv4 and IPv6. Clients will try the faster udp connection first. If that is blocked, they will fall back to a tcp connection that mimicks https traffic.

It automatically generates `.ovpn` client config files that work on Linux, Mac and Windows, Android and iOS.

## Getting started

1. Install the snap on the server.

   ```bash
   sudo snap install easy-openvpn-server
   ```

2. Copy the client config to your personal device.

   ```bash
   # Run this on the _server_ to create the config file.
   sudo easy-openvpn-server show-client default > default.ovpn
   ```

   and from your device

   ```bash
   # Run this on the _client_ to download the config file.
   scp my-user@my-server:~/default.ovpn .
   ```

3. Import the `.ovpn` config file into the VPN application of your device.

By default, the VPN will advertise itself as the default gateway, meaning that **all the traffic of your device will be sent over the VPN**. This is useful to secure your internet access or to pretend you are in a different country.

However, if you want to use the VPN to give users remote access to an internal network, you can run `sudo snap set easy-openvpn-server push-default-gateway=False`. This will make sure the VPN is only used for accessing resources on that internal network. Traffic from your device to the internet will not use the VPN in this mode.

## Managing clients

The snap automatically creates a client profile and config with the name `default`. However, it's recommended to create a separate client profile for each user. This way, you can revoke the client profile when that user does not need access to the VPN anymore.

```bash
# Add the client
sudo easy-openvpn-server add-client alice
# Get the client config
sudo easy-openvpn-server show-client alice > alice.ovpn
# Remove the client
sudo easy-openvpn-server remove-client alice
```

## Viewing connected clients and logs

```bash
# Show number of connected clients
sudo easy-openvpn-server.status
# Show logs
sudo journalctl -u snap.easy-openvpn-server.tcp-server
sudo journalctl -u snap.easy-openvpn-server.udp-server
```

## Changing hostname and port

The snap will do its best to figure out what the public address of the server is. However, when that fails, you can manually set the public address.

```bash
sudo snap set easy-openvpn-server public-address=example.com
```

By default the server runs on port 443/tcp (https) and 1194/udp (OpenVPN). If those ports are already used, you can change which ports the server runs on.

```bash
sudo snap set easy-openvpn-server udp-server.port=53
sudo snap set easy-openvpn-server tcp-server.port=80
```

## More options

You can specify additional search domains.

```bash
sudo snap set easy-openvpn-server additional-search-domains="test"
```

## Client-specific rules and access policies

You can give individual clients specific policies by creating a file with the name of that client in the following directory.

```txt
/var/snap/easy-openvpn-server/common/ccd/
```

For example, if you want the client `sysadmin` to always have the IP `10.8.1.1`, then add the following line to the file `/var/snap/easy-openvpn-server/common/ccd/sysadmin`

```txt
ifconfig-push 10.8.1.1 10.8.1.2
```

> Note: if you want to change the default config for all clients, you can add these changes in the file `/var/snap/easy-openvpn-server/common/ccd/sysadmin/DEFAULT`

## FAQ

### Why OpenVPN instead of Wireguard?

OpenVPN is a lot better at punching through firewalls.

Wireguard is a great tool for connecting networks over an untrusted *but cooperative* network. However, if the network wants to block Wireguard traffic, it can very easily do so because Wireguard does not try to hide itself. Because OpenVPN uses SSL, it's much harder to distinguish its traffic from regular HTTPS traffic.

### What can I use this VPN server for?

* Encrypt your communication with the internet.
* Change the location of your internet connection.
* Access services which are blocked by a firewall.
* Securely connect to a remote LAN.
* Access the IPv6 internet from a network that only supports IPv4 (or the other way around).

### Is this VPN secure?

This VPN is *intended* to be secure. It uses very secure encryption, DDoS protection and more. However, I am not a security expert, so it is definitely possible I made a mistake which causes it to be less secure.

You can verify the security yourself by looking at the generated configuration files in `/root/snap/easy-openvpn-server/current/`. If you find any issues, please let me know either on GitHub or by contacting me directly.

## Does it support IPv6?

Yes! You can connect to the server using both IPv4 and IPv6 and the tunnel also supports both. At the moment, it uses IPv6 NAT because it provides slightly better privacy and is compatible with almost any IPv6 setup. Read the [ipv6 brain-dump](./ipv6.md) for a more thorough comparison of the different ways to support IPv6 in OpenVPN.

## Authors

This software was created in the [IDLab research group](https://idlab.technology/) of [Ghent University](https://www.ugent.be/en) in Belgium.

* Merlijn Sebrechts <merlijn.sebrechts@ugent.be>
