# Easy OpenVPN Server

[![Snap Status](https://build.snapcraft.io/badge/IBCNServices/easy-openvpn-server.svg)](https://build.snapcraft.io/user/IBCNServices/easy-openvpn-server) [![Minecraft Installer](https://snapcraft.io/easy-openvpn-server/badge.svg)](https://snapcraft.io/easy-openvpn-server)

This snap contains a plug-and-play OpenVPN server. Get started in three steps:

1. Install the snap on the server.

   ```bash
   sudo snap install easy-openvpn-server
   sudo snap connect easy-openvpn-server:network-control
   sudo snap connect easy-openvpn-server:firewall-control
   ```

2. Copy the client config to your personal device.

   ```bash
   # Run this on the _server_ to create the config file.
   sudo easy-openvpn-server.show-client default > default.ovpn
   ```

   and from your device

   ```bash
   # Run this on the _client_ to download the config file.
   scp my-user@my-server:~/default.ovpn .
   ```

3. Import the `.ovpn` config file into the VPN application of your device.

The config file is set so the client will first try to connect using the fast udp protocol. If that fails, it will fall back to the harder-to-block tcp protocol which resembles HTTPS traffic.

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

```bash
# Change the ports of the udp and tcp daemon
sudo snap set easy-openvpn-server udp-server.port=1194
sudo snap set easy-openvpn-server tcp-server.port=80
# Update the address that clients use to connect to the server
sudo snap set easy-openvpn-server public-address=example.com
```

## FAQ

### Why OpenVPN instead of Wireguard?

OpenVPN is a lot better at punching through firewalls.

Wireguard is a great tool for connecting networks over an untrusted *but cooperative* network. However, if the network wants to block Wireguard traffic, it can very easily do so because Wireguard does not try to hide itself. Because OpenVPN uses SSL, it's much harder to distinguish its traffic from regular HTTPS traffic.



## Authors

This software was created in the [IDLab research group](https://idlab.technology/) of [Ghent University](https://www.ugent.be/en) in Belgium.

* Merlijn Sebrechts <merlijn.sebrechts@ugent.be>
