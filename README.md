# Easy OpenVPN Server

This snap contains a plug-and-play OpenVPN server. Install the snap, copy the client config to your device, and connect to the VPN.

## Use

```bash
sudo snap connect easy-openvpn-server:network-observe
sudo snap connect easy-openvpn-server:network-bind
sudo snap connect easy-openvpn-server:network-control
sudo snap connect easy-openvpn-server:firewall-control
```

```bash
# Initial setup
sudo easy-openvpn-server.setup
# Add clients
sudo easy-openvpn-server.add-client alice
# Remove clients
sudo easy-openvpn-server.remove-client alice
```

## Advanced Usage

```bash
# Show status

# Show logs
sudo journalctl -u snap.easy-openvpn-server.easy-openvpn-server
```

## Authors

This software was created in the [IDLab research group](https://idlab.technology/) of [Ghent University](https://www.ugent.be/en) in Belgium.

* Merlijn Sebrechts <merlijn.sebrechts@ugent.be>
