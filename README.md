# Easy OpenVPN Server

This snap contains a plug-and-play OpenVPN server. Install the snap, copy the client config to your device, and connect to the VPN.

# Use

```bash
sudo snap connect easy-openvpn-server:network-observe
sudo snap connect easy-openvpn-server:network-bind
sudo snap connect easy-openvpn-server:network-control
sudo snap connect easy-openvpn-server:firewall-control
```

```
sudo easy-openvpn-server.setup
```

# Advanced Usage

```
# Show status

# Show logs
sudo journalctl -u snap.easy-openvpn-server.easy-openvpn-server
```

# Authors

This software was created in the [IDLab research group](https://idlab.technology/) of [Ghent University](https://www.ugent.be/en) in Belgium.

* Merlijn Sebrechts <merlijn.sebrechts@ugent.be>
