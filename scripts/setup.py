#!/usr/bin/env python3

import datetime
from distutils.util import strtobool
import errno
import grp
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
import json
import logging
import os
from pathlib import Path
import pwd
import random
import socket
import stat
import subprocess
import sys

import click
import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import (serialization, hashes)
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import NameOID
from jinja2 import Environment, FileSystemLoader


#
#
# Certificate and key management
#
#

def create_RSA_keypair(path):
    '''Creates and returns an RSA keypair and writes the private key to disk.
    '''
    # Generate the key
    keypair = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    # Write the key to disk for safe keeping
    with open(path, "wb") as f:
        f.write(keypair.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    # Make sure other users can't read the private key
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return keypair


def create_ca(result_dir):
    # If the key exists, we assume there is a valid keypair and certificate.
    if os.path.isfile("{}/ca.key".format(result_dir)):
        logging.info("CA key already exists, not creating a new one..")
        return
    ca_key = create_RSA_keypair("{}/ca.key".format(result_dir))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"BE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"East Flanders"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Ghent"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Easy OpenVPN Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"easy-openvpn-server CA"),
    ])
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # This certificate will be valid for about 100 years
        datetime.datetime.utcnow() + datetime.timedelta(days=36500)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    # Sign the certificate with the CA private key (self-signed)
    ).sign(ca_key, hashes.SHA256(), default_backend())
    # Write the certificate out to disk.
    with open("{}/ca.crt".format(result_dir), "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))


def create_server_cert(result_dir):
    # If the key exists, we assume there is a valid keypair and certificate.
    if os.path.isfile("{}/server.key".format(result_dir)):
        logging.info("Server key already exists, not creating a new one..")
        return
    key = create_RSA_keypair("{}/server.key".format(result_dir))

    with open("{}/ca.crt".format(result_dir), "rb") as f:
        data = f.read()
        ca_cert = x509.load_pem_x509_certificate(data, default_backend())
    with open("{}/ca.key".format(result_dir), "rb") as f:
        data = f.read()
        ca_key = load_pem_private_key(data, None, default_backend())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"BE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"East Flanders"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Ghent"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Easy OpenVPN Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"easy-openvpn-server Server"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # This certificate will be valid for about 100 years
        datetime.datetime.utcnow() + datetime.timedelta(days=36500)
    ).add_extension(
        # Make it clear this is a server key.
        # More explanation:
        #  - https://www.v13.gr/blog/?p=386
        #  - https://forums.openvpn.net/viewtopic.php?t=7484
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=True,
    ).add_extension(
        # TODO: try to remove this.
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    # Sign the certificate with ca key
    ).sign(ca_key, hashes.SHA256(), default_backend())
    # Write the certificate out to disk.
    with open("{}/server.crt".format(result_dir), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def create_client_cert(result_dir, client_name):
    # If the key exists, we assume there is a valid keypair and certificate.
    if os.path.isfile("{}/client-configs/{}.key".format(result_dir, client_name)):
        logging.info("Client key already exists, not creating a new one..")
        return
    key = create_RSA_keypair("{}/client-configs/{}.key".format(result_dir, client_name))

    with open("{}/ca.crt".format(result_dir), "rb") as f:
        data = f.read()
        ca_cert = x509.load_pem_x509_certificate(data, default_backend())
    with open("{}/ca.key".format(result_dir), "rb") as f:
        data = f.read()
        ca_key = load_pem_private_key(data, None, default_backend())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"BE"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"East Flanders"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Ghent"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Easy OpenVPN Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, client_name),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # This certificate will be valid for about 100 years
        datetime.datetime.utcnow() + datetime.timedelta(days=36500)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=False,
    ).add_extension(
        # Make sure this key can only be used for clients
        # This is to prevent man-in-the-middle attack
        # with client certificate.
        # More info:
        #  - https://openvpn.net/community-resources/how-to
        #  - https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
        critical=True,
    # Sign the certificate with ca key
    ).sign(ca_key, hashes.SHA256(), default_backend())
    # Write the certificate out to disk.
    with open("{}/client-configs/{}.crt".format(result_dir, client_name), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))    


def create_dh_params(result_dir):
    # Generating these parameters is expensive so don't overwrite existing params.
    if os.path.isfile("{}/dh4096.pem".format(result_dir)):
        return
    logging.info("Generating Diffie-Hellman parameters. This might take up to a few minutes..")
    parameters = dh.generate_parameters(generator=2, key_size=4096,
                                        backend=default_backend())
    # Write the dh parameters to disk.
    with open("{}/dh4096.pem".format(result_dir), "wb") as f:
        f.write(parameters.parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3))


def get_dh_params_path(result_dir):
    dh_params_type = get_config("dh-params-type")
    if dh_params_type == "generated":
        create_dh_params(result_dir)
        return "./dh4096.pem"
    else:
        set_config("dh-params-type", "rfc3526")
        return "{}/templates/RFC3526-dh4096.pem".format(os.environ['SNAP'])


def create_psk(result_dir):
    # Don't overwrite existing PSK because that will break existing client
    # config files.
    if os.path.isfile("{}/ta.key".format(result_dir)):
        return
    subprocess.check_call(["openvpn", "--genkey", "--secret", "{}/ta.key".format(result_dir)])


#
#
#  Utility functions to gather information
#
#


def get_default_ip():
    '''Get the IP used by the interface that connects to
    the default gateway.
    '''
    output = subprocess.check_output(["ip", "-o", "route", "get", "1.1.1.1"],
                                     universal_newlines=True)
    return output.split(" ")[6]


def get_public_addresses():
    '''returns public addresses. If no address of server is public, and none is
    set in the config, it returns the ip used by the interface that connects to
    the default gateway.
    '''
    public_addresses = []
    output = subprocess.check_output(
        ["ip", "-o", "address", "show", "scope", "global", "primary"], universal_newlines=True)
    for line in output.rstrip().split("\n"):
        line = line.split()
        address = ip_address(line[3].split('/')[0])
        if address.is_global:
            public_addresses.append(address)
    # Prefer ipv4 addresses, since more places are ipv4-only than ipv6-only
    public_addresses.sort(key=lambda x: x.version)
    # If user manually set `public-address` setting, prefer that one.
    if get_config("public-address"):
        public_addresses.insert(0, get_config("public-address"))
    # Fallback to default ip when no public are found
    if len(public_addresses) == 0:
        public_addresses.append(IPv4Address(get_default_ip()))
    logging.info("Public addresses according to get_public_addresses: {}".format(public_addresses))
    return [str(a) for a in public_addresses]


# def get_internal_networks(public_ips):
#     internal_networks = []
#     for network in get_known_networks(remove_tunnels=True):
#         known = False
#         for ip in public_ips:
#             if ip in network:
#                 known = True
#                 break
#         if not known:
#             internal_networks.append("{} {}".format(
#                 network.network_address,
#                 network.netmask))
#     logging.info("Routes to push according to logic: {}".format(internal_networks))
#     return internal_networks

def get_dns_info():
    info = parse_resolvconf('/etc/resolv.conf')
    # Often, resolf.conf will point to local resolver. If this resolver is
    # resolvd, we can scan its file. Otherwise, don't pass a nameserver.
    loopback_ns = False
    for ns_address in info['nameservers']:
        ns_address = IPv4Address(ns_address)
        if ns_address.is_loopback:
            loopback_ns = True

    if loopback_ns:
        info['nameservers'] = []
        try:
            resolved_info = parse_resolvconf('/run/systemd/resolve/resolv.conf')
            info = resolved_info
        except FileNotFoundError:
            pass
    return info


def parse_resolvconf(resolv_path):
    info = {
        "nameservers": []
    }
    with open(resolv_path, 'r') as resolv_file:
        content = resolv_file.readlines()
    for line in content:
        words = line.split()
        if len(words) > 1:
            if words[0] == "nameserver":
                info['nameservers'].append(words[1])
            elif words[0] == "search":
                info['search'] = words[1:]
    return info


def get_known_networks(remove_tunnels=False):
    '''Returns a list with IPv4 networks that this host has routes for.
    '''
    networks = []
    output = subprocess.check_output(['ip', 'route', 'show'], universal_newlines=True)
    for line in output.splitlines():
        # Skip all tunnel and VPN-connected networks
        if remove_tunnels and ("tun" in line):
            continue
        words = line.split()
        # Skip default gateways
        if words[0] == "default":
            continue
        networks.append(ip_network(words[0]))
    return networks


def pick_tun_networks(netmask_bits):
    '''Returns a random network that is available to use for the tun interface.
    The randomness decreases the chance that the network will collide with
    existing remote networks and VPN's. This way, users can safely connect
    to multiple easy-openvpn-instances at the same time.
    '''
    known_network = get_known_networks()
    available_networks = [ip_network('10.0.0.0/255.0.0.0')]
    # Remove all used networks from the available networks.
    for used_net in known_network:
        updated = []
        for available_net in available_networks:
            try:
                net_iter = available_net.address_exclude(used_net)
                for n in net_iter:
                    updated.append(n)
            except ValueError:
                pass
        if updated:
            available_networks = updated
    if len(available_networks) == 0:
        logging.error('Could not find available server network')
    # Divide the available networks in subnets.
    subnets = []
    for available_net in available_networks:
        try:
            subs = available_net.subnets(new_prefix=netmask_bits)
            subnets.extend(subs)
        except ValueError:
            pass
    # Pick two random available subnet.
    return random.sample(subnets, 2)


def get_push_default_gateway():
    push_default_gateway = get_config("push-default-gateway")
    if push_default_gateway:
        return strtobool(push_default_gateway.lower())
    else:
        set_config("push-default-gateway", "True")
        return True
#
#
# Snapcraft utility functions
#
#


def get_config(key):
    output = subprocess.check_output(['snapctl', 'get', key], universal_newlines=True)
    output = output.rstrip()
    return output


def set_config(key, value):
    subprocess.check_call(['snapctl', 'set', '{}={}'.format(key, str(value))])


def restart_daemons():
    subprocess.check_call(['snapctl', 'restart', "easy-openvpn-server.tcp-server"])
    subprocess.check_call(['snapctl', 'restart', "easy-openvpn-server.udp-server"])


#
#
# Creation of config files
#
#


def get_tun_networks(result_dir):
    '''Returns the network to use for the tunnel. Generates a new
    network if one was not saved yet.
    '''
    tcp_tun_network = get_config("internal.tcp.tun-network")
    udp_tun_network = get_config("internal.udp.tun-network")
    if tcp_tun_network and udp_tun_network:
        try:
            tcp_tun_network = ip_network(tcp_tun_network)
            udp_tun_network = ip_network(udp_tun_network)
            return (tcp_tun_network, udp_tun_network)
        except ValueError as e:
            logging.error("tun-network setting is invalid: {}".format(e))
    tun_networks = pick_tun_networks(24)
    set_config("internal.tcp.tun-network", str(tun_networks[0]))
    set_config("internal.udp.tun-network", str(tun_networks[1]))
    return (tun_networks[0], tun_networks[1])


def get_ports():
    tcp_port = get_config("tcp-server.port")
    if not tcp_port:
        tcp_port = "443"
        set_config("tcp-server.port", tcp_port)
    udp_port = get_config("udp-server.port")
    if not udp_port:
        udp_port = "1194"
        set_config("udp-server.port", udp_port)
    return (tcp_port, udp_port)

def create_server_config(result_dir, status_dir):
    dns_info = get_dns_info()
    (tcp_tunnel_network, udp_tunnel_network) = get_tun_networks(result_dir)
    (tcp_port, udp_port) = get_ports()
    tcp_context = {
        'config_dir': '.',
        'data_dir': '.',
        'dh': get_dh_params_path(result_dir),
        'status_file_path': "{}/tcp-server-status.log".format(status_dir),
        'servername': "easy-openvpn-server-1",
        'protocol': "tcp6-server",
        'port': tcp_port,
        'duplicate_cn': True,
        'push_dns': True,
        'push_default_gateway': get_push_default_gateway(),
        # Default to OpenDNS when no nameservers were found
        'dns_servers': dns_info.get('nameservers', ["208.67.222.222", "208.67.220.220"]),
        'dns_search_domains': dns_info.get('search', []),
        'internal_networks': get_known_networks(remove_tunnels=True),
        'tunnel_network': str(tcp_tunnel_network.network_address),
        'tunnel_netmask': str(tcp_tunnel_network.netmask),
    }
    import jinja2
    j2_env = Environment(
        loader=FileSystemLoader(os.path.join(os.path.dirname(__file__),"../templates")),
        trim_blocks=True,
        lstrip_blocks=True,
        undefined=jinja2.StrictUndefined)
    template = j2_env.get_template('server.conf')
    output = template.render(output=result_dir, **tcp_context)
    with open('{}/tcp-server.conf'.format(result_dir), 'w') as f:
        f.write(output)

    udp_context = tcp_context
    udp_context['status_file_path'] = "{}/udp-server-status.log".format(status_dir)
    udp_context['port'] = udp_port
    udp_context['protocol'] = "udp6"
    udp_context['tunnel_network'] = str(udp_tunnel_network.network_address)
    udp_context['tunnel_netmask'] = str(udp_tunnel_network.netmask)

    j2_env = Environment(
        loader=FileSystemLoader(os.path.join(os.path.dirname(__file__),"../templates")),
        trim_blocks=True,
        lstrip_blocks=True)
    template = j2_env.get_template('server.conf')
    output = template.render(output=result_dir, **udp_context)
    with open('{}/udp-server.conf'.format(result_dir), 'w') as f:
        f.write(output)


def create_client_configs_dir(result_dir):
    try:
        os.makedirs("{}/client-configs".format(result_dir))
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


def create_client_config(result_dir, name):
    with open("{}/ca.crt".format(result_dir)) as f:
        ca_cert_str = f.read()
    with open("{}/client-configs/{}.crt".format(result_dir, name)) as f:
        client_cert_str = f.read()
    with open("{}/client-configs/{}.key".format(result_dir, name)) as f:
        client_key_str = f.read()
    with open("{}/ta.key".format(result_dir)) as f:
        ta_key_str = f.read()

    (tcp_port, udp_port) = get_ports()
    context = {
        'tcp_port': tcp_port,
        'udp_port': udp_port,
        'protocol': "tcp",
        'public_addresses': get_public_addresses(),
        'ca': ca_cert_str,
        'cert': client_cert_str,
        'key': client_key_str,
        'tls_auth': ta_key_str,
    }
    j2_env = Environment(
        loader=FileSystemLoader(os.path.join(os.path.dirname(__file__),"../templates")),                                                                                                                            
        trim_blocks=True,
        lstrip_blocks=True)
    template = j2_env.get_template('client.ovpn')
    output = template.render(output=result_dir, **context)
    with open("{}/client-configs/{}.ovpn".format(result_dir, name), 'w') as f:
        f.write(output)


def show_client_config(result_dir, name):
    try:
        with open("{}/client-configs/{}.ovpn".format(result_dir, name)) as f:
            client_config_str = f.read()
            print(client_config_str)
    except FileNotFoundError:
        logging.error(
            "Config for client {} does not appear to exist.\n"
            "You can create it by running\n"
            "\tsudo easy-openvpn-server add-client {}".format(name, name))


def get_clients(result_dir):
    '''Returns a list of all clients which have a certificate
    '''
    import glob
    clients = glob.glob(r'{}/client-configs/*.crt'.format(result_dir))
    clients = [os.path.splitext(os.path.basename(c))[0] for c in clients]
    return clients


def create_status_files(status_dir):
    # This function currently doesn't work
    # https://forum.snapcraft.io/t/system-usernames/13386/4?u=galgalesh
    tcp_status_path = Path('{}/tcp-server-status.log'.format(status_dir))
    udp_status_path = Path('{}/udp-server-status.log'.format(status_dir))
    tcp_status_path.touch()
    udp_status_path.touch()
    try:
        os.chmod(tcp_status_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
        os.chmod(udp_status_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
    except PermissionError:
        # This call is supposed to fail when the files are already chown'd.
        pass
    subprocess.check_call(['chown', 'snap_daemon', tcp_status_path])
    subprocess.check_call(['chown', 'snap_daemon', udp_status_path])
    # uid = pwd.getpwnam("snap_daemon").pw_uid
    # gid = grp.getgrnam("snap_daemon").gr_gid
    # os.chown(tcp_status_path, uid, 0)
    # os.chown(udp_status_path, uid, 0)


#
#
# Main program
#
#


@click.group()
@click.pass_context
def cli(ctx):
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    if os.geteuid() != 0:
        logging.error("Please run this as root!")
        exit(1)
    ctx.obj = {}
    ctx.obj["result_dir"] = os.environ['SNAP_USER_DATA']
    ctx.obj["status_dir"] = os.environ['SNAP_DATA']


@cli.command()
@click.pass_context
def setup(ctx):
    """Initialises OpenVPN config files, keys and CA.
    """
    create_ca(ctx.obj["result_dir"])
    create_psk(ctx.obj["result_dir"])
    create_server_cert(ctx.obj["result_dir"])
    create_server_config(ctx.obj["result_dir"], ctx.obj["status_dir"])
    create_status_files(ctx.obj["status_dir"])
    create_client_configs_dir(ctx.obj["result_dir"])
    restart_daemons()
    create_client_cert(ctx.obj["result_dir"], "default")
    for client in get_clients(ctx.obj["result_dir"]):
        create_client_config(ctx.obj["result_dir"], client)


@cli.command()
@click.pass_context
@click.argument('client_name')
def add_client(ctx, client_name):
    """Creates a new client config with given name.
    """
    create_client_cert(ctx.obj["result_dir"], client_name)
    create_client_config(ctx.obj["result_dir"], client_name)
    logging.info(
        "Added {name}. You can copy its config using\n"
        "\tsudo easy-openvpn-server show-client {name} > {name}.ovpn".format(
            name=client_name))


@cli.command()
@click.pass_context
@click.argument('client_name')
def show_client(ctx, client_name):
    """Outputs the client config file in `.ovpn` format to stdout.
    """
    show_client_config(ctx.obj["result_dir"], client_name)


@cli.command()
@click.pass_context
@click.argument('client_name')
def remove_client(ctx, client_name):
    """Remove the client config.
    """
    client_name = client_name.lower()
    try:
        os.rename(
            "{}/client-configs/{}.ovpn".format(ctx.obj["result_dir"], client_name),
            "{}/client-configs/{}.ovpn.removed".format(ctx.obj["result_dir"], client_name))
    except FileNotFoundError:
        logging.warning("Could not find client config file.")
    try:
        os.rename(
            "{}/client-configs/{}.crt".format(ctx.obj["result_dir"], client_name),
            "{}/client-configs/{}.crt.removed".format(ctx.obj["result_dir"], client_name))
    except FileNotFoundError:
        logging.warning("Could not find client certificate.")
    try:
        os.rename(
            "{}/client-configs/{}.key".format(ctx.obj["result_dir"], client_name),
            "{}/client-configs/{}.key.removed".format(ctx.obj["result_dir"], client_name))
    except FileNotFoundError:
        logging.warning("Could not find client private key.")


if __name__ == "__main__":
    cli() #pylint: disable=E1123,E1120
