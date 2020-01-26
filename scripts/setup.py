#!/usr/bin/env python3

import datetime
import errno
import grp
from ipaddress import IPv4Address, ip_network
import json
import os
from pathlib import Path
import pwd
import random
import socket
import stat
import subprocess
import sys

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
        print("INFO: CA key already exists, not creating a new one..")
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
        print("INFO: Server key already exists, not creating a new one..")
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
        print("INFO: Client key already exists, not creating a new one..")
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
    print("Generating Diffie-Hellman parameters. This might take up to a few minutes..")
    parameters = dh.generate_parameters(generator=2, key_size=4096,
                                        backend=default_backend())
    # Write the dh parameters to disk.
    with open("{}/dh4096.pem".format(result_dir), "wb") as f:
        f.write(parameters.parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3))


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


def facter(argument=None):
    ''' return output of `facter` as a dict
    '''
    output = subprocess.check_output(["facter", '-j', argument],
                                     universal_newlines=True)
    return json.loads(output)

def get_extip_and_networks():
    '''returns public ip. If no ip of server is public, it returns ip from
    `facter`
    '''
    net_info = facter('networking')
    ext_ip = None
    internal_networks = []
    for iface, content in net_info['networking']['interfaces'].items():
        if not any(bl_iface in iface for bl_iface in ['lo', 'tun']):
            for binding in content.get('bindings', []):
                address = IPv4Address(binding['address'])
                #
                # GET PUBLIC IP
                # Can't use is_global in 14.04 because of following bug:
                # https://bugs.python.org/issue21386
                if not address.is_private:
                    ext_ip = address
    if not ext_ip:
        ext_ip = net_info['networking']['ip']
    public_address = ext_ip
    # If user manually set `public-address` setting, use that one.
    if get_config("public-address"):
        public_address = get_config("public-address")

    print("External IP according to get_extip logic: {}".format(ext_ip))
    print("Public address according to get_extip logic: {}".format(public_address))

    try:
        public_ip = socket.gethostbyname(public_address)
    except socket.error:
        print("WARNING: Failed to resolve the public-address '{}'".format(public_address))
        public_ip = ext_ip

    internal_networks = []
    public_ip_obj = IPv4Address(public_ip)
    ext_ip_obj = IPv4Address(ext_ip)
    for network in get_used_networks(remove_tunnels=True):
        if public_ip_obj in network or ext_ip_obj in network:
            continue
        internal_networks.append("{} {}".format(
            network.network_address,
            network.netmask))
    print("Routes to push according to logic: {}".format(internal_networks))
    return {
        # IP of local interface that clients connect to.
        "external-ip": ext_ip,
        # Address that remote clients will use to connect to this machine.
        # This is identical to external-ip except when a user manually
        # overrides it.
        "public-address": public_address,
        "internal-networks": internal_networks,
    }


def get_dns_info():
    info = {}
    with open('/etc/resolv.conf', 'r') as resolv_file:
        content = resolv_file.readlines()
    for line in content:
        words = line.split()
        if len(words) > 1:
            if words[0] == "nameserver":
                info['nameserver'] = words[1]
            elif words[0] == "search":
                info['search'] = words[1:]
    return info


def get_used_networks(remove_tunnels=False):
    '''Returns a list with Ip Networks that are in use
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


def pick_tun_network(netmask_bits):
    '''Returns a random network that is available to use for the tun interface.
    The randomness decreases the chance that the network will collide with
    existing remote networks and VPN's. This way, users can safely connect
    to multiple easy-openvpn-instances at the same time.
    '''
    used_networks = get_used_networks()
    available_networks = [ip_network('10.0.0.0/255.0.0.0')]
    # Remove all used networks from the available networks.
    for used_net in used_networks:
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
        print('ERROR: Could not find available server network')
    # Divide the available networks in subnets.
    subnets = []
    for available_net in available_networks:
        try:
            subs = available_net.subnets(new_prefix=netmask_bits)
            subnets.extend(subs)
        except ValueError:
            pass
    # Pick a random available subnet.
    return random.choice(subnets)


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


#
#
# Creation of config files
#
#


def get_tun_network(result_dir):
    '''Returns the network to use for the tunnel. Generates a new
    network if one was not saved yet.
    '''
    tun_network = get_config("tun-network")
    if tun_network:
        try:
            tun_network = ip_network(tun_network)
            return tun_network
        except ValueError as e:
            print("ERROR: tun-network setting is invalid: {}".format(e))
    tun_network = pick_tun_network(24)
    set_config("tun-network", tun_network)
    return tun_network


def create_server_config(result_dir):
    dns_info = get_dns_info()
    eipndict = get_extip_and_networks()
    ext_ip = eipndict['external-ip']
    internal_networks = eipndict['internal-networks']
    tunnel_network = get_tun_network(result_dir)
    context = {
        'config_dir': '.',
        'data_dir': '.',
        'servername': "easy-openvpn-server-1",
        'protocol': "tcp-server",
        'port': "443",
        'duplicate_cn': True,
        'push_dns': True,
        'push_default_gateway': True,
        'dns_server': dns_info.get('nameserver', "8.8.8.8"),
        'dns_search_domains': dns_info.get('search', []),
        'ext_ip': ext_ip,
        'internal_networks': internal_networks,
        'tunnel_network': str(tunnel_network.network_address),
        'tunnel_netmask': str(tunnel_network.netmask),
    }
    j2_env = Environment(
        loader=FileSystemLoader(os.path.join(os.path.dirname(__file__),"../templates")),                                                                                                                            
        trim_blocks=True,
        lstrip_blocks=True)
    template = j2_env.get_template('server.conf')
    output = template.render(output=result_dir, **context)
    with open('{}/server.conf'.format(result_dir), 'w') as f:
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

    eipndict = get_extip_and_networks()
    pub_ip = eipndict["public-address"]
    context = {
        'protocol': "tcp",
        'address': pub_ip,
        'port': "443",
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


def create_init_script(result_dir):
    context = {
        'ovpn_network': str(get_tun_network(result_dir)),
    }
    j2_env = Environment(
        loader=FileSystemLoader(os.path.join(os.path.dirname(__file__),"../templates")),                                                                                                                            
        trim_blocks=True,
        lstrip_blocks=True)
    template = j2_env.get_template('init.sh')
    output = template.render(output=result_dir, **context)
    with open('{}/init.sh'.format(result_dir), 'w') as f:
        f.write(output)    


def create_status_file(result_dir):
    # This function currently doesn't work
    # https://forum.snapcraft.io/t/system-usernames/13386/4?u=galgalesh
    status_path = Path('{}/openvpn-server1-status.log'.format(result_dir))
    try:
        status_path.touch()
        # os.chmod(status_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH)
        os.chmod(status_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
        uid = pwd.getpwnam("snap_daemon").pw_uid
        gid = grp.getgrnam("snap_daemon").gr_gid
        os.chown(status_path, uid, gid)
    except PermissionError:
        pass


#
#
# Main program
#
#


if (len(sys.argv) < 1):
    print("ERROR: please specify a command.")
    exit(1)

command = sys.argv[1]
result_dir = os.environ['SNAP_USER_DATA']

if command == "setup":
    create_ca(result_dir)
    create_dh_params(result_dir)
    create_psk(result_dir)
    create_server_cert(result_dir)
    create_server_config(result_dir)
    create_status_file(result_dir)
    create_client_configs_dir(result_dir)
    create_init_script(result_dir)
    create_client_cert(result_dir, "default")
    create_client_config(result_dir, "default")

elif command == "add-client":
    if (len(sys.argv) < 2):
        print("ERROR: please specify the client name.")
        exit(1)
    client_name = sys.argv[2]
    create_client_cert(result_dir, client_name)
    create_client_config(result_dir, client_name)

elif command == "remove-client":
    if (len(sys.argv) < 2):
        print("ERROR: please specify the client name.")
        exit(1)
    client_name = sys.argv[2]
    try:
        os.rename(
            "{}/client-configs/{}.ovpn".format(result_dir, client_name),
            "{}/client-configs/{}.ovpn.removed".format(result_dir, client_name))
    except FileNotFoundError:
        print("WARNING: could not find client config file.")
    try:
        os.rename(
            "{}/client-configs/{}.crt".format(result_dir, client_name),
            "{}/client-configs/{}.crt.removed".format(result_dir, client_name))
    except FileNotFoundError:
        print("WARNING: could not find client certificate.")
    try:
        os.rename(
            "{}/client-configs/{}.key".format(result_dir, client_name),
            "{}/client-configs/{}.key.removed".format(result_dir, client_name))
    except FileNotFoundError:
        print("WARNING: could not find client private key.")

else:
    print("command {} not recognised".format(command))
