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
import stat
import subprocess
import sys

import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import (serialization, hashes)
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.oid import NameOID
from jinja2 import Environment, FileSystemLoader


def create_ca(result_dir):
    # Generate our key
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Write our key to disk for safe keeping
    with open("{}/ca.key".format(result_dir), "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
            # TODO: figure out if we can make this a bit more secure
            # encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))
    # Make sure other users can't read out private key
    os.chmod("{}/ca.key".format(result_dir), stat.S_IRUSR | stat.S_IWUSR )

    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Easy VPN server CA"),
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
        # Our certificate will be valid for about 100 years
        datetime.datetime.utcnow() + datetime.timedelta(days=36500)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    # Sign our certificate with our private key
    ).sign(ca_key, hashes.SHA256(), default_backend())
    # Write our certificate out to disk.
    with open("{}/ca.crt".format(result_dir), "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    return (ca_key, ca_cert, issuer)


def create_cert(ca_key, issuer, result_dir):
    # Generate our key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Write our key to disk for safe keeping
    with open("{}/server.key".format(result_dir), "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
            # encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))
    # Make sure other users can't read out private key
    os.chmod("{}/server.key".format(result_dir), stat.S_IRUSR | stat.S_IWUSR )

    # Various details about who we are.
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])



    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for about 100 years
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
    # Sign our certificate with given ca key
    ).sign(ca_key, hashes.SHA256(), default_backend())
    # Write our certificate out to disk.
    with open("{}/server.crt".format(result_dir), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # x509.KeyUsage()

    # x509.KeyUsage(digital_signature=True, key_encipherment=True)

def create_client_cert(result_dir, ca_key, ca_cert, issuer, client_name):
    # Generate our key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Write our key to disk for safe keeping
    with open("{}/client-configs/{}.key".format(result_dir, client_name), "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
            # encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))
    # Make sure other users can't read out private key
    os.chmod("{}/client-configs/{}.key".format(result_dir, client_name), stat.S_IRUSR | stat.S_IWUSR )

    # Various details about who we are.
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, client_name),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for about 100 years
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
    ).sign(ca_key, hashes.SHA256(), default_backend())
    # Write our certificate out to disk.
    with open("{}/client-configs/{}.crt".format(result_dir, client_name), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))    


def create_client_config(result_dir, name):
    with open("{}/ca.crt".format(result_dir)) as f:
        ca_cert_srt = f.read()
    with open("{}/client-configs/{}.crt".format(result_dir, name)) as f:
        client_cert_str = f.read()
    with open("{}/client-configs/{}.key".format(result_dir, name)) as f:
        client_key_str = f.read()
    with open("{}/ta.key".format(result_dir)) as f:
        ta_key_str = f.read()

    eipndict = get_extip_and_networks()
    pub_ip = eipndict['public-ip']
    context = {
        'protocol': "tcp",
        'address': pub_ip,
        'port': "443",
        'ca': ca_cert_srt,
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










def create_dh_params(result_dir):
    print("Generating Diffie-Hellman parameters. This might take up to a few minutes..")
    if not os.path.isfile("{}/dh4096.pem".format(result_dir)):
        parameters = dh.generate_parameters(generator=2, key_size=2048,
                                            backend=default_backend())
        # Write the dh parameters to disk.
        with open("{}/dh4096.pem".format(result_dir), "wb") as f:
            f.write(parameters.parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3))

def generate_psk(result_dir):
    if not os.path.isfile("{}/ta.key".format(result_dir)):
        subprocess.check_call(["openvpn", "--genkey", "--secret", "{}/ta.key".format(result_dir)])



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
    # TODO: do we need similar logic?
    # # If public-address is different from private-address, we're probably in a
    # # juju-supported cloud that we can trust to give us the right address that
    # # clients need to use to connect to us. If not, just use ext_ip.
    # if unit_get('private-address') != unit_get('public-address'):
    #     pub_ip = unit_get('public-address')
    # else:
    pub_ip = ext_ip
    print("External IP according to get_extip logic: {}".format(ext_ip))
    print("Public IP according to get_extip logic: {}".format(pub_ip))

    internal_networks = []
    pub_ip_obj = IPv4Address(pub_ip)
    ext_ip_obj = IPv4Address(ext_ip)
    for network in get_networks(remove_tunnels=True):
        if pub_ip_obj in network or ext_ip_obj in network:
            continue
        internal_networks.append("{} {}".format(
            network.network_address,
            network.netmask))
    print("Routes to push according to logic: {}".format(internal_networks))
    return {
        # IP of local interface that clients connect to.
        "external-ip": ext_ip,
        # IP that remote clients will use to connect to. This is identical to
        # external-ip except when Juju provides us with
        "public-ip": pub_ip,
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


def get_networks(remove_tunnels=False):
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


def get_tun_network():
    '''Return a random network for tun interface
    '''
    a_class = ip_network('10.0.0.0/255.0.0.0')
    nets = get_networks()
    available_networks = [a_class]
    for network in nets:
        updated = []
        for a_net in available_networks:
            try:
                net_iter = a_net.address_exclude(network)
                for n in net_iter:
                    updated.append(n)
            except ValueError:
                pass
        if updated:
            available_networks = updated
    if len(available_networks) == 0:
        print('ERROR: Could not find available server network')

    subnets = []
    for a_net in available_networks:
        try:
            subs = a_net.subnets(new_prefix=24)
            subnets.extend(subs)
        except ValueError:
            pass

    rand_ip = str(random.choice(subnets))
    return rand_ip.split('/')[0]

SERVERIP = get_tun_network()

def generate_config(result_dir):
    dns_info = get_dns_info()
    # clients = conf['clients'].split()
    eipndict = get_extip_and_networks()
    ext_ip = eipndict['external-ip']
    pub_ip = eipndict['public-ip']
    internal_networks = eipndict['internal-networks']
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
        'pub_ip': pub_ip,
        'internal_networks': internal_networks,
        'serverip': SERVERIP,
        'servernetmask': '255.255.255.0',
        'serverslashmask': '24',
    }
    j2_env = Environment(
        loader=FileSystemLoader(os.path.join(os.path.dirname(__file__),"../templates")),                                                                                                                            
        trim_blocks=True,
        lstrip_blocks=True)
    template = j2_env.get_template('server.conf')
    output = template.render(output=result_dir, **context)
    with open('{}/server.conf'.format(result_dir), 'w') as f:
        f.write(output)


def generate_init_script(result_dir):
    context = {
        'ovpn_network': "{}/24".format(SERVERIP),
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
    status_path = Path('{}/openvpn-server1-status.log'.format(result_dir))
    status_path.touch()
    uid = pwd.getpwnam("snap_daemon").pw_uid
    gid = grp.getgrnam("snap_daemon").gr_gid
    try:
        os.chown(status_path, uid, gid)
    except:
        pass

def create_client_configs_dir(result_dir):
    try:
        os.makedirs("{}/client-configs".format(result_dir))
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise










if (len(sys.argv) > 1):
    result_dir = sys.argv[1]
    ca_key, ca_cert, issuer = create_ca(result_dir)
    create_cert(ca_key, issuer, result_dir)
    create_dh_params(result_dir)
    generate_psk(result_dir)
    generate_config(result_dir)
    create_status_file(result_dir)
    create_client_configs_dir(result_dir)
    create_client_cert(result_dir, ca_key, ca_cert, issuer, "client42")
    create_client_config(result_dir, "client42")
    generate_init_script(result_dir)
else:
    print("ERROR: please specify the result directory.")
    exit(1)
