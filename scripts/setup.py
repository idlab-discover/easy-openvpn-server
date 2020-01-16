#!/usr/bin/env python3

import datetime
import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import (serialization, hashes)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import sys

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

    return (ca_key, issuer)


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
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    # Sign our certificate with given ca key
    ).sign(ca_key, hashes.SHA256(), default_backend())
    # Write our certificate out to disk.
    with open("{}/server.crt".format(result_dir), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


if (len(sys.argv) > 1):
    result_dir = sys.argv[1]
    ca_key, issuer = create_ca(result_dir)
    create_cert(ca_key, issuer, result_dir)
else:
    print("ERROR: please specify the result directory.")
    exit(1)


