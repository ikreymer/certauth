import logging
import os

from io import BytesIO

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, load_pem_private_key, pkcs12
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import idna
import ipaddress
import datetime

import random

import ipaddress
import tldextract

from argparse import ArgumentParser

from collections import OrderedDict

import threading

# =================================================================

_CA_CERT_VALID_DAYS = 1095
_HOST_CERT_VALID_DAYS = 3
def _CA_CERT_NOT_AFTER(): return datetime.datetime.utcnow() + datetime.timedelta(days=_CA_CERT_VALID_DAYS)
def _CA_CERT_NOT_BEFORE(): return datetime.datetime.utcnow() - datetime.timedelta(days=1)
def _HOST_CERT_NOT_AFTER(): return datetime.datetime.utcnow() + datetime.timedelta(days=_HOST_CERT_VALID_DAYS)
def _HOST_CERT_NOT_BEFORE(): return datetime.datetime.utcnow() - datetime.timedelta(days=1)

_CERTS_DIR = './ca/certs/'

_CERT_NAME = 'certauth sample CA'

#DEF_HASH_FUNC = 'sha256'

_ROOT_CA = '!!root_ca'

def _normalized(s): #we  must comply with str(ip_address()) to pass tests
        try:
            return str(ipaddress.ip_address(s))
        except (ValueError, UnicodeDecodeError):
            return s

# =================================================================
class CertificateAuthority(object):
    """
    Utility class for signing individual certificate
    with a root cert.

    Static generate_ca_root() method for creating the root cert

    All certs saved on filesystem. Individual certs are stored
    in specified certs_dir and reused if previously created.
    """

    def __init__(self, ca_name,
                 ca_file_cache,
                 cert_cache=None,
                 cert_not_before=None,
                 cert_not_after=None,
                 overwrite=False):

        if isinstance(ca_file_cache, str):
            self.ca_file_cache = RootCACache(ca_file_cache)
        else:
            self.ca_file_cache = ca_file_cache

        if isinstance(cert_cache, str):
            self.cert_cache = FileCache(cert_cache)
        elif isinstance(cert_cache, int):
            self.cert_cache = LRUCache(max_size=cert_cache)
        elif cert_cache is None:
            self.cert_cache = LRUCache(max_size=100)
        else:
            self.cert_cache = cert_cache

        self.ca_name = ca_name

        self.cert_not_before = cert_not_before

        self.cert_not_after = cert_not_after

        res = self.load_root_ca_cert(overwrite=overwrite)
        self.ca_cert, self.ca_key = res

    def load_root_ca_cert(self, overwrite=False):
        cert_str = None

        if not overwrite:
            cert_str = self.ca_file_cache.get(_ROOT_CA)

        # if cached, just read pem
        if cert_str:
            cert, key = self.read_pem(BytesIO(cert_str))

        else:
            cert, key = self.generate_ca_root(self.ca_name)

            # Write cert + key
            buff = BytesIO()
            self.write_pem(buff, cert, key)
            cert_str = buff.getvalue()

            # store cert in cache
            self.ca_file_cache[_ROOT_CA] = cert_str

        return cert, key

    def is_host_ip(self, host):
        try:
            # if py2.7, need to decode to unicode str
            if hasattr(host, 'decode'):  #pragma: no cover
                host = host.decode('ascii')

            ipaddress.ip_address(host)
            return True
        except (ValueError, UnicodeDecodeError):
            return False

    def get_wildcard_domain(self, host):
        host_parts = host.split('.', 1)
        if len(host_parts) < 2 or '.' not in host_parts[1]:
            return host

        ext = tldextract.extract(host)

        # allow using parent domain if:
        # 1) no suffix (unknown tld)
        # 2) the parent domain contains 'domain.suffix', not just .suffix
        if not ext.suffix or ext.domain + '.' + ext.suffix in host_parts[1]:
            return host_parts[1]

        return host

    def load_cert(self, host, overwrite=False,
                              wildcard=False,
                              wildcard_use_parent=False,
                              include_cache_key=False,
                              cert_ips=set(),
                              cert_fqdns=set()):

        is_ip = self.is_host_ip(host)

        if is_ip:
            wildcard = False

        if wildcard and wildcard_use_parent:
            host = self.get_wildcard_domain(host)

        cert_ips = list(cert_ips)  # set to ordered list

        cert_str = None

        if not overwrite:
            cert_str = self.cert_cache.get(host)

        # if cached, just read pem
        if cert_str:
            cert, key = self.read_pem(BytesIO(cert_str))
            
            #Renew certificate
            days_remain = (cert.not_valid_after - datetime.datetime.utcnow()).total_seconds()/86400 #float days til expiration
            print("DaysRemain: "+str(days_remain))
            if days_remain < 2*_HOST_CERT_VALID_DAYS/3:
                cert, key = self.renew_host_certificate(cert, key)
                # Write cert + key
                buff = BytesIO()
                self.write_pem(buff, cert, key)
                cert_str = buff.getvalue()
                self.cert_cache[host] = cert_str

        else:
            # if not cached, generate new root or host cert
            cert, key = self.generate_host_cert(host,
                                                self.ca_cert,
                                                self.ca_key,
                                                wildcard,
                                                is_ip=is_ip,
                                                cert_ips=cert_ips,
                                                cert_fqdns=cert_fqdns)

            # Write cert + key
            buff = BytesIO()
            self.write_pem(buff, cert, key)
            cert_str = buff.getvalue()

            # store cert in cache
            self.cert_cache[host] = cert_str

        if not include_cache_key:
            return cert, key

        else:
            cache_key = host
            if hasattr(self.cert_cache, 'key_for_host'):
                cache_key = self.cert_cache.key_for_host(host)

            return cert, key, cache_key

    def cert_for_host(self, host, overwrite=False,
                                  wildcard=False,
                                  cert_ips=set(),
                                  cert_fqdns=set()):

        res = self.load_cert(host, overwrite=overwrite,
                                wildcard=wildcard,
                                wildcard_use_parent=False,
                                include_cache_key=True,
                                cert_ips=cert_ips,
                                cert_fqdns=cert_fqdns)

        return res[2]

    def get_wildcard_cert(self, cert_host, overwrite=False):
        res = self.load_cert(cert_host, overwrite=overwrite,
                                        wildcard=True,
                                        wildcard_use_parent=True,
                                        include_cache_key=True)

        return res[2]

    def get_root_PKCS12(self):
        p12 = pkcs12.serialize_key_and_certificates(
            self.ca_name.encode(),
            self.ca_key,
            self.ca_cert,
            [self.ca_cert],
            NoEncryption())
        return p12

    def get_root_pem(self):
        return self.ca_file_cache.get(_ROOT_CA)

    def get_root_pem_filename(self):
        return self.ca_file_cache.ca_file

    def generate_ca_root(self, ca_name):

        #in case ca_name is ip_address:
        #THERE IS NO TEST FOR THIS, IS THIS A REAL CASE?
        ca_name = _normalized(ca_name)

        # Generate key
        key = ec.generate_private_key(ec.SECP384R1())

        # Generate cert
        builder = x509.CertificateBuilder()
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ca_name)]))
        if self.cert_not_before:
            builder = builder.not_valid_before(self.cert_not_before)
        else:
            builder = builder.not_valid_before(_CA_CERT_NOT_BEFORE())
            
        if self.cert_not_after:
            builder = builder.not_valid_after(self.cert_not_after)
        else:
            builder = builder.not_valid_after(_CA_CERT_NOT_AFTER())
            
        subj = builder._subject_name.rfc4514_string().strip('CN=')
        builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subj)]))
        builder = builder.public_key(key.public_key())
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        
        builder = builder.add_extension(x509.KeyUsage(
            content_commitment=True,
            crl_sign=True,
            data_encipherment=True,
            decipher_only=False,
            digital_signature=True,
            encipher_only=False,
            key_agreement=True,
            key_cert_sign=True, 
            key_encipherment=True),
            critical=True)
        
        builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        cert = builder.sign(private_key=key, algorithm=hashes.SHA256())

        return cert, key

    def generate_host_cert(self, host, root_cert, root_key,
                           wildcard=False,
                           is_ip=False,
                           cert_ips=set(),
                           cert_fqdns=set()):

        #In case host is an ip_address
        host = _normalized(host)

        # Generate Key
        key = ec.generate_private_key(ec.SECP384R1())

        # Generate Cert
        builder = x509.CertificateBuilder()
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
        if self.cert_not_before:
            builder = builder.not_valid_before(self.cert_not_before)
        else:
            builder = builder.not_valid_before(_HOST_CERT_NOT_BEFORE())

        if self.cert_not_after:
            builder = builder.not_valid_after(self.cert_not_after)
        else:
            builder = builder.not_valid_after(_HOST_CERT_NOT_AFTER())
        issuer = root_cert.subject.rfc4514_string().strip("CN=")
        builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))

        builder = builder.public_key(key.public_key())

        all_hosts = [x509.DNSName(host)]

        if wildcard:
            all_hosts += [x509.DNSName('*.'+host)]

        elif is_ip:
            all_hosts += [x509.IPAddress(ipaddress.ip_address(host))]

        all_hosts += [x509.IPAddress(ip) for ip in cert_ips]
        all_hosts += [x509.DNSName(fqdn) for fqdn in cert_fqdns]

        builder = builder.add_extension(x509.SubjectAlternativeName([san_host for san_host in all_hosts]),critical=False)
        cert = builder.sign(private_key=root_key, algorithm=hashes.SHA256())
        return cert, key

    def renew_host_certificate(self, cert, key):
        # Generate Cert
        print("I doth renew the cert")
        builder = x509.CertificateBuilder()
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.subject_name(cert.subject)
        builder = builder.not_valid_before(_HOST_CERT_NOT_BEFORE())
        builder = builder.not_valid_after(_HOST_CERT_NOT_AFTER())
        builder = builder.issuer_name(cert.issuer)
        builder = builder.public_key(key.public_key())
        builder._extensions = cert.extensions
        cert = builder.sign(private_key=self.ca_key, algorithm=hashes.SHA256())
        return cert, key

    def write_pem(self, buff, cert, key):
        keys = key.private_bytes(Encoding.PEM,PrivateFormat.TraditionalOpenSSL,NoEncryption()).decode()
        certs = cert.public_bytes(Encoding.PEM).decode()
        buff.write((keys+certs).encode())

    def read_pem(self, buff):
        buff = buff.read().decode().split("-----\n-----")
        keys,certs = buff[0]+"-----\n","-----"+buff[1]
        cert = x509.load_pem_x509_certificate(certs.encode(), default_backend())
        key = load_pem_private_key(keys.encode(), password=None)
        return cert, key

    

# =================================================================
class FileCache(object):
    def __init__(self, certs_dir):
        self._lock = threading.Lock()
        self.certs_dir = certs_dir
        self.modified = False

        if self.certs_dir and not os.path.exists(self.certs_dir):
            os.makedirs(self.certs_dir)

    def key_for_host(self, host):
        
        host = _normalized(host)
        host = host.replace(':', '-')
        return os.path.join(self.certs_dir, host) + '.pem'

    def __setitem__(self, host, cert_string):
        filename = _normalized(self.key_for_host(host))
        with self._lock:
            with open(filename, 'wb') as fh:
                fh.write(cert_string)
                self.modified = True

    def get(self, host):
        filename = self.key_for_host(host)
        try:
            with open(filename, 'rb') as fh:
                return fh.read()
        except:
            return b''


# =================================================================
class RootCACache(FileCache):
    def __init__(self, ca_file):
        self.ca_file = ca_file
        ca_dir = os.path.dirname(ca_file) or '.'
        super(RootCACache, self).__init__(ca_dir)

    def key_for_host(self, host=None):
        return self.ca_file


# =================================================================
class LRUCache(OrderedDict):
    def __init__(self, max_size):
        super(LRUCache, self).__init__()
        self.max_size = max_size

    def __setitem__(self, host, cert_string):
        super(LRUCache, self).__setitem__(host, cert_string)
        if len(self) > self.max_size:
            self.popitem(last=False)


# =================================================================
def main(args=None):
    parser = ArgumentParser(description='Certificate Authority Cert Maker Tools')

    parser.add_argument('root_ca_cert',
                        help='Path to existing or new root CA file')

    parser.add_argument('-c', '--certname', action='store', default=_CERT_NAME,
                        help='Name for root certificate')

    parser.add_argument('-n', '--hostname',
                        help='Hostname certificate to create')

    parser.add_argument('-d', '--certs-dir', default=_CERTS_DIR,
                        help='Directory for host certificates')

    parser.add_argument('-f', '--force', action='store_true',
                        help='Overwrite certificates if they already exist')

    parser.add_argument('-w', '--wildcard_cert', action='store_true',
                        help='add wildcard SAN to host: *.<host>, <host>')

    parser.add_argument('-I', '--cert_ips', action='store', default='',
                        help='add IPs to the cert\'s SAN')

    parser.add_argument('-D', '--cert_fqdns', action='store', default='',
                        help='add more domains to the cert\'s SAN')

    r = parser.parse_args(args=args)

    certs_dir = r.certs_dir
    wildcard = r.wildcard_cert

    root_cert = r.root_ca_cert
    hostname = r.hostname

    if r.cert_ips != '':
        cert_ips = r.cert_ips.split(',')
    else:
        cert_ips = []
    if r.cert_fqdns != '':
        cert_fqdns = r.cert_fqdns.split(',')
    else:
        cert_fqdns = []

    if not hostname:
        overwrite = r.force
    else:
        overwrite = False

    cert_cache = FileCache(certs_dir)
    ca_file_cache = RootCACache(root_cert)

    ca = CertificateAuthority(ca_name=r.certname,
                              ca_file_cache=ca_file_cache,
                              cert_cache=cert_cache,
                              overwrite=overwrite)

    # Just creating the root cert
    if not hostname:
        if ca_file_cache.modified:
            print('Created new root cert: "' + root_cert + '"')
            return 0
        else:
            print('Root cert "' + root_cert +
                  '" already exists,' + ' use -f to overwrite')
            return 1

    # Sign a certificate for a given host
    overwrite = r.force
    ca.load_cert(hostname, overwrite=overwrite,
                           wildcard=wildcard,
                           wildcard_use_parent=False,
                           cert_ips=cert_ips,
                           cert_fqdns=cert_fqdns)

    if cert_cache.modified:
        print('Created new cert "' + hostname +
              '" signed by root cert ' +
              root_cert)
        return 0

    else:
        print('Cert for "' + hostname + '" already exists,' +
              ' use -f to overwrite')
        return 1


if __name__ == "__main__":  #pragma: no cover
    main()
