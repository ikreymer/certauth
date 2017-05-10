import logging
import os

from io import BytesIO

from OpenSSL import crypto
from OpenSSL.SSL import FILETYPE_PEM

import random
from argparse import ArgumentParser

import threading

# =================================================================
# Valid for 3 years from now
# Max validity is 39 months:
# https://casecurity.org/2015/02/19/ssl-certificate-validity-periods-limited-to-39-months-starting-in-april/
CERT_NOT_AFTER = 3 * 365 * 24 * 60 * 60

CERTS_DIR = './ca/certs/'

CERT_NAME = 'certauth sample CA'

DEF_HASH_FUNC = 'sha256'


# =================================================================
class CertificateAuthority(object):
    """
    Utility class for signing individual certificate
    with a root cert.

    Static generate_ca_root() method for creating the root cert

    All certs saved on filesystem. Individual certs are stored
    in specified certs_dir and reused if previously created.
    """

    def __init__(self, ca_file, ca_name,
                 cert_cache=None,
                 overwrite=False,
                 cert_not_before=0,
                 cert_not_after=CERT_NOT_AFTER):

        assert(ca_file)
        self.ca_file = ca_file

        self.cert_cache = cert_cache or dict()

        assert(ca_name)
        self.ca_name = ca_name

        self._file_created = False

        self.cert_not_before = cert_not_before
        self.cert_not_after = cert_not_after

        if not os.path.exists(os.path.dirname(ca_file)):
            os.makedirs(os.path.dirname(ca_file))

        # if file doesn't exist or overwrite is true
        # create new root cert
        if (overwrite or not os.path.isfile(ca_file)):
            self.cert, self.key = self.generate_ca_root(ca_file, ca_name)
            self._file_created = True
            return

        # read previously created root cert
        with open(ca_file, 'rb') as buff:
            self.cert, self.key = self.read_pem(buff)

    def cert_for_host(self, host, overwrite=False, wildcard=False):
       cert_str = None

        if not overwrite:
            cert_str = self.cert_cache.get(host)

        if cert_str:
            cert, key = self.read_pem(BytesIO(cert_str))
            return cert, key

        cert_str, cert, key = self.generate_host_cert(host, self.cert, self.key, wildcard)

        self.cert_cache[host] = cert_str
        self._file_created = True

        return cert, key

    def get_wildcard_cert(self, cert_host):
        host_parts = cert_host.split('.', 1)
        if len(host_parts) == 2 and '.' in host_parts[1]:
            cert_host = host_parts[1]

        cert_key = self.cert_for_host(cert_host,
                                      wildcard=True)

        return cert_key

    def get_root_PKCS12(self):
        p12 = crypto.PKCS12()
        p12.set_certificate(self.cert)
        p12.set_privatekey(self.key)
        return p12.export()

    def _make_cert(self, certname):
        cert = crypto.X509()
        cert.set_serial_number(random.randint(0, 2 ** 64 - 1))
        cert.get_subject().CN = certname

        cert.set_version(2)
        cert.gmtime_adj_notBefore(self.cert_not_before)
        cert.gmtime_adj_notAfter(self.cert_not_after)
        return cert

    def generate_ca_root(self, ca_file, ca_name, hash_func=DEF_HASH_FUNC):
        # Generate key
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # Generate cert
        cert = self._make_cert(ca_name)

        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.add_extensions([
            crypto.X509Extension(b"basicConstraints",
                                 True,
                                 b"CA:TRUE, pathlen:0"),

            crypto.X509Extension(b"keyUsage",
                                 True,
                                 b"keyCertSign, cRLSign"),

            crypto.X509Extension(b"subjectKeyIdentifier",
                                 False,
                                 b"hash",
                                 subject=cert),
            ])
        cert.sign(key, hash_func)

        # Write cert + key
        with open(ca_file, 'w+b') as buff:
            self.write_pem(buff, cert, key)

        return cert, key

    def generate_host_cert(self, host, root_cert, root_key,
                           wildcard=False, hash_func=DEF_HASH_FUNC):

        host = host.encode('utf-8')

        # Generate key
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # Generate CSR
        req = crypto.X509Req()
        req.get_subject().CN = host
        req.set_pubkey(key)
        req.sign(key, hash_func)

        # Generate Cert
        cert = self._make_cert(host)

        cert.set_issuer(root_cert.get_subject())
        cert.set_pubkey(req.get_pubkey())

        if wildcard:
            DNS = b'DNS:'
            alt_hosts = [DNS + host,
                         DNS + b'*.' + host]

            alt_hosts = b', '.join(alt_hosts)

            cert.add_extensions([
                crypto.X509Extension(b'subjectAltName',
                                     False,
                                     alt_hosts)])

        cert.sign(root_key, hash_func)

        # Write cert + key
        buff = BytesIO()
        self.write_pem(buff, cert, key)
        return buff.getvalue(), cert, key

    def write_pem(self, buff, cert, key):
        buff.write(crypto.dump_privatekey(FILETYPE_PEM, key))
        buff.write(crypto.dump_certificate(FILETYPE_PEM, cert))

    def read_pem(self, buff):
        cert = crypto.load_certificate(FILETYPE_PEM, buff.read())
        buff.seek(0)
        key = crypto.load_privatekey(FILETYPE_PEM, buff.read())
        return cert, key


# =================================================================
class FileCache(object):
    def __init__(self, certs_dir):
        self._lock = threading.Lock()
        self.certs_dir = certs_dir

    def file_for_host(self, host):
        return os.path.join(self.certs_dir, host) + '.pem'

    def __setitem__(self, host, cert_string):
        filename = self.file_for_host(host)
        with self._lock:
            with open(filename, 'wb') as fh:
                fh.write(cert_string)

    def get(self, host):
        filename = self.file_for_host(host)
        try:
            with open(filename, 'rb') as fh:
                return fh.read()
        except:
            return b''


# =================================================================
def main(args=None):
    parser = ArgumentParser(description='Certificate Authority Cert Maker Tools')

    parser.add_argument('root_ca_cert',
                        help='Path to existing or new root CA file')

    parser.add_argument('-c', '--certname', action='store', default=CERT_NAME,
                        help='Name for root certificate')

    parser.add_argument('-n', '--hostname',
                        help='Hostname certificate to create')

    parser.add_argument('-d', '--certs-dir', default=CERTS_DIR,
                        help='Directory for host certificates')

    parser.add_argument('-f', '--force', action='store_true',
                        help='Overwrite certificates if they already exist')

    parser.add_argument('-w', '--wildcard_cert', action='store_true',
                        help='add wildcard SAN to host: *.<host>, <host>')

    r = parser.parse_args(args=args)

    certs_dir = r.certs_dir
    wildcard = r.wildcard_cert

    root_cert = r.root_ca_cert
    hostname = r.hostname

    if not hostname:
        overwrite = r.force
    else:
        overwrite = False

    ca = CertificateAuthority(ca_file=root_cert,
                              cert_cache=FileCache(r.certs_dir),
                              ca_name=r.certname,
                              overwrite=overwrite)

    # Just creating the root cert
    if not hostname:
        if ca._file_created:
            print('Created new root cert: "' + root_cert + '"')
            return 0
        else:
            print('Root cert "' + root_cert +
                  '" already exists,' + ' use -f to overwrite')
            return 1

    # Sign a certificate for a given host
    overwrite = r.force
    host_cert_key = ca.cert_for_host(hostname,
                                     overwrite, wildcard)

    if ca._file_created:
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
