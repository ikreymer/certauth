import os
import shutil

from certauth.certauth import main, CertificateAuthority, FileCache, LRUCache, _ROOT_CA, _ED_CURVES, _EC_CURVES

import tempfile
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key, pkcs12
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
import ipaddress

import datetime
import time

import pytest


CA_ROOT_FILENAME = 'certauth_test_ca.pem'

#NEED TESTS FOR:
#   CA EXTENSIONS, incl appropriate CONSTRAINTS, and USAGE
#   HOST EXTENSIONS, incl appropriate CONSTRAINTS, USAGE
#   FACTORY, GOOD AND BAD INPUTS

@pytest.fixture(params=[key for key in _ED_CURVES]+[key for key in _EC_CURVES])
def Curve(request):
    return request.param

@pytest.fixture
def ca(Curve):
    return CertificateAuthority('Test CA', TEST_CA_ROOT, TEST_CA_DIR, curve=Curve)



def normalized(s): #we  must comply with str(ip_address()) to pass tests
        try:
            return str(ipaddress.ip_address(s))
        except (ValueError, UnicodeDecodeError):
            return s

def setup_module():
    global TEST_CA_DIR
    TEST_CA_DIR = tempfile.mkdtemp()

    global orig_cwd
    orig_cwd = os.getcwd()
    os.chdir(TEST_CA_DIR)

    global TEST_CA_ROOT
    TEST_CA_ROOT = os.path.join(TEST_CA_DIR, CA_ROOT_FILENAME)

    global TEST_HOST_NAME
    TEST_HOST_NAME = "pytest_safetodelete"
    global ED_CURVES, EC_CURVES, CURVES
    ED_CURVES=[key for key in _ED_CURVES]
    EC_CURVES=[key for key in _EC_CURVES]
    CURVES = ED_CURVES+EC_CURVES

def teardown_module():
    os.chdir(orig_cwd)
    shutil.rmtree(TEST_CA_DIR)
    assert not os.path.isdir(TEST_CA_DIR)
    assert not os.path.isfile(TEST_CA_ROOT)


def verify_cert_san(cert, san_list):
    #We Always have 1.CONSTRAINTS, 2.USAGE, 3.EXT_USAGE, 4.SUBJ_KID, 5.AUTH_KID
    #Test if we added 6.SAN
    assert len(cert.extensions) == 6
    print("TEST: ")
    print(cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME))
    sans = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    print(sans)
    sans += [str(ipaddr) for ipaddr in cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.IPAddress)]
    print(sans)

    print('{} vs {}'.format(set(sans), set(san_list)))

    assert set(sans) == set(san_list)

def verify_san(ca, filename, san_list):
    assert os.path.isfile(filename)
    with open(filename, 'rb') as fh:
        cert, key = ca.read_pem(fh)
    verify_cert_san(cert, san_list)


def test_create_root():
    ret = main([TEST_CA_ROOT, '-c', 'Test Root Cert'])
    assert ret == 0

def test_file_create_host_cert(ca):
    ret = main([TEST_CA_ROOT, '-d', TEST_CA_DIR, '-n', ca.curve+'.example.com'])
    assert ret == 0
    certfile = os.path.join(TEST_CA_DIR, ca.curve+'.example.com.pem')

    verify_san(ca, certfile, [ca.curve+'.example.com'])

def test_file_create_wildcard_host_cert_force_overwrite(ca):
    ret = main([TEST_CA_ROOT, '-d', TEST_CA_DIR, '--hostname', ca.curve+'.com', '-w', '-f'])
    assert ret == 0
    certfile = os.path.join(TEST_CA_DIR, ca.curve+'.com.pem')

    verify_san(ca, certfile, [ca.curve+'.com', '*.'+ca.curve+'.com'])

def test_file_wildcard(ca):
    cert_filename = ca.get_wildcard_cert('test.example.proxy')
    filename = os.path.join(TEST_CA_DIR, 'example.proxy.pem')
    assert cert_filename == filename

    verify_san(ca, filename, ['example.proxy', '*.example.proxy'])

    os.remove(filename)

def test_file_wildcard_no_subdomain(ca):
    cert_filename = ca.get_wildcard_cert('example.proxy')
    filename = os.path.join(TEST_CA_DIR, 'example.proxy.pem')
    assert cert_filename == filename

    verify_san(ca, filename, ['example.proxy', '*.example.proxy'])

    os.remove(filename)

def test_file_wildcard_subdomains(ca):
    cert_filename = ca.get_wildcard_cert('a.b.c.test.example.com')
    filename = os.path.join(TEST_CA_DIR, 'b.c.test.example.com.pem')
    assert cert_filename == filename

    verify_san(ca, filename, ['b.c.test.example.com', '*.b.c.test.example.com'])

    os.remove(filename)

def test_file_non_wildcard(ca):
    cert_filename = ca.cert_for_host('test2.example.proxy')
    filename = os.path.join(TEST_CA_DIR, 'test2.example.proxy.pem')
    assert cert_filename == filename

    verify_san(ca, filename, ['test2.example.proxy'])

    os.remove(filename)

def test_file_ip_non_wildcard(ca):
    cert_filename = ca.cert_for_host('192.168.0.2')
    filename = os.path.join(TEST_CA_DIR, '192.168.0.2.pem')
    assert cert_filename == filename

    verify_san(ca, filename, ['192.168.0.2', '192.168.0.2'])

    os.remove(filename)

def test_file_ips(ca):
    wanted_ips = [ipaddress.ip_address(ipaddr) for ipaddr in ['192.168.1.1', '10.1.1.1', '2001:0:0:0:0:0:0:1002']]
    cert_filename = ca.cert_for_host('myhost', cert_ips=wanted_ips)
    vsan = [normalized(ipaddr) for ipaddr in ['192.168.1.1', '10.1.1.1', '2001:0:0:0:0:0:0:1002', 'myhost']]
    verify_san(ca, cert_filename, vsan) # must comply with ipaddress library

    os.remove(cert_filename)

def test_file_fqdns(ca):
    wanted_fqdns = ['example.com', 'example.net', 'example.org']
    cert_filename = ca.cert_for_host('myhost', cert_fqdns=wanted_fqdns)

    verify_san(ca, cert_filename, ['example.com', 'example.net', 'example.org', 'myhost'])

    os.remove(cert_filename)

def test_file_ips_and_fqdns(ca):
    wanted_fqdns = ['example.com', 'example.net', 'example.org']
    wanted_ips = [ipaddress.ip_address(ipaddr) for ipaddr in ['10.1.1.1', '2001:0:0:0:0:0:0:1002']]
    cert_filename = ca.cert_for_host('myhost', cert_fqdns=wanted_fqdns, cert_ips=wanted_ips)
    vsan = [normalized(ipaddr) for ipaddr in ['example.com', 'example.net', 'example.org', '10.1.1.1', '2001:0:0:0:0:0:0:1002', 'myhost']]
    verify_san(ca, cert_filename, vsan)

    os.remove(cert_filename)

def test_file_ipv6_wildcard_ignore(ca):
    cert_filename = ca.get_wildcard_cert('2001:0db8:85a3:0000:0000:8a2e:0370:7334')
    filename = os.path.join(TEST_CA_DIR, '2001-db8-85a3--8a2e-370-7334.pem')
    assert cert_filename == filename #
    vsan = [normalized(ipaddr) for ipaddr in ['2001:DB8:85A3:0:0:8A2E:370:7334', '2001:0db8:85a3:0000:0000:8a2e:0370:7334']]
    verify_san(ca, filename, vsan)

    os.remove(filename)

def test_file_create_already_exists(ca):
    ret = main([TEST_CA_ROOT, '-d', TEST_CA_DIR, '-n', ca.curve+'.com', '-w'])
    assert ret == 1
    certfile = os.path.join(TEST_CA_DIR, ca.curve+'.com.pem')

    # from previous run
    verify_san(ca, certfile, [ca.curve+'.com', '*.'+ca.curve+'.com'])

    # remove now
    os.remove(certfile)

def test_in_mem_cert():
    cert_cache = {}
    ca = CertificateAuthority('Test CA', TEST_CA_ROOT, cert_cache, overwrite=True)
    res = ca.load_cert('test.example.proxy')
    assert 'test.example.proxy' in cert_cache, cert_cache.keys()

    cached_value = cert_cache['test.example.proxy']
    cert, key = ca.load_cert('test.example.proxy')

    verify_cert_san(cert, ['test.example.proxy'])

    # assert underlying cache unchanged
    assert cached_value == cert_cache['test.example.proxy']

def test_in_mem_parent_wildcard_cert():
    cert_cache = {}
    ca = CertificateAuthority('Test CA', TEST_CA_ROOT, cert_cache)
    cert, key = ca.load_cert('test.example.proxy', wildcard=True, wildcard_use_parent=True)
    assert 'example.proxy' in cert_cache, cert_cache.keys()

    cached_value = cert_cache['example.proxy']
    cert2, key2 = ca.load_cert('example.proxy')
    # assert underlying cache unchanged
    assert cached_value == cert_cache['example.proxy']

    verify_cert_san(cert2, ['example.proxy', '*.example.proxy'])

def test_in_mem_parent_wildcard_cert_at_tld():
    cert_cache = {}
    ca = CertificateAuthority('Test CA', TEST_CA_ROOT, cert_cache)
    cert, key = ca.load_cert('example.org.uk', wildcard=True, wildcard_use_parent=True)
    assert 'example.org.uk' in cert_cache, cert_cache.keys()

    cached_value = cert_cache['example.org.uk']
    cert2, key2 = ca.load_cert('example.org.uk')
    # assert underlying cache unchanged
    assert cached_value == cert_cache['example.org.uk']

    verify_cert_san(cert2, ['example.org.uk', '*.example.org.uk'])

def test_in_mem_parent_wildcard_cert_2():
    cert_cache = {}
    ca = CertificateAuthority('Test CA', TEST_CA_ROOT, cert_cache)
    cert, key = ca.load_cert('test.example.org.uk', wildcard=True, wildcard_use_parent=True)
    assert 'example.org.uk' in cert_cache, cert_cache.keys()

    cached_value = cert_cache['example.org.uk']
    cert2, key2 = ca.load_cert('example.org.uk')
    # assert underlying cache unchanged
    assert cached_value == cert_cache['example.org.uk']

    verify_cert_san(cert2, ['example.org.uk', '*.example.org.uk'])

def test_create_root_already_exists():
    ret = main([TEST_CA_ROOT])
    # not created, already exists
    assert ret == 1
    # remove now
    os.remove(TEST_CA_ROOT)

def test_create_root_subdir():
    # create a new cert in a subdirectory
    subdir = os.path.join(TEST_CA_DIR, 'subdir')

    ca_file = os.path.join(subdir, 'certauth_test_ca.pem')

    certs_dir = os.path.join(subdir, 'certs')

    ca = CertificateAuthority('Test CA', ca_file, certs_dir)

    assert os.path.isdir(subdir)
    assert os.path.isfile(ca_file)
    assert os.path.isdir(certs_dir)

    assert ca.get_root_pem_filename() == ca_file

def test_ca_custom_not_before_not_after():
    ca = CertificateAuthority('Test Custom CA', TEST_CA_ROOT,
            ca_not_before=datetime.datetime.today() - datetime.timedelta(days=4),
            ca_not_after=datetime.datetime.utcnow() + datetime.timedelta(days=10))

    # check PKCS12 if supported
    if not ca.curve in ED_CURVES:
        buff_pk12 = ca.get_root_PKCS12()
        assert len(buff_pk12) > 0
        #cert_pk12 = crypto.load_pkcs12(buff_pk12).get_certificate()
        cert_pk12 = pkcs12.load_pkcs12(buff_pk12, password=None).cert.certificate
    else:
        cert, _ = ca.load_root_ca_cert("hosts_not_before_after.pytest.local")
        print("pk12 is not supported for curve "+ca.curve+" so the ca_not_before_after pk12 test was circumvented. This is ok.")
    expected_not_before = datetime.datetime.today() - datetime.timedelta(days=4)
    expected_not_after = datetime.datetime.utcnow() + datetime.timedelta(days=10)

    assert abs((cert.not_valid_before - expected_not_before).total_seconds()) < 10
    assert abs((cert.not_valid_after - expected_not_after).total_seconds()) < 10

def test_hosts_custom_not_before_not_after():
    ca = CertificateAuthority('Test Custom CA', TEST_CA_ROOT,
            hosts_not_before=datetime.datetime.today() - datetime.timedelta(days=4),
            hosts_not_after=datetime.datetime.utcnow() + datetime.timedelta(days=10))

    # check PKCS12 if supported
    if not ca.curve in ED_CURVES:
        buff_pk12 = ca.get_root_PKCS12()
        assert len(buff_pk12) > 0
        #cert_pk12 = crypto.load_pkcs12(buff_pk12).get_certificate()
        cert_pk12 = pkcs12.load_pkcs12(buff_pk12, password=None).cert.certificate
    else:
        cert, _ = ca.load_cert("hosts_not_before_after.pytest.local")
        print("pk12 is not supported for curve "+ca.curve+" so the ca_cert_in_mem pk12 test was circumvented. This is ok.")
    expected_not_before = datetime.datetime.today() - datetime.timedelta(days=4)
    expected_not_after = datetime.datetime.utcnow() + datetime.timedelta(days=10)

    assert abs((cert.not_valid_before - expected_not_before).total_seconds()) < 10
    assert abs((cert.not_valid_after - expected_not_after).total_seconds()) < 10

def test_ca_cert_in_mem():
    root_cert_dict = {}
    
    ca = CertificateAuthority('Test CA', root_cert_dict, 10)

    # check PEM
    buff_pem = ca.get_root_pem()
    assert len(buff_pem) > 0

    # PEM stored in root_cert_dict
    assert root_cert_dict[_ROOT_CA] == buff_pem

    #cert_pem = crypto.load_certificate(FILETYPE_PEM, buff_pem)
    cert_pem = x509.load_pem_x509_certificate(buff_pem, default_backend())
    
    # check PKCS12 if supported
    if not ca.curve in ED_CURVES:
        buff_pk12 = ca.get_root_PKCS12()
        assert len(buff_pk12) > 0
        #cert_pk12 = crypto.load_pkcs12(buff_pk12).get_certificate()
        cert_pk12 = pkcs12.load_pkcs12(buff_pk12, password=None).cert.certificate
    else:
        cert, _ = ca.load_cert("hosts_not_before_after.pytest.local")
        print("pk12 is not supported for curve "+ca.curve+" so the ca_cert_in_mem pk12 test was circumvented. This is ok.")

def test_ca_lru_cache():
    lru = LRUCache(max_size=2)
    ca = CertificateAuthority('Test CA LRU Cache', TEST_CA_ROOT, lru)

    res = ca.load_cert('example.com')
    assert 'example.com' in lru
    assert len(lru) == 1

    res = ca.load_cert('ABC.example.com')
    assert 'ABC.example.com' in lru
    assert 'example.com' in lru
    assert len(lru) == 2

    res = ca.load_cert('XYZ.example.com', include_cache_key=True)
    assert res[2] == 'XYZ.example.com'

    assert 'XYZ.example.com' in lru
    assert 'ABC.example.com' in lru
    assert len(lru) == 2

    assert 'example.com' not in lru


def test_create_root_no_dir_already_exists():
    ret = main([CA_ROOT_FILENAME, '-c', 'Test Root Cert'])
    assert ret == 1

def test_renew_expired_certificate(ca):

    ca.hosts_not_before = datetime.datetime.today() - datetime.timedelta(days=4)
    ca.hosts_not_after = datetime.datetime.utcnow() - datetime.timedelta(days=2)
    print("Not Before")
    print(ca.hosts_not_before)
    print(ca.hosts_not_after)

    cert1, key1 = ca.load_cert(ca.curve+'.test.example.proxy')

    #We have made an expired certificate
    assert (datetime.datetime.utcnow()-cert1.not_valid_after).total_seconds() > 0
    
    #It should renew
    cert2, key2 = ca.load_cert(ca.curve+'.test.example.proxy')
    assert cert1.fingerprint(hashes.SHA256()) != cert2.fingerprint(hashes.SHA256())

    #Key is unchanged
    key1pb = key1.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption())
    key2pb = key2.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption())
    assert key1pb == key2pb

    #certificate's public key is unchanged
    cert1pb = cert1.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
    cert2pb = cert2.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
    assert cert1pb == cert2pb

    #extensions match
    assert str(cert1.extensions) == str(cert2.extensions)
