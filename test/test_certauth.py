import os
import shutil

from certauth.certauth import main, CertificateAuthority, FileCache, LRUCache, ROOT_CA

import tempfile
from OpenSSL import crypto
from OpenSSL.SSL import FILETYPE_PEM
import datetime
import time

def setup_module():
    global TEST_CA_DIR
    TEST_CA_DIR = tempfile.mkdtemp()

    global TEST_CA_ROOT
    TEST_CA_ROOT = os.path.join(TEST_CA_DIR, 'certauth_test_ca.pem')

def teardown_module():
    shutil.rmtree(TEST_CA_DIR)
    assert not os.path.isdir(TEST_CA_DIR)
    assert not os.path.isfile(TEST_CA_ROOT)

def test_create_root():
    ret = main([TEST_CA_ROOT, '-c', 'Test Root Cert'])
    assert ret == 0

def test_file_create_host_cert():
    ret = main([TEST_CA_ROOT, '-d', TEST_CA_DIR, '-n', 'example.com'])
    assert ret == 0
    certfile = os.path.join(TEST_CA_DIR, 'example.com.pem')
    assert os.path.isfile(certfile)

def test_file_create_wildcard_host_cert_force_overwrite():
    ret = main([TEST_CA_ROOT, '-d', TEST_CA_DIR, '--hostname', 'example.com', '-w', '-f'])
    assert ret == 0
    certfile = os.path.join(TEST_CA_DIR, 'example.com.pem')
    assert os.path.isfile(certfile)

def test_file_wildcard():
    ca = CertificateAuthority('Test CA', TEST_CA_ROOT, TEST_CA_DIR)
    cert_filename = ca.get_wildcard_cert('test.example.proxy')
    filename = os.path.join(TEST_CA_DIR, 'example.proxy.pem')
    assert cert_filename == filename
    assert os.path.isfile(filename)
    os.remove(filename)

def test_file_non_wildcard():
    ca = CertificateAuthority('Test CA', TEST_CA_ROOT, TEST_CA_DIR)
    cert_filename = ca.cert_for_host('test2.example.proxy')
    filename = os.path.join(TEST_CA_DIR, 'test2.example.proxy.pem')
    assert cert_filename == filename
    assert os.path.isfile(filename)
    os.remove(filename)

def test_file_create_already_exists():
    ret = main([TEST_CA_ROOT, '-d', TEST_CA_DIR, '-n', 'example.com', '-w'])
    assert ret == 1
    certfile = os.path.join(TEST_CA_DIR, 'example.com.pem')
    assert os.path.isfile(certfile)
    # remove now
    os.remove(certfile)

def test_in_mem_cert():
    cert_cache = {}
    ca = CertificateAuthority('Test CA', TEST_CA_ROOT, cert_cache)
    res = ca.load_cert('test.example.proxy')
    assert 'test.example.proxy' in cert_cache, cert_cache.keys()

    cached_value = cert_cache['test.example.proxy']
    res = ca.load_cert('test.example.proxy')
    # assert underlying cache unchanged
    assert cached_value == cert_cache['test.example.proxy']

def test_in_mem_wildcard_cert():
    cert_cache = {}
    ca = CertificateAuthority('Test CA', TEST_CA_ROOT, cert_cache)
    cert, key = ca.load_cert('test.example.proxy', wildcard=True, wildcard_use_parent=True)
    assert 'example.proxy' in cert_cache, cert_cache.keys()

    cached_value = cert_cache['example.proxy']
    cert2, key2 = ca.load_cert('example.proxy')
    # assert underlying cache unchanged
    assert cached_value == cert_cache['example.proxy']

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

def test_custom_not_before_not_after():
    ca = CertificateAuthority('Test Custom CA', TEST_CA_ROOT,
                              cert_not_before=-60 * 60,
                              cert_not_after=60 * 60 * 24 * 3)

    # check PKCS12
    buff_pk12 = ca.get_root_PKCS12()
    assert len(buff_pk12) > 0

    cert = crypto.load_pkcs12(buff_pk12).get_certificate()

    expected_not_before = datetime.datetime.utcnow() - datetime.timedelta(seconds=60 * 60)
    expected_not_after = datetime.datetime.utcnow() + datetime.timedelta(seconds=60 * 60 * 24 * 3)


    actual_not_before = datetime.datetime.strptime(
            cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
    actual_not_after = datetime.datetime.strptime(
            cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')

    time.mktime(expected_not_before.utctimetuple())
    assert abs((time.mktime(actual_not_before.utctimetuple()) - time.mktime(expected_not_before.utctimetuple()))) < 10
    assert abs((time.mktime(actual_not_after.utctimetuple()) - time.mktime(expected_not_after.utctimetuple()))) < 10


def test_ca_cert_in_mem():
    root_cert_dict = {}

    ca = CertificateAuthority('Test CA', root_cert_dict, 10)

    # check PEM
    buff_pem = ca.get_root_pem()
    assert len(buff_pem) > 0

    # PEM stored in root_cert_dict
    assert root_cert_dict[ROOT_CA] == buff_pem

    cert_pem = crypto.load_certificate(FILETYPE_PEM, buff_pem)

    # check PKCS12
    buff_pk12 = ca.get_root_PKCS12()
    assert len(buff_pk12) > 0

    cert_pk12 = crypto.load_pkcs12(buff_pk12).get_certificate()


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

    res = ca.load_cert('XYZ.example.com')
    assert 'XYZ.example.com' in lru
    assert 'ABC.example.com' in lru
    assert len(lru) == 2

    assert 'example.com' not in lru


