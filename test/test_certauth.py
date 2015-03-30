import os
import shutil

from certauth.certauth import main, CertificateAuthority
import tempfile

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

def test_create_host_cert():
    ret = main([TEST_CA_ROOT, '-d', TEST_CA_DIR, '-n', 'example.com'])
    assert ret == 0
    certfile = os.path.join(TEST_CA_DIR, 'example.com.pem')
    assert os.path.isfile(certfile)

def test_create_wildcard_host_cert_force_overwrite():
    ret = main([TEST_CA_ROOT, '-d', TEST_CA_DIR, '--hostname', 'example.com', '-w', '-f'])
    assert ret == 0
    certfile = os.path.join(TEST_CA_DIR, 'example.com.pem')
    assert os.path.isfile(certfile)

def test_explicit_wildcard():
    ca = CertificateAuthority(TEST_CA_ROOT, TEST_CA_DIR, 'Test CA')
    filename = ca.get_wildcard_cert('test.example.proxy')
    certfile = os.path.join(TEST_CA_DIR, 'example.proxy.pem')
    assert filename == certfile
    assert os.path.isfile(certfile)
    os.remove(certfile)

def test_create_already_exists():
    ret = main([TEST_CA_ROOT, '-d', TEST_CA_DIR, '-n', 'example.com', '-w'])
    assert ret == 1
    certfile = os.path.join(TEST_CA_DIR, 'example.com.pem')
    assert os.path.isfile(certfile)
    # remove now
    os.remove(certfile)

def test_create_root_already_exists():
    ret = main([TEST_CA_ROOT])
    # not created, already exists
    assert ret == 1
    # remove now
    os.remove(TEST_CA_ROOT)

def test_create_root_subdir():
    # create a new cert in a subdirectory
    subdir = os.path.join(TEST_CA_DIR, 'subdir')

    ca = CertificateAuthority(TEST_CA_ROOT, subdir, 'Test CA')

    assert os.path.isdir(subdir)

    buff = ca.get_root_PKCS12()
    assert len(buff) > 0
