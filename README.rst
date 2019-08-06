Certificate Authority Certificate Maker Tools
=============================================

.. image:: https://travis-ci.org/ikreymer/certauth.svg?branch=master
    :target: https://travis-ci.org/ikreymer/certauth
.. image:: https://coveralls.io/repos/ikreymer/certauth/badge.svg?branch=master
    :target: https://coveralls.io/r/ikreymer/certauth?branch=master

This package provides a small library, built on top of ``pyOpenSSL``, which allows for creating a custom certificate authority certificate,
and genereating on-demand dynamic host certs using that CA certificate.

It is most useful for use with a man-in-the-middle HTTPS proxy, for example, for recording or replaying web content.

Trusting the CA created by this tool should be used with caution in a controlled setting to avoid security risks.


CertificateAuthority API
============================

The ``CertificateAuthority`` class provides an interface to manage a root CA and generate dynamic host certificates suitable
for use with the native Python ``ssl`` library as well as pyOpenSSL ``SSL`` module.

The class provides several options for storing the root CA and generated host CAs.


File-based Certificate Cache
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

   ca = CertificateAuthority('My Custom CA', 'my-ca.pem', cert_cache='/tmp/certs')
   filename = ca.cert_for_host('example.com')

In this configuration, the root CA is stored at ``my-ca.pem`` and dynamically generated certs
are placed in ``/tmp/certs``. The ``filename`` returned would be ``/tmp/certs/example.com.pem`` in this example.

This filename can then be used with the Python `ssl.load_cert_chain(certfile) <https://docs.python.org/3/library/ssl.html#ssl.SSLContext.load_cert_chain>`_ command.

Note that the dynamically created certs are never deleted by ``certauth``, it remains up to the user to handle cleanup occasionally if desired.


In-memory Certificate Cache
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

   ca = CertificateAuthority('My Custom CA', 'my-ca.pem', cert_cache=50)
   cert, key = ca.load_cert('example.com')
   
This configuration stores the root CA at ``my-ca.pem`` but uses an in-memory certificate cache for dynamically created certs. 
These certs are stored in an LRU cache, configured to keep at most 50 certs.

The ``cert`` and ``key`` can then be used with `OpenSSL.SSL.Context.use_certificate <http://www.pyopenssl.org/en/stable/api/ssl.html#OpenSSL.SSL.Context.use_certificate>`_

.. code:: python

        context = SSl.Context(...)
        context.use_privatekey(key)
        context.use_certificate(cert)


Custom Cache
~~~~~~~~~~~~

A custom cache implementations which stores and retrieves per-host certificates can also be provided:

.. code:: python

   ca = CertificateAuthority('My Custom CA', 'my-ca.pem', cert_cache=CustomCache())
   cert, key = ca.load_cert('example.com')
   
   class CustomCache:
       def __setitem__(self, host, cert_string):
          # store cert_string for host
          
       def get(self, host):
          # return cached cert_string, if available
          cert_string = ...
          return cert_string


Wildcard Certs
~~~~~~~~~~~~~~

To reduce the number of certs generated, it is convenient to generate wildcard certs.

.. code:: python

   cert, key = ca.load_cert('example.com', wildcard=True)

This will generate a cert for ``*.example.com``.

To automatically generate a wildcard cert for parent domain, use:

.. code:: python

   cert, key = ca.load_cert('test.example.com', wildcard=True, wildcard_for_parent=True)

This will also generate a cert for ``*.example.com``

Starting with 1.3.0, ``certauth`` uses ``tldextract`` to determine the tld for a given host,
and will not use a parent domain if it is itself a tld suffix.

For example, calling:

.. code:: python

   cert, key = ca.load_cert('example.co.uk', wildcard=True, wildcard_for_parent=True)
   
will now result in a cert for ``*.example.co.uk``, not ``*.co.uk``.


CLI Usage Examples
==================

``certauth`` also includes a simple command-line API for certificate creation and management.

::

  usage: certauth [-h] [-c CERTNAME] [-n HOSTNAME] [-d CERTS_DIR] [-f] [-w]
                root_ca_cert

  positional arguments:
    root_ca_cert          Path to existing or new root CA file

  optional arguments:
    -h, --help            show this help message and exit
    -c CERTNAME, --certname CERTNAME
                        Name for root certificate
    -n HOSTNAME, --hostname HOSTNAME
                        Hostname certificate to create
    -d CERTS_DIR, --certs-dir CERTS_DIR
                        Directory for host certificates
    -f, --force           Overwrite certificates if they already exist
    -w, --wildcard_cert   add wildcard SAN to host: *.<host>, <host>



To create a new root CA certificate:

``certauth myrootca.pem --certname "My Test CA"``

To create a host certificate signed with CA certificate in directory ``certs_dir``:

``certauth myrootca.pem --hostname "example.com" -d ./certs_dir``

If the root cert doesn't exist, it'll be created automatically.
If ``certs_dir``, doesn't exist, it'll be created automatically also.

The cert for ``example.com`` will be created as ``certs_dir/example.com.pem``.
If it already exists, it will not be overwritten (unless ``-f`` option is used).

The ``-w`` option can be used to create a wildcard cert which has subject alternate names (SAN) for ``example.com`` and ``*.example.com``


History
=======

The CertificateAuthority functionality has evolved from certificate management originally found in the man-in-the-middle proxy `pymiproxy <https://github.com/allfro/pymiproxy>`_ by Nadeem Douba.

It was also extended in `warcprox <https://github.com/internetarchive/warcprox>`_ by `Noah Levitt <https://github.com/nlevitt>`_ of Internet Archive.

The CA functionality was also reused in `pywb <https://github.com/ikreymer/pywb>`_ and finally factored out into this separate package for modularity.

It is now also used by `wsgiprox <https://github.com/webrecorder/wsgiprox>`_ to provide a generalized HTTPS proxy wrapper to any WSGI application.

