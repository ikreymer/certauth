Certificate Authority Cert Maker Tools v1.1.4
=============================================

.. image:: https://travis-ci.org/ikreymer/certauth.svg?branch=master
    :target: https://travis-ci.org/ikreymer/certauth
.. image:: https://coveralls.io/repos/ikreymer/certauth/badge.svg?branch=master
    :target: https://coveralls.io/r/ikreymer/certauth?branch=master

This package provides a small library, built on top of ``pyOpenSSL``, which allows for creating a custom certificate authority certificate,
and genereating on-demand dynamic host certs using that CA certificate.

It is most useful for use with a man-in-the-middle HTTPS proxy, for example, for archiving or playing back web content.

Certificates created by using this module should be used with caution.

History
-------

The CertificateAuthority functionality was originally found in the man-in-the-middle proxy `pymiproxy <https://github.com/allfro/pymiproxy>`_ by Nadeem Douba.

It was also extended in `warcprox <https://github.com/internetarchive/warcprox>`_ by `Noah Levitt <https://github.com/nlevitt>`_ of Internet Archive.

The CA functionality was also reused in `pywb <https://github.com/ikreymer/pywb>`_ and finally factored out into this separate package for modularity.


Usage Examples
--------------

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
