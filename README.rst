Certificate Authority Tools
===========================

.. image:: https://travis-ci.org/ikreymer/certauth.svg?branch=master
    :target: https://travis-ci.org/ikreymer/certauth

This package provides a small library, built on top of ``pyOpenSSL``, which allows for creating a custom certificate authority certificate,
and genereating on-demand dynamic host certs using that CA certificate.

It is most useful for use with a man-in-the-middle HTTPS proxy, for example, for archiving or playing back web content.

Certificates created by using this module should be used with caution.

(This module was originally part of the `pywb <https://github.com/ikreymer/pywb>`_ and `warcprox <https://github.com/internetarchive/warcprox>`_ projects and has been split off for modularity)
