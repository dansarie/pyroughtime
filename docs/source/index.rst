Pyroughtime Documentation
*************************

Overview
========

.. include:: versionnote.rst

Pyroughtime is a Python library and command line utility for Roughtime, a protocol for rough time
synchronization and timestamping. Pyroughtime makes it easy to query Roughtime servers for the
current time. Response signatures are automatically validated against servers' long-time keys,
ensuring that they are authentic. By querying multiple servers, Pyroughtime can detect incorrect
time responses sent by misbehaving or malfunctioning time servers.

As indicated by its name, the Roughtime protocol only provides a rough idea of the current time,
suitable for many, but not all, applications. Normally, the returned time is accurate to within one
or a few seconds. For applications that require higher accuracy, use of the Network Time Protocol
(NTP) is recommended. The ability of Roughtime to provide hard bounds for the current time can be
used to sanity check time obtained from NTP or system calls.

For basic use, Pyroughtime provides a simple API, allowing programs to fetch the current time with a
single API call. For more advanced use, Pyroughtime provides functions for querying individual
servers, examining responses, generating cryptographic proofs of malfaesance, and parsing Roughtime
packets.

In addition to the Python API, Pyroughtime also provides a command line utility that can be used to
query Roughtime servers.

API documentation
=================

The API documentation describes how Pyroughtime can be used from Python.

.. toctree::
   :maxdepth: 2

   api

Command Line Utility
====================

.. toctree::
   :maxdepth: 2

   clu

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
