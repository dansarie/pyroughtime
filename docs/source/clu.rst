Command line utility
====================

.. include:: versionnote.rst

Querying servers
----------------

The ``-s`` flag is used to query a single server. It takes three arguments: a server address, a
server port, and the server's long-term public key in base64 format.

.. code-block:: console

   $ ./pyroughtime.py -s roughtime.se 2002 S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI=
   2024-11-07 20:23:52 UTC (+/-  3 s) (RTT: 36.9 ms)
   Server version: draft-11
   Delegate key validity start: 2024-11-05 00:00:00
   Delegate key validity end:   2025-12-31 00:00:00
   Merkle tree path length: 0


The ``-l`` flag is used to query multiple servers. It takes a single argument: the name of an
ecosystem file in JSON format.

.. code-block:: console

  $ ./pyroughtime.py -l ecosystem.json
  time.txryan.com:          2024-11-07 20:37:53 UTC (+/-  1 s) RTT:  212.5 ms Version: draft-11
  roughtime.se:             2024-11-07 20:37:53 UTC (+/-  3 s) RTT:   12.7 ms Version: draft-11
  No inconsistent replies detected.

Running a test server
---------------------

The ``-t`` flag is used to start a server. It takes a single argument: the server's long-term
private key in base64 format. A delegate key is automatically generated.

.. code-block:: console

   $ ./pyroughtime.py -t AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
   Roughtime server started on port 2002
   Public key: O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=
   Press enter to stop...
