API Documentation
=================

.. module:: pyroughtime
.. include:: versionnote.rst

API Examples
------------

The RoughtimeClient class is used to query servers. The client automatically chains all replies,
making it possible to generate verifiable malfeasance reports. Replies to queries are returned as
RoughtimeResult objects which can be queried for information about the time response.

.. code-block:: python

   from pyroughtime import RoughtimeClient, RoughtimeServer
   serv, publ = RoughtimeServer.test_server()
   cl = RoughtimeClient()
   reply1 = cl.query('127.0.0.1', 2002, publ)
   reply2 = cl.query('roughtime.se', 2002, 'S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI=')
   serv.stop()
   # Print a string representation of the received time.
   print(reply1)
   # Get the received midpoint as a datetime instance.
   time = reply1.datetime()
   # Get a malfeasance report in JSON format.
   report = cl.get_malfeasance_report()

RoughtimeClient
---------------

.. autoclass:: RoughtimeClient
   :members:
   :undoc-members:
   :show-inheritance:

RoughtimeServer
---------------

.. autoclass:: RoughtimeServer
   :members:
   :undoc-members:
   :show-inheritance:

RoughtimeResult
---------------

.. autoclass:: RoughtimeResult
   :members:
   :undoc-members:
   :show-inheritance:

RoughtimeTag
------------

.. autoclass:: RoughtimeTag
   :members:
   :undoc-members:
   :show-inheritance:

RoughtimePacket
---------------

.. autoclass:: RoughtimePacket
   :members:
   :undoc-members:
   :show-inheritance:

RoughtimeError
---------------

.. autoclass:: RoughtimeError
   :members:
   :undoc-members:
   :show-inheritance:
