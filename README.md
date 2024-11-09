# Pyroughtime

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Pyroughtime is a Python library and command line utility for Roughtime, which is a protocol for
rough time synchronization and timestamping. Pyroughtime makes it possible to query Roughtime
servers for the current time. Response signatures are validated against servers' long-time keys,
ensuring that they are authentic. By querying multiple servers, Pyroughtime can detect incorrect
time responses sent by misbehaving or malfunctioning time servers.

In addition to a Roughtime client, Pyroughtime also contains a simple server implementation that can
be used for testing and validation.

Currently, Pyroughtime implements the version of the Roughtime protocol described by
[draft-ietf-ntp-roughtime-11](https://datatracker.ietf.org/doc/html/draft-ietf-ntp-roughtime-11).

## Dependencies

* [PyCryptodome](https://github.com/Legrandin/pycryptodome)

## Usage

### Querying a single server

The `-s` flag is used to query a single server. It takes three arguments: a server address, a server
port, and the server's long-term public key in base64 format.

```console
$ ./pyroughtime.py -s roughtime.se 2002 S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI=
2024-11-07 20:23:52 UTC (+/-  3 s) (RTT: 36.9 ms)
Server version: draft-11
Delegate key validity start: 2024-11-05 00:00:00
Delegate key validity end:   2025-12-31 00:00:00
Merkle tree path length: 0
```

### Querying multiple servers

The `-l` flag is used to query multiple servers. It takes a single argument: the name of an
ecosystem file in JSON format.

```console
$ ./pyroughtime.py -l ecosystem.json
time.txryan.com:          2024-11-07 20:37:53 UTC (+/-  1 s) RTT:  212.5 ms Version: draft-11
roughtime.se:             2024-11-07 20:37:53 UTC (+/-  3 s) RTT:   12.7 ms Version: draft-11
No inconsistent replies detected.
```

### From Python

The RoughtimeClient class can be used to query servers. The client automatically chains all replies,
making it possible to generate verifiable malfeasance reports. Replies to queries are returned
as RoughtimeResult objects which can be queried for information about the time response.

```python
from pyroughtime import RoughtimeClient, RoughtimeServer
serv, publ = RoughtimeServer.test_server()
cl = RoughtimeClient()
reply1 = cl.query('127.0.0.1', 2002, publ)
reply2 = cl.query('roughtime.se', 2002, 'S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI=')
serv.stop()
print(reply1) # Print a string representation of the received time.
time = reply1.datetime() # Get the received midpoint as a datetime instance.
report = cl.get_malfeasance_report() # Get a malfeasance report in JSON format.
```

### Running a server

The `-t` flag is used to start a server. It takes a single argument: the server's long-term private
key in base64 format. A delegate key is automatically generated.

```console
$ ./pyroughtime.py -t AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Roughtime server started on port 2002
Public key: O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=
Press enter to stop...
```

## License and Copyright

Copyright (C) 2019-2024 Marcus Dansarie

This program is free software: you can redistribute it and/or modify it under the terms of the GNU
General Public License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
[the GNU General Public License](LICENSE) for more details.
