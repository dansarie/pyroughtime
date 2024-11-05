# pyroughtime

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

An experimental Roughtime client and server implementation in Python 3 using the IETF draft at
<https://datatracker.ietf.org/doc/html/draft-ietf-ntp-roughtime-11>.

## Dependencies

* [PyCryptodome](https://github.com/Legrandin/pycryptodome)

## Example

### From Python

```python
from pyroughtime import RoughtimeClient, RoughtimeServer
serv, publ = RoughtimeServer.test_server()
cl = RoughtimeClient()
reply = cl.query('127.0.0.1', 2002, publ)
serv.stop()
print(reply['prettytime'])
```

### From console
```console
$ ./pyroughtime.py -l ecosystem.json
Caesium:                  2020-12-23 16:26:16.765275 UTC (+/- 1.000  s) (RTT:  100.5 ms)
Chainpoint-Roughtime:     2020-12-23 16:26:16.973777 UTC (+/- 1.000  s) (RTT:  288.9 ms)
Cloudflare-Roughtime:     2020-12-23 16:26:17.267000 UTC (+/- 1.000  s) (RTT:    3.7 ms)
Google-Sandbox-Roughtime: 2020-12-23 16:26:17.307968 UTC (+/- 1.000  s) (RTT:   16.1 ms)
int08h-Roughtime:         2020-12-23 16:26:17.401888 UTC (+/- 1.000  s) (RTT:  177.0 ms)
roughtime.se:             2020-12-23 16:26:17.574568 UTC (+/- 0.000 ms) (RTT:   26.1 ms)
sjwheel:                  2020-12-23 16:26:17.747868 UTC (+/- 1.000  s) (RTT:  485.6 ms)
No inconsistent replies detected.
$ ./pyroughtime.py -s roughtime.se 2002 S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI=
2020-12-23 16:26:44.499730 UTC (+/- 0.000 ms) (RTT: 25.7 ms)
TAI - UTC = 37s
Leap events:
  2017-01-01
  2015-07-01
  2012-07-01
Delegate key validity start: 2020-12-22 00:00:00.000000
Delegate key validity end:   2022-01-01 00:00:00.000000
Merkle tree path length: 0
```

A testing server can also be started from the command line.
```console
$ ./pyroughtime.py -t AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Roughtime server started on port 2002
Public key: O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=
Press enter to stop...
```

## License

This project is licensed under the GNU General Public License - see the [LICENSE](LICENSE)
file for details.
