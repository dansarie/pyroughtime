# pyroughtime

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

An experimental Roughtime client and server implementation in Python 3 using the IETF draft at
<https://tools.ietf.org/html/draft-ietf-ntp-roughtime-00>.

## Dependencies

* [ed25519](https://github.com/warner/python-ed25519/)

## Example

### From Python

```python
from pyroughtime import RoughtimeClient, RoughtimeServer
serv, publ = RoughtimeServer.test_server()
cl = RoughtimeClient()
local_reply = cl.query('127.0.0.1', 2002, publ, newtree=True)
google_reply = cl.query('roughtime.sandbox.google.com', 2002, 'etPaaIxcBMY1oUeGpwvPMCJMwlRVNxv51KK/tktoJTQ=', newtree=False)
serv.stop()
print(local_reply['prettytime'])
print(google_reply['prettytime'])
```

### From console
```console
$ ./pyroughtime.py -l ecosystem.json
Chainpoint-Roughtime:     2019-12-27 18:39:07.035450 UTC (+/- 1.000  s) (RTT:  236.5 ms)
Cloudflare-Roughtime:     2019-12-27 18:39:07.249000 UTC (+/- 1.000  s) (RTT:   16.6 ms)
Google-Sandbox-Roughtime: 2019-12-27 18:39:07.282948 UTC (+/- 1.000  s) (RTT:   12.4 ms)
int08h-Roughtime:         2019-12-27 18:39:07.375952 UTC (+/- 1.000  s) (RTT:  193.2 ms)
roughtime.se:             2019-12-27 18:39:07.535958 UTC (+/- 0.000 ms) (RTT:    4.5 ms)
ticktock:                 2019-12-27 18:39:07.573947 UTC (+/- 1.000  s) (RTT:   48.2 ms)
No inconsistent replies detected.
$ ./pyroughtime.py -s roughtime.se 2002 S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI=
2019-12-27 18:39:37.608463 UTC (+/- 0.000 ms) (RTT: 5.0 ms)
Delegate key validity start: 2019-12-22 00:00:00.000000
Delegate key validity end:   2020-12-31 00:00:00.000000
Merkle tree path length: 0
```

## License

This project is licensed under the GNU General Public License - see the [LICENSE](LICENSE)
file for details.
