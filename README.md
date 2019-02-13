# pyroughtime

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

An experimental Roughtime client and server implementation in Python 3 using the IETF draft at
<https://tools.ietf.org/html/draft-roughtime-aanchal-00>.

## Dependencies

* [ed25519](https://github.com/warner/python-ed25519/)

## Example

### From Python

```python
from pyroughtime import RoughtimeClient, RoughtimeServer
serv, publ = RoughtimeServer.test_server()
cl = RoughtimeClient()
local_reply = cl.query('127.0.0.1', 2002, publ)
google_reply = cl.query('roughtime.sandbox.google.com', 2002, 'etPaaIxcBMY1oUeGpwvPMCJMwlRVNxv51KK/tktoJTQ=')
serv.stop()
print(local_reply['prettytime'])
print(google_reply['prettytime'])
```

### From console
```console
$ ./pyroughtime.py ecosystem.json
Chainpoint-Roughtime:     2019-02-13 18:52:23.329492 UTC (+/- 1.00 s) (RTT:  128.1 ms)
Cloudflare-Roughtime:     2019-02-13 18:52:23.448000 UTC (+/- 1.00 s) (RTT:   18.0 ms)
Google-Sandbox-Roughtime: 2019-02-13 18:52:23.473657 UTC (+/- 1.00 s) (RTT:   13.8 ms)
int08h-Roughtime:         2019-02-13 18:52:23.559739 UTC (+/- 1.00 s) (RTT:  212.8 ms)
ticktock:                 2019-02-13 18:52:23.773237 UTC (+/- 1.00 s) (RTT:   59.0 ms)
No inconsistent replies detected.
$ ./pyroughtime.py roughtime.sandbox.google.com 2002 etPaaIxcBMY1oUeGpwvPMCJMwlRVNxv51KK/tktoJTQ=
2019-02-13 18:52:25.056672 UTC (+/- 1.00 s) (RTT: 13.0 ms)
```

## License

This project is licensed under the GNU General Public License - see the [LICENSE](LICENSE)
file for details.
