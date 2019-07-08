# pyroughtime

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

An experimental Roughtime client and server implementation in Python 3 using the IETF draft at
<https://tools.ietf.org/html/draft-roughtime-aanchal-03>.

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
$ ./pyroughtime.py ecosystem.json
Chainpoint-Roughtime:     2019-07-08 19:03:01.484444 UTC (+/- 1.000  s) (RTT:  149.3 ms)
Cloudflare-Roughtime:     2019-07-08 19:03:01.590000 UTC (+/- 1.000  s) (RTT:    6.1 ms)
Google-Sandbox-Roughtime: 2019-07-08 19:03:01.607248 UTC (+/- 1.000  s) (RTT:   13.3 ms)
int08h-Roughtime:         2019-07-08 19:03:01.690529 UTC (+/- 1.000  s) (RTT:  159.7 ms)
roughtime.se:             2019-07-08 19:03:01.799910 UTC (+/- 0.001 ms) (RTT:    6.4 ms)
ticktock:                 2019-07-08 19:03:01.851144 UTC (+/- 1.000  s) (RTT:   61.4 ms)
No inconsistent replies detected.
$ ./pyroughtime.py roughtime.se 2002 S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI=
2019-07-08 19:03:04.584587 UTC (+/- 0.001 ms) (RTT: 7.8 ms)

```

## License

This project is licensed under the GNU General Public License - see the [LICENSE](LICENSE)
file for details.
