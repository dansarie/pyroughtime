# pyroughtime

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Quick Roughtime client implementation using the IETF draft at
<https://tools.ietf.org/html/draft-roughtime-aanchal-00>.

## Dependencies

* [ed25519](https://github.com/warner/python-ed25519/)

## Example

```python
from pyroughtime import RoughtimeClient, RoughtimeServer
serv, publ = RoughtimeServer.test_server()
local = RoughtimeClient('127.0.0.1', 2002, publ)
google = RoughtimeClient('roughtime.sandbox.google.com', 2002, 'etPaaIxcBMY1oUeGpwvPMCJMwlRVNxv51KK/tktoJTQ=')
local_reply = local.query()
google_reply = google.query(local_reply['reply_data'])
serv.stop()
print(local_reply['prettytime'])
print(google_reply['prettytime'])
```
## License

This project is licensed under the GNU General Public License - see the [LICENSE](LICENSE)
file for details.
