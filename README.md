# pyroughtime

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Quick implementation of a Roughtime client using the IETF draft at
<https://tools.ietf.org/html/draft-roughtime-aanchal-00>.

## Dependencies

* [ed25519](https://github.com/warner/python-ed25519/)

## Example

```python
from pyroughtime import RoughtimeServer
google_server = RoughtimeServer('roughtime.sandbox.google.com', 2002, 'etPaaIxcBMY1oUeGpwvPMCJMwlRVNxv51KK/tktoJTQ=')
reply = google_server.query()
print(reply['prettytime'])
```
## License

This project is licensed under the GNU General Public License - see the [LICENSE](LICENSE)
file for details.
