# pyloxone-api

Low-level asynchronous client for the **Loxone Miniserver** WebSocket API.
It handles the HTTP bootstrap, WebSocket connection, authentication
(token and key exchange), commands and state events. It has no dependency
on Home Assistant.

Used by the [PyLoxone](https://github.com/JoDehli/PyLoxone) Home Assistant
integration.

## Installation

```bash
pip install pyloxone-api
```

Requires Python 3.14 or newer.

## Usage

```python
from pyloxone_api import LoxoneConnection, LoxoneException

connection = LoxoneConnection(host, port, username, password, ...)
```

The public API is exported from `pyloxone_api` (see `__all__`).
Everything else is internal and may change between releases.

Version 0.3.0 is a complete rewrite of the 0.2.x series and is not
API-compatible with it.

## Development

```bash
pip install -e .
pip install pytest pytest-asyncio
pytest                 # online tests (need a Miniserver) are skipped
pytest -m online       # run them against a real Miniserver
```

Dependency ranges are kept wide enough to install alongside Home Assistant
2026.9.1 (`aiohttp==3.14.3`, `websockets>=15.0.1`).

## License

Apache-2.0, see [LICENSE](LICENSE).
