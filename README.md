# pyloxone-api

A Python API for communicating with a [Loxone](https://www.loxone.com) Miniserver.

![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pyloxone-api?style=flat-square)
![PyPI - License](https://img.shields.io/pypi/l/pyloxone-api?style=flat-square)
[![PyPI](https://img.shields.io/pypi/v/pyloxone-api?style=flat-square)](https://pypi.python.org/pypi/pyloxone-api/)

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

Requires Python 3.13 or newer.

## Usage

```python
from pyloxone_api import LoxoneConnection, LoxoneException

connection = LoxoneConnection(host, username, password, port=8080)
```

### How a connection starts

1. HTTP: `jdev/cfg/apiKey`, `jdev/cfg/api` and the public key. These
   requests need no login, so no credentials are sent over HTTP.
2. `open()` loads the structure file (`LoxAPP3.json`) on a short websocket
   session: key exchange, login with the token (or the password hash, if
   there is no usable token), `data/LoxAPP3.json`, close. After `open()`,
   `connection.structure_file` is filled.
3. `start_listening()` / `run()` open the websocket for listening, log in
   and enable state updates. After a reconnect the structure file is loaded
   again on that session, after the login and before `"connected"` - unless
   `jdev/sps/LoxAPPversion3` shows it is unchanged.

### Keeping the token between runs

A token lets the library log in without the password. To keep it across
restarts, pass a `token_store` object that saves and loads the token. The
library never writes files itself. See [Saving the token](docs/TOKEN-STORE.md)
for the protocol, the stored format and a JSON-file example.

```python
connection = LoxoneConnection(host, username, password, token_store=my_store)
```

The public API is exported from `pyloxone_api` (see `__all__`).
Everything else is internal and may change between releases.

Version 0.3.0 is a complete rewrite of the 0.2.x series and is not
API-compatible with it.

## Documentation

- [Callbacks](docs/CALLBACKS.md): what the library calls back into, when, and what happens on errors.
- [Saving the token](docs/TOKEN-STORE.md): keep the login token between restarts with `token_store`.
- [Caching the structure file](docs/STRUCTURE-CACHE.md): skip downloading an unchanged `LoxAPP3.json`.
- [Live web view](dev_tools/README.md): a developer tool that shows a Miniserver's structure and live values in the browser.

## Development

We use [uv](https://docs.astral.sh/uv/) for environments and builds,
and [pytest](https://pytest.org) for tests.

```bash
uv sync --group dev        # create .venv with the package and dev tools
uv run pytest              # tests; online tests are skipped by default
uv run pytest -m online    # online tests, need a live Miniserver
```

Online tests can make a Miniserver behave oddly. Run them only against a
Miniserver you can afford to disturb.

Build the sdist and wheel into `dist/`:

```bash
./scripts/build
```

## License

AGPL-3.0-only, see [LICENSE](LICENSE).
