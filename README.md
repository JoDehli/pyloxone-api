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

## Documentation

- [Callbacks](docs/CALLBACKS.md): what the library calls back into, when, and what happens on errors.
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

Apache-2.0, see [LICENSE](LICENSE).
