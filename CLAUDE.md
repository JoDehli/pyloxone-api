# CLAUDE.md

Notes for future sessions on this project. Do not record private data here
(no addresses, user names, credentials, or device details).

## Project

pyloxone-api is an asynchronous Python library for the WebSocket API of the
Loxone Miniserver (Gen 1 over `ws://`). It has no dependency on Home Assistant.
The Home Assistant integration uses it, but lives in a separate project.

- Python: `>=3.14.2`
- Dependencies: `aiohttp`, `websockets` (`<16`), `pycryptodome`
- License: AGPL-3.0-only (since version 0.4.0). Earlier releases were Apache-2.0.
- Public API: `pyloxone_api/__init__.py` (`__all__`). Everything else is internal.

## Commands

```bash
uv run --frozen pytest                       # tests; online tests are deselected
uv run --frozen pytest -m online <file>      # device tests, see below
./scripts/build                              # sdist and wheel into dist/
```

Lint: Ruff is not listed in `pyproject.toml`. The project already has several
existing findings (mostly E501). New files should be clean.

## Layout

- `src/pyloxone_api/connection.py`: the core. Connection, login, the `run()`
  supervisor, commands, tokens, preflight.
- `src/pyloxone_api/token_store.py`: the `TokenStore` protocol and validation of stored tokens.
- `src/pyloxone_api/const.py`, `exceptions.py`: constants and exceptions.
- `src/pyloxone_api/loxone_http_client.py`: HTTP requests (bootstrap, structure file).
- `docs/CALLBACKS.md`, `docs/TOKEN-STORE.md`: public documentation.
- `release.md`: the release procedure.

## Working method

- Protect each change with a test that fails before the change. Then change
  the code until it passes.
- Do not commit or push unless the user explicitly asks. Commits carry the
  project's usual `Co-Authored-By` line.
- For questions about tokens and device commands, do not answer from memory.
  The Miniserver specification and the measured results below are the basis.
- Never write credentials, tokens, or device addresses into files, logs, test
  output, or commits.

## Device tests

- Run them only with explicit approval from the user.
- They run only with `-m online` and `PYLOXONE_LIVE=1`.
- Credentials come from the environment (`PYLOXONE_TEST_HOST`,
  `PYLOXONE_TEST_USER`, `PYLOXONE_TEST_PASSWORD`) or from `.env.live` in the
  project root. That file is git-ignored and must have mode 0600.
  Configuration lives in `tests/live_config.py`.
- Nothing may be switched on the device. `killtoken` only in the probe
  `tests/test_live_killtoken.py`, and only with approval.

## Measured results (Gen 1 Miniserver, firmware 17.x)

- `checktoken` with the cleartext token and PKCS#7 padding over `jdev/sys/enc`
  is answered with code 200. Zero-byte padding is not needed for this path.
- A token killed with `killtoken` is rejected by `authwithtoken` with 401.
- `killtoken` needs the cleartext token. A hashed token is rejected with 401.
- The documentation mentions 404 for `authwithtoken`, but it has not been
  measured on the device. The library treats 404 like 401 (drop the token and log in again).

## Decisions

- 4007 (update) and 4008 (no event slots) use the normal backoff (at most 60 s).
  A fixed 300 s wait was dropped, because it delayed reconnects after an update.
- HTTP basic auth is sent as an `Authorization` header, not through the
  deprecated `auth=` parameter.
- The source distribution excludes internal notes (`[tool.hatch.build.targets.sdist]`).
  Internal notes do not belong in the repository.

## Open items

- The behavior for 901 (maximum number of concurrent connections) is not decided.
- Keepalive: the rule "90 s without data means dead" has not been checked yet.
- `hasEventSlots` via `jdev/cfg/api` before connecting is implemented, but not
  yet used as the behavior for 4008.
- Request-response model (queue per keyword): benchmark first, then decide.
- The full handover with the history lives locally and is not in the repository.
