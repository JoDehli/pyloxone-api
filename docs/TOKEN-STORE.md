# Saving the token

A Loxone token lets the library log in without the password. The library
does not write files or databases. Your application decides where the
token lives, using the `token_store` hook.

## The protocol

Your store is any object with these two methods. No base class is needed.
`pyloxone_api.TokenStore` is the same `typing.Protocol`, if you want it for
type checking:

```python
from typing import Protocol

class TokenStore(Protocol):
    def load(self) -> dict | None: ...
    def save(self, token: dict | None) -> None: ...
```

- **`save(token)`** runs after every login and every token refresh, so the
  stored token is always current. It is called with `None` when the token
  is reset, for example after the Miniserver rejects it. Then delete the
  stored copy.
- **`load()`** runs once, in the `LoxoneConnection(...)` constructor. Return
  the dict saved last, or `None`.

Both run synchronously in the event loop. Keep them fast. A store that
writes slow media should hand the write to a thread itself (for example
`asyncio.to_thread`).

## The token dict

`save()` receives a plain dict. It is JSON-serialisable:

```json
{
  "token": "<token from the Miniserver>",
  "valid_until": 412345678.0,
  "hash_alg": "SHA256",
  "unsecure_password": false,
  "binding": {"url": "192.0.2.1:8080", "port": 8080, "user": "example-user"}
}
```

Treat `token` as a secret: it logs in as the user. Store it with file
permissions 0600 or in a secret store, and never put it in logs.

`binding` ties the token to the connection it was issued for. `load()`
returns the dict as it was saved. The library checks the binding itself.

## When a stored token is used

The library uses a loaded token only if all of these hold. Otherwise it
starts with no token and logs in with the password:

- the data is complete and well formed (token, valid time, hash algorithm),
- the `binding` matches the connection's host (with port), port and user,
- more than 100 seconds of validity remain (`TOKEN_MIN_REMAINING_SECONDS`).

A broken or foreign stored token is therefore not an error. It is just
not used. A failing `load()` or `save()` is logged as a warning and does
not stop the connection.

## Example: a JSON file

This example is not part of the library. It shows the shape. A real
implementation should also write atomically (write a temporary file, then
`os.replace`).

```python
import json
import os
from pathlib import Path

from pyloxone_api import LoxoneConnection


class JsonFileTokenStore:
    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self) -> dict | None:
        try:
            return json.loads(self._path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def save(self, token: dict | None) -> None:
        if token is None:
            self._path.unlink(missing_ok=True)
            return
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(token, f)


conn = LoxoneConnection(
    "192.0.2.1",
    "example-user",
    "password",
    port=8080,
    token_store=JsonFileTokenStore(Path("loxone_token.json")),
)
```

## Migrating from `token=` and `token_change_callback`

Both still work. Use `token=` for a token you already hold, and
`token_change_callback` for a plain notification. `token_store` replaces
both: pass either `token=` or `token_store=`, not both. Passing both raises
`ValueError`.

Tokens saved before the binding existed have no `binding` key. They are
not used, so the first start after the upgrade logs in with the password.
