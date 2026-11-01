# Callbacks

`pyloxone_api` calls back into your code in four places. None of them
raises into the library: a failing callback is logged and the connection
keeps running.

| Where | Parameter | Called with | Sync or async | On error |
|---|---|---|---|---|
| `LoxoneConnection(...)` | `executor` | `executor(target, *args)` | must return an awaitable | invalid JSON raises `ValueError`, any other failure `RuntimeError`, both from the structure load |
| `LoxoneConnection(...)` | `token_change_callback` | `token_dict` (dict) | either | logged as WARNING, never raised |
| `run(...)` | `on_state` | `state` (str) | either | logged as WARNING, never raised |
| `run(...)` / `start_listening(...)` | `callback` | `msg.as_dict()` (dict) | either | logged as ERROR with traceback, never raised |

## `executor`

Moves blocking work off the event loop. The library uses it for
`json.loads` of the structure file, which can be several megabytes.

```python
conn = LoxoneConnection(host, username, password, executor=loop_executor)

async def loop_executor(target, *args):
    return await asyncio.to_thread(target, *args)
```

Home Assistant passes `hass.async_add_executor_job`, which has the same
shape. Without `executor` the library parses inline.

## `token_change_callback`

Called after a new token is obtained (initial authentication or refresh).
Use it to persist the token, so the next start can reuse it without
logging in again with the password.

```python
def on_token(token: dict) -> None:
    store.save(token)

conn = LoxoneConnection(host, username, password, token_change_callback=on_token)
```

`token` has the keys returned by `get_token_dict()`. Treat it as secret:
the library never logs its value. If the callback is a coroutine function,
it runs as a tracked task, so the websocket path is not blocked.

## `on_state`

Passed to `run()`. Reports the connection state, so you can update
availability without watching tasks.

| `state` | Meaning |
|---|---|
| `"connected"` | Authenticated and listening. Fired again after every successful reconnect. |
| `"disconnected"` | The connection was closed, by you or by the library. |
| `"failed"` | A reconnect attempt failed. `run()` retries with backoff. |

```python
def on_state(state: str) -> None:
    print("Miniserver:", state)

await conn.run(on_state=on_state)
```

## `callback` (messages)

Passed to `run()` or `start_listening()`. Receives the message as a dict
from `msg.as_dict()`, only for these message types:

- `VALUE_STATES`: state values, keyed by state UUID
- `TEXT_STATES`: text states, keyed by state UUID
- `TEXT`
- `KEEPALIVE`

Some messages carry extra keys such as `control` or `keep_alive`. The
developer web view filters on them; see `src/pyloxone_api/__main__.py`.

```python
def on_message(data: dict) -> None:
    for uuid, value in data.items():
        print(uuid, value)

await conn.run(callback=on_message)
```

Messages of other types are not forwarded. The library handles them
internally.

### Known inconsistency

`start_listening(callback)` is annotated as `Callable[[str, Any], ...]`,
but it calls the callback with one argument, the message dict. Write the
callback with one parameter. The annotation is to be corrected.
