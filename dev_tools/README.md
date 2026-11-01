# Developer tools

Tools for working on `pyloxone_api` against a real Miniserver. They are not
part of the package and are not in the wheel.

## Live web view

`web.py` connects to a Miniserver, loads its structure file and serves a page
on `127.0.0.1` that shows the structure as a tree with live state values.

### Prerequisites

- The package installed in the environment you run from, editable from the
  checkout, for example `uv pip install -e .`
- Network access to the Miniserver

### Start

From the repository root, with the address:

```bash
python dev_tools/web.py --host 192.168.1.10 --port 80 admin
```

or let it search the local network:

```bash
python dev_tools/web.py --discover admin
```

Then open <http://127.0.0.1:8124/> in a browser. The page refreshes itself
and shows the value of each state as it changes.

### Flags

| Flag | Required | Default | Meaning |
|---|---|---|---|
| `username` | yes | | Miniserver user name. Positional, last argument. |
| `--host HOST` | one of `--host` / `--discover` | | Miniserver address, e.g. `192.168.1.10`. |
| `--discover` | one of `--host` / `--discover` | | Search the local network for 10 s. One answer is used directly; several answers give a numbered list to choose from. |
| `--port PORT` | no | `80` | Miniserver port. |
| `--uuid UUID` | no | all controls | Show only this control, including its states and sub-controls. Repeat the flag for more controls. |
| `--web-port PORT` | no | `8124` | Port of the local page on `127.0.0.1`. |
| `-v`, `--verbose` | no | off | Show every connection attempt of the library. Useful for debugging a failing connection. |
| `-h`, `--help` | no | | Show the built-in help. |

`--host` and `--discover` cannot be combined. One of them is required.

### What happens at start

1. **Address check.** Before anything else, the tool opens a plain TCP connection
   to `host:port`, with a 10 s timeout. If nothing accepts the connection, it
   stops at once with a message such as `cannot reach 10.0.0.5:80: no answer within 10 s`.
   No password is asked for in this case.
2. **Password.** Read from the environment variable `LOXONE_PASSWORD`, or asked
   for on the terminal.
3. **Connection.** The library connects, retries a few times with backoff, and
   then reports `connected`. Retries are logged only with `--verbose`.

### Examples

```bash
# Password from the environment, no prompt
LOXONE_PASSWORD='...' python dev_tools/web.py --host 192.168.1.10 admin

# Only one control, page on another port
python dev_tools/web.py --host 192.168.1.10 --uuid 0a1b2c3d-... --web-port 8200 admin

# Several controls
python dev_tools/web.py --host 192.168.1.10 --uuid UUID1 --uuid UUID2 admin

# Discover, then pick if several answer
python dev_tools/web.py --discover admin

# Debug a connection that does not come up
python dev_tools/web.py --host 192.168.1.10 --verbose admin
```

The password is never taken from the command line, because other users
could read it from the process list.

### Output

- `connecting to ...` at start.
- `web UI http://127.0.0.1:<port>/` once connected.
- `no connection to ... - retrying` while the library waits to reconnect.
- `giving up on ...` if the library stops retrying. The messages above say why.

### Notes

- The page serves only on `127.0.0.1`. It is not reachable from the network.
- Stop with Ctrl+C.

## Command-line output

The package also has a plain CLI that prints the traffic without a web page:

```bash
python -m pyloxone_api 192.168.1.10 80 admin --format raw
python -m pyloxone_api 192.168.1.10 80 admin --format pretty
```
