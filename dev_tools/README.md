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

From the repository root:

```bash
export LOXONE_PASSWORD='...'          # optional, otherwise asked for
python dev_tools/web.py 192.168.1.10 80 admin
```

Then open <http://127.0.0.1:8124/> in a browser. The page refreshes itself
and shows the value of each state as it changes.

### Options

| Option | Meaning |
|---|---|
| `host` `port` `username` | Miniserver address and user. Required. |
| `--uuid UUID` | Show only this control, including its states and sub-controls. Repeat for more. |
| `--web-port PORT` | Port of the local page (default `8124`). |

Example, limited to one control:

```bash
python dev_tools/web.py 192.168.1.10 80 admin --uuid 0a1b2c3d-...
```

The password is never taken from the command line, because other users
could read it from the process list. Use `LOXONE_PASSWORD` or the prompt.

### Notes

- The page serves only on `127.0.0.1`. It is not reachable from the network.
- Set `LOXONE_DEBUG=1` for debug logging of the connection.
- Stop with Ctrl+C.

## Command-line output

The package also has a plain CLI that prints the traffic without a web page:

```bash
python -m pyloxone_api 192.168.1.10 80 admin --format raw
python -m pyloxone_api 192.168.1.10 80 admin --format pretty
```
