"""Live structure web view for a Miniserver - developer tool, not shipped.

Serves the structure file as a tree with live state values on
``127.0.0.1``. Run it from the repository root::

    python dev_tools/web.py <host> <port> <username> [--uuid UUID] [--web-port PORT]

The password is read from ``LOXONE_PASSWORD`` or asked for, never taken
from the command line.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import os
import sys

from pyloxone_api.__main__ import _control_uuids, _error, _state_labels
from pyloxone_api.connection import LoxoneConnection
from web_ui import WebUi


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Live web view of a Miniserver structure.")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("username")
    parser.add_argument(
        "--uuid",
        action="append",
        default=[],
        metavar="UUID",
        help="show only this control and its states and sub-controls; repeat for more",
    )
    parser.add_argument(
        "--web-port",
        type=int,
        default=8124,
        metavar="PORT",
        help="port for the web page (default: %(default)s)",
    )
    return parser.parse_args(argv)


async def main(argv: list[str]) -> int:
    args = _parse_args(argv)
    password = os.environ.get("LOXONE_PASSWORD") or getpass.getpass(
        f"Password for {args.username}@{args.host}: "
    )
    ui = WebUi(port=args.web_port)
    api = LoxoneConnection(
        host=args.host, port=args.port, username=args.username, password=password
    )
    wanted: frozenset[str] | None = None

    def on_state(connected: bool) -> None:
        nonlocal wanted
        # The structure file is loaded before the connection is reported up.
        if connected:
            ui.labels = _state_labels(api.structure_file)
            ui.set_structure(api.structure_file)
        ui.connection(connected)
        if connected and args.uuid and wanted is None:
            try:
                wanted = _control_uuids(api.structure_file, args.uuid)
            except ValueError as error:
                _error(str(error))
                wanted = frozenset()

    def on_message(data) -> None:
        if not args.uuid:
            ui.message(data)
            return
        if wanted is None or not isinstance(data, dict):
            return
        if "control" in data or "keep_alive" in data:
            return
        states = {uuid: value for uuid, value in data.items() if uuid in wanted}
        if states:
            ui.message(states)

    try:
        await ui.run()
        await api.run(on_state, callback=on_message)
    finally:
        await api.close()
        await ui.stop()
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG if os.environ.get("LOXONE_DEBUG") else logging.INFO)
    try:
        sys.exit(asyncio.run(main(sys.argv[1:])))
    except KeyboardInterrupt:
        sys.exit(130)
