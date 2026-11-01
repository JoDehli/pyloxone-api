"""Live structure web view for a Miniserver - developer tool, not shipped.

Serves the structure file as a tree with live state values on
``127.0.0.1``. Run it from the repository root, either with an address::

    python dev_tools/web.py --host 192.168.1.10 --port 80 admin

or let it search the local network for Miniservers::

    python dev_tools/web.py --discover admin

If several Miniservers answer, you pick one from a list.

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
from pyloxone_api.discover import discover_all
from web_ui import WebUi

DISCOVER_SECONDS = 10


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Live web view of a Miniserver structure.")
    parser.add_argument("username")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--host", help="Miniserver address, e.g. 192.168.1.10")
    target.add_argument(
        "--discover",
        action="store_true",
        help=f"search the local network for {DISCOVER_SECONDS} s; pick one if several answer",
    )
    parser.add_argument("--port", type=int, default=80, help="Miniserver port (default: %(default)s)")
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
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="show every connection attempt of the library",
    )
    return parser.parse_args(argv)


async def _choose_miniserver() -> tuple[str, int]:
    print(f"searching the local network for Miniservers ({DISCOVER_SECONDS} s) ...")
    found = await discover_all(timeout=DISCOVER_SECONDS)
    if not found:
        raise SystemExit("no Miniserver answered. Check the network, or use --host and --port.")
    if len(found) == 1:
        ip, port, _ = found[0]
        print(f"found one Miniserver: {ip}:{port}")
        return ip, port

    print(f"found {len(found)} Miniservers:")
    for number, (ip, port, response) in enumerate(found, 1):
        print(f"  {number}) {ip}:{port}   {response.strip()[:70]}")
    if not sys.stdin.isatty():
        raise SystemExit(
            "several Miniservers found, but there is no terminal to choose from. "
            "Use --host and --port."
        )
    while True:
        answer = input(f"choose [1-{len(found)}]: ").strip()
        if answer.isdigit() and 1 <= int(answer) <= len(found):
            ip, port, _ = found[int(answer) - 1]
            return ip, port
        print("not a valid choice, try again")


async def _check_reachable(host: str, port: int, timeout: float = 10.0) -> str | None:
    """A plain TCP connect, so a wrong address fails in seconds, not after retries.

    Returns None if the port accepts connections, otherwise a short reason.
    """
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except asyncio.TimeoutError:
        return f"no answer within {timeout:.0f} s"
    except OSError as error:
        return error.strerror or str(error)
    writer.close()
    await writer.wait_closed()
    return None


async def main(argv: list[str]) -> int:
    args = _parse_args(argv)
    logging.getLogger("pyloxone_api").setLevel(logging.DEBUG if args.verbose else logging.WARNING)

    if args.discover:
        host, port = await _choose_miniserver()
    else:
        host, port = args.host, args.port

    problem = await _check_reachable(host, port)
    if problem:
        print(f"cannot reach {host}:{port}: {problem}. Check the address and port.")
        return 1

    password = os.environ.get("LOXONE_PASSWORD") or getpass.getpass(
        f"Password for {args.username}@{host}:{port}: "
    )

    ui = WebUi(port=args.web_port)
    api = LoxoneConnection(host=host, port=port, username=args.username, password=password)
    wanted: frozenset[str] | None = None
    print(
        f"connecting to {host}:{port} ... the library retries a few times with backoff, "
        "so a wrong address can take up to a minute to report"
    )

    def on_state(state: str) -> None:
        nonlocal wanted
        if state == "connected":
            # The structure file is loaded before the connection is reported up.
            ui.labels = _state_labels(api.structure_file)
            ui.set_structure(api.structure_file)
            ui.connection(True)
            if args.uuid and wanted is None:
                try:
                    wanted = _control_uuids(api.structure_file, args.uuid)
                except ValueError as error:
                    _error(str(error))
                    wanted = frozenset()
        elif state == "disconnected":
            ui.connection(False)
            print(f"no connection to {host}:{port} - retrying")
        elif state == "failed":
            print(
                f"giving up on {host}:{port}. The messages above say why "
                "(often a wrong username or password)."
            )

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
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        sys.exit(asyncio.run(main(sys.argv[1:])))
    except KeyboardInterrupt:
        sys.exit(130)
