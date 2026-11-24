"""Loxone Remote Connect: find the address of a Miniserver by its serial.

Spec "Communicating with the Miniserver" V17.0, "Remote Connect Service
>V17.0" and "CloudDNS": since 2026 ``dns.loxonecloud.com`` is deprecated,
``connect.loxonecloud.com`` is used instead. It also serves Miniservers on
the newest Remote Connect (distributed relays, fallback relays):

- ``GET /getip?snr={serial}`` -> ``200 {"url": "..."}``
- 400 invalid serial, 404 serial not found or no working relay,
  500 internal error, 504 Miniserver not connected to a relay

Older replies use the CloudDNS format (``Code``, ``IP``, ``IPHTTPS``) with
the codes 403 (not registered / CloudDNS disabled), 405 (not reporting),
409 (unsecure password, external access blocked), 412 (port not opened),
418 (denied, details in ``Info``), 481/482 (relay connection failed /
timed out) and 483 (scheduled restart).

A host given as ``connect.loxonecloud.com/{serial}`` (or the old
``dns.loxonecloud.com/{serial}``) switches a connection to Remote Connect;
the address is resolved again on every ``open()`` because the relay can
change. Remote Connect only supports HTTPS/WSS.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import aiohttp

from .exceptions import LoxoneRemoteConnectDeniedError, LoxoneRemoteConnectError

_LOGGER = logging.getLogger(__name__)

REMOTE_CONNECT_HOST = "connect.loxonecloud.com"
_REMOTE_HOSTS = {REMOTE_CONNECT_HOST, "dns.loxonecloud.com"}
_SERIAL = re.compile(r"[0-9A-F]{12}")

# Codes after which retrying is pointless until someone changes something.
_FINAL_CODES = {
    400: "invalid serial number",
    403: "request not permitted",
    405: "Miniserver is not reporting to the Loxone Cloud",
    409: "external access blocked because of an unsecure password",
    412: "port of the Miniserver not opened",
    418: "request denied",
}
# Codes that may resolve themselves (relay hiccup, restart, ...).
_TRANSIENT_CODES = {
    404: "serial not found or no working relay",
    481: "Miniserver could not connect to the Remote Connect service",
    482: "Remote Connect connection of the Miniserver timed out",
    483: "Miniserver makes a scheduled restart",
    500: "internal error of the Remote Connect service",
    504: "Miniserver is not connected to a relay",
}


def normalise_serial(value: Any) -> str | None:
    """``504F94A23DB1`` from ``50:4F:94:A2:3D:B1`` etc.; ``None`` if invalid."""
    if not isinstance(value, str):
        return None
    serial = re.sub(r"[\s:-]", "", value).upper()
    return serial if _SERIAL.fullmatch(serial) else None


def remote_connect_serial(host: str) -> str | None:
    """The serial of a Remote Connect host (``connect.loxonecloud.com/{snr}``)."""
    parsed = urlparse(host if "://" in host else f"//{host}")
    if (parsed.hostname or "").lower() not in _REMOTE_HOSTS:
        return None
    return normalise_serial(parsed.path.strip("/").split("/", 1)[0])


@dataclass(frozen=True)
class RemoteAddress:
    """Where the Miniserver is reachable: scheme and ``host[:port][/path]``."""

    scheme: str
    url: str


def _address_from_url(value: str) -> RemoteAddress:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    if not parsed.hostname:
        msg = f"Remote Connect returned an unusable address: {value!r}"
        raise LoxoneRemoteConnectError(msg)
    scheme = "https" if parsed.scheme in ("https", "wss", "") else "http"
    path = parsed.path.rstrip("/")
    return RemoteAddress(scheme, f"{parsed.netloc}{path}")


def _message(data: Any, fallback: str) -> str:
    if isinstance(data, dict):
        info = data.get("Info")
        if isinstance(info, dict) and info.get("message"):
            return str(info["message"])
        if data.get("error"):
            return str(data["error"])
    return fallback


def _dyndns_host(address: str, serial: str | None, data_center: Any) -> str:
    """``1.2.3.4:443`` -> ``1-2-3-4.{snr}.dyndns.{data center}:443``.

    The relay answers with an IP and port, but its certificate is issued for
    the dyndns host name (spec "Support for distributed data centers", step 4).
    Anything that is not an IPv4 literal, or an unknown serial, is kept as is.
    """
    host, sep, port = address.rpartition(":")
    if not sep:
        host, port = address, ""
    if serial is None or not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        return address
    domain = data_center if isinstance(data_center, str) and data_center else "loxonecloud.com"
    name = f"{host.replace('.', '-')}.{serial}.dyndns.{domain}"
    return f"{name}:{port}" if port else name


def parse_getip_response(
    status: int, body: bytes | str, serial: str | None = None
) -> RemoteAddress:
    """Turn a ``/getip`` reply into an address or the matching exception."""
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    try:
        data = json.loads(text) if text.strip() else None
    except ValueError:
        data = None

    code = status
    if isinstance(data, dict) and isinstance(data.get("Code"), int) and status == 200:
        code = data["Code"]  # CloudDNS format reports errors in the body

    if code == 200 and isinstance(data, dict):
        if isinstance(data.get("url"), str) and data["url"]:
            return _address_from_url(data["url"])
        # CloudDNS format: prefer the TLS address.
        if data.get("IPHTTPS"):
            host = _dyndns_host(str(data["IPHTTPS"]), serial, data.get("DataCenter"))
            return _address_from_url(f"https://{host}")
        if data.get("IP"):
            return _address_from_url(f"http://{data['IP']}")
        msg = "Remote Connect returned no address"
        raise LoxoneRemoteConnectError(msg, code=code)

    if code in _FINAL_CODES:
        msg = f"Remote Connect refused ({code}): {_message(data, _FINAL_CODES[code])}"
        raise LoxoneRemoteConnectDeniedError(msg, code=code)
    msg = f"Remote Connect failed ({code}): {_message(data, _TRANSIENT_CODES.get(code, 'unexpected reply'))}"
    raise LoxoneRemoteConnectError(msg, code=code)


async def _fetch(
    session: aiohttp.ClientSession, url: str, timeout: float
) -> tuple[int, bytes]:
    async with session.get(
        url, timeout=aiohttp.ClientTimeout(total=timeout)
    ) as response:
        return response.status, await response.read()


async def resolve_remote_address(
    serial: str,
    session: aiohttp.ClientSession | None = None,
    *,
    timeout: float = 10,
) -> RemoteAddress:
    """Ask ``connect.loxonecloud.com`` where the Miniserver ``serial`` is."""
    snr = normalise_serial(serial)
    if snr is None:
        msg = f"Invalid Miniserver serial number: {serial!r}"
        raise ValueError(msg)
    # Without ``json=true`` the service answers in XML (``<Answer .../>``).
    url = f"https://{REMOTE_CONNECT_HOST}/getip?snr={snr}&json=true"
    try:
        if session is not None:
            status, body = await _fetch(session, url, timeout)
        else:
            async with aiohttp.ClientSession() as own_session:
                status, body = await _fetch(own_session, url, timeout)
    except (aiohttp.ClientError, TimeoutError, OSError) as err:
        msg = f"Remote Connect not reachable: {err}"
        raise LoxoneRemoteConnectError(msg) from err
    address = parse_getip_response(status, body, snr)
    _LOGGER.debug(
        "Remote Connect: Miniserver %s reachable at %s://%s",
        snr,
        address.scheme,
        address.url,
    )
    return address
