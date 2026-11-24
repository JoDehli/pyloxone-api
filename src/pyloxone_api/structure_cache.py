"""Optional persistence hook for the structure file (``LoxAPP3.json``).

The library keeps the last structure file in memory and, before downloading
it again, asks the Miniserver for its version (``jdev/sps/LoxAPPversion3``).
If it equals ``lastModified`` of the kept file, the download is skipped
(spec "Structure-File: LoxAPP3.json", Download and caching).

To skip the download after a restart too, pass an object with two methods as
``structure_cache=`` to :class:`LoxoneConnection`:

- ``load() -> dict | None``: the structure file saved last, or ``None``.
- ``save(structure: dict) -> None``: called after every download.

Both may be slow (the file can be several megabytes); with an ``executor``
they run through it. Failures are logged, never raised.
"""

from __future__ import annotations

from typing import Any, Protocol


class StructureCache(Protocol):
    """Application-side persistence for the structure file."""

    def load(self) -> dict[str, Any] | None:
        """Return the structure file saved last, or ``None``."""
        ...

    def save(self, structure: dict[str, Any]) -> None:
        """Persist ``structure`` (as downloaded, a JSON object)."""
        ...


def _normalise_serial(value: Any) -> str:
    return str(value or "").replace(":", "").upper()


def cached_structure_for(data: Any, serial: str) -> dict[str, Any] | None:
    """``data`` if it is a usable structure file of the Miniserver ``serial``.

    A file without ``lastModified`` cannot be compared and is not used. When
    both serial numbers are known they must match.
    """
    if not isinstance(data, dict) or not data.get("lastModified"):
        return None
    cached_serial = _normalise_serial((data.get("msInfo") or {}).get("serialNr"))
    if not cached_serial or not serial:
        return None
    if cached_serial != _normalise_serial(serial):
        return None
    return data
