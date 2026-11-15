# Caching the structure file

The structure file (`LoxAPP3.json`) describes every control of the
Miniserver and can be several megabytes. The library loads it over the
websocket after each login. Before downloading, it asks the Miniserver for
the file's version (`jdev/sps/LoxAPPversion3`). If that equals
`lastModified` of the file it already has, the download is skipped.

Within one `LoxoneConnection` the last file is kept in memory, so a
reconnect without a configuration change downloads nothing. When the file
is unchanged, `structure_file` stays the same object.

## Keeping it across restarts

Pass a `structure_cache` object with two methods. No base class is needed;
`pyloxone_api.StructureCache` is the same `typing.Protocol`:

```python
class StructureCache(Protocol):
    def load(self) -> dict | None: ...
    def save(self, structure: dict) -> None: ...
```

- **`load()`** runs when a session has no file in memory yet (normally once,
  in `open()`). Return the dict saved last, or `None`.
- **`save(structure)`** runs after every download, with the file as the
  Miniserver sent it.

With an `executor` both run through it, as they may read or write several
megabytes. A failing `load()` or `save()` is logged as a warning and the
file is downloaded as usual.

A cached file is used only if it has `lastModified` and its
`msInfo.serialNr` matches the serial number the Miniserver reports, so a
file of another Miniserver is never used.

```python
import json
from pathlib import Path


class JsonFileStructureCache:
    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self) -> dict | None:
        try:
            return json.loads(self._path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def save(self, structure: dict) -> None:
        self._path.write_text(json.dumps(structure))


conn = LoxoneConnection(
    host, username, password,
    structure_cache=JsonFileStructureCache(Path("loxapp3.json")),
)
```

The structure file contains no secrets, but it describes the whole
installation (rooms, devices, users' names). Store it accordingly.
