"""Live web view of a Miniserver structure - developer tool, not shipped.

:class:`WebUi` renders the structure file as a tree with live state values
on ``127.0.0.1``. It is used by ``dev_tools/web.py`` and is not part of the
``pyloxone_api`` package or its wheel.
"""

from __future__ import annotations

import datetime
import html
import json
import urllib.parse

from aiohttp import web

from pyloxone_api.__main__ import _state_labels, _strings, _write


def _tree_nodes(entries: dict, labels: dict[str, str]) -> list[dict]:
    """The structure of one section as nested dicts, in file order.

    A node carries its control name, type, uuid, its states (with the
    readable label) and its ``subControls`` recursively - everything the
    web page renders, without having to see the raw structure file.
    """
    nodes = []
    for uuid, control in entries.items():
        if not isinstance(control, dict):
            nodes.append({"name": uuid, "uuid": uuid, "type": None, "states": [], "subControls": []})
            continue
        name = str(control.get("name") or uuid)
        states = []
        for key, value in (control.get("states") or {}).items():
            for state_uuid in _strings(value):
                states.append(
                    {
                        "key": key,
                        "uuid": state_uuid,
                        "label": labels.get(state_uuid, f"{name}.states.{key}"),
                    }
                )
        nodes.append(
            {
                "name": name,
                "type": control.get("type"),
                "uuid": uuid,
                "states": states,
                "subControls": _tree_nodes(
                    control.get("subControls") or {}, labels
                ),
            }
        )
    return nodes


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _value_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        trimmed = f"{value:g}"
        return trimmed
    try:
        return json.JSONEncoder(ensure_ascii=False, separators=(",", ":")).encode(value)
    except TypeError:
        return repr(value)


def _value_class(value) -> str:
    """CSS class: green for on/positive values, red for off/zero.

    Text values stay neutral - a nonempty text state is not on/off.
    """
    if isinstance(value, bool):
        return "on" if value else "off"
    if isinstance(value, (int, float)):
        return "on" if value > 0 else "off"
    return ""


_WEB_PAGE_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
{refresh}
<title>pyloxone-cli - live tree</title>
<style>
body { font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
       margin: 0; background: #eef1f5; color: #1f2933; font-size: 14px; }
header { background: #1e3a5f; color: #ffffff; padding: 0.9rem 1.5rem; }
header h1 { margin: 0; font-size: 1.05rem; font-weight: 600; letter-spacing: 0.02em; }
header span { color: #b8c7db; font-size: 0.78rem; }
main { padding: 1rem 1.5rem 2rem; }
form { margin: 0 0 1rem; display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
button { font: inherit; padding: 0.45rem 0.9rem; border-radius: 6px; cursor: pointer;
         background: #1e60aa; color: #ffffff; border: 1px solid #1e60aa; }
button[name="pause"], a.button { background: #ffffff; color: #1e3a5f; border: 1px solid #c3ccd8;
         border-radius: 6px; padding: 0.45rem 0.9rem; text-decoration: none; }
.status { font-size: 0.78rem; padding: 0.2rem 0.6rem; border-radius: 999px; margin-left: 0.3rem; }
.status.live { background: #e6f6ec; color: #05603a; }
.status.paused { background: #fff4e5; color: #8a4b08; }
input { font: inherit; padding: 0.45rem 0.7rem; width: 22rem; background: #ffffff;
        border: 1px solid #c3ccd8; border-radius: 6px; outline: none; }
input:focus { border-color: #1e60aa; box-shadow: 0 0 0 3px rgba(30, 96, 170, 0.15); }
section { background: #ffffff; border: 1px solid #dde3ea; border-radius: 8px;
          margin-bottom: 1rem; padding: 0.5rem 0.9rem 0.8rem;
          box-shadow: 0 1px 2px rgba(16, 24, 40, 0.05); }
h2 { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.08em;
     color: #1e60aa; margin: 0.3rem 0 0.4rem; }
ul { list-style: none; padding-left: 1rem; margin: 0; border-left: 1px solid #e3e8ef; }
li { padding: 0.25rem 0.3rem; border-radius: 4px; }
li:hover { background: #f5f8fc; }
.label { color: #1f2933; font-weight: 500; }
em { color: #7b8794; font-style: normal; font-size: 0.85em; }
.uuid { color: #6b7785; font-family: ui-monospace, monospace; font-size: 0.74rem;
        margin-left: 0.6rem; background: #f1f4f8; border: 1px solid #e3e8ef;
        border-radius: 4px; padding: 0.02rem 0.35rem; }
.value { font-family: ui-monospace, monospace; font-weight: 600; margin-left: 0.9rem;
         color: #3e4c59; display: inline-block; min-width: 4rem; max-width: 40rem;
         vertical-align: middle; text-align: center; overflow-wrap: anywhere;
         background: #f8fafc; border: 1px solid #cbd2db; border-radius: 5px;
         padding: 0.08rem 0.55rem; line-height: 1.5; }
.value.on { color: #05603a; background: #e6f6ec; border-color: #6cc08b; }
.value.off { color: #9b1c1c; background: #fdecea; border-color: #f0a3a3; }
.footer { color: #7b8794; font-size: 0.75rem; margin-top: 1rem; text-align: right; }
</style>
</head>
<body>
<header><h1>Loxone live tree</h1></header>
<main>
"""


class WebUi:
    """``--format web``: the structure as a tree with live values.

    Serves a read-only page on ``127.0.0.1`` only, rendered entirely in
    Python on every request: the structure file as a tree (JSON order,
    nested ``subControls``, ``autopilot`` last), every state labelled,
    each state value filled in from everything the connection has
    reported. The page reloads itself every two seconds via a plain HTML
    ``meta http-equiv="refresh"`` - no JavaScript anywhere. A text filter
    narrows the rendered tree server-side (``?q=...``, submitted with a
    plain HTML form).
    """

    def __init__(self, port: int = 8124) -> None:
        self._port = port
        self._runner = None
        self.labels: dict[str, str] = {}
        self.sections: list[dict] = []
        self.states: dict[str, object] = {}

    def set_structure(self, structure: dict) -> None:
        self.labels = _state_labels(structure)
        self.sections = [
            {"name": "controls", "nodes": _tree_nodes(structure.get("controls") or {}, self.labels)}
        ]
        if structure.get("autopilot"):
            self.sections.append(
                {
                    "name": "autopilot",
                    "nodes": _tree_nodes(structure["autopilot"], self.labels),
                }
            )

    def connection(self, connected: bool) -> None:
        _write(f"web UI    http://127.0.0.1:{self._port}/" if connected else "web UI    disconnected")

    def message(self, data) -> None:
        if not isinstance(data, dict):
            return
        # Replies and keepalives are not states.
        if "control" in data or "keep_alive" in data:
            return
        self.states.update(data)

    # --- rendering ----------------------------------------------------------

    @staticmethod
    def _node_matches(node: dict, query: str) -> bool:
        if query in node.get("name", "").lower() or query in node.get("uuid", "").lower():
            return True
        return any(
            query in state.get("label", "").lower()
            or query in state.get("uuid", "").lower()
            for state in node.get("states", [])
        ) or any(
            WebUi._node_matches(sub, query) for sub in node.get("subControls", [])
        )

    def _render_node(self, node: dict, query: str) -> str:
        title = _esc(node.get("name"))
        if node.get("type"):
            title += f" <em>({_esc(node['type'])})</em>"
        title += f' <span class="uuid">[{_esc(node.get("uuid"))}]</span>'
        states = "".join(
            f'<li><span class="label">{_esc(state["label"])}</span>'
            f'<span class="uuid">[{_esc(state["uuid"])}]</span>'
            + '<span class="value {cls}">{text}</span></li>'.format(
                cls=_esc(_value_class(value := self.states.get(state["uuid"]))),
                text=_esc(_value_text(value)),
            )
            for state in node.get("states", [])
            if not query or query in state.get("label", "").lower() or query in state.get("uuid", "").lower()
        )
        subs = [self._render_node(sub, query) for sub in node.get("subControls", [])]
        subs = "".join(sub for sub in subs if sub)
        if query and not states and not subs and not self._node_matches(node, query):
            return ""
        body = title
        if states:
            body += f"<ul>{states}</ul>"
        if subs:
            body += f"<ul>{subs}</ul>"
        return f"<li>{body}</li>"

    def _render_page(self, query: str, paused: bool = False) -> str:
        refresh = "" if paused else '<meta http-equiv="refresh" content="2">'
        parts = [_WEB_PAGE_HEAD.replace("{refresh}", refresh)]
        # Typing is only possible while the page is paused: a live refresh
        # would reload the form and drop the input.
        pause_field = '<input type="hidden" name="pause" value="1">' if paused else ""
        if paused:
            pause_button = f'<a class="button" href="/?{urllib.parse.urlencode({"q": query})}">Resume updates</a>'
        else:
            pause_button = '<button name="pause" value="1">Pause updates</button>'
        status = (
            '<span class="status paused">paused - updates off</span>'
            if paused
            else '<span class="status live">live</span>'
        )
        parts.append(
            f'<form method="get">{pause_field}'
            f'<input name="q" value="{_esc(query)}" placeholder="filter labels, uuids, names...">'
            f' <button>Filter</button> {pause_button} {status}'
            f"</form>"
        )
        for section in self.sections:
            nodes = [self._render_node(node, query) for node in section["nodes"]]
            body = "".join(node for node in nodes if node)
            parts.append(f"<section><h2>{_esc(section['name'])}</h2><ul>{body}</ul></section>")
        parts.append(
            f'<p class="footer">rendered at {datetime.datetime.now():%H:%M:%S}'
            f" &middot; reloads every 2 s</p>"
            "</main></body></html>"
        )
        return "".join(parts)

    # --- server -------------------------------------------------------------

    def build_app(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/", self._page)
        return app

    async def _page(self, request) -> web.Response:
        query = str(request.query.get("q", "")).lower().strip()
        paused = request.query.get("pause") == "1"
        return web.Response(
            text=self._render_page(query, paused), content_type="text/html"
        )

    async def run(self) -> None:
        self._runner = web.AppRunner(self.build_app())
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", self._port)
        await site.start()

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
