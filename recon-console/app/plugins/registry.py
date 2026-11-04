"""Registry: the single place that knows every plugin.

Powers the Tool Management screen (availability) and decides which plugins a
given scan runs. To add a tool, import it and add it to PLUGINS.
"""
from __future__ import annotations

from .base import Plugin
from .nmap_plugin import NmapPlugin
from .httpx_plugin import HttpxPlugin
from .wafw00f_plugin import Wafw00fPlugin
from .testssl_plugin import TestsslPlugin

PLUGINS: list[Plugin] = [
    NmapPlugin(),
    HttpxPlugin(),
    Wafw00fPlugin(),
    TestsslPlugin(),
]

BY_NAME = {p.name: p for p in PLUGINS}

# Which plugins each full-assessment profile runs, in order. nmap always leads
# so later plugins have services to dispatch on.
PROFILE_PIPELINE = {
    "discovery": ["nmap"],
    "standard":  ["nmap", "httpx", "wafw00f", "testssl.sh"],
    "extended":  ["nmap", "httpx", "wafw00f", "testssl.sh"],
}


def catalog() -> list[dict]:
    """Tool Management view: every plugin and whether its binary is present."""
    return [
        {
            "name": p.name,
            "description": p.description,
            "binary": p.binary,
            "available": p.is_available(),
        }
        for p in PLUGINS
    ]


def select(scan_mode: str, profile: str, modules: list[str]) -> list[Plugin]:
    """Resolve a scan request to an ordered list of plugin instances."""
    if scan_mode == "full":
        names = PROFILE_PIPELINE.get(profile, PROFILE_PIPELINE["standard"])
    else:  # single | custom -> whatever the user ticked
        names = modules
    # Preserve catalog order (nmap first) regardless of selection order.
    ordered = [p.name for p in PLUGINS]
    chosen = [n for n in ordered if n in set(names)]
    return [BY_NAME[n] for n in chosen if n in BY_NAME]
