"""Shared web-service heuristics.

httpx and wafw00f both dispatch on "is this a web port?". Keeping the port/name
sets and the endpoint-list builder in one place means a new web port is added
once, not per plugin.
"""
from __future__ import annotations

from .base import PluginContext

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090}
WEB_NAMES = {"http", "https", "http-alt", "http-proxy"}


def web_endpoints(ctx: PluginContext) -> list[str]:
    """scheme://ip:port for every discovered web service in the context."""
    urls = []
    for asset in ctx.assets:
        for s in asset.services:
            if s.port in WEB_PORTS or s.name in WEB_NAMES:
                scheme = "https" if s.port in (443, 8443) or "https" in s.name else "http"
                urls.append(f"{scheme}://{asset.ip}:{s.port}")
    return urls
