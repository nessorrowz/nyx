"""Target and request validation.

Two jobs:

  - keep the scope gate honest by refusing anything that is not a plausible
    IP / CIDR / hostname / URL. A target is handed to `nmap` as an argv entry,
    so a leading `-` would be read as a flag (option injection) rather than a
    host, and whitespace could smuggle a second operand;
  - normalise a URL down to the host the pipeline can actually scan. The result
    store is host-centric (Asset is keyed by IP), so `https://10.0.0.5:8443/app`
    becomes `10.0.0.5`. Ports come from discovery, not from the target string.

Every rejection raises ValueError with an operator-facing message; the API maps
that to a 400.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

# A /16 is already 65k hosts. Anything wider is almost certainly a typo and
# would pin a worker for hours, so widen this deliberately rather than by
# accident.
MAX_CIDR_HOSTS = 65_536

_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})*\.?$")


def normalize_target(raw: str) -> str:
    """Validate a scan target and return it in a form the tools can consume."""
    target = (raw or "").strip()
    if not target:
        raise ValueError("Target is required.")
    if any(ch.isspace() for ch in target):
        raise ValueError("Target must not contain whitespace.")
    if target.startswith("-"):
        raise ValueError("Target must not start with '-'.")
    if "://" in target:
        return _from_url(target)
    if "/" in target:
        return _network(target)
    return _host(target)


def _from_url(target: str) -> str:
    parts = urlsplit(target)
    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parts.hostname:
        raise ValueError("URL has no host.")
    return _host(parts.hostname)


def _network(target: str) -> str:
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        raise ValueError("Not a valid IP address or CIDR range.") from None
    if net.num_addresses > MAX_CIDR_HOSTS:
        raise ValueError(
            f"Range too large ({net.num_addresses} addresses, limit "
            f"{MAX_CIDR_HOSTS}). Scan a smaller range."
        )
    return str(net)


def _host(target: str) -> str:
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass
    if not _HOSTNAME.match(target):
        raise ValueError("Not a valid IP address, CIDR range, hostname, or URL.")
    return target


def parse_allowlist(raw: str | None) -> list[str]:
    """Split a RECON_SCOPE string into entries. Empty/None -> no allowlist."""
    if not raw:
        return []
    return [e.strip() for e in raw.replace("\n", ",").split(",") if e.strip()]


def enforce_scope(target: str, allowlist: list[str]) -> None:
    """Hard scope gate: reject a (already-normalized) target not inside the
    approved set. An empty allowlist allows everything (the checkbox gate still
    applies); a non-empty one is deny-by-default.

    An allowlist entry is either a CIDR/IP (an IP or CIDR target must sit inside
    it) or a domain (a hostname target must equal it or be a subdomain). IP and
    domain targets are matched only against entries of the same kind.
    """
    if not allowlist:
        return

    tgt_net = _as_network(target)
    for entry in allowlist:
        entry_net = _as_network(entry)
        if tgt_net is not None and entry_net is not None:
            if (tgt_net.version == entry_net.version
                    and tgt_net.subnet_of(entry_net)):
                return
        elif tgt_net is None and entry_net is None:
            t, e = target.rstrip(".").lower(), entry.lstrip(".").rstrip(".").lower()
            if t == e or t.endswith("." + e):
                return

    raise ValueError(
        f"Target '{target}' is not within the approved scope allowlist."
    )


def _as_network(value: str):
    """An IP or CIDR as an ip_network; None if it is a hostname/domain."""
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
