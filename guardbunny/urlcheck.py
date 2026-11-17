"""
Strict URL parsing shared by the policy engine and the executor.

Both sides must agree on which host a URL targets. Ad-hoc netloc slicing
disagrees with urllib on URLs that carry userinfo
(``http://allowed.com:x@evil.com/`` looks like ``allowed.com`` to a naive
``netloc.split(":")`` but urllib connects to ``evil.com``). This module
rejects every URL shape where such parser differentials are possible, and
returns one canonical (scheme, host, port) triple.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})
_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}
_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")


class UrlError(ValueError):
    """Raised when a URL is malformed or uses a disallowed shape."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


@dataclass(frozen=True)
class ParsedUrl:
    scheme: str
    host: str  # lowercase hostname or bare IP literal (no brackets)
    port: int  # explicit port, or the scheme default


def parse_url(url: str) -> ParsedUrl:
    """Parse and validate a URL. Raises UrlError on anything ambiguous."""
    if not isinstance(url, str) or not url:
        raise UrlError("URL_INVALID", "http.fetch: URL is empty or not a string.")

    # Control characters, whitespace and backslashes are interpreted
    # differently by different parsers; refuse them outright.
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in url) or "\\" in url:
        raise UrlError(
            "URL_INVALID",
            "http.fetch: URL contains whitespace, control characters or backslashes.",
        )
    if not url.isascii():
        raise UrlError("URL_INVALID", "http.fetch: URL must be ASCII (punycode IDNs).")

    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise UrlError(
            "URL_SCHEME_NOT_ALLOWED",
            f"http.fetch: URL scheme '{scheme or '<empty>'}' is not allowed. "
            "Only http and https are permitted.",
        )

    netloc = parts.netloc
    if "@" in netloc or parts.username is not None or parts.password is not None:
        raise UrlError(
            "URL_USERINFO_NOT_ALLOWED",
            "http.fetch: URLs with embedded credentials (user:pass@host) are not allowed.",
        )
    if "%" in netloc:
        raise UrlError("URL_INVALID", "http.fetch: percent-encoding in the host is not allowed.")

    host = (parts.hostname or "").lower()
    if not host:
        raise UrlError("URL_HOST_MISSING", f"http.fetch: URL '{url}' does not contain a valid host.")

    if netloc.startswith("["):
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            raise UrlError("URL_INVALID", f"http.fetch: invalid IPv6 literal '{host}'.") from None
    elif not _HOSTNAME_RE.match(host):
        raise UrlError("URL_INVALID", f"http.fetch: invalid hostname '{host}'.")

    try:
        port = parts.port
    except ValueError:
        raise UrlError("URL_INVALID", f"http.fetch: invalid port in URL '{url}'.") from None
    if port is None:
        port = _DEFAULT_PORTS[scheme]
    if not 0 < port < 65536:
        raise UrlError("URL_INVALID", f"http.fetch: port {port} out of range.")

    # Cross-check against the parser that will actually open the connection.
    try:
        req_host = urllib.request.Request(url).host
    except ValueError:
        raise UrlError("URL_INVALID", f"http.fetch: urllib rejected URL '{url}'.") from None
    expected = {f"[{host}]" if ":" in host else host}
    expected |= {f"{h}:{port}" for h in set(expected)}
    if (req_host or "").lower() not in expected:
        raise UrlError(
            "URL_PARSER_MISMATCH",
            f"http.fetch: URL host is ambiguous (parsed '{host}', urllib '{req_host}').",
        )

    return ParsedUrl(scheme=scheme, host=host, port=port)
