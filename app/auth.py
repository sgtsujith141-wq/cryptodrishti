"""Access control for the HTTP surface.

The tool's honest default is a single operator on their own machine, and for
that case a login screen is friction with no security value: the console is
bound to loopback and anything that can reach it can already read the files it
would scan.

The moment the bind address is *not* loopback, that reasoning stops holding.
The API can then enumerate directories, read file contents into
``evidence.snippet`` and open outbound connections on behalf of whoever asks.
So:

* Bound to loopback, no token set -- open, as before.
* Token set -- every ``/api`` route requires it, whatever the bind address.
* Bound to anything else with no token -- the server **refuses to start**.

That last one is the important line. A tool that silently becomes remotely
exploitable because someone set ``CD_HOST=0.0.0.0`` to demo it on a projector
is the failure mode worth engineering against.

The console is a static page with no login, so a token supplied once as
``?token=`` on the index is stored in a strict same-site cookie and the API
accepts either that or a bearer header. This is deliberately modest: it is an
access control for a single-operator tool, not a user system.
"""

from __future__ import annotations

import hmac
import ipaddress
import os
import secrets
from typing import Optional

COOKIE_NAME = "cd_token"
HEADER_NAME = "X-CD-Token"

# Routes reachable without a token even when one is configured. The index is
# how a token gets exchanged for a cookie; static assets carry no data.
_OPEN_PREFIXES = ("/static/", "/favicon.ico", "/healthz")


def configured_token() -> Optional[str]:
    token = os.environ.get("CD_TOKEN", "").strip()
    return token or None


def is_loopback(host: str) -> bool:
    """Whether a bind address only accepts connections from this machine."""
    h = (host or "").strip().lower()
    if h in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


class InsecureBinding(RuntimeError):
    """Raised when the server would be exposed without an access control."""


def check_binding(host: str) -> None:
    """Refuse a non-loopback bind with no token. Called before the server starts."""
    if is_loopback(host) or configured_token():
        return
    raise InsecureBinding(
        f"Refusing to bind {host}: this exposes directory browsing, file content "
        f"in scan evidence and outbound probing to the network with no access "
        f"control.\n"
        f"  Either bind loopback (the default, CD_HOST=127.0.0.1)\n"
        f"  or set an access token:  export CD_TOKEN=$(python -c "
        f"'import secrets;print(secrets.token_urlsafe(32))')\n"
        f"Then open the console once as  http://{host}:PORT/?token=$CD_TOKEN"
    )


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def token_matches(supplied: Optional[str]) -> bool:
    """Constant-time comparison against the configured token."""
    expected = configured_token()
    if expected is None:
        return True
    if not supplied:
        return False
    return hmac.compare_digest(supplied, expected)


def path_is_open(path: str) -> bool:
    return any(path.startswith(p) for p in _OPEN_PREFIXES)


def token_from_request(headers, cookies, query) -> Optional[str]:
    """Pull a token from the bearer header, the custom header, or the cookie."""
    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    header = headers.get(HEADER_NAME.lower()) or headers.get(HEADER_NAME)
    if header:
        return header.strip()
    cookie = cookies.get(COOKIE_NAME)
    if cookie:
        return cookie
    q = query.get("token")
    return q.strip() if q else None
