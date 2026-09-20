"""Destination policy for the network sensor.

The network sensor is the only part of this tool that makes an outbound
connection, and it does so to a host supplied over HTTP by whoever is driving
the console. That is a server-side request forgery primitive unless something
stands between the two, and this module is that something.

Three ideas do the work.

**Resolve, vet, then connect to the vetted address.** Checking a hostname and
then handing the *name* to ``socket.create_connection`` leaves a window in
which DNS can answer differently the second time -- the classic rebinding
attack. We resolve once, reject the destination if *any* returned address is
disallowed, and connect to the specific address that passed. The hostname is
still used for SNI and nothing else.

**Deny by property, not by pattern.** A blocklist of literal strings is
defeated by ``0x7f.1``, ``2130706433``, ``[::ffff:127.0.0.1]`` and a dozen
other spellings. ``ipaddress`` normalises all of them, so we ask the parsed
address what it *is* -- loopback, private, link-local, reserved -- rather than
what it looks like.

**A relaxation is recorded, never silent.** Probing a lab network is a
legitimate thing to want. ``CD_ALLOW_PRIVATE_TARGETS`` permits it, and every
finding produced under that relaxation carries a note saying so, because a
report that quietly mixes internet and lab results is worse than one that
refuses.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

# Ports a TLS inspection tool has a legitimate reason to reach. The point is
# not that these are safe -- it is that an endpoint list should not double as
# a port scanner for the host the console runs on.
DEFAULT_ALLOWED_PORTS = frozenset({
    443,    # HTTPS
    8443,   # HTTPS, alternate
    993,    # IMAPS
    995,    # POP3S
    465,    # SMTPS
    587,    # SMTP submission (STARTTLS)
    636,    # LDAPS
    22,     # SSH
    5432,   # PostgreSQL (TLS)
    3306,   # MySQL (TLS)
})

# Scheme -> default port. A scheme we do not know gets no default, which means
# the operator must name the port explicitly.
_SCHEME_PORTS = {
    "https": 443, "http": 80, "imaps": 993, "pop3s": 995,
    "smtps": 465, "ldaps": 636, "ssh": 22, "tls": 443,
}

# Networks denied on top of the property checks below. Some of these are
# already covered by ``is_private`` on current Python versions; listing them
# explicitly means the policy does not silently change with the interpreter.
_DENY_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8",            # "this network"
    "10.0.0.0/8",
    "100.64.0.0/10",        # carrier-grade NAT
    "127.0.0.0/8",
    "169.254.0.0/16",       # link-local, incl. 169.254.169.254 cloud metadata
    "172.16.0.0/12",
    "192.0.0.0/24",         # IETF protocol assignments
    "192.0.2.0/24",         # TEST-NET-1
    "192.168.0.0/16",
    "198.18.0.0/15",        # benchmarking
    "198.51.100.0/24",      # TEST-NET-2
    "203.0.113.0/24",       # TEST-NET-3
    "224.0.0.0/4",          # multicast
    "240.0.0.0/4",          # reserved
    "255.255.255.255/32",
    "::/128",               # unspecified
    "::1/128",              # loopback
    "64:ff9b::/96",         # NAT64 well-known prefix
    "100::/64",             # discard-only
    "2001:db8::/32",        # documentation
    "fc00::/7",             # unique local
    "fe80::/10",            # link-local
    "ff00::/8",             # multicast
))

# The single address most worth naming, so a refusal message can say why.
_METADATA_ADDRESSES = {
    ipaddress.ip_address("169.254.169.254"),   # AWS / Azure / GCP / OpenStack
    ipaddress.ip_address("fd00:ec2::254"),     # AWS IMDSv2 over IPv6
}


class DestinationRefused(ValueError):
    """A destination was rejected by policy. The message is operator-facing."""


@dataclass(frozen=True)
class NetPolicy:
    """What the network sensor is permitted to reach."""

    allowed_ports: frozenset[int] = DEFAULT_ALLOWED_PORTS
    # When non-empty, ONLY these hostnames or literal addresses may be probed.
    # This is the "explicitly authorized destinations" control: an allowlist
    # beats every deny rule below, because it is the operator stating intent.
    allowed_hosts: frozenset[str] = frozenset()
    allow_private: bool = False
    max_endpoints: int = 16
    resolve_timeout: float = 3.0

    @classmethod
    def from_env(cls) -> "NetPolicy":
        ports = os.environ.get("CD_ALLOWED_PORTS", "")
        hosts = os.environ.get("CD_ALLOWED_HOSTS", "")
        return cls(
            allowed_ports=(
                frozenset(int(p) for p in ports.replace(",", " ").split() if p.isdigit())
                or DEFAULT_ALLOWED_PORTS
            ),
            allowed_hosts=frozenset(
                h.strip().lower() for h in hosts.replace(",", " ").split() if h.strip()
            ),
            allow_private=_truthy(os.environ.get("CD_ALLOW_PRIVATE_TARGETS", "")),
            max_endpoints=int(os.environ.get("CD_MAX_ENDPOINTS", 16)),
        )

    def describe(self) -> dict:
        """Policy as data, so a scan can record the rules it ran under."""
        return {
            "allowed_ports": sorted(self.allowed_ports),
            "allowed_hosts": sorted(self.allowed_hosts) or None,
            "allow_private_targets": self.allow_private,
            "max_endpoints": self.max_endpoints,
        }


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Destination:
    """A destination that has passed policy and been resolved to addresses."""

    host: str                      # the name, kept for SNI and for display
    port: int
    addresses: tuple[str, ...]     # vetted literal addresses, in try order
    family: int = socket.AF_UNSPEC
    private_allowed: bool = False  # produced under the relaxation

    @property
    def label(self) -> str:
        return f"[{self.host}]:{self.port}" if ":" in self.host else f"{self.host}:{self.port}"


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

def parse_destination(raw: str) -> tuple[str, int]:
    """Split an operator-supplied destination into (host, port).

    Accepts ``host``, ``host:port``, ``[v6]``, ``[v6]:port`` and
    ``scheme://host[:port][/path]``. A bare IPv6 literal without brackets is
    recognised by its colon count rather than being torn in half by
    ``partition(':')``, which is what the original code did to ``[::1]:443``.
    """
    s = (raw or "").strip()
    if not s:
        raise DestinationRefused("Empty destination.")
    if any(c in s for c in "\r\n\t\x00 "):
        raise DestinationRefused(f"Destination contains whitespace or control characters: {s!r}")

    port: Optional[int] = None

    if "://" in s:
        parts = urlsplit(s)
        if not parts.hostname:
            raise DestinationRefused(f"No host in {s!r}.")
        scheme = (parts.scheme or "").lower()
        host = parts.hostname                      # urlsplit strips [] already
        try:
            port = parts.port                      # raises on a bad port
        except ValueError:
            raise DestinationRefused(f"Invalid port in {s!r}.")
        if port is None:
            port = _SCHEME_PORTS.get(scheme)
            if port is None:
                raise DestinationRefused(
                    f"Scheme {scheme!r} has no default port; name the port explicitly.")
    elif s.startswith("["):
        close = s.find("]")
        if close < 0:
            raise DestinationRefused(f"Unterminated IPv6 literal in {s!r}.")
        host = s[1:close]
        rest = s[close + 1:]
        if rest.startswith(":"):
            port = _port_or_refuse(rest[1:], s)
        elif rest:
            raise DestinationRefused(f"Trailing characters after IPv6 literal in {s!r}.")
    elif s.count(":") > 1:
        # Bare IPv6 literal: 2001:db8::1. No port can be expressed this way.
        host = s
    elif ":" in s:
        host, _, port_s = s.partition(":")
        port = _port_or_refuse(port_s, s)
    else:
        host = s

    host = host.strip().rstrip(".").lower()        # trailing dot is a valid FQDN form
    if not host:
        raise DestinationRefused(f"No host in {raw!r}.")
    if len(host) > 253:
        raise DestinationRefused("Hostname exceeds 253 characters.")

    return host, port if port is not None else 443


def _port_or_refuse(text: str, whole: str) -> int:
    if not text.isdigit():
        raise DestinationRefused(f"Port must be numeric in {whole!r}.")
    port = int(text)
    if not (1 <= port <= 65535):
        raise DestinationRefused(f"Port {port} is outside 1-65535.")
    return port


# --------------------------------------------------------------------------
# Address vetting
# --------------------------------------------------------------------------

def address_refusal(addr: ipaddress._BaseAddress) -> Optional[str]:
    """Why this address must not be probed, or None if it may be.

    Asks the parsed address what it is. Every obfuscated spelling of
    ``127.0.0.1`` -- decimal, octal, IPv4-mapped IPv6, 6to4 -- normalises to
    the same object before it gets here.
    """
    if addr in _METADATA_ADDRESSES:
        return "cloud instance metadata service"

    # Unwrap tunnelled and mapped forms before judging them, otherwise
    # ::ffff:127.0.0.1 reads as an ordinary global IPv6 address.
    for unwrapped in _unwrap(addr):
        if unwrapped is not addr:
            inner = address_refusal(unwrapped)
            if inner:
                return f"{inner} (reached via a mapped or tunnelled address)"

    if addr.is_unspecified:
        return "unspecified address"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_reserved:
        return "reserved"
    if getattr(addr, "is_site_local", False):
        return "site-local"
    if addr.is_private:
        return "private / internal"
    for net in _DENY_NETWORKS:
        if addr.version == net.version and addr in net:
            return f"inside denied range {net}"
    return None


def _unwrap(addr: ipaddress._BaseAddress) -> list[ipaddress._BaseAddress]:
    """Addresses embedded inside this one (IPv4-mapped, 6to4, Teredo)."""
    out: list[ipaddress._BaseAddress] = []
    for attr in ("ipv4_mapped", "sixtofour"):
        inner = getattr(addr, attr, None)
        if inner is not None:
            out.append(inner)
    teredo = getattr(addr, "teredo", None)
    if teredo:
        out.extend(teredo)
    return out


def _resolve(host: str, port: int, timeout: float) -> list[tuple[int, str]]:
    """Resolve to (family, address) pairs, or refuse."""
    previous = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise DestinationRefused(f"{host} does not resolve ({exc.strerror or exc}).")
    except OSError as exc:
        raise DestinationRefused(f"{host} could not be resolved ({exc}).")
    finally:
        socket.setdefaulttimeout(previous)

    seen: list[tuple[int, str]] = []
    for family, _type, _proto, _canon, sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        literal = sockaddr[0]
        if (family, literal) not in seen:
            seen.append((family, literal))
    if not seen:
        raise DestinationRefused(f"{host} resolved to no usable IPv4 or IPv6 address.")
    return seen


def vet(raw: str, policy: Optional[NetPolicy] = None) -> Destination:
    """Turn an operator-supplied destination into one that may be connected to.

    Raises ``DestinationRefused`` with an operator-facing reason otherwise.
    The reason is deliberately specific: a refusal the operator cannot explain
    to their security team is a refusal they will work around.
    """
    policy = policy or NetPolicy.from_env()
    host, port = parse_destination(raw)

    if policy.allowed_hosts and host not in policy.allowed_hosts:
        raise DestinationRefused(
            f"{host} is not in the authorized destination list "
            f"(CD_ALLOWED_HOSTS). Add it there to probe it.")

    if port not in policy.allowed_ports:
        raise DestinationRefused(
            f"Port {port} is not in the allowed set "
            f"{sorted(policy.allowed_ports)}. Set CD_ALLOWED_PORTS to widen it.")

    resolved = _resolve(host, port, policy.resolve_timeout)

    vetted: list[tuple[int, str]] = []
    refusals: list[str] = []
    relaxed = False
    for family, literal in resolved:
        try:
            addr = ipaddress.ip_address(literal)
        except ValueError:
            refusals.append(f"{literal}: not a valid address")
            continue
        reason = address_refusal(addr)
        if reason is None:
            vetted.append((family, literal))
        elif policy.allow_private:
            vetted.append((family, literal))
            relaxed = True
            refusals.append(f"{literal}: {reason} (permitted by CD_ALLOW_PRIVATE_TARGETS)")
        else:
            refusals.append(f"{literal}: {reason}")

    if not vetted:
        raise DestinationRefused(
            f"{host} resolves only to addresses this tool must not probe — "
            + "; ".join(refusals) + ". Set CD_ALLOW_PRIVATE_TARGETS=1 only for a "
            "network you are authorized to test.")

    # One name resolving to both a routable and an internal address is the
    # shape of a rebinding attack, not an ordinary deployment. Refuse the
    # whole destination rather than quietly using the half that passed.
    if len(vetted) < len(resolved) and not policy.allow_private:
        raise DestinationRefused(
            f"{host} resolves to a mix of permitted and denied addresses — "
            + "; ".join(refusals) + ". Refused entirely, because a name that "
            "answers with both is indistinguishable from DNS rebinding.")

    families = {f for f, _ in vetted}
    return Destination(
        host=host,
        port=port,
        addresses=tuple(a for _, a in vetted),
        family=families.pop() if len(families) == 1 else socket.AF_UNSPEC,
        private_allowed=relaxed,
    )


def vet_all(raws: list[str], policy: Optional[NetPolicy] = None
            ) -> tuple[list[Destination], list[dict[str, str]]]:
    """Vet a list of destinations. Returns (accepted, refusals).

    Refusals are returned rather than raised so one bad entry does not discard
    a whole scan, and so the operator is told about every one of them.
    """
    policy = policy or NetPolicy.from_env()
    accepted: list[Destination] = []
    refused: list[dict[str, str]] = []

    cleaned = [r for r in (s.strip() for s in raws) if r]
    if len(cleaned) > policy.max_endpoints:
        for extra in cleaned[policy.max_endpoints:]:
            refused.append({"destination": extra,
                            "reason": f"exceeds the {policy.max_endpoints}-endpoint "
                                      f"limit for a single scan"})
        cleaned = cleaned[:policy.max_endpoints]

    seen: set[tuple[str, int]] = set()
    for raw in cleaned:
        try:
            dest = vet(raw, policy)
        except DestinationRefused as exc:
            refused.append({"destination": raw, "reason": str(exc)})
            continue
        if (dest.host, dest.port) in seen:
            continue
        seen.add((dest.host, dest.port))
        accepted.append(dest)

    return accepted, refused


def connect(dest: Destination, timeout: float) -> socket.socket:
    """Open a TCP connection to a vetted address of ``dest``.

    Connects to the literal address that passed policy, never to the name, so
    the destination cannot change between the check and the connection.
    """
    last: Optional[OSError] = None
    for literal in dest.addresses:
        try:
            addr = ipaddress.ip_address(literal)
        except ValueError:
            continue
        family = socket.AF_INET6 if addr.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((literal, dest.port))
            return sock
        except OSError as exc:
            last = exc
            sock.close()
    raise last or OSError(f"could not connect to {dest.label}")
