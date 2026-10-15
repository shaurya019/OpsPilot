"""fetch_url: fetch a public web page. Guarded against SSRF.

SSRF (Server-Side Request Forgery): the agent runs inside your network, so a
URL like http://169.254.169.254/latest/meta-data/ (cloud credentials),
http://localhost:27017 (your MongoDB) or http://10.0.0.5/admin reaches things
the attacker never could from outside. The model will happily fetch them if a
user or a document asks nicely.

Defenses, in order:
  1. https only, default port, no "user@host" tricks
  2. host must be on the domain allowlist
  3. resolve DNS ourselves and reject private/loopback/link-local IPs
     (stops an allowlisted name that points at 127.0.0.1)
  4. no automatic redirects (a public page could redirect to an internal one)
  5. timeout + size cap

Advanced (not done here): DNS can change between our check and the request
("DNS rebinding"). The full fix is to connect to the exact IP we validated, or
to route all agent traffic through an egress proxy with its own allowlist.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Callable
from urllib.parse import urlparse

import httpx
from pydantic import Field

from .base import StrictArgs, Tool, ToolContext, ToolInputError

Resolver = Callable[[str], list[str]]


def system_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def validate_url(url: str, allowed_domains: list[str], resolver: Resolver = system_resolver) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ToolInputError("Only https:// URLs are allowed")
    if parsed.username or parsed.password or "@" in parsed.netloc:
        raise ToolInputError("Credentials in URLs are not allowed")
    if parsed.port not in (None, 443):
        raise ToolInputError("Non-standard ports are not allowed")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise ToolInputError("URL has no host")
    try:
        ipaddress.ip_address(host)
        raise ToolInputError("Raw IP addresses are not allowed")
    except ValueError:
        pass                                   # good: it's a name, not an IP
    if not any(host == d or host.endswith("." + d) for d in allowed_domains):
        raise ToolInputError(f"Domain {host} is not on the allowlist")
    try:
        addresses = resolver(host)
    except OSError as exc:
        raise ToolInputError(f"Could not resolve {host}") from exc
    for addr in addresses:
        ip = ipaddress.ip_address(addr)
        if not ip.is_global:                   # private, loopback, link-local, reserved...
            raise ToolInputError(f"{host} resolves to a non-public address ({addr})")
    return url


class FetchUrlArgs(StrictArgs):
    url: str = Field(min_length=10, max_length=500)


class FetchUrlTool(Tool):
    name = "fetch_url"
    description = "Fetch a public web page from an approved documentation site and return its text."
    Args = FetchUrlArgs
    trust = "external"

    def __init__(self, resolver: Resolver = system_resolver):
        self.resolver = resolver

    def check(self, args: FetchUrlArgs, ctx: ToolContext) -> None:
        validate_url(args.url, ctx.config(self.name).get("allowed_domains", []), self.resolver)

    def run(self, args: FetchUrlArgs, ctx: ToolContext) -> str:
        cfg = ctx.config(self.name)
        validate_url(args.url, cfg.get("allowed_domains", []), self.resolver)
        max_bytes = cfg.get("max_bytes", 100_000)
        with httpx.Client(follow_redirects=False, timeout=5.0) as client:
            with client.stream("GET", args.url) as resp:
                if resp.is_redirect:
                    raise ToolInputError("Redirects are not followed (they could point to internal hosts)")
                ctype = resp.headers.get("content-type", "")
                if not ctype.startswith(("text/", "application/json")):
                    raise ToolInputError(f"Unsupported content type: {ctype}")
                body = b""
                for chunk in resp.iter_bytes():
                    body += chunk
                    if len(body) > max_bytes:
                        break
        return body[:max_bytes].decode("utf-8", errors="replace")
