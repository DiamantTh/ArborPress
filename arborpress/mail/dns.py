"""SMTP DNS diagnostics with deliberately explicit DNSSEC trust semantics.

This module does not implement a recursive validator. ``trusted_ad`` is only
accepted when an operator explicitly trusts the configured recursive resolver's
AD bit; otherwise DNSSEC evidence remains indeterminate.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from typing import Any

import dns.asyncresolver
import dns.flags


@dataclass(frozen=True, slots=True)
class DNSAnswer:
    record_type: str
    values: tuple[str, ...]
    dnssec: str
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class SMTPDNSResolver:
    """Bounded DNS query facade; no ECS and no implicit trust in AD."""

    def __init__(
        self,
        *,
        nameservers: list[str] | None = None,
        dnssec_policy: str = "own_validation",
        timeout: float = 3.0,
    ) -> None:
        if dnssec_policy not in {"own_validation", "trusted_ad"}:
            raise ValueError("Unknown DNSSEC policy.")
        self.resolver = dns.asyncresolver.Resolver(configure=True)
        if nameservers:
            self.resolver.nameservers = nameservers
        self.resolver.use_edns(edns=0, ednsflags=dns.flags.DO)
        self.resolver.lifetime = timeout
        self.dnssec_policy = dnssec_policy

    async def query(self, name: str, record_type: str) -> DNSAnswer:
        kind = record_type.upper()
        if kind not in {"A", "AAAA", "MX", "TLSA", "CAA"}:
            raise ValueError("Unsupported DNS record type.")
        try:
            response = await self.resolver.resolve(name, kind, raise_on_no_answer=False)
            rrset = response.rrset
            values = tuple(str(item) for item in rrset) if rrset is not None else ()
            if self.dnssec_policy == "trusted_ad":
                status = "secure" if response.response.flags & dns.flags.AD else "insecure"
            else:
                # A DO query is useful evidence collection, not validation.
                status = "indeterminate"
            return DNSAnswer(kind, values, status, None if values else "no_answer")
        except dns.resolver.NXDOMAIN:
            return DNSAnswer(kind, (), "insecure", "nxdomain")
        except dns.resolver.NoNameservers:
            return DNSAnswer(kind, (), "indeterminate", "no_nameservers")
        except dns.exception.Timeout, OSError:
            return DNSAnswer(kind, (), "indeterminate", "resolver_unavailable")
        except Exception as exc:
            return DNSAnswer(kind, (), "indeterminate", type(exc).__name__.lower()[:64])

    async def smtp_diagnostics(self, hostname: str, port: int = 25) -> dict[str, Any]:
        host = hostname.rstrip(".")
        answers = await asyncio.gather(
            self.query(host, "A"),
            self.query(host, "AAAA"),
            self.query(host, "MX"),
            self.query(f"_{port}._tcp.{host}", "TLSA"),
            self.query(host, "CAA"),
        )
        a, aaaa, mx, tlsa, caa = answers
        return {
            "a": a.as_dict(),
            "aaaa": aaaa.as_dict(),
            "mx": mx.as_dict(),
            "tlsa": tlsa.as_dict(),
            "dane_authenticated_records": tlsa.dnssec == "secure" and bool(tlsa.values),
            "dane_certificate_match": "not_checked",
            "dane_mode": "report_only",
            "caa": caa.as_dict(),
            "note": "SMTP connects to the configured relay; recipient-domain MX is not used.",
        }
