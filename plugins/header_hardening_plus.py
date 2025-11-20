
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp

CAPS={"passive": True, "active": False, "requires_auth": False, "oast": False, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "header_hardening_plus"

REQUIRED = [
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
    "X-DNS-Prefetch-Control"
]

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target; self.session=session; self.config=config

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        try:
            async with self.session.get(self.target) as r:
                missing=[h for h in REQUIRED if h not in r.headers]
                if missing:
                    out.append(Finding("Modern Header Hardening", "Missing modern security headers", "Info",
                                       {"missing": missing}))
        except Exception:
            pass
        return out
