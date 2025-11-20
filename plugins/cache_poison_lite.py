
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp, random, string

CAPS={"passive": True, "active": True, "requires_auth": False, "oast": False, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "cache_poison_lite"

def _rand(): return ''.join(random.choices(string.ascii_lowercase+string.digits,k=8))

HEADERS = {
    "X-Forwarded-Host": "evil.example",
    "X-Original-URL": "/",
    "X-Forwarded-Proto": "https",
    "X-Forwarded-Port": "1337",
    "X-HTTP-Method-Override": "GET",
}

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target; self.session=session; self.config=config

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        url = self.target + ("&" if "?" in self.target else "?") + "cb=" + _rand()
        try:
            async with self.session.get(url, headers=HEADERS) as r:
                txt=await r.text()
                # Look for reflections in Location or body; check cache headers
                loc = r.headers.get("Location","")
                signs = any(v in txt or v in loc for v in HEADERS.values())
                cachey = any(h in r.headers for h in ["Age","X-Cache","CF-Cache-Status","X-Cache-Status"])
                if signs and cachey:
                    out.append(Finding("Possible Cache Poisoning Vector",
                                       "Unkeyed header(s) reflected with cache involvement",
                                       "Medium",
                                       {"url": url, "reflections": [k for k,v in HEADERS.items() if v in txt or v in loc],
                                        "cache_headers": {k:r.headers.get(k) for k in ["Age","X-Cache","CF-Cache-Status","Vary"]}}))
        except Exception:
            pass
        return out
