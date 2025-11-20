
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp, json

CAPS={"passive": False, "active": True, "requires_auth": False, "oast": False, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "proto_pollution_probe"

TARGETS=["/","/api","/api/update","/set","/config"]

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target; self.session=session; self.config=config

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        body = {"__proto__":{"polluted":"yes"}}
        for ep in TARGETS:
            url = self.target.rstrip('/') + ep
            try:
                async with self.session.post(url, json=body) as r:
                    try:
                        js = await r.json()
                    except Exception:
                        js = None
                    if isinstance(js, dict) and "polluted" in str(js):
                        out.append(Finding("Prototype Pollution Indicator", "Server echoes polluted keys", "High",
                                           {"url":url, "response": str(js)[:300]}))
                        return out
            except Exception:
                continue
        return out
