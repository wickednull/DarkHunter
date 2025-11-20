
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp, urllib.parse as up

CAPS={"passive": False, "active": True, "requires_auth": False, "oast": False, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "ssti_probe"

PARAMS = ["q","name","user","search","template","msg","value"]

PAYLOADS = [
    ("{{7*7}}","49"),
    ("${{7*7}}","49"),
    ("${7*7}","49"),
    ("<%=7*7%>","49"),
    ("#{7*7}","49"),
]

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target; self.session=session; self.config=config

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        for p in PARAMS:
            for payload, expect in PAYLOADS:
                q = up.urlencode({p: payload})
                url = self.target + ("&" if "?" in self.target else "?") + q
                try:
                    async with self.session.get(url) as r:
                        txt = await r.text()
                        if expect in txt and payload not in txt:
                            out.append(Finding(
                                title="Server-Side Template Injection (SSTI) indicator",
                                description=f"Expression evaluated for parameter '{p}'",
                                severity="High",
                                evidence={"url":url, "payload":payload, "expect":expect}
                            ))
                            return out
                except Exception:
                    continue
        return out
