
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp, html
CAPS={"passive": False, "active": True, "requires_auth": False, "oast": False, "dangerous": False}
@dataclass
class Finding:
    title: str; description: str; severity: str
    evidence: Dict[str, Any] = field(default_factory=dict); plugin: str = "check_xss_reflected"
class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target; self.session=session; self.config=config
    async def run(self)->List[Finding]:
        out=[]; payload="<xss_probe_123>"; test="%s?q=%s" % (self.target, payload)
        try:
            async with self.session.get(test) as r:
                txt=await r.text()
                if payload in txt:
                    out.append(Finding("Potential Reflected XSS","Echoed payload found in response","High",
                                       {"url": test, "evidence_snippet": "..."+html.escape(payload)+"..."}))
        except Exception:
            pass
        return out
