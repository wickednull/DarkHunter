
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp, re

CAPS={"passive": True, "active": False, "requires_auth": False, "oast": False, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "tech_fingerprint"

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target; self.session=session; self.config=config

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        try:
            async with self.session.get(self.target) as r:
                txt = await r.text()
                title = ""
                m = re.search(r"<title[^>]*>(.*?)</title>", txt, re.IGNORECASE|re.DOTALL)
                if m: title = re.sub(r"\s+", " ", m.group(1)).strip()
                tech = {"server": r.headers.get("Server",""), "x_powered_by": r.headers.get("X-Powered-By",""), "via": r.headers.get("Via",""), "title": title}
                out.append(Finding("Tech Fingerprint", "Basic server/framework indicators", "Info", tech))
        except Exception:
            pass
        return out
