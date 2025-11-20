
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp
CAPS={"passive": True, "active": False, "requires_auth": False, "oast": False, "dangerous": False}
@dataclass
class Finding:
    title: str; description: str; severity: str
    evidence: Dict[str, Any] = field(default_factory=dict); plugin: str = "check_headers"
class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target = target; self.session=session; self.config=config
    async def run(self) -> List[Finding]:
        out=[]
        try:
            async with self.session.get(self.target) as r:
                required=['Strict-Transport-Security','Content-Security-Policy','X-Content-Type-Options','X-Frame-Options']
                missing=[h for h in required if h not in r.headers]
                if missing:
                    out.append(Finding("Missing Security Headers", "Missing: " + ", ".join(missing), "Medium",
                                       {"url": self.target, "status": r.status, "missing": missing}))
        except Exception:
            pass
        return out
