
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp
from utils.oast_client import OASTClient
CAPS={"passive": False, "active": True, "requires_auth": False, "oast": True, "dangerous": False}
@dataclass
class Finding:
    title: str; description: str; severity: str
    evidence: Dict[str, Any] = field(default_factory=dict); plugin: str = "check_ssrf_oast"
class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target = target; self.session=session; self.config=config
        o=(config.get("oast") or {})
        mode=o.get("mode","simple_domain")
        self.oast = OASTClient(server=o.get("server","oast.pro"), token=o.get("token"), use_https=o.get("https",True), mode=mode)
    async def run(self) -> List[Finding]:
        out=[]; payload=self.oast.get_payload(); params=['url','redirect','next','src','file']
        for p in params:
            url="%s?%s=%s" % (self.target, p, payload)
            try: await self.session.get(url)
            except Exception: pass
        try:
            if await self.oast.check_interactions():
                out.append(Finding("Confirmed SSRF via OAST","OOB callbacks observed","Critical",{"oast_payload": payload}))
        except Exception: pass
        return out
