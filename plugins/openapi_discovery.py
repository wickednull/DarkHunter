
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp, json
from urllib.parse import urljoin

CAPS={"passive": True, "active": False, "requires_auth": False, "oast": False, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "openapi_discovery"

CANDIDATES=["/openapi.json","/swagger.json","/swagger/v1/swagger.json","/v3/api-docs","/v2/api-docs","/api-docs"]

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target; self.session=session; self.config=config

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        for path in CANDIDATES:
            url=urljoin(self.target, path)
            try:
                async with self.session.get(url) as r:
                    if r.status==200:
                        try:
                            data=await r.json()
                        except Exception:
                            txt=await r.text()
                            try:
                                data=json.loads(txt)
                            except Exception:
                                continue
                        paths=data.get("paths") if isinstance(data, dict) else None
                        cnt=len(paths) if isinstance(paths, dict) else 0
                        out.append(Finding("OpenAPI/Swagger Discovered", f"Found spec at {url}", "Info", {"url":url,"paths":cnt}))
                        break
            except Exception:
                continue
        return out
