
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
    plugin: str = "business_logic_boundary"

PARAMS=["qty","quantity","amount","price","total","discount","coupon","credits"]
VALUES=["0","-1","9999999","NaN","Infinity","1e309","0x10"]

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target; self.session=session; self.config=config

    async def _get_len(self, url: str)->int:
        try:
            async with self.session.get(url) as r:
                return len(await r.text())
        except Exception:
            return -1

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        base_len = await self._get_len(self.target + ("&" if "?" in self.target else "?") + "_=blb")
        if base_len < 0:
            return out
        for p in PARAMS:
            for v in VALUES:
                q=up.urlencode({p:v})
                url=self.target + ("&" if "?" in self.target else "?") + q
                l = await self._get_len(url)
                if l > 0 and abs(l - base_len) > 400:
                    out.append(Finding(
                        title="Potential Business-Logic Boundary Issue",
                        description=f"Large response delta when '{p}={v}'",
                        severity="Info",
                        evidence={"url":url, "base_len":base_len, "len":l}
                    ))
                    return out
        return out
