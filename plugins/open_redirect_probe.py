
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
    plugin: str = "open_redirect_probe"

PARAMS=["url","redirect","next","return","dest","destination","continue","r","u"]

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target; self.session=session; self.config=config

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        test="https://evil.example/"
        for p in PARAMS:
            q = up.urlencode({p: test})
            url = self.target + ("&" if "?" in self.target else "?") + q
            try:
                async with self.session.get(url, allow_redirects=False) as r:
                    loc=r.headers.get("Location","")
                    if 300 <= r.status < 400 and loc and loc.startswith("http") and "evil.example" in loc:
                        out.append(Finding("Possible Open Redirect", f"Parameter '{p}' appears to redirect externally", "Medium",
                                          {"url":url, "location":loc, "status":r.status}))
                        break
            except Exception:
                continue
        return out
