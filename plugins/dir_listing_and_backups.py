
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp

CAPS={"passive": True, "active": False, "requires_auth": False, "oast": False, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "dir_listing_and_backups"

DIRS=["/","/uploads/","/backup/","/backups/","/logs/","/files/","/assets/","/static/"]
FILES=["/.env","/.git/config","/config.php~","/wp-config.php.bak","/.DS_Store","/server-status","/package.json","/composer.lock"]

def looks_like_listing(text: str)->bool:
    t=text.lower()
    return ("index of /" in t) or ("directory listing for" in t) or ("<title>index of" in t)

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target.rstrip('/'); self.session=session; self.config=config

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        # dirs
        for d in DIRS:
            url=self.target + d
            try:
                async with self.session.get(url) as r:
                    if r.status==200:
                        txt=await r.text()
                        if looks_like_listing(txt):
                            out.append(Finding("Directory Listing Enabled", f"Autoindex likely exposed at {url}", "Medium", {"url":url}))
                            break
            except Exception:
                continue
        # files
        hits=[]
        for f in FILES:
            url=self.target + f
            try:
                async with self.session.get(url) as r:
                    if r.status==200:
                        hits.append(url)
                        if len(hits)>=5: break
            except Exception:
                continue
        if hits:
            out.append(Finding("Exposed Backup/Config Files", "Sensitive files accessible", "High", {"hits":hits}))
        return out
