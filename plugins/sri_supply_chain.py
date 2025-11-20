
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp, re, urllib.parse as up

CAPS={"passive": True, "active": False, "requires_auth": False, "oast": False, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "sri_supply_chain"

SCRIPT_RE = re.compile(r'<script[^>]+src=[\'\"]([^\'\"]+)[\'\"][^>]*>', re.I)
INTEGRITY_RE = re.compile(r'integrity=[\'\"][^\'\"]+[\'\"]', re.I)
CROSSORIGIN_RE = re.compile(r'crossorigin=[\'\"][^\'\"]+[\'\"]', re.I)

def _is_external(url: str, base_host: str)->bool:
    try:
        u=up.urlparse(url)
        return bool(u.netloc) and base_host not in u.netloc
    except Exception:
        return False

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target; self.session=session; self.config=config

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        try:
            async with self.session.get(self.target) as r:
                txt = await r.text()
                base_host = self.target.split("//",1)[-1].split("/",1)[0]
                missing=[]
                for m in SCRIPT_RE.finditer(txt):
                    src=m.group(1)
                    if _is_external(src, base_host):
                        snip=txt[m.start():m.end()]
                        has_int = bool(INTEGRITY_RE.search(snip))
                        if not has_int:
                            missing.append(src)
                if missing:
                    out.append(Finding("External Scripts Without SRI", "External JS lacks integrity= hashes", "Medium",
                                       {"count": len(missing), "examples": missing[:10]}))
        except Exception:
            pass
        return out
