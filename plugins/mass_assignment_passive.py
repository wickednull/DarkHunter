
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp, re, json

CAPS={"passive": True, "active": False, "requires_auth": False, "oast": False, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "mass_assignment_passive"

SENSITIVE = {"role","roles","is_admin","admin","isAdmin","group","groups","scopes","permissions","price","balance","discount","tier","plan","premium","verified","isVerified"}

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target; self.session=session; self.config=config

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        try:
            async with self.session.get(self.target) as r:
                text=await r.text()
                ct=r.headers.get("Content-Type","").lower()
                # HTML form scan
                names = re.findall(r'name=[\'\"]([a-zA-Z0-9_\-]+)[\'\"]', text, flags=re.I)
                hits = sorted(list(SENSITIVE.intersection(set(names))))
                # JSON body scan if response is JSON
                jhits=[]
                if "application/json" in ct:
                    try:
                        data=json.loads(text)
                        if isinstance(data, dict):
                            jhits = sorted(list(SENSITIVE.intersection(set(map(str, data.keys())))))
                    except Exception:
                        pass
                if hits or jhits:
                    out.append(Finding(
                        title="Potential Mass Assignment Risk (Heuristic)",
                        description="Sensitive field names exposed in forms or JSON output",
                        severity="Medium",
                        evidence={"form_fields": hits, "json_fields": jhits}
                    ))
        except Exception:
            pass
        return out
