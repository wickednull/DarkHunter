
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp, random, string, urllib.parse as up

CAPS={"passive": True, "active": True, "requires_auth": False, "oast": False, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "cors_misconfig"

def _rand_origin():
    s=''.join(random.choices(string.ascii_lowercase+string.digits,k=6))
    return f"https://{s}.evil.example"

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target
        self.session=session
        self.config=config

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        origin=_rand_origin()
        try:
            async with self.session.get(self.target, headers={"Origin":origin}) as r:
                acao=r.headers.get("Access-Control-Allow-Origin","")
                acac=r.headers.get("Access-Control-Allow-Credentials","")
                if acao == "*" and acac.lower()=="true":
                    out.append(Finding("CORS: '*' with credentials", "Wildcard ACAO with credentials is dangerous", "High",
                        {"acao":acao,"acac":acac,"origin_sent":origin}))
                elif acao == origin:
                    out.append(Finding("CORS: Reflected Origin", "Server reflects arbitrary Origin (check credentials, paths)", "Medium",
                        {"acao":acao,"acac":acac,"origin_sent":origin}))
        except Exception:
            pass
        return out
