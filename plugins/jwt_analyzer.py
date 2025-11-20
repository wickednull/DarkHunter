
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
import aiohttp, base64, json

CAPS={"passive": True, "active": False, "requires_auth": False, "oast": False, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "jwt_analyzer"

def _b64url_decode(s: str)->bytes:
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode())

def _parse_jwt(token: str)->Optional[Dict[str,Any]]:
    parts = token.split(".")
    if len(parts)!=3: return None
    try:
        header=json.loads(_b64url_decode(parts[0]))
        payload=json.loads(_b64url_decode(parts[1]))
        return {"header":header, "payload":payload, "signature_len":len(parts[2])}
    except Exception:
        return None

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target; self.session=session; self.config=config

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        try:
            async with self.session.get(self.target) as r:
                # Look in Set-Cookie and Authorization echo (rare)
                cookies = r.headers.getall("Set-Cookie", [])
                auth = r.headers.get("Authorization", "")
                tokens = []
                for c in cookies:
                    if "." in c and c.count(".")>=2:
                        t=c.split("=",1)[-1].split(";")[0].strip()
                        if t.count(".")==2: tokens.append(t)
                if auth.startswith("Bearer ") and auth.count(".")==2:
                    tokens.append(auth.split(" ",1)[1])
                for t in tokens[:3]:
                    parsed=_parse_jwt(t)
                    if not parsed: continue
                    issues=[]
                    alg=str(parsed["header"].get("alg","")).lower()
                    if alg=="none": issues.append("alg=none")
                    if "exp" not in parsed["payload"]: issues.append("missing exp")
                    if "aud" not in parsed["payload"]: issues.append("missing aud")
                    if "kid" in parsed["header"] and any(x in str(parsed["header"]["kid"]) for x in ["../","..\\",":","/etc/"]):
                        issues.append("suspicious kid header")
                    if issues:
                        out.append(Finding("JWT Weaknesses", "JWT token shows weak/missing claims/headers", "Medium",
                                          {"issues":issues, "header":parsed["header"], "payload":parsed["payload"]}))
                        break
        except Exception:
            pass
        return out
