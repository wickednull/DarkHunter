
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
    plugin: str = "cookie_flags"

def analyze(set_cookie_values):
    issues=[]
    for sc in set_cookie_values:
        low=sc.lower()
        name = sc.split('=')[0].strip()
        if "secure" not in low:
            issues.append(f"{name}: missing Secure")
        if "httponly" not in low:
            issues.append(f"{name}: missing HttpOnly")
        if "samesite" not in low:
            issues.append(f"{name}: missing SameSite")
        elif "samesite=none" in low and "secure" not in low:
            issues.append(f"{name}: SameSite=None without Secure")
    return issues

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target; self.session=session; self.config=config

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        try:
            async with self.session.get(self.target) as r:
                cookies=r.headers.getall("Set-Cookie", [])
                if cookies:
                    issues=analyze(cookies)
                    if issues:
                        out.append(Finding("Cookie Flag Issues", "Security attributes missing on cookies", "Medium", {"issues":issues}))
        except Exception:
            pass
        return out
