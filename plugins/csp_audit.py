
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
    plugin: str = "csp_audit"

def score_csp(csp: str):
    csp = csp or ""
    d = {}
    for part in csp.split(';'):
        part = part.strip()
        if not part: continue
        if ' ' in part:
            k,v = part.split(' ',1)
            d[k.lower()] = v.strip()
        else:
            d[part.lower()] = ""
    issues = []
    if "default-src" not in d: issues.append("missing default-src")
    if "script-src" in d and ("'unsafe-inline'" in d["script-src"] or "'unsafe-eval'" in d["script-src"]):
        issues.append("script-src allows unsafe-inline/eval")
    if "frame-ancestors" not in d: issues.append("missing frame-ancestors (clickjacking risk)")
    if "object-src" not in d or d.get("object-src","") != "'none'":
        issues.append("object-src not set to 'none'")
    if "base-uri" not in d: issues.append("missing base-uri")
    # naive score
    score = "A"
    if len(issues)>=1: score="B"
    if len(issues)>=2: score="C"
    if len(issues)>=3: score="D"
    if len(issues)>=4: score="E"
    if len(issues)>=5: score="F"
    return score, d, issues

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target
        self.session=session
        self.config=config

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        try:
            async with self.session.get(self.target) as r:
                csp = r.headers.get("Content-Security-Policy")
                if not csp:
                    out.append(Finding("CSP Missing", "No Content-Security-Policy header present", "Medium", {}))
                else:
                    grade, parsed, issues = score_csp(csp)
                    sev = "Info" if grade in ("A","B") else "Medium"
                    out.append(Finding("CSP Audit", f"CSP grade {grade}", sev, {"issues": issues, "parsed": parsed}))
        except Exception:
            pass
        return out
