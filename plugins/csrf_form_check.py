
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp, re

CAPS={"passive": True, "active": False, "requires_auth": False, "oast": False, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "csrf_form_check"

CSRF_NAMES = ["csrf","xsrf","_token","authenticity_token","__requestverificationtoken"]

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target; self.session=session; self.config=config

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        try:
            async with self.session.get(self.target) as r:
                html = await r.text()
        except Exception:
            return out
        forms = re.findall(r"<form[^>]*method=[\'\"]?post[^>]*>(.*?)</form>", html, flags=re.I|re.S)
        suspicious=[]
        for form in forms[:10]:
            # build regex without f-string to avoid quoting pitfalls
            tokens_present = any(re.search(r'name=[\'\"]%s[\'\"]' % re.escape(n), form, re.I) for n in CSRF_NAMES)
            if not tokens_present:
                inputs = re.findall(r"<input[^>]*>", form, flags=re.I)
                if inputs:
                    suspicious.append(form[:120])
        if suspicious:
            out.append(Finding("Potential Missing CSRF Tokens", "POST forms detected without typical anti-CSRF fields", "Medium",
                               {"samples": suspicious}))
        return out
