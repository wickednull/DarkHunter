
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp, re

CAPS={"passive": False, "active": True, "requires_auth": False, "oast": False, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "idor_access_control"

PARAMS = ["id","uid","user_id","account_id","order_id","project_id"]

def _pick_base_ids(html: str)->List[str]:
    # Pull some numeric IDs from HTML to seed neighbor tests
    nums = re.findall(r"(?:id|user|acct|order|project)[-_]?(\d{2,7})", html, flags=re.I)
    # also any bare numbers of length 4-7
    nums += re.findall(r"(?<![a-zA-Z])(\d{4,7})(?![a-zA-Z])", html)
    out=[]
    for n in nums[:5]:
        try:
            int(n); out.append(n)
        except: pass
    return list(dict.fromkeys(out))  # unique preserve order

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target.rstrip("?")
        self.session=session
        self.config=config

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        # Baseline page
        try:
            async with self.session.get(self.target) as r:
                base = await r.text()
        except Exception:
            return out

        seeds = _pick_base_ids(base) or ["1001","2001"]
        for s in seeds:
            try_ids=[str(int(s)-1), s, str(int(s)+1)]
            for p in PARAMS:
                for tid in try_ids:
                    sep="&" if "?" in self.target else "?"
                    url=f"{self.target}{sep}{p}={tid}"
                    try:
                        async with self.session.get(url) as r:
                            txt=await r.text()
                            # if response differs significantly from baseline and status is 200 -> interesting
                            if r.status==200 and len(txt)!=len(base) and (abs(len(txt)-len(base))>150 or s in base):
                                out.append(Finding(
                                    title="Possible IDOR / Access-Control Gap",
                                    description=f"Varying object access via parameter '{p}' using id {tid}",
                                    severity="High",
                                    evidence={"url":url, "hint":"manual review recommended"}
                                ))
                                return out
                    except Exception:
                        continue
        return out
