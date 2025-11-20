
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp, asyncio

CAPS={"passive": False, "active": True, "requires_auth": False, "oast": False, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "upload_security"

ENDPOINTS=["/upload","/api/upload","/file/upload","/image/upload","/uploads"]

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target.rstrip('/'); self.session=session; self.config=config

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        data = aiohttp.FormData()
        data.add_field("file", b"GIF89a", filename="test.php", content_type="image/gif")  # polyglot-ish
        for ep in ENDPOINTS:
            url=self.target+ep
            try:
                async with self.session.post(url, data=data) as r:
                    # suspicious if 200/201 and response reflects filename or returns a URL
                    txt=await r.text()
                    if r.status in (200,201) and ("test.php" in txt or "http" in txt):
                        out.append(Finding(
                            title="Upload Handling Weakness",
                            description=f"Upload endpoint may accept executable extensions or return public URL",
                            severity="High",
                            evidence={"endpoint":url, "status":r.status, "snippet":txt[:200]}
                        ))
                        return out
            except Exception:
                continue
        return out
