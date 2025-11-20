
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp
from urllib.parse import urljoin
CAPS={"passive": True, "active": False, "requires_auth": False, "oast": False, "dangerous": False}
@dataclass
class Finding:
    title: str; description: str; severity: str
    evidence: Dict[str, Any] = field(default_factory=dict); plugin: str = "check_graphql_detect"
class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target; self.session=session; self.config=config
    async def run(self)->List[Finding]:
        out=[]; candidates=['/graphql','/graphiql','/v1/graphql']
        for path in candidates:
            url=urljoin(self.target, path)
            try:
                async with self.session.post(url, json={"query":"{__typename}"} ) as r:
                    if r.status in (200,400):
                        out.append(Finding("GraphQL Endpoint Detected", "Endpoint responded at %s" % url, "Info",
                                           {"url": url, "status": r.status})); break
            except Exception:
                continue
        return out
