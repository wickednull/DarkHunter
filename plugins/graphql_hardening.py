
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp
from urllib.parse import urljoin

CAPS={"passive": True, "active": True, "requires_auth": False, "oast": False, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "graphql_hardening"

CANDIDATES=["/graphql","/v1/graphql"]

BATCH=[{"query":"{__typename}"},{"query":"{__typename}"}]
DEEP='query Deep { a: __typename b: __typename c: __typename d: __typename e: __typename f: __typename g: __typename }'

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target; self.session=session; self.config=config

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        for path in CANDIDATES:
            url=urljoin(self.target, path)
            try:
                # batching test
                async with self.session.post(url, json=BATCH) as r:
                    if r.status in (200, 400):
                        out.append(Finding("GraphQL Batching Allowed", "Endpoint accepted batched queries array", "Info", {"url": url}))
                        break
            except Exception:
                pass
            try:
                async with self.session.post(url, json={"query": DEEP}) as r:
                    if r.status in (200, 400):
                        out.append(Finding("GraphQL Depth/Cost Not Enforced", "Deep alias query accepted (heuristic)", "Info", {"url": url}))
                        break
            except Exception:
                pass
        return out
