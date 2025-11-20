
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp, asyncio
from urllib.parse import urljoin

CAPS={"passive": True, "active": True, "requires_auth": False, "oast": False, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "websocket_security"

CANDIDATES=["/ws","/websocket","/socket","/socket.io/?EIO=4&transport=websocket"]

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target
        self.session=session
        self.config=config

    async def _try(self, url: str, origin: str)->bool:
        try:
            async with self.session.ws_connect(url, headers={"Origin": origin}, timeout=10) as ws:
                await ws.close()
                return True
        except Exception:
            return False

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        # Infer ws:// or wss:// from target
        scheme = "wss://" if self.target.startswith("https://") else "ws://"
        base = self.target.replace("http://","").replace("https://","").rstrip("/")
        evil = "https://evil.example"
        for p in CANDIDATES:
            wsurl = scheme + base + p
            open_ok = await self._try(wsurl, origin=evil)
            if open_ok:
                out.append(Finding("WebSocket Origin Not Enforced", "Handshake accepted with cross-site Origin", "Medium",
                                   {"url": wsurl, "origin": evil}))
                break
        return out
