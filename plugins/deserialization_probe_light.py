
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp

CAPS={"passive": False, "active": True, "requires_auth": False, "oast": False, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "deserialization_probe_light"

ENDPOINTS=["/","/api","/serialize","/process","/upload"]

JAVA_MAGIC=bytes.fromhex("aced0005")  # triggers StreamCorruptedException if deserialized
YAML_SAMPLE=b"---\nfoo: bar\n"

TOKENS=[
    "streamcorruptedexception", "invalidclassexception", "readobject",
    "org.yaml.snakeyaml", "yaml.parse", "com.fasterxml.jackson",
    "php warning: unserialize", "notice: unserialize()",
    "marshal.load", "pickle", "dotnet", "binaryformatter"
]

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target.rstrip('/'); self.session=session; self.config=config

    async def _try(self, path: str)->str:
        url=self.target+path
        # try Java serialization hint
        try:
            async with self.session.post(url, data=JAVA_MAGIC, headers={"Content-Type":"application/x-java-serialized-object"}) as r:
                return (await r.text())[:800].lower()
        except Exception:
            pass
        # try YAML innocuous
        try:
            async with self.session.post(url, data=YAML_SAMPLE, headers={"Content-Type":"application/x-yaml"}) as r:
                return (await r.text())[:800].lower()
        except Exception:
            return ""

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        for ep in ENDPOINTS:
            body = await self._try(ep)
            if not body:
                continue
            if any(t in body for t in TOKENS):
                out.append(Finding(
                    title="Deserialization Stacktrace Indicator",
                    description="Endpoint emitted errors consistent with deserialization routines",
                    severity="Medium",
                    evidence={"endpoint": self.target+ep, "snippet": body[:180]}
                ))
                break
        return out
