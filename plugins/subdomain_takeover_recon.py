
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp, asyncio, re
from urllib.parse import urlparse

CAPS={"passive": True, "active": True, "requires_auth": False, "oast": False, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "subdomain_takeover_recon"

CANDIDATES=["","www","blog","shop","dev","staging","test","beta","old","cdn","static","assets","images","files","docs","help","status","api"]

# Fingerprint substrings (lowercased) commonly seen when a subdomain is dangling / unclaimed
FINGERPRINTS={
    "github_pages": ["there isn\'t a github pages site here", "github pages 404"],
    "aws_s3": ["nosuchbucket", "the specified bucket does not exist", "code: nosuchbucket"],
    "azure": ["404 web site not configured", "this web app has been stopped", "azurewebsites.net"],
    "heroku": ["no such app", "heroku | no such app"],
    "fastly": ["fastly error: unknown domain", "fastly_error"],
    "netlify": ["page not found", "not found - netlify"],
    "readmeio": ["project doesn\'t exist... yet", "there\'s nothing here, yet"],
    "cname_dangling": ["unrecognized domain", "domain is not configured", "no such site at"],
    "cloudfront": ["bad request", "cloudfront"],
}

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target; self.session=session; self.config=config

    async def _fetch(self, url: str):
        try:
            async with self.session.get(url, allow_redirects=True, timeout=8) as r:
                txt=await r.text()
                return r.status, txt.lower(), dict(r.headers)
        except Exception:
            return None, "", {}

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        host=urlparse(self.target).hostname or ""
        if not host or host.count(".")<1:
            return out
        parts=host.split(".")
        root=".".join(parts[-2:]) if len(parts)>=2 else host

        probes=[]
        for sub in CANDIDATES:
            h = f"{sub}.{root}" if sub else root
            scheme = "https" if self.target.startswith("https://") else "http"
            probes.append(f"{scheme}://{h}/")
        # Also try opposite scheme for resilience
        alt_scheme = "http" if self.target.startswith("https://") else "https"
        for sub in ["","www","blog","dev","staging","api"]:
            h = f"{sub}.{root}" if sub else root
            probes.append(f"{alt_scheme}://{h}/")

        # dedupe
        probes=list(dict.fromkeys(probes))

        for u in probes[:30]:
            status, body, headers = await self._fetch(u)
            if status is None:
                continue
            hit = None
            for k, sigs in FINGERPRINTS.items():
                if any(s in body for s in sigs):
                    hit = k; break
            if hit:
                out.append(Finding(
                    title="Subdomain Takeover Fingerprint",
                    description=f"Potentially unclaimed subdomain content at {u} ({hit})",
                    severity="High",
                    evidence={"url":u, "status":status, "provider":hit}
                ))
                # don't spam; one strong signal is enough
                break
        return out
