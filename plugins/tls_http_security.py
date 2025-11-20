
from dataclasses import dataclass, field
from typing import Dict, Any, List
import aiohttp, socket, ssl
from urllib.parse import urlparse

CAPS={"passive": True, "active": False, "requires_auth": False, "oast": False, "dangerous": False}

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    plugin: str = "tls_http_security"

def _get_cert_notAfter(host: str, port: int=443) -> str:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return cert.get("notAfter","")
    except Exception:
        return ""

class Plugin:
    def __init__(self, target: str, session: aiohttp.ClientSession, config: dict):
        self.target=target; self.session=session; self.config=config

    async def run(self)->List[Finding]:
        out: List[Finding] = []
        try:
            async with self.session.get(self.target, allow_redirects=False) as r:
                # HSTS check if HTTPS
                if self.target.startswith("https://"):
                    if "Strict-Transport-Security" not in r.headers:
                        out.append(Finding("HSTS Missing", "Strict-Transport-Security header not set", "Info", {}))
                    # Cert expiry
                    host = urlparse(self.target).hostname or ""
                    na = _get_cert_notAfter(host)
                    if na:
                        out.append(Finding("TLS Certificate", "Certificate expiry (notAfter)", "Info", {"notAfter": na}))
                else:
                    # HTTP -> HTTPS redirect?
                    loc = r.headers.get("Location","")
                    if 300 <= r.status < 400 and loc.startswith("https://"):
                        out.append(Finding("HTTPS Redirect Present", "HTTP redirects to HTTPS", "Info", {"location": loc}))
                    else:
                        out.append(Finding("No HTTPS Redirect", "Plain HTTP did not redirect to HTTPS", "Medium", {}))
        except Exception:
            pass
        return out
