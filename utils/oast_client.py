
import uuid, aiohttp, asyncio

class OASTClient:
    """
    Interactsh-compatible OAST client with graceful fallback.
    Modes:
      - simple_domain: generate unique subdomain and rely on external polling (no API)
      - interactsh_api: register & poll using server's HTTP API (if provided)
    """
    def __init__(self, server="oast.pro", token=None, use_https=True, mode="simple_domain"):
        self.server = server.strip().rstrip("/")
        self.token = (token or "").strip()
        self.session_id = str(uuid.uuid4()).replace("-", "")[:12]
        self.scheme = "https" if use_https else "http"
        self.mode = mode
        self._api_base = f"{self.scheme}://{self.server}"
        self.base_url = f"{self.scheme}://{self.session_id}.{self.server}"
        self._registered = False
        self._reg_token = None

    def get_payload(self):
        return self.base_url

    async def _register(self, session):
        for path in ("/register", "/v1/register"):
            try:
                async with session.post(f"{self._api_base}{path}", json={"id": self.session_id, "token": self.token}) as r:
                    if r.status in (200,201):
                        try:
                            data = await r.json()
                            self._registered = True
                            self._reg_token = data.get("token") or self.token or ""
                            return True
                        except Exception:
                            return False
            except Exception:
                continue
        return False

    async def _poll(self, session):
        if not self._registered and not await self._register(session):
            return False
        for path in (f"/poll?id={self.session_id}&token={self._reg_token}",
                     f"/v1/poll?id={self.session_id}&token={self._reg_token}",
                     f"/interactions?id={self.session_id}&token={self._reg_token}"):
            try:
                async with session.get(f"{self._api_base}{path}", timeout=aiohttp.ClientTimeout(total=10)) as r:
                    if r.status == 200:
                        txt = await r.text()
                        if txt.strip():
                            return True
            except Exception:
                continue
        return False

    async def check_interactions(self):
        if self.mode != "interactsh_api":
            return False
        async with aiohttp.ClientSession() as session:
            return await self._poll(session)
