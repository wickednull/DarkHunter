
import asyncio, aiohttp, time, re, importlib
from utils.har import export_har

STOP_REQUESTED=False
def request_stop():
    global STOP_REQUESTED; STOP_REQUESTED=True

DEFAULT_PLUGIN_CAPS={"passive": False,"active": True,"requires_auth": False,"oast": False,"dangerous": False}
def get_caps(mod): return getattr(mod, "CAPS", DEFAULT_PLUGIN_CAPS)

def _match_scope(url: str, pattern: str) -> bool:
    try:
        if pattern.startswith("regex:/") and pattern.endswith("/"):
            return re.search(pattern[6:-1], url) is not None
        import re as _re
        pat=_re.escape(pattern).replace("\\*",".*")
        return _re.match(pat, url) is not None
    except Exception: return False

def _url_in_scope(url: str, scope: dict) -> bool:
    allow=scope.get("allow") or []; deny=scope.get("deny") or []
    for pat in deny:
        if _match_scope(url, pat): return False
    if allow: return any(_match_scope(url, pat) for pat in allow)
    return True

def _iter_targets(config):
    tgt=(config.get("target") or "").strip()
    targets=[t.strip() for t in (config.get("targets") or []) if t.strip()]
    if tgt: targets.insert(0, tgt)
    out=[]; seen=set()
    for t in targets:
        if t and t not in seen:
            seen.add(t); out.append(t)
    return out

async def throttle(rate_limit:int):
    if rate_limit and rate_limit>0:
        await asyncio.sleep(1.0/max(rate_limit,1))

async def _request_with_retry(session, method, url, *, tries=3, backoff=0.5, **kw):
    last=None
    for i in range(tries):
        try:
            return await session._orig_request(method, url, **kw)
        except Exception as ex:
            last=ex; await asyncio.sleep(backoff*(2**i))
    raise last

async def run_plugin(plugin_class, target, session, config, queue=None, timeout_s=45, max_fail=2):
    name=plugin_class.__module__.split(".")[-1]
    try:
        inst=plugin_class(target, session, config)
    except Exception as e:
        if queue: queue.put(("log", f"❌ {name}: init failed: {e}"))
        return []
    attempts=0
    while attempts<=max_fail:
        try:
            res=await asyncio.wait_for(inst.run(), timeout=timeout_s)
            if queue and res:
                for f in res: queue.put(("finding", f))
            return res or []
        except asyncio.TimeoutError:
            if queue: queue.put(("log", f"⏳ {name}: timed out at {timeout_s}s"))
            attempts+=1
        except Exception as e:
            if queue: queue.put(("log", f"❗ {name}: error {e}"))
            attempts+=1
    if queue: queue.put(("log", f"⚠️ {name}: disabled after {max_fail} failures/timeouts"))
    return []

async def run_scan(config: dict, queue=None):
    global STOP_REQUESTED; STOP_REQUESTED=False
    headers=config.get("headers",{}); scope=config.get("scope",{}) or {}
    plugins_to_run=config.get("plugins_to_run", ["check_headers","check_ssrf_oast","check_xss_reflected","check_graphql_detect"])
    concurrency=int(config.get("concurrency",10)); rate=int(config.get("rate_limit",5)); timeout_s=int(config.get("plugin_timeout",45))
    targets=_iter_targets(config)
    if not targets:
        if queue: queue.put(("log","❗ No targets provided")); return []
    if queue: queue.put(("log", f"🚀 Start scan on {len(targets)} target(s)"))
    clss=[]; caps_map={}
    for name in plugins_to_run:
        try:
            mod=importlib.import_module(f"plugins.{name}")
            clss.append(getattr(mod,"Plugin")); caps_map[name]=get_caps(mod)
        except Exception as e:
            if queue: queue.put(("log", f"⚠️ Unable to load plugin {name}: {e}"))
    har=[]; tc=aiohttp.TraceConfig()
    async def on_start(s, ctx, params):
        ctx.t=time.time(); ctx.url=str(params.url); ctx.m=params.method; ctx.h=dict(params.headers)
    async def on_end(s, ctx, params):
        dt=int((time.time()-getattr(ctx,'t',time.time()))*1000)
        har.append({"startedDateTime": time.strftime("%Y-%m-%dT%H:%M:%S"),"time": dt,
                    "request":{"method":getattr(ctx,'m',''),"url":getattr(ctx,'url',''),"headers":getattr(ctx,'h',{})},"response":{}})
    tc.on_request_start.append(on_start); tc.on_request_end.append(on_end)
    timeout=aiohttp.ClientTimeout(total=None, sock_connect=15, sock_read=30)
    sem=asyncio.Semaphore(concurrency); findings_all=[]
    for ttarget in targets:
        if STOP_REQUESTED: break
        target=ttarget if ttarget.startswith(("http://","https://")) else "https://"+ttarget
        if queue: queue.put(("log", f"➡️ Target: {target}"))
        async with aiohttp.ClientSession(headers=headers, trace_configs=[tc], timeout=timeout) as session:
            session._orig_request=session._request
            async def guarded(method, url, *a, **kw):
                if not _url_in_scope(str(url), scope):
                    if queue: queue.put(("log", f"⛔ Out-of-scope: {url}"))
                    raise aiohttp.ClientError("Out-of-scope")
                return await _request_with_retry(session, method, url, **kw)
            session._request=guarded
            async def one(pcls):
                async with sem:
                    await throttle(rate)
                    return await run_plugin(pcls, target, session, config, queue, timeout_s=timeout_s)
            tasks=[asyncio.create_task(one(c)) for c in clss]; results=[]
            if tasks:
                for r in await asyncio.gather(*tasks):
                    results.extend(r or [])
            findings_all.extend(results)
    if har:
        try:
            p=export_har(har); 
            if queue: queue.put(("log", f"📦 HAR saved: {p}"))
        except Exception as e:
            if queue: queue.put(("log", f"HAR save failed: {e}"))
    if queue: queue.put(("finished", None)); return findings_all
