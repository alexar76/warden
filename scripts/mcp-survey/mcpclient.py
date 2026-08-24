import json, urllib.request, urllib.error, ssl
PROTO="2025-06-18"
UA="warden-survey/0.1 (+https://github.com/alexar76/warden)"
CTX=ssl.create_default_context()
def _post(url, body, session=None, timeout=20):
    data=json.dumps(body).encode()
    h={"Content-Type":"application/json","Accept":"application/json, text/event-stream",
       "User-Agent":UA,"MCP-Protocol-Version":PROTO}
    if session: h["Mcp-Session-Id"]=session
    req=urllib.request.Request(url, data=data, headers=h, method="POST")
    r=urllib.request.urlopen(req, timeout=timeout, context=CTX)
    raw=r.read().decode("utf-8","replace")
    return r.status, dict(r.headers), raw
def _parse(raw):
    raw=raw.strip()
    if not raw: return None
    if raw.startswith("{"):
        try: return json.loads(raw)
        except Exception: return None
    out=None
    for line in raw.splitlines():
        if line.startswith("data:"):
            try:
                o=json.loads(line[5:].strip())
                if isinstance(o,dict) and ("result" in o or "error" in o): out=o
            except Exception: pass
    return out
def list_tools(url, timeout=20):
    """Returns (status_str, tools, server_info). Never executes anything."""
    try:
        st,hdrs,raw=_post(url,{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":PROTO,"capabilities":{},
            "clientInfo":{"name":"warden-survey","version":"0.1"}}},timeout=timeout)
    except urllib.error.HTTPError as e:
        return (f"http-{e.code}", None, None)
    except Exception as e:
        return (f"net-{type(e).__name__}", None, None)
    init=_parse(raw)
    if not init or "result" not in init:
        return ("no-init", None, None)
    sid=hdrs.get("Mcp-Session-Id") or hdrs.get("mcp-session-id")
    info=init["result"].get("serverInfo") or {}
    try:
        _post(url,{"jsonrpc":"2.0","method":"notifications/initialized"},session=sid,timeout=timeout)
    except Exception: pass
    try:
        st,h2,raw2=_post(url,{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}},session=sid,timeout=timeout)
    except urllib.error.HTTPError as e:
        return (f"tools-http-{e.code}", None, info)
    except Exception as e:
        return (f"tools-net-{type(e).__name__}", None, info)
    tl=_parse(raw2)
    if not tl or "result" not in tl:
        return ("no-tools-result", None, info)
    return ("ok", tl["result"].get("tools",[]), info)
