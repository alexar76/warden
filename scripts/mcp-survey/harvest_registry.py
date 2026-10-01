import json, urllib.request, urllib.parse, time, sys
# optional page cap; 0 = whole registry. The 2026-08-24 run used a hard 80-page cap and stopped at
# exactly 8000 rows, so that corpus was the first 8000 registry rows, not the whole registry.
MAX_PAGES=int(sys.argv[1]) if len(sys.argv)>1 else 0
UA={"User-Agent":"warden-survey/0.1 (+https://github.com/alexar76/warden)"}
def get(u, tries=4):
    for i in range(tries):   # one slow page used to abort the whole walk
        try: return json.load(urllib.request.urlopen(urllib.request.Request(u, headers=UA), timeout=40))
        except Exception:
            if i==tries-1: raise
            time.sleep(5*(i+1))
cur=None; all_srv=[]; pages=0
while True:
    u="https://registry.modelcontextprotocol.io/v0/servers?limit=100"+(f"&cursor={urllib.parse.quote(cur)}" if cur else "")
    d=get(u); all_srv+=d["servers"]; pages+=1
    cur=d.get("metadata",{}).get("nextCursor")
    if pages%20==0: print("page",pages,"rows",len(all_srv),flush=True)
    if not cur or (MAX_PAGES and pages>=MAX_PAGES): break
    time.sleep(0.15)
truncated=bool(cur)
print("pages",pages,"rows",len(all_srv),"truncated",truncated)
# keep only latest per name
latest={}
for s in all_srv:
    srv=s["server"]; m=s.get("_meta",{}).get("io.modelcontextprotocol.registry/official",{})
    key=srv["name"]
    prev=latest.get(key)
    if prev is None or (m.get("isLatest") and not prev[1].get("isLatest")) or (m.get("publishedAt","") > prev[1].get("publishedAt","")):
        latest[key]=(srv,m)
print("unique servers",len(latest))
rem=[(n,s) for n,(s,m) in latest.items() if s.get("remotes")]
act=[(n,s) for n,(s,m) in latest.items() if m.get("status")=="active"]
print("unique with remotes",len(rem),"active",len(act))
json.dump({n:s for n,(s,m) in latest.items()}, open("registry_latest.json","w"))
json.dump({n:s for n,s in rem}, open("registry_remotes.json","w"))
json.dump({"fetched_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"pages":pages,"rows_fetched":len(all_srv),
           "truncated":truncated,"unique_servers":len(latest),"with_remotes":len(rem)}, open("registry_meta.json","w"), indent=2)
import collections
tr=collections.Counter(r["type"] for n,s in rem for r in s["remotes"])
print("remote types", dict(tr))
