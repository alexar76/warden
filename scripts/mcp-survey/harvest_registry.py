import json, urllib.request, urllib.parse, time, sys
UA={"User-Agent":"warden-survey/0.1 (+https://github.com/alexar76/warden)"}
def get(u):
    return json.load(urllib.request.urlopen(urllib.request.Request(u, headers=UA), timeout=40))
cur=None; all_srv=[]; pages=0
while True:
    u="https://registry.modelcontextprotocol.io/v0/servers?limit=100"+(f"&cursor={urllib.parse.quote(cur)}" if cur else "")
    d=get(u); all_srv+=d["servers"]; pages+=1
    cur=d.get("metadata",{}).get("nextCursor")
    if not cur or pages>=80: break
    time.sleep(0.15)
print("pages",pages,"rows",len(all_srv))
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
import collections
tr=collections.Counter(r["type"] for n,s in rem for r in s["remotes"])
print("remote types", dict(tr))
