import json, sys, time, threading, collections, urllib.parse
from concurrent.futures import ThreadPoolExecutor
from mcpclient import list_tools
# defaults are the survey pipeline; august_carryover.py reuses this with its own target file
IN=sys.argv[1] if len(sys.argv)>1 else "registry_remotes.json"
OUT=sys.argv[2] if len(sys.argv)>2 else "tools_raw.jsonl"
rem=json.load(open(IN))
targets=[]
for name,srv in rem.items():
    r=srv["remotes"][0]
    targets.append({"name":name,"url":r["url"],"type":r["type"],
                    "title":srv.get("title"),"description":srv.get("description"),
                    "version":srv.get("version")})
print("targets",len(targets)); sys.stdout.flush()
lock=threading.Lock(); done=[0]
# at most two connections per host, like HISTOR: many registry entries share one SaaS host
host_slots=collections.defaultdict(lambda: threading.BoundedSemaphore(2))
out=open(OUT,"w")
def work(t):
    if t["type"]!="streamable-http":
        res=("skip-sse",None,None)
    else:
        with host_slots[urllib.parse.urlsplit(t["url"]).hostname or ""]:
            res=list_tools(t["url"], timeout=20)
    st,tools,info=res
    rec={**t,"status":st,"server_info":info,"tools":tools,"observed_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())}
    with lock:
        out.write(json.dumps(rec)+"\n"); out.flush()
        done[0]+=1
        if done[0]%100==0: print("done",done[0],flush=True)
with ThreadPoolExecutor(max_workers=14) as ex:
    list(ex.map(work, targets))
out.close(); print("FINISHED", done[0], flush=True)
