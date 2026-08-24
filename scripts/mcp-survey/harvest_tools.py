import json, sys, time, threading
from concurrent.futures import ThreadPoolExecutor
from mcpclient import list_tools
rem=json.load(open("registry_remotes.json"))
targets=[]
for name,srv in rem.items():
    r=srv["remotes"][0]
    targets.append({"name":name,"url":r["url"],"type":r["type"],
                    "title":srv.get("title"),"description":srv.get("description"),
                    "version":srv.get("version")})
print("targets",len(targets)); sys.stdout.flush()
lock=threading.Lock(); done=[0]
out=open("tools_raw.jsonl","w")
def work(t):
    if t["type"]!="streamable-http":
        res=("skip-sse",None,None)
    else:
        res=list_tools(t["url"], timeout=20)
    st,tools,info=res
    rec={**t,"status":st,"server_info":info,"tools":tools}
    with lock:
        out.write(json.dumps(rec)+"\n"); out.flush()
        done[0]+=1
        if done[0]%100==0: print("done",done[0],flush=True)
with ThreadPoolExecutor(max_workers=14) as ex:
    list(ex.map(work, targets))
out.close(); print("FINISHED", done[0], flush=True)
