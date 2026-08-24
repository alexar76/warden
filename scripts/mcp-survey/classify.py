import json, re, collections
src=open("wardenrun/node_modules/@aimarket/warden/dist/static-scan.js").read()
# pull every { re: /.../flags , code: "..." , severity: "...", tier: "..." }
rules=[]
for m in re.finditer(r"re:\s*(/(?:\\.|[^/\\\n])+/[a-z]*)\s*,\s*\n?\s*code:\s*\"([A-Z_]+)\"", src):
    body, flags = m.group(1).rsplit("/",1)
    pat = body[1:]
    seg = src[m.end():m.end()+220]
    sev = (re.search(r'severity:\s*"(\w+)"', seg) or [None,"?"])[1]
    tier= (re.search(r'tier:\s*"(\w+)"', seg) or [None,"?"])[1]
    try: cre=re.compile(pat, re.I if "i" in flags else 0)
    except re.error as e: cre=None
    rules.append({"code":m.group(2),"pat":pat,"sev":sev,"tier":tier,"re":cre})
print("rules extracted:", len(rules), "compiled:", sum(1 for r in rules if r["re"]))
print("by code:", dict(collections.Counter(r["code"] for r in rules)))
json.dump([{k:v for k,v in r.items() if k!="re"} for r in rules], open("rules_v2.json","w"), indent=2)

tools_by={}
for line in open("tools_raw.jsonl"):
    r=json.loads(line)
    if r.get("tools"): tools_by[r["name"]]={t.get("name"):t for t in r["tools"]}
scan=json.load(open("scan_v2.json"))
def surfaces(t):
    return [("description", t.get("description") or ""),
            ("inputSchema", json.dumps(t.get("inputSchema") or {}, ensure_ascii=False)),
            ("name", t.get("name") or "")]
def window(s,a,b,w=90):
    return ("…" if a-w>0 else "")+s[max(0,a-w):min(len(s),b+w)].replace("\n"," ")+("…" if b+w<len(s) else "")
out=[]
for r in scan["rows"]:
    if not r["wouldBlock"]: continue
    for f in r["findings"]:
        if f["advisory"]: continue
        t=tools_by.get(r["server"],{}).get(f.get("tool"))
        if not t: continue
        hit=None
        for rule in rules:
            if rule["code"]!=f["code"] or not rule["re"]: continue
            for surf,s in surfaces(t):
                m=rule["re"].search(s)
                if m:
                    hit={"surface":surf,"matched":m.group(0)[:120],"context":window(s,m.start(),m.end()),"pattern":rule["pat"][:160]}
                    break
            if hit: break
        out.append({"server":r["server"],"tool":f["tool"],"code":f["code"],"severity":f["severity"],
                    "score":r["score"],"toolCount":r["toolCount"],"hit":hit,
                    "message":f["message"]})
json.dump(out,open("classified.json","w"),indent=2,ensure_ascii=False)
resolved=sum(1 for o in out if o["hit"])
print(f"blocking findings: {len(out)}  with exact match: {resolved}  unresolved: {len(out)-resolved}")
print("unresolved codes:", dict(collections.Counter(o["code"] for o in out if not o["hit"])))
