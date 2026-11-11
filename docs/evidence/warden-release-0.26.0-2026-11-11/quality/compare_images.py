"""Which local image is the candidate built FROM, and does its /app (HISTOR code) differ from the running prod image?
Read-only: docker image inspect, and `docker create` + `docker export` of /app trees into a temp dir."""
import hashlib, io, json, subprocess, sys, tarfile

PROD = "sha256:da716f988d4d6d8e19d3e80989fa73a9874c3d8296ddb222a72ec55c46a0f428"
CAND = "sha256:ee4f043c0c572a020d36a697e81becddbe31f8c515512cd45bca93b723f0e6a7"

def sh(*a): return subprocess.check_output(a, text=True)
def layers(i): return json.loads(sh("docker", "image", "inspect", "-f", "{{json .RootFS.Layers}}", i))
cand = layers(CAND)
for line in sh("docker", "images", "--no-trunc", "--format", "{{.ID}} {{.Repository}}:{{.Tag}}").splitlines():
    iid, name = line.split(" ", 1)
    l = layers(iid)
    if iid != CAND and cand[:len(l)] == l:
        print("candidate is built on", iid[7:19], name, f"({len(l)} of {len(cand)} layers)")

def app_tree(image):
    cid = sh("docker", "create", "--network", "none", image).strip()
    try:
        raw = subprocess.run(["docker", "export", cid], capture_output=True, check=True).stdout
    finally:
        subprocess.run(["docker", "rm", "-v", cid], capture_output=True)
    out = {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as t:
        for m in t.getmembers():
            if m.isfile() and (m.name.startswith("app/") or m.name.startswith("opt/venv/lib")) \
                    and "/node_modules/@aimarket/warden/" not in m.name and "__pycache__" not in m.name:
                out[m.name] = hashlib.sha256(t.extractfile(m).read()).hexdigest()
    return out

p, c = app_tree(PROD), app_tree(CAND)
only_p = sorted(set(p) - set(c)); only_c = sorted(set(c) - set(p))
diff = sorted(k for k in set(p) & set(c) if p[k] != c[k])
print("files compared", len(p), len(c), "| only prod", len(only_p), "| only candidate", len(only_c), "| differ", len(diff))
for name, lst in (("only prod", only_p), ("only candidate", only_c), ("differ", diff)):
    for k in lst[:15]:
        print(" ", name, k)
