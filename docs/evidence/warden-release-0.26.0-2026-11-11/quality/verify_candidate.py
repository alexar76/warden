"""Candidate vs running prod image: every file of the two filesystems, and the WARDEN build digest as MOMUS and
check-quality-gate.mjs compute it (sha256 over sorted dist/*.js: name NUL content NUL). Read-only."""
import hashlib, io, json, subprocess, sys, tarfile
PROD = "sha256:da716f988d4d6d8e19d3e80989fa73a9874c3d8296ddb222a72ec55c46a0f428"
CAND = sys.argv[1]
def export(image):
    cid = subprocess.check_output(["docker", "create", "--network", "none", image], text=True).strip()
    try:
        raw = subprocess.run(["docker", "export", cid], capture_output=True, check=True).stdout
    finally:
        subprocess.run(["docker", "rm", "-v", cid], capture_output=True)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as t:
        for m in t.getmembers():
            if m.isfile():
                files[m.name] = t.extractfile(m).read()
    return files
p, c = export(PROD), export(CAND)
W = ("app/scanner/node_modules/@aimarket/warden/", "opt/warden-source/src/")
def outside(names): return sorted(n for n in names if not n.startswith(W))
only_p, only_c = outside(set(p) - set(c)), outside(set(c) - set(p))
differ = outside(k for k in set(p) & set(c) if p[k] != c[k])
print("files prod", len(p), "candidate", len(c))
print("outside WARDEN: only prod", only_p[:10], "only candidate", only_c[:10], "differ", differ[:10])
h = hashlib.sha256()
dist = sorted(n for n in c if n.startswith(W[0] + "dist/") and n.count("/") == 6 and n.endswith(".js"))
for n in dist:
    h.update(n.rsplit("/", 1)[1].encode() + b"\0" + c[n] + b"\0")
pkg = json.loads(c[W[0] + "package.json"])
print("candidate warden", pkg["version"], "dist js", len(dist), "buildDigest", h.hexdigest())
print("source files", sum(1 for n in c if n.startswith(W[1])))
