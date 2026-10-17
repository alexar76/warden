# compare.py A.json B.json [label]  — per-server, per-scanner cell diff between two normalized results
import json, sys
a, b = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
cell = lambda v: 'block' if v['block'] else 'flag' if v['warn'] else ('error' if v['status'] == 'error' else '-')
scs = sorted({sc for v in a.values() for sc in v} & {sc for v in b.values() for sc in v})
for sc in scs:
    d = [(k, cell(a[k][sc]), cell(b[k][sc])) for k in sorted(set(a) & set(b)) if sc in a[k] and sc in b[k] and cell(a[k][sc]) != cell(b[k][sc])]
    codes = sum(1 for k in set(a) & set(b) if sc in a[k] and sc in b[k] and a[k][sc].get('codes') != b[k][sc].get('codes'))
    n = sum(1 for k in set(a) & set(b) if sc in a[k] and sc in b[k])
    print(f'{sc:15s} compared {n:5d}  verdict diffs {len(d):4d}  code diffs {codes:4d}', d[:6])
