#!/usr/bin/env python3
"""Download the MCPTox dataset (Wang et al., AAAI 2026, arXiv 2508.14925) from where its authors publish it.

usage: fetch_mcptox.py OUTDIR

Fetches pure_tool.json, response_all.json and the 485 def_tool/*.py files from
https://anonymous.4open.science/r/AAAI26-7C02, slowly: the host answers 429 to bursts, so there is a
pause between files and a minute's wait after a 429. Files already present are kept. Nothing is run.
"""
import json, os, sys, time, urllib.error, urllib.request
BASE = 'https://anonymous.4open.science/api/repo/AAAI26-7C02/file/'
out = os.path.abspath(sys.argv[1]); os.makedirs(os.path.join(out, 'def_tool'), exist_ok=True)

def get(path):
    dest = os.path.join(out, path)
    if os.path.exists(dest) and os.path.getsize(dest) > 0: return
    for _ in range(12):
        try:
            data = urllib.request.urlopen(urllib.request.Request(BASE + path, headers={'User-Agent': 'warden-scanner-comparison'}), timeout=60).read()
            open(dest, 'wb').write(data); time.sleep(3); return
        except urllib.error.HTTPError as e:
            time.sleep(60 if e.code == 429 else 10)
        except Exception:
            time.sleep(10)
    raise SystemExit(f'could not fetch {path}')

for f in ('pure_tool.json', 'response_all.json'): get(f)
pure = json.load(open(os.path.join(out, 'pure_tool.json')))
for a in sorted({c['tool_address'] for e in pure for c in e.values()}, key=lambda x: int(x.split('/')[-1][:-3])): get(a)
print('MCPTox in', out)
