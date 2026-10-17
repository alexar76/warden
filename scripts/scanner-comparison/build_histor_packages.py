#!/usr/bin/env python3
"""Build the `packages` set: tool lists HISTOR has already observed for npm and PyPI stdio servers.

usage: build_histor_packages.py OUTDIR [--n 1000|all] [--workers 3] [--url https://histor.modelmarket.dev]

Reads HISTOR's public API only (GET /api/v1/servers, GET /api/v1/servers/{id}); it queues nothing
on HISTOR's crawl sandboxes and starts no server. Every package target with a pinned tool set is
listed, a seeded sample of N is drawn (random.Random("warden scanner comparison packages
2026-10-16")) or, with --n all, every one is taken, and each target's last observed tools are
written as a replay file, like the corpus set. Fetched records are cached in OUTDIR/_fetched, so an
interrupted run resumes. The packages are unlabelled: a block here is judged by reading the text,
and the set is a false-positive measurement, not an attack set. packages-index.json records each
target's id, name and toolSetDigest, so the same snapshot can be checked against HISTOR's log later.

On 2026-10-16 the 1000-sample (whose every block was judged by hand) was drawn from the listing of
that morning, 14 933 targets; results/packages-sample-2026-10-16.json names its targets. The full
set was listed in the afternoon (14 936) and taken whole with --n all.
"""
import concurrent.futures as cf, json, os, random, shutil, sys, time, urllib.parse, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
out = os.path.abspath(sys.argv[1]); os.makedirs(out, exist_ok=True)
n = sys.argv[sys.argv.index('--n') + 1] if '--n' in sys.argv else '1000'
workers = int(sys.argv[sys.argv.index('--workers') + 1]) if '--workers' in sys.argv else 3
base = sys.argv[sys.argv.index('--url') + 1] if '--url' in sys.argv else 'https://histor.modelmarket.dev'

def get(path):
    for attempt in range(6):
        try:
            req = urllib.request.Request(base + path, headers={'User-Agent': 'warden-scanner-comparison'})
            return json.load(urllib.request.urlopen(req, timeout=60))
        except Exception:
            time.sleep(5 * (attempt + 1))
    raise SystemExit(f'could not fetch {path}')

targets = {}
for prefix in ('npm:', 'pypi:'):
    offset = 0
    while True:
        page = get(f'/api/v1/servers?q={urllib.parse.quote(prefix)}&state=pinned&limit=200&offset={offset}')
        for s in page['servers']:
            if s['endpoint'].startswith(prefix) and s['transport'] == 'stdio':
                targets[s['id']] = s
        offset += 200
        if offset >= page['total'] or not page['servers']: break
        time.sleep(0.5)
ids = sorted(targets)
sample = ids if n == 'all' else random.Random('warden scanner comparison packages 2026-10-16').sample(ids, min(int(n), len(ids)))

cache = os.path.join(out, '_fetched'); os.makedirs(cache, exist_ok=True)
def fetch(tid):
    path = os.path.join(cache, tid + '.json')
    if not os.path.exists(path):
        d = get(f'/api/v1/servers/{tid}')
        json.dump({'server': d['server'], 'tools': d.get('tools') or []}, open(path + '.part', 'w'), ensure_ascii=False)
        os.replace(path + '.part', path)
    return tid
with cf.ThreadPoolExecutor(workers) as ex:
    for i, _ in enumerate(ex.map(fetch, sorted(sample)), 1):
        if i % 500 == 0: print(f'fetched {i}/{len(sample)}', flush=True)

files = os.path.join(out, 'packages'); os.makedirs(files, exist_ok=True)
node, replay = shutil.which('node'), os.path.join(HERE, 'replay.mjs')
cfg, index = {}, {}
for i, tid in enumerate(sorted(sample), 1):
    d = json.load(open(os.path.join(cache, tid + '.json')))
    tools = d['tools']
    if not tools: continue
    key = f'p{i:05d}'
    path = os.path.join(files, key + '.json')
    json.dump({'name': key, 'tools': tools}, open(path, 'w'), ensure_ascii=False)
    cfg[key] = {'command': node, 'args': [replay, path]}
    index[key] = {'id': tid, 'name': d['server']['name'], 'endpoint': d['server']['endpoint'],
                  'packageVersion': d['server'].get('packageVersion'), 'toolSetDigest': d['server'].get('toolSetDigest'), 'tools': len(tools)}
json.dump({'mcpServers': cfg}, open(os.path.join(out, 'packages-config.json'), 'w'), indent=1)
json.dump({'source': base, 'listed': len(ids), 'sampled': len(sample), 'servers': index},
          open(os.path.join(out, 'packages-index.json'), 'w'), indent=1, ensure_ascii=False)
print(f'package targets pinned: {len(ids)}; taken {len(sample)}; with tools: {len(index)} '
      f'(npm {sum(v["endpoint"].startswith("npm:") for v in index.values())}, pypi {sum(v["endpoint"].startswith("pypi:") for v in index.values())})')
