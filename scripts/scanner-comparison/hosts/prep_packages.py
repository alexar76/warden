# prep_packages.py PKGALL_DIR WORKDIR  → WORKDIR/sets/{packages-a,packages-b,packages-xhost}[-config.json] + split.json
import hashlib, json, os, shutil, sys
src, work = sys.argv[1:3]
idx = json.load(open(os.path.join(src, 'packages-index.json')))
cfg = json.load(open(os.path.join(src, 'packages-config.json')))['mcpServers']
h = lambda s: int(hashlib.sha256(s.encode()).hexdigest(), 16)
part = {k: ('packages-a' if h(v['id']) % 3 == 0 else 'packages-b') for k, v in idx['servers'].items()}
xhost = sorted(idx['servers'], key=lambda k: hashlib.sha256(('warden cross-host 2026-10-16|' + idx['servers'][k]['id']).encode()).hexdigest())[:100]
sets = {'packages-a': [k for k in sorted(part) if part[k] == 'packages-a'], 'packages-b': [k for k in sorted(part) if part[k] == 'packages-b'], 'packages-xhost': sorted(xhost)}
for name, keys in sets.items():
    d = os.path.join(work, 'sets', name); os.makedirs(d, exist_ok=True); out = {}
    for k in keys:
        shutil.copy(cfg[k]['args'][1], os.path.join(d, k + '.json'))
        out[k] = {'command': 'node', 'args': ['/work/harness/replay.mjs', f'/work/sets/{name}/{k}.json']}
    json.dump({'mcpServers': out}, open(os.path.join(work, 'sets', f'{name}-config.json'), 'w'), indent=1)
    print(name, len(out))
json.dump({'rule': 'packages-a (PingBlip) = int(sha256(target id), 16) % 3 == 0; packages-b (attested) = the rest; '
                   'packages-xhost (both hosts) = the 100 targets with the smallest sha256("warden cross-host 2026-10-16|" + target id)',
           'counts': {n: len(v) for n, v in sets.items()}, 'xhost': {k: idx['servers'][k]['id'] for k in sets['packages-xhost']}},
          open(os.path.join(work, 'split.json'), 'w'), indent=1)
