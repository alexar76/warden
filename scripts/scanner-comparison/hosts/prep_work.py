# usage: prep_work.py WORKDIR HARNESS_DIR NAME=SRC_CONFIG ...   (copies replay files, rewrites to /work paths)
import json, os, shutil, sys
work, harness = sys.argv[1], sys.argv[2]
os.makedirs(os.path.join(work, 'harness'), exist_ok=True); os.makedirs(os.path.join(work, 'sets'), exist_ok=True); os.makedirs(os.path.join(work, 'raw'), exist_ok=True)
for f in ('replay.mjs', 'run_competitors.py', 'normalize.py'):
    shutil.copy(os.path.join(harness, f), os.path.join(work, 'harness', f))
for arg in sys.argv[3:]:
    name, src = arg.split('=', 1)
    cfg = json.load(open(src))['mcpServers']; d = os.path.join(work, 'sets', name); os.makedirs(d, exist_ok=True); out = {}
    for key, e in cfg.items():
        shutil.copy(e['args'][1], os.path.join(d, key + '.json'))
        out[key] = {'command': 'node', 'args': ['/work/harness/replay.mjs', f'/work/sets/{name}/{key}.json']}
    json.dump({'mcpServers': out}, open(os.path.join(work, 'sets', f'{name}-config.json'), 'w'), indent=1)
    print(name, len(out))
