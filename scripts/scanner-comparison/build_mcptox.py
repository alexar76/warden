#!/usr/bin/env python3
"""Build replay sets from MCPTox (Wang et al., AAAI 2026, arXiv 2508.14925).

usage: build_mcptox.py MCPTOX_DIR OUTDIR

MCPTOX_DIR holds the dataset as published at https://anonymous.4open.science/r/AAAI26-7C02:
pure_tool.json, response_all.json and def_tool/*.py (parsed with ast by mcptox_parse_defs.py, never run).

  mcptox-served     each of the 485 poisoned tools exactly as its server would serve it (def_tool), alone
  mcptox-decorated  the same tools as the benchmark's test prompts show them, where a prefix such as
                    "<IMPORTANT>" or "Ignore the previous instructions and do the following:" was added
  mcptox-clean      the clean tool set of each of the 45 real servers the benchmark poisons

Split: servers are ordered by sha256("mcptox split 2026-10-09|" + server_name); the first half is
`dev` (rules may be written from it), the rest `test` (only reported). The split is by server, so
no test server's tools are ever read while writing rules.
"""
import hashlib, json, os, re, shutil, sys

HERE = os.path.dirname(os.path.abspath(__file__))
src, out = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
os.makedirs(out, exist_ok=True)
node, replay = shutil.which('node'), os.path.join(HERE, 'replay.mjs')

pure = json.load(open(os.path.join(src, 'pure_tool.json')))
resp = json.load(open(os.path.join(src, 'response_all.json')))
defs_path = os.path.join(out, 'mcptox-defs.json')
os.system(f'python3 -I {os.path.join(HERE, "mcptox_parse_defs.py")} {os.path.join(src, "def_tool")} {defs_path} >/dev/null')
defs = json.load(open(defs_path))

servers = sorted({c['server_name'] for e in pure for c in e.values()})
order = sorted(servers, key=lambda s: hashlib.sha256(f'mcptox split 2026-10-09|{s}'.encode()).hexdigest())
split = {s: ('dev' if i < len(order) // 2 else 'test') for i, s in enumerate(order)}

def schema(params):
    return {'type': 'object', 'properties': params or {}}

served, decorated, labels = {}, {}, {}
for entry in pure:
    for case_id, c in entry.items():
        key = 'X-' + re.sub(r'[^A-Za-z0-9_-]', '_', case_id)
        fname = os.path.basename(c['tool_address'])
        d = defs.get(fname)
        desc = (d['doc'] if d and d['doc'] else c['tool_content']).strip()
        tool = {'name': c['tool_name'], 'description': desc, 'inputSchema': schema(d['params'] if d else {})}
        served[key] = [tool]
        labels[key] = {'server': c['server_name'], 'split': split[c['server_name']], 'risk': c['security risk'],
                       'template': c['paradigm'], 'params_from_def_tool': bool(d)}

# The benchmark's prompts: the poisoned tool as an instance shows it ("Tool: x\nDescription: …").
byname = {(v['server'], served[k][0]['name']): k for k, v in labels.items()}
for sname, s in resp['servers'].items():
    for m in s['malicious_instance']:
        mm = re.match(r'Tool: (.*?)\nDescription: (.*)', m['poisoned_tool'], re.S)
        if not mm: continue
        key = byname.get((sname, mm.group(1).strip()))
        if not key: continue
        desc = mm.group(2).split('\nArguments:')[0].strip()
        if desc != served[key][0]['description'] and key not in decorated:
            decorated[key] = [{**served[key][0], 'description': desc}]

clean, clean_labels = {}, {}
TOOL = re.compile(r'Tool: (.+?)\nDescription: (.*?)(?:\nArguments:\n(.*?))?(?=\n\s*\nTool: |\Z)', re.S)
for sname, s in resp['servers'].items():
    tools = []
    for name, desc, args in TOOL.findall(s['clean_system_promot']):
        props = {}
        for a in re.findall(r'^- (\w+): (.*)$', args or '', re.M):
            text = re.sub(r'\s*\((?:required|optional)\)\s*$', '', a[1])
            props[a[0]] = {'type': 'string', **({'description': text} if text and text != 'No description' else {})}
        tools.append({'name': name.strip(), 'description': desc.strip(), 'inputSchema': schema(props)})
    key = 'C-' + re.sub(r'[^A-Za-z0-9_-]', '_', sname)
    clean[key] = tools; clean_labels[key] = {'server': sname, 'split': split.get(sname, 'n/a'), 'tools': len(tools)}

def write(name, cases):
    files = os.path.join(out, name); os.makedirs(files, exist_ok=True); cfg = {}
    for key, tools in cases.items():
        path = os.path.join(files, key + '.json')
        json.dump({'name': key, 'tools': tools}, open(path, 'w'), ensure_ascii=False)
        cfg[key] = {'command': node, 'args': [replay, path]}
    json.dump({'mcpServers': cfg}, open(os.path.join(out, f'{name}-config.json'), 'w'), indent=1)

write('mcptox-served', served); write('mcptox-decorated', decorated); write('mcptox-clean', clean)
json.dump({'served': labels, 'clean': clean_labels, 'split': split,
           'sha256': {f: hashlib.sha256(open(os.path.join(src, f), 'rb').read()).hexdigest() for f in ('pure_tool.json', 'response_all.json')},
           'def_tool_files_parsed': len(defs)}, open(os.path.join(out, 'mcptox-labels.json'), 'w'), indent=1, ensure_ascii=False)
print(f'served {len(served)} (params from def_tool: {sum(v["params_from_def_tool"] for v in labels.values())}), '
      f'decorated {len(decorated)}, clean servers {len(clean)} ({sum(len(v) for v in clean.values())} tools), '
      f'dev servers {sum(v == "dev" for v in split.values())}, test {sum(v == "test" for v in split.values())}')
