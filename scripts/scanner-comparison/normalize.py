#!/usr/bin/env python3
"""Normalize WARDEN / mcp-audit / mcp-shield / truecopy / mcpsentry outputs to {server: {scanner: {status, block, warn, codes}}}.

block = the scanner's own high-or-worse verdict on the tool definitions; warn = any finding about
the tool definitions at all. Config-level findings caused by the replay harness (absolute node path,
/tmp paths, file permissions, first-scan baselines) are excluded for every scanner.
usage: normalize.py RAWDIR OUT.json   (RAWDIR holds warden-*.json, mcp-audit/*.json, mcp-shield/*.txt,
                                       truecopy/*.txt, mcpsentry/*.txt)
"""
import json, os, re, sys, glob
raw, out = sys.argv[1], sys.argv[2]
res = {}
def put(server, scanner, **v): res.setdefault(server, {})[scanner] = v

# One file per WARDEN build: warden-<version>.json, from `scan --json-file` or warden_gates.mjs.
for wp in sorted(glob.glob(os.path.join(raw, 'warden*.json'))):
    name = os.path.basename(wp)[:-5]
    for s in json.load(open(wp))['servers']:
        codes = sorted({f['code'] for f in s['findings'] if f['code'] != 'TOOL_DEF_UNPINNED'})
        blocking = sorted({f['code'] for f in s['findings'] if not f.get('advisory') and f['code'] != 'TOOL_DEF_UNPINNED'})
        put(s['key'], name, status=s['status'], block=s['allow'] is False, warn=bool(codes), codes=codes, blocking=blocking)

DESC = {'poisoning', 'toxic_flow'}
for p in glob.glob(os.path.join(raw, 'mcp-audit', '*.json')):
    key = os.path.basename(p)[:-5]; d = json.load(open(p))
    if '_error' in d: put(key, 'mcp-audit', status='error', block=False, warn=False, codes=[]); continue
    f = [x for x in d.get('findings', []) if x['analyzer'] in DESC]
    connect_errors = [e for e in d.get('errors', []) if 'connect' in json.dumps(e).lower()]
    put(key, 'mcp-audit', status='error' if connect_errors else 'scanned', block=any(x['severity'] in ('HIGH', 'CRITICAL') for x in f), warn=bool(f),
        codes=sorted({f"{x['id']}:{x['severity']}" for x in f}))

# mcp-shield prints a live tree (redrawn in place) and then, when anything was found, a
# "Vulnerabilities Detected" list of `N. Server / Tool / Risk Level / Issues`. The tree's header
# scrolls away on servers with many tools, so the verdict is read from the list, and a run counts
# as completed when the tree shows a final state (✓ or ✗) for its tools.
ENTRY = re.compile(r'^\s*\d+\. Server: .*\n\s*Tool: (.*)\n\s*Risk Level: (\w+)\n\s*Issues:\n((?:\s*– .*\n?)*)', re.M)
for p in glob.glob(os.path.join(raw, 'mcp-shield', '*.txt')):
    key = os.path.basename(p)[:-4]; text = open(p).read().split('--STDERR--')[0]
    if text.startswith('TIMEOUT') or not re.search(r'[✓✗] \S', text):
        put(key, 'mcp-shield', status='error', block=False, warn=False, codes=[]); continue
    entries = ENTRY.findall(text)
    levels = [lvl.upper() for _, lvl, _ in entries]
    issues = sorted({m for _, _, block in entries for m in re.findall(r'– ([^:\n]+):', block)})
    put(key, 'mcp-shield', status='scanned', block=any(l in ('HIGH', 'CRITICAL') for l in levels), warn=bool(entries), codes=issues)

# truecopy-mcp withholds every tool without a lock; the reason it names is the verdict. It has one
# tier for tool definitions (any finding withholds the tool as `poisoned`), so block and flag agree.
for p in glob.glob(os.path.join(raw, 'truecopy', '*.txt')):
    key = os.path.basename(p)[:-4]; out_, _, err = open(p).read().partition('--STDERR--')
    if '"id":2,"result"' not in out_.replace(' ', ''):
        put(key, 'truecopy', status='error', block=False, warn=False, codes=[]); continue
    poisoned = sorted(set(re.findall(r'^\[truecopy\] dropped (.+) \(poisoned\)$', err, re.M)))
    put(key, 'truecopy', status='scanned', block=bool(poisoned), warn=bool(poisoned), codes=['poisoned'] if poisoned else [])

# mcpsentry prints one `SEVERITY  MCP-00N  tool` line per finding; high and critical are its blocking tiers.
FINDING = re.compile(r'^\s*(CRITICAL|HIGH|MEDIUM|LOW)\s+(MCP-\d+)\s+\S', re.M)
for p in glob.glob(os.path.join(raw, 'mcpsentry', '*.txt')):
    key = os.path.basename(p)[:-4]; text = open(p).read().split('--STDERR--')[0]
    if 'tool(s) discovered' not in text:
        put(key, 'mcpsentry', status='error', block=False, warn=False, codes=[]); continue
    f = FINDING.findall(text)
    put(key, 'mcpsentry', status='scanned', block=any(sev in ('CRITICAL', 'HIGH') for sev, _ in f), warn=bool(f), codes=sorted({f'{r}:{sev}' for sev, r in f}))
json.dump(res, open(out, 'w'), indent=1, ensure_ascii=False)
print('servers', len(res))
