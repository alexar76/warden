#!/usr/bin/env python3
"""Assemble the 2026-10-16 two-host run into one normalized result per set, with provenance.

usage: assemble_hosts.py FINAL_DIR OUT_DIR

FINAL_DIR/<host>/raw/ holds each host's raw outputs as copied back from /opt/warden-cmp/20261016/raw
(host = attested | pingblip). For every set it runs normalize.py on the competitor raws plus that
set's WARDEN report, then writes OUT_DIR/<set>.json (the shape normalize.py writes, which
summarize.py reads) and OUT_DIR/provenance.json:

  where   which host computed which set
  retried every (set, scanner, server) whose first pass ended in a harness error (a timeout) and was
          run once more in a fresh container: on the same host (retry_set.sh, first-pass files kept
          in raw-firstpass/) or on the other host (retry_cross.sh, output in raw/<set>-retry/)
  errors  what is still an error after the retry: a scanner that could not check a server

A retried server keeps the retry's verdict; nothing else is merged.
"""
import json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
final, out = sys.argv[1:3]
os.makedirs(out, exist_ok=True)
TOOLS = ('mcp-audit', 'mcp-shield', 'truecopy', 'mcpsentry')
WHERE = {'labelled': 'attested', 'independent': 'attested', 'corpus': 'attested', 'mcptox-served': 'attested',
         'mcptox-decorated': 'attested', 'mcptox-clean': 'attested', 'packages-a': 'pingblip', 'packages-b': 'attested'}

def normalize(raw_set_dir, warden_json):
    with tempfile.TemporaryDirectory() as d:
        for t in TOOLS:
            if os.path.isdir(os.path.join(raw_set_dir, t)): os.symlink(os.path.abspath(os.path.join(raw_set_dir, t)), os.path.join(d, t))
        if warden_json and os.path.exists(warden_json): os.symlink(os.path.abspath(warden_json), os.path.join(d, 'warden-0.16.0.json'))
        subprocess.run(['python3', os.path.join(HERE, 'normalize.py'), d, os.path.join(d, 'n.json')], check=True, capture_output=True)
        return json.load(open(os.path.join(d, 'n.json')))

prov = {'where': WHERE | {'packages-xhost': 'both (cross-host check)'}, 'retried': {}, 'errors': {}}
for s, host in WHERE.items():
    raw = os.path.join(final, host, 'raw')
    r = normalize(os.path.join(raw, s), os.path.join(raw, s + '-warden', 'warden-0.16.0.json'))
    fp = os.path.join(final, host, 'raw-firstpass', s)
    if os.path.isdir(fp):   # retried on the same host; the retry's files are already in raw/<set>/
        for t in os.listdir(fp):
            prov['retried'].setdefault(s, {})[t] = {'on': host, 'servers': sorted(f.rsplit('.', 1)[0] for f in os.listdir(os.path.join(fp, t)))}
    other = 'attested' if host == 'pingblip' else 'pingblip'
    xr = os.path.join(final, other, 'raw', s + '-retry')
    if os.path.isdir(xr):   # retried on the other host
        rr = normalize(xr, None)
        for k, v in rr.items():
            for t, cell in v.items():
                r[k][t] = cell
                prov['retried'].setdefault(s, {}).setdefault(t, {'on': other, 'servers': []})['servers'].append(k)
    for t in TOOLS + ('warden-0.16.0',):
        e = sorted(k for k, v in r.items() if t in v and v[t]['status'] == 'error')
        if e: prov['errors'].setdefault(s, {})[t] = e
    json.dump(r, open(os.path.join(out, s + '.json'), 'w'), ensure_ascii=False)
    print(s, host, len(r), {t: len(v['servers']) for t, v in prov['retried'].get(s, {}).items()}, {t: len(v) for t, v in prov['errors'].get(s, {}).items()})
a, b = (json.load(open(os.path.join(out, f'packages-{h}.json'))) for h in 'ab')
json.dump({**a, **b}, open(os.path.join(out, 'packages.json'), 'w'), ensure_ascii=False)
for h in ('attested', 'pingblip'):
    json.dump(normalize(os.path.join(final, h, 'raw', 'packages-xhost'), os.path.join(final, h, 'raw', 'packages-xhost-warden', 'warden-0.16.0.json')),
              open(os.path.join(out, f'packages-xhost-{h}.json'), 'w'), ensure_ascii=False)
json.dump(prov, open(os.path.join(out, 'provenance.json'), 'w'), indent=1)
