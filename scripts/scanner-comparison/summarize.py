#!/usr/bin/env python3
"""Summarize the comparison: per set and scanner, attacks blocked and flagged, benign blocked,
and on the corpus every block with our judgment of it.

usage: summarize.py SETS_DIR RESULTS_DIR JUDGMENTS.json OUT.json
  SETS_DIR     output of build_sets.py (labels and corpus index)
  RESULTS_DIR  normalize.py output per set: labelled.json, independent.json, corpus.json
"""
import json, os, sys, collections
sets, res, judg_path, out = sys.argv[1:5]
judgments = json.load(open(judg_path))
summary = {'labelled': {}, 'independent': {}, 'corpus': {}}
detail = {'labelled': {}, 'independent': {}, 'corpus': {}}
cell = lambda v: 'block' if v['block'] else 'flag' if v['warn'] else ('error' if v['status'] == 'error' else '-')
for name in ('labelled', 'independent'):
    labels = json.load(open(os.path.join(sets, f'{name}-labels.json')))
    r = json.load(open(os.path.join(res, f'{name}.json')))
    scanners = sorted({sc for v in r.values() for sc in v})
    for sc in scanners:
        att = [k for k in r if labels[k] == 'attack']; ben = [k for k in r if labels[k] != 'attack']
        summary[name][sc] = {
            'attacks': len(att), 'attacks_blocked': sum(r[k][sc]['block'] for k in att),
            'attacks_flagged': sum(r[k][sc]['block'] or r[k][sc]['warn'] for k in att),
            'others': len(ben), 'others_blocked': sum(r[k][sc]['block'] for k in ben),
            'others_flagged': sum(r[k][sc]['block'] or r[k][sc]['warn'] for k in ben),
        }
    detail[name] = {k: {'label': labels[k], **{sc: cell(r[k][sc]) for sc in scanners}} for k in sorted(r)}
index = json.load(open(os.path.join(sets, 'corpus-index.json')))
r = json.load(open(os.path.join(res, 'corpus.json')))
scanners = sorted({sc for v in r.values() for sc in v})
for sc in scanners:
    blocked = [k for k in r if r[k][sc]['block']]
    verdicts = collections.Counter(judgments.get(index[k], {}).get('verdict', 'unjudged') for k in blocked)
    summary['corpus'][sc] = {'servers': len(r), 'checked': sum(r[k][sc]['status'] != 'error' for k in r),
        'blocked': len(blocked), 'flagged': sum(r[k][sc]['block'] or r[k][sc]['warn'] for k in r), 'blocked_by_judgment': dict(verdicts)}
detail['corpus'] = {index[k]: {sc: cell(r[k][sc]) for sc in scanners} for k in sorted(r) if any(r[k][sc]['block'] for sc in scanners)}
json.dump({'summary': summary, 'detail': detail, 'judgments': judgments}, open(out, 'w'), indent=1, ensure_ascii=False)
for name, by in summary.items():
    print(f'== {name}')
    for sc, v in by.items(): print(f'  {sc:16s} {json.dumps(v, ensure_ascii=False)}')
