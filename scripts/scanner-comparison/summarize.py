#!/usr/bin/env python3
"""Summarize the comparison: per set and scanner, attacks blocked and flagged, benign blocked,
and on the corpus every block with our judgment of it.

usage: summarize.py SETS_DIR RESULTS_DIR JUDGMENTS.json OUT.json [PACKAGES_DIR [JUDGED_SUBSET.json]]
  SETS_DIR      output of build_sets.py (labels and corpus index)
  RESULTS_DIR   normalize.py output per set: labelled.json, independent.json, corpus.json
                (and packages.json when PACKAGES_DIR is given)
  PACKAGES_DIR  output of build_histor_packages.py; its blocks are summarized like the corpus's,
                keyed by the package's endpoint (npm:… / pypi:…)
  JUDGED_SUBSET {"endpoints": [...]}: the packages whose every block was judged; summarized as `sample`
"""
import json, os, sys, collections
sets, res, judg_path, out = sys.argv[1:5]
pkg_dir = sys.argv[5] if len(sys.argv) > 5 else None
subset = set(json.load(open(sys.argv[6]))['endpoints']) if len(sys.argv) > 6 else None
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
def unlabelled(name, index, r):
  scanners = sorted({sc for v in r.values() for sc in v})
  for sc in scanners:
    blocked = [k for k in r if sc in r[k] and r[k][sc]['block']]
    # A judgment with `scanners` was made by reading what those scanners matched; for any other
    # scanner the block stays unjudged. Judgments without it (2026-10-09) read the whole server.
    who = 'warden' if sc.startswith('warden') else sc
    judged = lambda j: j.get('verdict', 'unjudged') if who in j.get('scanners', [who]) else 'unjudged'
    verdicts = collections.Counter(judged(judgments.get(index[k], {})) for k in blocked)
    ran = [k for k in r if sc in r[k]]
    summary[name][sc] = {'servers': len(r), 'ran': len(ran), 'checked': sum(r[k][sc]['status'] != 'error' for k in ran),
        'blocked': len(blocked), 'flagged': sum(r[k][sc]['block'] or r[k][sc]['warn'] for k in ran), 'blocked_by_judgment': dict(verdicts)}
    if name == 'packages' and subset is not None:
      sk = [k for k in r if index[k] in subset]
      summary[name][sc]['sample'] = {'servers': len(sk), 'blocked': sum(r[k][sc]['block'] for k in sk),
        'blocked_by_judgment': dict(collections.Counter(judged(judgments.get(index[k], {})) for k in sk if r[k][sc]['block']))}
  detail[name] = {index[k]: {sc: cell(r[k][sc]) for sc in scanners if sc in r[k]} for k in sorted(r) if any(r[k].get(sc, {}).get('block') for sc in scanners)}
unlabelled('corpus', json.load(open(os.path.join(sets, 'corpus-index.json'))), json.load(open(os.path.join(res, 'corpus.json'))))
if pkg_dir:
  summary['packages'], detail['packages'] = {}, {}
  pidx = json.load(open(os.path.join(pkg_dir, 'packages-index.json')))
  summary['packages_source'] = {'source': pidx['source'], 'listed': pidx['listed'], 'sampled': pidx['sampled']}
  unlabelled('packages', {k: v['endpoint'] for k, v in pidx['servers'].items()}, json.load(open(os.path.join(res, 'packages.json'))))
json.dump({'summary': summary, 'detail': detail, 'judgments': judgments}, open(out, 'w'), indent=1, ensure_ascii=False)
for name, by in summary.items():
    print(f'== {name}')
    if name == 'packages_source': print(f'  {by}'); continue
    for sc, v in by.items(): print(f'  {sc:16s} {json.dumps(v, ensure_ascii=False)}')
