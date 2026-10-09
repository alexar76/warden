#!/usr/bin/env python3
"""Summarize the MCPTox measurement: per half and scanner, poisoned tools blocked and flagged; clean
servers blocked; and, when a classifier run is given, what rules plus classifier catch.

usage: summarize_mcptox.py SETS_DIR NORMALIZED_DIR [CLASSIFIER_RUN_DIR] OUT.json
  SETS_DIR        output of build_mcptox.py (mcptox-labels.json)
  NORMALIZED_DIR  normalize.py output: mcptox-served.json, mcptox-clean.json, mcptox-decorated.json
  CLASSIFIER_RUN  `scan --classifier-url … --json-file` outputs: mcptox-served.json, mcptox-clean.json
"""
import json, os, sys
args = sys.argv[1:]
sets, norm, out = args[0], args[1], args[-1]
cls_dir = args[2] if len(args) == 4 else None
labels = json.load(open(os.path.join(sets, 'mcptox-labels.json')))
L = labels['served']
served = json.load(open(os.path.join(norm, 'mcptox-served.json')))
clean = json.load(open(os.path.join(norm, 'mcptox-clean.json')))
decorated = json.load(open(os.path.join(norm, 'mcptox-decorated.json')))
scanners = sorted({sc for v in served.values() for sc in v})
summary = {'dataset': {'poisoned_tools': len(L), 'servers': len(labels['split']), 'sha256': labels['sha256'],
                       'split': {h: sorted(s for s, v in labels['split'].items() if v == h) for h in ('dev', 'test')}}, 'scanners': {}}
for sc in scanners:
    row = {}
    for h in ('dev', 'test'):
        ks = [k for k in L if L[k]['split'] == h]
        row[h] = {'tools': len(ks), 'blocked': sum(served[k][sc]['block'] for k in ks), 'flagged': sum(served[k][sc]['block'] or served[k][sc]['warn'] for k in ks)}
    row['by_template_test_blocked'] = {t: f"{sum(served[k][sc]['block'] for k in L if L[k]['split'] == 'test' and L[k]['template'] == t)}/{sum(1 for k in L if L[k]['split'] == 'test' and L[k]['template'] == t)}" for t in ('Template-1', 'Template-2', 'Template-3')}
    ran = [v for v in decorated.values() if sc in v]
    row['decorated_blocked'] = f"{sum(v[sc]['block'] for v in ran)}/{len(decorated)}" if ran else 'not run'
    row['clean_servers_blocked'] = f"{sum(v[sc]['block'] for v in clean.values() if sc in v)}/{len(clean)}"
    summary['scanners'][sc] = row
if cls_dir:
    def load(n): return {s['key']: s for s in json.load(open(os.path.join(cls_dir, n)))['servers']}
    cs, cc = load('mcptox-served.json'), load('mcptox-clean.json')
    sev = lambda s, lv: any(f['code'] == 'TOOL_DEF_CLASSIFIER' and f['severity'] in lv for f in s['findings'])
    # The newest WARDEN build: compare versions numerically ("0.10.0" > "0.8.2", unlike as strings).
    rules = max((sc for sc in scanners if sc.startswith('warden-')), key=lambda sc: tuple(int(x) for x in sc.split('-', 1)[1].split('.')))
    c = {'model': next((s['classifier']['model'] for s in cs.values() if s.get('classifier')), None), 'rules': rules}
    for h in ('dev', 'test'):
        ks = [k for k in L if L[k]['split'] == h]
        c[h] = {'classifier_any': sum(sev(cs[k], ('high', 'medium', 'low')) for k in ks), 'classifier_high': sum(sev(cs[k], ('high',)) for k in ks),
                'rules_or_classifier_high': sum(served[k][rules]['block'] or sev(cs[k], ('high',)) for k in ks),
                'rules_or_classifier_any': sum(served[k][rules]['block'] or sev(cs[k], ('high', 'medium', 'low')) for k in ks)}
    c['clean_servers_flagged'] = {'any': sum(sev(s, ('high', 'medium', 'low')) for s in cc.values()), 'high': sum(sev(s, ('high',)) for s in cc.values()), 'of': len(cc)}
    summary['classifier'] = c
detail = {k: {'server': L[k]['server'], 'split': L[k]['split'], 'template': L[k]['template'], 'risk': L[k]['risk'],
              **{sc: ('block' if served[k][sc]['block'] else 'flag' if served[k][sc]['warn'] else ('error' if served[k][sc]['status'] == 'error' else '-')) for sc in scanners}} for k in sorted(L)}
json.dump({'summary': summary, 'detail': detail}, open(out, 'w'), indent=1, ensure_ascii=False)
print(json.dumps(summary['scanners'], indent=1)); print(json.dumps(summary.get('classifier'), indent=1))
