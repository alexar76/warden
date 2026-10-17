# write_manifest.py SCRATCH OUT_JSON OUT_FILES_GZ  — the fixed inputs and tools of the 2026-10-16 run
import gzip, hashlib, json, os, re, subprocess, sys, datetime
S, out, out_files = sys.argv[1:4]
def tree(lines):
    sets = {}
    for l in lines:
        h, p = l.split(None, 1); p = p.strip()[2:]
        name = p.split('/', 1)[0] if '/' in p else p.replace('-config.json', '')
        sets.setdefault(name, []).append((p, h))
    return {n: {'files': len(v), 'tree_sha256': hashlib.sha256(''.join(f'{h}  {p}\n' for p, h in sorted(v)).encode()).hexdigest()} for n, v in sorted(sets.items())}
set_lines = [l for l in open(os.path.join(S, 'local-sets.sha')) if l.strip()]
harness = {l.split(None, 1)[1].strip()[2:]: l.split()[0] for l in open(os.path.join(S, 'local-harness.sha')) if l.strip()}
inv = open(os.path.join(S, 'inventory-competitors.txt')).read()
pip = inv.split('PIPFREEZE')[1].split('APK')[0].split()
extra = json.load(open(os.path.join(S, 'manifest-extra.json')))
m = {
  'written': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
  'note': 'Hashes of the exact files the containers read. sets/ is read-only to the container user; '
          'per-file hashes are in manifest-files-2026-10-16.txt.gz.',
  'sets': tree(set_lines),
  'harness': harness,
  'competitor_image_pip_freeze': pip,
  **extra,
}
json.dump(m, open(out, 'w'), indent=1, ensure_ascii=False)
with gzip.open(out_files, 'wt') as g: g.writelines(sorted(set_lines))
print('sets', len(m['sets']), 'files', len(set_lines))
