#!/bin/sh
# Rerun first-pass timeouts once; keep their original raws in raw-firstpass/SET/.
#   retry_set.sh SET CPUS
# Self-contained so the historical host copy needs no additional helper file.
exec python3 - "$@" <<'PY'
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

W = Path('/opt/warden-cmp/20261016')
TOOLS = frozenset(('mcp-audit', 'mcp-shield', 'truecopy', 'mcpsentry'))


def refuse(message):
    raise ValueError(message)


def cpus_value(value):
    if not re.fullmatch(r'(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)', value) or Decimal(value) <= 0:
        refuse('CPUS must be a positive decimal')
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            refuse('duplicate JSON object key')
        result[key] = value
    return result


def retry_plan(path):
    with path.open() as handle:
        data = json.load(handle, object_pairs_hook=unique_object)
    if not isinstance(data, dict) or not set(data).issubset(TOOLS):
        refuse('retry JSON must map only the four supported scanner names to server lists')
    for keys in data.values():
        if not isinstance(keys, list) or any(
            not isinstance(key, str) or key in ('', '.', '..') or '/' in key or '\\' in key or '\0' in key
            for key in keys
        ):
            refuse('retry server keys must be single file names')
    return data


def stamp(message):
    print(datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), message, flush=True)


# Code is fixed here; the JSON argument is data, never shell source.
DRIVER = '''import json, subprocess, sys
status = 0
for command in json.loads(sys.argv[1]):
    status = subprocess.run(command, check=False).returncode
sys.exit(status)
'''


def main():
    if len(sys.argv) != 3:
        refuse('usage: retry_set.sh SET CPUS')
    name, cpus = sys.argv[1:]
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', name):
        refuse('SET must be a single name using letters, numbers, dots, underscores or hyphens')
    cpus = cpus_value(cpus)
    if (W / 'cpus.cap').is_file():
        cpus = cpus_value((W / 'cpus.cap').read_text().strip())
    flags = ['--rm', '--runtime=runsc', '--network', 'none', '--cpus', cpus]
    if (W / 'cpu.shares').is_file():
        shares = (W / 'cpu.shares').read_text().strip()
        if not re.fullmatch(r'[0-9]+', shares) or not 2 <= int(shares) <= 262144:
            refuse('cpu.shares must be an integer between 2 and 262144')
        flags += ['--cpu-shares', shares]
    plan = retry_plan(W / 'retry' / f'{name}.json')
    firstpass = W / 'raw-firstpass' / name
    if firstpass.exists():
        refuse('already retried this SET')
    # Validate the whole plan before moving any first-pass evidence.
    for tool, keys in plan.items():
        target = firstpass / tool
        target.mkdir(parents=True, exist_ok=True)
        for key in keys:
            for extension in ('.txt', '.json'):
                source = W / 'raw' / name / tool / (key + extension)
                if source.exists():
                    shutil.move(str(source), str(target / source.name))
    commands = [
        ['python3', '/work/harness/run_competitors.py', f'/work/sets/{name}-config.json',
         f'/work/raw/{name}', '--installed', '--only', tool, '--workers', '4']
        for tool in plan
    ]
    flags += ['--memory', '2g', '--memory-swap', '2g', '--pids-limit', '512', '--read-only',
              '--tmpfs', '/tmp:size=512m', '-v', f'{W}:/work', '--name', f'warden-cmp-{name}-retry']
    stamp(f'start retry {name} cpus={cpus}')
    with (W / 'raw' / f'{name}-retry.stdout').open('w') as output:
        result = subprocess.run(['docker', 'run', '-i', *flags, 'warden-cmp:20261016',
                                 'python3', '-', json.dumps(commands)], input=DRIVER, text=True,
                                stdout=output, stderr=subprocess.STDOUT, check=False)
    stamp(f'done retry {name} exit={result.returncode}')
    return result.returncode


try:
    sys.exit(main())
except (ValueError, OSError) as exc:
    print(f'REFUSE retry: {exc}', file=sys.stderr)
    sys.exit(2)
PY
