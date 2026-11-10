#!/bin/sh
# Retry another host's first-pass timeouts into raw/SET-retry/; retain its originals.
#   retry_cross.sh SET CPUS
# Self-contained so the historical host copy needs no additional helper file.
exec python3 - "$@" <<'PY'
import json
import re
import subprocess
import sys
import time
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


def worker_values():
    values = {'AUDIT_W': '6', 'TC_W': '8', 'MS_W': '8', 'SH_W': '32'}
    path = W / 'workers.conf'
    if path.is_file():
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            match = re.fullmatch(r'(AUDIT_W|TC_W|MS_W|SH_W)=([0-9]+)', line)
            if not match or not 1 <= int(match[2]) <= 512:
                refuse('workers.conf must contain supported worker assignments between 1 and 512')
            values[match[1]] = match[2]
    return {'mcp-audit': values['AUDIT_W'], 'truecopy': values['TC_W'],
            'mcpsentry': values['MS_W'], 'mcp-shield': values['SH_W']}


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
        refuse('usage: retry_cross.sh SET CPUS')
    name, cpus = sys.argv[1:]
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', name):
        refuse('SET must be a single name using letters, numbers, dots, underscores or hyphens')
    cpus = cpus_value(cpus)
    while not (W / 'chain.log').is_file() or 'ALL-DONE attested' not in (W / 'chain.log').read_text():
        time.sleep(60)
    retry = W / 'retry' / f'{name}.json'
    while not retry.is_file():
        time.sleep(60)
    # A queued retry can wait hours; use the operator's current caps at launch readiness.
    if (W / 'cpus.cap').is_file():
        cpus = cpus_value((W / 'cpus.cap').read_text().strip())
    flags = ['--rm', '--runtime=runsc', '--network', 'none', '--cpus', cpus]
    if (W / 'cpu.shares').is_file():
        shares = (W / 'cpu.shares').read_text().strip()
        if not re.fullmatch(r'[0-9]+', shares) or not 2 <= int(shares) <= 262144:
            refuse('cpu.shares must be an integer between 2 and 262144')
        flags += ['--cpu-shares', shares]
    workers = worker_values()
    plan = retry_plan(retry)
    with (W / 'sets' / f'{name}-config.json').open() as handle:
        cfg = json.load(handle, object_pairs_hook=unique_object)['mcpServers']
    if not isinstance(cfg, dict) or any(key not in cfg for keys in plan.values() for key in keys):
        refuse('retry plan references a server absent from the SET config')
    out = W / 'raw' / f'{name}-retry'
    if out.exists():
        refuse('cross-retry output already exists')
    out.mkdir(parents=True)
    subprocess.run(['chown', '1000:1000', str(out)], check=True)
    for tool, keys in plan.items():
        with (out / f'{tool}-config.json').open('w') as target:
            json.dump({'mcpServers': {key: cfg[key] for key in keys}}, target, indent=1)
    subprocess.Popen(['setsid', 'nohup', 'sh', str(W / 'hub_watchdog_host2.sh'),
                      f'CROSS-RETRY-DONE {name}'], stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    while True:
        running = subprocess.run(['docker', 'ps', '-a', '--format', '{{.Names}}'],
                                 capture_output=True, text=True, check=True)
        if not any(line.startswith('warden-cmp-') for line in running.stdout.splitlines()):
            break
        time.sleep(30)
    commands = [
        ['python3', '/work/harness/run_competitors.py', f'/work/raw/{name}-retry/{tool}-config.json',
         f'/work/raw/{name}-retry', '--installed', '--only', tool, '--workers', workers[tool]]
        for tool in plan
    ]
    flags += ['--memory', '2g', '--memory-swap', '2g', '--pids-limit', '512', '--read-only',
              '--tmpfs', '/tmp:size=512m', '-v', f'{W}:/work', '--name', f'warden-cmp-{name}-retry']
    stamp(f'start cross-retry {name} cpus={cpus}')
    with Path(str(out) + '.stdout').open('w') as output:
        result = subprocess.run(['docker', 'run', '-i', *flags, 'warden-cmp:20261016',
                                 'python3', '-', json.dumps(commands)], input=DRIVER, text=True,
                                stdout=output, stderr=subprocess.STDOUT, check=False)
    stamp(f'done cross-retry {name} exit={result.returncode}')
    stamp(f'CROSS-RETRY-DONE {name}')
    return result.returncode


try:
    sys.exit(main())
except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as exc:
    print(f'REFUSE cross-retry: {exc}', file=sys.stderr)
    sys.exit(2)
PY
