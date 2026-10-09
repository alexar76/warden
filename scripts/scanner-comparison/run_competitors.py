#!/usr/bin/env python3
"""Run mcp-audit (--connect) and mcp-shield on each server of a config, one server per run.

usage: run_competitors.py CONFIG OUTDIR [--workers N] [--only mcp-audit|mcp-shield]
Each run gets its own one-server config and its own HOME, so cross-server heuristics and
baseline state never leak between servers. Raw outputs are kept for inspection.
"""
import json, os, subprocess, sys, tempfile, concurrent.futures as cf, re, time
cfg_path, outdir = sys.argv[1], os.path.abspath(sys.argv[2])
workers = int(sys.argv[sys.argv.index('--workers') + 1]) if '--workers' in sys.argv else 4
only = sys.argv[sys.argv.index('--only') + 1] if '--only' in sys.argv else None
servers = json.load(open(cfg_path))['mcpServers']
os.makedirs(outdir, exist_ok=True)
ANSI = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]')

def run_one(tool, key, entry):
    raw = os.path.join(outdir, tool, key + ('.json' if tool == 'mcp-audit' else '.txt'))
    if os.path.exists(raw) and os.path.getsize(raw) > 0: return key, 'cached'
    os.makedirs(os.path.dirname(raw), exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='cmp-') as home:
        cfg = os.path.join(home, 'mcp.json')
        json.dump({'mcpServers': {key: entry}}, open(cfg, 'w'))
        os.chmod(cfg, 0o600)
        env = {'PATH': os.environ['PATH'], 'HOME': home, 'NO_COLOR': '1', 'TERM': 'dumb', 'UV_CACHE_DIR': os.path.expanduser('~/.cache/uv'), 'npm_config_cache': os.path.expanduser('~/.npm')}
        try:
            if tool == 'mcp-audit':
                p = subprocess.run(['uvx', '--from', 'mcp-audit-scanner[mcp]==0.18.2', 'mcp-audit', 'scan', cfg, '--connect', '--format', 'json', '-o', raw], env=env, cwd=home, capture_output=True, text=True, timeout=180)
                if not os.path.exists(raw): open(raw, 'w').write(json.dumps({'_error': p.stderr[-2000:], '_code': p.returncode}))
            else:
                p = subprocess.run(['npx', '--yes', 'mcp-shield@1.0.4', '--path', cfg], env=env, cwd=home, capture_output=True, text=True, timeout=180)
                open(raw, 'w').write(ANSI.sub('', p.stdout + '\n--STDERR--\n' + p.stderr))
        except subprocess.TimeoutExpired:
            open(raw, 'w').write(json.dumps({'_error': 'timeout'}) if tool == 'mcp-audit' else 'TIMEOUT')
    return key, 'ran'

tools = [only] if only else ['mcp-audit', 'mcp-shield']
t0 = time.time()
for tool in tools:
    with cf.ThreadPoolExecutor(workers) as ex:
        futs = [ex.submit(run_one, tool, k, v) for k, v in servers.items()]
        done = 0
        for f in cf.as_completed(futs):
            f.result(); done += 1
            if done % 50 == 0: print(f'{tool}: {done}/{len(servers)} ({time.time()-t0:.0f}s)', flush=True)
    print(f'{tool}: all {len(servers)} done ({time.time()-t0:.0f}s)', flush=True)
