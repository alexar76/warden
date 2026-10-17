#!/usr/bin/env python3
"""Run mcp-audit (--connect), mcp-shield, truecopy and mcpsentry on each server of a config, one server per run.

usage: run_competitors.py CONFIG OUTDIR [--workers N] [--only mcp-audit|mcp-shield|truecopy|mcpsentry] [--installed]
Each run gets its own one-server config and its own HOME, so cross-server heuristics and
baseline state never leak between servers. Raw outputs are kept for inspection.

truecopy has no command that connects to a server and only scans, so it is run as what it ships
for live servers, its `truecopy-mcp` proxy with no lock: the harness sends initialize and
tools/list through it and keeps its stderr, where every tool it withholds is named with a reason
(`poisoned`, or `unpinned` for every clean tool when there is no lock).

--installed runs the scanners already on PATH instead of fetching them with uvx/npx: that is how
the 2026-10-16 run used them, inside a container image (Dockerfile.competitors) built with exactly
these versions and run with no network.
"""
import json, os, subprocess, sys, tempfile, concurrent.futures as cf, re, time
cfg_path, outdir = sys.argv[1], os.path.abspath(sys.argv[2])
workers = int(sys.argv[sys.argv.index('--workers') + 1]) if '--workers' in sys.argv else 4
only = sys.argv[sys.argv.index('--only') + 1] if '--only' in sys.argv else None
installed = '--installed' in sys.argv
servers = json.load(open(cfg_path))['mcpServers']
os.makedirs(outdir, exist_ok=True)
ANSI = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]')

def run_one(tool, key, entry):
    raw = os.path.join(outdir, tool, key + ('.json' if tool == 'mcp-audit' else '.txt'))
    INIT = '\n'.join(json.dumps(m) for m in ({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'cmp', 'version': '1'}}},
                                         {'jsonrpc': '2.0', 'method': 'notifications/initialized'}, {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'})) + '\n'
    if os.path.exists(raw) and os.path.getsize(raw) > 0: return key, 'cached'
    os.makedirs(os.path.dirname(raw), exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='cmp-') as home:
        cfg = os.path.join(home, 'mcp.json')
        json.dump({'mcpServers': {key: entry}}, open(cfg, 'w'))
        os.chmod(cfg, 0o600)
        env = {'PATH': os.environ['PATH'], 'HOME': home, 'NO_COLOR': '1', 'TERM': 'dumb', 'UV_CACHE_DIR': os.path.expanduser('~/.cache/uv'), 'npm_config_cache': os.path.expanduser('~/.npm'),
               # The pinned package is in the cache after the first run; do not ask the registry each time.
               'npm_config_prefer_offline': 'true', 'UV_OFFLINE': '1'}
        try:
            if tool == 'mcp-audit':
                p = subprocess.run([*(['mcp-audit'] if installed else ['uvx', '--from', 'mcp-audit-scanner[mcp]==0.18.2', 'mcp-audit']), 'scan', cfg, '--connect', '--format', 'json', '-o', raw], env=env, cwd=home, capture_output=True, text=True, timeout=180)
                if not os.path.exists(raw): open(raw, 'w').write(json.dumps({'_error': p.stderr[-2000:], '_code': p.returncode}))
            elif tool == 'mcp-shield':
                p = subprocess.run([*(['mcp-shield'] if installed else ['npx', '--yes', 'mcp-shield@1.0.4']), '--path', cfg], env=env, cwd=home, capture_output=True, text=True, timeout=180)
                open(raw, 'w').write(ANSI.sub('', p.stdout + '\n--STDERR--\n' + p.stderr))
            elif tool == 'mcpsentry':
                p = subprocess.run([*(['mcpsentry'] if installed else ['npx', '--yes', '@roshan6335/mcpsentry@0.1.5']), 'scan', entry['command'], *entry['args']], env=env, cwd=home, capture_output=True, text=True, timeout=180)
                open(raw, 'w').write(ANSI.sub('', p.stdout + f'\n--EXIT {p.returncode}--\n--STDERR--\n' + p.stderr))
            else:
                # The proxy exits when the replayed server does, which is when its stdin closes.
                p = subprocess.run([*(['truecopy-mcp'] if installed else ['npx', '--yes', '-p', '@askalf/truecopy@0.10.4', 'truecopy-mcp']), '--lock', os.path.join(home, 'truecopy.lock'), '--', entry['command'], *entry['args']],
                                   input=INIT, env=env, cwd=home, capture_output=True, text=True, timeout=180)
                open(raw, 'w').write(ANSI.sub('', p.stdout + f'\n--EXIT {p.returncode}--\n--STDERR--\n' + p.stderr))
        except subprocess.TimeoutExpired:
            open(raw, 'w').write(json.dumps({'_error': 'timeout'}) if tool == 'mcp-audit' else 'TIMEOUT')
    return key, 'ran'

tools = [only] if only else ['mcp-audit', 'mcp-shield', 'truecopy', 'mcpsentry']
t0 = time.time()
for tool in tools:
    with cf.ThreadPoolExecutor(workers) as ex:
        futs = [ex.submit(run_one, tool, k, v) for k, v in servers.items()]
        done = 0
        for f in cf.as_completed(futs):
            f.result(); done += 1
            if done % 50 == 0: print(f'{tool}: {done}/{len(servers)} ({time.time()-t0:.0f}s)', flush=True)
    print(f'{tool}: all {len(servers)} done ({time.time()-t0:.0f}s)', flush=True)
