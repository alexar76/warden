#!/usr/bin/env python3
"""Run mcp-audit (--connect), mcp-shield and Snyk Agent Scan on each server of a config, one server per run.

usage: run_competitors.py CONFIG OUTDIR [--workers N] [--only mcp-audit|mcp-shield|snyk-agent-scan] [--pause S]
Each run gets its own one-server config and its own HOME, so cross-server heuristics and
baseline state never leak between servers. Raw outputs are kept for inspection.

Snyk Agent Scan judges tool text on Snyk's servers and needs SNYK_TOKEN in the environment; the
token is passed to that scanner only. Its free tier has a shared quota: on a quota refusal the run
stops, keeps nothing for that server and exits with code 75, so it can be resumed later. --pause
waits between Snyk requests (default 3 s).
"""
import json, os, subprocess, sys, tempfile, concurrent.futures as cf, re, time, threading
cfg_path, outdir = sys.argv[1], os.path.abspath(sys.argv[2])
workers = int(sys.argv[sys.argv.index('--workers') + 1]) if '--workers' in sys.argv else 4
only = sys.argv[sys.argv.index('--only') + 1] if '--only' in sys.argv else None
pause = float(sys.argv[sys.argv.index('--pause') + 1]) if '--pause' in sys.argv else 3.0
SNYK = 'snyk-agent-scan==0.6.8'
PY_DIR = os.path.expanduser('~/.local/share/uv/python')
quota_hit = threading.Event()
# The scanner turns every HTTP 429 into this sentence; the service's own reply says the public quota is spent.
QUOTA = ('Daily usage limit reached', "429, message='Too Many Requests'")
servers = json.load(open(cfg_path))['mcpServers']
os.makedirs(outdir, exist_ok=True)
ANSI = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]')

def run_one(tool, key, entry):
    raw = os.path.join(outdir, tool, key + ('.txt' if tool == 'mcp-shield' else '.json'))
    if os.path.exists(raw) and os.path.getsize(raw) > 0: return key, 'cached'
    if quota_hit.is_set(): return key, 'skipped'
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
                p = subprocess.run(['uvx', '--from', 'mcp-audit-scanner[mcp]==0.18.2', 'mcp-audit', 'scan', cfg, '--connect', '--format', 'json', '-o', raw], env=env, cwd=home, capture_output=True, text=True, timeout=180)
                if not os.path.exists(raw): open(raw, 'w').write(json.dumps({'_error': p.stderr[-2000:], '_code': p.returncode}))
            elif tool == 'snyk-agent-scan':
                env['SNYK_TOKEN'] = os.environ['SNYK_TOKEN']
                # The run's HOME is a temp dir, so point uv at the real managed Pythons and pin one; it judges online anyway.
                env.update(UV_PYTHON='3.11', UV_PYTHON_INSTALL_DIR=PY_DIR); env.pop('UV_OFFLINE', None)
                p = subprocess.run(['uvx', '--from', SNYK, 'snyk-agent-scan', 'scan', '--json', '--no-skills', '--dangerously-run-mcp-servers',
                                    '--storage-file', os.path.join(home, 'state'), '--server-timeout', '30', cfg], env=env, cwd=home, capture_output=True, text=True, timeout=300)
                time.sleep(pause)
                if any(q in p.stdout for q in QUOTA):
                    quota_hit.set(); return key, 'quota'
                out = p.stdout if p.stdout.strip().startswith('{') else json.dumps({'_error': p.stderr[-2000:], '_code': p.returncode})
                # Never keep the token, wherever a scanner might echo it.
                open(raw, 'w').write(out.replace(env['SNYK_TOKEN'], '<token>'))
            else:
                p = subprocess.run(['npx', '--yes', 'mcp-shield@1.0.4', '--path', cfg], env=env, cwd=home, capture_output=True, text=True, timeout=180)
                open(raw, 'w').write(ANSI.sub('', p.stdout + '\n--STDERR--\n' + p.stderr))
        except subprocess.TimeoutExpired:
            open(raw, 'w').write(json.dumps({'_error': 'timeout'}) if tool == 'mcp-audit' else 'TIMEOUT')
    return key, 'ran'

tools = [only] if only else ['mcp-audit', 'mcp-shield']
if 'snyk-agent-scan' in tools and not os.environ.get('SNYK_TOKEN'): sys.exit('snyk-agent-scan needs SNYK_TOKEN in the environment')
t0 = time.time()
for tool in tools:
    with cf.ThreadPoolExecutor(1 if tool == 'snyk-agent-scan' else workers) as ex:
        futs = [ex.submit(run_one, tool, k, v) for k, v in servers.items()]
        done = 0
        for f in cf.as_completed(futs):
            f.result(); done += 1
            if done % 50 == 0: print(f'{tool}: {done}/{len(servers)} ({time.time()-t0:.0f}s)', flush=True)
    if quota_hit.is_set():
        left = sum(1 for k in servers if not os.path.exists(os.path.join(outdir, tool, k + '.json')))
        print(f'{tool}: stopped on the shared quota, {left} of {len(servers)} servers left ({time.time()-t0:.0f}s)', flush=True)
        sys.exit(75)
    print(f'{tool}: all {len(servers)} done ({time.time()-t0:.0f}s)', flush=True)
