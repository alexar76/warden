"""Parse MCPTox def_tool/*.py with ast only (never imported or executed)."""
import ast, json, sys, os, glob
out = {}
for p in glob.glob(os.path.join(sys.argv[1], '*.py')):
    tree = ast.parse(open(p, encoding='utf-8').read())
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        params = {}
        for a in fn.args.args:
            ann = ast.unparse(a.annotation) if a.annotation else 'str'
            t = {'int': 'integer', 'float': 'number', 'bool': 'boolean', 'str': 'string'}.get(ann.split('[')[0], 'string')
            if ann.startswith(('list', 'List')): t = 'array'
            if ann.startswith(('dict', 'Dict')): t = 'object'
            params[a.arg] = {'type': t}
        out[os.path.basename(p)] = {'name': fn.name, 'doc': (ast.get_docstring(fn) or '').strip(), 'params': params}
json.dump(out, open(sys.argv[2], 'w'), ensure_ascii=False, indent=1)
print('parsed', len(out), '| with params', sum(1 for v in out.values() if v['params']))
