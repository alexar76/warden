import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';

// Run the actual compiled path guard in a new process so os.homedir() observes
// exactly the child's HOME. In a uid-only Linux container HOME may legitimately
// be '/', which previously constructed '//.claude.json' inside the guard.
describe.skipIf(process.platform === 'win32')('protected settings with a root or ordinary home', () => {
  it.each(['/', '/tmp/warden-home-regression'])('protects config and plugin paths with HOME=%s', home => {
    const moduleUrl = new URL('../dist/flow-guard-paths.js', import.meta.url).href;
    const code = `
      import { homedir } from 'node:os';
      import { join } from 'node:path';
      import { isProtectedPath } from ${JSON.stringify(moduleUrl)};
      const home = homedir();
      const env = { WARDEN_STATE_DIR: '/tmp/warden-independent-state' };
      console.log(JSON.stringify({
        home,
        config: isProtectedPath(join(home, '.claude.json'), '/work/project', env),
        pluginDirectory: isProtectedPath(join(home, '.claude', 'plugins'), '/work/project', env),
        pluginFile: isProtectedPath(join(home, '.claude', 'plugins', 'fixture', 'handler.mjs'), '/work/project', env),
        adjacentDirectory: isProtectedPath(join(home, '.claude', 'plugins-other', 'notes.md'), '/work/project', env),
        unrelatedFile: isProtectedPath(join(home, 'Documents', 'notes.md'), '/work/project', env),
      }));
    `;
    const result = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', code], {
      env: { ...process.env, HOME: home }, encoding: 'utf8',
    }));
    expect(result).toEqual({
      home, config: true, pluginDirectory: true, pluginFile: true,
      adjacentDirectory: false, unrelatedFile: false,
    });
  });
});
