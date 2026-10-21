import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Compile once, before any worker starts. Tests spawn dist/mcp-server.js; when action.test.ts and
// wrap.test.ts each rebuilt dist in their own beforeAll, tsc rewrote it while other workers were
// spawning it, and a child that loaded a half-written module failed persistent-pins at random.
export default function setup(): void {
  const root = fileURLToPath(new URL('..', import.meta.url));
  execFileSync(process.execPath, ['node_modules/typescript/bin/tsc', '-p', 'tsconfig.json'], { cwd: root, stdio: 'inherit' });
}
