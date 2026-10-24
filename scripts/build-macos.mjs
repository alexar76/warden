#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

if (process.platform !== 'darwin') throw new Error('Native desktop build requires macOS and Xcode command-line tools');
if (process.argv.slice(2).some(x => x !== '--tests') || process.argv.slice(2).length > 1) throw new Error('Expected [--tests]');
const root = fileURLToPath(new URL('..', import.meta.url));
const build = join(root, 'native/macos/.build'); mkdirSync(build, { recursive: true });
const cache = join(build, 'module-cache'); mkdirSync(cache, { recursive: true });
{
  if (!['arm64', 'x64'].includes(process.arch)) throw new Error('Unsupported macOS architecture');
  const args = ['swiftc', '-swift-version', '5', '-parse-as-library', '-O', '-target', `${process.arch === 'arm64' ? 'arm64' : 'x86_64'}-apple-macos13.0`, '-module-cache-path', cache,
    '-framework', 'AppKit', '-framework', 'CryptoKit', '-framework', 'Security',
    ...['WardenDesktop/NativeSurface.swift', 'WardenDesktop/StandardIO.swift', 'WardenDesktopHost/Main.swift'].map(f => join(root, 'native/macos/Sources', f))];
  const test = process.argv.includes('--tests');
  if (test) args.push('-D', 'WARDEN_DESKTOP_TESTS');
  const path = join(build, test ? 'warden-desktop-test' : 'warden-desktop');
  execFileSync('/usr/bin/xcrun', [...args, '-o', path], { cwd: root, stdio: 'inherit', env: { ...process.env, CLANG_MODULE_CACHE_PATH: cache } });
  process.stdout.write(path + '\n');
}
