import { defineConfig } from 'vitest/config';
export default defineConfig({ test: {
  include: ['test/macos/**/*.integration.ts'], environment: 'node', setupFiles: ['test/setup.ts'],
  fileParallelism: false, maxWorkers: 1, testTimeout: 12_000,
} });
