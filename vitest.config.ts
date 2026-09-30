import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    setupFiles: ["test/setup.ts"],
  },
  coverage: {
    provider: "v8",
    reporter: ["text", "json-summary"],
    include: ["src/**/*.ts"],
    exclude: ["src/**/*.d.ts"],
  },
});
