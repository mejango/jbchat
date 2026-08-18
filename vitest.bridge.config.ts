import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// MLS bridge subprocess tests. They need the compiled bridge binary named
// by JBM_MLS_BRIDGE_BINARY and run through node scripts/mls/run-bridge-lab.mjs,
// never through the offline npm test suite.
export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.labtest.ts"],
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
