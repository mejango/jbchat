import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// PostgreSQL-backed storage repository tests. They need a migrated database
// named by JBM_STORAGE_DATABASE_URL and run through npm run test:storage,
// never through the offline npm test suite.
export default defineConfig({
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.pgtest.ts"],
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
