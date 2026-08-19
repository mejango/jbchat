import { defineConfig, globalIgnores } from "eslint/config";
import nextCoreWebVitals from "eslint-config-next/core-web-vitals";
import nextTypeScript from "eslint-config-next/typescript";

export default defineConfig([
  ...nextCoreWebVitals,
  ...nextTypeScript,
  globalIgnores([
    ".next/**",
    "coverage/**",
    "next-env.d.ts",
    // wasm-bindgen generated glue for the MLS wasm core
    "src/lib/messaging/mlsWasm/**",
    "crypto/crates/wasm-client/pkg/**",
  ]),
]);
