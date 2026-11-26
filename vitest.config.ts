import { defineConfig, configDefaults } from "vitest/config";

export default defineConfig({
  test: {
    // Vitest 4's default exclude is only node_modules and .git; dist/ is build output.
    // .github/scripts has its own node:test tests, run by the Release workflow.
    exclude: [...configDefaults.exclude, "**/dist/**", "**/.claude/**", "**/.github/**"],
  },
});
