/** Runs from frontend/ for staged files under it (see ../.husky/pre-commit). */
export default {
  "*.{ts,tsx,js,css,html,json,md}": "prettier --write --ignore-unknown",
  "*.{ts,tsx}": [
    // Staged files oxlint ignores (the generated API types) would otherwise fail the hook.
    "oxlint --no-error-on-unmatched-pattern",
    // Type errors can surface in files that were not staged, so check the project.
    () => "tsc -b",
  ],
};
