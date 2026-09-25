// Conventional Commits 1.0.0 (https://www.conventionalcommits.org/en/v1.0.0/),
// checked by the commit-msg hook. Rules and examples: AGENTS.md → "Commits".

/** Attribution lines that must never appear: commits carry only the Git user's identity. */
const FORBIDDEN_ATTRIBUTION = [
  { pattern: /^co-authored-by:/im, reason: "Co-authored-by trailers" },
  { pattern: /generated (with|by) .*(claude|ai\b|assistant)/i, reason: "AI generation notes" },
  { pattern: /claude\.(com|ai)\/(code|claude-code)/i, reason: "Claude Code links" },
  { pattern: /noreply@anthropic\.com/i, reason: "Anthropic addresses" },
  { pattern: /\u{1F916}/u, reason: "the robot emoji" },
];

export default {
  extends: ["@commitlint/config-conventional"],
  plugins: [
    {
      rules: {
        "no-ai-attribution": ({ raw }) => {
          const found = FORBIDDEN_ATTRIBUTION.filter(({ pattern }) => pattern.test(raw ?? ""));
          return [
            found.length === 0,
            `remove ${found.map(({ reason }) => reason).join(", ")}; ` +
              "commits carry only the Git user's identity",
          ];
        },
      },
    },
  ],
  rules: {
    "no-ai-attribution": [2, "always"],
    // Optional scope, but when present it names a part of this repository.
    "scope-enum": [
      2,
      "always",
      ["frontend", "backend", "api", "db", "infra", "ci", "hooks", "docs", "deps", "research"],
    ],
    "header-max-length": [2, "always", 100],
  },
};
