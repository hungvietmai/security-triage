// Screening configuration for the scan worker. Pinned by hash in the scan profile.
// It only wires the parser and the plugin: the profile's language config names the rules,
// and the worker turns each of them on with --rule. Nothing here reads the scanned project.
import parser from "@typescript-eslint/parser";
import security from "eslint-plugin-security";

export default [
  {
    files: ["**/*.js", "**/*.jsx", "**/*.mjs", "**/*.cjs", "**/*.ts", "**/*.tsx"],
    languageOptions: { parser, ecmaVersion: "latest", sourceType: "module" },
    linterOptions: { noInlineConfig: true, reportUnusedDisableDirectives: "off" },
    plugins: { security },
  },
];
