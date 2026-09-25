// @vitest-environment node
/// <reference types="node" />
// Enforces the import rules in frontend/AGENTS.md. oxlint's no-restricted-imports
// could not express per-directory zones here, so this test scans the sources.
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC = fileURLToPath(new URL("../", import.meta.url));

const SHARED = ["components", "config", "hooks", "lib", "types", "utils"];

const IMPORT_RE = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)["']([^"']+)["']/g;

interface SourceFile {
  path: string;
  specifiers: string[];
}

function sourceFiles(): SourceFile[] {
  return readdirSync(SRC, { recursive: true, encoding: "utf8" })
    .map((path) => path.replaceAll("\\", "/"))
    .filter((path) => /\.(ts|tsx)$/.test(path) && !path.endsWith(".d.ts"))
    .map((path) => ({
      path,
      specifiers: [...readFileSync(SRC + path, "utf8").matchAll(IMPORT_RE)].map(
        (match) => match[1],
      ),
    }));
}

const isTest = (path: string) => /\.test\.tsx?$/.test(path);

function violations(check: (file: SourceFile, specifier: string) => boolean) {
  return sourceFiles().flatMap((file) =>
    file.specifiers
      .filter((specifier) => check(file, specifier))
      .map((specifier) => `${file.path} -> ${specifier}`),
  );
}

describe("architecture", () => {
  it("scans the source tree", () => {
    expect(sourceFiles().length).toBeGreaterThan(20);
  });

  it("keeps shared code independent of features and the app layer", () => {
    expect(
      violations(
        ({ path }, specifier) =>
          SHARED.includes(path.split("/")[0]) &&
          /^@\/(features|app)(\/|$)/.test(specifier),
      ),
    ).toEqual([]);
  });

  it("keeps features independent of each other and of the app layer", () => {
    expect(
      violations(({ path }, specifier) => {
        const [layer, feature] = path.split("/");
        if (layer !== "features") return false;
        if (/^@\/app(\/|$)/.test(specifier)) return true;
        const target = /^@\/features\/([^/]+)/.exec(specifier)?.[1];
        return target !== undefined && target !== feature;
      }),
    ).toEqual([]);
  });

  it("uses @/ instead of relative imports", () => {
    expect(violations((_, specifier) => specifier.startsWith("."))).toEqual([]);
  });

  it("keeps test utilities out of production code", () => {
    expect(
      violations(
        ({ path }, specifier) =>
          !isTest(path) &&
          !path.startsWith("testing/") &&
          // main.tsx lazily starts the dev-only MSW worker.
          !(path === "main.tsx" && specifier === "@/testing/mocks/browser") &&
          specifier.startsWith("@/testing"),
      ),
    ).toEqual([]);
  });
});
