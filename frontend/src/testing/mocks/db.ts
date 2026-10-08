import type { Schemas } from "@/types/api";

type Project = Schemas["ProjectRead"];
type Scan = Schemas["ScanRead"];
type Unit = Schemas["UnitDetail"];

/** In-memory backend state shared by the MSW handlers; reset before each test. */
export const db = {
  projects: [] as Project[],
  scans: [] as Scan[],
  units: {} as Record<string, Unit[]>,
};

let sequence = 0;

export function resetDb() {
  sequence = 0;
  db.projects = [];
  db.scans = [];
  db.units = {};
}

export function makeScan(overrides: Partial<Scan> = {}): Scan {
  sequence += 1;
  return {
    id: `10000000-0000-4000-8000-${String(sequence).padStart(12, "0")}`,
    project_id: db.projects[0]?.id ?? "00000000-0000-4000-8000-000000000001",
    status: "completed",
    profile: "command-injection-v0.1",
    created_at: "2026-10-08T00:00:00Z",
    started_at: "2026-10-08T00:00:01Z",
    finished_at: "2026-10-08T00:00:10Z",
    error_message: null,
    reconciler_version: "reconciler-v0.1",
    policy_version: "policy-v0.1",
    snapshot: {
      id: "20000000-0000-4000-8000-000000000001",
      status: "ready",
      source_kind: "github_archive",
      source_coordinate: `github:owner/repo@${"a".repeat(40)}`,
      sha256: "b".repeat(64),
      provenance_kind: "tofu",
      error_message: null,
    },
    tool_runs: [
      {
        tool: "semgrep",
        language: "javascript",
        status: "completed",
        tool_version: "1.2.3",
        exit_code: 0,
        error_message: null,
      },
      {
        tool: "codeql",
        language: "javascript",
        status: "completed",
        tool_version: "2.3.4",
        exit_code: 0,
        error_message: null,
      },
    ],
    unit_counts: { P1: 0, P2: 0, U: 0, P3: 0, P4: 0 },
    ...overrides,
  };
}

export function makeUnit(overrides: Partial<Unit> = {}): Unit {
  sequence += 1;
  const id = `30000000-0000-4000-8000-${String(sequence).padStart(12, "0")}`;
  return {
    id,
    unit_key: `unit-${id}`,
    path: "app.js",
    start_line: 12,
    end_line: 12,
    start_column: 1,
    end_column: 20,
    sink_kind: "child_process.exec",
    argument_role: "shell_command",
    mapping_status: "mapped",
    priority: "P1",
    decision_id: "D01",
    reason: "Untrusted command path",
    tools: ["semgrep", "codeql"],
    matched_conditions: ["strong_flow"],
    predicate_values: { strong_flow: true, verified_blocker: false },
    unknown_fields: ["source_library_input_or_unknown"],
    source_types: ["library_input"],
    shell_state: "absent",
    blocker_proof: null,
    finding_evidence: [],
    policy_id: "command-injection",
    policy_version: "v0.1",
    policy_sha256: "c".repeat(64),
    spec_sha256: "d".repeat(64),
    rule_claims_version: "v0.1",
    rule_claims_sha256: "e".repeat(64),
    reconciler_version: "reconciler-v0.1",
    findings: [
      {
        id: `40000000-0000-4000-8000-${String(sequence).padStart(12, "0")}`,
        tool: "codeql",
        language: "javascript",
        raw_id: "codeql:0:0",
        rule_id: "js/command-line-injection",
        raw_rule_id: null,
        file_path: "app.js",
        start_line: 12,
        end_line: 12,
        start_column: 1,
        end_column: 20,
        message: "User input reaches a command",
        cwe_ids: ["CWE-78"],
        raw_result: {},
      },
    ],
    ...overrides,
  };
}

export function makeProject(overrides: Partial<Project> = {}): Project {
  sequence += 1;
  return {
    id: `00000000-0000-4000-8000-${String(sequence).padStart(12, "0")}`,
    name: `Dự án ${sequence}`,
    description: null,
    created_at: new Date(Date.now() - sequence * 60_000).toISOString(),
    ...overrides,
  };
}
