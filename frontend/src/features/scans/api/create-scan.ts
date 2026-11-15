import { useMutation, useQueryClient } from "@tanstack/react-query";
import { z } from "zod";
import type { ScanAccepted, ScanCreate } from "@/features/scans/types";
import { api } from "@/lib/api-client";
import type { MutationConfig } from "@/lib/react-query";

// Keep these expressions aligned with app/scanners/sources.py (full matches).
const npmName = /^(?:@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/;
const semver =
  /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?$/;

export const createScanInputSchema = z.object({
  source: z.discriminatedUnion("kind", [
    z.object({
      kind: z.literal("npm"),
      package: z
        .string()
        .trim()
        .max(214)
        .regex(npmName, "Tên npm không hợp lệ (có thể dùng @scope/package)."),
      version: z
        .string()
        .trim()
        .max(256)
        .regex(semver, "Nhập phiên bản SemVer chính xác, ví dụ 1.2.3."),
    }),
    z.object({
      kind: z.literal("github"),
      owner: z
        .string()
        .trim()
        .regex(/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/, "Owner GitHub không hợp lệ."),
      repo: z
        .string()
        .trim()
        .regex(/^[A-Za-z0-9._-]{1,100}$/, "Tên repo GitHub không hợp lệ.")
        .refine(
          (value) => value !== "." && value !== "..",
          "Tên repo GitHub không hợp lệ.",
        ),
      commit: z
        .string()
        .trim()
        .regex(
          /^[0-9a-f]{40}$/,
          "Commit phải có đúng 40 ký tự hex viết thường.",
        ),
    }),
  ]),
  profile: z.enum([
    "command-injection-v0.1",
    "command-injection-v0.2",
    "command-injection-v0.3",
    "path-traversal-v0.2",
  ]),
}) satisfies z.ZodType<ScanCreate>;

export const SCAN_PROFILES: Record<
  ScanCreate["profile"],
  { label: string; description: string }
> = {
  "command-injection-v0.1": {
    label: "CWE-78 · Command injection",
    description:
      "Semgrep và CodeQL cho JavaScript và Python; xếp hàng đợi theo chính sách ưu tiên v0.1.",
  },
  "command-injection-v0.2": {
    label: "CWE-78 · Command injection (thêm Bandit, ESLint)",
    description:
      "Sàng lọc bằng Semgrep cùng Bandit (Python) hoặc eslint-plugin-security (JavaScript/TypeScript), thẩm định bằng CodeQL; xếp hàng đợi theo chính sách ưu tiên v0.2.",
  },
  "command-injection-v0.3": {
    label: "CWE-78 · Command injection (v0.3: đối sánh JavaScript tốt hơn)",
    description:
      "Như v0.2, thêm bộ định vị lời gọi JavaScript v1, phạm vi tệp của Semgrep do worker quyết định, và quy tắc gạn lệnh hằng cho JavaScript/TypeScript.",
  },
  "path-traversal-v0.2": {
    label: "CWE-22 · Path traversal (bằng chứng an toàn)",
    description:
      "CodeQL cho Python. Cảnh báo có bằng chứng an toàn được xếp cuối hàng đợi, không bị xóa.",
  },
};

export function createScan({
  projectId,
  data,
}: {
  projectId: string;
  data: ScanCreate;
}): Promise<ScanAccepted> {
  return api.post<ScanAccepted>(
    `/projects/${encodeURIComponent(projectId)}/scans`,
    data,
  );
}

export function useCreateScan({
  mutationConfig,
}: { mutationConfig?: MutationConfig<typeof createScan> } = {}) {
  const queryClient = useQueryClient();
  const { onSuccess, ...restConfig } = mutationConfig ?? {};
  return useMutation({
    ...restConfig,
    mutationFn: createScan,
    onSuccess: async (scan, ...args) => {
      await queryClient.invalidateQueries({ queryKey: ["scans", "list"] });
      await onSuccess?.(scan, ...args);
    },
  });
}
