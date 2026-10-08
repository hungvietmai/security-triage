import { z } from "zod";
import { TIERS, TOOLS } from "@/features/scans/types";

export const scanSearchSchema = z.object({
  page: z.number().int().min(1).default(1).catch(1),
  tier: z.enum(TIERS).optional().catch(undefined),
  tool: z.enum(TOOLS).optional().catch(undefined),
});
