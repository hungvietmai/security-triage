import { toast } from "sonner";
import { describe, expect, it, vi } from "vitest";
import { ApiError } from "@/lib/api-client";
import { createQueryClient } from "@/lib/react-query";

function runFailingMutation(meta?: { handlesError?: boolean }) {
  const queryClient = createQueryClient();
  const mutation = queryClient.getMutationCache().build(queryClient, {
    mutationFn: () => Promise.reject(new ApiError("Máy chủ lỗi (500).", 500)),
    meta,
  });
  return mutation.execute(undefined).catch(() => {});
}

describe("createQueryClient", () => {
  it("toasts failed mutations by default", async () => {
    const error = vi.spyOn(toast, "error");
    await runFailingMutation();
    expect(error).toHaveBeenCalledWith("Máy chủ lỗi (500).");
  });

  it("stays quiet when the caller renders the error itself", async () => {
    const error = vi.spyOn(toast, "error");
    await runFailingMutation({ handlesError: true });
    expect(error).not.toHaveBeenCalled();
  });

  it("does not retry client errors", () => {
    const retry = createQueryClient().getDefaultOptions().queries?.retry;
    expect(typeof retry).toBe("function");
    const shouldRetry = retry as (count: number, error: Error) => boolean;
    expect(shouldRetry(0, new ApiError("Not found", 404))).toBe(false);
    expect(shouldRetry(0, new ApiError("Bad gateway", 502))).toBe(true);
    expect(shouldRetry(2, new ApiError("Bad gateway", 502))).toBe(false);
  });
});
