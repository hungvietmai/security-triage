import { describe, expect, it } from "vitest";
import { formatRelative, shortId } from "@/utils/format";

const NOW = Date.parse("2026-09-25T12:00:00Z");
const ago = (seconds: number) => new Date(NOW - seconds * 1000);

describe("formatRelative", () => {
  it("treats the last minute as just now", () => {
    expect(formatRelative(ago(30), NOW)).toBe("vừa xong");
  });

  it.each([
    [5 * 60, "5 phút trước"],
    [3 * 3600, "3 giờ trước"],
    [24 * 3600, "Hôm qua"],
    [3 * 24 * 3600, "3 ngày trước"],
  ])("formats %i seconds ago as %s", (seconds, expected) => {
    expect(formatRelative(ago(seconds), NOW)).toBe(expected);
  });
});

describe("shortId", () => {
  it("keeps the first UUID segment", () => {
    expect(shortId("1485a2ea-4508-4f3c-ba58-13cf61dafaff")).toBe("1485a2ea");
  });
});
