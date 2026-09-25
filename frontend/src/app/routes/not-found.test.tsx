import { describe, expect, it } from "vitest";
import { mainContent as main, renderApp } from "@/testing/test-utils";

describe("Not found", () => {
  it("renders inside the layout for unknown paths", async () => {
    await renderApp("/does-not-exist");
    expect(await main().findByText("Không tìm thấy trang")).toBeInTheDocument();
    expect(
      main().getByRole("link", { name: "Về trang tổng quan" }),
    ).toHaveAttribute("href", "/");
  });
});
