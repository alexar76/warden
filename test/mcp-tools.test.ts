import { describe, it, expect } from "vitest";

describe("advertised tool-definition schema", () => {
  it("requires only what asTools() enforces, so the documented example validates", async () => {
    const { MCP_TOOLS } = await import("../src/mcp-tools.js");
    const vet = MCP_TOOLS.find((t) => t.name === "vet_mcp_server")!;
    const item = (vet.inputSchema as any).properties.tools.items;
    expect(item.required).toEqual(["name", "description", "inputSchema"]);
  });
});
