import type {
  WardenFinding,
  WardenGate,
  WardenGateInput,
  WardenGateResult,
} from "./types.js";

/**
 * Origin gate — enforces `policy.allowUnknownServers` against where a server
 * declaration came from.
 *
 * Every server ARGUS connects to is one of two things: declared by the operator
 * under `mcp.servers`, or discovered from a remote catalog listed under
 * `mcp.catalogs` — in which case `McpServerRef.catalog` names that catalog
 * (see CatalogConnector.normalize). Only the second kind is "unknown": nothing
 * local ever vouched for it.
 *
 * This gate replaces the reputation gate that used to occupy this slot in the
 * chain. That gate asked LUMEN for a PageRank score without ever supplying trust
 * edges, so the oracle returned its neutral default without any request being
 * made: the scored branch was unreachable in production, the composite score was
 * permanently multiplied by a constant, and the user was told the oracle was
 * unreachable when nothing had been tried. Catalog provenance needs no network,
 * is always available, and cannot deadlock — an operator's own servers are known
 * by definition, so fail-closed still leaves a way to connect.
 */
export class OriginGate implements WardenGate {
  readonly name = "origin";

  // eslint-disable-next-line @typescript-eslint/require-await -- gate interface is async
  async evaluate(input: WardenGateInput): Promise<WardenGateResult> {
    const catalog = input.server.catalog;
    if (!catalog) {
      // Operator-declared under mcp.servers: known, nothing to report.
      return { findings: [], score: 1 };
    }

    const strict = input.policy.allowUnknownServers !== true;
    const finding: WardenFinding = {
      gate: this.name,
      severity: strict ? "high" : "info",
      code: "SERVER_UNDECLARED",
      message: strict
        ? `Server "${input.server.id}" was discovered from catalog "${catalog}" and is not declared under mcp.servers; ` +
          `policy forbids undeclared servers (allowUnknownServers=false) — blocking. Add it to mcp.servers to allow it.`
        : `Server "${input.server.id}" was discovered from catalog "${catalog}", not declared under mcp.servers.`,
    };
    // Catalog provenance on its own is not a defect, so the permissive path does
    // not tax the composite score; it only says where the server came from.
    return { findings: [finding], score: strict ? 0 : 1, fatal: strict };
  }
}
