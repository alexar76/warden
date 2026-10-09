import { writeFile } from 'node:fs/promises';
import { parseScanArgs, runScan, exitCode, UsageRequested, SCAN_USAGE } from './scan.js';
import { toJson, toTable, toSarif, toMarkdown } from './scan-report.js';
import { displaySafe } from './sanitize.js';

/** `warden-mcp scan …` — returns the process exit code. */
export async function runScanCli(argv: string[]): Promise<number> {
  let opts;
  try { opts = await parseScanArgs([...argv]); }
  catch (err) {
    if (err instanceof UsageRequested) { process.stdout.write(SCAN_USAGE + '\n'); return 0; }
    process.stderr.write(`warden-mcp scan: ${displaySafe(err instanceof Error ? err.message : String(err), 2000)}\nRun warden-mcp scan --help for options.\n`);
    return 2;
  }
  let report;
  try { report = await runScan(opts); }
  catch (err) {
    process.stderr.write(`warden-mcp scan: ${displaySafe(err instanceof Error ? err.message : String(err), 2000)}\n`);
    return 2;
  }
  if (opts.sarif) await writeFile(opts.sarif, JSON.stringify(toSarif(report, opts.cwd), null, 2) + '\n');
  if (opts.markdown) await writeFile(opts.markdown, toMarkdown(report, opts.cwd));
  if (opts.jsonFile) await writeFile(opts.jsonFile, toJson(report) + '\n');
  process.stdout.write((opts.format === 'json' ? toJson(report) : toTable(report, opts.cwd, opts.color)) + '\n');
  return exitCode(report, opts);
}
