import type { WardenLogger } from "./types.js";

/**
 * A logger that writes nothing — the default when a host supplies none.
 *
 * WARDEN reports every decision through the logger, so a host that drops it
 * loses the audit trail but never the enforcement: verdicts are returned as
 * data from `vet()`, not inferred from log output.
 */
export function silentLogger(): WardenLogger {
  const noop = (): void => {};
  const self: WardenLogger = {
    debug: noop,
    info: noop,
    warn: noop,
    error: noop,
    child: () => self,
  };
  return self;
}
