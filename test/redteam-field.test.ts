import { describe, expect, it } from 'vitest';
import { assertFieldRedteam, FIELD_ATTACK_IDS } from '../scripts/redteam/flow-gate.mjs';

// Field regressions: attacks that got through on a real installation (TONM-13/14) before their fix.
const good = () => ({ field: FIELD_ATTACK_IDS.map((id: string) => ({ id, calls: ['deny'], outcome: 'denied' })) });

describe('field regressions in the release gate', () => {
  it('passes when every field regression is refused', () => {
    expect(assertFieldRedteam(good())).toEqual({ fieldRegressions: 4, fieldDelivered: 0 });
  });

  it.each(['delivered', 'missing', 'unknown', 'absent'])('fails closed when a field regression is %s', kind => {
    const report: { field?: Array<{ id: string; calls: string[]; outcome: string }> } = good();
    if (kind === 'delivered') { report.field![0]!.calls = ['pass']; report.field![0]!.outcome = 'delivered'; }
    if (kind === 'missing') report.field!.pop();
    if (kind === 'unknown') report.field![0]!.id = 'field-something-else';
    if (kind === 'absent') delete report.field;
    expect(() => assertFieldRedteam(report)).toThrow();
  });
});
