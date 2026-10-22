import { describe, expect, it } from 'vitest';
import { parseSnpReport } from '../src/amd/report.js';
import { toHex } from '../src/lib/bytes.js';
import { routerReportBytes } from './fixtures.js';

const ROUTER_MEASUREMENT =
  'ffb708f1bb0fcb489faa6455680f3efb99f582f6183da219fbd109b7a72017f0011a25e00431016dbc5d38d0b450b0b4';

describe('parseSnpReport', () => {
  it('reads the report of the router', async () => {
    const report = parseSnpReport(await routerReportBytes());
    expect(report.version).toBe(3);
    expect(report.product).toBe('Genoa');
    expect(toHex(report.measurement)).toBe(ROUTER_MEASUREMENT);
    expect(report.policy.debug).toBe(false);
    expect(report.signatureR).toHaveLength(72);
  });

  it('rejects a report of the wrong size', async () => {
    const bytes = await routerReportBytes();
    expect(() => parseSnpReport(bytes.subarray(1))).toThrow(/bytes/);
  });

  it('rejects data in reserved bytes', async () => {
    const bytes = Uint8Array.from(await routerReportBytes());
    bytes[0x4c] = 1;
    expect(() => parseSnpReport(bytes)).toThrow(/reserved bytes/);
  });

  it('rejects a policy without its reserved bit', async () => {
    const bytes = Uint8Array.from(await routerReportBytes());
    bytes[0x0a] = (bytes[0x0a] ?? 0) & ~0b10;
    expect(() => parseSnpReport(bytes)).toThrow(/bit 17/);
  });
});
