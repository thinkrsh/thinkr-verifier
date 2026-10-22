import { describe, expect, it } from 'vitest';
import type { VerifiedVcek } from '../src/amd/chain.js';
import { checkSnpPolicy } from '../src/amd/policy.js';
import { parseSnpReport, type SnpReport } from '../src/amd/report.js';
import { routerReportBytes } from './fixtures.js';

async function routerReport(): Promise<SnpReport> {
  return parseSnpReport(await routerReportBytes());
}

/** A VCEK that matches the report: the policy is the only check in play. */
function matchingVcek(report: SnpReport): VerifiedVcek {
  return {
    publicKey: {} as CryptoKey,
    tcb: { ...report.reportedTcb },
    hardwareId: report.chipId,
  };
}

describe('checkSnpPolicy', () => {
  it('accepts the report of the router', async () => {
    const report = await routerReport();
    expect(() => {
      checkSnpPolicy(report, matchingVcek(report));
    }).not.toThrow();
  });

  it('rejects an enclave in debug mode', async () => {
    const report = await routerReport();
    const debug = { ...report, policy: { ...report.policy, debug: true } };
    expect(() => {
      checkSnpPolicy(debug, matchingVcek(report));
    }).toThrow(/debug/);
  });

  it('rejects a migration agent', async () => {
    const report = await routerReport();
    const migrating = { ...report, policy: { ...report.policy, migrationAgent: true } };
    expect(() => {
      checkSnpPolicy(migrating, matchingVcek(report));
    }).toThrow(/migration/);
  });

  it('rejects a TCB below the minimum', async () => {
    const report = await routerReport();
    const old = { ...report, currentTcb: { ...report.currentTcb, microcode: 0 } };
    expect(() => {
      checkSnpPolicy(old, matchingVcek(report));
    }).toThrow(/current TCB/);
  });

  it('rejects provisional firmware', async () => {
    const report = await routerReport();
    const provisional = { ...report, tcbCommitted: false };
    expect(() => {
      checkSnpPolicy(provisional, matchingVcek(report));
    }).toThrow(/provisional/);
  });

  it('rejects the VCEK of another chip', async () => {
    const report = await routerReport();
    const other = { ...matchingVcek(report), hardwareId: new Uint8Array(64) };
    expect(() => {
      checkSnpPolicy(report, other);
    }).toThrow(/another chip/);
  });

  it('rejects a VCEK issued for another TCB', async () => {
    const report = await routerReport();
    const vcek = matchingVcek(report);
    const other = { ...vcek, tcb: { ...vcek.tcb, snp: vcek.tcb.snp + 1 } };
    expect(() => {
      checkSnpPolicy(report, other);
    }).toThrow(/SPL/);
  });

  it('requires TSME on the platform', async () => {
    const report = await routerReport();
    const plain = { ...report, platformInfo: { ...report.platformInfo, tsme: false } };
    expect(() => {
      checkSnpPolicy(plain, matchingVcek(report));
    }).toThrow(/TSME/);
  });
});
