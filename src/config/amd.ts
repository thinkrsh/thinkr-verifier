import type { AmdProduct } from './amdRoots.js';

/** The security patch levels of a TCB version of AMD SEV-SNP (Genoa layout). */
export interface TcbLevels {
  bootloader: number;
  tee: number;
  snp: number;
  microcode: number;
}

/** What the verifier demands of a platform and of a guest. */
export interface SnpPolicy {
  /** The lowest version of the attestation report: 2 is revision 1.55 of the ABI. */
  minimumReportVersion: number;
  minimumGuestSvn: number;
  /** The lowest build of the SNP firmware. */
  minimumFirmwareBuild: number;
  /** The lowest API version of the SNP firmware. */
  minimumFirmwareVersion: { major: number; minor: number };
  minimumTcb: TcbLevels;
  guest: {
    debugAllowed: boolean;
    migrationAgentAllowed: boolean;
    smtAllowed: boolean;
    cxlAllowed: boolean;
    aes256XtsAllowed: boolean;
  };
  platform: {
    smtAllowed: boolean;
    tsmeRequired: boolean;
  };
}

/**
 * The minimum state of a platform and of a guest that the verifier accepts. The values are those
 * that the verifiers of Tinfoil enforce (`tinfoil-js` 1.3.0, `packages/verifier`, read 23 Oct 2026),
 * so the verifier of Thinkr accepts the same enclaves.
 */
export const SNP_POLICY: Readonly<SnpPolicy> = {
  minimumReportVersion: 2,
  minimumGuestSvn: 0,
  minimumFirmwareBuild: 21,
  minimumFirmwareVersion: { major: 1, minor: 55 },
  minimumTcb: { bootloader: 0x07, tee: 0x00, snp: 0x0e, microcode: 0x48 },
  guest: {
    debugAllowed: false,
    migrationAgentAllowed: false,
    smtAllowed: true,
    cxlAllowed: false,
    aes256XtsAllowed: false,
  },
  platform: {
    smtAllowed: true,
    tsmeRequired: true,
  },
};

/** The algorithm number of ECDSA P-384 with SHA-384 in the report. */
export const SIGNATURE_ALGORITHM_ECDSA_P384_SHA384 = 1;

/** The value of SIGNING_KEY in SIGNER_INFO when the VCEK signs the report. */
export const REPORT_SIGNER_VCEK = 0;

/** The family and model of each product in a report of version 3 or later. */
export const AMD_CPU_IDS: Readonly<Record<AmdProduct, { family: number; model: number }>> = {
  Genoa: { family: 0x19, model: 0x11 },
};

/** The fields of the name of every AMD certificate in the chain. */
export const AMD_CERTIFICATE_NAME = {
  C: 'US',
  L: 'Santa Clara',
  ST: 'CA',
  O: 'Advanced Micro Devices',
  OU: 'Engineering',
} as const;

/** The common names of the certificates of the chain. */
export const AMD_COMMON_NAMES = {
  ark: (product: AmdProduct): string => `ARK-${product}`,
  ask: (product: AmdProduct): string => `SEV-${product}`,
  vcek: 'SEV-VCEK',
} as const;

/** The length of the chip ID in a report and in the HWID extension of a VCEK. */
export const CHIP_ID_BYTES = 64;
