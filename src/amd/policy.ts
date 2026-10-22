import {
  REPORT_SIGNER_VCEK,
  SIGNATURE_ALGORITHM_ECDSA_P384_SHA384,
  SNP_POLICY,
  type TcbLevels,
} from '../config/amd.js';
import { bytesEqual, isAllZero } from '../lib/bytes.js';
import type { VerifiedVcek } from './chain.js';
import type { FirmwareVersion, SnpReport } from './report.js';

const TCB_PARTS = ['bootloader', 'tee', 'snp', 'microcode'] as const;

/**
 * Checks a report against the policy of the verifier and against its VCEK: the format, the guest
 * policy, the firmware, the TCB, and the chip. Throws on the first failure.
 */
export function checkSnpPolicy(report: SnpReport, vcek: VerifiedVcek): void {
  checkFormat(report);
  checkGuest(report);
  checkFirmware(report);
  checkTcb(report);
  checkVcekMatches(report, vcek);
  checkPlatform(report);
}

function checkFormat(report: SnpReport): void {
  if (report.version < SNP_POLICY.minimumReportVersion) {
    throw new Error(`The report version ${String(report.version)} is too old.`);
  }
  if (report.signatureAlgorithm !== SIGNATURE_ALGORITHM_ECDSA_P384_SHA384) {
    throw new Error('The report is not signed with ECDSA P-384 and SHA-384.');
  }
  if (report.signerInfo.signingKey !== REPORT_SIGNER_VCEK) {
    throw new Error('The report is not signed by a VCEK.');
  }
}

function checkGuest(report: SnpReport): void {
  const allowed = SNP_POLICY.guest;
  const { policy } = report;
  if (policy.debug && !allowed.debugAllowed) {
    throw new Error('The enclave runs in debug mode.');
  }
  if (policy.migrationAgent && !allowed.migrationAgentAllowed) {
    throw new Error('The enclave allows a migration agent.');
  }
  if (policy.smt && !allowed.smtAllowed) {
    throw new Error('The enclave allows SMT.');
  }
  if (policy.cxl && !allowed.cxlAllowed) {
    throw new Error('The enclave allows CXL memory.');
  }
  if (policy.aes256Xts && !allowed.aes256XtsAllowed) {
    throw new Error('The enclave asks for AES-256-XTS, which the policy does not allow.');
  }
  if (report.guestSvn < SNP_POLICY.minimumGuestSvn) {
    throw new Error(`The guest SVN ${String(report.guestSvn)} is below the minimum.`);
  }
}

function versionNumber(firmware: FirmwareVersion): number {
  return firmware.major * 256 + firmware.minor;
}

function checkFirmware(report: SnpReport): void {
  const minimum = SNP_POLICY.minimumFirmwareVersion;
  for (const firmware of [report.currentFirmware, report.committedFirmware]) {
    if (firmware.build < SNP_POLICY.minimumFirmwareBuild) {
      throw new Error(`The SNP firmware build ${String(firmware.build)} is below the minimum.`);
    }
    if (versionNumber(firmware) < versionNumber({ ...minimum, build: 0 })) {
      throw new Error(
        `The SNP firmware ${String(firmware.major)}.${String(firmware.minor)} is below the minimum.`,
      );
    }
  }
  const { currentFirmware: current, committedFirmware: committed } = report;
  const sameFirmware =
    current.build === committed.build &&
    current.minor === committed.minor &&
    current.major === committed.major;
  if (!sameFirmware || !report.tcbCommitted) {
    throw new Error('The platform runs firmware that is not committed (provisional firmware).');
  }
}

function meetsMinimum(tcb: TcbLevels, minimum: TcbLevels): boolean {
  return TCB_PARTS.every((part) => tcb[part] >= minimum[part]);
}

function checkTcb(report: SnpReport): void {
  const fields = {
    current: report.currentTcb,
    committed: report.committedTcb,
    reported: report.reportedTcb,
    launch: report.launchTcb,
  };
  for (const [name, tcb] of Object.entries(fields)) {
    if (!meetsMinimum(tcb, SNP_POLICY.minimumTcb)) {
      throw new Error(`The ${name} TCB is below the minimum.`);
    }
  }
}

/** The VCEK must be the key of this chip at the reported TCB. */
function checkVcekMatches(report: SnpReport, vcek: VerifiedVcek): void {
  for (const part of TCB_PARTS) {
    if (vcek.tcb[part] !== report.reportedTcb[part]) {
      throw new Error(`The ${part} SPL of the VCEK differs from the reported TCB.`);
    }
  }
  if (report.signerInfo.maskChipKey) {
    if (!isAllZero(report.chipId)) {
      throw new Error('The chip ID is masked but not zero.');
    }
    return;
  }
  if (!bytesEqual(vcek.hardwareId, report.chipId)) {
    throw new Error('The VCEK belongs to another chip.');
  }
}

function checkPlatform(report: SnpReport): void {
  if (report.platformInfo.smt && !SNP_POLICY.platform.smtAllowed) {
    throw new Error('The platform has SMT on.');
  }
  if (!report.platformInfo.tsme && SNP_POLICY.platform.tsmeRequired) {
    throw new Error('The platform does not encrypt all of its memory (TSME is off).');
  }
}
