import { AMD_CPU_IDS, CHIP_ID_BYTES, type TcbLevels } from '../config/amd.js';
import { AMD_PRODUCTS, type AmdProduct } from '../config/amdRoots.js';
import { isAllZero } from '../lib/bytes.js';

/**
 * The layout of the attestation report of AMD SEV-SNP, from the SEV-SNP firmware ABI specification
 * (table "ATTESTATION_REPORT Structure"). Offsets are in bytes; integers are little-endian.
 */
const LAYOUT = {
  version: 0x00,
  guestSvn: 0x04,
  policy: 0x08,
  familyId: [0x10, 0x20],
  imageId: [0x20, 0x30],
  vmpl: 0x30,
  signatureAlgorithm: 0x34,
  currentTcb: 0x38,
  platformInfo: 0x40,
  signerInfo: 0x48,
  reserved1: [0x4c, 0x50],
  reportData: [0x50, 0x90],
  measurement: [0x90, 0xc0],
  hostData: [0xc0, 0xe0],
  idKeyDigest: [0xe0, 0x110],
  authorKeyDigest: [0x110, 0x140],
  reportId: [0x140, 0x160],
  reportIdMa: [0x160, 0x180],
  reportedTcb: 0x180,
  cpuFamily: 0x188,
  cpuModel: 0x189,
  cpuStepping: 0x18a,
  cpuIdReservedEnd: 0x1a0,
  chipId: [0x1a0, 0x1a0 + CHIP_ID_BYTES],
  committedTcb: 0x1e0,
  currentFirmware: 0x1e8,
  reserved3: [0x1eb, 0x1ec],
  committedFirmware: 0x1ec,
  reserved4: [0x1ef, 0x1f0],
  launchTcb: 0x1f0,
  mitigationVectorsEnd: 0x208,
  reservedBeforeSignature: 0x1f8,
  signature: 0x2a0,
  size: 0x4a0,
} as const;

/** The two halves of the ECDSA P-384 signature: R and S, each 72 bytes, little-endian. */
const SIGNATURE_PART_BYTES = 72;

/** Reports of version 5 and later use bytes 0x1F8 to 0x208 for the mitigation vectors. */
const MITIGATION_VECTORS_FROM_VERSION = 5;

/** Reports of version 3 and later carry the family, model, and stepping of the CPU. */
const CPU_ID_FROM_VERSION = 3;

/** The policy bit that must be one, and the first of the bits that must be zero. */
const POLICY_RESERVED_ONE_BIT = 17n;
const POLICY_FIRST_ZERO_BIT = 26n;

export interface GuestPolicy {
  abiMinor: number;
  abiMajor: number;
  smt: boolean;
  migrationAgent: boolean;
  debug: boolean;
  singleSocket: boolean;
  cxl: boolean;
  aes256Xts: boolean;
}

export interface PlatformInfo {
  smt: boolean;
  tsme: boolean;
}

export interface FirmwareVersion {
  build: number;
  minor: number;
  major: number;
}

export interface SignerInfo {
  signingKey: number;
  maskChipKey: boolean;
  authorKey: boolean;
}

/** A parsed attestation report of AMD SEV-SNP. */
export interface SnpReport {
  version: number;
  guestSvn: number;
  policy: GuestPolicy;
  vmpl: number;
  signatureAlgorithm: number;
  currentTcb: TcbLevels;
  reportedTcb: TcbLevels;
  committedTcb: TcbLevels;
  launchTcb: TcbLevels;
  /** True when CURRENT_TCB and COMMITTED_TCB hold the same value. */
  tcbCommitted: boolean;
  platformInfo: PlatformInfo;
  signerInfo: SignerInfo;
  reportData: Uint8Array;
  measurement: Uint8Array;
  hostData: Uint8Array;
  chipId: Uint8Array;
  currentFirmware: FirmwareVersion;
  committedFirmware: FirmwareVersion;
  product: AmdProduct;
  /** The bytes that the signature covers. */
  signedBytes: Uint8Array;
  /** R and S of the signature, little-endian, 72 bytes each. */
  signatureR: Uint8Array;
  signatureS: Uint8Array;
}

/** Parses a raw report and checks every field that must be zero. Throws on a malformed report. */
export function parseSnpReport(bytes: Uint8Array): SnpReport {
  if (bytes.length !== LAYOUT.size) {
    throw new Error(`The report has ${String(bytes.length)} bytes, not ${String(LAYOUT.size)}.`);
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const version = view.getUint32(LAYOUT.version, true);
  checkReservedBytes(bytes, version);
  const currentTcb = view.getBigUint64(LAYOUT.currentTcb, true);
  const committedTcb = view.getBigUint64(LAYOUT.committedTcb, true);
  return {
    version,
    guestSvn: view.getUint32(LAYOUT.guestSvn, true),
    policy: parsePolicy(view.getBigUint64(LAYOUT.policy, true)),
    vmpl: view.getUint32(LAYOUT.vmpl, true),
    signatureAlgorithm: view.getUint32(LAYOUT.signatureAlgorithm, true),
    currentTcb: parseTcb(currentTcb, 'CURRENT_TCB'),
    reportedTcb: parseTcb(view.getBigUint64(LAYOUT.reportedTcb, true), 'REPORTED_TCB'),
    committedTcb: parseTcb(committedTcb, 'COMMITTED_TCB'),
    launchTcb: parseTcb(view.getBigUint64(LAYOUT.launchTcb, true), 'LAUNCH_TCB'),
    tcbCommitted: currentTcb === committedTcb,
    platformInfo: parsePlatformInfo(view.getBigUint64(LAYOUT.platformInfo, true)),
    signerInfo: parseSignerInfo(view.getUint32(LAYOUT.signerInfo, true)),
    reportData: slice(bytes, LAYOUT.reportData),
    measurement: slice(bytes, LAYOUT.measurement),
    hostData: slice(bytes, LAYOUT.hostData),
    chipId: slice(bytes, LAYOUT.chipId),
    currentFirmware: parseFirmware(view, LAYOUT.currentFirmware),
    committedFirmware: parseFirmware(view, LAYOUT.committedFirmware),
    product: parseProduct(view, version),
    signedBytes: bytes.slice(0, LAYOUT.signature),
    signatureR: bytes.slice(LAYOUT.signature, LAYOUT.signature + SIGNATURE_PART_BYTES),
    signatureS: bytes.slice(
      LAYOUT.signature + SIGNATURE_PART_BYTES,
      LAYOUT.signature + 2 * SIGNATURE_PART_BYTES,
    ),
  };
}

function slice(bytes: Uint8Array, [start, end]: readonly [number, number]): Uint8Array {
  return bytes.slice(start, end);
}

function checkReservedBytes(bytes: Uint8Array, version: number): void {
  const cpuIdEnd = version >= CPU_ID_FROM_VERSION ? LAYOUT.cpuStepping + 1 : LAYOUT.cpuFamily;
  const beforeSignature =
    version >= MITIGATION_VECTORS_FROM_VERSION
      ? LAYOUT.mitigationVectorsEnd
      : LAYOUT.reservedBeforeSignature;
  const ranges: [number, number][] = [
    [...LAYOUT.reserved1],
    [cpuIdEnd, LAYOUT.cpuIdReservedEnd],
    [...LAYOUT.reserved3],
    [...LAYOUT.reserved4],
    [beforeSignature, LAYOUT.signature],
    [LAYOUT.signature + 2 * SIGNATURE_PART_BYTES, LAYOUT.size],
  ];
  for (const [start, end] of ranges) {
    if (!isAllZero(bytes.subarray(start, end))) {
      throw new Error(`The report has data in reserved bytes 0x${start.toString(16)}.`);
    }
  }
}

function bit(value: bigint, index: number): boolean {
  return ((value >> BigInt(index)) & 1n) === 1n;
}

function byte(value: bigint, index: number): number {
  return Number((value >> BigInt(index * 8)) & 0xffn);
}

function parsePolicy(value: bigint): GuestPolicy {
  if (!bit(value, Number(POLICY_RESERVED_ONE_BIT))) {
    throw new Error('The reserved bit 17 of the guest policy is not set.');
  }
  if (value >> POLICY_FIRST_ZERO_BIT !== 0n) {
    throw new Error('The reserved bits 26 to 63 of the guest policy are not zero.');
  }
  return {
    abiMinor: byte(value, 0),
    abiMajor: byte(value, 1),
    smt: bit(value, 16),
    migrationAgent: bit(value, 18),
    debug: bit(value, 19),
    singleSocket: bit(value, 20),
    cxl: bit(value, 21),
    aes256Xts: bit(value, 22),
  };
}

/** A TCB version of Genoa: bootloader, TEE, 32 reserved bits, SNP, and microcode. */
function parseTcb(value: bigint, field: string): TcbLevels {
  if (((value >> 16n) & 0xffffffffn) !== 0n) {
    throw new Error(`The reserved bits of ${field} are not zero.`);
  }
  return {
    bootloader: byte(value, 0),
    tee: byte(value, 1),
    snp: byte(value, 6),
    microcode: byte(value, 7),
  };
}

function parsePlatformInfo(value: bigint): PlatformInfo {
  return { smt: bit(value, 0), tsme: bit(value, 1) };
}

function parseSignerInfo(value: number): SignerInfo {
  if (value >>> 5 !== 0) {
    throw new Error('The reserved bits of SIGNER_INFO are not zero.');
  }
  return {
    authorKey: (value & 0b1) !== 0,
    maskChipKey: (value & 0b10) !== 0,
    signingKey: (value >>> 2) & 0b111,
  };
}

function parseFirmware(view: DataView, offset: number): FirmwareVersion {
  return {
    build: view.getUint8(offset),
    minor: view.getUint8(offset + 1),
    major: view.getUint8(offset + 2),
  };
}

/**
 * A report of version 2 carries no CPU ID. The verifier accepts only Genoa, so it reads such a report
 * as Genoa; a report of another product then fails the chain of certificates.
 */
function parseProduct(view: DataView, version: number): AmdProduct {
  if (version < CPU_ID_FROM_VERSION) {
    return 'Genoa';
  }
  const family = view.getUint8(LAYOUT.cpuFamily);
  const model = view.getUint8(LAYOUT.cpuModel);
  const product = AMD_PRODUCTS.find(
    (name) => AMD_CPU_IDS[name].family === family && AMD_CPU_IDS[name].model === model,
  );
  if (product === undefined) {
    throw new Error(
      `The CPU of the report (family 0x${family.toString(16)}, model 0x${model.toString(16)}) is not supported.`,
    );
  }
  return product;
}
