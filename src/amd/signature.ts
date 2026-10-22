import { ownBytes, reversed } from '../lib/bytes.js';
import type { SnpReport } from './report.js';

/** The size of R and of S of a P-384 signature in the raw form of WebCrypto. */
const P384_PART_BYTES = 48;

/**
 * True when the VCEK signed the report. The report stores R and S little-endian in 72 bytes each;
 * WebCrypto takes them big-endian in 48 bytes each.
 */
export async function verifyReportSignature(
  report: SnpReport,
  vcekKey: CryptoKey,
): Promise<boolean> {
  const signature = new Uint8Array(2 * P384_PART_BYTES);
  signature.set(toP384Part(report.signatureR), 0);
  signature.set(toP384Part(report.signatureS), P384_PART_BYTES);
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-384' },
    vcekKey,
    signature,
    ownBytes(report.signedBytes),
  );
}

/** One half of the signature, big-endian, in 48 bytes; throws when it does not fit. */
function toP384Part(littleEndian: Uint8Array): Uint8Array {
  const bigEndian = reversed(littleEndian);
  const padding = bigEndian.subarray(0, bigEndian.length - P384_PART_BYTES);
  if (padding.some((byte) => byte !== 0)) {
    throw new Error('A part of the report signature is longer than 48 bytes.');
  }
  return bigEndian.slice(bigEndian.length - P384_PART_BYTES);
}
