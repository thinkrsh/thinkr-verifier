import type { TcbLevels } from '../config/amd.js';
import type { AmdProduct } from '../config/amdRoots.js';
import { fromBase64, gunzip, toHex } from '../lib/bytes.js';
import { verifyAmdChain } from './chain.js';
import { checkSnpPolicy } from './policy.js';
import { parseSnpReport } from './report.js';
import { verifyReportSignature } from './signature.js';

/** REPORT_DATA holds the fingerprint of the TLS key, then the HPKE key of the enclave. */
const TLS_KEY_FINGERPRINT_BYTES = 32;
const HPKE_KEY_BYTES = 32;

/** What a verified report of AMD SEV-SNP says about the enclave. */
export interface VerifiedHardware {
  product: AmdProduct;
  /** The launch measurement of the enclave, 48 bytes, as hex. */
  measurement: string;
  /** The SHA-256 of the TLS public key of the enclave, as hex. */
  tlsKeyFingerprint: string;
  /** The X25519 public key that EHBP encrypts to, as hex. */
  hpkePublicKey: string;
  reportedTcb: TcbLevels;
}

/**
 * Verifies an attestation document of AMD SEV-SNP (a gzip of the raw report, in base64) with the
 * VCEK of its chip, at the time `now`. Throws on any failure.
 */
export async function verifySevSnpDocument(
  body: string,
  vcekDer: Uint8Array,
  now: Date,
): Promise<VerifiedHardware> {
  const report = parseSnpReport(await gunzip(fromBase64(body)));
  const vcek = await verifyAmdChain(report.product, vcekDer, now);
  if (!(await verifyReportSignature(report, vcek.publicKey))) {
    throw new Error('The signature of the report does not match the VCEK.');
  }
  checkSnpPolicy(report, vcek);
  return {
    product: report.product,
    measurement: toHex(report.measurement),
    tlsKeyFingerprint: toHex(report.reportData.subarray(0, TLS_KEY_FINGERPRINT_BYTES)),
    hpkePublicKey: toHex(
      report.reportData.subarray(
        TLS_KEY_FINGERPRINT_BYTES,
        TLS_KEY_FINGERPRINT_BYTES + HPKE_KEY_BYTES,
      ),
    ),
    reportedTcb: report.reportedTcb,
  };
}
