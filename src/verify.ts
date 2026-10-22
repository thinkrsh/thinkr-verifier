import { verifySevSnpDocument, type VerifiedHardware } from './amd/index.js';
import type { AttestationBundle } from './bundle.js';
import { verifyRelease, type VerifiedRelease } from './code/release.js';
import { FORMATS } from './config/release.js';
import { verifyEnclaveCertificate } from './enclave/certificate.js';
import { VerificationError, type VerificationStep } from './errors.js';
import { fromBase64, sha256Hex } from './lib/bytes.js';

export interface VerifyOptions {
  /** The repository whose signed releases the enclave must run, such as the router of Tinfoil. */
  repo: string;
  /** The time at which the certificates must be valid; now by default. */
  now?: Date;
  /** Called after each step passes, in order. */
  onStep?: (step: VerificationStep) => void;
}

/** The result of a verification that passed every step. */
export interface Verification {
  enclaveHost: string;
  repo: string;
  releaseTag: string;
  releaseDigest: string;
  /** The version of the confidential VM image of the release, when it names one. */
  imageVersion: string | undefined;
  hardware: VerifiedHardware;
  /** The SHA-256 of the attestation document, which the certificate of the enclave names. */
  attestationHash: string;
  certificateNotAfter: Date;
  verifiedAt: Date;
}

/**
 * Verifies an enclave from its bundle, in four steps after the bundle itself: the hardware (the
 * report of AMD SEV-SNP and its chain to AMD), the code (the signed release in Sigstore), the
 * measurement (the enclave runs that release), and the keys (the certificate carries the attested
 * keys). Throws a `VerificationError` that names the step that failed.
 */
export async function verifyBundle(
  bundle: AttestationBundle,
  options: VerifyOptions,
): Promise<Verification> {
  const now = options.now ?? new Date();
  const pass = (step: VerificationStep): void => options.onStep?.(step);
  if (bundle.attestation.format !== FORMATS.sevSnpGuestV2) {
    throw new VerificationError(
      'bundle',
      `The format ${bundle.attestation.format} is not supported.`,
    );
  }
  pass('bundle');
  const hardware = await runStep('hardware', () =>
    verifySevSnpDocument(bundle.attestation.body, fromBase64(bundle.vcek), now),
  );
  pass('hardware');
  const release = await runStep('code', () => verifyCode(bundle, options.repo));
  pass('code');
  if (release.snpMeasurement !== hardware.measurement) {
    throw new VerificationError('measurement', 'The enclave does not run the signed release.');
  }
  pass('measurement');
  const attestationHash = await sha256Hex(
    new TextEncoder().encode(bundle.attestation.format + bundle.attestation.body),
  );
  const certificate = await runStep('keys', () =>
    verifyEnclaveCertificate(bundle.enclaveCertificate, bundle.enclaveHost, {
      tlsKeyFingerprint: hardware.tlsKeyFingerprint,
      hpkePublicKey: hardware.hpkePublicKey,
      attestationHash,
    }),
  );
  pass('keys');
  return {
    enclaveHost: bundle.enclaveHost,
    repo: options.repo,
    releaseTag: release.releaseTag,
    releaseDigest: bundle.releaseDigest,
    imageVersion: release.imageVersion,
    hardware,
    attestationHash,
    certificateNotAfter: certificate.notAfter,
    verifiedAt: now,
  };
}

/** The signed release must cover the digest, and its tag must be the tag the source named. */
async function verifyCode(bundle: AttestationBundle, repo: string): Promise<VerifiedRelease> {
  const release = await verifyRelease(bundle.sigstoreBundle, bundle.releaseDigest, repo);
  if (bundle.releaseTag !== undefined && bundle.releaseTag !== release.releaseTag) {
    throw new Error(`The source named ${bundle.releaseTag}, but ${release.releaseTag} was signed.`);
  }
  return release;
}

async function runStep<T>(step: VerificationStep, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new VerificationError(step, message, { cause: error });
  }
}
