import {
  AllOf,
  GITHUB_OIDC_ISSUER,
  GitHubWorkflowRepository,
  OIDCIssuer,
  SigstoreVerifier,
  type SigstoreBundle,
  type VerificationPolicy,
  type X509Certificate,
} from '@freedomofpress/sigstore-browser';
import { FORMATS, SIGNED_RELEASE } from '../config/release.js';
import { SIGSTORE_TRUSTED_ROOT } from '../config/sigstoreTrustedRoot.js';
import { isRecord } from '../lib/json.js';

/** An SNP launch measurement is 48 bytes: 96 hex characters. */
const SNP_MEASUREMENT_PATTERN = /^[0-9a-f]{96}$/;

/** What a verified release says the enclave must run. */
export interface VerifiedRelease {
  /** The tag of the release, from the identity of the workflow that signed it. */
  releaseTag: string;
  /** The expected SNP launch measurement, as hex. */
  snpMeasurement: string;
  /** The version of the confidential VM image, when the predicate names it. */
  imageVersion: string | undefined;
}

/**
 * Verifies the Sigstore bundle of a release of `repo`: the DSSE signature, the certificate from
 * Fulcio, the entry in Rekor, and the identity of the GitHub workflow, which must run on a tag. Then
 * checks that the statement covers `digest` and reads the expected measurement. Throws on failure.
 */
export async function verifyRelease(
  bundle: unknown,
  digest: string,
  repo: string,
): Promise<VerifiedRelease> {
  const tagPolicy = new TagRefPolicy();
  const verifier = new SigstoreVerifier();
  await verifier.loadSigstoreRoot(SIGSTORE_TRUSTED_ROOT);
  const envelope = await verifier.verifyDsse(
    asDsseBundle(bundle),
    new AllOf([new OIDCIssuer(GITHUB_OIDC_ISSUER), new GitHubWorkflowRepository(repo), tagPolicy]),
  );
  if (envelope.payloadType !== SIGNED_RELEASE.payloadType) {
    throw new Error(`The release signs a payload of type ${envelope.payloadType}.`);
  }
  const statement = parseStatement(envelope.payload);
  checkSubject(statement, digest);
  return { releaseTag: tagPolicy.tag(), ...readPredicate(statement) };
}

/** The workflow ref of the signing certificate must be a tag; its name is the release tag. */
class TagRefPolicy implements VerificationPolicy {
  private verifiedTag: string | undefined;

  verify(certificate: X509Certificate): void {
    const ref = certificate.extGitHubWorkflowRef?.workflowRef;
    if (ref?.startsWith(SIGNED_RELEASE.tagRefPrefix) !== true) {
      throw new Error(`The release was not signed from a tag (ref ${String(ref)}).`);
    }
    this.verifiedTag = ref.slice(SIGNED_RELEASE.tagRefPrefix.length);
  }

  tag(): string {
    if (this.verifiedTag === undefined) {
      throw new Error('The tag of the release was not verified.');
    }
    return this.verifiedTag;
  }
}

/** Accepts only the v0.3 layout with one certificate and a DSSE envelope. */
function asDsseBundle(bundle: unknown): SigstoreBundle {
  if (!isRecord(bundle) || bundle.mediaType !== SIGNED_RELEASE.bundleMediaType) {
    throw new Error(`The release bundle is not a Sigstore bundle v0.3.`);
  }
  const material = bundle.verificationMaterial;
  if (!isRecord(material) || !isRecord(material.certificate)) {
    throw new Error('The release bundle carries no signing certificate.');
  }
  if (material.x509CertificateChain !== undefined) {
    throw new Error('The release bundle carries a certificate chain, which v0.3 forbids.');
  }
  if (!isRecord(bundle.dsseEnvelope) || !Array.isArray(material.tlogEntries)) {
    throw new Error('The release bundle carries no DSSE envelope or no log entry.');
  }
  return bundle as unknown as SigstoreBundle;
}

function parseStatement(payload: Uint8Array): Record<string, unknown> {
  const statement: unknown = JSON.parse(new TextDecoder().decode(payload));
  if (!isRecord(statement)) {
    throw new Error('The statement of the release is not a JSON object.');
  }
  const allowed: readonly string[] = SIGNED_RELEASE.statementFields;
  const unknown = Object.keys(statement).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) {
    throw new Error(`The statement has unknown fields: ${unknown.join(', ')}.`);
  }
  return statement;
}

/** The statement must name exactly one subject, whose SHA-256 is the digest of the release. */
function checkSubject(statement: Record<string, unknown>, digest: string): void {
  const subjects = statement.subject;
  if (!Array.isArray(subjects) || subjects.length !== 1) {
    throw new Error('The statement must name exactly one subject.');
  }
  const [subject] = subjects as unknown[];
  const subjectDigest = isRecord(subject) && isRecord(subject.digest) ? subject.digest : {};
  if (subjectDigest.sha256 !== digest.toLowerCase()) {
    throw new Error('The signed release does not cover the digest of the release.');
  }
}

function readPredicate(
  statement: Record<string, unknown>,
): Pick<VerifiedRelease, 'snpMeasurement' | 'imageVersion'> {
  if (statement.predicateType !== FORMATS.snpTdxMultiplatformV1) {
    throw new Error(`The predicate type ${String(statement.predicateType)} is not supported.`);
  }
  const predicate = statement.predicate;
  const measurement = isRecord(predicate) ? predicate.snp_measurement : undefined;
  if (typeof measurement !== 'string' || !SNP_MEASUREMENT_PATTERN.test(measurement)) {
    throw new Error('The predicate has no valid SNP measurement.');
  }
  const hashes = isRecord(predicate) ? predicate.hashes : undefined;
  const version = isRecord(hashes) ? hashes.version : undefined;
  return {
    snpMeasurement: measurement,
    imageVersion: typeof version === 'string' ? version : undefined,
  };
}
