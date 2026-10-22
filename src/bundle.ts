import { FETCH_TIMEOUT_MS, SOURCES } from './config/sources.js';
import { TINFOIL } from './config/tinfoil.js';
import { gunzip, fromBase64, toBase64, toHex } from './lib/bytes.js';
import { parseSnpReport } from './amd/report.js';
import { isRecord } from './lib/json.js';

/** Everything a verification needs, gathered before it starts. */
export interface AttestationBundle {
  /** The host of the enclave, such as `inference.tinfoil.sh`. */
  enclaveHost: string;
  /** The attestation document that the enclave serves. */
  attestation: { format: string; body: string };
  /** The SHA-256 of the deployment of the release, as hex. */
  releaseDigest: string;
  /** The tag of the release, when the source names it. */
  releaseTag: string | undefined;
  /** The Sigstore bundle of the release, as JSON. */
  sigstoreBundle: unknown;
  /** The VCEK of the chip, DER in base64. */
  vcek: string;
  /** The TLS certificate of the enclave, PEM. */
  enclaveCertificate: string;
}

/** Which enclave and repository a bundle service builds the bundle for. */
export interface BundleTarget {
  enclaveUrl: string;
  repo: string;
}

function requiredString(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  if (typeof value !== 'string' || value === '') {
    throw new Error(`The bundle has no ${field}.`);
  }
  return value;
}

/**
 * Reads a bundle in the JSON form that the attestation service of Tinfoil and the proxy of Thinkr
 * serve: `domain`, `enclaveAttestationReport`, `digest`, `releaseTag`, `sigstoreBundle`, `vcek`,
 * and `enclaveCert`.
 */
export function parseBundle(json: unknown): AttestationBundle {
  if (!isRecord(json) || !isRecord(json.enclaveAttestationReport)) {
    throw new Error('The bundle is not a JSON object with an attestation document.');
  }
  const document = json.enclaveAttestationReport;
  const tag = json.releaseTag;
  return {
    enclaveHost: requiredString(json, 'domain'),
    attestation: {
      format: requiredString(document, 'format'),
      body: requiredString(document, 'body'),
    },
    releaseDigest: requiredString(json, 'digest').toLowerCase(),
    releaseTag: typeof tag === 'string' && tag !== '' ? tag : undefined,
    sigstoreBundle: json.sigstoreBundle,
    vcek: requiredString(json, 'vcek'),
    enclaveCertificate: requiredString(json, 'enclaveCert'),
  };
}

/**
 * Fetches a bundle from a bundle service, such as the proxy of Thinkr. With a target, it asks for
 * the bundle of that enclave and repository; without one, for the default router.
 */
export async function fetchBundle(url: string, target?: BundleTarget): Promise<AttestationBundle> {
  if (!url.startsWith('https://')) {
    throw new Error('A bundle must come over HTTPS.');
  }
  const init: RequestInit =
    target === undefined
      ? {}
      : {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enclaveUrl: target.enclaveUrl, repo: target.repo }),
        };
  return parseBundle(await (await fetchOk(url, init)).json());
}

/**
 * Builds the bundle with no service of Tinfoil in between: the attestation document and the
 * certificate from the enclave, the release from GitHub, and the VCEK from AMD. Runs in Node; a
 * browser cannot reach AMD for lack of CORS.
 */
export async function assembleBundle(
  enclaveHost: string,
  repo: string,
): Promise<AttestationBundle> {
  const enclave = `https://${enclaveHost}`;
  const [attestation, certificate, release] = await Promise.all([
    fetchJson(`${enclave}${TINFOIL.attestationPath}`),
    fetchJson(`${enclave}${TINFOIL.certificatePath}`),
    latestRelease(repo),
  ]);
  if (!isRecord(attestation) || !isRecord(certificate)) {
    throw new Error('The enclave served no attestation document or no certificate.');
  }
  const body = requiredString(attestation, 'body');
  const sigstore = await fetchJson(
    `${SOURCES.githubApi}/repos/${repo}/attestations/sha256:${release.digest}`,
  );
  return {
    enclaveHost,
    attestation: { format: requiredString(attestation, 'format'), body },
    releaseDigest: release.digest,
    releaseTag: release.tag,
    sigstoreBundle: firstSigstoreBundle(sigstore),
    vcek: toBase64(await fetchVcek(body)),
    enclaveCertificate: requiredString(certificate, 'certificate'),
  };
}

async function latestRelease(repo: string): Promise<{ tag: string; digest: string }> {
  const release = await fetchJson(`${SOURCES.githubApi}/repos/${repo}/releases/latest`);
  if (!isRecord(release)) {
    throw new Error(`GitHub returned no release for ${repo}.`);
  }
  const tag = requiredString(release, 'tag_name');
  const asset = `${SOURCES.githubWeb}/${repo}/releases/download/${tag}/${TINFOIL.releaseDigestAsset}`;
  const digest = (await (await fetchOk(asset)).text()).trim().toLowerCase();
  return { tag, digest };
}

function firstSigstoreBundle(response: unknown): unknown {
  const attestations = isRecord(response) ? response.attestations : undefined;
  const first: unknown = Array.isArray(attestations) ? attestations[0] : undefined;
  if (!isRecord(first) || first.bundle === undefined) {
    throw new Error('GitHub holds no Sigstore bundle for the digest of the release.');
  }
  return first.bundle;
}

/** The VCEK of the chip and TCB that the report names, from the key distribution service of AMD. */
async function fetchVcek(attestationBody: string): Promise<Uint8Array> {
  const report = parseSnpReport(await gunzip(fromBase64(attestationBody)));
  const tcb = report.reportedTcb;
  const query = new URLSearchParams({
    blSPL: String(tcb.bootloader),
    teeSPL: String(tcb.tee),
    snpSPL: String(tcb.snp),
    ucodeSPL: String(tcb.microcode),
  });
  const url = `${SOURCES.amdKds}/vcek/v1/${report.product}/${toHex(report.chipId)}?${query.toString()}`;
  return new Uint8Array(await (await fetchOk(url)).arrayBuffer());
}

async function fetchOk(url: string, init: RequestInit = {}): Promise<Response> {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!response.ok) {
    throw new Error(`${url} answered ${String(response.status)}.`);
  }
  return response;
}

async function fetchJson(url: string): Promise<unknown> {
  return (await fetchOk(url)).json();
}
