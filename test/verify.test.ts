import { Verifier } from '@tinfoilsh/verifier';
import { describe, expect, it } from 'vitest';
import { parseBundle, type AttestationBundle } from '../src/bundle.js';
import { VerificationError, type VerificationStep } from '../src/errors.js';
import { fromBase64, gunzip, toBase64 } from '../src/lib/bytes.js';
import { verifyBundle } from '../src/verify.js';
import {
  FIXTURE_TIME,
  readFixture,
  ROUTER_REPO,
  routerBundle,
  routerBundleJson,
} from './fixtures.js';

async function expectStepFailure(
  bundle: AttestationBundle,
  step: VerificationStep,
  options: { repo?: string; now?: Date } = {},
): Promise<VerificationError> {
  const result = verifyBundle(bundle, {
    repo: options.repo ?? ROUTER_REPO,
    now: options.now ?? FIXTURE_TIME,
  });
  await expect(result).rejects.toBeInstanceOf(VerificationError);
  const error = (await result.catch((caught: unknown) => caught)) as VerificationError;
  expect(error.step).toBe(step);
  return error;
}

/** The attestation document with one byte of its report changed, gzipped again. */
async function tamperedBody(body: string, offset: number): Promise<string> {
  const report = Uint8Array.from(await gunzip(fromBase64(body)));
  report[offset] = (report[offset] ?? 0) ^ 0xff;
  const stream = new Blob([report]).stream().pipeThrough(new CompressionStream('gzip'));
  return toBase64(new Uint8Array(await new Response(stream).arrayBuffer()));
}

describe('verifyBundle', () => {
  it('verifies the router of Tinfoil, every step in order', async () => {
    const steps: VerificationStep[] = [];
    const verification = await verifyBundle(routerBundle(), {
      repo: ROUTER_REPO,
      now: FIXTURE_TIME,
      onStep: (step) => steps.push(step),
    });
    expect(steps).toEqual(['bundle', 'hardware', 'code', 'measurement', 'keys']);
    expect(verification.releaseTag).toBe('v0.0.166');
    expect(verification.imageVersion).toBe('v0.14.15');
    expect(verification.hardware.product).toBe('Genoa');
    expect(verification.hardware.hpkePublicKey).toBe(
      '602da6296ca7a1a03922f4ea0a00c42a9001cf5b8cb72aa6f94413bd609e8378',
    );
  });

  it('reaches the same result as the verifier of Tinfoil', async () => {
    const theirs = await new Verifier({ configRepo: ROUTER_REPO }).verifyBundle({
      ...(routerBundleJson() as unknown as Parameters<Verifier['verifyBundle']>[0]),
    });
    const ours = await verifyBundle(routerBundle(), { repo: ROUTER_REPO, now: FIXTURE_TIME });
    expect(ours.hardware.measurement).toBe(theirs.measurement.registers[0]);
    expect(ours.hardware.hpkePublicKey).toBe(theirs.hpkePublicKey);
    expect(ours.hardware.tlsKeyFingerprint).toBe(theirs.tlsPublicKeyFingerprint);
  });

  it('fails the hardware step when a byte of the report changes', async () => {
    const bundle = routerBundle();
    const body = await tamperedBody(bundle.attestation.body, 0x90);
    await expectStepFailure(
      { ...bundle, attestation: { ...bundle.attestation, body } },
      'hardware',
    );
  });

  it('fails the hardware step once the VCEK has expired', async () => {
    await expectStepFailure(routerBundle(), 'hardware', { now: new Date('2040-01-01T00:00:00Z') });
  });

  it('fails the hardware step when the signature of the VCEK changes', async () => {
    const bundle = routerBundle();
    const vcek = Uint8Array.from(fromBase64(bundle.vcek));
    vcek[vcek.length - 1] = (vcek[vcek.length - 1] ?? 0) ^ 0x01;
    const error = await expectStepFailure({ ...bundle, vcek: toBase64(vcek) }, 'hardware');
    expect(error.message).toMatch(/not signed by the ASK/);
  });

  it('fails the code step when the signature of the release changes', async () => {
    const bundle = routerBundle();
    const sigstore = structuredClone(bundle.sigstoreBundle) as {
      dsseEnvelope: { signatures: { sig: string }[] };
    };
    const [signature] = sigstore.dsseEnvelope.signatures;
    if (signature === undefined) throw new Error('The fixture has no signature.');
    const bytes = Uint8Array.from(fromBase64(signature.sig));
    bytes[bytes.length - 1] = (bytes[bytes.length - 1] ?? 0) ^ 0x01;
    signature.sig = toBase64(bytes);
    await expectStepFailure({ ...bundle, sigstoreBundle: sigstore }, 'code');
  });

  it('fails the code step when the signed statement changes', async () => {
    const bundle = routerBundle();
    const sigstore = structuredClone(bundle.sigstoreBundle) as {
      dsseEnvelope: { payload: string };
    };
    const statement = new TextDecoder().decode(fromBase64(sigstore.dsseEnvelope.payload));
    const forged = statement.replace(/"snp_measurement":"[0-9a-f]{2}/, '"snp_measurement":"00');
    expect(forged).not.toBe(statement);
    sigstore.dsseEnvelope.payload = toBase64(new TextEncoder().encode(forged));
    await expectStepFailure({ ...bundle, sigstoreBundle: sigstore }, 'code');
  });

  it('fails the code step for a release of another repository', async () => {
    await expectStepFailure(routerBundle(), 'code', { repo: 'tinfoilsh/tinfoil-webapp' });
  });

  it('fails the code step when the digest is not the signed one', async () => {
    const bundle = { ...routerBundle(), releaseDigest: '00'.repeat(32) };
    await expectStepFailure(bundle, 'code');
  });

  it('fails the code step when the source names another tag', async () => {
    await expectStepFailure({ ...routerBundle(), releaseTag: 'v0.0.165' }, 'code');
  });

  it('fails the measurement step for a signed release the enclave does not run', async () => {
    const older = readFixture('router-release-v0.0.162.json') as {
      digest: string;
      sigstoreBundle: unknown;
    };
    const bundle = {
      ...routerBundle(),
      releaseDigest: older.digest,
      releaseTag: undefined,
      sigstoreBundle: older.sigstoreBundle,
    };
    await expectStepFailure(bundle, 'measurement');
  });

  it('fails the keys step for the certificate of another enclave', async () => {
    const other = readFixture('router-0-certificate.json') as { certificate: string };
    await expectStepFailure({ ...routerBundle(), enclaveCertificate: other.certificate }, 'keys');
  });

  it('fails the keys step when the host is not the one of the certificate', async () => {
    await expectStepFailure({ ...routerBundle(), enclaveHost: 'router-0.tinfoil.sh' }, 'keys');
  });

  it('fails the bundle step for an unknown attestation format', async () => {
    const bundle = routerBundle();
    const attestation = { ...bundle.attestation, format: 'https://example.com/predicate/v1' };
    await expectStepFailure({ ...bundle, attestation }, 'bundle');
  });

  it('rejects JSON that is not a bundle', () => {
    expect(() => parseBundle({ domain: 'x' })).toThrow(/attestation document/);
  });
});
