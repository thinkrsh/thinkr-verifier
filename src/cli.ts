#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { assembleBundle, fetchBundle, type AttestationBundle } from './bundle.js';
import { SOURCES } from './config/sources.js';
import { TINFOIL } from './config/tinfoil.js';
import { VerificationError, type VerificationStep } from './errors.js';
import { verifyBundle, type Verification } from './verify.js';

const USAGE = `Usage: thinkr-verify [--bundle <url> | --enclave <host>] [--repo <owner/name>] [--json]

Verifies the enclave of the private lane of Thinkr on this machine.

  --bundle <url>    Fetch the attestation bundle from a bundle service.
                    Default: ${SOURCES.thinkrBundle}
  --enclave <host>  Build the bundle from the enclave, GitHub, and AMD, with no service between.
  --repo <name>     The repository whose signed release the enclave must run.
                    Default: ${TINFOIL.routerRepo}
  --json            Print the result as JSON.
  --help            Print this help.`;

const STEP_LABELS: Readonly<Record<VerificationStep, string>> = {
  bundle: 'The bundle is complete',
  hardware: 'AMD signed the report of the enclave',
  code: 'The release is signed in Sigstore',
  measurement: 'The enclave runs that release',
  keys: 'The certificate carries the attested keys',
};

/** Shortens a long hex value to its start and end, for the terminal. */
function short(hex: string): string {
  return `${hex.slice(0, 12)}…${hex.slice(-12)}`;
}

function summary(verification: Verification): string {
  const { hardware } = verification;
  return [
    `Enclave      ${verification.enclaveHost}`,
    `Release      ${verification.repo} ${verification.releaseTag}`,
    `Image        ${verification.imageVersion ?? 'not named'}`,
    `Hardware     AMD SEV-SNP, ${hardware.product}`,
    `Measurement  ${short(hardware.measurement)}`,
    `TLS key      ${short(hardware.tlsKeyFingerprint)}`,
    `HPKE key     ${short(hardware.hpkePublicKey)}`,
  ].join('\n');
}

async function loadBundle(values: {
  bundle?: string;
  enclave?: string;
  repo: string;
}): Promise<AttestationBundle> {
  if (values.enclave !== undefined) {
    return assembleBundle(values.enclave, values.repo);
  }
  return fetchBundle(values.bundle ?? SOURCES.thinkrBundle);
}

async function main(): Promise<number> {
  const { values } = parseArgs({
    options: {
      bundle: { type: 'string' },
      enclave: { type: 'string' },
      repo: { type: 'string', default: TINFOIL.routerRepo },
      json: { type: 'boolean', default: false },
      help: { type: 'boolean', default: false },
    },
  });
  if (values.help) {
    console.log(USAGE);
    return 0;
  }
  if (values.bundle !== undefined && values.enclave !== undefined) {
    console.error('Give --bundle or --enclave, not both.');
    return 2;
  }
  const print = (step: VerificationStep): void => {
    if (!values.json) console.log(`pass  ${STEP_LABELS[step]}`);
  };
  try {
    const bundle = await loadBundle({ ...values, repo: values.repo });
    const verification = await verifyBundle(bundle, { repo: values.repo, onStep: print });
    console.log(values.json ? JSON.stringify(verification, null, 2) : `\n${summary(verification)}`);
    return 0;
  } catch (error) {
    const step = error instanceof VerificationError ? error.step : 'bundle';
    const message = error instanceof Error ? error.message : String(error);
    console.error(
      values.json
        ? JSON.stringify({ step, error: message })
        : `fail  ${STEP_LABELS[step]}: ${message}`,
    );
    return 1;
  }
}

process.exitCode = await main();
