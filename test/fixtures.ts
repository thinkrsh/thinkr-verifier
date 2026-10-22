import { readFileSync } from 'node:fs';
import { parseBundle, type AttestationBundle } from '../src/bundle.js';
import { fromBase64, gunzip } from '../src/lib/bytes.js';

/** The time of the fixtures: the bundle of the router of Tinfoil, fetched on 23 Oct 2026. */
export const FIXTURE_TIME = new Date('2026-10-23T12:00:00Z');

/** The repository whose release v0.0.166 the router ran on 23 Oct 2026. */
export const ROUTER_REPO = 'tinfoilsh/confidential-model-router';

export function readFixture(name: string): unknown {
  return JSON.parse(readFileSync(new URL(`fixtures/${name}`, import.meta.url), 'utf8'));
}

/** The bundle as the attestation service of Tinfoil served it, raw JSON. */
export function routerBundleJson(): Record<string, unknown> {
  return readFixture('router-bundle-2026-10-23.json') as Record<string, unknown>;
}

export function routerBundle(): AttestationBundle {
  return parseBundle(routerBundleJson());
}

export async function routerReportBytes(): Promise<Uint8Array> {
  return gunzip(fromBase64(routerBundle().attestation.body));
}
