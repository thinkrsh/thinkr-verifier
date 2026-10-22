import type { CipherSuite, Key } from 'hpke';
import { EHBP } from '../config/ehbp.js';
import { EhbpError } from '../errors.js';
import { concatBytes } from '../lib/bytes.js';
import { frame } from './frames.js';

/** A request body sealed to the enclave, with what the response needs. */
export interface SealedBody {
  /** The HPKE encapsulated key, sent in the header `Ehbp-Encapsulated-Key`. */
  encapsulatedKey: Uint8Array;
  /** The frames of the sealed body, in order. */
  framed: Uint8Array;
  /** The secret exported from the request context, from which the response keys derive. */
  exportedSecret: Uint8Array;
}

const encoder = new TextEncoder();

/**
 * Seals a body to the key of the enclave (section 4.4.1): one HPKE context for the whole body, one
 * frame for each 64 KiB of plaintext, then the export of the response secret.
 */
export async function sealBody(
  suite: CipherSuite,
  key: Key,
  body: Uint8Array,
): Promise<SealedBody> {
  let setup: Awaited<ReturnType<CipherSuite['SetupSender']>>;
  try {
    setup = await suite.SetupSender(key, { info: encoder.encode(EHBP.requestInfo) });
  } catch (error) {
    throw new EhbpError('HPKE_SETUP_FAILED', 'The HPKE context could not be set up.', {
      cause: error,
    });
  }
  const frames: Uint8Array[] = [];
  for (let start = 0; start < body.length; start += EHBP.requestFramePlaintextBytes) {
    const plaintext = body.subarray(start, start + EHBP.requestFramePlaintextBytes);
    frames.push(frame(await setup.ctx.Seal(plaintext)));
  }
  const exportedSecret = await setup.ctx.Export(encoder.encode(EHBP.exportLabel), EHBP.exportBytes);
  return {
    encapsulatedKey: setup.encapsulatedSecret,
    framed: concatBytes(...frames),
    exportedSecret,
  };
}
