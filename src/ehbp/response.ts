import { AEAD_AES_256_GCM, KDF_HKDF_SHA256 } from 'hpke';
import { EHBP } from '../config/ehbp.js';
import { EhbpError } from '../errors.js';
import { concatBytes, fromHex } from '../lib/bytes.js';
import { frameDecoder } from './frames.js';

const RESPONSE_NONCE_PATTERN = /^[0-9a-f]{64}$/;

/** The last 8 bytes of the AES-GCM nonce take the sequence number of the frame (section 4.4.1). */
const SEQUENCE_BYTES = 8;
const MAX_SEQUENCE = 2 ** 53 - 1;

const encoder = new TextEncoder();
const kdf = KDF_HKDF_SHA256();
const aead = AEAD_AES_256_GCM();

/** The AES-256-GCM key and base nonce of one response. */
export interface ResponseKeys {
  key: Uint8Array;
  nonceBase: Uint8Array;
}

/** Reads and checks the response nonce; the hex of exactly 32 bytes (section 4.2). */
export function parseResponseNonce(value: string): Uint8Array {
  if (value.includes(',')) {
    throw new EhbpError('DUPLICATE_RESPONSE_NONCE', 'The response carries the nonce twice.');
  }
  if (!RESPONSE_NONCE_PATTERN.test(value)) {
    throw new EhbpError('INVALID_RESPONSE_NONCE', 'The response nonce is not 32 bytes of hex.');
  }
  return fromHex(value);
}

/**
 * Derives the keys of a response as OHTTP does (section 4.4.1): salt = enc || response_nonce,
 * prk = Extract(salt, secret), key = Expand(prk, "key", 32), nonce = Expand(prk, "nonce", 12).
 */
export async function deriveResponseKeys(
  exportedSecret: Uint8Array,
  encapsulatedKey: Uint8Array,
  responseNonce: Uint8Array,
): Promise<ResponseKeys> {
  try {
    const prk = await kdf.Extract(concatBytes(encapsulatedKey, responseNonce), exportedSecret);
    return {
      key: await kdf.Expand(prk, encoder.encode(EHBP.responseKeyLabel), EHBP.aesKeyBytes),
      nonceBase: await kdf.Expand(prk, encoder.encode(EHBP.responseNonceLabel), EHBP.aesNonceBytes),
    };
  } catch (error) {
    throw new EhbpError('HPKE_SETUP_FAILED', 'The response keys could not be derived.', {
      cause: error,
    });
  }
}

/** The nonce of frame `sequence`: the base nonce XOR the sequence, big-endian, in its last bytes. */
export function frameNonce(nonceBase: Uint8Array, sequence: number): Uint8Array {
  if (!Number.isSafeInteger(sequence) || sequence < 0 || sequence > MAX_SEQUENCE) {
    throw new EhbpError(
      'SEQUENCE_OVERFLOW',
      `The frame number ${String(sequence)} is out of range.`,
    );
  }
  const nonce = Uint8Array.from(nonceBase);
  let rest = BigInt(sequence);
  for (let i = 0; i < SEQUENCE_BYTES; i++) {
    const index = nonce.length - 1 - i;
    nonce[index] = (nonce[index] ?? 0) ^ Number(rest & 0xffn);
    rest >>= 8n;
  }
  return nonce;
}

/** The plaintext body of a sealed response, frame by frame, as each frame authenticates. */
export function openResponseBody(
  body: ReadableStream<Uint8Array>,
  keys: ResponseKeys,
): ReadableStream<Uint8Array> {
  return body.pipeThrough(
    frameDecoder(async (ciphertext, sequence) => {
      const nonce = frameNonce(keys.nonceBase, sequence);
      try {
        return await aead.Open(keys.key, nonce, new Uint8Array(0), ciphertext);
      } catch (error) {
        throw new EhbpError(
          'AEAD_DECRYPT_FAILED',
          `Frame ${String(sequence)} did not authenticate.`,
          {
            cause: error,
          },
        );
      }
    }),
  );
}
