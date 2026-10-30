import { EHBP } from '../config/ehbp.js';
import { toHex } from '../lib/bytes.js';
import { sealBody } from './request.js';
import { deriveResponseKeys, openResponseBody, parseResponseNonce } from './response.js';
import { enclaveKey, ehbpSuite } from './suite.js';

/**
 * A request body sealed apart from its sending, for a caller that sends with another tool. The
 * secrets open the answer, so they stay on the machine that sealed the body.
 */
export interface SealedRequestBody {
  /** The frames of the sealed body, in order. */
  readonly body: Uint8Array<ArrayBuffer>;
  /** The headers of EHBP to send with the body. */
  readonly headers: Readonly<Record<string, string>>;
  readonly encapsulatedKey: Uint8Array;
  readonly exportedSecret: Uint8Array;
}

/** Seals a body to the key of the enclave, as `createSealedFetch` does, and sends nothing. */
export async function sealRequestBody(
  hpkePublicKey: string,
  plaintext: Uint8Array,
): Promise<SealedRequestBody> {
  const suite = ehbpSuite();
  const sealed = await sealBody(suite, await enclaveKey(suite, hpkePublicKey), plaintext);
  return {
    body: new Uint8Array(sealed.framed),
    headers: { [EHBP.encapsulatedKeyHeader]: toHex(sealed.encapsulatedKey) },
    encapsulatedKey: sealed.encapsulatedKey,
    exportedSecret: sealed.exportedSecret,
  };
}

/**
 * Opens a whole answer to a body that `sealRequestBody` sealed, from the response nonce that came
 * with it. Throws an `EhbpError` for a nonce of another shape or a frame that does not authenticate.
 */
export async function openResponseBytes(
  sealed: Pick<SealedRequestBody, 'encapsulatedKey' | 'exportedSecret'>,
  responseNonce: string,
  framed: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array> {
  const keys = await deriveResponseKeys(
    sealed.exportedSecret,
    sealed.encapsulatedKey,
    parseResponseNonce(responseNonce),
  );
  const frames = new Blob([framed]).stream();
  return new Uint8Array(await new Response(openResponseBody(frames, keys)).arrayBuffer());
}
