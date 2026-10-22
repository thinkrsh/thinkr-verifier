import { EHBP } from '../config/ehbp.js';
import { TINFOIL } from '../config/tinfoil.js';
import { EhbpError } from '../errors.js';
import { toHex } from '../lib/bytes.js';
import { isRecord } from '../lib/json.js';
import { sealBody, type SealedBody } from './request.js';
import { deriveResponseKeys, openResponseBody, parseResponseNonce } from './response.js';
import { enclaveKey, ehbpSuite } from './suite.js';

export interface SealedFetchOptions {
  /** The X25519 key of the enclave, as hex, from a verification that passed. */
  hpkePublicKey: string;
  /** Where requests go: the enclave itself, or a proxy in front of it. */
  baseUrl: string;
  /** The enclave, when the requests go through a proxy on another origin. */
  enclaveUrl?: string;
  /** The secret that scopes the prompt cache to this user, sealed into each eligible body. */
  cacheSecret?: string;
  /** The fetch to send with; the global fetch by default. */
  fetch?: typeof fetch;
}

const JSON_MEDIA_TYPE = 'application/json';

/** The status range of a success, which must always come sealed. */
const SUCCESS_MIN = 200;
const SUCCESS_MAX = 299;

/**
 * A fetch that seals every request body to the enclave with EHBP and opens each sealed response.
 * It sends only to the origin of `baseUrl` (and of the enclave), since EHBP leaves headers in the
 * clear. A request with no body goes out as it is, and so does its response (section 7.4).
 */
export function createSealedFetch(options: SealedFetchOptions): typeof fetch {
  const send = options.fetch ?? globalThis.fetch.bind(globalThis);
  const base = new URL(options.baseUrl);
  const allowedOrigins = new Set([base.origin]);
  const enclave = options.enclaveUrl === undefined ? undefined : new URL(options.enclaveUrl);
  if (enclave !== undefined) allowedOrigins.add(enclave.origin);
  const suite = ehbpSuite();
  const keyPromise = enclaveKey(suite, options.hpkePublicKey);

  return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = new Request(resolveInput(input, base), init);
    const target = new URL(request.url);
    if (!allowedOrigins.has(target.origin)) {
      throw new EhbpError('INVALID_INPUT', `Refusing to send to ${target.origin}.`);
    }
    if (request.headers.has(EHBP.encapsulatedKeyHeader)) {
      throw new EhbpError('INVALID_INPUT', `The header ${EHBP.encapsulatedKeyHeader} is reserved.`);
    }
    const headers = new Headers(request.headers);
    if (enclave !== undefined && enclave.origin !== base.origin) {
      headers.set(TINFOIL.enclaveUrlHeader, enclave.href);
    }
    const body = new Uint8Array(await request.arrayBuffer());
    if (body.length === 0) {
      return send(new Request(request, { headers }));
    }
    const plaintext = withCacheSecret(body, target.pathname, headers, options.cacheSecret);
    const sealed = await sealBody(suite, await keyPromise, plaintext);
    headers.set(EHBP.encapsulatedKeyHeader, toHex(sealed.encapsulatedKey));
    headers.delete('content-length');
    const response = await send(target.href, {
      method: request.method,
      headers,
      body: new Uint8Array(sealed.framed),
      signal: request.signal,
      credentials: request.credentials,
      redirect: request.redirect,
      cache: request.cache,
      referrerPolicy: request.referrerPolicy,
    });
    return openResponse(response, sealed);
  };
}

/** A relative path resolves against the base URL, so `/v1/chat/completions` reaches the proxy. */
function resolveInput(input: RequestInfo | URL, base: URL): RequestInfo | URL {
  return typeof input === 'string' ? new URL(input, base) : input;
}

/**
 * Opens a sealed response. A success must carry the response nonce; an error without it passes
 * through as an unauthenticated message from a proxy on the way (section 5.3).
 */
async function openResponse(response: Response, sealed: SealedBody): Promise<Response> {
  const nonceHeader = response.headers.get(EHBP.responseNonceHeader);
  if (nonceHeader === null) {
    if (response.status >= SUCCESS_MIN && response.status <= SUCCESS_MAX) {
      throw new EhbpError('MISSING_RESPONSE_NONCE', 'A successful response came without a nonce.');
    }
    return response;
  }
  const keys = await deriveResponseKeys(
    sealed.exportedSecret,
    sealed.encapsulatedKey,
    parseResponseNonce(nonceHeader),
  );
  const headers = new Headers(response.headers);
  headers.delete('content-length');
  headers.delete(EHBP.responseNonceHeader);
  const body = response.body === null ? null : openResponseBody(response.body, keys);
  return new Response(body, { status: response.status, statusText: response.statusText, headers });
}

/**
 * Adds the cache secret to a JSON body of a chat endpoint, inside the seal, unless the body already
 * names one. Other bodies stay as they are.
 */
function withCacheSecret(
  body: Uint8Array,
  path: string,
  headers: Headers,
  secret: string | undefined,
): Uint8Array {
  const eligible = TINFOIL.cacheSecretPaths.some((suffix) => path.endsWith(suffix));
  const isJson = headers.get('content-type')?.split(';')[0]?.trim() === JSON_MEDIA_TYPE;
  if (secret === undefined || secret === '' || !eligible || !isJson) return body;
  const parsed: unknown = JSON.parse(new TextDecoder().decode(body));
  if (!isRecord(parsed)) return body;
  const current = parsed[TINFOIL.cacheSecretField];
  if (typeof current === 'string' && current !== '') return body;
  return new TextEncoder().encode(
    JSON.stringify({ ...parsed, [TINFOIL.cacheSecretField]: secret }),
  );
}
