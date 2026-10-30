import {
  deriveResponseKeys as referenceDeriveKeys,
  encryptChunk as referenceEncryptChunk,
} from 'ehbp';
import type { KeyPair } from 'hpke';
import { beforeAll, describe, expect, it } from 'vitest';
import { EHBP } from '../src/config/ehbp.js';
import { TINFOIL } from '../src/config/tinfoil.js';
import { createSealedFetch } from '../src/ehbp/fetch.js';
import { frame } from '../src/ehbp/frames.js';
import { deriveResponseKeys, frameNonce, parseResponseNonce } from '../src/ehbp/response.js';
import { openResponseBytes, sealRequestBody } from '../src/ehbp/steps.js';
import { ehbpSuite } from '../src/ehbp/suite.js';
import { EhbpError } from '../src/errors.js';
import { concatBytes, fromHex, toHex } from '../src/lib/bytes.js';

const BASE_URL = 'https://proxy.example';
const ENCLAVE_URL = 'https://enclave.example';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

interface Exchange {
  plaintext: string;
  headers: Headers;
  url: string;
}

/**
 * A test enclave: it opens each request with HPKE, as any EHBP server does, and seals its answer
 * with the response primitives of the reference implementation (`ehbp`, MIT), so the client of
 * Thinkr is checked against code it does not share.
 */
class TestEnclave {
  readonly exchanges: Exchange[] = [];

  constructor(
    private readonly keyPair: KeyPair,
    private readonly answer: (exchange: Exchange) => { status: number; frames: string[] },
  ) {}

  readonly fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = new Request(input, init);
    const encapsulatedKey = fromHex(request.headers.get(EHBP.encapsulatedKeyHeader) ?? '');
    const suite = ehbpSuite();
    const ctx = await suite.SetupRecipient(this.keyPair, encapsulatedKey, {
      info: encoder.encode(EHBP.requestInfo),
    });
    const body = new Uint8Array(await request.arrayBuffer());
    const parts: Uint8Array[] = [];
    for (let offset = 0; offset < body.length;) {
      const length = new DataView(body.buffer, offset, 4).getUint32(0, false);
      parts.push(await ctx.Open(body.slice(offset + 4, offset + 4 + length)));
      offset += 4 + length;
    }
    const exchange = {
      plaintext: decoder.decode(concatBytes(...parts)),
      headers: request.headers,
      url: request.url,
    };
    this.exchanges.push(exchange);
    const secret = await ctx.Export(encoder.encode(EHBP.exportLabel), EHBP.exportBytes);
    const nonce = crypto.getRandomValues(new Uint8Array(EHBP.responseNonceBytes));
    const keys = await referenceDeriveKeys(secret, encapsulatedKey, nonce);
    const { status, frames } = this.answer(exchange);
    const sealed = await Promise.all(
      frames.map(async (text, index) =>
        frame(await referenceEncryptChunk(keys, index, encoder.encode(text))),
      ),
    );
    return new Response(new Uint8Array(concatBytes(...sealed)), {
      status,
      headers: { [EHBP.responseNonceHeader]: toHex(nonce) },
    });
  };
}

let keyPair: KeyPair;
let publicKeyHex: string;

beforeAll(async () => {
  const suite = ehbpSuite();
  keyPair = await suite.GenerateKeyPair(true);
  publicKeyHex = toHex(await suite.SerializePublicKey(keyPair.publicKey));
});

function sealedFetch(send: typeof fetch, cacheSecret?: string): typeof fetch {
  return createSealedFetch({
    hpkePublicKey: publicKeyHex,
    baseUrl: BASE_URL,
    enclaveUrl: ENCLAVE_URL,
    ...(cacheSecret === undefined ? {} : { cacheSecret }),
    fetch: send,
  });
}

async function expectEhbpError(promise: Promise<unknown>, code: string): Promise<void> {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(EhbpError);
  expect((error as EhbpError).code).toBe(code);
}

describe('response keys', () => {
  it('derive as the reference implementation derives them', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const enc = crypto.getRandomValues(new Uint8Array(32));
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    const ours = await deriveResponseKeys(secret, enc, nonce);
    const theirs = await referenceDeriveKeys(secret, enc, nonce);
    expect(toHex(ours.key)).toBe(toHex(theirs.keyBytes));
    expect(toHex(ours.nonceBase)).toBe(toHex(theirs.nonceBase));
  });

  it('XOR the frame number into the last bytes of the nonce', () => {
    const base = new Uint8Array(12);
    expect(toHex(frameNonce(base, 0))).toBe('000000000000000000000000');
    expect(toHex(frameNonce(base, 1))).toBe('000000000000000000000001');
    expect(toHex(frameNonce(base, 258))).toBe('000000000000000000000102');
  });

  it('reject a nonce that is not 32 bytes of hex, or that came twice', () => {
    expect(() => parseResponseNonce('ab')).toThrow(EhbpError);
    expect(() => parseResponseNonce(`${'a'.repeat(64)}, ${'b'.repeat(64)}`)).toThrow(/twice/);
  });
});

describe('createSealedFetch', () => {
  it('seals a chat, adds the cache secret inside the seal, and opens a streamed answer', async () => {
    const enclave = new TestEnclave(keyPair, () => ({
      status: 200,
      frames: ['data: {"a":1}\n\n', 'data: {"a":2}\n\n', 'data: [DONE]\n\n'],
    }));
    const send = sealedFetch(enclave.fetch, 'secret-of-this-user');
    const response = await send('/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer test' },
      body: JSON.stringify({ model: 'gpt-oss-120b', messages: [] }),
    });
    expect(await response.text()).toBe('data: {"a":1}\n\ndata: {"a":2}\n\ndata: [DONE]\n\n');
    const [exchange] = enclave.exchanges;
    expect(JSON.parse(exchange?.plaintext ?? '{}')).toEqual({
      model: 'gpt-oss-120b',
      messages: [],
      [TINFOIL.cacheSecretField]: 'secret-of-this-user',
    });
    expect(exchange?.url).toBe(`${BASE_URL}/v1/chat/completions`);
    expect(exchange?.headers.get(TINFOIL.enclaveUrlHeader)).toBe(`${ENCLAVE_URL}/`);
    expect(exchange?.headers.get('authorization')).toBe('Bearer test');
  });

  it('keeps a cache secret that the body already names', async () => {
    const enclave = new TestEnclave(keyPair, () => ({ status: 200, frames: ['{}'] }));
    const send = sealedFetch(enclave.fetch, 'client-secret');
    await send('/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ [TINFOIL.cacheSecretField]: 'request-secret' }),
    });
    expect(JSON.parse(enclave.exchanges[0]?.plaintext ?? '{}')).toEqual({
      [TINFOIL.cacheSecretField]: 'request-secret',
    });
  });

  it('seals a multipart upload as it is, split into frames of 64 KiB', async () => {
    const enclave = new TestEnclave(keyPair, () => ({ status: 200, frames: ['{"document":{}}'] }));
    const form = new FormData();
    form.append('files', new Blob([new Uint8Array(200 * 1024).fill(7)]), 'scan.pdf');
    const response = await sealedFetch(enclave.fetch, 'secret')('/v1/convert/file', {
      method: 'POST',
      body: form,
    });
    expect(await response.json()).toEqual({ document: {} });
    expect(enclave.exchanges[0]?.plaintext).toContain('filename="scan.pdf"');
    expect(enclave.exchanges[0]?.plaintext).not.toContain(TINFOIL.cacheSecretField);
  });

  it('sends a request with no body unsealed', async () => {
    let sent: Request | undefined;
    const send = sealedFetch((input, init) => {
      sent = new Request(input, init);
      return Promise.resolve(new Response('plain', { status: 200 }));
    });
    expect(await (await send('/v1/models')).text()).toBe('plain');
    expect(sent?.headers.has(EHBP.encapsulatedKeyHeader)).toBe(false);
  });

  it('fails a success that comes without a nonce', async () => {
    const send = sealedFetch(() => Promise.resolve(new Response('forged', { status: 200 })));
    await expectEhbpError(
      send('/v1/chat/completions', { method: 'POST', body: '{}' }),
      'MISSING_RESPONSE_NONCE',
    );
  });

  it('passes an error without a nonce through, unopened', async () => {
    const send = sealedFetch(() => Promise.resolve(new Response('rate limited', { status: 429 })));
    const response = await send('/v1/chat/completions', { method: 'POST', body: '{}' });
    expect(response.status).toBe(429);
    expect(await response.text()).toBe('rate limited');
  });

  it('stops at a frame that does not authenticate', async () => {
    const enclave = new TestEnclave(keyPair, () => ({ status: 200, frames: ['first', 'second'] }));
    const tampering: typeof fetch = async (input, init) => {
      const response = await enclave.fetch(input, init);
      const bytes = new Uint8Array(await response.arrayBuffer());
      bytes[bytes.length - 1] = (bytes[bytes.length - 1] ?? 0) ^ 1;
      return new Response(bytes, { status: 200, headers: response.headers });
    };
    const response = await sealedFetch(tampering)('/v1/chat/completions', {
      method: 'POST',
      body: '{}',
    });
    await expectEhbpError(response.text(), 'AEAD_DECRYPT_FAILED');
  });

  it('fails a body that ends inside a frame', async () => {
    const enclave = new TestEnclave(keyPair, () => ({ status: 200, frames: ['complete'] }));
    const truncating: typeof fetch = async (input, init) => {
      const response = await enclave.fetch(input, init);
      const bytes = new Uint8Array(await response.arrayBuffer());
      return new Response(bytes.slice(0, -3), { status: 200, headers: response.headers });
    };
    const response = await sealedFetch(truncating)('/v1/chat/completions', {
      method: 'POST',
      body: '{}',
    });
    await expectEhbpError(response.text(), 'FRAMING_TRUNCATED');
  });

  it('refuses to send to another origin', async () => {
    const send = sealedFetch(() => Promise.resolve(new Response(null)));
    await expectEhbpError(
      send('https://elsewhere.example/v1/chat/completions', { method: 'POST', body: '{}' }),
      'INVALID_INPUT',
    );
  });

  it('refuses a caller that sets the reserved header', async () => {
    const send = sealedFetch(() => Promise.resolve(new Response(null)));
    const init = { method: 'POST', body: '{}', headers: { [EHBP.encapsulatedKeyHeader]: '00' } };
    await expectEhbpError(send('/v1/chat/completions', init), 'INVALID_INPUT');
  });

  it('refuses a key that is not 32 bytes', async () => {
    const send = createSealedFetch({
      hpkePublicKey: 'abcd',
      baseUrl: BASE_URL,
      fetch: () => Promise.resolve(new Response(null)),
    });
    await expectEhbpError(
      send('/v1/chat/completions', { method: 'POST', body: '{}' }),
      'INVALID_KEY_CONFIG',
    );
  });
});

describe('sealRequestBody and openResponseBytes', () => {
  /** Sends what `sealRequestBody` made to the test enclave, as another tool would. */
  async function roundTrip(frames: string[]): Promise<{
    enclave: TestEnclave;
    sealed: Awaited<ReturnType<typeof sealRequestBody>>;
    response: Response;
  }> {
    const enclave = new TestEnclave(keyPair, () => ({ status: 200, frames }));
    const sealed = await sealRequestBody(publicKeyHex, encoder.encode('{"model":"m"}'));
    const response = await enclave.fetch(`${BASE_URL}/v1/chat/completions`, {
      method: 'POST',
      headers: sealed.headers,
      body: sealed.body,
    });
    return { enclave, sealed, response };
  }

  it('seals a body that an enclave opens, and opens its whole answer', async () => {
    const { enclave, sealed, response } = await roundTrip(['{"ans', 'wer":1}']);
    expect(enclave.exchanges[0]?.plaintext).toBe('{"model":"m"}');
    const opened = await openResponseBytes(
      sealed,
      response.headers.get(EHBP.responseNonceHeader) ?? '',
      new Uint8Array(await response.arrayBuffer()),
    );
    expect(decoder.decode(opened)).toBe('{"answer":1}');
  });

  it('shows no plain text in the sealed body', async () => {
    const { sealed } = await roundTrip(['ok']);
    expect(decoder.decode(sealed.body)).not.toContain('model');
  });

  it('refuses an answer that was changed, or a nonce of another shape', async () => {
    const { sealed, response } = await roundTrip(['ok']);
    const nonce = response.headers.get(EHBP.responseNonceHeader) ?? '';
    const framed = new Uint8Array(await response.arrayBuffer());
    const changed = Uint8Array.from(framed);
    changed[changed.length - 1] = (changed[changed.length - 1] ?? 0) ^ 1;
    await expectEhbpError(openResponseBytes(sealed, nonce, changed), 'AEAD_DECRYPT_FAILED');
    await expectEhbpError(openResponseBytes(sealed, 'abcd', framed), 'INVALID_RESPONSE_NONCE');
  });

  it('opens an answer only with the secrets of its own request', async () => {
    const { response } = await roundTrip(['ok']);
    const other = await sealRequestBody(publicKeyHex, encoder.encode('{}'));
    await expectEhbpError(
      openResponseBytes(
        other,
        response.headers.get(EHBP.responseNonceHeader) ?? '',
        new Uint8Array(await response.arrayBuffer()),
      ),
      'AEAD_DECRYPT_FAILED',
    );
  });
});
