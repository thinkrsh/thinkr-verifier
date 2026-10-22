const HEX_PATTERN = /^(?:[0-9a-f]{2})*$/;

/** Lowercase hex of a byte array. */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** Bytes of a lowercase or uppercase hex string; throws on an odd length or a stray character. */
export function fromHex(hex: string): Uint8Array {
  const lower = hex.toLowerCase();
  if (!HEX_PATTERN.test(lower)) {
    throw new Error(`Not a hex string: ${hex.slice(0, 16)}`);
  }
  const bytes = new Uint8Array(lower.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(lower.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Bytes of a standard base64 string. */
export function fromBase64(text: string): Uint8Array {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Standard base64 of a byte array. */
export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

/** True when both arrays hold the same bytes. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) {
    difference |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return difference === 0;
}

/** One array with the bytes of every part, in order. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

/** True when every byte is zero. */
export function isAllZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

/** The bytes in reverse order, as a new array. */
export function reversed(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(bytes).reverse();
}

/** A copy of the bytes over a plain ArrayBuffer, the form that WebCrypto and Blob take. */
export function ownBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

/** The SHA-256 of the bytes, as lowercase hex. */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', ownBytes(bytes));
  return toHex(new Uint8Array(digest));
}

/** The bytes of a gzip stream, unpacked with the DecompressionStream of the platform. */
export async function gunzip(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([ownBytes(bytes)]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
