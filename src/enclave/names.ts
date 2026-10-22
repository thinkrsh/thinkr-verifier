const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
const BITS_PER_CHARACTER = 5;
const BITS_PER_BYTE = 8;

/** The first label of each name: the index of the chunk in two digits, then the base32 text. */
const CHUNK_PATTERN = /^(\d{2})([a-z2-7]+)$/;

/**
 * Decodes the bytes that an enclave spreads over the DNS names of its certificate. Each name has
 * the form `<index><base32>.<label>.<domain>`, where `<domain>` is the domain of the enclave host
 * or one of its parents. The chunks join in the order of their index.
 */
export function decodeNames(
  names: readonly string[],
  label: string,
  enclaveHost: string,
): Uint8Array {
  const chunks = names
    .map((name) => name.split('.'))
    .filter(([, nameLabel, ...domain]) => nameLabel === label && isParentOf(domain, enclaveHost))
    .map(([first]) => parseChunk(first ?? ''))
    .sort((a, b) => a.index - b.index);
  if (chunks.length === 0) {
    throw new Error(`The certificate has no names under .${label} for ${enclaveHost}.`);
  }
  chunks.forEach((chunk, position) => {
    if (chunk.index !== position) {
      throw new Error(`The names under .${label} skip or repeat chunk ${String(position)}.`);
    }
  });
  return decodeBase32(chunks.map((chunk) => chunk.text).join(''));
}

/** True when the labels form the host itself or a parent domain of it. */
function isParentOf(labels: string[], host: string): boolean {
  const domain = labels.join('.');
  return labels.length >= 2 && (host === domain || host.endsWith(`.${domain}`));
}

function parseChunk(label: string): { index: number; text: string } {
  const match = CHUNK_PATTERN.exec(label);
  if (match?.[1] === undefined || match[2] === undefined) {
    throw new Error(`The label ${label} is not a chunk of encoded data.`);
  }
  return { index: Number.parseInt(match[1], 10), text: match[2] };
}

/** Decodes base32 (RFC 4648) in lowercase, without padding, as DNS names carry it. */
function decodeBase32(text: string): Uint8Array {
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const character of text) {
    const value = BASE32_ALPHABET.indexOf(character);
    if (value < 0) {
      throw new Error(`The character ${character} is not base32.`);
    }
    buffer = ((buffer << BITS_PER_CHARACTER) | value) & 0xffff;
    bits += BITS_PER_CHARACTER;
    if (bits >= BITS_PER_BYTE) {
      bits -= BITS_PER_BYTE;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return Uint8Array.from(bytes);
}
