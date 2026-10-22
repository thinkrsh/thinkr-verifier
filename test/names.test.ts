import { describe, expect, it } from 'vitest';
import { decodeNames } from '../src/enclave/names.js';
import { toHex } from '../src/lib/bytes.js';

const HOST = 'inference.tinfoil.sh';
const NAMES = [
  'inference.tinfoil.sh',
  '00maw2mklmu6q2aojc6tvauagefkiadt23rs3svjxziqj32.hpke.tinfoil.sh',
  '01ye6qn4a.hpke.tinfoil.sh',
];
const HPKE_KEY = '602da6296ca7a1a03922f4ea0a00c42a9001cf5b8cb72aa6f94413bd609e8378';

describe('decodeNames', () => {
  it('joins the chunks of the HPKE key in the order of their index', () => {
    expect(toHex(decodeNames(NAMES, 'hpke', HOST))).toBe(HPKE_KEY);
    expect(toHex(decodeNames([...NAMES].reverse(), 'hpke', HOST))).toBe(HPKE_KEY);
  });

  it('ignores names under a domain that is not a parent of the host', () => {
    expect(() => decodeNames(['00maw2mk.hpke.example.com'], 'hpke', HOST)).toThrow(/no names/);
  });

  it('rejects a missing chunk', () => {
    expect(() => decodeNames([NAMES[2] ?? ''], 'hpke', HOST)).toThrow(/skip or repeat/);
  });
});
