/**
 * The values of the Encrypted HTTP Body Protocol (EHBP), from its specification, `SPEC.md` of
 * `tinfoilsh/encrypted-http-body-protocol` at commit 6de5889 (MIT, read 23 Oct 2026).
 */
export const EHBP = {
  encapsulatedKeyHeader: 'Ehbp-Encapsulated-Key',
  responseNonceHeader: 'Ehbp-Response-Nonce',
  /** The HPKE info of the request context (section 4.4.1). */
  requestInfo: 'ehbp request',
  /** The label of the secret exported for the response keys (section 4.4.1). */
  exportLabel: 'ehbp response',
  /** The HKDF-Expand labels of the response key and nonce (section 4.4.1). */
  responseKeyLabel: 'key',
  responseNonceLabel: 'nonce',
  exportBytes: 32,
  responseNonceBytes: 32,
  aesKeyBytes: 32,
  aesNonceBytes: 12,
  /** The length of the encapsulated key of DHKEM(X25519, HKDF-SHA256). */
  encapsulatedKeyBytes: 32,
  /** The length of an X25519 public key. */
  publicKeyBytes: 32,
  /** The length prefix of each frame (section 4.3). */
  frameLengthBytes: 4,
  /** The largest frame a receiver accepts (section 4.3): 64 MiB of ciphertext. */
  maxFrameBytes: 64 * 1024 * 1024,
  /** The plaintext sealed into each frame of a request; the specification asks for 8 to 64 KiB. */
  requestFramePlaintextBytes: 64 * 1024,
} as const;
