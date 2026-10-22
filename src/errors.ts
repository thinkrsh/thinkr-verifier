/** The steps of a verification, in the order they run. */
export const VERIFICATION_STEPS = ['bundle', 'hardware', 'code', 'measurement', 'keys'] as const;

export type VerificationStep = (typeof VERIFICATION_STEPS)[number];

/** A verification that failed, with the step where it stopped. */
export class VerificationError extends Error {
  override readonly name = 'VerificationError';

  constructor(
    readonly step: VerificationStep,
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
  }
}

/** The error classes of EHBP, section 5.5 of its specification (client side). */
export const EHBP_ERROR_CODES = [
  'INVALID_KEY_CONFIG',
  'HPKE_SETUP_FAILED',
  'MISSING_RESPONSE_NONCE',
  'INVALID_RESPONSE_NONCE',
  'DUPLICATE_RESPONSE_NONCE',
  'FRAMING_TRUNCATED',
  'CHUNK_TOO_LARGE',
  'AEAD_DECRYPT_FAILED',
  'SEQUENCE_OVERFLOW',
  'INVALID_INPUT',
] as const;

export type EhbpErrorCode = (typeof EHBP_ERROR_CODES)[number];

/** A failure of EHBP. The message has the form `<CODE>: <detail>`, as the specification asks. */
export class EhbpError extends Error {
  override readonly name = 'EhbpError';

  constructor(
    readonly code: EhbpErrorCode,
    detail: string,
    options?: { cause?: unknown },
  ) {
    super(`${code}: ${detail}`, options);
  }
}
