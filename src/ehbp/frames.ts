import { EHBP } from '../config/ehbp.js';
import { EhbpError } from '../errors.js';
import { concatBytes } from '../lib/bytes.js';

/** One frame: the length of the ciphertext in 4 bytes, big-endian, then the ciphertext. */
export function frame(ciphertext: Uint8Array): Uint8Array {
  const framed = new Uint8Array(EHBP.frameLengthBytes + ciphertext.length);
  new DataView(framed.buffer).setUint32(0, ciphertext.length, false);
  framed.set(ciphertext, EHBP.frameLengthBytes);
  return framed;
}

/** Opens one frame of ciphertext; `sequence` counts the non-empty frames from zero. */
export type FrameOpener = (ciphertext: Uint8Array, sequence: number) => Promise<Uint8Array>;

/**
 * A stream that reads frames from the bytes of a body and emits the plaintext of each frame once it
 * authenticates (section 4.3). An empty frame is skipped and does not count. A body that ends inside
 * a frame fails, and nothing follows a frame that fails.
 */
export function frameDecoder(open: FrameOpener): TransformStream<Uint8Array, Uint8Array> {
  let pending: Uint8Array = new Uint8Array(0);
  let sequence = 0;
  return new TransformStream({
    async transform(chunk, controller) {
      pending = concatBytes(pending, chunk);
      for (;;) {
        const length = readLength(pending);
        if (length === undefined || pending.length < EHBP.frameLengthBytes + length) return;
        const ciphertext = pending.slice(EHBP.frameLengthBytes, EHBP.frameLengthBytes + length);
        pending = pending.slice(EHBP.frameLengthBytes + length);
        if (length === 0) continue;
        controller.enqueue(await open(ciphertext, sequence));
        sequence += 1;
      }
    },
    flush() {
      if (pending.length > 0) {
        throw new EhbpError('FRAMING_TRUNCATED', 'The body ended inside a frame.');
      }
    },
  });
}

/** The length of the next frame, or undefined while its prefix is incomplete. */
function readLength(pending: Uint8Array): number | undefined {
  if (pending.length < EHBP.frameLengthBytes) return undefined;
  const length = new DataView(pending.buffer, pending.byteOffset, EHBP.frameLengthBytes).getUint32(
    0,
    false,
  );
  if (length > EHBP.maxFrameBytes) {
    throw new EhbpError('CHUNK_TOO_LARGE', `A frame of ${String(length)} bytes is too large.`);
  }
  return length;
}
