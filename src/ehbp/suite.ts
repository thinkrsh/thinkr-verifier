import { KEM_DHKEM_X25519_HKDF_SHA256 } from '@panva/hpke-noble';
import { AEAD_AES_256_GCM, CipherSuite, KDF_HKDF_SHA256, type Key } from 'hpke';
import { EHBP } from '../config/ehbp.js';
import { EhbpError } from '../errors.js';
import { fromHex } from '../lib/bytes.js';

/**
 * The one HPKE suite of EHBP (section 3.2): DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
 * X25519 comes from the audited noble library, so it works in browsers whose WebCrypto lacks it.
 */
export function ehbpSuite(): CipherSuite {
  return new CipherSuite(KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM);
}

/** The HPKE public key of the enclave, from the hex that its attestation carries. */
export async function enclaveKey(suite: CipherSuite, hpkePublicKeyHex: string): Promise<Key> {
  let bytes: Uint8Array;
  try {
    bytes = fromHex(hpkePublicKeyHex);
  } catch (error) {
    throw new EhbpError('INVALID_KEY_CONFIG', 'The HPKE key is not hex.', { cause: error });
  }
  if (bytes.length !== EHBP.publicKeyBytes) {
    throw new EhbpError('INVALID_KEY_CONFIG', `The HPKE key has ${String(bytes.length)} bytes.`);
  }
  try {
    return await suite.DeserializePublicKey(bytes);
  } catch (error) {
    throw new EhbpError('INVALID_KEY_CONFIG', 'The HPKE key is not an X25519 key.', {
      cause: error,
    });
  }
}
