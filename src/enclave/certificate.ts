import { ASN1Obj } from '@freedomofpress/crypto-browser';
import { X509Certificate } from '@freedomofpress/sigstore-browser';
import { OIDS } from '../config/oids.js';
import { TINFOIL } from '../config/tinfoil.js';
import { sha256Hex, toHex } from '../lib/bytes.js';
import { decodeNames } from './names.js';

/** The tag of a dNSName in GeneralNames: context-specific, primitive, number 2 (RFC 5280). */
const DNS_NAME_TAG = 0x82;

/** The position of subjectPublicKeyInfo in TBSCertificate (RFC 5280, section 4.1). */
const SPKI_INDEX = 6;

/** What the attestation says the certificate must carry. */
export interface AttestedKeys {
  tlsKeyFingerprint: string;
  hpkePublicKey: string;
  attestationHash: string;
}

export interface VerifiedCertificate {
  notAfter: Date;
}

/**
 * Checks that the TLS certificate of an enclave belongs to the attested enclave: its key is the
 * attested TLS key, it names the host, and its names carry the attested HPKE key and the hash of
 * the attestation document. Throws on any mismatch.
 */
export async function verifyEnclaveCertificate(
  pem: string,
  enclaveHost: string,
  attested: AttestedKeys,
): Promise<VerifiedCertificate> {
  const certificate = X509Certificate.parse(pem);
  const spki = certificate.tbsCertificate.subs[SPKI_INDEX];
  if (spki === undefined || (await sha256Hex(spki.toDER())) !== attested.tlsKeyFingerprint) {
    throw new Error('The key of the certificate is not the attested TLS key.');
  }
  const names = dnsNames(certificate);
  if (!names.some((name) => matchesHost(name, enclaveHost))) {
    throw new Error(`The certificate does not name ${enclaveHost}.`);
  }
  const hpkeKey = toHex(decodeNames(names, TINFOIL.certificateLabels.hpkeKey, enclaveHost));
  if (hpkeKey !== attested.hpkePublicKey) {
    throw new Error('The HPKE key in the certificate is not the attested key.');
  }
  const hashBytes = decodeNames(names, TINFOIL.certificateLabels.attestationHash, enclaveHost);
  if (new TextDecoder().decode(hashBytes) !== attested.attestationHash) {
    throw new Error('The certificate names another attestation document.');
  }
  return { notAfter: certificate.notAfter };
}

function dnsNames(certificate: X509Certificate): string[] {
  const extension = certificate.extension(OIDS.subjectAltName);
  if (extension === undefined) {
    throw new Error('The certificate has no subject alternative names.');
  }
  return ASN1Obj.parseBuffer(extension.value)
    .subs.filter((name) => name.tag.toDER() === DNS_NAME_TAG)
    .map((name) => new TextDecoder().decode(name.value).toLowerCase());
}

/** An exact match, or a wildcard that covers one label (RFC 6125). */
function matchesHost(name: string, host: string): boolean {
  if (name === host) return true;
  if (!name.startsWith('*.')) return false;
  const dot = host.indexOf('.');
  return dot > 0 && host.slice(dot + 1) === name.slice(2);
}
