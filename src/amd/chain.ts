import { ASN1Obj } from '@freedomofpress/crypto-browser';
import { X509Certificate } from '@freedomofpress/sigstore-browser';
import { AMD_CERTIFICATE_NAME, AMD_COMMON_NAMES, CHIP_ID_BYTES } from '../config/amd.js';
import { OIDS } from '../config/oids.js';
import { AMD_ROOTS, type AmdProduct } from '../config/amdRoots.js';
import type { TcbLevels } from '../config/amd.js';

/** The X.509 version that every certificate of the chain must carry. */
const X509_V3 = 'v3';

/** The extension of a VCEK that names its product: a DER IA5String (tag 0x16). */
const IA5_STRING_TAG = 0x16;

/** The VCEK of a chip, verified up to the pinned root of AMD. */
export interface VerifiedVcek {
  publicKey: CryptoKey;
  tcb: TcbLevels;
  hardwareId: Uint8Array;
}

/**
 * Verifies the chain ARK > ASK > VCEK of a product against the pinned roots of AMD, at the time
 * `now`, and returns the key and the extensions of the VCEK. Throws on any failure.
 */
export async function verifyAmdChain(
  product: AmdProduct,
  vcekDer: Uint8Array,
  now: Date,
): Promise<VerifiedVcek> {
  const ark = X509Certificate.parse(AMD_ROOTS[product].ark);
  const ask = X509Certificate.parse(AMD_ROOTS[product].ask);
  const vcek = X509Certificate.parse(vcekDer);
  checkAmdCertificate(ark, AMD_COMMON_NAMES.ark(product), now);
  checkAmdCertificate(ask, AMD_COMMON_NAMES.ask(product), now);
  checkAmdCertificate(vcek, AMD_COMMON_NAMES.vcek, now);
  checkVcekShape(vcek, product);
  await checkSignedBy(ark, ark, 'The ARK is not self-signed.');
  await checkSignedBy(ask, ark, 'The ASK is not signed by the ARK.');
  await checkSignedBy(vcek, ask, 'The VCEK is not signed by the ASK.');
  return {
    publicKey: await vcek.getPublicKeyObj(),
    tcb: readVcekTcb(vcek),
    hardwareId: requiredExtension(vcek, OIDS.vcek.hardwareId),
  };
}

function checkAmdCertificate(certificate: X509Certificate, commonName: string, now: Date): void {
  if (certificate.version !== X509_V3) {
    throw new Error(`The certificate ${commonName} is not X.509 v3.`);
  }
  for (const name of [certificate.issuerDN, certificate.subjectDN]) {
    for (const [field, expected] of Object.entries(AMD_CERTIFICATE_NAME)) {
      if (name.get(field) !== expected) {
        throw new Error(`The certificate ${commonName} has a name outside AMD (${field}).`);
      }
    }
  }
  if (certificate.subjectDN.get('CN') !== commonName) {
    throw new Error(
      `Expected the certificate ${commonName}, got ${String(certificate.subjectDN.get('CN'))}.`,
    );
  }
  if (!certificate.validForDate(now)) {
    throw new Error(`The certificate ${commonName} is not valid on ${now.toISOString()}.`);
  }
}

/** A VCEK is signed with RSASSA-PSS, holds a P-384 key, names its product, and has no CSP_ID. */
function checkVcekShape(vcek: X509Certificate, product: AmdProduct): void {
  if (vcek.signatureAlgorithmOid !== OIDS.rsassaPss) {
    throw new Error('The VCEK is not signed with RSASSA-PSS.');
  }
  const algorithm = vcek.tbsCertificate.subs[6]?.subs[0];
  if (
    algorithm?.subs[0]?.toOID() !== OIDS.ecPublicKey ||
    algorithm.subs[1]?.toOID() !== OIDS.secp384r1
  ) {
    throw new Error('The key of the VCEK is not ECDSA P-384.');
  }
  if (vcek.extension(OIDS.vcek.cspId) !== undefined) {
    throw new Error('The certificate carries a CSP_ID: it is a VLEK, not a VCEK.');
  }
  if (requiredExtension(vcek, OIDS.vcek.hardwareId).length !== CHIP_ID_BYTES) {
    throw new Error('The hardware ID of the VCEK has the wrong length.');
  }
  const productName = ASN1Obj.parseBuffer(requiredExtension(vcek, OIDS.vcek.productName));
  if (
    productName.tag.toDER() !== IA5_STRING_TAG ||
    new TextDecoder().decode(productName.value) !== product
  ) {
    throw new Error(`The VCEK is not for ${product}.`);
  }
}

async function checkSignedBy(
  certificate: X509Certificate,
  issuer: X509Certificate,
  message: string,
): Promise<void> {
  if (!(await certificate.verify(issuer))) {
    throw new Error(message);
  }
}

function requiredExtension(certificate: X509Certificate, oid: string): Uint8Array {
  const extension = certificate.extension(oid);
  if (extension === undefined) {
    throw new Error(`The VCEK lacks the extension ${oid}.`);
  }
  return extension.value;
}

function extensionInteger(certificate: X509Certificate, oid: string): number {
  return Number(ASN1Obj.parseBuffer(requiredExtension(certificate, oid)).toInteger());
}

function readVcekTcb(vcek: X509Certificate): TcbLevels {
  return {
    bootloader: extensionInteger(vcek, OIDS.vcek.bootloaderSpl),
    tee: extensionInteger(vcek, OIDS.vcek.teeSpl),
    snp: extensionInteger(vcek, OIDS.vcek.snpSpl),
    microcode: extensionInteger(vcek, OIDS.vcek.microcodeSpl),
  };
}
