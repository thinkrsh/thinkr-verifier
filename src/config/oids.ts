/**
 * The object identifiers that the verifier reads: RFC 4055 (RSASSA-PSS), RFC 5480 (EC keys), RFC 5280
 * (subject alternative names), and the VCEK certificate specification of AMD.
 */
export const OIDS = {
  rsassaPss: '1.2.840.113549.1.1.10',
  ecPublicKey: '1.2.840.10045.2.1',
  secp384r1: '1.3.132.0.34',
  subjectAltName: '2.5.29.17',
  vcek: {
    productName: '1.3.6.1.4.1.3704.1.2',
    bootloaderSpl: '1.3.6.1.4.1.3704.1.3.1',
    teeSpl: '1.3.6.1.4.1.3704.1.3.2',
    snpSpl: '1.3.6.1.4.1.3704.1.3.3',
    microcodeSpl: '1.3.6.1.4.1.3704.1.3.8',
    hardwareId: '1.3.6.1.4.1.3704.1.4',
    cspId: '1.3.6.1.4.1.3704.1.5',
  },
} as const;
