/**
 * The formats of a signed release: the attestation formats of an enclave, the in-toto statement in
 * the Sigstore bundle, and the identity of the GitHub workflow that signs it. Read 23 Oct 2026 from
 * the release of `tinfoilsh/confidential-model-router` and from docs.tinfoil.sh.
 */
export const FORMATS = {
  /** The attestation document of an enclave on AMD SEV-SNP: a gzip of the raw report, in base64. */
  sevSnpGuestV2: 'https://tinfoil.sh/predicate/sev-snp-guest/v2',
  /** The predicate of a release: the expected SNP measurement and the TDX registers. */
  snpTdxMultiplatformV1: 'https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1',
} as const;

export const SIGNED_RELEASE = {
  /** The only Sigstore bundle layout accepted: one signing certificate, no chain. */
  bundleMediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
  payloadType: 'application/vnd.in-toto+json',
  /** The top-level fields an in-toto statement may carry; any other field fails the release. */
  statementFields: ['_type', 'subject', 'predicateType', 'predicate'],
  /** The workflow that signs a release must run on a tag. */
  tagRefPrefix: 'refs/tags/',
} as const;
