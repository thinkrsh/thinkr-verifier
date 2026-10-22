/**
 * How the enclaves of Tinfoil publish their attestation and take sealed requests. Read 23 Oct 2026
 * from docs.tinfoil.sh, the README of each repository, and the live router. Each value is a fact of
 * the protocol of Tinfoil; another provider gets a file of its own.
 */
export const TINFOIL = {
  /** The repository whose signed releases the router runs. */
  routerRepo: 'tinfoilsh/confidential-model-router',
  /** The attestation document of an enclave. */
  attestationPath: '/.well-known/tinfoil-attestation',
  /** The TLS certificate of an enclave, with its keys in the subject alternative names. */
  certificatePath: '/.well-known/tinfoil-certificate',
  /** The asset of a release that holds the SHA-256 of its deployment. */
  releaseDigestAsset: 'tinfoil.hash',
  /** The labels of the names that carry the HPKE key and the hash of the attestation document. */
  certificateLabels: { hpkeKey: 'hpke', attestationHash: 'hatt' },
  /** The header that names the enclave when a request goes through a proxy. */
  enclaveUrlHeader: 'X-Tinfoil-Enclave-Url',
  /** The field of the body that scopes the prompt cache to one user. */
  cacheSecretField: 'user_cache_secret',
  /** The endpoints whose bodies carry that field, matched as the end of the path. */
  cacheSecretPaths: ['/chat/completions', '/completions', '/responses'],
} as const;
