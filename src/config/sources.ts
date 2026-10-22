/**
 * Where the verifier fetches the parts of an attestation when it builds the bundle itself, with no
 * service of Tinfoil in between: the enclave, GitHub, and AMD.
 */
export const SOURCES = {
  githubApi: 'https://api.github.com',
  githubWeb: 'https://github.com',
  amdKds: 'https://kdsintf.amd.com',
  /** The attestation bundle that the proxy of Thinkr serves to the app. */
  thinkrBundle: 'https://chat.thinkr.sh/api/private/attestation',
} as const;

/** How long the verifier waits for one fetch, in milliseconds. */
export const FETCH_TIMEOUT_MS = 20_000;
