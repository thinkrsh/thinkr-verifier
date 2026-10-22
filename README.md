# Thinkr verifier

This package verifies the enclave behind the private lane of Thinkr, and it
encrypts each request to that enclave with the Encrypted HTTP Body Protocol
(EHBP). It runs in Node and in the browser. Its command-line tool lets anyone
verify the enclave from a terminal.

The readers are developers and auditors who want to verify the enclave
themselves. The provider of the enclave is Tinfoil. The verifier uses no code
of Tinfoil: it follows the published formats and the EHBP specification.

## Verify the enclave from a terminal

This section shows how to run the verification on your own machine. You need
Node 22.12 or later.

1. Install the packages and build:

   ```sh
   npm install
   npm run build
   ```

2. To verify the enclave that the app of Thinkr uses, run:

   ```sh
   node dist/cli.js
   ```

3. To verify with no service between you and the enclave, name the enclave.
   The tool then fetches the attestation from the enclave, the release from
   GitHub, and the key of the chip from AMD:

   ```sh
   node dist/cli.js --enclave inference.tinfoil.sh
   ```

The output on 23 Oct 2026:

```text
pass  The bundle is complete
pass  AMD signed the report of the enclave
pass  The release is signed in Sigstore
pass  The enclave runs that release
pass  The certificate carries the attested keys

Enclave      inference.tinfoil.sh
Release      tinfoilsh/confidential-model-router v0.0.166
Image        v0.14.15
Hardware     AMD SEV-SNP, Genoa
Measurement  ffb708f1bb0f…38d0b450b0b4
TLS key      ca7756da2278…ad5099aed176
HPKE key     602da6296ca7…13bd609e8378
```

The tool exits with 0 when every step passes, 1 when a step fails, and 2 on
wrong arguments. Add `--json` for output that a script can read. Add
`--repo <owner/name>` to verify an enclave that runs another repository, such
as `tinfoilsh/confidential-pii-cpu` for the privacy filter.

## The steps of a verification

This section lists the steps of a verification in the order they run. A
verification stops at the first step that fails, and the error names that
step.

| Step          | What the step verifies                                                                                                                                                                                                                                             |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `bundle`      | The bundle is complete, and its attestation format is AMD SEV-SNP.                                                                                                                                                                                                 |
| `hardware`    | The report parses, its reserved bytes are zero, and the VCEK of the chip signed it. The chain from the VCEK to the root of AMD verifies. The guest has debug mode off, the running firmware is the committed one and recent enough, and the TCB meets the minimum. |
| `code`        | The Sigstore bundle of the release verifies against the trusted root of Sigstore. A GitHub workflow of the repository signed it from a tag. The signed statement covers the digest of the release.                                                                 |
| `measurement` | The measurement of the enclave equals the measurement of the signed release.                                                                                                                                                                                       |
| `keys`        | The TLS certificate of the enclave holds the attested TLS key and names the host. Its names carry the attested HPKE key and the hash of the attestation document.                                                                                                  |

## Use the library

This section shows how an app verifies the enclave and then sends sealed
requests. To verify a bundle and send one sealed chat, use:

```ts
import { createSealedFetch, fetchBundle, verifyBundle } from '@thinkr/verifier';

const bundle = await fetchBundle('https://chat.thinkr.sh/api/private/attestation');
const verification = await verifyBundle(bundle, {
  repo: 'tinfoilsh/confidential-model-router',
});

const sealedFetch = createSealedFetch({
  hpkePublicKey: verification.hardware.hpkePublicKey,
  baseUrl: 'https://chat.thinkr.sh/api/private',
  enclaveUrl: `https://${verification.enclaveHost}`,
});
const response = await sealedFetch('/v1/chat/completions', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ model: 'gpt-oss-120b', messages: [], stream: true }),
});
```

`createSealedFetch` seals each request body to the attested key and opens each
response frame by frame, so a streamed answer reads as it arrives. It sends
only to the origin of `baseUrl` and of the enclave. A request with no body goes
out unsealed, as EHBP defines.

## Trust roots

This section lists the keys that the verifier trusts. Every other key must
chain to one of them.

- **AMD:** the ARK and the ASK of AMD EPYC Genoa, in
  `src/config/amdRoots.ts`. Downloaded from AMD on 23 Oct 2026, from
  `https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain`.
- **Sigstore:** the trusted root of the public Sigstore instance, in
  `src/config/sigstoreTrustedRoot.ts`. Taken on 23 Oct 2026 from the TUF
  repository of Sigstore, targets version 14.
- **The policy:** the minimum firmware and TCB, in `src/config/amd.ts`. The
  values match the verifiers of Tinfoil, so both accept the same enclaves.

## Limits

This section lists what the verifier does not do yet.

- It accepts AMD EPYC Genoa only. Milan, Turin, and Intel TDX need their own
  roots and policy first.
- It accepts any signed release of the repository, as the verifiers of Tinfoil
  do. It does not require the latest release.
- A browser cannot fetch the VCEK from AMD, because AMD sends no CORS headers.
  In the browser, the VCEK comes in the bundle, and the chain to the pinned
  root of AMD still verifies it.
- The sealed request body is built in memory before it is sent. The response
  streams.

## Development

This section lists the commands for work on the package.

- To run the formatter, the linter, the type checker, and the tests, run
  `npm run check`.
- To run the tool from the sources, run `npm run dev:verify`.

The tests use a bundle of the router from 23 Oct 2026, in `test/fixtures/`.
They compare each result with the verifier of Tinfoil, which is a development
dependency only. The EHBP tests open each response with the primitives of the
reference implementation of EHBP (MIT).

## Sources

- The EHBP specification: `SPEC.md` of
  `github.com/tinfoilsh/encrypted-http-body-protocol` (MIT), read 23 Oct 2026.
- The attestation report: the SEV-SNP firmware ABI specification of AMD.
- The formats of the attestation document, the release, and the certificate:
  docs.tinfoil.sh and the live router, read 23 Oct 2026.

## License

The Apache License 2.0. The full text is in `LICENSE`.
