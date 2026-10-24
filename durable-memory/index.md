# lmssl durable memory

Design and investigation notes for the lmssl host (OpenSSL 4.0.3 built statically + lmcode-cpp, scripted by lmscript
`_dsl_` bytecode). Read in numeric order.

- `01-purpose-and-design.md` — what lmssl is, how one binary is both `openssl` and a DSL host, the host-vs-script boundary.
- `02-static-openssl-build.md` — how OpenSSL is configured, built and repackaged (main renaming, object archive,
  link libraries), the glibc static caveat, the embedded `openssl.cnf`, system trust roots.
- `03-schema.md` — the schema type by type, conventions (errors, ownership, `self` returns), deliberate omissions.
- `04-tls-and-pki-internals.md` — which OpenSSL calls sit behind each DSL call; a map for readers who want to learn
  libcrypto/libssl from the examples.
- `05-testing.md` — what `test.sh` checks, the bugs it and ASan caught, how to add a check.
- `06-ci-and-release.md` — GitHub Actions matrix, release asset naming, platform findings.
- `07-open-items.md` — known gaps and next steps.

Related, outside this repo: `../lmcode-cpp` (runtime, pinned by `sdk.lock`), `../lmhtml` and `../lmcad` (sibling hosts
whose layout this follows), lmscript `durable-memory/dsl-framework.md` (the `_dsl_` language).
