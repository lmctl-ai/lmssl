# 03 — The schema

`schema/lmssl.dsl.json` (`"dsl.schema": 2`) is the contract; `lmssl --dsl-schema` prints a readable summary and
`--dsl-schema --json` the exact bytes (embedded by CMake as a byte array, so the binary prints what the compiler hashed).
`test.sh` diffs `lmssl --dsl-signatures` against `lmscript --dsl-signatures schema/lmssl.dsl.json` (147 entries): a
method added to one side and not the other fails the build.

## Context variables

`ssl: Ssl`, `out: Out`, `fs: Fs`, `net: Net`. All four are views of the same C++ `Host` object (one `void*` registered
under four names); the schema split is only for readability in scripts.

## Types

| Type | Role | Notes |
| --- | --- | --- |
| `Ssl` | factory and utility | `version`, `args`, `now`; `hex/unhex/b64/unb64`; `rand_bytes/rand_hex`; `digest`, `hmac`, `pbkdf2`, `seal`/`open`; `gen_rsa/gen_ec/gen_ed25519`, `load_key` (+ passphrase overload), `parse_key`; `new_cert`, `cert_from_csr`, `load_cert`, `parse_cert`, `new_csr`, `load_csr`; `client_ctx`, `server_ctx` |
| `Key` | `EVP_PKEY` | inspect (`type`, `bits`, `curve`, `text`, `fingerprint`), export (`pem`, `public_pem`, `save`, `save_encrypted`), `sign`/`verify` (Ed25519 ignores the digest argument) |
| `Cert` | `X509` | builder + inspector (below) |
| `Csr` | `X509_REQ` | `san` collects names; `sign(key, digest)` adds them as a requested extension and signs; `verify` checks the self-signature |
| `Conn` | plain TCP socket (a `BIO`) | `read`, `read_until`, `write`, `peer`, `local`, `close`; becomes unusable once wrapped by TLS (`peer`/`local` stay readable) |
| `Listener` | `BIO_new_accept` | `port` (resolves port 0), `accept`, `close` |
| `Net` | resolver and sockets | `resolve`, `connect`, `listen`, `timeout` (seconds, applies to connections created afterwards) |
| `TlsCtx` | `SSL_CTX` | client/server policy; every setter returns itself |
| `Tls` | `SSL` after a completed handshake | negotiated parameters, peer certificate and chain, `trace`, stream I/O |
| `StrList` | `vector<string>` | `len/at/add/join`; `str_list()` and `str_split()` make them |
| `Out`, `Fs` | process I/O | `line/text/warn/fail`; `read/write/write_private/exists/mkdir/remove` |

Free functions: `str_list`, `str_split`, `str_len`, `str_find`, `str_contains`, `str_starts_with`, `str_ends_with`,
`str_substr`, `str_replace`, `str_trim`, `str_lower`, `str_to_int`. These are lmssl's own byte-oriented versions with the
same names as the SDK's optional string catalog; the catalog was not vendored because it also contains float parsing
(`std::from_chars<double>`), which older Apple libc++ lacks, and lmssl needs only these twelve.

## Conventions

- **Builders return `self`.** `Cert.san/ca/ext/valid_days/serial/valid_between/sign_*`, `Csr.san/sign`, `StrList.add` and
  every `TlsCtx` setter return the receiver (registered with the concrete type name, e.g. `"Cert"`), so scripts either
  chain or call for effect.
- **Distinguish signing from template.** `new_cert` fills the subject, random 63-bit serial, 365-day validity and the
  public key. Policy (`san`, `ca`, `ext`, `valid_days`) is added before signing. `sign_self` / `sign_with` set the
  issuer, add `subjectKeyIdentifier`, `basicConstraints CA:FALSE` (unless `ca(true)` ran) and `authorityKeyIdentifier`
  when the issuer has a key id, then sign. Ed25519/Ed448 issuer keys sign with a null digest.
- **Names.** DN strings are `CN=a,O=b` or `/CN=a/O=b`; a backslash escapes the next character. `subject()` prints in the
  same style (`XN_FLAG_SEP_COMMA_PLUS | FN_SN`, comma without space).
- **Hex everywhere binary matters.** `digest`, `hmac`, `pbkdf2`, `seal`, `Key.sign`, `rand_hex` return lowercase hex;
  `seal`'s output is `hex(ciphertext || 16-byte tag)`. Keys/IVs go in as hex. Plain text and raw byte strings (`rand_bytes`,
  `Fs.read`, `Tls.read`) are ordinary DSL strings, which carry arbitrary bytes.
- **Integers.** The DSL `int` is 64-bit. `Cert.serial(n)` takes a positive int; larger serials are not expressible.
- **Defaults fail closed.** `client_ctx()` verifies peers and has no trust anchors; handshake errors include the X509
  verify reason (`certificate verify: self-signed certificate`).
- **`Tls.verified()` vs the handshake.** With `ctx.verify(false)` a handshake succeeds on an untrusted chain and
  `verified()`/`verify_result()` report what validation concluded, which is how `https-steps` can explain a failure.

## Deliberate omissions

CRLs/OCSP, PKCS#12/PKCS#7/CMS, DH/ECDH raw operations, session resumption, DTLS/QUIC, STARTTLS, X.509 name constraints,
RSA-PSS parameters, provider selection. The CLI half covers them (`lmssl pkcs12`, `lmssl cms`, `lmssl ocsp`, ...);
adding a schema type for any of them is mechanical (see 07).
